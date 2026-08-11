# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper 通常用于指 **Quarantine + Gatekeeper + XProtect** 的组合，这 3 个 macOS 安全模块会尝试 **阻止用户执行下载的潜在恶意软件**。

更多信息：


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## 进程限制

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **将运行在其中的应用程序限制** 为该应用运行时所使用的 **Sandbox profile 中指定的允许操作**。这有助于确保 **应用程序只访问预期的资源**。


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** 是一个安全框架，旨在 **管理应用程序的权限**，尤其是通过监管其对敏感功能的访问。这些功能包括 **定位服务、联系人、照片、麦克风、摄像头、辅助功能和完整磁盘访问权限**。TCC 确保应用只有在获得用户明确同意后才能访问这些功能，从而增强隐私保护以及对个人数据的控制。


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS 中的 Launch constraints 是一种通过定义 **谁可以启动** 进程、**如何启动** 以及 **从何处启动** 来 **规范进程启动** 的安全功能。该功能于 macOS Ventura 中引入，会将系统二进制文件归类到 **trust cache** 中的约束类别。每个可执行二进制文件都有一组用于其 **启动** 的 **规则**，包括 **self**、**parent** 和 **responsible** 约束。在 macOS Sonoma 中，该功能扩展为第三方应用的 **Environment Constraints**，通过控制进程启动条件，帮助降低潜在的系统利用风险。


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) 是 macOS 安全基础设施的另一部分。顾名思义，MRT 的主要功能是 **从受感染的系统中移除已知 malware**。

一旦 Mac 检测到 malware（无论是通过 XProtect 还是其他方式），就可以使用 MRT 自动 **移除 malware**。MRT 会在后台静默运行，通常在系统更新或下载新的 malware 定义时运行（MRT 用于检测 malware 的规则似乎位于其二进制文件中）。

虽然 XProtect 和 MRT 都是 macOS 安全措施的一部分，但它们执行的功能不同：

- **XProtect** 是一种预防工具。它会 **检查下载的文件**（通过某些应用程序下载），如果检测到任何已知类型的 malware，就会 **阻止文件打开**，从而在 malware 感染系统之前阻止其进入系统。
- 而 **MRT** 是一种 **响应式工具**。它在系统检测到 malware 后运行，目标是移除恶意软件并清理系统。

MRT 应用程序位于 **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** 现在每当工具使用众所周知的 **持久化代码执行技术**（例如 Login Items、Daemons 等）时，都会发出 **警告**，使用户能够更清楚地知道 **哪些软件正在进行持久化**。<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

该功能由位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` 的 **daemon** 以及位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` 的 **agent** 运行。<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** 判断某个内容是否安装在持久化文件夹中的方式，是 **获取 FSEvents** 并为其创建一些 **handlers**。<sup>[[1]](#references)</sup>

此外，还有一个 plist 文件，其中包含 Apple 维护的、经常进行持久化的 **已知应用程序**，位于：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### 枚举

可以使用 Apple cli tool **枚举所有**已配置的后台项目：<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
此外，还可以使用 [**DumpBTM**](https://github.com/objective-see/DumpBTM) 列出这些信息。<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
此信息存储在 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** 中，并且 Terminal 需要 FDA。<sup>[[2]](#references)</sup>

### Messing with BTM

发现新的 persistence 时，会触发一个类型为 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 的事件。因此，任何能够**阻止**发送此**事件**或**阻止 agent 发出警报**的方法，都将帮助攻击者 _**绕过**_ BTM。<sup>[[1]](#references)</sup>

- **重置数据库**：运行以下命令会重置数据库（系统应会从头开始重建数据库）。但是，执行此操作后，直到系统重启之前，**不会出现新的 persistence 警报**。<sup>[[1]](#references)</sup>
- 需要 **root** 权限。
```bash
# Reset the database
sfltool resettbtm
```
- **停止 Agent**：可以向 Agent 发送停止信号，使其在发现新的检测结果时**不会提醒用户**。<sup>[[1]](#references)</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug**：如果**创建 persistence 的进程随后立即退出**，daemon 会尝试**获取其信息**，但**失败**，因此**无法发送**指示新 item 正在 persistence 的事件。<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0：“揭秘（及绕过）macOS 的 Background Task Management” - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool：“DumpBTM” - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [在 Mac 上管理 login items 和 background tasks - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
