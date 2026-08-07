# macOS 安全防护

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper 通常用于指 **Quarantine + Gatekeeper + XProtect** 的组合，它们是 macOS 中会尝试 **阻止用户执行下载的潜在恶意软件** 的 3 个安全模块。

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

MacOS Sandbox 会将运行在 sandbox 中的 **应用程序限制** 在其运行所使用的 **Sandbox profile 中指定的允许操作** 范围内。这有助于确保 **应用程序只访问预期的资源**。


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** 是一个安全框架，旨在 **管理应用程序的权限**，尤其是通过控制它们对敏感功能的访问。这些功能包括 **定位服务、联系人、照片、麦克风、摄像头、辅助功能和完整磁盘访问权限** 等。TCC 确保应用程序只有在获得用户明确同意后才能访问这些功能，从而增强隐私保护以及对个人数据的控制。


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS 中的 Launch constraints 是一种通过定义 **谁可以启动** 进程、**如何启动** 以及 **从何处启动** 来 **规范进程启动** 的安全功能。该功能于 macOS Ventura 中引入，会将系统二进制文件归类到 **trust cache** 中的约束类别。每个可执行二进制文件都有一组用于其 **launch** 的 **规则**，包括 **self**、**parent** 和 **responsible** 约束。在 macOS Sonoma 中，该功能扩展为面向第三方应用的 **Environment** Constraints，通过控制进程启动条件来帮助缓解潜在的系统利用行为。


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) 是 macOS 安全基础设施的另一部分。顾名思义，MRT 的主要功能是 **从受感染的系统中移除已知 malware**。

当 Mac 上检测到 malware 后（无论是通过 XProtect 还是其他方式），MRT 都可用于自动 **移除 malware**。MRT 会在后台静默运行，通常会在系统更新或下载新的 malware 定义时运行（MRT 用于检测 malware 的规则似乎位于该二进制文件内部）。

虽然 XProtect 和 MRT 都是 macOS 安全措施的一部分，但它们执行的功能不同：

- **XProtect** 是一种预防工具。它会 **检查正在下载的文件**（通过某些应用程序），如果检测到任何已知类型的 malware，就会 **阻止文件打开**，从而在 malware 感染系统之前阻止其进入系统。
- 而 **MRT** 是一种 **响应式工具**。它会在系统检测到 malware 后运行，目标是移除相关软件以清理系统。

MRT 应用程序位于 **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** 现在会在工具每次使用已知的 **持久化 code execution 的 technique**（例如 Login Items、Daemons 等）时发出 **提醒**，以便用户更清楚地了解 **哪些软件正在进行持久化**。<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

该功能通过位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` 的 **daemon** 以及位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` 的 **agent** 运行。<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** 判断某个内容是否安装在持久化文件夹中的方式，是 **获取 FSEvents** 并为其创建一些 **handlers**。<sup>[[1]](#references)</sup>

此外，还有一个由 apple 维护的 plist 文件，其中包含经常进行持久化的 **知名应用程序**，位于：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

可以使用 Apple cli 工具**枚举所有**已配置的后台项目：<sup>[[3]](#references)</sup>
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
这些信息存储在 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** 中，并且 Terminal 需要 FDA。<sup>[[2]](#references)</sup>

### 干扰 BTM

当发现新的 persistence 时，会产生一个类型为 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 的 event。因此，任何能够**阻止**该 **event** 被发送，或阻止 **agent alerting** 用户的方法，都将帮助攻击者 _**bypass**_ BTM。<sup>[[1]](#references)</sup>

- **重置数据库**：运行以下命令将重置数据库（应该会从头重建），但是由于某种原因，运行此命令后，直到系统重启前，**不会 alert 任何新的 persistence**。<sup>[[1]](#references)</sup>
- 需要 **root** 权限。
```bash
# Reset the database
sfltool resettbtm
```
- **停止 Agent**：可以向 Agent 发送停止信号，使其在发现新的检测结果时**不会向用户发出警报**。<sup>[[1]](#references)</sup>
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
- **Bug**: 如果创建 persistence 的 **process 在创建后立即退出**，daemon 将尝试获取其**信息**，但会**失败**，因此**无法发送**表示有新项目正在进行 persistence 的 event。<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "揭秘（并绕过）macOS 的后台任务管理" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [在 Mac 上管理登录项目和后台任务 - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
