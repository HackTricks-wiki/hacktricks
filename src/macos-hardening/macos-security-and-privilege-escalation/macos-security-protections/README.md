# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper 通常用于指 **Quarantine + Gatekeeper + XProtect** 的组合，这 3 个 macOS security modules 会尝试 **阻止用户执行下载的潜在恶意软件**。

更多信息请参阅：


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Processes Limitants

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **将运行在 sandbox 内的应用程序限制为**该应用运行时所使用的 **Sandbox profile 中指定的允许操作**。这有助于确保 **应用程序只访问预期的资源**。


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** 是一个 security framework，旨在 **管理应用程序的权限**，具体通过控制应用程序对敏感功能的访问来实现。这些功能包括 **位置服务、联系人、照片、麦克风、摄像头、辅助功能和完整磁盘访问权限**。TCC 确保应用只能在获得用户明确同意后访问这些功能，从而增强隐私保护以及对个人数据的控制。


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS 中的 launch constraints 是一种 security feature，通过定义 **谁可以启动**进程、**如何启动**以及 **从哪里启动**来 **规范进程启动**。该功能在 macOS Ventura 中引入，会将 system binaries 按 constraint categories 分类到 **trust cache** 中。每个 executable binary 都有一组用于其 **启动**的 **rules**，包括 **self**、**parent** 和 **responsible** constraints。在 macOS Sonoma 中，该功能扩展为适用于 third-party apps 的 **Environment** Constraints，通过管理进程启动条件来帮助缓解潜在的 system exploitations。


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) 是 macOS security infrastructure 的另一部分。顾名思义，MRT 的主要功能是 **从受感染的系统中移除已知 malware**。

当 Mac 检测到 malware 后（无论是通过 XProtect 还是其他方式），都可以使用 MRT 自动 **移除 malware**。MRT 会在后台静默运行，通常会在系统更新或下载新的 malware definition 时运行（MRT 用于检测 malware 的 rules 似乎位于该 binary 内）。

虽然 XProtect 和 MRT 都属于 macOS 的 security measures，但它们执行的功能不同：

- **XProtect** 是一种 preventative tool。它会 **检查下载的文件**（通过某些应用程序下载），如果检测到任何已知类型的 malware，就会 **阻止文件打开**，从而在 malware 感染系统之前阻止其运行。
- 另一方面，**MRT** 是一种 **reactive tool**。它会在系统检测到 malware 后运行，目标是移除恶意软件，以清理系统。

MRT 应用位于 **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** 现在会在工具每次使用众所周知的 **持久化 code execution 的 technique**（例如 Login Items、Daemons……）时发出 **alert**，让用户更清楚地了解 **哪些 software 正在持久化**。<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

该功能通过位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` 的 **daemon** 和位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` 的 **agent** 运行。<sup>[1]</sup>

**`backgroundtaskmanagementd`** 判断某个内容是否安装在 persistent folder 中的方法，是 **获取 FSEvents** 并为其创建一些 **handlers**。<sup>[1]</sup>

此外，还有一个由 Apple 维护的 plist 文件，其中包含经常进行 persistence 的 **well known applications**，位于：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
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

可以使用 Apple cli 工具**枚举所有**已配置的后台项目：<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
此外，还可以使用 [**DumpBTM**](https://github.com/objective-see/DumpBTM) 列出这些信息。<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
此信息存储在 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** 中，并且 Terminal 需要 FDA。<sup>[2]</sup>

### 修改 BTM

发现新的 persistence 时，会生成一个类型为 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 的 event。因此，任何能够**阻止**此 **event** 发送，或阻止 **agent alerting** 用户的方法，都能帮助攻击者 _**bypass**_ BTM。<sup>[1]</sup>

- **重置数据库**：运行以下命令将重置数据库（应该会从头开始重建），但是，由于某种原因，运行此命令后，直到系统重新启动前，**不会对新的 persistence 发出 alert**。<sup>[1]</sup>
- 需要 **root** 权限。
```bash
# Reset the database
sfltool resettbtm
```
- **停止 Agent**：可以向 Agent 发送停止信号，使其在发现新的检测结果时**不会向用户发出警报**。<sup>[1]</sup>
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
- **Bug**: If the **process that created the persistence exits fast right after it**, the daemon will try to **获取有关它的信息**, **失败**, and **无法发送** indicating that a new thing is persisting 的事件。<sup>[1]</sup>

## References

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
