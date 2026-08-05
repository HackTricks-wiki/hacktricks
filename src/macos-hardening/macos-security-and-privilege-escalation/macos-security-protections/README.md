# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper 通常用于指代 **Quarantine + Gatekeeper + XProtect** 的组合，这 3 个 macOS security modules 将尝试 **阻止用户执行下载的潜在恶意软件**。

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

MacOS Sandbox 将 **限制** 在 sandbox 中运行的 **applications**，使其只能执行应用运行时所使用的 **Sandbox profile 中指定的允许操作**。这有助于确保 **application 只访问预期的资源**。


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** 是一个 security framework，旨在 **管理 applications 的权限**，具体而言，是规范它们对敏感功能的访问。这些功能包括 **location services、contacts、photos、microphone、camera、accessibility 和 full disk access**。TCC 确保 apps 只有在获得用户明确同意后才能访问这些功能，从而增强对隐私和个人数据的控制。


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS 中的 launch constraints 是一种 security feature，通过定义 **谁可以 launch** process、**如何 launch** 以及 **从哪里 launch**，来 **规范 process initiation**。该功能在 macOS Ventura 中引入，会将 system binaries 按 constraint categories 分类，并存储在 **trust cache** 中。每个 executable binary 都有针对其 **launch** 的 **rules**，包括 **self**、**parent** 和 **responsible** constraints。在 macOS Sonoma 中，该功能扩展至 third-party apps，称为 **Environment** Constraints。这些功能通过控制 process launching conditions，帮助缓解潜在的 system exploitations。


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) 是 macOS security infrastructure 的另一部分。顾名思义，MRT 的主要功能是 **从受感染的 systems 中移除已知 malware**。

一旦 Mac 上检测到 malware（由 XProtect 或其他方式检测），就可以使用 MRT 自动 **移除 malware**。MRT 在后台静默运行，通常会在 system 更新或下载新的 malware definition 时运行（MRT 用于检测 malware 的 rules 看起来位于该 binary 内部）。

虽然 XProtect 和 MRT 都是 macOS security measures 的组成部分，但它们执行的功能不同：

- **XProtect** 是一种预防性工具。它会 **在 files 被下载时进行检查**（通过某些 applications），如果检测到任何已知类型的 malware，就会 **阻止 file 打开**，从而在 malware 感染 system 之前阻止它。
- 另一方面，**MRT** 是一种 **响应式工具**。它在 system 检测到 malware 后运行，目标是移除相关 software，从而清理 system。

MRT application 位于 **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** 现在每当某个 tool 使用众所周知的 **technique 来持久化 code execution**（例如 Login Items、Daemons 等）时，都会发出 **alert**，以便用户更清楚地了解 **哪些 software 正在持久化**。<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

该功能由位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` 的 **daemon** 以及位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` 的 **agent** 运行。<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** 通过 **获取 FSEvents** 并为其创建一些 **handlers**，来判断某个内容是否安装在 persistent folder 中。<sup>[[1]](#references)</sup>

此外，还有一个 plist file，其中包含由 Apple 维护的、经常进行 persistence 的 **well known applications**，位于：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

可以使用 Apple cli tool 枚举所有已配置的后台项目：<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
此外，也可以使用 [**DumpBTM**](https://github.com/objective-see/DumpBTM) 列出这些信息。<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
此信息存储在 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** 中，并且 Terminal 需要 FDA 权限。<sup>[[2]](#references)</sup>

### 操作 BTM

发现新的 persistence 时，会触发一个类型为 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 的 event。因此，任何能够 **阻止** 发送此 **event** 或阻止 **agent 向用户发出警报** 的方法，都将帮助攻击者 _**绕过**_ BTM。<sup>[[1]](#references)</sup>

- **重置数据库**：运行以下命令将重置数据库（应该会从头开始重建），但是，由于某种原因，运行此命令后，在系统重启之前，**不会对新的 persistence 发出警报**。<sup>[[1]](#references)</sup>
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
- **Bug**: 如果创建 persistence 的 **process 在创建后立即退出**，daemon 将尝试获取关于它的 **信息**，但会 **失败**，因此 **无法发送** 表示新 persistence 正在生效的事件。<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0：“揭秘（及绕过）macOS 的后台任务管理” - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [新（Developer）Tool：“DumpBTM” - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [在 Mac 上管理 login items 和后台任务 - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
