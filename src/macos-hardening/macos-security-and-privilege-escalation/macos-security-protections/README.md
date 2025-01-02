# macOS 安全保护

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper 通常用于指代 **Quarantine + Gatekeeper + XProtect** 的组合，这三个 macOS 安全模块将尝试 **防止用户执行潜在恶意软件**。

更多信息请参见：

{{#ref}}
macos-gatekeeper.md
{{#endref}}

## 进程限制

### MACF

### SIP - 系统完整性保护

{{#ref}}
macos-sip.md
{{#endref}}

### 沙盒

MacOS 沙盒 **限制应用程序** 在沙盒内运行时的 **允许操作，这些操作在沙盒配置文件中指定**。这有助于确保 **应用程序仅访问预期的资源**。

{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **透明性、同意和控制**

**TCC (透明性、同意和控制)** 是一个安全框架。它旨在 **管理应用程序的权限**，特别是通过调节它们对敏感功能的访问。这包括 **位置服务、联系人、照片、麦克风、相机、无障碍和完整磁盘访问** 等元素。TCC 确保应用程序只能在获得用户明确同意后访问这些功能，从而增强对个人数据的隐私和控制。

{{#ref}}
macos-tcc/
{{#endref}}

### 启动/环境约束与信任缓存

macOS 中的启动约束是一种安全功能，用于 **调节进程启动**，通过定义 **谁可以启动** 进程、**如何** 启动以及 **从哪里** 启动。该功能在 macOS Ventura 中引入，将系统二进制文件分类为信任缓存中的约束类别。每个可执行二进制文件都有设定的 **启动规则**，包括 **自我**、**父级** 和 **责任** 约束。扩展到第三方应用程序作为 macOS Sonoma 中的 **环境** 约束，这些功能通过管理进程启动条件来帮助减轻潜在的系统利用。

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - 恶意软件移除工具

恶意软件移除工具 (MRT) 是 macOS 安全基础设施的另一个组成部分。顾名思义，MRT 的主要功能是 **从感染的系统中移除已知恶意软件**。

一旦在 Mac 上检测到恶意软件（无论是通过 XProtect 还是其他方式），可以使用 MRT 自动 **移除恶意软件**。MRT 在后台静默运行，通常在系统更新或下载新恶意软件定义时运行（看起来 MRT 检测恶意软件的规则在二进制文件内）。

虽然 XProtect 和 MRT 都是 macOS 安全措施的一部分，但它们执行不同的功能：

- **XProtect** 是一种预防工具。它 **检查下载的文件**（通过某些应用程序），如果检测到任何已知类型的恶意软件，它 **阻止文件打开**，从而防止恶意软件首先感染您的系统。
- **MRT** 则是一个 **反应工具**。它在系统检测到恶意软件后运行，旨在移除有问题的软件以清理系统。

MRT 应用程序位于 **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## 背景任务管理

**macOS** 现在 **在每次工具使用众所周知的 **技术来保持代码执行**（如登录项、守护进程...）时发出警报，以便用户更好地了解 **哪些软件在持续运行**。

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

这通过位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` 的 **守护进程** 和位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` 的 **代理** 运行。

**`backgroundtaskmanagementd`** 知道某些东西安装在持久文件夹中的方式是通过 **获取 FSEvents** 并为这些事件创建一些 **处理程序**。

此外，还有一个 plist 文件，包含 **众所周知的应用程序**，这些应用程序经常保持由苹果维护，位于：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

可以使用 Apple cli 工具 **枚举所有** 配置的后台项目：
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
此外，还可以使用 [**DumpBTM**](https://github.com/objective-see/DumpBTM) 列出这些信息。
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
此信息存储在 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** 中，终端需要 FDA。

### 操作 BTM

当发现新的持久性时，会发生类型为 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 的事件。因此，任何 **防止** 该 **事件** 被发送或 **代理不警告** 用户的方法都将帮助攻击者 _**绕过**_ BTM。

- **重置数据库**：运行以下命令将重置数据库（应该从头开始重建），但是，由于某种原因，在运行此命令后，**在系统重启之前不会警告任何新的持久性**。
- **需要 root 权限**。
```bash
# Reset the database
sfltool resettbtm
```
- **停止代理**：可以向代理发送停止信号，以便它**不会在发现新检测时提醒用户**。
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
- **错误**：如果**创建持久性的进程在其后快速存在**，守护进程将尝试**获取信息**，**失败**，并且**无法发送事件**，指示新的事物正在持久化。

参考和**关于BTM的更多信息**：

- [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
- [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
