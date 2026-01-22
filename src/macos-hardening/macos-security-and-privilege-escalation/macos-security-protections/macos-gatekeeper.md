# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** 是为 macOS 开发的一项安全功能，旨在确保用户在其系统上只运行受信任的软件。它通过对用户从 **App Store 以外** 下载并尝试打开的软件（例如应用、插件或安装包）进行 **验证** 来实现这一点。

Gatekeeper 的关键机制在于其 **验证** 过程。它会检查下载的软件是否由 **受信任的开发者签名**，以确保软件的真实性。此外，它还会确认该软件是否已被 **Apple notarised**，以验证软件中不存在已知的恶意内容，且在 notarisation 之后未被篡改。

另外，Gatekeeper 通过在用户首次打开下载的软件时 **提示用户批准打开**，加强了用户控制与安全性。这一保护有助于防止用户将潜在有害的可执行代码误认为无害的数据文件并意外运行。

### 应用签名

应用签名（也称为代码签名）是 Apple 安全架构的重要组成部分。它们用于 **验证软件作者的身份**（开发者）并确保自上次签名以来代码未被篡改。

其工作流程如下：

1. **对应用进行签名：** 当开发者准备发布其应用时，会使用私钥对应用进行签名。此私钥与开发者在加入 Apple Developer Program 时由 Apple 颁发的证书相关联。签名过程包括对应用的所有部分生成加密哈希并使用开发者的私钥对该哈希进行加密。
2. **分发应用：** 签名后的应用连同包含相应公钥的开发者证书一并分发给用户。
3. **验证应用：** 当用户下载并尝试运行该应用时，macOS 使用开发者证书中的公钥解密哈希，然后根据当前应用的状态重新计算哈希并将其与解密后的哈希进行比较。如果两者匹配，说明 **应用自签名以来未被修改**，系统便允许该应用运行。

应用签名是 Apple Gatekeeper 技术的重要部分。当用户尝试 **打开从互联网下载的应用** 时，Gatekeeper 会验证该应用的签名。如果签名使用 Apple 颁发给已知开发者的证书，且代码未被篡改，Gatekeeper 将允许应用运行。否则，它会阻止该应用并提醒用户。

从 macOS Catalina 开始，**Gatekeeper 还会检查应用是否已被 Apple notarised**，为安全增加了一层保护。notarisation 过程会检查应用是否存在已知的安全问题和恶意代码，如果这些检查通过，Apple 会向应用添加一个票据，Gatekeeper 可以验证该票据。

#### 检查签名

在检查某些 **malware sample** 时，你应始终 **检查二进制的签名**，因为为其签名的 **开发者** 可能已经与 **malware** 有关联。
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### 公证

Apple 的公证流程作为额外的防护，帮助保护用户免受可能有害的软件影响。它包括 **开发者将其应用提交以供审查** 由 **Apple's Notary Service** 进行（不要与 App Review 混淆）。该服务是一个 **自动化系统**，会检查提交的软件是否包含 **恶意内容** 以及与代码签名相关的潜在问题。

如果软件 **通过** 该检查且未提出异议，Notary Service 会生成一个公证票据。开发者随后需要 **将该票据附加到其软件上**，这一过程称为 'stapling'。此外，公证票据还会发布到在线位置，Gatekeeper（Apple 的安全技术）可以访问该票据。

当用户首次安装或运行该软件时，无论公证票据是随可执行文件 stapled 在本地，还是在线可查到，票据的存在都会 **告知 Gatekeeper 该软件已由 Apple 完成公证**。因此，Gatekeeper 会在首次启动对话框中显示一条说明性信息，表明该软件已由 Apple 检查是否包含恶意内容。这个过程从而提高了用户对其在系统上安装或运行软件安全性的信心。

### spctl & syspolicyd

> [!CAUTION]
> 注意，从 Sequoia 版本开始，**`spctl`** 不再允许修改 Gatekeeper 的配置。

**`spctl`** 是用于枚举和与 Gatekeeper 交互的 CLI 工具（通过 XPC 消息与 `syspolicyd` 守护进程通信）。例如，可以通过以下方式查看 GateKeeper 的 **状态**：
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> 请注意，GateKeeper 的签名检查仅针对具有 **Quarantine attribute** 的文件执行，而不是每个文件。

GateKeeper 会根据 **偏好设置 & 签名** 来检查二进制是否可以执行：

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** 是负责执行 Gatekeeper 的主要守护进程。它维护一个位于 `/var/db/SystemPolicy` 的数据库，你可以在这里找到支持该数据库的代码：[database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) 和 SQL 模板：[SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)。请注意该数据库不受 SIP 限制且可被 root 写入，且数据库 `/var/db/.SystemPolicy-default` 用作原始备份，以防另一个数据库损坏。

此外，bundle **`/var/db/gke.bundle`** 和 **`/var/db/gkopaque.bundle`** 包含一些会插入数据库的规则文件。你可以以 root 身份使用以下命令检查该数据库：
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** 还暴露了一个 XPC 服务器，具有 `assess`、`update`、`record` 和 `cancel` 等不同操作，这些操作也可以通过 **`Security.framework`'s `SecAssessment*`** APIs 访问，并且 **`spctl`** 实际上通过 XPC 与 **`syspolicyd`** 通信。

注意第一个规则以 "**App Store**" 结尾，第二个以 "**Developer ID**" 结尾，并且在之前的图像中它被 **启用以允许来自 App Store 和已识别开发者的应用运行**。\\
如果你将该设置 **修改** 为 App Store，**Notarized Developer ID 的规则将会消失**。

还有数千条 **type GKE** 规则 :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
这些是来自以下位置的哈希：

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

或者你可以使用以下命令列出先前的信息：
```bash
sudo spctl --list
```
**`--master-disable`** 和 **`--global-disable`** 这两个 **`spctl`** 的选项会完全 **disable** 这些签名检查：
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
完全启用后，会出现一个新选项：

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

可以使用以下方式**检查某个 App 是否会被 GateKeeper 允许**：
```bash
spctl --assess -v /Applications/App.app
```
可以在 GateKeeper 中添加新规则，以允许使用以下方法执行某些应用：
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
Regarding **kernel extensions**, the folder `/var/db/SystemPolicyConfiguration` contains files with lists of kexts allowed to be loaded. Moreover, `spctl` has the entitlement `com.apple.private.iokit.nvram-csr` because it's capable of adding new pre-approved kernel extensions which need to be saved also in NVRAM in a `kext-allowed-teams` key.

#### 在 macOS 15 (Sequoia) 及更高版本上管理 Gatekeeper

- 长期存在的 Finder **Ctrl+Open / Right‑click → Open** 绕过已被移除；用户在首次阻止对话框后必须从 **System Settings → Privacy & Security → Open Anyway** 明确允许被阻止的应用。
- `spctl --master-disable/--global-disable` 不再被接受；`spctl` 在评估和标签管理方面实际上为只读，而策略执行通过 UI 或 MDM 配置。

从 macOS 15 Sequoia 开始，最终用户不能再通过 `spctl` 切换 Gatekeeper 策略。管理通过 System Settings 或部署带有 `com.apple.systempolicy.control` payload 的 MDM 配置配置文件来完成。下面是允许 App Store 和 identified developers（但不包括 "Anywhere"）的示例配置文件片段：

<details>
<summary>MDM profile to allow App Store and identified developers</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Quarantine Files

Upon **downloading** an application or file, specific macOS **applications** such as web browsers or email clients **attach an extended file attribute**, commonly known as the "**quarantine flag**," to the downloaded file. This attribute acts as a security measure to **mark the file** as coming from an untrusted source (the internet), and potentially carrying risks. However, not all applications attach this attribute, for instance, common BitTorrent client software usually bypasses this process.

**The presence of a quarantine flag signals macOS's Gatekeeper security feature when a user attempts to execute the file**.

In the case where the **quarantine flag is not present** (as with files downloaded via some BitTorrent clients), Gatekeeper's **checks may not be performed**. Thus, users should exercise caution when opening files downloaded from less secure or unknown sources.

> [!NOTE] > **Checking** the **validity** of code signatures is a **resource-intensive** process that includes generating cryptographic **hashes** of the code and all its bundled resources. Furthermore, checking certificate validity involves doing an **online check** to Apple's servers to see if it has been revoked after it was issued. For these reasons, a full code signature and notarization check is **impractical to run every time an app is launched**.
>
> Therefore, these checks are **only run when executing apps with the quarantined attribute.**

> [!WARNING]
> This attribute must be **set by the application creating/downloading** the file.
>
> However, files that are sandboxed will have this attribute set to every file they create. And non sandboxed apps can set it themselves, or specify the [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key in the **Info.plist** which will make the system set the `com.apple.quarantine` extended attribute on the files created,

Moreover, all files created by a process calling **`qtn_proc_apply_to_self`** are quarantined. Or the API **`qtn_file_apply_to_path`** adds the quarantine attribute to a specified file path.

It's possible to **check it's status and enable/disable** (root required) with:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
你也可以**找出文件是否具有 quarantine 扩展属性**：
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
检查 **扩展** **属性** 的 **值**，并找出写入 quarantine attr 的应用：
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
实际上，一个进程“可以为它创建的文件设置 quarantine flags”（我已经尝试在创建的文件中应用 USER_APPROVED 标志，但无法应用）:

<details>

<summary>Source Code apply quarantine flags</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

然后使用以下命令**移除**该属性：
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
并使用以下命令查找所有被隔离的文件:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine 信息还存储在 LaunchServices 管理的中央数据库 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** 中，GUI 可以通过它获取文件的来源数据。此外，这些信息可以被某些想隐藏来源的应用覆盖。并且可以通过 LaunchServices APIs 完成此操作。

#### **libquarantine.dylib**

该库导出若干函数，允许操作扩展属性字段。

`qtn_file_*` APIs 处理文件隔离策略，`qtn_proc_*` APIs 应用于进程（由该进程创建的文件）。未导出的 `__qtn_syscall_quarantine*` 函数是用于应用这些策略的，它会调用 `mac_syscall`，以 "Quarantine" 作为第一个参数，将请求发送到 `Quarantine.kext`。

#### **Quarantine.kext**

该内核扩展只能通过系统的 **kernel cache** 获取；不过，你 _可以_ 从 [**https://developer.apple.com/**](https://developer.apple.com/) 下载 **Kernel Debug Kit**，其中包含该扩展的符号化版本。

该 Kext 会通过 MACF hook 若干调用，以捕获所有文件生命周期事件：创建、打开、重命名、硬链接等，甚至会拦截 `setxattr`，以阻止设置 `com.apple.quarantine` 扩展属性。

它还使用了几个 MIB：

- `security.mac.qtn.sandbox_enforce`: 在 Sandbox 中强制执行隔离策略
- `security.mac.qtn.user_approved_exec`: 被隔离的进程只能执行已批准的文件

#### Provenance xattr (Ventura and later)

macOS 13 Ventura 引入了一个单独的 provenance 机制，当隔离应用第一次被允许运行时会填充该机制。会创建两个工件：

- 在 `.app` 应用包目录上的 `com.apple.provenance` xattr（固定大小的二进制值，包含主键和标志）。
- 在 ExecPolicy 数据库的 `provenance_tracking` 表（位于 `/var/db/SystemPolicyConfiguration/ExecPolicy/`）中有一行，存储了该应用的 cdhash 和元数据。

实际用法：
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect 是 macOS 内置的 **anti-malware** 功能。XProtect 会在应用首次启动或被修改时，**将其与已知恶意软件和不安全文件类型的数据库进行比对**。当你通过某些应用（例如 Safari、Mail 或 Messages）下载文件时，XProtect 会自动扫描该文件。如果它与数据库中的已知恶意软件匹配，XProtect 将 **阻止该文件运行** 并提醒你存在威胁。

XProtect 的数据库由 Apple **定期更新** 新的恶意软件定义，这些更新会自动下载并安装到你的 Mac 上。这可确保 XProtect 始终针对最新已知威胁保持更新。

不过，值得注意的是，**XProtect 并非全功能 antivirus 解决方案**。它仅检查特定的已知威胁列表，并不像大多数 antivirus 软件那样执行 on-access scanning。

你可以运行以下命令来获取有关最新 XProtect 更新的信息：
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect 位于受 SIP 保护的位置 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**，在该 bundle 内可以找到 XProtect 使用的信息：

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: 允许具有那些 cdhashes 的代码使用 legacy entitlements。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: 列出通过 BundleID 和 TeamID 被禁止加载的插件和扩展，或指明最小版本要求。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: 用于检测恶意软件的 Yara 规则。
- **`XProtect.bundle/Contents/Resources/gk.db`**: 包含被阻止应用及 TeamIDs 哈希的 SQLite3 数据库。

注意在 **`/Library/Apple/System/Library/CoreServices/XProtect.app`** 还有另一个与 XProtect 相关的 App，但它不参与 Gatekeeper 过程。

> XProtect Remediator: 在现代 macOS 上，Apple 提供按需扫描器（XProtect Remediator），通过 launchd 定期运行以检测并修复某些恶意软件家族。你可以在统一日志中观察到这些扫描：
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### 不是 Gatekeeper

> [!CAUTION]
> 注意 Gatekeeper **并不是每次** 执行应用时都会运行，只有 _**AppleMobileFileIntegrity**_ (AMFI) 会在你执行一个已被 Gatekeeper 执行并验证过的应用时才会 **verify executable code signatures**。

因此，过去可以先执行一个应用以让 Gatekeeper 缓存它，然后 **修改应用的非可执行文件**（例如 Electron asar 或 NIB 文件），如果没有其他防护，应用会带着这些 **恶意** 的附加内容被 **执行**。

然而现在这已不可行，因为 macOS **阻止修改** 应用包内的文件。所以，如果你尝试 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 攻击，你会发现无法再滥用它：在执行应用以让 Gatekeeper 缓存后，你无法修改该 bundle。例如，如果你像漏洞中那样将 Contents 目录重命名为 NotCon，然后执行应用的主二进制以让 Gatekeeper 缓存它，会触发错误并且不会执行。

## Gatekeeper 绕过

任何能绕过 Gatekeeper（设法让用户下载并在 Gatekeeper 应该阻止时执行）的方式都被视为 macOS 的一个漏洞。以下是一些过去被分配为允许绕过 Gatekeeper 的技术相关的 CVE：

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

观察到如果使用 **Archive Utility** 进行解压，路径长度超过 **886 characters** 的文件不会获得 com.apple.quarantine 扩展属性。此情况会无意间使这些文件能够 **规避 Gatekeeper 的** 安全检查。

查看 [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) 获取更多信息。

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

当使用 **Automator** 创建应用时，关于应用执行所需信息位于 `application.app/Contents/document.wflow`，而不是可执行文件。可执行文件只是一个通用的 Automator 二进制，称为 **Automator Application Stub**。

因此，你可以让 `application.app/Contents/MacOS/Automator\ Application\ Stub` **通过符号链接指向系统内的另一个 Automator Application Stub**，这样会执行 `document.wflow` 中的内容（你的脚本），并且 **不会触发 Gatekeeper**，因为实际的可执行文件没有 quarantine xattr。

示例的预期位置：`/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

查看 [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) 获取更多信息。

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

在该绕过中，创建了一个 zip 文件，其压缩时从 `application.app/Contents` 开始而不是从 `application.app` 开始。因此，**quarantine attr** 被应用到了 `application.app/Contents` 中的所有文件，但 **没有应用到 `application.app`**（Gatekeeper 检查的是 `application.app`），因此当触发 `application.app` 时它 **没有 quarantin e 属性**，从而绕过了 Gatekeeper。
```bash
zip -r test.app/Contents test.zip
```
请查看 [**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) 了解更多信息。

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

即使组件不同，该漏洞的利用方式与前一个非常相似。在这种情况下，我们会从 **`application.app/Contents`** 生成一个 Apple Archive，因此当由 **Archive Utility** 解压时，**`application.app` won't get the quarantine attr**。
```bash
aa archive -d test.app/Contents -o test.app.aar
```
请查看 [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) 获取更多信息。

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** 可用于阻止任何人向文件写入属性：
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
此外，**AppleDouble** 文件格式在复制文件时会包含其 ACEs。

在 [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) 中可以看到，存储在名为 **`com.apple.acl.text`** 的 xattr 内的 ACL 文本表示会被设置为解压后文件的 ACL。因此，如果你用 **AppleDouble** 文件格式将一个应用程序压缩成 zip 文件，并且该文件的 ACL 阻止向其写入其他 xattr... quarantine xattr 就不会被设置到该应用程序：
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
查看 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) 以获取更多信息。

注意，这也可以通过 AppleArchives 被利用：
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

发现 **Google Chrome 没有为下载的文件设置隔离属性**，原因是 macOS 的一些内部问题。

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble 文件格式将文件的属性存储在以 `._` 开头的单独文件中，这有助于**在 macOS 机器之间**复制文件属性。然而，观察到在解压 AppleDouble 文件后，以 `._` 开头的文件**并未被赋予隔离属性**。
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
能够创建一个不会被设置 quarantine 属性的文件，就**可以绕过 Gatekeeper。** The trick was to **create a DMG file application** using the AppleDouble name convention (start it with `._`) and create a **visible file as a sym link to this hidden** file without the quarantine attribute.\
诀窍是使用 AppleDouble 命名约定（以 `._` 开头），**创建一个 DMG 文件应用**，并创建一个**可见文件作为指向这个没有 quarantine 属性的隐藏文件的 sym link**。\
当**dmg file is executed**时，由于它没有 quarantine 属性，它会**绕过 Gatekeeper**。
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

一个在 macOS Sonoma 14.0 中修复的 Gatekeeper 绕过漏洞允许精心构造的应用在无提示情况下运行。补丁发布后细节被公开披露，且在修复前该问题曾在真实环境中被主动利用。确保安装了 Sonoma 14.0 或更高版本。

### [CVE-2024-27853]

macOS 14.4（2024 年 3 月发布）中的一个 Gatekeeper 绕过，源于 `libarchive` 对恶意 ZIP 的处理，允许应用规避评估。请更新到 14.4 或更高版本，Apple 在该版本中修复了此问题。

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

嵌入在已下载应用中的 **Automator Quick Action workflow** 可能在未经过 Gatekeeper 评估的情况下触发，原因是 workflows 被视为数据并由 Automator helper 在常规 notarization 提示路径之外执行。因此，一个捆绑了运行 shell 脚本的 Quick Action 的精心构造的 `.app`（例如位于 `Contents/PlugIns/*.workflow/Contents/document.wflow` 内）可能在启动时立即执行。Apple 在 Ventura **13.7**、Sonoma **14.7** 和 Sequoia **15** 中增加了额外的同意对话并修复了评估路径。

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

一些流行解压工具（例如 The Unarchiver）中的多个漏洞导致从归档中解压的文件缺少 `com.apple.quarantine` xattr，从而为 Gatekeeper 绕过创造了机会。在测试时始终使用 macOS Archive Utility 或已修补的工具，并在解压后验证 xattrs。

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- 创建一个包含 app 的目录。
- 对该 app 添加 uchg。
- 将该 app 压缩为 tar.gz 文件。
- 将 tar.gz 文件发送给受害者。
- 受害者打开 tar.gz 文件并运行 app。
- Gatekeeper 不会检查该 app。

### Prevent Quarantine xattr

在一个 ".app" 包中如果未向其添加 quarantine xattr，那么在执行时 **Gatekeeper 不会被触发**。


## References

- Apple Platform Security: 关于 macOS Sonoma 14.4 的安全内容（包含 CVE-2024-27853） – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: How macOS now tracks the provenance of apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: 关于 macOS Sonoma 14.7 / Ventura 13.7 的安全内容 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
