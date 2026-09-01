# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** 是为 Mac 操作系统开发的一项安全功能，旨在确保用户在系统上**仅运行受信任的软件**。它通过**验证软件**来发挥作用，这些软件是用户从 **App Store 之外的来源**下载并尝试打开的，例如 app、插件或安装程序包。

Gatekeeper 的核心机制在于其**验证**过程。它会检查下载的软件是否由**受认可的开发者签名**，以确保软件的真实性。此外，它还会确认软件是否已由 Apple **notarised**，以证明其中不包含已知的恶意内容，并且在 notarisation 后未被篡改。

此外，Gatekeeper 通过**提示用户批准首次打开**下载的软件，进一步强化用户控制和安全性。这项保护措施有助于防止用户无意中运行潜在有害的可执行代码，而用户可能误以为这些代码只是无害的数据文件。

### Application Signatures

Application signatures，也称为 code signatures，是 Apple 安全基础设施的重要组成部分。它们用于**验证软件作者的身份**（开发者），并确保代码自上次签名以来未被篡改。

其工作方式如下：

1. **Signing the Application：** 当开发者准备分发其 application 时，会使用**私钥对 application 进行签名**。该私钥与 Apple 在开发者加入 Apple Developer Program 时向其签发的**证书**相关联。签名过程包括为 app 的所有部分创建 cryptographic hash，并使用开发者的私钥对该 hash 进行加密。
2. **Distributing the Application：** 签名后的 application 会与开发者的证书一起分发给用户，该证书包含对应的公钥。
3. **Verifying the Application：** 当用户下载并尝试运行 application 时，其 Mac 操作系统会使用开发者证书中的公钥解密 hash。随后，系统会根据 application 的当前状态重新计算 hash，并将其与解密后的 hash 进行比较。如果两者匹配，则表示**application 自开发者签名以来未被修改**，系统便允许 application 运行。

Application signatures 是 Apple Gatekeeper 技术的重要组成部分。当用户尝试**打开从互联网下载的 application** 时，Gatekeeper 会验证 application signature。如果它使用 Apple 向已知开发者签发的证书进行签名，且代码未被篡改，Gatekeeper 就会允许 application 运行。否则，它会阻止 application 并向用户发出警告。

从 macOS Catalina 开始，**Gatekeeper 还会检查 application 是否已由 Apple notarized**，从而增加额外的安全层。notarization 过程会检查 application 是否存在已知安全问题和恶意代码；如果检查通过，Apple 会向 application 添加一个 Gatekeeper 可以验证的 ticket。

#### Check Signatures

检查某个 **malware sample** 时，应始终**检查其 signature**，因为为其签名的**developer** 可能已经与 **malware** 有关。
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

Apple 的公证流程是一项额外的安全措施，用于保护用户免受潜在有害软件的侵害。该流程要求**开发者将其应用提交给** **Apple's Notary Service** **进行检查**，这不应与 App Review 混淆。该服务是一个**自动化系统**，用于检查所提交的软件是否包含**恶意内容**，以及是否存在任何潜在的代码签名问题。

如果软件通过了检查且未发现任何问题，Notary Service 会生成一张公证票据。随后，开发者必须**将此票据附加到其软件中**，这一过程称为“stapling”。此外，公证票据也会发布到网上，Gatekeeper（Apple 的安全技术）可以访问该票据。

当用户首次安装或执行软件时，无论公证票据是已 stapled 到可执行文件中，还是从网上获取，**都会告知 Gatekeeper 该软件已通过 Apple 的公证**。因此，Gatekeeper 会在首次启动对话框中显示一条描述性消息，说明该软件已由 Apple 检查是否包含恶意内容。通过这一流程，用户对其在系统上安装或运行的软件的安全性会更有信心。

### spctl & syspolicyd

> [!CAUTION]
> 请注意，从 Sequoia 版本开始，**`spctl`** 不再允许修改 Gatekeeper 配置。

**`spctl`** 是用于枚举和与 Gatekeeper 交互的 CLI 工具（通过 XPC 消息与 `syspolicyd` daemon 交互）。例如，可以使用以下命令查看 GateKeeper 的**状态**：
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> 请注意，GateKeeper 签名检查仅针对具有 **Quarantine attribute** 的文件执行，而不是针对每个文件。

GateKeeper 将根据 **preferences & signature** 检查某个 binary 是否可以执行：

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** 是负责强制执行 Gatekeeper 的主要 daemon。它维护一个位于 `/var/db/SystemPolicy` 的数据库，并且可以在[此处](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)找到支持该 [database](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) 的 code，以及[此处](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)找到 [SQL template](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)。请注意，该 database 不受 SIP 限制，且 root 可写入；数据库 `/var/db/.SystemPolicy-default` 用作原始 backup，以防另一个数据库损坏。

此外，bundles **`/var/db/gke.bundle`** 和 **`/var/db/gkopaque.bundle`** 包含会被插入 database 的规则文件。你可以使用 root 身份通过以下命令检查此 database：
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
**`syspolicyd`** 还会通过 XPC 暴露一个包含 `assess`、`update`、`record` 和 `cancel` 等不同操作的服务器，这些操作也可以通过 **`Security.framework` 的 `SecAssessment*`** APIs 访问，而 **`spctl`** 实际上通过 XPC 与 **`syspolicyd`** 通信。

注意第一条规则以“**App Store**”结尾，第二条规则以“**Developer ID**”结尾，并且在之前的映像中，它被**启用为允许运行来自 App Store 和已识别开发者的应用**。\
如果将该设置**修改**为 App Store，“**Notarized Developer ID**”规则将会消失。

此外，还有数千条**类型为 GKE** 的规则：
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
这些是来自以下位置的 hashes：

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

或者，你也可以使用以下命令列出之前的信息：
```bash
sudo spctl --list
```
**`spctl`** 的选项 **`--master-disable`** 和 **`--global-disable`** 将完全**禁用**这些签名检查：
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
完全启用后，将出现一个新选项：

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

可以使用以下命令**检查某个 App 是否会被 GateKeeper 允许**：
```bash
spctl --assess -v /Applications/App.app
```
在 macOS 14 及更高版本中，**`syspolicy_check`** 是用于应用程序 bundle 的实用高级分发前检查工具。与单独使用 `spctl` 相比，它能提供更具可操作性的可信执行诊断；不过，Apple 仍建议测试真实的下载/解压/首次启动流程，因为这也会验证 quarantine 的传播过程。<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
可以在 GateKeeper 中添加新规则，以允许执行某些应用程序：
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
关于 **kernel extensions**，文件夹 `/var/db/SystemPolicyConfiguration` 包含列出允许加载的 kext 的文件。此外，`spctl` 具有 `com.apple.private.iokit.nvram-csr` entitlement，因为它能够添加新的预批准 kernel extensions；这些扩展还需要通过 `kext-allowed-teams` key 保存到 NVRAM 中。

#### 在 macOS 15（Sequoia）及更高版本上管理 Gatekeeper

- 长期存在的 Finder **Ctrl+Open / 右键 → Open** bypass 已被移除；用户必须在首次阻止对话框之后，通过 **System Settings → Privacy & Security → Open Anyway** 明确允许被阻止的 app。<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` 不再接受 unattended policy changes。修改 rule database 或 global assessment state 的操作已被弃用，因此应使用 `spctl` 进行 assessment，并通过 UI 或 MDM 配置 enforcement。

从 macOS 15 Sequoia 开始，终端用户无法再通过 `spctl` 切换 Gatekeeper policy。管理操作通过 System Settings 执行，或通过部署包含 `com.apple.systempolicy.control` payload 的 MDM configuration profile 完成。以下是允许 App Store 和已识别开发者（但不允许 “Anywhere”）的 profile 片段示例：

<details>
<summary>允许 App Store 和已识别开发者的 MDM profile</summary>
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

在**下载**应用程序或文件时，某些 macOS **应用程序**（例如 Web 浏览器或电子邮件客户端）会为下载的文件**附加扩展文件属性**，通常称为“**quarantine flag**”。此属性是一种安全措施，用于**标记文件**来自不受信任的来源（互联网），并且可能存在风险。不过，并非所有应用程序都会附加此属性，例如常见的 BitTorrent 客户端软件通常会绕过这一过程。

**当用户尝试执行文件时，quarantine flag 的存在会向 macOS 的 Gatekeeper 安全功能发出信号**。

如果**不存在 quarantine flag**（例如通过某些 BitTorrent 客户端下载的文件），Gatekeeper 可能**不会执行检查**。因此，用户打开从安全性较低或未知来源下载的文件时应保持谨慎。

> [!NOTE] > **检查**代码签名的**有效性**是一个**资源密集型**过程，其中包括为代码及其所有捆绑资源生成加密**哈希**。此外，检查证书有效性还需要对 Apple 的服务器执行**在线检查**，以确认该证书在签发后是否已被撤销。由于这些原因，每次启动应用时都运行完整的代码签名和 notarization 检查是**不切实际的**。
>
> 因此，这些检查**仅在执行带有 quarantined 属性的应用时运行**。

> [!WARNING]
> 此属性必须由创建/下载文件的**应用程序设置**。
>
> 但是，sandboxed 文件会为其创建的每个文件设置此属性。而 non sandboxed 应用可以自行设置该属性，或在 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) 的 **Info.plist** 中指定此键，这将使系统在所创建的文件上设置 `com.apple.quarantine` 扩展属性，

此外，调用 **`qtn_proc_apply_to_self`** 的进程创建的所有文件都会被隔离。或者，API **`qtn_file_apply_to_path`** 会将 quarantine 属性添加到指定的文件路径。

可以使用以下方式**检查其状态并启用/禁用**（需要 root）：
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
你还可以通过以下方式**查找文件是否具有 quarantine 扩展属性**：
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
检查 **extended** **attributes** 的 **value**，并使用以下命令找出写入 quarantine attr 的 app：
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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
实际上，某个进程“可以为其创建的文件设置 quarantine flags”（我已经尝试在创建的文件中应用 USER_APPROVED flag，但无法应用它）：

<details>

<summary>应用 quarantine flags 的源代码</summary>
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

并使用以下命令**移除**该属性：
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
并使用以下命令查找所有被隔离的文件：
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine 信息还存储在由 LaunchServices 管理的中央数据库 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** 中，使 GUI 能够获取有关文件来源的数据。此外，该信息可能会被有意隐藏其来源的应用覆盖。而且，这也可以通过 LaunchServices APIS 完成。

#### **libquarantine.dylib**

该库导出了多个可用于操作扩展属性字段的函数。

`qtn_file_*` APIs 处理文件 quarantine 策略，`qtn_proc_*` APIs 应用于进程（由进程创建的文件）。未导出的 `__qtn_syscall_quarantine*` 函数负责应用这些策略，它们会调用 `mac_syscall`，并将 `"Quarantine"` 作为第一个参数，从而向 `Quarantine.kext` 发送请求。

#### **Quarantine.kext**

该 kernel extension 仅存在于**系统上的 kernel cache** 中；不过，你可以从 [**https://developer.apple.com/**](https://developer.apple.com/) **下载 Kernel Debug Kit**，其中包含该 extension 的 symbolicated 版本。

该 Kext 会通过 MACF hook 多个调用，以便捕获所有文件生命周期事件：创建、打开、重命名、创建 hard link……甚至包括 `setxattr`，以阻止其设置 `com.apple.quarantine` 扩展属性。

它还使用了几个 MIB：

- `security.mac.qtn.sandbox_enforce`：强制在 Sandbox 中执行 quarantine
- `security.mac.qtn.user_approved_exec`：Quarantine 的进程只能执行已批准的文件

#### Provenance xattr（Ventura 及更高版本）

macOS 13 Ventura 引入了一种独立的 provenance 机制，该机制会在 quarantined app 首次获准运行时写入数据。<sup>[[2]](#references)</sup> 此时会创建两个 artefacts：

- `.app` bundle 目录上的 `com.apple.provenance` xattr（包含 primary key 和 flags 的固定大小二进制值）。
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` 中 ExecPolicy 数据库的 `provenance_tracking` 表中的一行，用于存储该 app 的 cdhash 和 metadata。

实际用途：
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect 是 macOS 内置的**反恶意软件**功能。XProtect 会在应用程序首次启动或被修改时，**根据其数据库中的已知恶意软件和不安全文件类型检查任何应用程序**。当你通过某些应用程序（例如 Safari、Mail 或 Messages）下载文件时，XProtect 会自动扫描该文件。如果文件与其数据库中的任何已知恶意软件匹配，XProtect 将**阻止文件运行**，并提醒你注意该威胁。

Apple 会**定期更新** XProtect 数据库，加入新的恶意软件定义，这些更新会自动下载并安装到你的 Mac 上。这可确保 XProtect 始终包含针对最新已知威胁的防护。

不过，需要注意的是，**XProtect 并不是功能完整的 antivirus 解决方案**。它只会检查特定的已知威胁列表，并且不会像大多数 antivirus 软件那样执行访问时扫描。

你可以通过运行以下命令获取最新 XProtect 更新的信息：
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect 位于 SIP 保护的位置 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**，在该 bundle 中可以找到 XProtect 使用的信息：

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**：允许具有这些 cdhash 的代码使用 legacy entitlements。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**：列出禁止通过 BundleID 和 TeamID 加载的 plugins 和 extensions，或指定最低版本。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**：用于检测 malware 的 Yara 规则。
- **`XProtect.bundle/Contents/Resources/gk.db`**：包含被阻止 applications 的 hashes 和 TeamIDs 的 SQLite3 数据库。

注意，**`/Library/Apple/System/Library/CoreServices/XProtect.app`** 中还有另一个与 XProtect 相关的 App，但它不参与 Gatekeeper 进程。

> XProtect Remediator：在现代 macOS 上，Apple 提供按需 scanner（XProtect Remediator），它们通过 launchd 定期运行，以检测并修复 malware 家族。你可以在 unified logs 中观察这些扫描：
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Not Gatekeeper

> [!CAUTION]
> 注意，Gatekeeper **不会在你每次执行 application 时运行**，只有 _**AppleMobileFileIntegrity**_ 会在你执行一个已经由 Gatekeeper 执行并验证过的 app 时，**验证 executable code signatures**。

因此，以前可以先执行一个 app，使其被 Gatekeeper 缓存，然后**修改 application 中的非 executable 文件**（例如 Electron asar 或 NIB 文件）；如果没有其他 protections，application 就会带着这些**恶意** additions 被**执行**。

然而，现在这已经不可能了，因为 macOS **会阻止修改 applications bundles 内的文件**。因此，如果你尝试使用 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack，就会发现它不再能够被 abuse：因为在执行 app 使其被 Gatekeeper 缓存后，你将无法修改 bundle。此外，如果你例如将 Contents directory 的名称更改为 NotCon（如 exploit 中所示），然后执行 app 的 main binary 以使其被 Gatekeeper 缓存，就会触发 error 且不会执行。

## Gatekeeper Bypasses

任何绕过 Gatekeeper 的方式（设法让 user 下载并执行某些内容，而 Gatekeeper 本应禁止该操作）都被视为 macOS 中的 vulnerability。以下是过去允许绕过 Gatekeeper 的 techniques 所对应的一些 CVEs：

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

有人发现，如果使用 **Archive Utility** 进行 extraction，**路径超过 886 个字符**的文件不会获得 com.apple.quarantine extended attribute。这种情况会意外地允许这些文件**绕过 Gatekeeper 的** security checks。<sup>[[5]](#references)</sup>

有关更多信息，请查看[**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)。<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

使用 **Automator** 创建 application 时，关于它需要如何执行的信息位于 `application.app/Contents/document.wflow` 中，而不在 executable 中。该 executable 只是一个名为 **Automator Application Stub** 的通用 Automator binary。

因此，你可以让 `application.app/Contents/MacOS/Automator\ Application\ Stub` **通过 symbolic link 指向 system 内另一个 Automator Application Stub**，这样它就会执行 `document.wflow` 中的内容（你的 script），**而不会触发 Gatekeeper**，因为实际的 executable 没有 quarantine xattr。<sup>[[6]](#references)</sup>

示例中的预期位置：`/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

有关更多信息，请查看[**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper)。<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

在此 bypass 中，创建 zip 文件时从 `application.app/Contents` 开始压缩 application，而不是从 `application.app` 开始。因此，**quarantine attr** 被应用到了 **`application.app/Contents` 中的所有 files**，但没有应用到 **`application.app`**；而 Gatekeeper 检查的正是后者。因此，Gatekeeper 被绕过了，因为触发 `application.app` 时，它**没有 quarantine attribute。**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
如需了解更多信息，请查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)。<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

即使组件不同，此漏洞的 exploitation 方式也与前一个漏洞非常相似。在本例中，我们将从 **`application.app/Contents`** 生成一个 Apple Archive，这样 **`application.app` 在被 **Archive Utility** 解压时就不会获得 quarantine attr**。<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)以获取更多信息。<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** 可用于阻止任何人向文件写入属性：
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
此外，**AppleDouble** 文件格式会复制文件，包括其 ACE。<sup>[[9]](#references)</sup>

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中可以看到，存储在名为 **`com.apple.acl.text`** 的 xattr 中的 ACL 文本表示将被设置为解压文件的 ACL。因此，如果你使用 **AppleDouble** 文件格式将一个应用程序压缩成 zip 文件，并为其设置了阻止写入其他 xattr 的 ACL……那么 quarantine xattr 就不会被设置到该应用程序中：
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)以获取更多信息。<sup>[[9]](#references)</sup>

请注意，这也可以通过 AppleArchives 加以利用：
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

据发现，由于 macOS 的一些内部问题，**Google Chrome 未能为下载的文件设置 quarantine 属性**。<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble 将文件的属性存储在一个单独的文件中，其名称以 `._` 开头；这有助于**在 macOS 机器之间**复制文件属性。但是，解压缩 AppleDouble 文件后，以 `._` 开头的文件**未被赋予 quarantine 属性**。<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
能够创建一个不会设置 quarantine 属性的文件，就**可以绕过 Gatekeeper。**具体方法是使用 AppleDouble 命名约定（以 `._` 开头）创建一个 **DMG 文件应用程序**，然后创建一个**可见文件**，将其作为指向这个没有 quarantine 属性的隐藏文件的符号链接。\
当**执行 dmg 文件**时，由于它没有 quarantine 属性，就会**绕过 Gatekeeper**。
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

Apple 通过改进检查，修复了 macOS Sonoma 14.0 中的 LaunchServices 逻辑错误。公开 advisory 仅说明某个 app 可以绕过 Gatekeeper，因此不要仅根据 CVE 条目推断具体的载体格式或 exploitation chain。<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4（2024 年 3 月发布）中的一个 Gatekeeper bypass 源于 `libarchive` 对恶意 ZIP 的处理缺陷，允许 app 规避 assessment。请更新到 14.4 或更高版本，Apple 已在其中修复该问题。<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

嵌入下载 app 中的 **Automator Quick Action workflow** 可以在未经 Gatekeeper assessment 的情况下触发，因为 workflow 被视为数据，并由 Automator helper 在正常 notarization 提示路径之外执行。因此，捆绑了可运行 shell script 的 Quick Action 的 crafted `.app`（例如位于 `Contents/PlugIns/*.workflow/Contents/document.wflow` 中）可能在启动时立即执行。Apple 在 Ventura **13.7**、Sonoma **14.7** 和 Sequoia **15** 中增加了额外的 consent dialog，并修复了 assessment path。<sup>[[3]](#references)</sup>

### 在 extraction 和 copy 边界处的 Quarantine propagation failures

一项 2024 年的研究发现，在测试版本的 iZip（ZIP/TAR/7Z）、Archiver（ARCHIVER/ZIP/TAR/7Z）、BetterZip（ZIP/TAR/7Z）、WinRAR（ZIP/TAR/7Z）和 7z Utility（DMG/ZIP/7Z）中存在 propagation gaps；研究还观察到，在 VMware Tools 的 host-to-guest copy 过程中该 attribute 会丢失。此后，多家 vendor 宣布修复，因此应将这些名称视为进行**version-specific retesting**的线索，而不是永久性的 vulnerable-software list。同样的 trust-boundary 问题也适用于 native Unix workflows：`curl`/`scp` 不会添加 quarantine，而 command-line `tar`/`unzip` 不会自动从 carrier archive 继承它。<sup>[[15]](#references)</sup>

对于 offensive testing，请在每次经过 **browser、mail client、archive、disk-image、cloud-sync、shared-folder 和 VM-copy** transition 后，对 carrier 和最终 app 进行比较。明确的 `spctl` rejection 不会修复缺失的 xattr：如果没有 quarantine，正常的首次打开 Gatekeeper path 可能根本不会请求该 assessment。<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg（来自此 [演讲](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)）

- 创建一个包含 app 的目录。
- 为 app 添加 uchg。
- 将 app 压缩为 tar.gz 文件。
- 将 tar.gz 文件发送给受害者。
- 受害者打开 tar.gz 文件并运行 app。
- Gatekeeper 不会检查该 app。<sup>[[12]](#references)</sup>

### Prevent Quarantine xattr

如果 ".app" bundle 未添加 quarantine xattr，执行它时 **Gatekeeper 不会被触发**。

参见 [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks)，了解可阻止或丢弃 extended attributes 的基于 filesystem、flag、ACL 和 AppleDouble 的 primitives。



## References

- [1] [Apple Platform Security：关于 macOS Sonoma 14.4 的安全内容（包括 CVE-2024-27853）](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light：macOS 现在如何跟踪 app 的来源](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple：关于 macOS Sonoma 14.7 / Ventura 13.7 的安全内容（CVE-2024-44128）](https://support.apple.com/en-us/121234)
- [4] [MacRumors：macOS 15 Sequoia 移除了 Control‑click“Open”Gatekeeper bypass](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs：CVE-2021-1810 的发现](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990，绕过 macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs 发现可用于 Gatekeeper bypass 的 Safari vulnerability](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs 发现可用于 Gatekeeper bypass 的 macOS Archive Utility vulnerability（CVE-2022-32910）](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper 的 Achilles heel：挖掘 macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure：发现 Gatekeeper Bypass（CVE-2023-27943）](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [借助 Mac Monitor 发现并报告 Gatekeeper bypass exploit](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023：绕过 macOS Security and Privacy Mechanisms——从 Gatekeeper 到 System Integrity Protection（Koh Nakagawa）](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple：关于 macOS Sonoma 14 的安全内容（CVE-2023-41067）](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums：Testing a notarised product](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42：Gatekeeper Bypass——揭示 macOS Security Mechanism 中的 weaknesses](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
