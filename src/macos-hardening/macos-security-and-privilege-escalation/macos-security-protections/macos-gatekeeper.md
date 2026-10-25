# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** 是为 Mac 操作系统开发的一项安全功能，旨在确保用户的系统**只运行可信软件**。它会**验证软件**，检查用户从 **App Store 以外的来源**（例如应用、插件或安装包）下载并尝试打开的软件。

Gatekeeper 的核心机制是其**验证**流程。它会检查下载的软件是否由**受认可的开发者签名**，以确保软件的真实性。此外，它还会确认软件是否经过 Apple **公证**，以确保软件不包含已知恶意内容，并且在公证后未被篡改。

此外，Gatekeeper 通过**提示用户批准首次打开**下载的软件，进一步增强用户控制能力和安全性。这项保护措施有助于防止用户误将可能有害的可执行代码当作无害的数据文件而运行。

### Application Signatures

应用签名，也称为代码签名，是 Apple 安全基础设施的重要组成部分。它们用于**验证软件作者（开发者）的身份**，并确保代码自上次签名后未被篡改。

其工作原理如下：

1. **签署应用：** 开发者准备发布应用时，会**使用私钥为应用签名**。此私钥与 Apple 在开发者加入 Apple Developer Program 时颁发的**证书相关联**。签名过程会为应用的所有部分生成加密哈希，并使用开发者的私钥加密该哈希。
2. **分发应用：** 签名后的应用会与开发者证书一同分发给用户，证书中包含对应的公钥。
3. **验证应用：** 用户下载并尝试运行应用时，Mac 操作系统会使用开发者证书中的公钥解密哈希。随后，系统会根据应用的当前状态重新计算哈希，并将其与解密后的哈希进行比较。如果两者匹配，说明**应用自开发者签名后未被修改**，系统便会允许运行该应用。

应用签名是 Apple Gatekeeper 技术的重要组成部分。用户尝试**打开从互联网下载的应用**时，Gatekeeper 会验证应用签名。如果应用使用 Apple 为已知开发者颁发的证书签名，且代码未被篡改，Gatekeeper 就会允许运行该应用。否则，它会阻止该应用并提醒用户。

从 macOS Catalina 开始，**Gatekeeper 还会检查应用是否经过 Apple 公证**，以增加一层安全保护。公证流程会检查应用是否存在已知安全问题和恶意代码；如果检查通过，Apple 会为应用添加一个 Gatekeeper 可验证的票据。

#### Check Signatures

检查某个 **malware 样本**时，应始终**检查二进制文件的签名**，因为签署该文件的**开发者**可能已经与 **malware** **相关联**。

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

Apple 的公证流程是一项额外的保护措施，旨在保护用户免受潜在有害软件的侵害。该流程要求**开发者将其应用提交给** **Apple 的公证服务**进行检查；请勿将其与 App Review 混淆。该服务是一个**自动化系统**，会检查提交的软件是否包含**恶意内容**，以及代码签名是否存在潜在问题。

如果软件通过检查且未发现任何问题，公证服务就会生成一张公证票据。开发者随后需要**将这张票据附加到软件上**，这个过程称为“stapling”。此外，公证票据也会发布到网上，供 Apple 的安全技术 Gatekeeper 获取。

用户首次安装或运行软件时，无论公证票据是 stapled 到可执行文件上，还是在线获取，**都会告知 Gatekeeper 该软件已由 Apple 公证**。因此，Gatekeeper 会在首次启动对话框中显示一条说明性消息，表明 Apple 已检查该软件是否包含恶意内容。这个流程可以增强用户对其在系统上安装或运行的软件安全性的信心。

### spctl & syspolicyd

> [!CAUTION]
> 请注意，从 Sequoia 版本开始，**`spctl`** 不再允许修改 Gatekeeper 配置。

**`spctl`** 是用于枚举和与 Gatekeeper 交互的 CLI 工具（通过 XPC 消息与 `syspolicyd` 守护进程交互）。例如，可以通过以下方式查看 GateKeeper 的**状态**：

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> 请注意，GateKeeper 只会对带有 **Quarantine 属性**的文件执行签名检查，而不是检查每个文件。

GateKeeper 会根据**偏好设置和签名**检查是否可以执行某个二进制文件：

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** 是负责强制执行 Gatekeeper 的主要守护进程。它维护一个位于 `/var/db/SystemPolicy` 的数据库，可以在[此处](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)找到支持该数据库的代码，并在[此处](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)找到 SQL 模板。请注意，该数据库不受 SIP 限制，root 可写入；数据库 `/var/db/.SystemPolicy-default` 则用作原始备份，以便在另一个数据库损坏时使用。

此外，bundle **`/var/db/gke.bundle`** 和 **`/var/db/gkopaque.bundle`** 中包含会被插入数据库的规则文件。你可以以 root 身份检查此数据库：

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

**`syspolicyd`** 还会通过 XPC server 暴露不同的操作，例如 `assess`、`update`、`record` 和 `cancel`。这些操作也可以通过 **`Security.framework` 的 `SecAssessment*`** APIs 访问，而 **`spctl`** 实际上会通过 XPC 与 **`syspolicyd`** 通信。

注意，第一条规则以“**App Store**”结尾，第二条以“**Developer ID**”结尾；并且在前一张图片中，设置为**允许执行来自 App Store 和已识别开发者的应用**。\
如果将该设置**修改**为 App Store，“**Notarized Developer ID**”规则就会消失。

此外，还有数千条**类型为 GKE** 的规则：

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

这些哈希来自：

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

或者，你也可以通过以下方式列出之前的信息：

```bash
sudo spctl --list
```

**`spctl`** 的 **`--master-disable`** 和 **`--global-disable`** 选项会彻底**禁用**这些签名检查：

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

可以使用以下命令**检查 GateKeeper 是否允许某个 App**：

```bash
spctl --assess -v /Applications/App.app
```

在 macOS 14 及更高版本中，**`syspolicy_check`** 是在分发前对应用程序包进行检查的实用高级工具。与单独的 `spctl` 结果相比，它能提供更具可操作性的可信执行诊断信息。不过，Apple 仍建议测试真实的下载、解压和首次启动流程，因为这也能验证 quarantine 属性是否会随文件传递。<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

可以在 GateKeeper 中添加新规则，以允许执行某些应用：

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

关于 **内核扩展**，文件夹 `/var/db/SystemPolicyConfiguration` 中包含允许加载的 kext 列表。此外，`spctl` 拥有 `com.apple.private.iokit.nvram-csr` entitlement，因为它能够添加新的预先批准的内核扩展；这些扩展也需要保存到 NVRAM 的 `kext-allowed-teams` 键中。

#### 在 macOS 15（Sequoia）及更高版本中管理 Gatekeeper

- 长期存在的 Finder **Ctrl+Open / 右键单击 → 打开**绕过方式已被移除；首次出现拦截对话框后，用户必须前往**系统设置 → 隐私与安全性 → 仍要打开**，明确允许被拦截的应用。<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` 不再接受作为无人值守的策略更改。修改规则数据库或全局评估状态的操作已弃用，因此应使用 `spctl` 进行评估，并通过 UI 或 MDM 配置强制措施。

从 macOS 15 Sequoia 开始，最终用户无法再通过 `spctl` 切换 Gatekeeper 策略。应通过系统设置管理，或部署包含 `com.apple.systempolicy.control` payload 的 MDM 配置描述文件。允许 App Store 和已识别开发者（但不允许“任何来源”）的配置描述文件片段示例：

<details>
<summary>允许 App Store 和已识别开发者的 MDM 配置描述文件</summary>

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

### 隔离文件

**下载**应用程序或文件时，某些 macOS **应用程序**（例如 Web 浏览器或电子邮件客户端）会为下载的文件**附加扩展文件属性**，通常称为“**隔离标记**”。此属性是一种安全措施，用于**标记文件**来自不受信任的来源（互联网），并可能带有风险。不过，并非所有应用程序都会附加此属性，例如，常见的 BitTorrent 客户端软件通常会绕过此流程。

**当用户尝试执行文件时，隔离标记的存在会触发 macOS 的 Gatekeeper 安全功能**。

如果**不存在隔离标记**（例如通过某些 BitTorrent 客户端下载的文件），Gatekeeper **可能不会执行检查**。因此，用户应谨慎打开从安全性较低或未知来源下载的文件。

> [!NOTE] > **检查**代码签名的**有效性**是一个**资源密集型**过程，其中包括为代码及其所有捆绑资源生成加密**哈希**。此外，检查证书有效性还需要**在线检查** Apple 的服务器，以确认该证书在签发后是否已被撤销。出于这些原因，每次启动应用时都执行完整的代码签名和公证检查并**不切实际**。
>
> 因此，**只有在执行带有隔离属性的应用时，才会运行这些检查。**

> [!WARNING]
> 此属性必须由**创建/下载**文件的应用程序**设置**。
>
> 不过，沙盒化的文件会为其创建的每个文件设置此属性。非沙盒应用也可以自行设置此属性，或在 **Info.plist** 中指定 [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) 键，以使系统为所创建的文件设置 `com.apple.quarantine` 扩展属性，

此外，调用 **`qtn_proc_apply_to_self`** 的进程所创建的所有文件都会被隔离。或者，API **`qtn_file_apply_to_path`** 会为指定的文件路径添加隔离属性。

可以通过以下方式**检查其状态并启用/禁用**（需要 root 权限）：

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

检查 **扩展** **属性**的 **值**，并通过以下命令找出写入 quarantine 属性的应用程序：

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

实际上，进程“可以为其创建的文件设置 quarantine 标志”（我已经尝试在创建的文件中设置 USER_APPROVED 标志，但没有成功）：

<details>

<summary>应用 quarantine 标志的源代码</summary>

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

并使用以下方式**移除**该属性：

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

并使用以下命令查找所有被隔离的文件：

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Quarantine 信息也存储在由 LaunchServices 管理的中央数据库 **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** 中，GUI 可通过该数据库获取文件来源信息。此外，应用程序也可能会覆盖这些信息以隐藏其来源。也可以通过 LaunchServices API 执行此操作。

#### **libquarantine.dylib**

此库导出了多个可用于操作扩展属性字段的函数。

`qtn_file_*` API 用于处理文件隔离策略，`qtn_proc_*` API 则应用于进程（由该进程创建的文件）。未导出的 `__qtn_syscall_quarantine*` 函数负责应用这些策略；它们会将 "Quarantine" 作为第一个参数调用 `mac_syscall`，从而将请求发送到 `Quarantine.kext`。

#### **Quarantine.kext**

此内核扩展仅存在于系统的 **内核缓存中**；不过，你_可以_从 [**https://developer.apple.com/**](https://developer.apple.com/) 下载 **Kernel Debug Kit**，其中包含经过符号化处理的扩展版本。

此 Kext 会通过 MACF hook 多个调用，以拦截所有文件生命周期事件：创建、打开、重命名、创建硬链接……甚至包括 `setxattr`，以阻止其设置 `com.apple.quarantine` 扩展属性。

它还使用了几个 MIB：

- `security.mac.qtn.sandbox_enforce`：在 Sandbox 中强制执行 quarantine
- `security.mac.qtn.user_approved_exec`：被 quarantine 的进程只能执行已批准的文件

#### Ventura 及更高版本中的 Provenance xattr

macOS 13 Ventura 引入了一种独立的 provenance 机制，该机制会在首次允许运行被 quarantine 的应用时填充。<sup>[[2]](#references)</sup> 此机制会创建两个工件：

- `.app` bundle 目录上的 `com.apple.provenance` xattr（包含主键和标志的定长二进制值）。
- ExecPolicy 数据库 `/var/db/SystemPolicyConfiguration/ExecPolicy/` 中 `provenance_tracking` 表的一行记录，用于存储应用的 cdhash 和元数据。

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

XProtect 是 macOS 内置的**反恶意软件**功能。XProtect 会在应用首次启动或修改时，**将其与已知恶意软件和不安全文件类型的数据库进行检查**。当你通过 Safari、Mail 或 Messages 等特定应用下载文件时，XProtect 会自动扫描该文件。如果文件与数据库中的任何已知恶意软件匹配，XProtect 将**阻止该文件运行**并向你发出威胁警告。

Apple 会**定期更新** XProtect 数据库，加入新的恶意软件定义，并自动将这些更新下载并安装到你的 Mac 上。这确保 XProtect 始终包含最新的已知威胁信息。

不过，需要注意的是，**XProtect 并非功能齐全的防病毒解决方案**。它只会检查特定列表中的已知威胁，不会像大多数防病毒软件那样执行访问时扫描。

你可以通过运行以下命令获取最新 XProtect 更新的信息：

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect 位于受 SIP 保护的位置 **/Library/Apple/System/Library/CoreServices/XProtect.bundle**，在 bundle 内可以找到 XProtect 使用的信息：

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**：允许具有这些 cdhash 的代码使用 legacy entitlements。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**：列出禁止加载的插件和扩展，依据 BundleID 和 TeamID 进行限制，或指定最低版本。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**：用于检测 malware 的 Yara 规则。
- **`XProtect.bundle/Contents/Resources/gk.db`**：包含被阻止应用和 TeamID 哈希值的 SQLite3 数据库。

请注意，**`/Library/Apple/System/Library/CoreServices/XProtect.app`** 中还有另一个与 XProtect 相关的 App，但它不参与 Gatekeeper 进程。

> XProtect Remediator：在现代 macOS 上，Apple 提供按需扫描器（XProtect Remediator），它们通过 launchd 定期运行，以检测并修复各种 malware。你可以在 unified logs 中查看这些扫描：
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### 非 Gatekeeper

> [!CAUTION]
> 请注意，Gatekeeper **并不会在每次执行应用程序时都运行**，只有 _**AppleMobileFileIntegrity**_ (AMFI) 会在你执行一个已由 Gatekeeper 执行并验证过的应用时，**验证可执行代码签名**。

因此，以前可以先执行应用，让 Gatekeeper 缓存它，然后**修改应用程序中非可执行文件**（例如 Electron asar 或 NIB 文件）；如果没有其他保护措施，应用程序就会带着这些**恶意**内容被**执行**。

不过，现在这已不可能，因为 macOS **会阻止修改应用程序包内的文件**。因此，如果你尝试 [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 攻击，会发现它已无法被利用：执行应用让 Gatekeeper 缓存它之后，你将无法修改应用程序包。并且，如果你像 exploit 中所示，将 Contents 目录改名为 NotCon，然后执行应用的主二进制文件，让 Gatekeeper 缓存它，就会触发错误，且无法执行。

## Gatekeeper 绕过

任何绕过 Gatekeeper 的方式（设法让用户下载并执行本应被 Gatekeeper 禁止的内容）都被视为 macOS 中的漏洞。以下是过去为能够绕过 Gatekeeper 的技术分配的一些 CVE：

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

研究发现，如果使用 **Archive Utility** 解压，**路径超过 886 个字符**的文件不会获得 com.apple.quarantine 扩展属性。这种情况会意外地允许这些文件**绕过 Gatekeeper 的**安全检查。<sup>[[5]](#references)</sup>

如需了解更多信息，请查看[**原始报告**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)。<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

使用 **Automator** 创建应用程序时，关于其需要执行什么的信息位于 `application.app/Contents/document.wflow` 中，而不在可执行文件内。可执行文件只是一个名为 **Automator Application Stub** 的通用 Automator 二进制文件。

因此，你可以让 `application.app/Contents/MacOS/Automator\ Application\ Stub` **通过符号链接指向系统中的另一个 Automator Application Stub**，这样它就会执行 `document.wflow` 中的内容（你的脚本），**而不会触发 Gatekeeper**，因为实际的可执行文件没有 quarantine xattr。<sup>[[6]](#references)</sup>

预期位置示例：`/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

如需了解更多信息，请查看[**原始报告**](https://ronmasas.com/posts/bypass-macos-gatekeeper)。<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

在这种绕过方法中，创建 zip 文件时，从 `application.app/Contents` 开始压缩应用程序，而不是从 `application.app` 开始。因此，**quarantine attr** 被应用到 `application.app/Contents` 中的所有**文件**，但**没有应用到 `application.app`**；而 Gatekeeper 检查的正是 `application.app`。因此，当触发 `application.app` 时，它**没有 quarantine 属性**，从而绕过了 Gatekeeper。<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

如需了解更多信息，请查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)。<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

即使组件不同，此漏洞的利用方式也与前一个非常相似。在这种情况下，我们将从 **`application.app/Contents`** 创建 Apple Archive，这样 **Archive Utility** 解压后，**`application.app`** 就不会带有 quarantine 属性。<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

查看[**原始报告**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)了解更多信息。<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** 可用于阻止任何人向文件写入属性：

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

此外，**AppleDouble** 文件格式会复制文件及其 ACE。<sup>[[9]](#references)</sup>

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中可以看到，存储在名为 **`com.apple.acl.text`** 的 xattr 中的 ACL 文本表示会被设置为解压后文件的 ACL。因此，如果你使用 **AppleDouble** 文件格式将应用程序压缩为 zip 文件，并为其设置了禁止写入其他 xattr 的 ACL……隔离 xattr 就不会被设置到该应用程序上：

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

如需了解更多信息，请查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)。<sup>[[9]](#references)</sup> 有关 sidecar 的构造和验证步骤，请参阅 [AppleDouble/ACL reproduction](macos-fs-tricks/macos-xattr-acls-extra-stuff.md)。

请注意，也可以利用 AppleArchives 发起攻击：

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

研究人员发现，由于 macOS 的一些内部问题，**Google Chrome 没有为下载的文件设置 quarantine attribute**。<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble 会将文件的属性存储在一个单独的文件中，该文件名以 `._` 开头；这有助于在 **macOS 设备之间**复制文件属性。然而，解压 AppleDouble 文件后，以 `._` 开头的文件**没有被设置 quarantine attribute**。<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

能够创建一个不会设置 quarantine attribute 的文件，因此**可以绕过 Gatekeeper。**诀窍是使用 AppleDouble 命名约定（以 `._` 开头）创建一个 **DMG 文件应用**，并创建一个指向这个没有 quarantine attribute 的隐藏文件的**可见符号链接**。\
**执行 dmg 文件时**，由于它没有 quarantine attribute，因此会**绕过 Gatekeeper**。

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

Apple 通过改进检查，修复了 macOS Sonoma 14.0 中的 LaunchServices 逻辑错误。公开公告仅指出某个 app 可能绕过 Gatekeeper，因此不要仅凭 CVE 条目推断具体的载体格式或利用链。<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4（2024 年 3 月发布）中的 Gatekeeper 绕过问题源于 `libarchive` 对恶意 ZIP 文件的处理，使 app 能逃过评估。请更新至 14.4 或更高版本；Apple 已在这些版本中修复此问题。<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

下载的 app 中嵌入的 **Automator Quick Action workflow** 可能在未经 Gatekeeper 评估的情况下触发，因为 workflow 被视为数据，并由 Automator helper 在常规公证提示流程之外执行。因此，精心构造的 `.app` 若捆绑了一个运行 shell script 的 Quick Action（例如，位于 `Contents/PlugIns/*.workflow/Contents/document.wflow` 中），就可能在启动时立即执行。Apple 在 Ventura **13.7**、Sonoma **14.7** 和 Sequoia **15** 中添加了额外的同意对话框，并修复了评估流程。<sup>[[3]](#references)</sup>

### 解压和复制边界处的 Quarantine 传播故障

一项 2024 年的研究在测试版本的 iZip (ZIP/TAR/7Z)、Archiver (ARCHIVER/ZIP/TAR/7Z)、BetterZip (ZIP/TAR/7Z)、WinRAR (ZIP/TAR/7Z) 和 7z Utility (DMG/ZIP/7Z) 中发现了传播缺口；研究还观察到，在 VMware Tools 的主机到客户机复制过程中，该属性会丢失。随后有几家供应商宣布推出修复，因此应将这些名称视为**需要按版本重新测试**的线索，而不是永久易受攻击的软件列表。同样的信任边界问题也适用于原生 Unix 工作流：`curl`/`scp` 不会添加 quarantine，而命令行 `tar`/`unzip` 也不会自动从载体归档文件继承该属性。<sup>[[15]](#references)</sup>

进行攻击性测试时，应在每次浏览器、邮件客户端、归档工具、磁盘映像、云同步、共享文件夹和 VM 复制转换后，对比载体和最终 app。明确的 `spctl` 拒绝并不能修复缺失的 xattr：如果没有 quarantine，常规的首次打开 Gatekeeper 流程可能根本不会请求该评估。<sup>[[15]](#references)</sup>

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

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- 创建一个包含 app 的目录。
- 为 app 添加 uchg。
- 将 app 压缩为 tar.gz 文件。
- 将 tar.gz 文件发送给受害者。
- 受害者打开 tar.gz 文件并运行 app。
- Gatekeeper 不会检查该 app。<sup>[[12]](#references)</sup>

### 阻止 Quarantine xattr

如果 ".app" bundle 没有添加 quarantine xattr，执行时 **Gatekeeper 不会被触发**。

参见 [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks)，了解可阻止或丢弃扩展属性的基于文件系统、标志、ACL 和 AppleDouble 的原语。





## References

- [1] [Apple Platform Security：关于 macOS Sonoma 14.4 的安全性内容（包括 CVE-2024-27853）](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light：macOS 现在如何追踪 app 的来源](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple：关于 macOS Sonoma 14.7 / Ventura 13.7 的安全性内容（CVE-2024-44128）](https://support.apple.com/en-us/121234)
- [4] [MacRumors：macOS 15 Sequoia 移除了通过 Control‑click“打开”绕过 Gatekeeper 的方法](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs：CVE-2021-1810 的发现](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990：绕过 macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs 发现 Safari 漏洞，可绕过 Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs 发现 macOS Archive Utility 漏洞，可绕过 Gatekeeper（CVE-2022-32910）](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper 的致命弱点：挖掘 macOS 漏洞](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure：发现 Gatekeeper 绕过漏洞（CVE-2023-27943）](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [借助 Mac Monitor 发现并报告 Gatekeeper 绕过漏洞](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023：绕过 macOS 安全与隐私机制——从 Gatekeeper 到 System Integrity Protection（Koh Nakagawa）](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple：关于 macOS Sonoma 14 的安全性内容（CVE-2023-41067）](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums：测试经过公证的产品](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42：绕过 Gatekeeper——揭示 macOS 安全机制中的弱点](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
