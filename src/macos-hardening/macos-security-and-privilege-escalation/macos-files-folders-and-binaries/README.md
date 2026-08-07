# macOS 文件、文件夹、二进制文件与内存

{{#include ../../../banners/hacktricks-training.md}}

## 文件层次结构布局

- **/Applications**：已安装的应用程序应位于此处。所有用户都可以访问它们。
- **/bin**：命令行二进制文件
- **/cores**：如果存在，则用于存储 core dump
- **/dev**：所有内容都被视为文件，因此你可能会看到存储在此处的硬件设备。
- **/etc**：配置文件
- **/Library**：这里可以找到许多与偏好设置、缓存和日志相关的子目录和文件。根目录以及每个用户的目录中都存在一个 Library 文件夹。
- **/private**：未公开说明，但许多上述文件夹都是指向 private 目录的 symbolic link。
- **/sbin**：必要的系统二进制文件（与管理相关）
- **/System**：用于使 OS X 运行的文件。这里主要应当只有 Apple 特定的文件（而不是第三方文件）。
- **/tmp**：文件会在 3 天后删除（它是指向 /private/tmp 的软链接）
- **/Users**：用户的主目录。
- **/usr**：配置文件和系统二进制文件
- **/var**：日志文件
- **/Volumes**：已挂载的驱动器会出现在这里。
- **/.vol**：运行 `stat a.txt` 时，你会获得类似 `16777223 7545753 -rw-r--r-- 1 username wheel ...` 的输出，其中第一个数字是文件所在卷的 ID，第二个数字是 inode 编号。使用这些信息运行 `cat /.vol/16777223/7545753`，即可通过 /.vol/ 访问该文件的内容。

### 应用程序文件夹

- **系统应用程序** 位于 `/System/Applications`
- **已安装的** 应用程序通常安装在 `/Applications` 或 `~/Applications`
- **应用程序数据** 可以在以 root 身份运行的应用程序的 `/Library/Application Support` 中找到，也可以在以用户身份运行的应用程序的 `~/Library/Application Support` 中找到。
- 需要以 **root 身份运行** 的第三方应用程序 **守护进程** 通常位于 `/Library/PrivilegedHelperTools/`
- **Sandboxed** 应用程序会映射到 `~/Library/Containers` 文件夹中。每个应用程序都有一个按照应用程序 bundle ID（`com.apple.Safari`）命名的文件夹。
- **内核** 位于 `/System/Library/Kernels/kernel`
- **Apple 的内核扩展** 位于 `/System/Library/Extensions`
- **第三方内核扩展** 存储在 `/Library/Extensions`

### 包含敏感信息的文件

MacOS 会在多个位置存储密码等信息：


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 易受攻击的 pkg 安装程序


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X 特有扩展名

- **`.dmg`**：Apple Disk Image 文件在安装程序中非常常见。
- **`.kext`**：它必须遵循特定结构，是 OS X 版本的驱动程序。（它是一个 bundle）
- **`.plist`**：也称为 property list，以 XML 或二进制格式存储信息。
- 可以是 XML 或二进制格式。二进制文件可以使用以下命令读取：
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**：遵循目录结构的 Apple 应用程序（它是一个 bundle）。
- **`.dylib`**：动态库（类似于 Windows DLL 文件）
- **`.pkg`**：与 xar（eXtensible Archive format）相同。可以使用 installer 命令安装这些文件的内容。
- **`.DS_Store`**：每个目录中都有此文件，用于保存该目录的属性和自定义设置。
- **`.Spotlight-V100`**：此文件夹出现在系统每个卷的根目录中。
- **`.metadata_never_index`**：如果此文件位于卷的根目录，Spotlight 将不会为该卷建立索引。
- **`.noindex`**：带有此扩展名的文件和文件夹不会被 Spotlight 建立索引。
- **`.sdef`**：bundle 内的文件，用于指定如何通过 AppleScript 与应用程序进行交互。

### macOS Bundles

bundle 是一个 **目录**，在 Finder 中**看起来像一个对象**（bundle 的示例是 `*.app` 文件）。


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache（SLC）

在 macOS（以及 iOS）上，所有系统共享库（例如 frameworks 和 dylibs）都被**合并到一个文件中**，称为 **dyld shared cache**。这提升了性能，因为代码可以更快地加载。

在 macOS 中，该文件位于 `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`；在旧版本中，你可能可以在 **`/System/Library/dyld/`** 中找到 **shared cache**。\
在 iOS 中，你可以在 **`/System/Library/Caches/com.apple.dyld/`** 中找到它们。

与 dyld shared cache 类似，内核和内核扩展也会被编译到 kernel cache 中，并在启动时加载。

为了从单个 dylib shared cache 文件中提取库，可以使用二进制文件 [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip)，但它现在可能无法正常工作；你也可以使用 [**dyldextractor**](https://github.com/arandomdev/dyldextractor)：
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> 请注意，即使 `dyld_shared_cache_util` 工具无法正常工作，你也可以将 **shared dyld binary 传入 Hopper**，Hopper 将能够识别所有库，并让你**选择要调查的库**：

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

由于 dylib 使用硬编码地址进行了预链接，某些提取器可能无法工作，因此它们可能会跳转到未知地址

> [!TIP]
> 也可以在 macos 中使用 Xcode 中的 emulator 下载其他 \*OS 设备的 Shared Library Cache。它们将被下载到：ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`，例如：`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** 使用 syscall **`shared_region_check_np`** 确认 SLC 是否已被映射（该 syscall 会返回地址），并使用 **`shared_region_map_and_slide_np`** 映射 SLC。

请注意，即使 SLC 在首次使用时会进行 slide，所有 **processes** 也会使用**同一个副本**；如果 attacker 能够在系统中运行 processes，这就会**消除 ASLR** 保护。过去实际上曾利用过这一点，后来通过 shared region pager 进行了修复。

Branch pools 是一些小型 Mach-O dylib，它们会在 image mappings 之间创建小空间，从而使 interpose 函数变得不可能。

### Override SLCs

使用以下 env variables：

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> 这将允许加载新的 shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`**，并手动将 libraries 替换为指向 shared cache 中真实 libraries 的 symlinks（你需要先提取它们）

## Special File Permissions

### Folder permissions

在 **folder** 中，**read** 权限允许**列出其中的内容**，**write** 权限允许**删除文件**以及向其中**写入文件**，而 **execute** 权限允许**遍历**该 directory。因此，例如，某个用户虽然对 directory 中的某个 **file** 拥有 **read permission**，但如果他没有 **execute** permission，就**无法读取**该 file。

### Flag modifiers

某些 flags 可以设置在 files 上，使 file 的行为有所不同。你可以使用 `ls -lO /path/directory` **检查** directory 中 files 的 flags。

- **`uchg`**：称为 **uchange** flag，会**阻止任何修改或删除**该 **file** 的操作。设置方式：`chflags uchg file.txt`
- root user 可以**移除该 flag** 并修改 file
- **`restricted`**：此 flag 会使 file **受到 SIP 保护**（你无法向 file 添加此 flag）。
- **`Sticky bit`**：如果某个 directory 设置了 sticky bit，**只有该 directory 的 owner 或 root 才能重命名或删除** files。通常会在 /tmp directory 上设置此 flag，以防止普通 users 删除或移动其他 users 的 files。

所有 flags 都可以在 `sys/stat.h` 文件中找到（使用 `mdfind stat.h | grep stat.h` 查找），具体如下：

- `UF_SETTABLE` 0x0000ffff：owner 可更改 flags 的掩码。
- `UF_NODUMP` 0x00000001：不 dump file。
- `UF_IMMUTABLE` 0x00000002：file 不得更改。
- `UF_APPEND` 0x00000004：对 file 的写入只能追加。
- `UF_OPAQUE` 0x00000008：相对于 union，directory 是 opaque 的。
- `UF_COMPRESSED` 0x00000020：file 已压缩（某些 file-systems）。
- `UF_TRACKED` 0x00000040：设置此 flag 的 files 不会收到删除/重命名通知。
- `UF_DATAVAULT` 0x00000080：读取和写入需要 entitlement。
- `UF_HIDDEN` 0x00008000：提示此 item 不应在 GUI 中显示。
- `SF_SUPPORTED` 0x009f0000：superuser 支持的 flags 的掩码。
- `SF_SETTABLE` 0x3fff0000：superuser 可更改 flags 的掩码。
- `SF_SYNTHETIC` 0xc0000000：system 只读 synthetic flags 的掩码。
- `SF_ARCHIVED` 0x00010000：file 已归档。
- `SF_IMMUTABLE` 0x00020000：file 不得更改。
- `SF_APPEND` 0x00040000：对 file 的写入只能追加。
- `SF_RESTRICTED` 0x00080000：写入需要 entitlement。
- `SF_NOUNLINK` 0x00100000：item 不得被移除、重命名或挂载。
- `SF_FIRMLINK` 0x00800000：file 是 firmlink。
- `SF_DATALESS` 0x40000000：file 是 dataless object。

### **File ACLs**

File **ACLs** 包含 **ACE**（Access Control Entries），可以为不同 users 分配更加**细粒度的权限**。

可以为 **directory** 授予以下 permissions：`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
而 **file** 可以授予：`read`、`write`、`append`、`execute`。

当 file 包含 ACLs 时，**列出 permissions 时会看到一个 "+"，例如**：
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
你可以使用以下命令**读取**文件的 ACL：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
你可以使用以下命令查找**所有带有 ACL 的文件**（这非常慢）：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 扩展属性

扩展属性包含一个名称和任意所需的值，可以使用 `ls -@` 查看，并使用 `xattr` 命令进行操作。一些常见的扩展属性包括：

- `com.apple.resourceFork`: Resource fork 兼容性。也可显示为 `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS：Gatekeeper quarantine 机制 (III/6)
- `metadata:*`: MacOS：各种 metadata，例如 `_backup_excludeItem` 或 `kMD*`
- `com.apple.lastuseddate` (#PS): 文件最后使用日期
- `com.apple.FinderInfo`: MacOS：Finder 信息（例如颜色 Tags）
- `com.apple.TextEncoding`: 指定 ASCII 文本文件的文本编码
- `com.apple.logd.metadata`: 由 logd 用于 `/var/db/diagnostics` 中的文件
- `com.apple.genstore.*`: Generational storage（文件系统根目录中的 `/.DocumentRevisions-V100`）
- `com.apple.rootless`: MacOS：由 System Integrity Protection 用于标记文件 (III/10)
- `com.apple.uuidb.boot-uuid`: logd 使用唯一 UUID 标记启动 epoch
- `com.apple.decmpfs`: MacOS：透明文件压缩 (II/7)
- `com.apple.cprotect`: \*OS：每个文件的加密数据 (III/11)
- `com.apple.installd.*`: \*OS：由 installd 使用的 metadata，例如 `installType`、`uniqueInstallID`

### Resource Forks | macOS ADS

这是在 **MacOS** 机器上获取 **Alternate Data Streams** 的一种方法。通过将内容保存到文件中的扩展属性 **com.apple.ResourceFork**，可以将其存储在 **file/..namedfork/rsrc** 中。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
你可以使用以下命令**查找包含此扩展属性的所有文件**：
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

扩展属性 `com.apple.decmpfs` 表示文件以压缩形式存储，`ls -l` 会报告其**大小为 0**，而压缩数据位于此属性中。每当访问该文件时，系统都会在内存中将其解压。

使用 `ls -lO` 可以看到此属性，文件会被标记为 compressed，因为压缩文件也会带有 `UF_COMPRESSED` 标志。如果通过 `chflags nocompressed </path/to/file>` 移除压缩文件的此标志，系统将无法知道该文件曾被压缩，因此也无法解压和访问其中的数据（系统会认为该文件实际上是空的）。

可以使用工具 afscexpand 强制解压文件。


### Interesting configuration locations (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | 存储 Apple 的 feature-flag plist 文件，用于控制系统 daemon / framework 中的可选或实验性行为 | 如果攻击者能够绕过 SIP 或获得权限，篡改这些文件可能启用隐藏的代码路径或禁用安全措施 |
| `/System/Library/CoreServices/systemVersion.plist` | 保存 macOS 版本元数据（ProductVersion、BuildVersion），供应用程序 / 安装程序限制行为 | 修改这些信息可能欺骗应用程序或安装程序接受不受支持的 OS 版本，或解锁相关功能 |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | 应用程序 / 系统范围的偏好设置 | 如果可写，攻击者可以注入设置以控制应用程序行为、禁用保护措施或造成配置错误 |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | 后台 daemon 和 agent 的 plist 定义 | 恶意插入或操纵 plist（如果权限允许）可以实现持久化或权限提升 |
| `/etc/hosts` | 系统 DNS resolver 使用的主机名 ↔ IP 映射 | 重定向域名、拦截流量、伪造由本地控制的服务 |
| `/etc/sudoers` | 定义谁可以使用 `sudo` 执行命令，以及适用的条件 | 损坏的 sudoers 文件可能向 root 或攻击者账户授予不当权限 |
| `/private/var/db/dslocal/nodes/Default/users/` | 本地用户账户定义 plist | 篡改这些文件可以创建或修改用户账户、密码哈希或用户元数据 |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extension / driver | 安装或修改 kext 可能导致获得 kernel-level 控制；其受到 SIP / 签名策略的严格保护 |
| `/private/var/db/SystemPolicyConfiguration/` | 存储系统策略执行的配置（例如 Gatekeeper、notarization） | 篡改这些配置可能绕过策略检查或信任规则 |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binary 和配置文件 | 配置错误可能导致 SSH 安全性较弱、未授权访问或使用不安全的算法 |
| `/System/Library/Sandbox/Profiles` | 系统 sandbox profile（SBPL），用于限制进程行为 | 替换或修改这些 profile 可能打开 sandbox escape vector 或削弱隔离能力 |

> **Note**：其中许多路径位于受 SIP 保护的目录（例如 `/System`）下，除非禁用或绕过 SIP，否则禁止写入。


## **Universal binaries &** Mach-o 格式

Mac OS binary 通常会被编译为 **universal binaries**。**universal binary** 可以在同一个文件中**支持多个架构**。

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Mac OS 风险类别文件

目录 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` 存储了与**不同文件扩展名相关的风险**的信息。该目录会将文件划分为不同的风险级别，从而影响 Safari 在下载文件后如何处理这些文件。类别如下：

- **LSRiskCategorySafe**：此类别中的文件被认为是**完全安全的**。Safari 会在下载完成后自动打开这些文件。
- **LSRiskCategoryNeutral**：这些文件不会显示警告，且不会被 Safari **自动打开**。
- **LSRiskCategoryUnsafeExecutable**：此类别中的文件会**触发警告**，提示该文件是应用程序。这是一项用于提醒用户的安全措施。
- **LSRiskCategoryMayContainUnsafeExecutable**：此类别适用于可能包含 executable 的文件，例如 archive。除非 Safari 能够验证其中的所有内容都是安全或中性的，否则会**触发警告**。

## 日志文件

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：包含已下载文件的信息，例如其下载来源的 URL。
- **`/var/log/system.log`**：OSX 系统的主要日志。com.apple.syslogd.plist 负责执行 syslogging（可以在 `launchctl list` 中查找 "com.apple.syslogd"，以检查其是否被禁用）。
- **`/private/var/log/asl/*.asl`**：这些是 Apple System Logs，可能包含有价值的信息。
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：存储通过 "Finder" 最近访问的文件和应用程序。
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**：存储系统启动时要启动的项目。
- **`$HOME/Library/Logs/DiskUtility.log`**：DiskUtility App 的日志文件（包含有关驱动器的信息，包括 USB 驱动器）。
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：包含有关无线接入点的数据。
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：已停用 daemon 的列表。

{{#include ../../../banners/hacktricks-training.md}}
