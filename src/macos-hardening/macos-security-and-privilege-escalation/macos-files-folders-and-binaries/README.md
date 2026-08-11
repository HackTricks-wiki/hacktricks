# macOS 文件、文件夹、二进制文件与内存

{{#include ../../../banners/hacktricks-training.md}}

## 文件层级布局

Apple 将 macOS 文件系统记录为由系统、本地、网络和用户域组成的层级结构。具体内容会因 OS 版本而异，并且系统位置正日益受到保护或由系统合成。 <sup>[[1]](#references)</sup>

- **/Applications**：已安装的应用程序应位于此处。所有用户都可以访问它们。
- **/bin**：命令行二进制文件
- **/cores**：如果存在，则用于存储 core dumps
- **/dev**：所有内容都被视为文件，因此你可能会看到存储于此处的硬件设备。
- **/etc**：配置文件
- **/Library**：这里可以找到许多与偏好设置、缓存和日志相关的子目录及文件。根目录和每个用户的目录中都存在一个 Library 文件夹。
- **/private**：未公开说明，但上述许多文件夹都是指向 private 目录的符号链接。
- **/sbin**：必要的系统二进制文件（与管理相关）
- **/System**：macOS 所需的文件；此树主要包含 Apple 提供的组件。
- **/tmp**：临时文件（指向 `/private/tmp` 的符号链接）。历史上的安装通常会按周期清理旧的临时文件，有时被描述为三天清理一次，但当前的清理时间取决于系统和策略；不要依赖其中的数据持续存在。
- **/Users**：用户的主目录。
- **/usr**：配置文件和系统二进制文件
- **/var**：日志文件
- **/Volumes**：挂载的卷会显示在此处。
- **/.vol**：运行 `stat a.txt` 时，你会获得类似 `16777223 7545753 -rw-r--r-- 1 username wheel ...` 的输出，其中第一个数字是文件所在卷的 ID，第二个数字是 inode 编号。使用这些信息运行 `cat /.vol/16777223/7545753`，即可通过 `/.vol/` 访问此文件的内容。

### 应用程序文件夹

- **系统应用程序** 位于 `/System/Applications`
- **已安装的** 应用程序通常安装在 `/Applications` 或 `~/Applications`
- 应用程序数据可以在以 root 运行的应用程序的 `/Library/Application Support` 中找到，也可以在以用户身份运行的应用程序的 `~/Library/Application Support` 中找到。
- 通常需要以 root 身份运行的第三方应用程序 **daemons** 位于 `/Library/PrivilegedHelperTools/`。
- **Sandboxed** 应用程序会映射到 `~/Library/Containers` 文件夹中。每个应用程序都有一个根据其 bundle ID（`com.apple.Safari`）命名的文件夹。
- **kernel** 位于 `/System/Library/Kernels/kernel`
- **Apple 的 kernel extensions** 位于 `/System/Library/Extensions`
- **第三方 kernel extensions** 存储在 `/Library/Extensions`

### 包含敏感信息的文件

macOS 会在多个位置存储敏感信息，包括凭据：


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 易受攻击的 pkg 安装程序


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X 特有扩展名

- **`.dmg`**：Apple Disk Image 文件，在安装程序中非常常见。
- **`.kext`**：必须遵循特定结构，是 OS X 版本的驱动程序。（它是一个 bundle）
- **`.plist`**：property list 以 XML 或二进制格式存储结构化信息。
- 可以是 XML 或二进制格式。二进制文件可以使用以下命令读取：
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**：遵循标准 macOS 目录结构的应用程序 bundle。
- **`.dylib`**：动态库（类似 Windows DLL 文件）
- **`.pkg`**：与 xar（eXtensible Archive format）相同。可以使用 installer 命令安装这些文件的内容。
- **`.DS_Store`**：每个目录中都有此文件，用于保存目录的属性和自定义设置。
- **`.Spotlight-V100`**：此文件夹会出现在系统中每个卷的根目录中。
- **`.metadata_never_index`**：如果此文件位于卷的根目录，Spotlight 将不会为该卷建立索引。
- **`.noindex`**：带有此扩展名的文件和文件夹不会被 Spotlight 建立索引。
- **`.sdef`**：用于描述 AppleScript 如何与应用程序交互的 scripting definition 文件。

### macOS Bundles

bundle 是一个具有标准化层级结构的目录，Finder 可以将其呈现为单个对象；应用程序 bundle 使用 `.app` 扩展名。 <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

在 macOS 和 iOS 上，常用的系统库和 framework 会被预先链接到 **dyld shared cache** 中，从而提升应用程序启动性能。虽然它在逻辑上被视为一个缓存，但当前版本可能会将其存储为一个主缓存和多个 subcache 文件，而不是严格意义上的单个文件。其格式和位置属于实现细节，会随 OS 版本变化。 <sup>[[3]](#references)</sup>

在 macOS 中，它位于 `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`；在较旧版本中，你可能可以在 **`/System/Library/dyld/`** 找到 **shared cache**。\
在 iOS 中，你可以在 **`/System/Library/Caches/com.apple.dyld/`** 找到它们。

与 dyld shared cache 类似，kernel 和 kernel extensions 也会被编译到 kernel cache 中，并在启动时加载。

较旧版本可以使用 [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) 提取。该构建版本可能不支持当前的缓存格式；[**dyldextractor**](https://github.com/arandomdev/dyldextractor) 是另一个选择：
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> 注意，即使 `dyld_shared_cache_util` 工具无法正常工作，你也可以将 **shared dyld binary 传递给 Hopper**，Hopper 将能够识别所有库，并让你**选择要调查的库**：

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

某些 extractors 将无法工作，因为 dylibs 会预先链接到硬编码地址，因此它们可能会跳转到未知地址

> [!TIP]
> 也可以在 macos 中通过 Xcode 的 emulator 下载其他 \*OS 设备的 Shared Library Cache。它们会被下载到：ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`，例如：`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** 使用 syscall **`shared_region_check_np`** 来确认 SLC 是否已被映射（该 syscall 会返回地址），并使用 **`shared_region_map_and_slide_np`** 来映射 SLC。

注意，即使 SLC 在首次使用时会进行 slide，所有**进程**仍使用**同一份副本**；如果攻击者能够在系统中运行进程，这就会**消除 ASLR** 保护。该问题过去曾被实际利用，后来通过 shared region pager 修复。

Branch pools 是一些小型 Mach-O dylibs，它们会在 image mappings 之间创建小空间，从而使 interpose 函数变得不可能。

### Override SLCs

使用以下 env variables：

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> 这将允许加载新的 shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`**，并手动将 libraries 替换为指向 shared cache 中真实 libraries 的 symlinks（你需要先 extract 它们）

## Special File Permissions

### Folder permissions

对于 directory，**read** 允许列出 entries，**write** 允许创建或移除 entries，而 **execute** 允许 traversal。因此，能够读取 file 但无法 traversal parent directory 的用户，不能通过路径访问该 file。 <sup>[[4]](#references)</sup>

### Flag modifiers

Files 可以携带改变其行为的 flags。使用 `ls -lO /path/directory` 检查 directory 中的 flags。

- **`uchg`**：称为 **uchange** flag，会**阻止任何更改或删除 file 的操作**。设置方法：`chflags uchg file.txt`
- root user 可以**移除该 flag** 并修改 file
- **`restricted`**：此 flag 会使 file **受到 SIP 保护**（你无法将此 flag 添加到 file）。
- **`Sticky bit`**：在设置了 sticky bit 的 directory 中，只有 file owner、directory owner 或 root 才能重命名或删除 entry。该选项通常在 `/tmp` 上启用，以防止用户删除或移动其他用户的 files。

所有 flags 都可以在 file `sys/stat.h` 中找到（使用 `mdfind stat.h | grep stat.h` 查找），具体如下：

- `UF_SETTABLE` 0x0000ffff: Owner 可更改 flags 的掩码。
- `UF_NODUMP` 0x00000001: 不 dump file。
- `UF_IMMUTABLE` 0x00000002: File 不可更改。
- `UF_APPEND` 0x00000004: 对 file 的写入只能 append。
- `UF_OPAQUE` 0x00000008: Directory 相对于 union 是 opaque。
- `UF_COMPRESSED` 0x00000020: File 已压缩（某些 file-systems）。
- `UF_TRACKED` 0x00000040: 对于设置了此 flag 的 files，不发送 delete/rename notifications。
- `UF_DATAVAULT` 0x00000080: 读取和写入需要 entitlement。
- `UF_HIDDEN` 0x00008000: 提示 GUI 不应显示此 item。
- `SF_SUPPORTED` 0x009f0000: Superuser 支持的 flags 掩码。
- `SF_SETTABLE` 0x3fff0000: Superuser 可更改的 flags 掩码。
- `SF_SYNTHETIC` 0xc0000000: System 只读 synthetic flags 的掩码。
- `SF_ARCHIVED` 0x00010000: File 已归档。
- `SF_IMMUTABLE` 0x00020000: File 不可更改。
- `SF_APPEND` 0x00040000: 对 file 的写入只能 append。
- `SF_RESTRICTED` 0x00080000: 写入需要 entitlement。
- `SF_NOUNLINK` 0x00100000: Item 不可移除、重命名或 mount。
- `SF_FIRMLINK` 0x00800000: File 是 firmlink。
- `SF_DATALESS` 0x40000000: File 是 dataless object。

### **File ACLs**

File **ACLs** 包含 **ACE**（Access Control Entries），可以为不同用户分配更**细粒度的权限**。

可以为 **directory** 授予以下权限：`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
对于 **file**：`read`、`write`、`append` 和 `execute`。

当 file 包含 ACLs 时，在列出 permissions 时会**看到一个 "+"，例如**：
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
你可以使用以下命令**读取 ACL**：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
你可以使用以下命令查找**所有带有 ACL 的文件**（速度非常慢）：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes 是独立于文件普通属性存储的命名元数据值。使用 `ls -l@` 列出，并使用 `xattr` 检查或修改它们。 <sup>[[5]](#references)</sup> 一些常见的 extended attributes 包括：

- `com.apple.resourceFork`：Resource fork 兼容性。也可通过 `filename/..namedfork/rsrc` 查看
- `com.apple.quarantine`：macOS Gatekeeper quarantine 元数据
- `metadata:*`：macOS 元数据，例如 `_backup_excludeItem` 或 `kMD*`
- `com.apple.lastuseddate` (#PS)：文件最后使用日期
- `com.apple.FinderInfo`：macOS Finder 信息，例如颜色标签
- `com.apple.TextEncoding`：指定 ASCII 文本文件的文本编码
- `com.apple.logd.metadata`：由 logd 用于 `/var/db/diagnostics` 中的文件
- `com.apple.genstore.*`：Generational storage（文件系统根目录中的 `/.DocumentRevisions-V100`）
- `com.apple.rootless`：与 System Integrity Protection 相关的 macOS 元数据
- `com.apple.uuidb.boot-uuid`：logd 使用唯一 UUID 标记启动时期
- `com.apple.decmpfs`：macOS 透明文件压缩元数据
- `com.apple.cprotect`：\*OS：每个文件的加密数据（III/11）
- `com.apple.installd.*`：\*OS：由 installd 使用的元数据，例如 `installType`、`uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks 在 macOS 上提供 alternate data stream。内容可以存储在 `com.apple.ResourceFork` extended attribute 中，并通过 `file/..namedfork/rsrc` 访问。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
你可以使用以下命令**查找所有包含此扩展属性的文件**：
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

扩展属性 `com.apple.decmpfs` 存储透明压缩的元数据；它不表示加密。根据压缩格式的不同，压缩数据可能存储在该属性中，也可能存储在 resource fork 中，并在读取时透明解压。

`UF_COMPRESSED` 标志在 `ls -lO` 中显示为 `compressed`。不要手动清除它：这样做可能导致系统错误地解释压缩表示。

这里展示清除该标志的命令，是因为它在取证审查期间很有用；但对压缩文件运行该命令，可能导致文件显示为空或无法访问，直到其元数据得到修复：
```bash
chflags nocompressed /path/to/file
```
内置的 `/usr/bin/afscexpand` utility 可以强制展开透明压缩的文件。单独的第三方 `afsctool` utility 也可以检查或解压 Apple filesystem compression，但不应将其与内置 command 混淆。 <sup>[[8]](#references)</sup>


### 有趣的配置位置（macOS）

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | 存储 Apple 的 feature-flag plist 文件，用于控制 system daemons / frameworks 中的可选或实验性行为 | 如果 attacker 能够绕过 SIP 或获得 privilege，篡改这些文件可能启用隐藏的 code paths 或禁用安全措施 |
| `/System/Library/CoreServices/systemVersion.plist` | 保存 macOS 版本元数据（ProductVersion、BuildVersion），供 apps / installers 用于限制行为 | 修改它可能欺骗 apps 或 installers，使其接受不受支持的 OS 版本或解锁 features |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Application / system-wide preferences | 如果可写，attackers 可以注入 settings 以引导 app 行为、禁用 protections 或造成 misconfiguration |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | 后台 daemons 和 agents 的 plist 定义 | 恶意插入或操纵 plist（如果 permissions 允许）可以实现 persistence 或 privilege escalations |
| `/etc/hosts` | 系统 DNS resolver 使用的 Hostname ↔ IP 映射 | 重定向 domain names、拦截 traffic、spoof 受本地控制的 services |
| `/etc/sudoers` | 定义谁可以使用 `sudo` 运行 commands 以及适用条件 | 被篡改的 sudoers 文件可能向 attacker accounts 授予 root 或不当 privileges |
| `/private/var/db/dslocal/nodes/Default/users/` | 本地 user accounts 的定义 plist | 篡改可以创建或修改 user accounts、password hashes 或 user metadata |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | 安装或修改 kexts 可能导致 kernel-level control；受到 SIP / signature policies 的严格保护 |
| `/private/var/db/SystemPolicyConfiguration/` | 存储 system policy enforcement 的配置（例如 Gatekeeper、notarization） | 篡改这些配置可能允许绕过 policy checks 或 trust rules |
| `/usr/libexec/ssh-keysign`、`/etc/ssh/ssh_config`、`/etc/ssh/sshd_config` | SSH helper binaries 和配置文件 | Misconfiguration 会导致较弱的 SSH security、unauthorized access 或不安全的 algorithms |
| `/System/Library/Sandbox/Profiles` | 用于限制 process actions 的 system sandbox profiles（SBPL） | 替换或修改 profiles 可能打开 sandbox escape vectors 或削弱 containment |

> **注意**：其中许多 paths 位于 SIP-protected directories（例如 `/System`）下，除非 SIP 被禁用或绕过，否则会受到写入保护。


## Universal Binaries And Mach-O Format

Mach-O 是 macOS 的 native executable format。universal 或 fat binary 会将多个特定于 architecture 的 Mach-O slices 封装在一个文件中；专门页面介绍了这两种 formats：

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk And Handler Metadata

LaunchServices、file quarantine 和 Gatekeeper 共同影响 macOS 如何处理 downloaded files，以及如何为 extensions 和 URL schemes 选择 applications。它们的 databases 和 internal resource files 会随 releases 变化；请使用专门页面，而不要将 private CoreTypes path 当作稳定的 policy interface：

在某些 releases 中，如果 legacy CoreTypes risk metadata 位于 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` 下，常见的 categories 包括：<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**：根据适用的 application policy，被认为足够安全、可以自动打开的 content。
- **`LSRiskCategoryNeutral`**：通常不会触发 warning，且不会自动打开的 content。
- **`LSRiskCategoryUnsafeExecutable`**：用户应收到 application warning 的 executable content。
- **`LSRiskCategoryMayContainUnsafeExecutable`**：可能包含 executable content 并需要进一步检查的 containers，例如 archives。

这些属于 implementation details，而不是稳定的 public policy API；请在被测试的 macOS version 上确认实际的 metadata 以及 Safari/Gatekeeper 行为。

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：包含 downloaded files 的信息，例如其下载来源的 URL。
- **Unified log**：在当前 macOS versions 上，使用 `log show` 和 `log stream` 查询 system 和 application events。 <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** 和 **`/private/var/log/asl/*.asl`**：在较旧 systems 上可能仍然相关的 legacy logging artifacts。在这些 releases 中，`/System/Library/LaunchDaemons/com.apple.syslogd.plist` 配置 `syslogd`；`launchctl list | grep com.apple.syslogd` 可以帮助确定该 service 是否已加载。
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：通过 "Finder" 存储最近访问的 files 和 applications。
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**：与 login items 相关的 legacy preference path；现代 macOS versions 使用其他 mechanisms。
- **`$HOME/Library/Logs/DiskUtility.log`**：legacy Disk Utility log，可能包含 drives 的信息，包括 USB devices。
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：关于 wireless access points 的 data。
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：legacy launchd override data。

## References

- [1] [Apple - File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle Programming Guide](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld shared cache overview](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - File System Programming Guide: macOS File System Security](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS manual page](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS manual page](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS manual page](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
