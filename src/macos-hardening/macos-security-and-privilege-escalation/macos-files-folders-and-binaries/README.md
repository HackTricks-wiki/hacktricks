# macOS 文件、文件夹、二进制文件和内存

{{#include ../../../banners/hacktricks-training.md}}

## 文件层次结构

- **/Applications**: 安装的应用程序应在此处。所有用户都可以访问它们。
- **/bin**: 命令行二进制文件
- **/cores**: 如果存在，用于存储核心转储
- **/dev**: 一切都被视为文件，因此您可能会看到存储在此处的硬件设备。
- **/etc**: 配置文件
- **/Library**: 可以在此找到许多与偏好设置、缓存和日志相关的子目录和文件。根目录和每个用户目录中都有一个 Library 文件夹。
- **/private**: 未记录，但许多提到的文件夹是指向私有目录的符号链接。
- **/sbin**: 重要的系统二进制文件（与管理相关）
- **/System**: 使 OS X 运行的文件。您在这里主要会找到仅与 Apple 相关的文件（而非第三方）。
- **/tmp**: 文件在 3 天后被删除（这是指向 /private/tmp 的软链接）
- **/Users**: 用户的主目录。
- **/usr**: 配置和系统二进制文件
- **/var**: 日志文件
- **/Volumes**: 挂载的驱动器将在此处出现。
- **/.vol**: 运行 `stat a.txt` 您将获得类似 `16777223 7545753 -rw-r--r-- 1 username wheel ...` 的内容，其中第一个数字是文件所在卷的 ID 号，第二个是 inode 号。您可以通过 /.vol/ 使用该信息访问此文件的内容，运行 `cat /.vol/16777223/7545753`

### 应用程序文件夹

- **系统应用程序** 位于 `/System/Applications` 下
- **已安装** 的应用程序通常安装在 `/Applications` 或 `~/Applications` 中
- **应用程序数据** 可以在 `/Library/Application Support` 中找到，适用于以 root 身份运行的应用程序，以及在 `~/Library/Application Support` 中找到，适用于以用户身份运行的应用程序。
- 需要以 root 身份运行的第三方应用程序 **守护进程** 通常位于 `/Library/PrivilegedHelperTools/`
- **沙盒** 应用程序映射到 `~/Library/Containers` 文件夹。每个应用程序都有一个根据应用程序的包 ID 命名的文件夹（`com.apple.Safari`）。
- **内核** 位于 `/System/Library/Kernels/kernel`
- **Apple 的内核扩展** 位于 `/System/Library/Extensions`
- **第三方内核扩展** 存储在 `/Library/Extensions`

### 包含敏感信息的文件

MacOS 在多个地方存储信息，例如密码：

{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 易受攻击的 pkg 安装程序

{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X 特定扩展

- **`.dmg`**: Apple 磁盘映像文件在安装程序中非常常见。
- **`.kext`**: 必须遵循特定结构，是 OS X 版本的驱动程序。（这是一个包）
- **`.plist`**: 也称为属性列表，以 XML 或二进制格式存储信息。
- 可以是 XML 或二进制。二进制文件可以使用以下命令读取：
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Apple 应用程序，遵循目录结构（这是一个包）。
- **`.dylib`**: 动态库（如 Windows DLL 文件）
- **`.pkg`**: 与 xar（可扩展归档格式）相同。可以使用安装命令安装这些文件的内容。
- **`.DS_Store`**: 此文件位于每个目录中，保存目录的属性和自定义设置。
- **`.Spotlight-V100`**: 此文件夹出现在系统中每个卷的根目录上。
- **`.metadata_never_index`**: 如果此文件位于卷的根目录，Spotlight 将不会索引该卷。
- **`.noindex`**: 具有此扩展名的文件和文件夹将不会被 Spotlight 索引。
- **`.sdef`**: 包内的文件，指定如何通过 AppleScript 与应用程序进行交互。

### macOS 包

包是一个 **目录**，在 Finder 中 **看起来像一个对象**（包的示例是 `*.app` 文件）。

{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld 共享库缓存 (SLC)

在 macOS（和 iOS）中，所有系统共享库，如框架和 dylibs，**合并为一个单一文件**，称为 **dyld 共享缓存**。这提高了性能，因为代码可以更快加载。

在 macOS 中，这位于 `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`，在旧版本中，您可能会在 **`/System/Library/dyld/`** 中找到 **共享缓存**。\
在 iOS 中，您可以在 **`/System/Library/Caches/com.apple.dyld/`** 中找到它们。

与 dyld 共享缓存类似，内核和内核扩展也被编译到内核缓存中，在启动时加载。

为了从单一文件 dylib 共享缓存中提取库，可以使用二进制文件 [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip)，虽然现在可能无法使用，但您也可以使用 [**dyldextractor**](https://github.com/arandomdev/dyldextractor)：
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> 请注意，即使 `dyld_shared_cache_util` 工具无法工作，您仍然可以将 **共享 dyld 二进制文件传递给 Hopper**，Hopper 将能够识别所有库并让您 **选择要调查的库**：

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

一些提取器可能无法工作，因为 dylibs 是与硬编码地址预链接的，因此它们可能会跳转到未知地址。

> [!TIP]
> 还可以通过在 Xcode 中使用模拟器下载其他 \*OS 设备的共享库缓存。它们将下载到：ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`，例如：`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### 映射 SLC

**`dyld`** 使用系统调用 **`shared_region_check_np`** 来知道 SLC 是否已映射（返回地址），并使用 **`shared_region_map_and_slide_np`** 来映射 SLC。

请注意，即使 SLC 在第一次使用时滑动，所有 **进程** 也使用 **相同的副本**，这 **消除了 ASLR** 保护，如果攻击者能够在系统中运行进程。这在过去实际上被利用过，并通过共享区域分页器修复。

分支池是小的 Mach-O dylibs，它在映像映射之间创建小空间，使得无法插入函数。

### 覆盖 SLCs

使用环境变量：

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> 这将允许加载新的共享库缓存
- **`DYLD_SHARED_CACHE_DIR=avoid`** 并手动用指向共享缓存的符号链接替换库（您需要提取它们）

## 特殊文件权限

### 文件夹权限

在一个 **文件夹** 中，**读取** 允许 **列出它**，**写入** 允许 **删除** 和 **写入** 其中的文件，**执行** 允许 **遍历** 目录。因此，例如，具有 **文件的读取权限** 的用户在没有 **执行权限** 的目录中 **将无法读取** 该文件。

### 标志修饰符

文件中可以设置一些标志，使文件表现得不同。您可以使用 `ls -lO /path/directory` **检查目录中文件的标志**。

- **`uchg`**：被称为 **uchange** 标志将 **防止任何操作** 更改或删除 **文件**。要设置它，请执行：`chflags uchg file.txt`
- root 用户可以 **删除标志** 并修改文件
- **`restricted`**：此标志使文件受到 **SIP 保护**（您无法将此标志添加到文件）。
- **`Sticky bit`**：如果目录具有粘滞位，**只有** 该 **目录的所有者或 root 可以重命名或删除** 文件。通常，这在 /tmp 目录上设置，以防止普通用户删除或移动其他用户的文件。

所有标志可以在文件 `sys/stat.h` 中找到（使用 `mdfind stat.h | grep stat.h` 查找），并且是：

- `UF_SETTABLE` 0x0000ffff：可更改的所有者标志的掩码。
- `UF_NODUMP` 0x00000001：不转储文件。
- `UF_IMMUTABLE` 0x00000002：文件不可更改。
- `UF_APPEND` 0x00000004：对文件的写入只能追加。
- `UF_OPAQUE` 0x00000008：目录在联合方面是透明的。
- `UF_COMPRESSED` 0x00000020：文件被压缩（某些文件系统）。
- `UF_TRACKED` 0x00000040：对于设置此标志的文件，不会有删除/重命名的通知。
- `UF_DATAVAULT` 0x00000080：读取和写入需要权限。
- `UF_HIDDEN` 0x00008000：提示该项不应在 GUI 中显示。
- `SF_SUPPORTED` 0x009f0000：超级用户支持标志的掩码。
- `SF_SETTABLE` 0x3fff0000：超级用户可更改标志的掩码。
- `SF_SYNTHETIC` 0xc0000000：系统只读合成标志的掩码。
- `SF_ARCHIVED` 0x00010000：文件已归档。
- `SF_IMMUTABLE` 0x00020000：文件不可更改。
- `SF_APPEND` 0x00040000：对文件的写入只能追加。
- `SF_RESTRICTED` 0x00080000：写入需要权限。
- `SF_NOUNLINK` 0x00100000：项目不可被删除、重命名或挂载。
- `SF_FIRMLINK` 0x00800000：文件是 firmlink。
- `SF_DATALESS` 0x40000000：文件是无数据对象。

### **文件 ACLs**

文件 **ACLs** 包含 **ACE**（访问控制条目），可以为不同用户分配更 **细粒度的权限**。

可以为 **目录** 授予这些权限：`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
对于 **文件**：`read`、`write`、`append`、`execute`。

当文件包含 ACLs 时，您将 **在列出权限时找到一个 "+"，如**：
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
您可以使用以下命令**读取文件的 ACL**：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
您可以找到 **所有具有 ACL 的文件**（这非常慢）：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 扩展属性

扩展属性具有名称和任何所需的值，可以使用 `ls -@` 查看，并使用 `xattr` 命令进行操作。一些常见的扩展属性包括：

- `com.apple.resourceFork`: 资源分叉兼容性。也可显示为 `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: Gatekeeper 隔离机制 (III/6)
- `metadata:*`: MacOS: 各种元数据，例如 `_backup_excludeItem` 或 `kMD*`
- `com.apple.lastuseddate` (#PS): 最后文件使用日期
- `com.apple.FinderInfo`: MacOS: Finder 信息（例如，颜色标签）
- `com.apple.TextEncoding`: 指定 ASCII 文本文件的文本编码
- `com.apple.logd.metadata`: logd 在 `/var/db/diagnostics` 中使用的文件
- `com.apple.genstore.*`: 代际存储（`/.DocumentRevisions-V100` 在文件系统根目录中）
- `com.apple.rootless`: MacOS: 由系统完整性保护用于标记文件 (III/10)
- `com.apple.uuidb.boot-uuid`: logd 对具有唯一 UUID 的启动时期的标记
- `com.apple.decmpfs`: MacOS: 透明文件压缩 (II/7)
- `com.apple.cprotect`: \*OS: 每个文件的加密数据 (III/11)
- `com.apple.installd.*`: \*OS: installd 使用的元数据，例如 `installType`，`uniqueInstallID`

### 资源分叉 | macOS ADS

这是一种在 MacOS 机器中获取 **备用数据流** 的方法。您可以通过将内容保存在名为 **com.apple.ResourceFork** 的扩展属性中，将其保存在 **file/..namedfork/rsrc** 中。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
您可以**找到所有包含此扩展属性的文件**：
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

扩展属性 `com.apple.decmpfs` 表示文件是加密存储的，`ls -l` 将报告 **大小为 0**，压缩数据存储在此属性中。每当访问该文件时，它将在内存中解密。

此属性可以通过 `ls -lO` 查看，标记为压缩，因为压缩文件也带有标志 `UF_COMPRESSED`。如果通过 `chflags nocompressed </path/to/file>` 删除压缩文件的此标志，系统将不知道该文件是压缩的，因此无法解压并访问数据（它会认为该文件实际上是空的）。

工具 afscexpand 可用于强制解压文件。

## **Universal binaries &** Mach-o Format

Mac OS 二进制文件通常被编译为 **universal binaries**。一个 **universal binary** 可以 **在同一文件中支持多种架构**。

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}

## macOS Process Memory

## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

目录 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` 存储有关 **不同文件扩展名相关风险的信息**。该目录将文件分类为不同的风险级别，影响 Safari 下载这些文件时的处理方式。类别如下：

- **LSRiskCategorySafe**：此类别中的文件被认为是 **完全安全的**。Safari 会在下载后自动打开这些文件。
- **LSRiskCategoryNeutral**：这些文件没有警告，Safari **不会自动打开**。
- **LSRiskCategoryUnsafeExecutable**：此类别下的文件 **触发警告**，指示该文件是一个应用程序。这是一个安全措施，用于提醒用户。
- **LSRiskCategoryMayContainUnsafeExecutable**：此类别适用于可能包含可执行文件的文件，例如归档文件。除非 Safari 能验证所有内容是安全或中性的，否则将 **触发警告**。

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：包含有关下载文件的信息，例如它们的下载 URL。
- **`/var/log/system.log`**：OSX 系统的主日志。com.apple.syslogd.plist 负责执行 syslogging（您可以通过在 `launchctl list` 中查找 "com.apple.syslogd" 来检查它是否被禁用）。
- **`/private/var/log/asl/*.asl`**：这些是 Apple 系统日志，可能包含有趣的信息。
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：通过 "Finder" 存储最近访问的文件和应用程序。
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**：存储系统启动时要启动的项目。
- **`$HOME/Library/Logs/DiskUtility.log`**：DiskUtility 应用程序的日志文件（有关驱动器的信息，包括 USB）。
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：有关无线接入点的数据。
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：已停用的守护进程列表。

{{#include ../../../banners/hacktricks-training.md}}
