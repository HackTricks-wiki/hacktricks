# macOS 文件、文件夹、二进制文件与内存

{{#include ../../../banners/hacktricks-training.md}}

## 文件系统层级布局

Apple 将 macOS 文件系统描述为由系统、本地、网络和用户域组成的层级结构。具体内容会因 OS 版本而异，系统位置也越来越多地受到保护或由系统合成。 <sup>[[1]](#references)</sup>

- **/Applications**：已安装的应用应位于此处。所有用户都可以访问它们。
- **/bin**：命令行二进制文件
- **/cores**：如果存在，则用于存储 core dump
- **/dev**：所有内容都被视为文件，因此你可能会在此处看到硬件设备。
- **/etc**：配置文件
- **/Library**：此处有许多与偏好设置、缓存和日志相关的子目录和文件。根目录和每个用户的目录中都存在一个 Library 文件夹。
- **/private**：未公开说明，但许多上述文件夹都是指向 private 目录的符号链接。
- **/sbin**：必要的系统二进制文件（与管理相关）
- **/System**：macOS 所需的文件；此目录树主要包含 Apple 提供的组件。
- **/tmp**：临时文件（指向 `/private/tmp` 的符号链接）。历史上的安装通常会定期清理旧临时文件，有时会说是每三天清理一次；但当前清理时间取决于系统和策略，因此不要依赖数据会一直保留在此处。
- **/Users**：用户的主目录。
- **/usr**：配置和系统二进制文件
- **/var**：日志文件
- **/Volumes**：已挂载的卷会显示在此处。
- **/.vol**：运行 `stat a.txt`，你会得到类似 `16777223 7545753 -rw-r--r-- 1 username wheel ...` 的结果，其中第一个数字是文件所在卷的 ID，第二个数字是 inode 编号。使用这些信息运行 `cat /.vol/16777223/7545753`，即可通过 `/.vol/` 访问该文件的内容。

### Applications 文件夹

- **系统应用**位于 `/System/Applications`
- **已安装的**应用通常安装在 `/Applications` 或 `~/Applications`
- **应用数据**可在 `/Library/Application Support` 中找到（适用于以 root 身份运行的应用），以用户身份运行的应用则位于 `~/Library/Application Support`。
- **第三方应用的 daemon**若**需要以 root 身份运行**，通常位于 `/Library/PrivilegedHelperTools/`。
- **沙盒化**应用映射到 `~/Library/Containers` 文件夹中。每个应用都有一个按应用 bundle ID 命名的文件夹（`com.apple.Safari`）。
- **kernel** 位于 `/System/Library/Kernels/kernel`
- **Apple 的 kernel 扩展**位于 `/System/Library/Extensions`
- **第三方 kernel 扩展**存储在 `/Library/Extensions`

### 包含敏感信息的文件

macOS 会在多个位置存储敏感信息，包括凭据：


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 易受攻击的 pkg 安装程序


{{#ref}}
macos-installers-abuse.md
{{#endref}}

关于此层级结构中可写的 Data 卷与密封的 System 卷之间的区别，请参阅 [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md)。

## OS X 特定扩展名

- **`.dmg`**：Apple Disk Image 文件常用于安装程序。
- **`.kext`**：它必须遵循特定结构，是 OS X 版本的驱动程序。（它是一个 bundle）
- **`.plist`**：property list 以 XML 或二进制格式存储结构化信息。
  - 可以是 XML 或二进制格式。二进制文件可以通过以下方式读取：
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**：遵循标准 macOS 目录结构的应用 bundle。
- **`.dylib`**：动态库（类似 Windows DLL 文件）
- **`.pkg`**：现代扁平安装程序包是 XAR 归档，但 `.pkg` 是一种安装程序格式，并不是 XAR 的同义词。较早的 bundle 风格安装程序包是目录。有关包结构和检查方法，请参阅 [macOS installers](macos-installers-abuse.md)。 <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**：每个目录中都有此文件，用于保存目录的属性和自定义设置。
- **`.Spotlight-V100`**：此文件夹会出现在系统中每个卷的根目录。
- **`.metadata_never_index`**：如果此文件位于卷的根目录，Spotlight 就不会为该卷编制索引。
- **`.noindex`**：带有此扩展名的文件和文件夹不会被 Spotlight 编制索引。
- **`.sdef`**：脚本定义文件，用于描述 AppleScript 如何与应用交互。

### macOS Bundles

bundle 是一种采用标准化层级结构的目录，Finder 可以将其显示为单个对象；应用 bundle 使用 `.app` 扩展名。 <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

在 macOS 和 iOS 上，常用的系统库和 framework 会预先链接到 **dyld shared cache** 中，以提升应用启动性能。虽然它在逻辑上被视为一个缓存，但当前版本可能会将其存储为一个主缓存和多个子缓存文件，而非实际的单个文件。其格式和位置属于实现细节，会随 OS 版本变化。 <sup>[[3]](#references)</sup>

在 macOS 中，它位于 `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`；在较旧的版本中，你可能会在 **`/System/Library/dyld/`** 找到 **shared cache**。\
在 iOS 中，你可以在 **`/System/Library/Caches/com.apple.dyld/`** 找到它们。

与 dyld shared cache 类似，kernel 和 kernel 扩展也会被编译到 kernel cache 中，并在启动时加载。

较旧版本可以使用 [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) 提取。该构建可能不支持当前的缓存格式；[**dyldextractor**](https://github.com/arandomdev/dyldextractor) 也是一种选择：

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> 请注意，即使 `dyld_shared_cache_util` 工具无法使用，你也可以将 **shared dyld binary 传给 Hopper**，Hopper 能识别所有库，并让你**选择要调查的库**：

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

由于 dylib 预先链接了硬编码地址，某些提取器可能无法正常工作，因此它们可能会跳转到未知地址。

> [!TIP]
> 也可以在 macOS 中使用 Xcode 模拟器下载其他 \*OS 设备的 Shared Library Cache。它们会下载到以下位置：`$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`，例如：`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### 映射 SLC

**`dyld`** 使用系统调用 **`shared_region_check_np`** 检查 SLC 是否已映射（该调用会返回地址），并使用 **`shared_region_map_and_slide_np`** 映射 SLC。

请注意，即使 SLC 在首次使用时会进行滑动，所有**进程**也会使用**同一个副本**；如果攻击者能够在系统中运行进程，这就会**消除 ASLR** 保护。过去曾有人利用这一点，之后通过 shared region pager 修复了该问题。

Branch pools 是小型 Mach-O dylib，它们会在映像映射之间创建小型空间，使函数拦截变得不可能。

### Shared-cache 环境限制

`DYLD_SHARED_CACHE_DIR` 指定缓存目录，而 `DYLD_SHARED_REGION` 选择 shared-region 模式。此前的 `DYLD_DHARED_REGION` 拼写无效，并且 `avoid` 不是 `DYLD_SHARED_CACHE_DIR` 的有效值。当前的 dyld 会根据 AMFI 是否允许使用自定义 shared cache 来限制 `private` 模式，因此，仅设置环境变量并不能证明进程能够加载替代缓存。 <sup>[[10]](#references)</sup>

## 特殊文件权限

### 文件夹权限

对于目录，**读取**权限允许列出目录项，**写入**权限允许创建或删除目录项，**执行**权限允许遍历目录。因此，用户即使有权读取某个文件，但如果无法遍历其父目录，也无法通过路径访问该文件。 <sup>[[4]](#references)</sup>

### 标志修饰符

文件可以带有会改变其行为的标志。使用 `ls -lO /path/directory` 检查目录中的标志。

- **`uchg`**：称为 **uchange** 标志，可**阻止对文件进行任何更改或删除操作**。设置方法：`chflags uchg file.txt`
  - 文件所有者或 root 可以使用 `chflags nouchg file.txt` 移除此**用户**标志；它并不能防止这两者操作。独立的**系统**不可变标志（`schg`）仅限 root 设置。 <sup>[[11]](#references)</sup>
- **`restricted`**：此标志使文件受 **SIP** 保护（无法为文件添加此标志）。
- **`Sticky bit`**：在设置了 sticky bit 的目录中，只有文件所有者、目录所有者或 root 可以重命名或删除目录项。通常会在 `/tmp` 上启用此标志，以防止用户删除或移动其他用户的文件。

所有标志都可以在 `sys/stat.h` 文件中找到（使用 `mdfind stat.h | grep stat.h` 查找），包括：

- `UF_SETTABLE` 0x0000ffff：所有者可更改标志的掩码。
- `UF_NODUMP` 0x00000001：不转储文件。
- `UF_IMMUTABLE` 0x00000002：文件不可更改。
- `UF_APPEND` 0x00000004：只能向文件追加写入。
- `UF_OPAQUE` 0x00000008：目录对于 union 不透明。
- `UF_COMPRESSED` 0x00000020：文件已压缩（部分文件系统）。
- `UF_TRACKED` 0x00000040：设置此标志的文件被删除或重命名时，不发送通知。
- `UF_DATAVAULT` 0x00000080：读取和写入需要 entitlement。
- `UF_HIDDEN` 0x00008000：提示 GUI 不应显示此项目。
- `SF_SUPPORTED` 0x009f0000：超级用户支持的标志掩码。
- `SF_SETTABLE` 0x3fff0000：超级用户可更改标志的掩码。
- `SF_SYNTHETIC` 0xc0000000：系统只读 synthetic 标志的掩码。
- `SF_ARCHIVED` 0x00010000：文件已归档。
- `SF_IMMUTABLE` 0x00020000：文件不可更改。
- `SF_APPEND` 0x00040000：只能向文件追加写入。
- `SF_RESTRICTED` 0x00080000：写入需要 entitlement。
- `SF_NOUNLINK` 0x00100000：项目不可删除、重命名或挂载其上。
- `SF_FIRMLINK` 0x00800000：文件是 firmlink。
- `SF_DATALESS` 0x40000000：文件是 dataless 对象。

### **文件 ACL**

文件 **ACL** 包含 **ACE**（访问控制条目），可为不同用户分配更**细粒度的权限**。

可以为**目录**授予以下权限：`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
对于**文件**，权限包括：`read`、`write`、`append` 和 `execute`。

当文件包含 ACL 时，**列出权限时会看到一个 "+"，例如**：

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

你可以通过以下方式**读取**该文件的 ACL：

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

你可以使用以下命令查找**所有带有 ACL 的文件**（速度非常慢）：

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### 扩展属性

扩展属性是独立于文件普通属性存储的命名元数据值。使用 `ls -l@` 列出它们，并使用 `xattr` 查看或修改它们。 <sup>[[5]](#references)</sup> 一些常见的扩展属性包括：

- `com.apple.resourceFork`：资源分叉兼容性。也可通过 `filename/..namedfork/rsrc` 查看
- `com.apple.quarantine`：macOS Gatekeeper 隔离元数据
- `metadata:*`：macOS 元数据，例如 `_backup_excludeItem` 或 `kMD*`
- `com.apple.lastuseddate` (#PS)：文件最后使用日期
- `com.apple.FinderInfo`：macOS Finder 信息，例如颜色标签
- `com.apple.TextEncoding`：指定 ASCII 文本文件的文本编码
- `com.apple.logd.metadata`：logd 用于 `/var/db/diagnostics` 中文件的元数据
- `com.apple.genstore.*`：代际存储（文件系统根目录下的 `/.DocumentRevisions-V100`）
- `com.apple.rootless`：与系统完整性保护相关的 macOS 元数据
- `com.apple.uuidb.boot-uuid`：logd 使用唯一 UUID 标记启动时段
- `com.apple.decmpfs`：macOS 透明文件压缩元数据
- `com.apple.cprotect`：\*OS：每个文件的加密数据（III/11）
- `com.apple.installd.*`：\*OS：installd 使用的元数据，例如 `installType`、`uniqueInstallID`

### 资源分叉 | macOS ADS

资源分叉在 macOS 上提供备用数据流。内容可以存储在 `com.apple.ResourceFork` 扩展属性中，并通过 `file/..namedfork/rsrc` 访问。

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

扩展属性 `com.apple.decmpfs` 存储透明压缩所需的元数据；它不表示加密。根据压缩格式，压缩数据可能存储在该属性或资源分支中，并在读取时自动解压。

`UF_COMPRESSED` 标志在 `ls -lO` 中显示为 `compressed`。不要手动清除此标志：这样可能导致系统错误地解析压缩表示形式。

这里展示了清除此标志的命令，因为它在取证审查中很有用；但对压缩文件运行此命令，可能会导致文件显示为空或无法访问，直到其元数据得到修复：

```bash
chflags nocompressed /path/to/file
```

内置的 `/usr/bin/afscexpand` 工具可以强制展开透明压缩文件。独立的第三方 `afsctool` 工具也可以检查或解压 Apple 文件系统压缩内容，但不要将其与内置命令混淆。 <sup>[[8]](#references)</sup>


### 有趣的配置位置（macOS）

| 路径 / 位置 | 用途 / 配置内容 | 安全 / 攻击潜力 |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | 存储 Apple 的功能标志 plist 文件，用于控制系统守护进程 / 框架中的可选或实验性行为 | 如果攻击者能够绕过 SIP 或获取特权，篡改这些文件可能启用隐藏代码路径或禁用安全措施 |
| `/System/Library/CoreServices/systemVersion.plist` | 保存 macOS 版本元数据（ProductVersion、BuildVersion），供应用 / 安装程序判断行为 | 修改它可能诱使应用或安装程序接受不受支持的 OS 版本或解锁功能 |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | 应用 / 系统范围的偏好设置 | 如果可写，攻击者可以注入设置以影响应用行为、禁用保护或造成配置错误 |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | 后台守护进程和代理的 plist 定义 | 如果权限允许，插入或篡改恶意 plist 可实现持久化或权限提升 |
| `/etc/hosts` | 系统 DNS 解析器使用的主机名 ↔ IP 映射 | 重定向域名、拦截流量、欺骗受本地控制的服务 |
| `/etc/sudoers` | 定义哪些用户可以运行 `sudo` 命令以及适用条件 | 损坏的 sudoers 文件可能向攻击者账户授予 root 或不当权限 |
| `/private/var/db/dslocal/nodes/Default/users/` | 本地用户账户定义 plist | 篡改可用于创建或修改用户账户、密码哈希或用户元数据 |
| `/System/Library/Extensions/` / `/Library/Extensions/` | 内核扩展 / 驱动程序 | 安装或修改 kext 可能导致获得内核级控制；SIP / 签名策略对此有严格保护 |
| `/private/var/db/SystemPolicyConfiguration/` | 存储系统策略实施配置（例如 Gatekeeper、notarization） | 篡改这些文件可能绕过策略检查或信任规则 |
| `/usr/libexec/ssh-keysign`、`/etc/ssh/ssh_config`、`/etc/ssh/sshd_config` | SSH 辅助二进制文件和配置文件 | 配置错误会导致 SSH 安全性薄弱、未经授权的访问或使用不安全算法 |
| `/System/Library/Sandbox/Profiles` | 用于限制进程操作的系统 sandbox 配置文件（SBPL） | 替换或修改配置文件可能带来 sandbox escape 攻击面或削弱隔离 |

> **注意**：其中许多路径位于 SIP 保护的目录（例如 `/System`）下，除非禁用或绕过 SIP，否则无法写入。  


## 通用二进制文件与 Mach-O 格式

Mach-O 是 macOS 上的原生可执行文件格式。通用二进制文件（也称 fat 二进制文件）会将多个特定架构的 Mach-O 切片封装在一个文件中；专门的页面会介绍这两种格式：

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS 内存转储

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## 文件风险与处理程序元数据

LaunchServices、文件 quarantine 和 Gatekeeper 会共同影响 macOS 处理下载文件的方式，以及为扩展名和 URL scheme 选择应用程序的方式。它们的数据库和内部资源文件会随版本变化；请参阅专门的页面，不要将私有 CoreTypes 路径视为稳定的策略接口：

在提供旧版 CoreTypes 风险元数据的系统版本中，该元数据位于 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` 下，常见类别包括：<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**：根据适用的应用程序策略，被认为足够安全、可以自动打开的内容。
- **`LSRiskCategoryNeutral`**：通常不会触发警告，也不会自动打开的内容。
- **`LSRiskCategoryUnsafeExecutable`**：可执行内容，应向用户显示应用程序警告。
- **`LSRiskCategoryMayContainUnsafeExecutable`**：可能包含可执行内容、需要进一步检查的容器，例如归档文件。

这些属于实现细节，而非稳定的公共策略 API；请在待测 macOS 版本上确认实际元数据以及 Safari / Gatekeeper 的行为。

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## 日志文件

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：包含下载文件的信息，例如文件的下载来源 URL。
- **统一日志**：在当前 macOS 版本中，使用 `log show` 和 `log stream` 查询系统和应用程序事件。 <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** 和 **`/private/var/log/asl/*.asl`**：旧版日志记录文件，在较旧的系统上可能仍有参考价值。在这些系统版本中，`/System/Library/LaunchDaemons/com.apple.syslogd.plist` 用于配置 `syslogd`；`launchctl list | grep com.apple.syslogd` 可帮助判断该服务是否已加载。
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：存储通过 "Finder" 最近访问的文件和应用程序。
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**：与登录项相关的旧版偏好设置路径；现代 macOS 版本还使用其他机制。
- **`$HOME/Library/Logs/DiskUtility.log`**：旧版 Disk Utility 日志，可能包含有关驱动器的信息，包括 USB 设备。
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：无线接入点相关数据。
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：旧版 launchd 覆盖数据。



## References

- [1] [Apple - 文件系统编程指南](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle 编程指南](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld shared cache 概述](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - 文件系统编程指南：macOS 文件系统安全性](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS 手册页](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS 手册页](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS 手册页](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums - 解包 Apple 归档文件](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Shell 脚本安全性：特殊文件权限标志](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - 代码签名任务：安装程序包](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
