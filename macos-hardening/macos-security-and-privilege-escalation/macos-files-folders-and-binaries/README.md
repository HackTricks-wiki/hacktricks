# macOS ファイル、フォルダ、バイナリ＆メモリ

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>を学ぶ！</strong></summary>

HackTricks をサポートする他の方法：

- **HackTricks で企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **Discordグループ**に**参加**💬(https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>

## ファイル階層レイアウト

- **/Applications**: インストールされたアプリはここにあるはずです。すべてのユーザがアクセスできます。
- **/bin**: コマンドラインバイナリ
- **/cores**: 存在する場合、コアダンプを保存するために使用されます
- **/dev**: すべてがファイルとして扱われるため、ここにハードウェアデバイスが保存されていることがあります。
- **/etc**: 設定ファイル
- **/Library**: 好み、キャッシュ、ログに関連する多くのサブディレクトリとファイルがここに見つかります。ルートと各ユーザのディレクトリにLibraryフォルダが存在します。
- **/private**: 文書化されていませんが、言及されている多くのフォルダはprivateディレクトリへのシンボリックリンクです。
- **/sbin**: システムの基本バイナリ（管理に関連する）
- **/System**: OS Xを実行するためのファイル。ここには主にApple固有のファイルのみがあります（サードパーティ製ではありません）。
- **/tmp**: ファイルは3日後に削除されます（/private/tmpへのソフトリンクです）
- **/Users**: ユーザーのホームディレクトリ。
- **/usr**: 設定とシステムバイナリ
- **/var**: ログファイル
- **/Volumes**: マウントされたドライブはここに表示されます。
- **/.vol**: `stat a.txt`を実行すると、`16777223 7545753 -rw-r--r-- 1 username wheel ...`のようなものが得られます。最初の数値はファイルが存在するボリュームのID番号であり、2番目の数値はinode番号です。このファイルの内容には、その情報を使用して`cat /.vol/16777223/7545753`を実行することでアクセスできます。

### アプリケーションフォルダ

- **システムアプリケーション**は`/System/Applications`にあります
- **インストールされた**アプリケーションは通常、`/Applications`または`~/Applications`にインストールされます
- **アプリケーションデータ**は、ルートとして実行されるアプリケーションの場合は`/Library/Application Support`、ユーザーとして実行されるアプリケーションの場合は`~/Library/Application Support`にあります。
- **ルートとして実行する必要がある**サードパーティアプリケーションの**デーモン**は通常`/Library/PrivilegedHelperTools/`にあります
- **サンドボックス化された**アプリケーションは`~/Library/Containers`フォルダにマップされます。各アプリには、アプリケーションのバンドルIDに従って名前が付けられたフォルダがあります（`com.apple.Safari`など）。
- **カーネル**は`/System/Library/Kernels/kernel`にあります
- **Appleのカーネル拡張**は`/System/Library/Extensions`にあります
- **サードパーティのカーネル拡張**は`/Library/Extensions`に保存されています

### 機密情報を含むファイル

MacOSは、パスワードなどの情報をいくつかの場所に保存します：

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### 脆弱なpkgインストーラ

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X固有の拡張子

- **`.dmg`**: Apple Disk Imageファイルはインストーラーで非常に頻繁に使用されます。
- **`.kext`**: 特定の構造に従う必要があり、OS Xバージョンのドライバーです（バンドルです）。
- **`.plist`**: プロパティリストとしても知られ、情報をXMLまたはバイナリ形式で保存します。
- XMLまたはバイナリです。バイナリの場合は次のように読み取ることができます：
  - `defaults read config.plist`
  - `/usr/libexec/PlistBuddy -c print config.plsit`
  - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
  - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
  - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: ディレクトリ構造に従うAppleアプリケーション（バンドル）です。
- **`.dylib`**: ダイナミックライブラリ（WindowsのDLLファイルのようなもの）
- **`.pkg`**: xar（eXtensible Archive形式）と同じです。これらのファイルの内容をインストールするには、installerコマンドを使用できます。
- **`.DS_Store`**: このファイルは各ディレクトリにあり、ディレクトリの属性とカスタマイズを保存します。
- **`.Spotlight-V100`**: このフォルダはシステムのすべてのボリュームのルートディレクトリに表示されます。
- **`.metadata_never_index`**: このファイルがボリュームのルートにある場合、Spotlightはそのボリュームをインデックスしません。
- **`.noindex`**: この拡張子を持つファイルとフォルダはSpotlightによってインデックスされません。

### macOSバンドル

バンドルは、Finderでオブジェクトのように見える**ディレクトリ**です（`*.app`ファイルの例があります）。

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld Shared Cache

macOS（およびiOS）では、フレームワークやdylibなどのすべてのシステム共有ライブラリが**1つのファイル**に結合され、**dyld共有キャッシュ**と呼ばれています。コードをより速く読み込むことができるため、パフォーマンスが向上します。

dyld共有キャッシュと同様に、カーネルとカーネル拡張もカーネルキャッシュにコンパイルされ、起動時に読み込まれます。

1つのファイルからライブラリを抽出するには、以前はバイナリ[dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip)を使用することができましたが、現在は機能しないかもしれません。代わりに[**dyldextractor**](https://github.com/arandomdev/dyldextractor)を使用できます：

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

古いバージョンでは、**`/System/Library/dyld/`** で **共有キャッシュ** を見つけることができるかもしれません。

iOSでは、**`/System/Library/Caches/com.apple.dyld/`** にそれらを見つけることができます。

{% hint style="success" %}
`dyld_shared_cache_util` ツールが機能しなくても、**共有dyldバイナリをHopperに渡す**ことができ、Hopperはすべてのライブラリを識別し、調査したい**どれを選択するか**を許可します。
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## 特別なファイル権限

### フォルダの権限

**フォルダ**では、**read** は **リスト化** を許可し、**write** は **削除** および **ファイルの書き込み** を許可し、**execute** は **ディレクトリのトラバース** を許可します。つまり、例えば、ユーザーが**実行権限を持たないディレクトリ**内の**ファイルに対する読み取り権限**を持っていても、そのファイルを**読み取ることはできません**。

### フラグ修飾子

ファイルに設定されるいくつかのフラグがあり、ファイルの動作を異なるものにすることができます。`ls -lO /path/directory` でディレクトリ内のファイルのフラグを**確認**できます。

* **`uchg`**: **uchange** フラグとして知られ、**ファイルの変更や削除を防止**します。設定するには: `chflags uchg file.txt`
* ルートユーザーは**フラグを削除**してファイルを変更できます
* **`restricted`**: このフラグはファイルを**SIPで保護**します（このフラグをファイルに追加することはできません）。
* **`Sticky bit`**: スティッキービットが設定されたディレクトリの場合、**ディレクトリの所有者またはルートのみがファイルの名前を変更または削除**できます。通常、これは/tmpディレクトリに設定され、通常のユーザーが他のユーザーのファイルを削除したり移動したりするのを防ぎます。

### **ファイルACL**

ファイルの**ACL**には、異なるユーザーに**より細かい権限**を割り当てることができる**ACE**（アクセス制御エントリ）が含まれています。

これらの権限を**ディレクトリ**に付与することが可能です: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`。\
そして**ファイル**に対して: `read`, `write`, `append`, `execute`。

ファイルにACLが含まれている場合、**権限をリスト表示する際に**「+」が表示されます。
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
ファイルのACLを次のようにして読むことができます：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
あなたはこれで**すべてのACLを持つファイルを見つけることができます**（これは非常に遅いです）:
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### リソースフォーク | macOS ADS

これは、**MacOS** マシンで **Alternate Data Streams** を取得する方法です。ファイル内にコンテンツを保存することができます。**file/..namedfork/rsrc** という名前のファイル内の **com.apple.ResourceFork** という拡張属性に保存します。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
次のコマンドを使用して、この拡張属性を持つすべてのファイルを見つけることができます：

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Universal binaries &** Mach-o Format

Mac OSのバイナリは通常、**universal binaries**としてコンパイルされます。**universal binary**は**同じファイル内で複数のアーキテクチャをサポート**できます。

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOSメモリダンプ

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## リスクカテゴリファイル Mac OS

ディレクトリ`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`には、**異なるファイル拡張子に関連するリスクに関する情報**が格納されています。このディレクトリはファイルをさまざまなリスクレベルに分類し、Safariがこれらのファイルをダウンロード後にどのように処理するかに影響を与えます。カテゴリは次のとおりです：

- **LSRiskCategorySafe**：このカテゴリのファイルは**完全に安全**と見なされます。Safariはこれらのファイルを自動的にダウンロード後に開きます。
- **LSRiskCategoryNeutral**：これらのファイルには警告がなく、Safariによって**自動的に開かれません**。
- **LSRiskCategoryUnsafeExecutable**：このカテゴリのファイルは、そのファイルがアプリケーションであることを示す**警告をトリガー**します。これはユーザーに警告するセキュリティ対策となります。
- **LSRiskCategoryMayContainUnsafeExecutable**：このカテゴリは、実行可能ファイルを含む可能性があるアーカイブなどのファイル用です。Safariは、すべてのコンテンツが安全または中立であることを検証できない限り、**警告をトリガー**します。

## ログファイル

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：ダウンロードしたファイルに関する情報が含まれています。ダウンロード元のURLなどが含まれます。
* **`/var/log/system.log`**：OSXシステムのメインログ。com.apple.syslogd.plistはsysloggingの実行を担当しています（`launchctl list`で "com.apple.syslogd" を検索して無効になっていないか確認できます）。
* **`/private/var/log/asl/*.asl`**：これらは興味深い情報が含まれる可能性のあるApple System Logsです。
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：最近「Finder」を介してアクセスしたファイルやアプリケーションが格納されています。
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**：システム起動時に起動するアイテムが格納されています。
* **`$HOME/Library/Logs/DiskUtility.log`**：DiskUtility Appのログファイル（USBを含むドライブに関する情報が含まれます）。
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：ワイヤレスアクセスポイントに関するデータ。
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：無効になっているデーモンのリスト。
