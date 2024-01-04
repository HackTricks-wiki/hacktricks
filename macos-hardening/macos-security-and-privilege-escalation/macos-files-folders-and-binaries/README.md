# macOS ファイル、フォルダ、バイナリ & メモリ

<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**PEASS ファミリー**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFT**](https://opensea.io/collection/the-peass-family) コレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に**参加する**か、[**テレグラムグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**
* **HackTricks** の [**GitHub リポジトリ**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) に PR を提出して、あなたのハッキングのコツを共有する。

</details>

## ファイル階層レイアウト

* **/Applications**: インストールされたアプリはここにあるべきです。全ユーザーがアクセスできます。
* **/bin**: コマンドラインバイナリ
* **/cores**: 存在する場合、コアダンプを保存するために使用されます
* **/dev**: すべてがファイルとして扱われるので、ハードウェアデバイスがここに保存されている可能性があります。
* **/etc**: 設定ファイル
* **/Library**: 優先順位、キャッシュ、ログに関連する多くのサブディレクトリとファイルがここにあります。ルートと各ユーザーのディレクトリにライブラリフォルダが存在します。
* **/private**: 文書化されていませんが、多くの前述のフォルダはプライベートディレクトリへのシンボリックリンクです。
* **/sbin**: 管理に関連する重要なシステムバイナリ
* **/System**: OS X を動作させるためのファイル。ここには主に Apple 固有のファイルが見つかるはずです（サードパーティ製ではない）。
* **/tmp**: ファイルは3日後に削除されます（/private/tmp へのソフトリンクです）
* **/Users**: ユーザーのホームディレクトリ。
* **/usr**: 設定とシステムバイナリ
* **/var**: ログファイル
* **/Volumes**: マウントされたドライブがここに表示されます。
* **/.vol**: `stat a.txt` を実行すると `16777223 7545753 -rw-r--r-- 1 username wheel ...` のようなものが得られ、最初の数字はファイルが存在するボリュームの ID 番号で、2番目の数字は inode 番号です。この情報を使って `cat /.vol/16777223/7545753` を実行することで、/.vol/ を通じてこのファイルの内容にアクセスできます。

### アプリケーションフォルダ

* **システムアプリケーション**は `/System/Applications` の下に位置しています
* **インストールされた** アプリケーションは通常 `/Applications` または `~/Applications` にインストールされます
* **アプリケーションデータ**は、root として実行されるアプリケーションの場合は `/Library/Application Support` に、ユーザーとして実行されるアプリケーションの場合は `~/Library/Application Support` に見つかります。
* root として実行する必要があるサードパーティアプリケーションの **デーモン** は通常 `/Library/PrivilegedHelperTools/` に位置しています
* **サンドボックス化された** アプリは `~/Library/Containers` フォルダにマッピングされます。各アプリにはアプリケーションのバンドル ID（`com.apple.Safari`）に従って名前が付けられたフォルダがあります。
* **カーネル**は `/System/Library/Kernels/kernel` に位置しています
* **Apple のカーネル拡張**は `/System/Library/Extensions` に位置しています
* **サードパーティのカーネル拡張**は `/Library/Extensions` に保存されます

### 機密情報を含むファイル

MacOS はパスワードなどの情報をいくつかの場所に保存します：

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### 脆弱な pkg インストーラー

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X 固有の拡張機能

* **`.dmg`**: Apple Disk Image ファイルはインストーラーで非常に頻繁に使用されます。
* **`.kext`**: 特定の構造に従う必要があり、OS X のドライバーのバージョンです（バンドルです）。
* **`.plist`**: プロパティリストとしても知られ、情報を XML またはバイナリ形式で保存します。
* XML またはバイナリ形式であることができます。バイナリ形式は以下の方法で読むことができます：
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: ディレクトリ構造に従う Apple アプリケーション（バンドルです）。
* **`.dylib`**: 動的ライブラリ（Windows の DLL ファイルのようなもの）
* **`.pkg`**: xar（eXtensible Archive format）と同じです。インストーラーコマンドを使用して、これらのファイルの内容をインストールすることができます。
* **`.DS_Store`**: このファイルは各ディレクトリにあり、ディレクトリの属性とカスタマイズを保存します。
* **`.Spotlight-V100`**: このフォルダはシステム上のすべてのボリュームのルートディレクトリに表示されます。
* **`.metadata_never_index`**: このファイルがボリュームのルートにある場合、Spotlight はそのボリュームをインデックスしません。
* **`.noindex`**: この拡張子を持つファイルとフォルダは Spotlight によってインデックスされません。

### macOS バンドル

基本的に、バンドルはファイルシステム内の **ディレクトリ構造** です。興味深いことに、デフォルトではこのディレクトリは Finder で **単一のオブジェクトのように見えます**（`.app` のように）。&#x20;

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld 共有キャッシュ

macOS（および iOS）では、フレームワークや dylibs などのすべてのシステム共有ライブラリが **単一のファイルに組み合わされています**。これは **dyld 共有キャッシュ** と呼ばれます。これによりパフォーマンスが向上し、コードをより速く読み込むことができます。

dyld 共有キャッシュと同様に、カーネルとカーネル拡張もカーネルキャッシュにコンパイルされ、ブート時に読み込まれます。

単一ファイルの dylib 共有キャッシュからライブラリを抽出するために、以前は [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip) というバイナリを使用することができましたが、現在は機能していない可能性があります。しかし、[**dyldextractor**](https://github.com/arandomdev/dyldextractor) を使用することもできます：

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

iOSでは、**`/System/Library/Caches/com.apple.dyld/`** で見つけることができます。

{% hint style="success" %}
`dyld_shared_cache_util` ツールが機能しない場合でも、**共有 dyld バイナリを Hopper に渡す** ことができ、Hopper はすべてのライブラリを識別し、調査したいものを **選択する** ことができます：
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## 特別なファイル権限

### フォルダ権限

**フォルダ**では、**読み取り** は **リスト表示** を許可し、**書き込み** は **削除** とフォルダ内のファイルへの **書き込み** を許可し、**実行** はディレクトリの **移動** を許可します。例えば、実行権限がないディレクトリ内のファイルに対する **読み取り権限** を持つユーザーは、ファイルを **読むことができません**。

### フラグ修飾子

ファイルの動作を変更するフラグがいくつかあります。ディレクトリ内のファイルのフラグを `ls -lO /path/directory` で **確認できます**

* **`uchg`**: **uchange** フラグとして知られ、ファイルの変更や削除を **防ぎます**。設定するには: `chflags uchg file.txt`
* root ユーザーはフラグを **削除して** ファイルを変更できます
* **`restricted`**: このフラグはファイルを **SIP によって保護される** ようにします（このフラグをファイルに追加することはできません）。
* **`Sticky bit`**: sticky bit が設定されたディレクトリでは、**ディレクトリの所有者または root のみが** ファイルの名前を変更したり削除したりできます。通常、他のユーザーが他のユーザーのファイルを削除または移動するのを防ぐために /tmp ディレクトリに設定されます。

### **ファイル ACL**

ファイル **ACL** には、異なるユーザーにより **詳細な権限** を割り当てることができる **ACE**（アクセス制御エントリ）が含まれています。

**ディレクトリ** には次の権限を付与することができます: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`。\
そして **ファイル** には: `read`, `write`, `append`, `execute`。

ファイルに ACL が含まれている場合、権限をリスト表示するときに **"+"** が表示されます。
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
```
ファイルの**ACLを読む**には以下を使用します:
```
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
**ACLが設定されているすべてのファイル**は、以下の方法で見つけることができます（これは非常に遅いです）：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### リソースフォーク | macOS ADS

これは**macOS**マシンで**Alternate Data Streams**を取得する方法です。**com.apple.ResourceFork**という拡張属性の中に内容を保存することにより、**file/..namedfork/rsrc**内のファイルに保存できます。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
以下のコマンドで、この拡張属性を含む**すべてのファイルを見つける**ことができます：

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **ユニバーサルバイナリ &** Mach-o フォーマット

Mac OS のバイナリは通常、**ユニバーサルバイナリ**としてコンパイルされます。**ユニバーサルバイナリ**は、同じファイルで**複数のアーキテクチャをサポート**できます。

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS メモリダンプ

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## リスクカテゴリファイル Mac OS

ファイル `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` には、ファイル拡張子に応じたファイルのリスクが含まれています。

可能なカテゴリには以下が含まれます：

* **LSRiskCategorySafe**: **完全に** **安全**; Safari はダウンロード後に自動的に開きます
* **LSRiskCategoryNeutral**: 警告はありませんが、**自動的には開かれません**
* **LSRiskCategoryUnsafeExecutable**: 「このファイルはアプリケーションです...」という**警告を引き起こします**
* **LSRiskCategoryMayContainUnsafeExecutable**: 実行可能ファイルを含むアーカイブなどのためのものです。Safari がすべての内容が安全または中立であると判断できない限り、**警告を引き起こします**。

## ログファイル

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: ダウンロードされたファイルに関する情報、例えばダウンロード元のURLが含まれています。
* **`/var/log/system.log`**: OSX システムのメインログ。com.apple.syslogd.plist は syslogging の実行を担当しています（`launchctl list` で "com.apple.syslogd" を探して無効になっているか確認できます）。
* **`/private/var/log/asl/*.asl`**: Apple システムログで、興味深い情報が含まれている可能性があります。
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" を通じて最近アクセスしたファイルやアプリケーションを保存します。
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: システム起動時に起動するアイテムを保存します。
* **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtility アプリのログファイル（ドライブに関する情報、USB を含む）。
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: ワイヤレスアクセスポイントに関するデータ。
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: 無効にされたデーモンのリスト。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWS ハッキングをゼロからヒーローまで学ぶ</strong></a><strong>!</strong></summary>

HackTricks をサポートする他の方法：

* **HackTricks にあなたの**会社を広告したい、または**HackTricks を PDF でダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に**参加する**、または **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github リポジトリにあなたのハッキングのコツを PR で共有する。

</details>
