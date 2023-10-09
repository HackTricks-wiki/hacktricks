# macOS ファイル、フォルダ、バイナリ＆メモリ

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## ファイル階層レイアウト

* **/Applications**: インストールされたアプリはここにあります。すべてのユーザーがアクセスできます。
* **/bin**: コマンドラインバイナリ
* **/cores**: 存在する場合、コアダンプを保存するために使用されます
* **/dev**: すべてがファイルとして扱われるため、ここにハードウェアデバイスが保存されている場合があります。
* **/etc**: 設定ファイル
* **/Library**: 好み、キャッシュ、ログに関連する多くのサブディレクトリとファイルがここにあります。ルートと各ユーザーのディレクトリにLibraryフォルダが存在します。
* **/private**: 文書化されていませんが、多くの言及されたフォルダはprivateディレクトリへのシンボリックリンクです。
* **/sbin**: システム管理に関連する必須のシステムバイナリ
* **/System**: OS Xを実行するためのファイル。ここには主にAppleの固有のファイルがあります（サードパーティではありません）。
* **/tmp**: ファイルは3日後に削除されます（/private/tmpへのソフトリンクです）
* **/Users**: ユーザーのホームディレクトリ。
* **/usr**: 設定とシステムバイナリ
* **/var**: ログファイル
* **/Volumes**: マウントされたドライブはここに表示されます。
* **/.vol**: `stat a.txt`を実行すると、`16777223 7545753 -rw-r--r-- 1 username wheel ...`のような結果が得られます。最初の数値はファイルが存在するボリュームのID番号であり、2番目の数値はinode番号です。このファイルの内容には、その情報を使用して`cat /.vol/16777223/7545753`を実行することでアクセスできます。

### アプリケーションフォルダ

* **システムアプリケーション**は`/System/Applications`にあります。
* **インストールされた**アプリケーションは通常`/Applications`または`~/Applications`にインストールされます。
* **アプリケーションデータ**は、ルートとユーザーとして実行されるアプリケーションの場合は`/Library/Application Support`、ユーザーとして実行されるアプリケーションの場合は`~/Library/Application Support`にあります。
* **ルートとして実行する必要がある**サードパーティのアプリケーション**デーモン**は通常`/Library/PrivilegedHelperTools/`にあります。
* **サンドボックス化された**アプリは`~/Library/Containers`フォルダにマップされます。各アプリには、アプリケーションのバンドルID（`com.apple.Safari`など）に基づいた名前のフォルダがあります。
* **カーネル**は`/System/Library/Kernels/kernel`にあります。
* **Appleのカーネル拡張**は`/System/Library/Extensions`にあります。
* **サードパーティのカーネル拡張**は`/Library/Extensions`に保存されます。

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

* **`.dmg`**: Appleディスクイメージファイルはインストーラーに非常に頻繁に使用されます。
* **`.kext`**: 特定の構造に従う必要があり、ドライバーのOS Xバージョンです（バンドルです）。
* **`.plist`**: プロパティリストとしても知られ、情報をXMLまたはバイナリ形式で保存します。
* XMLまたはバイナリ形式になります。バイナリ形式のものは次のコマンドで読み取ることができます：
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: ディレクトリ構造に従うAppleアプリケーションです（バンドルです）。
* **`.dylib`**: 動的ライブラリ（WindowsのDLLファイルのようなもの）
* **`.pkg`**: xar（eXtensible Archive形式）と同じです。installerコマンドを使用してこれらのファイルの内容をインストールできます。
* **`.DS_Store`**: このファイルは各ディレクトリにあり、ディレクトリの属性とカスタマイズを保存します。
* **`.Spotlight-V100`**: このフォルダはシステムのすべてのボリュームのルートディレクトリに表示されます。
* **`.metadata_never_index`**: このファイルがボリュームのルートにある場合、Spotlightはそのボリュームをインデックスしません。
* **`.noindex`**: この拡張子を持つファイルとフォルダはSpotlightによってインデックスされません。
### macOSバンドル

基本的に、バンドルはファイルシステム内の**ディレクトリ構造**です。興味深いことに、このディレクトリはデフォルトではFinderで**単一のオブジェクトのように見えます**（例：`.app`）。

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld共有キャッシュ

macOS（およびiOS）では、フレームワークやdylibなどのシステム共有ライブラリは、**単一のファイル**であるdyld共有キャッシュに結合されます。これにより、コードの読み込みが高速化されます。

dyld共有キャッシュと同様に、カーネルとカーネル拡張もカーネルキャッシュにコンパイルされ、起動時に読み込まれます。

単一のファイルdylib共有キャッシュからライブラリを抽出するためには、以前はバイナリの[dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip)を使用することができましたが、現在は動作しないかもしれません。代わりに[**dyldextractor**](https://github.com/arandomdev/dyldextractor)を使用することもできます。

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

古いバージョンでは、**共有キャッシュ**を**`/System/Library/dyld/`**に見つけることができるかもしれません。

iOSでは、それらを**`/System/Library/Caches/com.apple.dyld/`**に見つけることができます。

{% hint style="success" %}
`dyld_shared_cache_util`ツールが機能しなくても、**共有dyldバイナリをHopperに渡す**ことができ、Hopperはすべてのライブラリを識別し、**調査したいライブラリを選択**することができます。
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## 特殊なファイルのパーミッション

### フォルダのパーミッション

**フォルダ**では、**読み取り**は**リスト表示**を許可し、**書き込み**は**ファイルの削除**と**書き込み**を許可し、**実行**は**ディレクトリの移動**を許可します。したがって、例えば、**ファイル内の読み取り権限**を持つユーザーが、**実行権限がない**ディレクトリ内にあるファイルを**読み取ることはできません**。

### フラグ修飾子

ファイルに設定されているフラグによって、ファイルの動作が異なるようになります。`ls -lO /path/directory`でディレクトリ内のファイルのフラグを**チェック**することができます。

* **`uchg`**：**uchange**フラグとして知られており、**ファイル**の変更や削除を**防止**します。設定するには：`chflags uchg file.txt`
* ルートユーザーはフラグを**削除**してファイルを変更できます
* **`restricted`**：このフラグは、ファイルを**SIPで保護**します（このフラグをファイルに追加することはできません）。
* **`Sticky bit`**：スティッキービットが設定されたディレクトリでは、**ディレクトリの所有者またはルートのみがファイルの名前を変更または削除**できます。通常、これは/tmpディレクトリに設定され、一般ユーザーが他のユーザーのファイルを削除または移動できないようにします。

### **ファイルACL**

ファイルの**ACL（アクセス制御エントリ）**には、異なるユーザーに対してより**細かい権限**を割り当てることができる**ACE（アクセス制御エントリ）**が含まれています。

ディレクトリにこれらの権限を付与することができます：`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
ファイルには次の権限があります：`read`、`write`、`append`、`execute`。

ファイルにACLが含まれている場合、パーミッションをリスト表示する際に**"+"が表示されます**。
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
次のコマンドでファイルのACLを読むことができます：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
次のコマンドを使用して、**ACLを持つすべてのファイル**を見つけることができます（これは非常に遅いです）:

```bash
find / -type f -exec ls -le {} \; 2>/dev/null
```

このコマンドは、ACLを持つすべてのファイルを検索し、それぞれのファイルのACL情報を表示します。ただし、このコマンドは非常に時間がかかる可能性があるため、注意が必要です。
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### リソースフォーク | macOS ADS

これは、**macOSマシンでの代替データストリーム**を取得する方法です。ファイルを**file/..namedfork/rsrc**に保存することで、**com.apple.ResourceFork**という拡張属性内にコンテンツを保存することができます。
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

## **ユニバーサルバイナリと**Mach-oフォーマット

Mac OSのバイナリは通常、**ユニバーサルバイナリ**としてコンパイルされます。**ユニバーサルバイナリ**は、**同じファイル内で複数のアーキテクチャをサポート**することができます。

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOSメモリダンプ

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## リスクカテゴリファイル Mac OS

ファイル `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` には、ファイルの拡張子に応じたリスクが含まれています。

可能なカテゴリは以下の通りです：

* **LSRiskCategorySafe**：**完全に安全**；ダウンロード後にSafariが自動的に開く
* **LSRiskCategoryNeutral**：警告はないが、**自動的に開かれない**
* **LSRiskCategoryUnsafeExecutable**：「このファイルはアプリケーションです...」という**警告をトリガー**する
* **LSRiskCategoryMayContainUnsafeExecutable**：実行可能ファイルを含むアーカイブなどに使用されます。Safariがすべてのコンテンツが安全または中立であることを判断できない場合、**警告をトリガー**します。

## ログファイル

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：ダウンロードされたファイルに関する情報が含まれています。ダウンロード元のURLなど。
* **`/var/log/system.log`**：OSXシステムのメインログ。sysloggingの実行はcom.apple.syslogd.plistが担当しています（`launchctl list`で「com.apple.syslogd」を検索して無効になっているかどうかを確認できます）。
* **`/private/var/log/asl/*.asl`**：興味深い情報が含まれている可能性のあるApple System Logsです。
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：「Finder」を介して最近アクセスしたファイルとアプリケーションを保存します。
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**：システム起動時に起動するアイテムを保存します。
* **`$HOME/Library/Logs/DiskUtility.log`**：DiskUtilityアプリのログファイル（ドライブに関する情報、USBを含む）
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：ワイヤレスアクセスポイントに関するデータ。
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：無効化されたデーモンのリスト。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
