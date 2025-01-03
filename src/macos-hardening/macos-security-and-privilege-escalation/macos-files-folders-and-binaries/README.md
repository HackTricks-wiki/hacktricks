# macOSのファイル、フォルダー、バイナリとメモリ

{{#include ../../../banners/hacktricks-training.md}}

## ファイル階層レイアウト

- **/Applications**: インストールされたアプリがここにあります。すべてのユーザーがアクセスできます。
- **/bin**: コマンドラインバイナリ
- **/cores**: 存在する場合、コアダンプを保存するために使用されます。
- **/dev**: すべてがファイルとして扱われるため、ここにハードウェアデバイスが保存されているのを見ることができます。
- **/etc**: 設定ファイル
- **/Library**: 設定、キャッシュ、ログに関連する多くのサブディレクトリとファイルがここにあります。Libraryフォルダーはルートと各ユーザーのディレクトリに存在します。
- **/private**: 文書化されていませんが、前述の多くのフォルダーはプライベートディレクトリへのシンボリックリンクです。
- **/sbin**: 必要なシステムバイナリ（管理に関連）
- **/System**: OS Xを実行するためのファイルです。ここには主にApple特有のファイル（サードパーティではない）があります。
- **/tmp**: ファイルは3日後に削除されます（これは/private/tmpへのソフトリンクです）。
- **/Users**: ユーザーのホームディレクトリ。
- **/usr**: 設定とシステムバイナリ
- **/var**: ログファイル
- **/Volumes**: マウントされたドライブがここに表示されます。
- **/.vol**: `stat a.txt`を実行すると、`16777223 7545753 -rw-r--r-- 1 username wheel ...`のような出力が得られます。最初の数字はファイルが存在するボリュームのID番号で、2番目はinode番号です。この情報を使って`cat /.vol/16777223/7545753`を実行することで、このファイルの内容にアクセスできます。

### アプリケーションフォルダー

- **システムアプリケーション**は`/System/Applications`にあります。
- **インストールされた**アプリケーションは通常`/Applications`または`~/Applications`にインストールされます。
- **アプリケーションデータ**は、rootとして実行されるアプリケーションのために`/Library/Application Support`に、ユーザーとして実行されるアプリケーションのために`~/Library/Application Support`にあります。
- サードパーティのアプリケーションの**デーモン**は、通常`/Library/PrivilegedHelperTools/`にあります。
- **サンドボックス化された**アプリは`~/Library/Containers`フォルダーにマッピングされます。各アプリにはアプリケーションのバンドルID（`com.apple.Safari`）に従った名前のフォルダーがあります。
- **カーネル**は`/System/Library/Kernels/kernel`にあります。
- **Appleのカーネル拡張**は`/System/Library/Extensions`にあります。
- **サードパーティのカーネル拡張**は`/Library/Extensions`に保存されています。

### 機密情報を含むファイル

MacOSはパスワードなどの情報をいくつかの場所に保存します：

{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 脆弱なpkgインストーラー

{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X特有の拡張子

- **`.dmg`**: Apple Disk Imageファイルはインストーラーに非常に頻繁に使用されます。
- **`.kext`**: 特定の構造に従う必要があり、OS Xバージョンのドライバーです。（バンドルです）
- **`.plist`**: プロパティリストとも呼ばれ、XMLまたはバイナリ形式で情報を保存します。
- XMLまたはバイナリのいずれかです。バイナリのものは次のコマンドで読み取れます：
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: ディレクトリ構造に従ったAppleアプリケーション（バンドルです）。
- **`.dylib`**: 動的ライブラリ（Windows DLLファイルのようなもの）
- **`.pkg`**: xar（eXtensible Archive format）と同じです。インストーラーコマンドを使用してこれらのファイルの内容をインストールできます。
- **`.DS_Store`**: このファイルは各ディレクトリにあり、ディレクトリの属性とカスタマイズを保存します。
- **`.Spotlight-V100`**: このフォルダーはシステムのすべてのボリュームのルートディレクトリに表示されます。
- **`.metadata_never_index`**: このファイルがボリュームのルートにある場合、Spotlightはそのボリュームをインデックスしません。
- **`.noindex`**: この拡張子を持つファイルとフォルダーはSpotlightによってインデックスされません。
- **`.sdef`**: バンドル内のファイルで、AppleScriptからアプリケーションとどのように対話できるかを指定します。

### macOSバンドル

バンドルは**Finderでオブジェクトのように見える**（バンドルの例は`*.app`ファイルです）**ディレクトリ**です。

{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld共有ライブラリキャッシュ（SLC）

macOS（およびiOS）では、すべてのシステム共有ライブラリ、フレームワークやdylibのようなものが**単一のファイル**に**結合されて**おり、これを**dyld共有キャッシュ**と呼びます。これにより、コードをより速く読み込むことができ、パフォーマンスが向上します。

これはmacOSの`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`にあり、古いバージョンでは**`/System/Library/dyld/`**に**共有キャッシュ**が見つかるかもしれません。\
iOSでは**`/System/Library/Caches/com.apple.dyld/`**にあります。

dyld共有キャッシュと同様に、カーネルとカーネル拡張もカーネルキャッシュにコンパイルされ、ブート時にロードされます。

単一ファイルのdylib共有キャッシュからライブラリを抽出するために、バイナリの[dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip)を使用することが可能でしたが、現在は機能しないかもしれませんが、[**dyldextractor**](https://github.com/arandomdev/dyldextractor)を使用することもできます：
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> `dyld_shared_cache_util` ツールが機能しなくても、**共有された dyld バイナリを Hopper に渡す**ことで、Hopper はすべてのライブラリを特定し、**調査したいものを選択**できるようになります：

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

一部のエクストラクターは、dylibs がハードコーディングされたアドレスでプリリンクされているため、未知のアドレスにジャンプする可能性があるため、機能しない場合があります。

> [!TIP]
> エミュレーターを使用して Xcode で他の \*OS デバイスの共有ライブラリキャッシュをダウンロードすることも可能です。これらは次の場所にダウンロードされます： ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`、例：`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### SLC のマッピング

**`dyld`** は、SLC がマッピングされているかどうかを知るためにシステムコール **`shared_region_check_np`** を使用し（アドレスを返します）、**`shared_region_map_and_slide_np`** を使用して SLC をマッピングします。

SLC が最初の使用時にスライドしても、すべての **プロセス** は **同じコピー** を使用するため、攻撃者がシステムでプロセスを実行できる場合、**ASLR** 保護が **排除されます**。これは実際に過去に悪用され、共有領域ページャーで修正されました。

ブランチプールは、画像マッピングの間に小さなスペースを作成する小さな Mach-O dylibs であり、関数を介入させることを不可能にします。

### SLC のオーバーライド

環境変数を使用して：

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> これにより、新しい共有ライブラリキャッシュをロードできます。
- **`DYLD_SHARED_CACHE_DIR=avoid`** として、ライブラリを共有キャッシュの実際のものへのシンボリックリンクで手動で置き換えます（それらを抽出する必要があります）。

## 特殊ファイル権限

### フォルダの権限

**フォルダ**内の **読み取り** は **リスト** を許可し、**書き込み** は **削除** と **書き込み** を許可し、**実行** は **ディレクトリを横断** することを許可します。したがって、たとえば、**実行権限がない**ディレクトリ内のファイルに対して **読み取り権限を持つユーザー** は、そのファイルを **読み取ることができません**。

### フラグ修飾子

ファイルに設定できるフラグがいくつかあり、ファイルの動作を異なるものにします。ディレクトリ内のファイルの **フラグを確認** するには `ls -lO /path/directory` を使用します。

- **`uchg`**: **uchange** フラグとして知られ、**ファイル**の変更や削除を **防止** します。設定するには： `chflags uchg file.txt`
- ルートユーザーは **フラグを削除** し、ファイルを変更できます。
- **`restricted`**: このフラグはファイルを **SIP によって保護** します（このフラグをファイルに追加することはできません）。
- **`Sticky bit`**: スティッキービットが設定されたディレクトリでは、**ディレクトリの所有者またはルートのみがファイルを名前変更または削除**できます。通常、これは /tmp ディレクトリに設定され、通常のユーザーが他のユーザーのファイルを削除または移動するのを防ぎます。

すべてのフラグはファイル `sys/stat.h` に見つけることができ（`mdfind stat.h | grep stat.h` を使用して見つけます）、次のようになります：

- `UF_SETTABLE` 0x0000ffff: 所有者変更可能フラグのマスク。
- `UF_NODUMP` 0x00000001: ファイルをダンプしない。
- `UF_IMMUTABLE` 0x00000002: ファイルは変更できません。
- `UF_APPEND` 0x00000004: ファイルへの書き込みは追加のみ可能です。
- `UF_OPAQUE` 0x00000008: ディレクトリはユニオンに対して不透明です。
- `UF_COMPRESSED` 0x00000020: ファイルは圧縮されています（いくつかのファイルシステム）。
- `UF_TRACKED` 0x00000040: この設定があるファイルの削除/名前変更に対する通知はありません。
- `UF_DATAVAULT` 0x00000080: 読み取りおよび書き込みには権限が必要です。
- `UF_HIDDEN` 0x00008000: このアイテムは GUI に表示されるべきではないというヒント。
- `SF_SUPPORTED` 0x009f0000: スーパーユーザーサポートフラグのマスク。
- `SF_SETTABLE` 0x3fff0000: スーパーユーザー変更可能フラグのマスク。
- `SF_SYNTHETIC` 0xc0000000: システム読み取り専用合成フラグのマスク。
- `SF_ARCHIVED` 0x00010000: ファイルはアーカイブされています。
- `SF_IMMUTABLE` 0x00020000: ファイルは変更できません。
- `SF_APPEND` 0x00040000: ファイルへの書き込みは追加のみ可能です。
- `SF_RESTRICTED` 0x00080000: 書き込みには権限が必要です。
- `SF_NOUNLINK` 0x00100000: アイテムは削除、名前変更、またはマウントできません。
- `SF_FIRMLINK` 0x00800000: ファイルはファームリンクです。
- `SF_DATALESS` 0x40000000: ファイルはデータレスオブジェクトです。

### **ファイル ACLs**

ファイル **ACLs** には **ACE** (アクセス制御エントリ) が含まれており、異なるユーザーに対してより **詳細な権限** を割り当てることができます。

**ディレクトリ** に次の権限を付与することが可能です： `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`。\
ファイルには： `read`, `write`, `append`, `execute`。

ファイルに ACLs が含まれている場合、権限をリスト表示すると **"+" が表示されます**：
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
ファイルの**ACLを読む**には、次のコマンドを使用します:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
すべてのACLを持つ**ファイルを見つける**には（これは非常に遅いです）：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 拡張属性

拡張属性には名前と任意の値があり、`ls -@`を使用して表示し、`xattr`コマンドを使用して操作できます。一般的な拡張属性には以下があります：

- `com.apple.resourceFork`: リソースフォークの互換性。`filename/..namedfork/rsrc`としても表示されます
- `com.apple.quarantine`: MacOS: Gatekeeperの隔離メカニズム (III/6)
- `metadata:*`: MacOS: `_backup_excludeItem`や`kMD*`などのさまざまなメタデータ
- `com.apple.lastuseddate` (#PS): 最後のファイル使用日
- `com.apple.FinderInfo`: MacOS: Finder情報（例：カラータグ）
- `com.apple.TextEncoding`: ASCIIテキストファイルのテキストエンコーディングを指定
- `com.apple.logd.metadata`: `/var/db/diagnostics`内のファイルでlogdによって使用される
- `com.apple.genstore.*`: 世代ストレージ（ファイルシステムのルートにある`/.DocumentRevisions-V100`）
- `com.apple.rootless`: MacOS: システム整合性保護によってファイルにラベル付けされる (III/10)
- `com.apple.uuidb.boot-uuid`: ユニークUUIDを持つブートエポックのlogdマーク
- `com.apple.decmpfs`: MacOS: 透過的ファイル圧縮 (II/7)
- `com.apple.cprotect`: \*OS: ファイルごとの暗号化データ (III/11)
- `com.apple.installd.*`: \*OS: installdによって使用されるメタデータ（例：`installType`、`uniqueInstallID`）

### リソースフォーク | macOS ADS

これは**MacOSにおける代替データストリーム**を取得する方法です。**file/..namedfork/rsrc**内の拡張属性**com.apple.ResourceFork**にコンテンツを保存することができます。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
この拡張属性を含むすべてのファイルは、次のコマンドで**見つけることができます**:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

拡張属性 `com.apple.decmpfs` は、ファイルが暗号化されて保存されていることを示します。`ls -l` は **サイズが0** であると報告し、圧縮データはこの属性内にあります。ファイルにアクセスされるたびに、メモリ内で復号化されます。

この属性は `ls -lO` で確認でき、圧縮されたファイルはフラグ `UF_COMPRESSED` でタグ付けされているため、圧縮されていることが示されます。圧縮ファイルが `chflags nocompressed </path/to/file>` で削除されると、システムはそのファイルが圧縮されていたことを認識せず、したがってデータを解凍してアクセスすることができません（実際には空であると考えます）。

ツール afscexpand を使用して、ファイルを強制的に解凍することができます。

## **ユニバーサルバイナリ &** Mach-oフォーマット

Mac OSのバイナリは通常、**ユニバーサルバイナリ**としてコンパイルされます。**ユニバーサルバイナリ**は、**同じファイル内で複数のアーキテクチャをサポートすることができます**。

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}

## macOSプロセスメモリ

## macOSメモリダンプ

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## リスクカテゴリファイル Mac OS

ディレクトリ `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` には、**異なるファイル拡張子に関連するリスクに関する情報が保存されています**。このディレクトリは、ファイルをさまざまなリスクレベルに分類し、Safariがこれらのファイルをダウンロード時にどのように扱うかに影響を与えます。カテゴリは次のとおりです：

- **LSRiskCategorySafe**: このカテゴリのファイルは **完全に安全** と見なされます。Safariはこれらのファイルをダウンロード後に自動的に開きます。
- **LSRiskCategoryNeutral**: これらのファイルには警告がなく、Safariによって **自動的に開かれません**。
- **LSRiskCategoryUnsafeExecutable**: このカテゴリのファイルは **警告を引き起こします**。これは、そのファイルがアプリケーションであることを示すセキュリティ対策です。
- **LSRiskCategoryMayContainUnsafeExecutable**: このカテゴリは、実行可能ファイルを含む可能性のあるアーカイブなどのファイルに適用されます。Safariは、すべての内容が安全または中立であることを確認できない限り、**警告を引き起こします**。

## ログファイル

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: ダウンロードされたファイルに関する情報を含み、どこからダウンロードされたかのURLが含まれています。
- **`/var/log/system.log`**: OSXシステムのメインログ。com.apple.syslogd.plistはsysloggingの実行を担当しています（`launchctl list`で "com.apple.syslogd" を探すことで無効になっているか確認できます）。
- **`/private/var/log/asl/*.asl`**: これらはAppleシステムログで、興味深い情報が含まれている可能性があります。
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder"を通じて最近アクセスされたファイルとアプリケーションを保存します。
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: システム起動時に起動するアイテムを保存します。
- **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtilityアプリのログファイル（ドライブに関する情報、USBを含む）。
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: ワイヤレスアクセスポイントに関するデータ。
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: 無効化されたデーモンのリスト。

{{#include ../../../banners/hacktricks-training.md}}
