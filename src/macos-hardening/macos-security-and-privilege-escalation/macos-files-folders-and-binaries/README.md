# macOS のファイル、フォルダー、バイナリ、メモリ

{{#include ../../../banners/hacktricks-training.md}}

## ファイル階層の構成

Apple は macOS のファイルシステムを、システム、ローカル、ネットワーク、ユーザーの各ドメインからなる階層として説明しています。正確な内容は OS のリリースによって異なり、システムの場所は保護または合成されるものが増えています。 <sup>[[1]](#references)</sup>

- **/Applications**: インストール済みのアプリはここに配置されます。すべてのユーザーがアクセスできます。
- **/bin**: コマンドラインバイナリ
- **/cores**: 存在する場合、コアダンプの保存に使用されます。
- **/dev**: すべてがファイルとして扱われるため、ハードウェアデバイスがここに保存されている場合があります。
- **/etc**: 設定ファイル
- **/Library**: 環境設定、キャッシュ、ログに関連する多くのサブディレクトリやファイルがあります。Library フォルダーはルートと各ユーザーのディレクトリに存在します。
- **/private**: 詳細は公開されていませんが、前述したフォルダーの多くは `private` ディレクトリへのシンボリックリンクです。
- **/sbin**: 重要なシステムバイナリ（管理関連）
- **/System**: macOS に必要なファイル。このツリーには主に Apple が提供するコンポーネントが含まれます。
- **/tmp**: 一時ファイル（`/private/tmp` へのシンボリックリンク）。従来のインストール環境では、古い一時ファイルは定期的に削除され、3 日ごとと説明されることもありましたが、現在の削除タイミングはシステムやポリシーによって異なります。ここにデータが保持されることを前提にしないでください。
- **/Users**: ユーザーのホームディレクトリ
- **/usr**: 設定とシステムバイナリ
- **/var**: ログファイル
- **/Volumes**: マウントされたボリュームがここに表示されます。
- **/.vol**: `stat a.txt` を実行すると、`16777223 7545753 -rw-r--r-- 1 username wheel ...` のような結果が得られます。最初の数字はファイルが存在するボリュームの ID、2 番目の数字は inode 番号です。この情報を使って `cat /.vol/16777223/7545753` を実行すると、`/.vol/` 経由でファイルの内容にアクセスできます。

### Applications フォルダー

- **システムアプリケーション**は `/System/Applications` にあります。
- **インストール済み**アプリケーションは通常、`/Applications` または `~/Applications` にインストールされます。
- **アプリケーションデータ**は、root として実行されるアプリケーションの場合は `/Library/Application Support`、ユーザーとして実行されるアプリケーションの場合は `~/Library/Application Support` にあります。
- root として実行する**必要がある**サードパーティ製アプリケーションの**デーモン**は、通常 `/Library/PrivilegedHelperTools/` にあります。
- **Sandbox 化された**アプリは `~/Library/Containers` フォルダーに割り当てられます。各アプリには、アプリケーションの bundle ID（`com.apple.Safari`）に基づく名前のフォルダーがあります。
- **カーネル**は `/System/Library/Kernels/kernel` にあります。
- **Apple のカーネル拡張**は `/System/Library/Extensions` にあります。
- **サードパーティ製カーネル拡張**は `/Library/Extensions` に保存されます。

### 機密情報を含むファイル

macOS は、認証情報を含む機密情報を複数の場所に保存します。


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 脆弱な pkg インストーラー


{{#ref}}
macos-installers-abuse.md
{{#endref}}

この階層で見える書き込み可能な Data ボリュームと封印された System ボリュームの違いについては、[macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md) を参照してください。

## OS X 固有の拡張子

- **`.dmg`**: Apple Disk Image ファイル。インストーラーでよく使われます。
- **`.kext`**: 特定の構造に従う必要があり、OS X 版のドライバーです（bundle です）。
- **`.plist`**: property list は、構造化情報を XML またはバイナリ形式で保存します。
  - XML 形式またはバイナリ形式があります。バイナリ形式は以下の方法で読み取れます。
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: 標準的な macOS ディレクトリ構造に従うアプリケーション bundle です。
- **`.dylib`**: Dynamic library（Windows の DLL ファイルに相当）
- **`.pkg`**: 最新のフラット形式のインストーラーパッケージは XAR アーカイブですが、`.pkg` はインストーラー形式であり、XAR と同義ではありません。古い bundle 形式のインストーラーパッケージはディレクトリです。パッケージの構造と調査については [macOS installers](macos-installers-abuse.md) を参照してください。 <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: 各ディレクトリにあるファイルで、そのディレクトリの属性やカスタマイズ情報を保存します。
- **`.Spotlight-V100`**: このフォルダーは、システム上の各ボリュームのルートディレクトリに表示されます。
- **`.metadata_never_index`**: このファイルがボリュームのルートにある場合、Spotlight はそのボリュームをインデックス化しません。
- **`.noindex`**: この拡張子の付いたファイルやフォルダーは Spotlight によってインデックス化されません。
- **`.sdef`**: AppleScript がアプリケーションとどのようにやり取りできるかを記述するスクリプティング定義ファイルです。

### macOS Bundles

bundle は、標準化された階層を持つディレクトリで、Finder はそれを単一のオブジェクトとして表示できます。アプリケーション bundle には `.app` 拡張子が使われます。 <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS と iOS では、よく使われるシステムライブラリやフレームワークが **dyld shared cache** に事前リンクされ、アプリケーションの起動パフォーマンスが向上します。論理的には 1 つのキャッシュとして扱われますが、現在のリリースでは実際には 1 つのファイルではなく、メインキャッシュと複数のサブキャッシュファイルとして保存される場合があります。形式と場所は実装の詳細であり、OS リリースによって変わります。 <sup>[[3]](#references)</sup>

macOS では `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` にあります。古いバージョンでは **`/System/Library/dyld/`** に **shared cache** がある場合があります。\
iOS では **`/System/Library/Caches/com.apple.dyld/`** にあります。

dyld shared cache と同様に、カーネルとカーネル拡張もカーネルキャッシュにコンパイルされ、起動時に読み込まれます。

古いリリースでは [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) で抽出できました。このビルドは現在のキャッシュ形式に対応していない場合があります。別の選択肢として [**dyldextractor**](https://github.com/arandomdev/dyldextractor) があります。

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> `dyld_shared_cache_util` ツールが動作しない場合でも、**shared dyld binary を Hopper に渡せば**、Hopper がすべてのライブラリを識別し、調査したいものを**選択**できる点に注意してください。

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

dylib はハードコードされたアドレスで事前にリンクされているため、一部の extractor は動作しません。その結果、未知のアドレスにジャンプすることがあります。

> [!TIP]
> Xcode の emulator を使えば、macOS 上で他の \*OS デバイスの Shared Library Cache をダウンロードすることもできます。次の場所にダウンロードされます: `ls $HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`。例:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### SLCのマッピング

**`dyld`** は、SLC がマッピング済みかどうかを確認するために syscall **`shared_region_check_np`**（アドレスを返します）を使用し、SLC をマッピングするために **`shared_region_map_and_slide_np`** を使用します。

初回使用時に SLC が slide されても、すべての**プロセス**が**同じコピー**を使用するため、攻撃者がシステム上でプロセスを実行できる場合、ASLR の保護は**なくなります**。これは実際に過去に悪用され、その後 shared region pager によって修正されました。

Branch pools は小さな Mach-O dylib で、image mappings の間に小さな領域を作り、関数の interpose を不可能にします。

### Shared-cache環境の制限

`DYLD_SHARED_CACHE_DIR` は cache directory を指定し、`DYLD_SHARED_REGION` は shared-region mode を選択します。以前の `DYLD_DHARED_REGION` という表記は無効であり、`avoid` は `DYLD_SHARED_CACHE_DIR` の値ではありません。現在の dyld は、custom shared cache を使用する AMFI 権限がある場合に限り `private` mode を許可します。そのため、環境変数を設定しただけでは、プロセスが置き換えられた cache を読み込めるとは限りません。 <sup>[[10]](#references)</sup>

## 特殊なファイル権限

### フォルダーの権限

ディレクトリでは、**read** によってエントリの一覧表示が可能になり、**write** によってエントリの作成または削除が可能になり、**execute** によってそのディレクトリを通過できます。そのため、ファイルを読み取れるユーザーでも、親ディレクトリを通過できなければ、そのファイルにパスでアクセスすることはできません。 <sup>[[4]](#references)</sup>

### フラグ修飾子

ファイルには、動作を変更するフラグを設定できます。`ls -lO /path/directory` でディレクトリ内のフラグを確認します。

- **`uchg`**: **uchange** フラグとして知られ、ファイルの変更や削除を**すべて禁止**します。設定するには、`chflags uchg file.txt` を実行します。
  - ファイルの所有者または root は、`chflags nouchg file.txt` でこの**ユーザー**フラグを解除できます。したがって、どちらに対する保護にもなりません。別個の**システム**不変フラグ（`schg`）を設定できるのは root に限られます。 <sup>[[11]](#references)</sup>
- **`restricted`**: このフラグを設定すると、ファイルは**SIP によって保護**されます（ファイルにこのフラグを追加することはできません）。
- **`Sticky bit`**: sticky bit が設定されたディレクトリでは、ファイルの所有者、ディレクトリの所有者、または root だけがエントリの名前変更や削除を行えます。ユーザーが他のユーザーのファイルを削除したり移動したりできないよう、通常は `/tmp` で有効になっています。

すべてのフラグは `sys/stat.h` にあります（`mdfind stat.h | grep stat.h` で検索できます）。

- `UF_SETTABLE` 0x0000ffff: 所有者が変更可能なフラグのマスク。
- `UF_NODUMP` 0x00000001: ファイルを dump しない。
- `UF_IMMUTABLE` 0x00000002: ファイルを変更できない。
- `UF_APPEND` 0x00000004: ファイルへの書き込みは追記のみ可能。
- `UF_OPAQUE` 0x00000008: union に関してディレクトリを opaque にする。
- `UF_COMPRESSED` 0x00000020: ファイルが圧縮されている（一部の file system）。
- `UF_TRACKED` 0x00000040: このフラグが設定されたファイルの削除や名前変更について通知しない。
- `UF_DATAVAULT` 0x00000080: 読み取りと書き込みに entitlement が必要。
- `UF_HIDDEN` 0x00008000: GUI でこの項目を表示しないようにするヒント。
- `SF_SUPPORTED` 0x009f0000: superuser がサポートするフラグのマスク。
- `SF_SETTABLE` 0x3fff0000: superuser が変更可能なフラグのマスク。
- `SF_SYNTHETIC` 0xc0000000: システムの読み取り専用 synthetic flags のマスク。
- `SF_ARCHIVED` 0x00010000: ファイルがアーカイブされている。
- `SF_IMMUTABLE` 0x00020000: ファイルを変更できない。
- `SF_APPEND` 0x00040000: ファイルへの書き込みは追記のみ可能。
- `SF_RESTRICTED` 0x00080000: 書き込みに entitlement が必要。
- `SF_NOUNLINK` 0x00100000: 項目を削除、名前変更、またはマウントできない。
- `SF_FIRMLINK` 0x00800000: ファイルが firmlink である。
- `SF_DATALESS` 0x40000000: ファイルが dataless object である。

### **ファイル ACL**

ファイルの **ACL** には **ACE**（Access Control Entries）が含まれ、異なるユーザーに対してより**細かな権限**を割り当てられます。

**ディレクトリ**には、`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child` の権限を付与できます。\
**ファイル**には、`read`、`write`、`append`、`execute` を付与できます。

ファイルに ACL が含まれている場合、権限を一覧表示すると、次のように **「+」が表示されます**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

ファイルの**ACLを読み取る**には、次を使います:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

次のコマンドで**ACLを持つすべてのファイル**を見つけられます（非常に時間がかかります）：

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### 拡張属性

拡張属性は、ファイルの通常の属性とは別に保存される、名前付きのメタデータ値です。`ls -l@` で一覧表示し、`xattr` で確認または変更できます。 <sup>[[5]](#references)</sup> よく使われる拡張属性には、次のものがあります。

- `com.apple.resourceFork`: リソースフォーク互換性。`filename/..namedfork/rsrc` からも確認できます
- `com.apple.quarantine`: macOS Gatekeeper の隔離メタデータ
- `metadata:*`: `_backup_excludeItem` や `kMD*` などの macOS メタデータ
- `com.apple.lastuseddate` (#PS): ファイルの最終使用日時
- `com.apple.FinderInfo`: カラータグなどの macOS Finder 情報
- `com.apple.TextEncoding`: ASCII テキストファイルのテキストエンコーディングを指定
- `com.apple.logd.metadata`: `/var/db/diagnostics` 内のファイルで logd が使用
- `com.apple.genstore.*`: 世代ストレージ（ファイルシステムのルートにある `/.DocumentRevisions-V100`）
- `com.apple.rootless`: System Integrity Protection に関連付けられた macOS メタデータ
- `com.apple.uuidb.boot-uuid`: 一意の UUID を使った、起動エポックを示す logd のマーク
- `com.apple.decmpfs`: macOS の透過的なファイル圧縮メタデータ
- `com.apple.cprotect`: \*OS: ファイルごとの暗号化データ（III/11）
- `com.apple.installd.*`: \*OS: `installType` や `uniqueInstallID` など、installd が使用するメタデータ

### リソースフォーク | macOS ADS

リソースフォークは、macOS で代替データストリームを提供します。コンテンツは `com.apple.ResourceFork` 拡張属性に保存でき、`file/..namedfork/rsrc` を通じてアクセスできます。

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

次の方法で、この拡張属性を含むすべてのファイルを**検索できます**：

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

拡張属性 `com.apple.decmpfs` は透過圧縮のメタデータを格納するものであり、暗号化を示すものではありません。圧縮形式によっては、圧縮データは属性またはリソースフォークに格納され、読み取り時に透過的に展開されます。

`UF_COMPRESSED` フラグは `ls -lO` で `compressed` と表示されます。このフラグを手動でクリアしないでください。圧縮表現がシステムによって誤って解釈されるおそれがあります。

このフラグをクリアするコマンドは、フォレンジック調査で役立つためここに示します。ただし、圧縮ファイルに対して実行すると、メタデータが修復されるまでファイルが空に見えたり、アクセスできなくなったりすることがあります。

```bash
chflags nocompressed /path/to/file
```

組み込みの`/usr/bin/afscexpand`ユーティリティは、透過圧縮されたファイルを強制的に展開できます。別のサードパーティ製ユーティリティ`afsctool`でも、Apple filesystem compressionを調査または解凍できますが、組み込みコマンドと混同しないでください。 <sup>[[8]](#references)</sup>


### 興味深い設定場所 (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | システムデーモン / framework のオプションまたは実験的な動作を制御する、Appleのfeature-flag plistファイルを格納 | 攻撃者がSIPを回避するか権限を取得できる場合、これらを改ざんして隠れたコードパスを有効にしたり、保護機能を無効にしたりできる |
| `/System/Library/CoreServices/systemVersion.plist` | アプリ / installer が動作制御に使用するmacOSバージョンのメタデータ (ProductVersion、BuildVersion) を保持 | 改変すると、アプリやinstallerに未サポートのOSバージョンを受け入れさせたり、機能をロック解除させたりできる |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | アプリケーション / システム全体の環境設定 | 書き込み可能な場合、攻撃者は設定を注入してアプリの動作を誘導したり、保護機能を無効にしたり、設定ミスを引き起こしたりできる |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | バックグラウンドデーモンおよびagentのplist定義 | 権限が許せば、悪意のあるplistの挿入や改変によって永続化や権限昇格が可能 |
| `/etc/hosts` | システムのDNS resolverが使用するホスト名 ↔ IPアドレスの対応 | ドメイン名のリダイレクト、通信の傍受、ローカル制御下でのサービスのなりすまし |
| `/etc/sudoers` | `sudo`でコマンドを実行できるユーザーと、その条件を定義 | sudoersファイルが改ざんされると、攻撃者のアカウントにroot権限や不適切な権限が付与される可能性がある |
| `/private/var/db/dslocal/nodes/Default/users/` | ローカルユーザーアカウントの定義plist | 改ざんにより、ユーザーアカウント、パスワードハッシュ、ユーザーメタデータの作成や変更が可能 |
| `/System/Library/Extensions/` / `/Library/Extensions/` | kernel extension / driver | kextのインストールや改変によってkernelレベルの制御を得られる可能性がある。SIP / 署名ポリシーによる強い保護がある |
| `/private/var/db/SystemPolicyConfiguration/` | システムポリシーの適用設定 (Gatekeeper、notarizationなど) を格納 | これらを改ざんすると、ポリシーチェックや信頼ルールを回避できる可能性がある |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaryおよび設定ファイル | 設定ミスにより、SSHセキュリティの低下、不正アクセス、安全でないアルゴリズムの使用につながる |
| `/System/Library/Sandbox/Profiles` | プロセスの操作を制限するシステムsandbox profile (SBPL) | profileの置き換えや変更によって、sandbox escapeの経路が生まれたり、隔離が弱まったりする |

> **注**: これらの場所の多くはSIPで保護されたディレクトリ (例: `/System`) にあり、SIPが無効化または回避されない限り、書き込みから保護されています。  


## Universal BinariesとMach-O Format

Mach-OはmacOSのネイティブな実行ファイル形式です。universal binary (fat binaryとも呼ばれる) は、複数のアーキテクチャ固有のMach-O sliceを1つのファイルにまとめます。専用ページでは、両方の形式について説明しています:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOSのメモリダンプ

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## ファイルのリスクとハンドラーのメタデータ

LaunchServices、file quarantine、Gatekeeperは連携して、macOSがダウンロードしたファイルをどのように処理するか、また拡張子やURL schemeに対してどのアプリケーションを選択するかに影響します。これらのデータベースや内部リソースファイルはリリースによって変わるため、privateなCoreTypesのパスを安定したポリシーインターフェースとして扱わず、専用ページを参照してください:

従来のCoreTypesリスクメタデータが`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`にあるリリースでは、よく見られるカテゴリは次のとおりです:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: 該当するアプリケーションポリシーの下で、自動的に開くのに十分安全と見なされるコンテンツ。
- **`LSRiskCategoryNeutral`**: 通常は警告を引き起こさず、自動的にも開かれないコンテンツ。
- **`LSRiskCategoryUnsafeExecutable`**: ユーザーにアプリケーションの警告を表示すべき実行可能コンテンツ。
- **`LSRiskCategoryMayContainUnsafeExecutable`**: 実行可能コンテンツを含む可能性があり、さらに調査が必要なアーカイブなどのコンテナ。

これらは実装の詳細であり、安定した公開ポリシーAPIではありません。検証対象のmacOSバージョンで、実際のメタデータとSafari / Gatekeeperの動作を確認してください。

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## ログファイル

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: ダウンロードしたファイルに関する情報 (ダウンロード元のURLなど) が含まれます。
- **Unified log**: 現行のmacOSバージョンでは、`log show`および`log stream`を使ってシステムイベントやアプリケーションイベントを検索できます。 <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** および **`/private/var/log/asl/*.asl`**: 古いシステムでは現在も関連する場合がある、従来のログ関連ファイルです。これらのリリースでは、`/System/Library/LaunchDaemons/com.apple.syslogd.plist`が`syslogd`を設定します。サービスがロードされているか確認するには、`launchctl list | grep com.apple.syslogd`が役立ちます。
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder"で最近アクセスしたファイルやアプリケーションを保存します。
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: login itemsに関連する従来の環境設定パスです。現行のmacOSバージョンでは、追加の仕組みが使われています。
- **`$HOME/Library/Logs/DiskUtility.log`**: ドライブ (USBデバイスを含む) の情報が含まれる場合がある、従来のDisk Utilityログです。
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: wireless access pointに関するデータです。
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: 従来のlaunchd overrideデータです。



## References

- [1] [Apple - File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle Programming Guide](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld shared cache overview](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - File System Programming Guide: macOS File System Security](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS manual page](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS manual page](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS manual page](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums - Unpacking Apple Archives](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Shell Script Security: special file permission flags](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Code Signing Tasks: installer packages](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
