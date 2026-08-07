# macOS のファイル、フォルダ、バイナリ、メモリ

{{#include ../../../banners/hacktricks-training.md}}

## ファイル階層のレイアウト

- **/Applications**: インストールされたアプリはここに配置されます。すべてのユーザーがアクセスできます。
- **/bin**: コマンドラインバイナリ
- **/cores**: 存在する場合、core dump の保存に使用されます。
- **/dev**: すべてがファイルとして扱われるため、ハードウェアデバイスがここに保存されていることがあります。
- **/etc**: 設定ファイル
- **/Library**: 環境設定、キャッシュ、ログに関連する多数のサブディレクトリとファイルがあります。Library フォルダはルートと各ユーザーのディレクトリに存在します。
- **/private**: 文書化されていませんが、前述したフォルダの多くは private ディレクトリへの symbolic link です。
- **/sbin**: 重要なシステムバイナリ（管理関連）
- **/System**: OS X の実行に必要なファイル。ここには主に Apple 固有のファイルがあり、third-party のファイルはほとんどありません。
- **/tmp**: ファイルは3日後に削除されます（`/private/tmp` への soft link です）。
- **/Users**: ユーザーのホームディレクトリ
- **/usr**: 設定およびシステムバイナリ
- **/var**: ログファイル
- **/Volumes**: マウントされたドライブがここに表示されます。
- **/.vol**: `stat a.txt` を実行すると、`16777223 7545753 -rw-r--r-- 1 username wheel ...` のような結果が得られます。最初の数字はファイルが存在する volume の ID 番号で、2番目の数字は inode 番号です。`cat /.vol/16777223/7545753` を実行すると、`/.vol/` とそれらの情報を使ってこのファイルの内容にアクセスできます。

### Applications フォルダ

- **System applications** は `/System/Applications` にあります。
- **Installed** applications は通常、`/Applications` または `~/Applications` にインストールされます。
- **Application data** は、root として実行されるアプリケーションの場合は `/Library/Application Support`、ユーザーとして実行されるアプリケーションの場合は `~/Library/Application Support` にあります。
- **root として実行する必要がある** third-party applications の **daemons** は通常、`/Library/PrivilegedHelperTools/` にあります。
- **Sandboxed** apps は `~/Library/Containers` フォルダにマッピングされます。各 app には、application の bundle ID（`com.apple.Safari`）に従って名前が付けられたフォルダがあります。
- **kernel** は `/System/Library/Kernels/kernel` にあります。
- **Apple's kernel extensions** は `/System/Library/Extensions` にあります。
- **Third-party kernel extensions** は `/Library/Extensions` に保存されます。

### 機密情報を含むファイル

MacOS は、パスワードなどの情報を複数の場所に保存します。


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### 脆弱な pkg installers


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## OS X 固有の拡張子

- **`.dmg`**: Apple Disk Image ファイルで、installers によく使用されます。
- **`.kext`**: 特定の構造に従う必要があり、OS X 版の driver です（bundle です）。
- **`.plist`**: property list とも呼ばれ、XML または binary 形式で情報を保存します。
- XML または binary にできます。Binary のものは次のコマンドで読み取れます。
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: directory structure に従う Apple applications です（bundle です）。
- **`.dylib`**: Dynamic libraries（Windows の DLL files に相当）
- **`.pkg`**: xar（eXtensible Archive format）と同じです。installer command を使用して、これらのファイルの内容をインストールできます。
- **`.DS_Store`**: 各 directory に存在するファイルで、directory の属性とカスタマイズを保存します。
- **`.Spotlight-V100`**: この folder は、システム上のすべての volume の root directory に表示されます。
- **`.metadata_never_index`**: このファイルが volume の root にある場合、Spotlight はその volume を index しません。
- **`.noindex`**: この extension を持つ files と folders は Spotlight によって index されません。
- **`.sdef`**: bundle 内にあるファイルで、AppleScript から application と対話する方法を指定します。

### macOS Bundles

bundle は、**Finder で object のように見える** **directory** です（bundle の例として `*.app` files があります）。


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS（および iOS）では、frameworks や dylibs などのすべての system shared libraries が、**dyld shared cache** と呼ばれる **単一のファイルに結合**されています。これにより、code をより高速にロードできるため、パフォーマンスが向上しました。

macOS では `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` にあります。古いバージョンでは **`/System/Library/dyld/`** に **shared cache** がある場合があります。\
iOS では、`/System/Library/Caches/com.apple.dyld/` にあります。

dyld shared cache と同様に、kernel と kernel extensions も kernel cache にコンパイルされ、boot 時にロードされます。

単一ファイルの dylib shared cache から libraries を抽出するには、以前は binary [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) を使用できました。現在は動作しない可能性がありますが、[**dyldextractor**](https://github.com/arandomdev/dyldextractor) も使用できます。
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> `dyld_shared_cache_util` toolが動作しない場合でも、**shared dyld binaryをHopperに渡す**ことができます。Hopperはすべてのlibraryを識別し、調査したいものを**選択できる**ようにします。

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

一部のextractorは動作しません。これは、dylibがハードコードされたアドレスでprelinkされているため、未知のアドレスへjumpする可能性があるためです。

> [!TIP]
> Xcodeのemulatorを使用すれば、macos上で他の\*OSデバイスのShared Library Cacheをdownloadすることもできます。これらは次の場所にdownloadされます: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`、例:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### SLCのMapping

**`dyld`**はsyscall **`shared_region_check_np`**を使用してSLCがmappingされているか確認し（アドレスを返します）、**`shared_region_map_and_slide_np`**を使用してSLCをmappingします。

SLCは初回使用時にslideされますが、すべての**process**は**同じcopy**を使用するため、攻撃者がsystem上でprocessを実行できた場合、**ASLR**のprotectionは**排除される**ことに注意してください。これは過去に実際にexploitされ、shared region pagerによって修正されました。

Branch poolsは小さなMach-O dylibであり、image mappingの間に小さなspaceを作ることで、functionのinterposeを不可能にします。

### SLCのOverride

次のenv variableを使用します:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> 新しいshared library cacheをloadできるようになります
- **`DYLD_SHARED_CACHE_DIR=avoid`**およびlibraryをshared cacheへのsymlinkで手動replaceします。realなlibraryが必要です（extractする必要があります）

## Special File Permissions

### Folder permissions

**folder**では、**read**によって**list**が可能になり、**write**によってそのfolder上のfileを**delete**および**write**でき、**execute**によってdirectoryを**traverse**できます。したがって、例えばdirectory内の**fileに対するread permission**を持つuserでも、そのdirectoryに対する**execute**permissionを持って**いない**場合、そのfileを**readできません**。

### Flag modifiers

fileに設定できるflagには、fileの動作を変えるものがあります。directory内のfileの**flagは**`ls -lO /path/directory`で**確認できます**。

- **`uchg`**: **uchange** flagとして知られ、**file**を変更またはdeleteする**あらゆるactionを防止**します。設定するには: `chflags uchg file.txt`
- root userは**flagをremove**してfileを変更できます
- **`restricted`**: このflagによりfileは**SIPによってprotected**されます（このflagをfileに追加することはできません）。
- **`Sticky bit`**: sticky bitが設定されたdirectoryでは、**directoryのownerまたはrootのみが**fileを**renameまたはdelete**できます。通常、これは/tmp directoryに設定され、一般userが他のuserのfileをdeleteまたはmoveするのを防ぎます。

すべてのflagは`sys/stat.h` fileにあります（`mdfind stat.h | grep stat.h`で検索できます）。その内容は次のとおりです:

- `UF_SETTABLE` 0x0000ffff: ownerが変更可能なflagのmask。
- `UF_NODUMP` 0x00000001: fileをdumpしない。
- `UF_IMMUTABLE` 0x00000002: fileを変更できない。
- `UF_APPEND` 0x00000004: fileへのwriteはappendのみ可能。
- `UF_OPAQUE` 0x00000008: unionに関してdirectoryがopaque。
- `UF_COMPRESSED` 0x00000020: fileがcompressed（いくつかのfile-system）。
- `UF_TRACKED` 0x00000040: このflagが設定されたfileについて、delete/renameのnotificationを行わない。
- `UF_DATAVAULT` 0x00000080: readおよびwriteにEntitlementが必要。
- `UF_HIDDEN` 0x00008000: GUIにこのitemを表示しないようにするhint。
- `SF_SUPPORTED` 0x009f0000: superuserがsupportするflagのmask。
- `SF_SETTABLE` 0x3fff0000: superuserが変更可能なflagのmask。
- `SF_SYNTHETIC` 0xc0000000: system read-only synthetic flagのmask。
- `SF_ARCHIVED` 0x00010000: fileがarchived。
- `SF_IMMUTABLE` 0x00020000: fileを変更できない。
- `SF_APPEND` 0x00040000: fileへのwriteはappendのみ可能。
- `SF_RESTRICTED` 0x00080000: writeにEntitlementが必要。
- `SF_NOUNLINK` 0x00100000: itemをremove、rename、またはmountできない。
- `SF_FIRMLINK` 0x00800000: fileがfirmlink。
- `SF_DATALESS` 0x40000000: fileがdataless object。

### **File ACLs**

File **ACLs**には**ACE**（Access Control Entries）が含まれており、異なるuserに対してより**granularなpermission**を割り当てることができます。

**directory**には次のpermissionをgrantできます: `list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
また、**file**には: `read`、`write`、`append`、`execute`。

fileにACLsが含まれている場合、permissionをlistすると**「+」が表示されます**。例:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
次のコマンドで、ファイルの ACL を**読み取る**ことができます：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
**ACLを持つすべてのファイル**は、次のコマンドで見つけられます（非常に遅いです）。
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 拡張属性

拡張属性には名前と任意の値があり、`ls -@` を使用して確認し、`xattr` コマンドで操作できます。一般的な拡張属性には以下があります。

- `com.apple.resourceFork`: Resource fork の互換性。`filename/..namedfork/rsrc` としても確認できます
- `com.apple.quarantine`: macOS: Gatekeeper の quarantine メカニズム (III/6)
- `metadata:*`: macOS: `_backup_excludeItem` や `kMD*` などの各種メタデータ
- `com.apple.lastuseddate` (#PS): ファイルの最終使用日時
- `com.apple.FinderInfo`: macOS: Finder 情報（色 Tags など）
- `com.apple.TextEncoding`: ASCII テキストファイルのテキストエンコーディングを指定
- `com.apple.logd.metadata`: `/var/db/diagnostics` 内のファイルで logd によって使用される
- `com.apple.genstore.*`: Generational storage（ファイルシステムのルートにある `/.DocumentRevisions-V100`）
- `com.apple.rootless`: macOS: System Integrity Protection がファイルにラベルを付けるために使用 (III/10)
- `com.apple.uuidb.boot-uuid`: 一意の UUID を使用した boot epoch の logd マーキング
- `com.apple.decmpfs`: macOS: 透過的なファイル圧縮 (II/7)
- `com.apple.cprotect`: \*OS: ファイル単位の暗号化データ (III/11)
- `com.apple.installd.*`: \*OS: installd が使用するメタデータ（`installType`、`uniqueInstallID` など）

### Resource Forks | macOS ADS

これは **macOS** マシンで **Alternate Data Streams** を取得する方法です。ファイルを **file/..namedfork/rsrc** に保存することで、ファイル内の **com.apple.ResourceFork** という拡張属性にコンテンツを保存できます。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
次の方法で**この拡張属性を含むすべてのファイルを検索できます**：
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

拡張属性 `com.apple.decmpfs` は、ファイルが暗号化されて保存されていることを示します。`ls -l` では **サイズが 0** と報告され、圧縮データはこの属性内に格納されます。ファイルにアクセスされるたびに、メモリ内で復号されます。

この属性は `ls -lO` で確認でき、圧縮ファイルにはフラグ `UF_COMPRESSED` も付与されているため、compressed と表示されます。圧縮ファイルから `chflags nocompressed </path/to/file>` でこのフラグを削除すると、システムはファイルが圧縮されていたことを認識できなくなり、データを解凍してアクセスできなくなります（実際には空のファイルだと認識します）。

afscexpand ツールを使用すると、ファイルを強制的に解凍できます。


### 興味深い設定場所 (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | system daemons / frameworks におけるオプションまたは実験的な動作を制御する、Apple の feature-flag plist ファイルを格納 | 攻撃者が SIP を bypass するか privilege を取得できる場合、これらを改ざんすることで隠れた code path を有効化したり、保護機能を無効化したりできる |
| `/System/Library/CoreServices/systemVersion.plist` | アプリや installer が動作を制限する際に使用する macOS のバージョン metadata (ProductVersion、BuildVersion) を保持 | 改変により、アプリや installer に未サポートの OS version を受け入れさせたり、機能を unlock させたりできる |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | アプリケーション / system-wide の preferences | 書き込み可能な場合、攻撃者は設定を injection してアプリの動作を誘導したり、保護機能を無効化したり、設定ミスを引き起こしたりできる |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | background daemons および agents の plist 定義 | 権限が許せば、悪意のある plist の挿入または操作により persistence や privilege escalations が可能になる |
| `/etc/hosts` | system DNS resolver が使用する hostname ↔ IP の mapping | domain name の redirect、traffic の interception、ローカル管理下での service spoofing |
| `/etc/sudoers` | `sudo` を使用してコマンドを実行できるユーザーと、その条件を定義 | sudoers ファイルが破損すると、攻撃者の account に root または不適切な privilege を付与できる |
| `/private/var/db/dslocal/nodes/Default/users/` | ローカル user account の定義 plist | 改ざんにより、user account、password hash、user metadata の作成または変更が可能になる |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | kext の install または変更により kernel-level control につながる可能性がある。SIP / signature policies により厳重に保護されている |
| `/private/var/db/SystemPolicyConfiguration/` | system policy enforcement (Gatekeeper、notarization など) の設定を格納 | これらを改ざんすると、policy check や trust rule を circumvention できる可能性がある |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries および config files | 設定ミスにより、SSH security の低下、unauthorized access、または insecure algorithms の使用につながる |
| `/System/Library/Sandbox/Profiles` | process action の制限に使用される system sandbox profiles (SBPL) | profile の置換または変更により、sandbox escape vector を開いたり、containment を弱めたりできる |

> **Note**: これらの Path の多くは SIP-protected directories (例: `/System`) 配下にあり、SIP が無効化または bypass されない限り、書き込みから保護されています。


## **Universal binaries &** Mach-o Format

Mac OS の binaries は通常、**universal binaries** として compile されます。**universal binary** は、**同じ file 内で複数の architecture を support できます**。

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Mac OS の Risk Category Files

`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` directory には、**さまざまな file extension に関連する risk の情報が格納されています**。この directory は files を複数の risk level に分類し、download 時に Safari がこれらの files をどのように扱うかに影響します。categories は次のとおりです。

- **LSRiskCategorySafe**: この category の files は **完全に safe** と見なされます。Safari は download 後、これらの files を自動的に open します。
- **LSRiskCategoryNeutral**: これらの files には warning が表示されず、Safari によって **自動的に open されません**。
- **LSRiskCategoryUnsafeExecutable**: この category の files では、その file が application であることを示す **warning が表示されます**。これは user に alert を出す security measure です。
- **LSRiskCategoryMayContainUnsafeExecutable**: この category は、executable を含む可能性がある archive などの files 用です。Safari がすべての contents が safe または neutral であることを verify できない限り、**warning が表示されます**。

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: download された files に関する情報（download 元の URL など）が含まれます。
- **`/var/log/system.log`**: OSX systems の main log。com.apple.syslogd.plist が syslogging の実行を担当します。無効化されているかどうかは、`launchctl list` で "com.apple.syslogd" を検索して確認できます。
- **`/private/var/log/asl/*.asl`**: Apple System Logs で、興味深い情報が含まれている可能性があります。
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" を介して最近 access された files と applications を格納します。
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: system startup 時に launch する items を格納します。
- **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtility App の log file（USB を含む drives に関する情報）。
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: wireless access points に関する data。
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: deactivate された daemons の list。

{{#include ../../../banners/hacktricks-training.md}}
