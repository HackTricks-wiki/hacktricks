# macOS のファイル、フォルダー、バイナリ、メモリ

{{#include ../../../banners/hacktricks-training.md}}

## ファイル階層のレイアウト

Apple は macOS のファイルシステムを、system、local、network、user の各ドメインから成る階層として文書化しています。正確な内容は OS のリリースによって異なり、システムの場所はますます保護または合成されるようになっています。 <sup>[[1]](#references)</sup>

- **/Applications**: インストールされたアプリはここに配置されます。すべてのユーザーがアクセスできます。
- **/bin**: コマンドラインバイナリ
- **/cores**: 存在する場合、core dump の保存に使用されます。
- **/dev**: すべてがファイルとして扱われるため、ハードウェアデバイスがここに保存されていることがあります。
- **/etc**: 設定ファイル
- **/Library**: 環境設定、キャッシュ、ログに関連する多数のサブディレクトリとファイルがあります。Library フォルダーはルートディレクトリと各ユーザーのディレクトリに存在します。
- **/private**: 文書化されていませんが、前述したフォルダーの多くは private ディレクトリへの symbolic link です。
- **/sbin**: 重要なシステムバイナリ（管理関連）
- **/System**: macOS に必要なファイル。主に Apple が提供するコンポーネントが含まれています。
- **/tmp**: 一時ファイル（`/private/tmp` への symbolic link）。以前のインストールでは、古い一時ファイルを定期的に削除するのが一般的で、3日間と説明されることもありましたが、現在の削除タイミングはシステムとポリシーによって異なります。データがここに保持されることを前提にしないでください。
- **/Users**: ユーザーのホームディレクトリ
- **/usr**: 設定およびシステムバイナリ
- **/var**: ログファイル
- **/Volumes**: マウントされたボリュームがここに表示されます。
- **/.vol**: `stat a.txt` を実行すると、`16777223 7545753 -rw-r--r-- 1 username wheel ...` のような結果が得られます。最初の数字はファイルが存在するボリュームの ID 番号で、2番目の数字は inode 番号です。次のようにその情報を使って `/.vol/` 経由でこのファイルの内容にアクセスできます: `cat /.vol/16777223/7545753`

### Applications フォルダー

- **System applications** は `/System/Applications` にあります。
- **Installed** applications は通常、`/Applications` または `~/Applications` にインストールされます。
- **Application data** は、root として実行されるアプリケーションの場合は `/Library/Application Support` に、ユーザーとして実行されるアプリケーションの場合は `~/Library/Application Support` にあります。
- **root として実行する必要がある**サードパーティ製アプリケーションの **daemons** は、通常 `/Library/PrivilegedHelperTools/` にあります。
- **Sandboxed** apps は `~/Library/Containers` フォルダーにマッピングされます。各 app には、アプリケーションの bundle ID（`com.apple.Safari`）に従って名前が付けられたフォルダーがあります。
- **kernel** は `/System/Library/Kernels/kernel` にあります。
- **Apple's kernel extensions** は `/System/Library/Extensions` にあります。
- **Third-party kernel extensions** は `/Library/Extensions` に保存されます。

### 機密情報を含むファイル

macOS は credentials を含む機密情報を、複数の場所に保存します。


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
- **`.plist`**: property list は、XML または binary 形式で構造化された情報を保存します。
- XML または binary 形式にできます。binary 形式のものは次のコマンドで読み取れます。
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: 標準的な macOS ディレクトリ構造に従う application bundle です。
- **`.dylib`**: Dynamic libraries（Windows の DLL ファイルに相当）
- **`.pkg`**: xar（eXtensible Archive format）と同じものです。installer command を使用して、これらのファイルの内容をインストールできます。
- **`.DS_Store`**: 各ディレクトリに存在するファイルで、ディレクトリの属性とカスタマイズを保存します。
- **`.Spotlight-V100`**: システム上のすべてのボリュームのルートディレクトリにこのフォルダーが表示されます。
- **`.metadata_never_index`**: このファイルがボリュームのルートにある場合、Spotlight はそのボリュームを index しません。
- **`.noindex`**: この拡張子を持つファイルとフォルダーは Spotlight によって index されません。
- **`.sdef`**: AppleScript がアプリケーションとどのように対話できるかを記述する scripting definition file です。

### macOS Bundles

bundle は標準化された階層を持つディレクトリであり、Finder はそれを単一のオブジェクトとして表示できます。application bundle には `.app` 拡張子が使用されます。 <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

macOS と iOS では、一般的に使用されるシステムライブラリと framework が **dyld shared cache** に prelink され、アプリケーションの startup performance が向上します。論理的には1つの cache として扱われますが、現在のリリースでは、文字どおり1つのファイルではなく、main cache と複数の subcache files として保存される場合があります。その形式と場所は実装の詳細であり、OS のリリースごとに変更されます。 <sup>[[3]](#references)</sup>

macOS では `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` にあります。古いバージョンでは、**shared cache** が **`/System/Library/dyld/`** にある場合があります。\
iOS では **`/System/Library/Caches/com.apple.dyld/`** にあります。

dyld shared cache と同様に、kernel と kernel extensions も kernel cache に compile され、boot 時に load されます。

以前のリリースでは [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) で extract できました。この build は現在の cache 形式をサポートしていない可能性があります。別の選択肢として [**dyldextractor**](https://github.com/arandomdev/dyldextractor) があります。
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> `dyld_shared_cache_util` tool が動作しない場合でも、**shared dyld binary を Hopper に渡す**ことができます。Hopper はすべてのライブラリを識別し、調査したいものを**選択できる**ようにします。

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

dylib はハードコードされたアドレスで prelinked されているため、一部の extractor は動作しません。そのため、unknown addresses へジャンプする可能性があります。

> [!TIP]
> Xcode の emulator を使用すれば、macos で他の \*OS devices の Shared Library Cache を download することもできます。これらは次の場所に download されます: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`、例:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** は syscall **`shared_region_check_np`** を使用して、SLC が mapped されているかどうかを確認します（この syscall は address を返します）。また、**`shared_region_map_and_slide_np`** を使用して SLC を map します。

SLC は最初の使用時に slide されますが、すべての **processes** は**同じ copy**を使用する点に注意してください。これにより、attacker が system 上で processes を実行できた場合、**ASLR** protection が**排除されました**。これは実際に過去に exploit され、shared region pager によって修正されました。

Branch pools は小さな Mach-O dylibs であり、image mappings の間に小さな spaces を作成することで、functions の interpose を不可能にします。

### Override SLCs

次の env variables を使用します:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> これにより、新しい shared library cache を load できます
- **`DYLD_SHARED_CACHE_DIR=avoid`** を設定し、libraries を shared cache への symlinks で real ones に手動で replace します（事前に extract する必要があります）

## Special File Permissions

### Folder permissions

directory では、**read** により entries の listing、**write** により entries の creation または removal、**execute** により traversal が許可されます。したがって、file を read できても parent directory を traverse できない user は、その file に path で access できません。 <sup>[[4]](#references)</sup>

### Flag modifiers

Files には、その behavior を変更する flags を付けることができます。directory 内の flags は `ls -lO /path/directory` で inspect します。

- **`uchg`**: **uchange** flag として知られ、**file** を変更または delete する**あらゆる action を prevent**します。設定するには `chflags uchg file.txt` を実行します
- root user は**flag を remove**して file を modify できます
- **`restricted`**: この flag により file は **SIP によって protected** されます（この flag を file に add することはできません）。
- **`Sticky bit`**: sticky bit が set された directory では、file owner、directory owner、または root だけが entry を rename または delete できます。これは通常 `/tmp` で enabled され、users が他の users の files を delete または move するのを防ぎます。

すべての flags は `sys/stat.h` file にあります（`mdfind stat.h | grep stat.h` で find できます）。その一覧は次のとおりです:

- `UF_SETTABLE` 0x0000ffff: owner が変更可能な flags の mask。
- `UF_NODUMP` 0x00000001: file を dump しない。
- `UF_IMMUTABLE` 0x00000002: file を変更できない。
- `UF_APPEND` 0x00000004: file への writes は append のみ可能。
- `UF_OPAQUE` 0x00000008: directory は union に関して opaque。
- `UF_COMPRESSED` 0x00000020: file は compressed（some file-systems）。
- `UF_TRACKED` 0x00000040: この flag が set された files では deletes/renames の notifications がない。
- `UF_DATAVAULT` 0x00000080: read と write に entitlement が必要。
- `UF_HIDDEN` 0x00008000: この item を GUI に表示しないための hint。
- `SF_SUPPORTED` 0x009f0000: superuser が supported する flags の mask。
- `SF_SETTABLE` 0x3fff0000: superuser が変更可能な flags の mask。
- `SF_SYNTHETIC` 0xc0000000: system の read-only synthetic flags の mask。
- `SF_ARCHIVED` 0x00010000: file は archived。
- `SF_IMMUTABLE` 0x00020000: file を変更できない。
- `SF_APPEND` 0x00040000: file への writes は append のみ可能。
- `SF_RESTRICTED` 0x00080000: writing に entitlement が必要。
- `SF_NOUNLINK` 0x00100000: item を remove、rename、または mount できない。
- `SF_FIRMLINK` 0x00800000: file は firmlink。
- `SF_DATALESS` 0x40000000: file は dataless object。

### **File ACLs**

File **ACLs** には **ACE**（Access Control Entries）が含まれており、異なる users に対してより**granular な permissions**を割り当てることができます。

**directory** には次の permissions を grant できます: `list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
**file** には: `read`、`write`、`append`、`execute`。

file に ACLs が含まれている場合、**permissions を listing すると `+` が表示されます。次のようになります**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
ファイルの ACL は次のコマンドで **読み取れます**:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
以下のコマンドで、**ACL が設定されたすべてのファイル**を確認できます（非常に遅いです）：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes は、ファイルの通常の属性とは別に保存される名前付きメタデータ値です。`ls -l@` で一覧表示し、`xattr` で確認または変更できます。 <sup>[[5]](#references)</sup> 一般的な extended attributes には次のものがあります。

- `com.apple.resourceFork`: Resource fork との互換性。`filename/..namedfork/rsrc` としても確認できます
- `com.apple.quarantine`: macOS Gatekeeper の quarantine メタデータ
- `metadata:*`: `_backup_excludeItem` や `kMD*` などの macOS メタデータ
- `com.apple.lastuseddate` (#PS): ファイルの最終使用日時
- `com.apple.FinderInfo`: color tags などの macOS Finder 情報
- `com.apple.TextEncoding`: ASCII text files のテキストエンコーディングを指定
- `com.apple.logd.metadata`: `/var/db/diagnostics` 内のファイルで logd によって使用されます
- `com.apple.genstore.*`: Generational storage（ファイルシステムのルートにある `/.DocumentRevisions-V100`）
- `com.apple.rootless`: System Integrity Protection に関連付けられた macOS メタデータ
- `com.apple.uuidb.boot-uuid`: 一意の UUID による boot epoch の logd markings
- `com.apple.decmpfs`: macOS の透過的なファイル圧縮メタデータ
- `com.apple.cprotect`: \*OS: ファイルごとの暗号化データ（III/11）
- `com.apple.installd.*`: \*OS: `installType` や `uniqueInstallID` など、installd によって使用されるメタデータ

### Resource Forks | macOS ADS

Resource forks は macOS 上で alternate data stream を提供します。コンテンツは `com.apple.ResourceFork` extended attribute に保存でき、`file/..namedfork/rsrc` を通じてアクセスできます。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
**この拡張属性を含むすべてのファイルは、次の方法で検索できます**：
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

拡張属性 `com.apple.decmpfs` には透過的な圧縮のメタデータが保存されます。これは暗号化を示すものではありません。圧縮形式によっては、圧縮データが属性内または resource fork に保存され、読み取り時に透過的に展開されます。

`UF_COMPRESSED` フラグは、`ls -lO` では `compressed` として表示されます。これを手動でクリアしないでください。クリアすると、システムが圧縮表現を誤って解釈する可能性があります。

このフラグをクリアするコマンドをここに示すのは、forensic review で役立つためです。ただし、圧縮ファイルに対して実行すると、メタデータが修復されるまで、そのファイルが空またはアクセス不能に見える可能性があります。
```bash
chflags nocompressed /path/to/file
```
組み込みの `/usr/bin/afscexpand` utility は、透過的に圧縮されたファイルの展開を強制できます。別の third-party `afsctool` utility でも Apple filesystem compression の検査や解凍ができますが、組み込み command と混同しないでください。 <sup>[[8]](#references)</sup>


### 興味深い configuration locations (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | system daemons / frameworks におけるオプションまたは experimental な挙動を制御する、Apple の feature-flag plist files を格納 | attacker が SIP を bypass するか privilege を取得できる場合、これらを tampering することで hidden code paths を有効化したり safeguards を無効化したりできる |
| `/System/Library/CoreServices/systemVersion.plist` | apps / installers が挙動を制限するために使用する macOS version metadata (ProductVersion、BuildVersion) を保持 | Modification により、apps や installers に unsupported OS versions を受け入れさせたり、features を unlock させたりできる |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Application / system-wide preferences | writable な場合、attackers は settings を inject して app behavior を誘導し、protections を disable にしたり misconfiguration を引き起こしたりできる |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | background daemons と agents の plist definitions | Malicious plist の insertion または manipulation（permissions が許可する場合）により persistence や privilege escalations が可能になる |
| `/etc/hosts` | system DNS resolver が使用する Hostname ↔ IP mappings | domain names の redirect、traffic の interception、local control 下での services の spoofing |
| `/etc/sudoers` | `sudo` を使用して commands を実行できる者と、その条件を定義 | corrupted sudoers file により、attacker accounts に root または不適切な privileges を付与できる |
| `/private/var/db/dslocal/nodes/Default/users/` | Local user account definition plists | Tampering により、user accounts、password hashes、user metadata の creation または modification が可能になる |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | kexts の installing または modifying により kernel-level control につながる可能性がある。SIP / signature policies により厳重に保護されている |
| `/private/var/db/SystemPolicyConfiguration/` | system policy enforcement（例: Gatekeeper、notarization）の configuration を格納 | これらの tampering により、policy checks や trust rules の circumvention が可能になる場合がある |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | SSH helper binaries と config files | Misconfiguration により、weak SSH security、unauthorized access、または insecure algorithms が生じる |
| `/System/Library/Sandbox/Profiles` | process actions の制限に使用される system sandbox profiles (SBPL) | profiles の replacing または altering により、sandbox escape vectors が開かれたり containment が弱体化したりする可能性がある |

> **Note**: これらの paths の多くは SIP-protected directories（例: `/System`）にあり、SIP が disabled または bypassed でない限り writes から保護されています。


## Universal Binaries And Mach-O Format

Mach-O は macOS の native executable format です。universal、または fat、binary は、複数の architecture-specific Mach-O slices を1つの file にラップします。専用ページでは両方の formats を説明しています。

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File Risk And Handler Metadata

LaunchServices、file quarantine、Gatekeeper は、それぞれ downloaded files を macOS がどのように扱い、extensions や URL schemes に対して applications をどのように選択するかに影響します。これらの databases と internal resource files は releases ごとに変化するため、private CoreTypes path を stable policy interface とみなすのではなく、専用ページを使用してください。

legacy CoreTypes risk metadata が `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` の下に公開されている releases では、一般的に見られる categories は次のとおりです:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: 該当する application policy の下で automatic opening に十分安全とみなされる content。
- **`LSRiskCategoryNeutral`**: 通常は warning を trigger せず、automatically opened されない content。
- **`LSRiskCategoryUnsafeExecutable`**: user に application warning を表示すべき executable content。
- **`LSRiskCategoryMayContainUnsafeExecutable`**: executable content を含む可能性があり、さらなる inspection が必要な archives などの containers。

これらは implementation details であり、stable public policy API ではありません。test 対象の macOS version における実際の metadata と Safari/Gatekeeper behavior を確認してください。

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: downloaded files に関する情報（download 元の URL など）を含む。
- **Unified log**: current macOS versions では、`log show` と `log stream` を使用して system および application events を query する。 <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** および **`/private/var/log/asl/*.asl`**: older systems では依然として relevant な可能性がある legacy logging artifacts。これらの releases では、`/System/Library/LaunchDaemons/com.apple.syslogd.plist` が `syslogd` を configure します。`launchctl list | grep com.apple.syslogd` は service が loaded かどうかの判断に役立ちます。
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: "Finder" を通じて最近 access された files と applications を格納。
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: login items に関連する legacy preference path。modern macOS versions では additional mechanisms が使用されます。
- **`$HOME/Library/Logs/DiskUtility.log`**: drives（USB devices を含む）に関する情報を含む可能性がある legacy Disk Utility log。
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: wireless access points に関する data。
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: legacy launchd override data。

## References

- [1] [Apple - File System Programming Guide](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Bundle Programming Guide](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - dyld shared cache overview](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - File System Programming Guide: macOS File System Security](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - macOS manual page](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - macOS manual page](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - macOS manual page](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
