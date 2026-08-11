# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

ユーザーごとの notification database は `%LOCALAPPDATA%\Microsoft\Windows\Notifications`（例: `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`）にあります。初期の Windows 10 リリースでは `appdb.dat` が使用され、Anniversary Update (1607) では `wpndatabase.db` が導入されました。SQLite database には notification payload と時刻関連のフィールドを含む `Notification` table がありますが、保持期間と利用可能なデータはリリースや cleanup policy によって異なります。<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline は activity-history feature で、supported applications、documents、その他のユーザー activity の records を含むことがあります。対象範囲は application と Windows version に依存します。<sup>[[4]](#references)</sup>

database は `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` にあります。SQLite で開くか、[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) で parse できます。出力は [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) で確認できます。<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

local trust boundary の外部から download された files には、zone information を記録し、URL などの origin metadata を含むことがある **`Zone.Identifier` alternate data stream** が存在する場合があります。その存在と fields は producer と system policy によって異なります。<sup>[[6]](#references)</sup>

## **File Backups**

### Recycle Bin

Vista 以降では、**Recycle Bin** は drive の root にある **`$Recycle.bin`** folder（例: `C:\$Recycle.bin`）にあります。\
この folder で file を delete すると、2 つの特定の files が作成されます。

- `$I{id}`: file information（deletion time と original path を含む）
- `$R{id}`: file の content

![File Backups - Recycle Bin: $R{id}: file の content](<../../../images/image (1029).png>)

これらの files があれば、[**Rifiuti2**](https://github.com/abelcheung/rifiuti2) を使用して original path と deletion time を extract できます（target Windows release に適した version を使用してください）。<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) は、ファイルが使用中であってもボリュームの特定時点のシャドウコピーを作成できます。シャドウコピーは forensic image の代替にはなりません。<sup>[[8]](#references)</sup>

コピーのメタデータは通常、ボリュームルートにある `\System Volume Information` に関連付けられており、識別子はシステムによって異なります。

![Recycle Bin - Volume Shadow Copies: これらのバックアップは通常、ファイルシステムのルートにある System Volume Information に保存され、名前は以下に示す UID で構成されます...](<../../../images/image (94).png>)

適切な forensic mounter で image を mount した後、[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) を使用して、利用可能な VSS snapshot を列挙し、そこからファイルを参照またはコピーできます。<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: ArsenalImageMounter で forensic image を mount すると、ShadowCopyView を使用して shadow copy を調査し、ファイルを抽出することもできます...](<../../../images/image (576).png>)

VSS registry writer の設定には `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` が含まれており、バックアップから除外するファイルとキーを指定できます。<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: registry エントリ HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore には、バックアップ対象外にするファイルとキーが含まれています](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` キーにも VSS service の設定が含まれています。<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover の場所は、Office application、version、設定によって異なります。Word については、Microsoft が `%APPDATA%\Microsoft\Word` を default location として文書化しています。アクティブな path は application の設定で確認してください。<sup>[[12]](#references)</sup>

## Shell Items

shell item は、別のファイルへのアクセス方法に関する情報を含む item です。

### Recent Documents (LNK)

Windows は、ユーザーが item を開いたり、その他の方法でアクセスしたりすると、通常、recent item の shortcut を作成します。

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

folder にアクセスすると、その folder および関連する親 folder の link も作成される場合があります。

これらの link file には、target type、target MAC times、volume information、target path が含まれることがあります。この metadata は削除された target の特定に役立つ場合がありますが、この artifact だけでは、特定のユーザーが target を開いたことの証明にはなりません。<sup>[[13]](#references)[[14]](#references)</sup>

LNK 自体の filesystem timestamps と、埋め込まれた target timestamps は別のものです。形式上、target timestamps は link file の timestamps とは別に保存されるため、裏付けとなる artifact がない状態で、link の作成を最初の使用、link の変更を最後の使用として解釈しないでください。<sup>[[13]](#references)[[14]](#references)</sup>

既存の [**LinkParser**](http://4discovery.com/our-tools/) link は historical option として残されていますが、review 時点では documentation を利用できませんでした。documentation が整備された command-line parser には、[**LECmd**](https://github.com/EricZimmerman/LECmd) を使用してください。<sup>[[15]](#references)</sup>

これらの tools では、通常、次の 2 組の timestamps が表示されます。

- **Target timestamps:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Link-file timestamps:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

最初の組は target を指し、2 番目の組は LNK file 自体を指します。両方を parser の documentation および filesystem context と併せて解釈してください。<sup>[[14]](#references)[[15]](#references)</sup>

Windows CLI tool の [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) を実行しても、同じ情報を取得できます。<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
この場合、情報は CSV ファイル内に保存されます。

### Jumplists

Jump Lists は、アプリケーションごとの最近使用した項目またはタスク固有の項目のリストで、自動またはカスタムのものがあります。<sup>[[13]](#references)</sup>

Automatic Jump Lists は `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` に保存され、`{id}.automaticDestinations-ms` のような名前が使用されます。この ID はアプリケーションを識別します。

Custom Jump Lists は `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` に保存されます。どのタスクまたは項目のエントリを作成するかは、アプリケーションによって制御されます。

ファイルシステムの作成時刻と変更時刻は Jump List ファイル自体を示すものであり、一覧に含まれるすべての対象への最初と最後のアクセスを自動的に示すものではありません。解析したエントリをファイルのタイムスタンプやその他の artifact と関連付けてください。<sup>[[13]](#references)</sup>

Jump Lists は [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) を使用して調査できます。<sup>[[5]](#references)</sup>

![最近使用したドキュメント（LNK）- Jumplists: JumplistExplorer を使用して jumplists を調査できます](<../../../images/image (168).png>)

(_JumplistExplorer が提供するタイムスタンプは jumplist ファイル自体に関連するものであることに注意してください_)

### Shellbags

[**shellbags について学ぶには、このリンクを参照してください。**](interesting-windows-registry-keys.md#shellbags)

## Windows USB の使用

リムーバブルメディアからファイルにアクセスした際に作成される artifact によって、USB の使用を裏付けられる場合があります。これには次のものが含まれます。

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com) などのツールは、これらの artifact を USB デバイスの記録と関連付けます。ただし、artifact の可用性は Windows のバージョンとアプリケーションによって異なります。<sup>[[18]](#references)</sup>

Windows XP および Windows 7 の MTP ワークフローについて記録されたテストでは、一部の LNK が元のパスではなく `WPDNSE` フォルダーを指していました。<sup>[[16]](#references)</sup>

![Shellbags - Windows USB の使用: 一部の LNK ファイルは元のパスではなく WPDNSE フォルダーを指していることに注意してください](<../../../images/image (218).png>)

この調査では、`%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` 配下にコピーが確認されました。テストでは一時的な内容は再起動後に残らず、GUID は shellbag データと関連付けることができました。これは普遍的な規則ではなく、OS、デバイス、アプリケーションに依存する動作として扱ってください。<sup>[[16]](#references)</sup>

### Registry Information

[このページを確認して](interesting-windows-registry-keys.md#usb-information)、USB 接続デバイスに関する興味深い情報を含むレジストリキーを確認してください。

### setupapi

Vista 以降では、デバイスのインストール活動を確認するために `C:\Windows\inf\setupapi.dev.log` を調査します。セクションヘッダーには `Section start` のタイムスタンプが含まれます。これはセットアップ処理を記録したものであり、正確な物理的挿入時刻として扱うのではなく、他の接続証拠と関連付ける必要があります。<sup>[[17]](#references)</sup>

![Registry Information - setupapi: USB 接続が行われた時刻を取得するには C: Windows inf setupapi.dev.log ファイルを確認してください（Section start を検索）](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) を使用すると、イメージに接続された USB デバイスに関する情報を取得できます。<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective を使用すると、イメージに接続された USB デバイスに関する情報を取得できます](<../../../images/image (452).png>)

### Plug and Play Cleanup

`Plug and Play Cleanup` という名前のスケジュールされたタスクは、古いドライバーバージョンを削除します。Adam Harrison が記録した Windows 10 のタスク定義では、30 日間非アクティブなドライバーも対象としているため、リムーバブルデバイスのドライバーに関する証拠が削除される可能性があります。この動作を一般化する前に、ローカルのタスク定義と Windows build を確認してください。<sup>[[1]](#references)</sup>

タスクは次のパスにあります: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

![Windows Plug and Play Cleanup スケジュールタスクの XML 定義](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**タスクの主なコンポーネントと設定:**

- **pnpclean.dll**: 実際の cleanup 処理を担当する DLL です。
- **UseUnifiedSchedulingEngine**: `TRUE` に設定され、汎用タスクスケジューリングエンジンが使用されることを示します。
- **MaintenanceSettings**:
- **Period ('P1M')**: 通常の Automatic maintenance 中に、Task Scheduler が cleanup タスクを毎月開始するよう指示します。
- **Deadline ('P2M')**: タスクが 2 か月連続で失敗した場合、緊急の Automatic maintenance 中にタスクを実行するよう Task Scheduler に指示します。

この設定により、定期的な maintenance と、連続して失敗した場合の再試行がスケジュールされます。正確な XML と動作はバージョンに依存します。<sup>[[1]](#references)</sup>

**詳細については、こちらを確認してください:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)。<sup>[[1]](#references)</sup>

## メール

メールには、**メールのヘッダーと本文という 2 つの興味深い部分**があります。**ヘッダー**には次のような情報があります。

- メールを**送信した人物**（メールアドレス、IP、メールを転送したメールサーバー）
- メールが**送信された時刻**

また、`References` ヘッダーと `In-Reply-To` ヘッダーには、返信を会話に関連付けるために使用されるメッセージ ID が含まれる場合があります。<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - メール: メールが送信された時刻](<../../../images/image (593).png>)

### Windows Mail App

このアプリケーションは、`\Users\<username>\AppData\Local\Comms\Unistore\data\3\` などのパスにある補助的なテキストファイルまたは HTML ファイルにメールの内容を保存します。正確な番号付きフォルダーとファイルの構成は artifact によって異なる場合があります。<sup>[[75]](#references)</sup>

メールの**メタデータ**と**連絡先**は、**ESE database** である `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` 内にあります。<sup>[[75]](#references)</sup>

`store.vol` は Extensible Storage Engine（ESE）形式を使用します。コピーを作成して作業し、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) などの ESE parser を使用してください。ツールが `.edb` 拡張子を要求する場合は、コピーだけを rename し、`Message` table を前提にする前に table schema を確認してください。<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Outlook MAPI properties を調査する際の canonical properties には、次のものがあります。

- `PidTagClientSubmitTime`: client が message を submit した UTC 時刻。
- `PidTagConversationIndex`: conversation thread 内における message の相対位置。
- `PidTagEntryId`: message object の identifier。
- `PidTagMessageFlags`: submitted、read、unread、attachments の有無などの status flags。
- `PidTagLastVerbExecuted`: open、reply、forward など、message に対して最後に記録された operation。<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook data-file の場所は、バージョンと account type によって異なります。Microsoft は PST/OST file の一般的な場所として次を記載しています。

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` によって、Outlook profile と関連する data-file configuration を特定できる場合があります。

PST files には、messages、contacts、calendar data、その他の Outlook items が含まれる場合があります。[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) を使用してコピーを調査できます。<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Kernel PST Viewer ツールを使用して PST file を開くことができます](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** は Exchange または Microsoft 365 accounts の local cache です。Cached Exchange Mode は POP または IMAP accounts には適用されません。offline period は設定可能で、デフォルトでは 12 か月であることが多く、PST/OST size limits も別途設定可能です。OST file を表示するには、[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) を使用できます。<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Retrieving Attachments

失われた attachments は、次の場所から復元できる場合があります。

- legacy Outlook/IE configurations の場合: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- newer Outlook/IE11 configurations の場合: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`。<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** は profile data を `%APPDATA%\Thunderbird\Profiles` 配下に保存します。mail folders では通常、account-specific な `Mail` または `ImapMail` directories 配下に、拡張子のない mbox files が使用されます。<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: thumbnail previews は通常、フォルダーごとの `thumbs.db` files に保存されていました。
- **Network folders**: 関連する thumbnail behavior が有効な場合、UNC folder に対して `thumbs.db` file が作成されることがあります。すべての Windows version または policy がこれを作成すると仮定しないでください。
- **Windows Vista and newer**: system thumbnail cache は `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` 配下に集約され、**thumbcache_xxx.db** などの files が使用されます。[**Thumbsviewer**](https://thumbsviewer.github.io) は legacy `Thumbs.db` を parse でき、[**ThumbCache Viewer**](https://thumbcacheviewer.github.io) は modern thumbnail-cache databases を parse できます。<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

system と user の configuration data を保存する Windows Registry は、次の場所にある hive files に格納されています。

- `%WINDIR%\System32\Config`: 各種 `HKEY_LOCAL_MACHINE` subkeys の基盤となる machine hives。
- `%USERPROFILE%\NTUSER.DAT`: user の `HKEY_CURRENT_USER` hive。
- 一部の古い Windows installations には `%WINDIR%\System32\Config\RegBack\` 内にも copies があります。Windows 10 version 1803 以降では、periodic backup が有効になっていない限り、この directory は自動的に populate されません。<sup>[[34]](#references)[[35]](#references)</sup>
- per-user shell および class-registration data も、modern Windows では通常 `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` に保存されます。<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

registry hives の分析にはいくつかの tools が役立ちます。出力を信頼する前に、各 tool がサポートする hive formats と version を確認してください。

- **Registry Editor**: Windows にインストールされています。現在の session の Windows registry を GUI で移動するための tool です。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): registry file を load し、GUI で移動できます。また、興味深い情報を含む keys を強調表示する Bookmarks も備えています。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): これも、load した registry 内を GUI で移動でき、load した registry 内の興味深い情報を強調表示する plugins を備えています。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): load した registry hive から情報を抽出できる、別の GUI application です。<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recovering Deleted Element

削除された hive cells は、その領域が再利用されるまで残る場合があります。ただし、復元は hive の状態と parser に依存します。復元された deleted keys は、確実な records ではなく、validation が必要な evidence として扱ってください。

### Last Write Time

Registry keys には last-write timestamp が付与されます。Windows は key またはその value entries のいずれかに対してこの timestamp を公開するため、value が独立した modification timestamp を持つとは限りません。<sup>[[69]](#references)</sup>

### SAM

**SAM** hive には、local user と group account の data が含まれます。これには、system の boot-key material によって保護された password hashes も含まれます。<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users` では、account identifiers と、一部の logon および policy fields を取得できます。offline hash extraction には、関連する boot-key material を復元するために `SYSTEM` hive も必要です。<sup>[[38]](#references)[[39]](#references)</sup>

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[一般的な Windows processes に関する既存の post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) は追加の参考資料として残されています。process behavior に関する主張は、現在の Windows documentation と local evidence を用いて裏付けてください。<sup>[[2]](#references)</sup>

### Windows Recent APPs

これを公開している Windows 10 versions では、`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` に、last-used time や launch count などの fields を持つ per-application subkeys が含まれます。この artifact は後の releases で削除されているため、対象 build を確認してください。<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Background Activity Moderator を公開している systems では、`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` または新しい `...\bam\State\UserSettings\{SID}` path を調査します。values は user SID をキーとしており、tracked executable paths と FILETIME-like execution data を含む場合があります。この artifact は version-dependent であり、他の evidence と照合する必要があります。<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch は resources と launch metadata を cache し、programs をより高速に起動できるようにします。

Prefetch files は `C:\Windows\Prefetch` に `.pf` files として保存されます。format、retention、file-count limits は Windows version によって異なります。Microsoft は Windows 8 以降について、最後の 8 回分の execution times と最大 1024 files の retention を記載しているため、古い固定上限の説明を一般化しないでください。<sup>[[13]](#references)</sup>

filename には通常 `{program_name}-{hash}.pf` が使用されます。この hash は path や arguments などの execution context から導出されます。Windows 10 以降では file が圧縮される場合があります。存在は execution evidence として有用ですが、それだけで user による execution の証明にはならないため、他の artifacts と照合する必要があります。<sup>[[13]](#references)</sup>

これらの files は [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) を使用して調査できます。この tool は、directory parsing、CSV/HTML output、該当する Windows 10 Prefetch files の decompression support を記載しています。<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** は、過去の使用パターンを利用して読み込みを改善することで Prefetch を補完します。これらを生成するシステムでは、データベースファイルは通常 `C:\Windows\Prefetch\Ag*.db` にあります。形式と存在はバージョンによって異なります。<sup>[[41]](#references)</sup>

これらのデータベースには、アプリケーション名、使用回数、アクセスされたファイルまたはボリューム、パス、時間範囲が含まれる場合がありますが、正確な実行ログとして扱うべきではありません。<sup>[[41]](#references)</sup>

既存の [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) リンクは、利用可能なパーサー候補として残されています。使用前に、現在のツールのドキュメントで利用可能性とサポートされる出力を確認してください。

### SRUM

**System Resource Usage Monitor** (SRUM) は、アプリケーションおよびユーザーによるリソース使用状況を記録します。これは Windows 8 で導入され、ESE データベース `C:\Windows\System32\sru\SRUDB.dat` にデータを保存します。<sup>[[13]](#references)</sup>

次の情報が得られます。

- AppID と Path
- レコードに関連付けられた User/SID
- 送信バイト数
- 受信バイト数
- ネットワークインターフェース
- 接続時間
- プロセス実行時間

収集間隔と保持期間は実装に依存します。すべてのレコードが正確な 60 分間の実行間隔を表すと想定しないでください。<sup>[[13]](#references)</sup>

[**srum_dump**](https://github.com/MarkBaggett/srum-dump) を使用してデータを抽出および確認できます。オプションについては、現在のツールバージョンのドキュメントに従ってください。<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache** は **ShimCache** とも呼ばれ、Windows のアプリケーション互換性インフラストラクチャの一部であり、互換性判断のためにファイルメタデータを記録します。ハイブのパス、レコード形式、保持容量、フィールドは Windows のリリースによって異なります。最新の Windows では、ShimCache だけでユーザーがファイルを実行したことを証明することはできません。関連する `SYSTEM` ハイブを [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) で解析し、その出力を実行アーティファクトと照合してください。<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): 保存された情報を解析するには、AppCompatCacheParser tool の使用が推奨されます](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** ファイルは、Windows が確認したアプリケーションとファイルを一覧化するレジストリハイブです。通常は `C:\Windows\AppCompat\Programs\Amcache.hve` にあります。

関連付けられたファイルエントリおよび関連付けられていないファイルエントリ、パス、SHA1 値が含まれる場合がありますが、その存在はインベントリの証拠であり、プロセスが実行されたことを単独で証明するものではありません。<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve** を抽出して分析するには、[**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool を使用します。このコマンドはハイブを解析し、CSV 出力を書き込みます。<sup>[[44]](#references)</sup>

例:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
生成された CSV ファイルの中では、`Amcache_Unassociated file entries` が、認識されたプログラムに関連付けられていないファイルを調査する際に役立つ場合があります。<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7 システムでは、`C:\Windows\AppCompat\Programs\RecentFileCache.bcf` に、最近観測されたバイナリに関する情報が含まれている場合があります。利用可能性と意味はバージョンによって異なります。

[**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) を使用してファイルを解析できます。<sup>[[45]](#references)</sup>

### Scheduled tasks

Scheduled task の証拠は、最新のタスクでは `C:\Windows\System32\Tasks` に、legacy task では `.job` ファイルを含む `C:\Windows\Tasks` に存在する場合があります。OS に適したタスク定義形式を調査してください。<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Service Control Manager のデータベースは `SYSTEM\CurrentControlSet\Services` にあります（offline の SYSTEM hive では、対応する control-set key を調査します）。ここには、実行可能ファイルのパスや start type など、service と driver の設定が含まれています。<sup>[[72]](#references)</sup>

### **Windows Store**

インストールされた Windows Store application は、`\ProgramData\Microsoft\Windows\AppRepository\` の下に登録されている場合があり、データベース **`StateRepository-Machine.srd`** などが含まれます。schema と path は Windows の release によって異なります。<sup>[[71]](#references)</sup>

データベースには、application identifier、package number、display name が含まれている場合があります。identifier の欠落だけでは application が uninstall された証拠にはなりません。package と registry の状態で裏付けを取ってください。

Package registration は、`HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` の下にも存在する場合があります。Microsoft は、削除された provisioned app 用に version-specific な `Deprovisioned` subkey を文書化しています。すべての build に `Deleted` subkey が存在すると想定しないでください。<sup>[[70]](#references)</sup>

## Windows Events

provider によっては、Windows event に次の情報が含まれる場合があります。

- 発生した事象
- event schema と host の時刻コンテキストに基づいて解釈する必要がある `TimeCreated` timestamp
- 関係した users
- 関係した hosts（hostname、IP）
- access された assets（files、folders、printers、services）。<sup>[[49]](#references)</sup>

Windows Vista より前では、event log は通常 `C:\Windows\System32\config` の下にある legacy binary format を使用していました。Vista 以降では Windows Event Log format が使用され、通常は `C:\Windows\System32\winevt\Logs` の下に保存されます。`.evtx` ファイルには、XML として render された event data が含まれます。<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry は、**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** の下に channel configuration を保存しています。これには、設定された file path と retention settings が含まれます。<sup>[[47]](#references)</sup>

Windows Event Viewer（**`eventvwr.msc`**）または [**Event Log Explorer**](https://eventlogxp.com)、[**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) などの tool で表示できます。<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Vista 以降では、Security channel は通常 `C:\Windows\System32\winevt\Logs\Security.evtx` に保存されます。最大サイズと retention policy は設定可能です。circular logging が有効な場合、ファイルが上限に達すると古い record が上書きされる可能性があります。関連する auditing が有効な場合、この channel には authentication、logoff、privilege、audit-policy、object-access event を記録できます。<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: account logon が成功した。<sup>[[50]](#references)</sup>
- **Event ID 4625**: account logon に失敗した。<sup>[[51]](#references)</sup>
- **Event ID 4634**: logon session が終了した。<sup>[[52]](#references)</sup>
- **Event ID 4647**: user が logoff を開始した。<sup>[[53]](#references)</sup>
- **Event ID 4672**: 新しい logon に special privilege が割り当てられた。これは system account や administrator account で一般的に発生するため、これだけで malicious activity の証拠にはなりません。<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: interactive な local logon。
- **Network (3)**: shared resource への access。
- **Batch (4)**: batch-process logon。
- **Service (5)**: service logon。
- **Unlock (7)**: workstation の unlock。
- **NetworkCleartext (8)**: authentication package に cleartext で credential を提供する network logon。
- **NewCredentials (9)**: outbound connection 用に提供された alternate credential を使用する logon。
- **RemoteInteractive (10)**: Remote Desktop または Terminal Services の logon。
- **CachedInteractive (11)**: cached domain credential を使用する interactive logon。
- **CachedRemoteInteractive (12)**: cached remote-interactive logon。
- **CachedUnlock (13)**: cached credential を使用する unlock。<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: その user は存在しない。
- **0xC000006A**: user name は正しいが password が間違っている。
- **0xC0000234**: account が lockout されている。
- **0xC0000072**: account が disabled になっている。
- **0xC000006F**: 許可された時間外の logon。
- **0xC0000070**: workstation restriction 違反。
- **0xC0000193**: account の有効期限が切れている。
- **0xC0000071**: password の有効期限が切れている。
- **0xC0000133**: client と server の時刻差が大きすぎる。
- **0xC0000224**: account の password を変更する必要がある。
- **0xC0000225**: `STATUS_NOT_FOUND`。この code だけでは system bug や attack を特定できない。
- **0xC000015B**: 要求された logon type が account に許可されていない。<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: system time が変更された。多くの event は通常の time-service correction を反映するため、tampering と判断する前に actor と time source を相関させてください。<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: Event 12 は OS start、13 は OS shutdown、1074 は planned shutdown または restart、6008 は unexpected shutdown、6009 は boot 時の Windows version を記録します。Event 6005 と 6006 は、それぞれ Event Log service の start と stop を示します。これらだけでは OS の startup と shutdown の証拠にはなりません。<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 は Security audit log が clear されたことを記録します。この event だけから intent を推測するのではなく、actor と周辺の event を調査してください。<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: first-use または installation activity の確立に役立つ `UserPnp` device-installation event。
- **10000 / 10100**: device activity に伴って発生する可能性がある `DriverFrameworks-UserMode` event。
- **Event ID 112**: insertion に関連する timestamp を提供できる `DeviceSetupManager/Admin` activity。
- provider、channel、event の意味は Windows version によって異なります。意味を割り当てる前に provider name と event payload を調査してください。<sup>[[59]](#references)</sup>

logon type と、それに関連する credential material の実例については、[Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) を参照してください。<sup>[[60]](#references)</sup>

event の詳細には、logon type、status、substatus、source address、process field などが含まれ、Event ID 4625 の context を提供します。status code や repeated failure pattern は調査の手がかりであり、結論ではありません。<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

event log は一般に circular であるため、logger によって上書きされた record は復元できない場合があります。live system を操作する前に forensic image または working copy を保存してください。**Bulk_extractor** などの validated parser または carver は、tool version が対象の `.evtx` data をサポートしていることを確認してから使用し、event の復元だけを目的として稼働中の system の電源を抜かないでください。<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

実用的な event-ID reference については、既存の [Red Team Recipe](https://redteamrecipe.com/event-codes/) link を参照し、その examples を上記の provider documentation と照合してください。

#### Brute Force Attacks

繰り返される Event ID 4625 の failure を、その後の 4624 success、logon type、status、source、account context と相関させてください。この sequence は調査の indicator であり、attack の証拠ではありません。<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 は system-time change を記録するため、timeline analysis を複雑にする可能性があります。time-service および host evidence と比較してください。<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event ID は provider-specific です。`UserPnp` 20001/20003、`DriverFrameworks-UserMode` 10000/10100、`DeviceSetupManager/Admin` 112 を SetupAPI および registry artifact と相関させてください。<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

OS start、shutdown、restart、unexpected-power context には 12/13/1074/6008/6009 を使用します。6005/6006 は Event Log service の start/stop を示します。<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 は Security audit log が clear されたことを記録するため、responsible account と process と相関させる必要があります。<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play の cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - 一般的な Windows process の調査](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 notifications の digital forensic view](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman の forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier と Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS における registry の backup と restore operation](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [backup と restore 用の registry key](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover location における Word の performance issue](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: data exfiltration artifact の特定](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entry](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID と Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook data file の検索と transfer](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Mode の有効化](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [一部の item だけが synchronized される](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlook data file の size limit の設定](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Thunderbird が user data を保存する場所](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account setting と mbox directory](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry は RegBack に backup されない](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [registry の remote edit](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Passwords technical overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [system event log を使用した unexpected reboot の troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [process 中の shutdown の troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [USB Storage Device Forensics for Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook Desktop で Quick Print が PDF attachment を印刷しなくなる](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [update 中に removed app が戻らないようにする](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK と Registry Viewer の test result](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Installed Services の database](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Task Scheduler Service Is Not Available error により Scheduled Tasks が失敗する](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mail database の navigating](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
