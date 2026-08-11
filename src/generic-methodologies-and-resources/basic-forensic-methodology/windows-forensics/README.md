# Windowsアーティファクト

{{#include ../../../banners/hacktricks-training.md}}

## 一般的なWindowsアーティファクト

### Windows 10の通知

ユーザーごとの通知データベースは `%LOCALAPPDATA%\Microsoft\Windows\Notifications`（例: `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`）にあります。初期のWindows 10リリースでは `appdb.dat` が使用されていましたが、Anniversary Update（1607）では `wpndatabase.db` が導入されました。SQLiteデータベースには、通知のペイロードとタイミングフィールドを含む `Notification` テーブルがありますが、保持期間と利用可能なデータは、リリースおよびクリーンアップポリシーによって異なります。<sup>[[3]](#references)</sup>

### Timeline

Windows Timelineは、対応するアプリケーション、ドキュメント、その他のユーザーアクティビティの記録を含むことがあるアクティビティ履歴機能です。対象範囲は、アプリケーションとWindowsのバージョンによって異なります。<sup>[[4]](#references)</sup>

データベースは `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` にあります。SQLiteで開くことも、[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)で解析することもできます。出力は[**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md)で確認できます。<sup>[[4]](#references)[[5]](#references)</sup>

### ADS（Alternate Data Streams）

ローカルの信頼境界外からダウンロードされたファイルには、ゾーン情報を記録し、URLなどの発信元メタデータを含むことがある **`Zone.Identifier` alternate data stream** が存在する場合があります。その存在とフィールドは、生成元とシステムポリシーによって異なります。<sup>[[6]](#references)</sup>

## **ファイルバックアップ**

### ごみ箱

Vista以降では、**ごみ箱**はドライブのルートにある **`$Recycle.bin`** フォルダー（例: `C:\$Recycle.bin`）にあります。\
このフォルダー内のファイルが削除されると、2つの固有のファイルが作成されます。

- `$I{id}`: 削除時刻や元のパスなどのファイル情報
- `$R{id}`: ファイルの内容

![ファイルバックアップ - ごみ箱: $R{id}: ファイルの内容](<../../../images/image (1029).png>)

これらのファイルがあれば、[**Rifiuti2**](https://github.com/abelcheung/rifiuti2)を使用して元のパスと削除時刻を抽出できます（対象のWindowsリリースに適したバージョンを使用してください）。<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) は、ファイルが使用中であってもボリュームの特定時点の shadow copy を作成できます。ただし、shadow copy は forensic image の代替にはなりません。<sup>[[8]](#references)</sup>

コピーのメタデータは通常、ボリュームルートにある `\System Volume Information` に関連付けられており、識別子はシステムごとに異なります。

![Recycle Bin - Volume Shadow Copies: これらのバックアップは通常、ファイルシステムのルートにある System Volume Information に保存され、名前は以下に示す UID で構成されます](<../../../images/image (94).png>)

適切な forensic mounter で image を mount した後、[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) を使用すると、利用可能な VSS snapshot を列挙し、そこからファイルを閲覧またはコピーできます。<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: ArsenalImageMounter で forensic image を mount すると、ShadowCopyView を使用して shadow copy を調査し、ファイルを抽出することもできます](<../../../images/image (576).png>)

VSS registry writer の設定には `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` が含まれており、backup から除外するファイルや key を指定できます。<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore には、backup しないファイルと key が含まれています](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` key には、VSS service の設定も含まれています。<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover の場所は、Office application、version、設定によって異なります。Word については、Microsoft が `%APPDATA%\Microsoft\Word` を default location として記載しています。現在有効な path は application の設定で確認してください。<sup>[[12]](#references)</sup>

## Shell Items

shell item は、別の file へのアクセス方法に関する情報を含む item です。

### Recent Documents (LNK)

Windows は、user が item を開いたり、その他の方法で access したりすると、recent item の shortcut を作成することが一般的です。

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

folder に access すると、その folder および関連する parent folder の link も作成されることがあります。

これらの link file には、target type、target の MAC time、volume information、target path が含まれる場合があります。この metadata は削除された target の特定に役立つ可能性がありますが、この artifact だけでは、特定の user が target を開いた証拠にはなりません。<sup>[[13]](#references)[[14]](#references)</sup>

LNK 自体の filesystem timestamp と、埋め込まれた target timestamp は別のものです。format では target timestamp が link file 自体の timestamp とは別に保存されるため、裏付けとなる artifact なしに、link の作成を最初の使用、link の変更を最後の使用と解釈しないでください。<sup>[[13]](#references)[[14]](#references)</sup>

既存の [**LinkParser**](http://4discovery.com/our-tools/) link は historical option として保持されていますが、review 時点で documentation は利用できませんでした。documentation がある command-line parser を使用する場合は、[**LECmd**](https://github.com/EricZimmerman/LECmd) を使用してください。<sup>[[15]](#references)</sup>

これらの tool では、通常、次の 2 組の timestamp が表示されます。

- **Target timestamps:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Link-file timestamps:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

最初の組は target を指し、2 番目の組は LNK file 自体を指します。両方とも、parser の documentation と filesystem context に基づいて解釈してください。<sup>[[14]](#references)[[15]](#references)</sup>

Windows CLI tool である [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) を実行しても、同じ information を取得できます。<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
この場合、情報は CSV ファイル内に保存されます。

### Jumplists

Jump Lists は、アプリケーションごとの最近使用した項目またはタスク固有の項目のリストで、自動またはカスタムにできます。<sup>[[13]](#references)</sup>

Automatic Jump Lists は `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` に保存され、`{id}.automaticDestinations-ms` のような名前が使用されます。ID はアプリケーションを識別します。

Custom Jump Lists は `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` に保存されます。作成されるタスクまたは項目のエントリはアプリケーションによって制御されます。

ファイルシステムの作成日時と変更日時は Jump List ファイルについて記録されたものであり、リスト内のすべての対象に対する最初と最後のアクセスを自動的に示すものではありません。解析したエントリをファイルのタイムスタンプや他の artifact と相関させてください。<sup>[[13]](#references)</sup>

Jump Lists は [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) を使用して確認できます。<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: JumplistExplorer を使用して jumplists を確認できます](<../../../images/image (168).png>)

(_JumplistExplorer が提供するタイムスタンプは jumplist ファイル自体に関連するものであることに注意してください_)

### Shellbags

[**shellbags について学ぶにはこのリンクを参照してください。**](interesting-windows-registry-keys.md#shellbags)

## Use of Windows USBs

USB の使用は、リムーバブルメディアからファイルにアクセスした際に作成される artifact によって、裏付けられる場合があります。これには次のものが含まれます。

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com) などのツールは、これらの artifact を USB デバイスの記録と相関させます。ただし、artifact が利用できるかどうかは Windows のバージョンとアプリケーションによって異なります。<sup>[[18]](#references)</sup>

Windows XP および Windows 7 の MTP ワークフローについて記録されたテストでは、一部の LNK が元のパスではなく `WPDNSE` フォルダーを指していました。<sup>[[16]](#references)</sup>

![Shellbags - Use of Windows USBs: 一部の LNK ファイルは元のパスではなく WPDNSE フォルダーを指していることに注意してください](<../../../images/image (218).png>)

この調査では、`%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` 配下にコピーが確認されました。テストでは一時的な内容は再起動後に残らず、GUID は shellbag データと相関させることができました。これは OS、デバイス、アプリケーションに依存する挙動であり、普遍的な規則として扱わないでください。<sup>[[16]](#references)</sup>

### Registry Information

USB 接続されたデバイスに関する興味深い情報を含むレジストリキーについては、[このページを確認してください](interesting-windows-registry-keys.md#usb-information)。

### setupapi

Vista 以降では、デバイスのインストール活動を確認するために `C:\Windows\inf\setupapi.dev.log` を調べます。セクションヘッダーには `Section start` のタイムスタンプが含まれます。これらはセットアップ処理を記録したものであり、正確な物理的挿入時刻として扱うのではなく、他の接続証拠と相関させる必要があります。<sup>[[17]](#references)</sup>

![Registry Information - setupapi: USB 接続が行われた時刻を取得するには、ファイル C: Windows inf setupapi.dev.log を確認してください（Section start を検索）](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) を使用すると、イメージに接続されたことのある USB デバイスに関する情報を取得できます。<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective を使用すると、イメージに接続されたことのある USB デバイスに関する情報を取得できます](<../../../images/image (452).png>)

### Plug and Play Cleanup

`Plug and Play Cleanup` と呼ばれるスケジュールされたタスクは、古いドライバーバージョンを削除します。Adam Harrison が記録した Windows 10 のタスク定義では、30 日間非アクティブなドライバーも対象としているため、リムーバブルデバイスのドライバーに関する証拠が削除される可能性があります。この挙動を一般化する前に、ローカルのタスク定義と Windows build を確認してください。<sup>[[1]](#references)</sup>

タスクは次のパスにあります：`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

**タスクの主要コンポーネントと設定：**

- **pnpclean.dll**: この DLL は実際のクリーンアップ処理を担当します。
- **UseUnifiedSchedulingEngine**: `TRUE` に設定されており、汎用タスクスケジューリングエンジンが使用されることを示します。
- **MaintenanceSettings**:
- **Period ('P1M')**: 通常の Automatic maintenance 中に、Task Scheduler が毎月クリーンアップタスクを開始するよう指示します。
- **Deadline ('P2M')**: タスクが 2 か月連続で失敗した場合、緊急 Automatic maintenance 中にタスクを実行するよう Task Scheduler に指示します。

この設定では定期メンテナンスと、連続した失敗後の再試行がスケジュールされます。正確な XML と挙動はバージョンによって異なります。<sup>[[1]](#references)</sup>

**詳細については次を確認してください：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)。<sup>[[1]](#references)</sup>

## Emails

Emails には、**メールの 2 つの興味深い部分、ヘッダーと内容**が含まれています。**ヘッダー**では次のような情報を確認できます。

- **誰が**メールを送信したか（メールアドレス、IP、メールをリダイレクトしたメールサーバー）
- メールが**いつ**送信されたか

また、`References` および `In-Reply-To` ヘッダーには、返信を会話に関連付けるために使用される message ID が含まれる場合があります。<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: メールがいつ送信されたか](<../../../images/image (593).png>)

### Windows Mail App

このアプリケーションは、メールの内容を `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` などのパスにある補助的なテキストまたは HTML ファイルに保存します。正確な番号付きフォルダーとファイルの構成は artifact によって異なる場合があります。<sup>[[75]](#references)</sup>

Emails の**メタデータ**と**連絡先**は、**ESE database** の `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` 内にあります。<sup>[[75]](#references)</sup>

`store.vol` は Extensible Storage Engine (ESE) 形式を使用します。コピーを作業対象にし、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) などの ESE parser を使用してください。ツールが `.edb` 拡張子を必要とする場合はコピーのみをリネームし、`Message` テーブルに依存する前にテーブルスキーマを確認してください。<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Outlook MAPI properties を調べる際の canonical properties には、次のものがあります。

- `PidTagClientSubmitTime`: client が message を送信した UTC 時刻。
- `PidTagConversationIndex`: conversation thread 内における message の相対的な位置。
- `PidTagEntryId`: message object の識別子。
- `PidTagMessageFlags`: 送信済み、既読、未読、添付ファイルの有無などの status flags。
- `PidTagLastVerbExecuted`: open、reply、forward など、message に対して最後に記録された操作。<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook data-file の場所は、バージョンとアカウントタイプによって異なります。Microsoft は PST/OST ファイルについて、次の一般的な場所を記載しています。

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` から、Outlook profile と関連する data-file の設定を特定できる場合があります。

PST ファイルには、message、contacts、calendar data、その他の Outlook items が含まれる場合があります。[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) を使用してコピーを確認できます。<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Kernel PST Viewer ツールを使用して PST ファイルを開けます](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** は Exchange または Microsoft 365 accounts 用の local cache です。Cached Exchange Mode は POP または IMAP accounts には適用されません。offline period は設定可能で、デフォルトでは 12 か月であることが多く、PST/OST size limits も個別に設定可能です。OST file を表示するには、[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) を使用できます。<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Retrieving Attachments

失われた attachments は、次の場所から復元できる可能性があります。

- 旧来の Outlook/IE configurations の場合：`%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- 新しい Outlook/IE11 configurations の場合：`%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`。<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** は profile data を `%APPDATA%\Thunderbird\Profiles` 配下に保存します。mail folders では通常、account-specific な `Mail` または `ImapMail` directories 内に拡張子のない mbox files が使用されます。<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Thumbnail previews は通常、フォルダーごとの `thumbs.db` files に保存されていました。
- **Network folders**: 該当する thumbnail behavior が有効な場合、UNC folder に対して `thumbs.db` file が作成されることがあります。すべての Windows version または policy が作成するとは限りません。
- **Windows Vista and newer**: system thumbnail cache は `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` 配下に集約され、**thumbcache_xxx.db** などの files が含まれます。[**Thumbsviewer**](https://thumbsviewer.github.io) は legacy `Thumbs.db` を解析でき、[**ThumbCache Viewer**](https://thumbcacheviewer.github.io) は modern thumbnail-cache databases を解析できます。<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

system と user の configuration data を保存する Windows Registry は、次の hive files に含まれています。

- `%WINDIR%\System32\Config`: 各種 `HKEY_LOCAL_MACHINE` subkeys の基盤となる machine hives。
- `%USERPROFILE%\NTUSER.DAT`: user の `HKEY_CURRENT_USER` hive。
- 古い Windows installations の一部には `%WINDIR%\System32\Config\RegBack\` に copies が含まれています。Windows 10 version 1803 以降では、periodic backup が有効でない限り、この directory は自動的に populate されません。<sup>[[34]](#references)[[35]](#references)</sup>
- user ごとの shell および class-registration data は、modern Windows では通常 `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` にも保存されます。<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

registry hives の解析には便利な tools があります。出力に依存する前に、各 tool がサポートする hive formats と version を確認してください。

- **Registry Editor**: Windows にインストールされています。現在の session の Windows registry を GUI で移動するためのものです。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): registry file を load し、GUI で移動できます。また、興味深い情報を含む keys を強調表示する Bookmarks も備えています。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): これも load した registry を GUI で移動でき、load した registry 内の興味深い情報を強調表示する plugins も含まれています。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): load した registry hive から情報を抽出できる、別の GUI application です。<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recovering Deleted Element

削除された hive cells は、その領域が再利用されるまで残っている場合があります。ただし、recovery は hive の状態と parser に依存します。復元された deleted keys は、確実な記録ではなく、検証が必要な evidence として扱ってください。

### Last Write Time

Registry keys には last-write timestamp が付与されます。Windows はその key または value entries のいずれかについてこの timestamp を公開するため、value が独自の独立した変更 timestamp を持つとは限りません。<sup>[[69]](#references)</sup>

### SAM

**SAM** hive には、password hashes などの local user および group account data が含まれており、password hashes は system の boot-key material によって保護されています。<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users` では、account identifiers と一部の logon および policy fields を取得できます。offline hash extraction には、関連する boot-key material を復元するために `SYSTEM` hive も必要です。<sup>[[38]](#references)[[39]](#references)</sup>

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[common Windows processes に関する既存の post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) は追加の参考資料として残されています。process behavior に関する主張は、最新の Windows documentation と local evidence によって裏付けてください。<sup>[[2]](#references)</sup>

### Windows Recent APPs

Windows 10 versions のうち、この機能を公開しているものでは、`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` に、last-used time や launch count などの fields を持つ application ごとの subkeys が含まれています。この artifact は後の releases で削除されているため、対象 build を検証してください。<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Background Activity Moderator を公開している systems では、`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` または新しい `...\bam\State\UserSettings\{SID}` path を確認します。values は user SID をキーとし、追跡された executable paths と FILETIME-like execution data を含む場合があります。この artifact は version-dependent であり、他の evidence と相関させる必要があります。<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch は resources と launch metadata を cache し、programs をより速く起動できるようにします。

Prefetch files は `C:\Windows\Prefetch` に `.pf` files として保存されます。format、retention、file-count limits は Windows version によって異なります。Microsoft は Windows 8 以降について、最後の 8 回の execution times と最大 1024 files の保持を記載しているため、古い fixed-limit の説明を一般化しないでください。<sup>[[13]](#references)</sup>

filename には通常 `{program_name}-{hash}.pf` が使用されます。hash は path や arguments などの execution context から算出されます。Windows 10 以降では file が compress される場合があります。存在は execution evidence として有用ですが、それだけで user による execution の証明にはならないため、他の artifacts と相関させる必要があります。<sup>[[13]](#references)</sup>

これらの files を確認するには、[**PECmd.exe**](https://github.com/EricZimmerman/PECmd) を使用できます。この tool は directory parsing、CSV/HTML output、該当する Windows 10 Prefetch files の decompression support を記載しています。<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** は、過去の使用パターンを利用して読み込みを改善することで Prefetch を補完します。これらを生成するシステムでは、データベースファイルは通常 `C:\Windows\Prefetch\Ag*.db` にあります。形式と存在はバージョンによって異なります。<sup>[[41]](#references)</sup>

これらのデータベースには、アプリケーション名、使用回数、アクセスされたファイルまたはボリューム、パス、時間範囲が含まれている場合がありますが、正確な実行ログとして扱うべきではありません。<sup>[[41]](#references)</sup>

既存の [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) リンクは、使用可能な parser の候補として残されています。使用前に、ツールのドキュメントで現在の提供状況とサポートされる出力を確認してください。

### SRUM

**System Resource Usage Monitor**（SRUM）は、アプリケーションとユーザーによるリソース使用状況を記録します。これは Windows 8 で導入され、ESE database `C:\Windows\System32\sru\SRUDB.dat` にデータを保存します。<sup>[[13]](#references)</sup>

以下の情報を提供します。

- AppID and Path
- レコードに関連付けられた User/SID
- 送信バイト数
- 受信バイト数
- Network Interface
- 接続時間
- プロセス実行時間

収集間隔と保持期間は実装に依存するため、すべてのレコードが正確な 60 分間の実行間隔を表すと想定しないでください。<sup>[[13]](#references)</sup>

[**srum_dump**](https://github.com/MarkBaggett/srum-dump) を使用して、現在のツールバージョンで文書化されているオプションに従い、データを抽出して確認できます。<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**（**ShimCache**とも呼ばれます）は、Windows のアプリケーション互換性インフラストラクチャの一部であり、互換性の判断に使用するファイルメタデータを記録します。ハイブのパス、レコード形式、保持容量、フィールドは Windows のリリースによって異なります。最新の Windows では、ShimCache だけではユーザーがファイルを実行したことを証明できません。関連する `SYSTEM` ハイブを [**AppCompatCacheParser ツール**](https://github.com/EricZimmerman/AppCompatCacheParser) で解析し、その出力を実行アーティファクトと照合してください。<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): 保存された情報を解析するには、AppCompatCacheParser ツールの使用が推奨されます](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** ファイルは、Windows が検出したアプリケーションとファイルをインベントリするレジストリハイブです。通常は `C:\Windows\AppCompat\Programs\Amcache.hve` にあります。

関連付けられたファイルエントリおよび関連付けられていないファイルエントリ、パス、SHA1 値が含まれることがありますが、その存在はインベントリの証拠であり、それだけでプロセスが実行されたことを証明するものではありません。<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve** を抽出して分析するには、[**AmcacheParser ツール**](https://github.com/EricZimmerman/AmcacheParser) を使用します。このコマンドはハイブを解析し、CSV 出力を書き込みます。<sup>[[44]](#references)</sup>

例：
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
生成されたCSVファイルの中では、`Amcache_Unassociated file entries`が、認識されたプログラムに関連付けられていないファイルを調査する際に役立つことがあります。<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7システムでは、`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`に、最近観測されたバイナリに関する情報が含まれている場合があります。利用可能性と意味はバージョンによって異なります。

[**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser)を使用してファイルを解析できます。<sup>[[45]](#references)</sup>

### Scheduled tasks

Scheduled taskの証拠は、最新のtaskでは`C:\Windows\System32\Tasks`に、レガシーtaskでは`.job`ファイルを含む`C:\Windows\Tasks`に存在する場合があります。OSに適したtask定義形式を調査してください。<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Service Control Managerのデータベースは`SYSTEM\CurrentControlSet\Services`にあります（offlineのSYSTEM hiveでは、対応するcontrol-set keyを調査します）。このデータベースには、実行可能ファイルのパスやstart typeなど、serviceとdriverの設定が含まれています。<sup>[[72]](#references)</sup>

### **Windows Store**

インストールされたWindows Storeアプリケーションは、`\ProgramData\Microsoft\Windows\AppRepository\`に記録されている場合があります。これにはデータベース**`StateRepository-Machine.srd`**も含まれます。schemaとpathはWindows releaseによって異なります。<sup>[[71]](#references)</sup>

データベースには、application identifier、package number、display nameが含まれている場合があります。identifierの欠落だけでは、アプリケーションがuninstallされた証拠にはなりません。packageとregistryの状態を照合してください。

package registrationは、`HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`にも存在する場合があります。Microsoftは、削除されたprovisioned app向けにversion-specificな`Deprovisioned` subkeyを文書化しています。すべてのbuildに`Deleted` subkeyが存在すると仮定しないでください。<sup>[[70]](#references)</sup>

## Windows Events

providerによっては、Windows eventに次の情報が含まれる場合があります。

- 何が起きたか
- event schemaとhostの時刻コンテキストに基づいて解釈する必要がある`TimeCreated` timestamp
- 関与したuser
- 関与したhost（hostname、IP）
- accessされたasset（file、folder、printer、service）。<sup>[[49]](#references)</sup>

Windows Vistaより前では、event logは通常、`C:\Windows\System32\config`にあるlegacy binary formatを使用していました。Vista以降ではWindows Event Log formatが使用され、通常は`C:\Windows\System32\winevt\Logs`に保存されます。`.evtx`ファイルには、XMLとしてrenderされたevent dataが含まれます。<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registryには、channel configurationが**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**に保存されています。これには、設定されたfile pathとretention settingが含まれます。<sup>[[47]](#references)</sup>

これらはWindows Event Viewer（**`eventvwr.msc`**）や、[**Event Log Explorer**](https://eventlogxp.com)、[**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)などのtoolで表示できます。<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Vista以降では、Security channelは通常`C:\Windows\System32\winevt\Logs\Security.evtx`に保存されます。最大サイズとretention policyは設定可能です。circular loggingでは、fileが上限に達すると古いrecordが上書きされる場合があります。関連するauditingが有効になっている場合、このchannelにはauthentication、logoff、privilege、audit-policy、object-access eventを記録できます。<sup>[[46]](#references)[[47]](#references)</sup>

### User Authenticationの主要なEvent ID：

- **Event ID 4624**: account logonが成功した。<sup>[[50]](#references)</sup>
- **Event ID 4625**: account logonが失敗した。<sup>[[51]](#references)</sup>
- **Event ID 4634**: logon sessionが終了した。<sup>[[52]](#references)</sup>
- **Event ID 4647**: userがlogoffを開始した。<sup>[[53]](#references)</sup>
- **Event ID 4672**: 新しいlogonにspecial privilegeが割り当てられた。これはsystem accountやadministrator accountで一般的なため、これだけではmalicious activityの証拠にはなりません。<sup>[[54]](#references)</sup>

#### 4624、4625、4634、4647で一般的に記録されるlogon type：

- **Interactive (2)**: interactiveなlocal logon。
- **Network (3)**: shared resourceへのaccess。
- **Batch (4)**: batch-process logon。
- **Service (5)**: service logon。
- **Unlock (7)**: workstationのunlock。
- **NetworkCleartext (8)**: authentication packageにcredentialをcleartextで提供するnetwork logon。
- **NewCredentials (9)**: outbound connection用に提供されたalternate credentialを使用するlogon。
- **RemoteInteractive (10)**: Remote DesktopまたはTerminal Servicesのlogon。
- **CachedInteractive (11)**: cached domain credentialを使用するinteractive logon。
- **CachedRemoteInteractive (12)**: cached remote-interactive logon。
- **CachedUnlock (13)**: cached credentialを使用したunlock。<sup>[[50]](#references)[[51]](#references)</sup>

#### EventID 4625のStatusおよびSub Status Code：

- **0xC0000064**: 該当するuserが存在しない。
- **0xC000006A**: user nameは正しいが、passwordが間違っている。
- **0xC0000234**: accountがlockoutされている。
- **0xC0000072**: accountがdisableされている。
- **0xC000006F**: 許可された時間外のlogon。
- **0xC0000070**: workstation restriction違反。
- **0xC0000193**: accountの有効期限が切れている。
- **0xC0000071**: passwordの有効期限が切れている。
- **0xC0000133**: clientとserverの時刻差が大きすぎる。
- **0xC0000224**: accountはpasswordを変更する必要がある。
- **0xC0000225**: `STATUS_NOT_FOUND`。このcodeだけでは、system bugやattackを特定できない。
- **0xC000015B**: 要求されたlogon typeがaccountに許可されていない。<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616：

- **Time Change**: system timeが変更された。多くのeventは通常のtime-service correctionを反映するため、tamperingと判断する前にactorとtime sourceを照合してください。<sup>[[56]](#references)</sup>

#### Event IDs 12、13、1074、6005、6006、6008、6009：

- **Power and service context**: Event 12はOS start、13はOS shutdown、1074はplanned shutdownまたはrestart、6008はunexpected shutdown、6009はboot時のWindows versionを記録します。Event 6005と6006は、それぞれEvent Log serviceのstartとstopを示します。これらだけではOSのstartupとshutdownの証拠にはなりません。<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102：

- **Log Deletion**: Event 1102はSecurity audit logがclearされたことを記録します。このeventだけから意図を推測するのではなく、actorと前後のeventを調査してください。<sup>[[62]](#references)</sup>

#### USB Device TrackingのEvent ID：

- **20001 / 20003**: first-useまたはinstallation activityの確立に役立つ`UserPnp` device-installation event。
- **10000 / 10100**: device activityに伴って記録される場合がある`DriverFrameworks-UserMode` event。
- **Event ID 112**: insertion-related timestampを提供できる`DeviceSetupManager/Admin` activity。
- provider、channel、eventの意味はWindows versionによって異なります。意味を割り当てる前に、provider nameとevent payloadを調査してください。<sup>[[59]](#references)</sup>

logon typeと関連するcredential materialの実用的な例については、[Altered Securityの詳細なguide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)を参照してください。<sup>[[60]](#references)</sup>

logon type、status、substatus、source address、process fieldなどのevent detailは、Event ID 4625のcontextを提供します。status codeや繰り返されるfailure patternは、結論ではなくinvestigationの手掛かりです。<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

event logは一般的にcircularであるため、loggerによって上書きされたrecordはrecoverできない場合があります。live systemを操作する前にforensic imageまたはworking copyを保存してください。**Bulk_extractor**などのvalidated parserまたはcarverは、tool versionが対象の`.evtx` dataをサポートしていることを確認してから使用してください。eventをrecoverする目的だけで、稼働中のsystemの電源を抜かないでください。<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

実用的なevent-ID referenceについては、既存の[Red Team Recipe](https://redteamrecipe.com/event-codes/) linkを参照し、そこにある例を上記のprovider documentationと照合してください。

#### Brute Force Attacks

繰り返されるEvent ID 4625のfailureを、その後の4624 success、logon type、status、source、account contextと相関させてください。このsequenceは調査対象となるindicatorであり、attackの証拠ではありません。<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616はsystem timeの変更を記録し、timeline analysisを複雑にする場合があります。time-serviceとhostのevidenceと比較してください。<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDはprovider-specificです。`UserPnp` 20001/20003、`DriverFrameworks-UserMode` 10000/10100、`DeviceSetupManager/Admin` 112をSetupAPIおよびregistry artifactと相関させてください。<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

OS start、shutdown、restart、unexpected-power contextには12/13/1074/6008/6009を使用します。6005/6006はEvent Log serviceのstart/stopを示します。<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102はSecurity audit logがclearされたことを記録します。responsible accountおよびprocessと相関させてください。<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Playのcleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - 一般的なWindows processの調査](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 notificationのdigital forensic view](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmermanのforensic tool](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.IdentifierとAlternate Data Stream](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSSにおけるregistry backupおよびrestore operation](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [backupおよびrestore用のregistry key](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover locationにおけるWord performance issue](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: data exfiltration artifactの特定](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entry](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryIDと関連するtype](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook data fileの検索とtransfer](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Modeを有効化](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [一部のitemのみがsynchronizeされる](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlook data fileのsize limitを設定](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profile - Thunderbirdがuser dataを保存する場所](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settingとmbox directory](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registryがRegBackにbackupされない](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [registryをremote edit](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Password technical overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
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
- [55] [MS-ERREF: NTSTATUS value](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [system event logを使用したunexpected rebootのtroubleshoot](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [shutdown in processのtroubleshoot](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10向けUSB Storage Device Forensics](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook DesktopでQuick PrintがPDF attachmentをprintしなくなる](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry file](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [update中に削除済みappが戻らないようにする](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTKおよびRegistry Viewerのtest result](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Installed Serviceのdatabase](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Task Scheduler Service Is Not Available errorによるScheduled Task failure](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mail databaseのnavigate](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
