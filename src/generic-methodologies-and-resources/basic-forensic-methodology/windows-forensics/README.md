# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

パス `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` には、データベース `appdb.dat`（Windows anniversary より前）または `wpndatabase.db`（Windows Anniversary より後）があります。

この SQLite データベース内には、興味深いデータを含む可能性があるすべての通知（XML 形式）が格納された `Notification` テーブルがあります。

### Timeline

Timeline は、アクセスした Web ページ、編集したドキュメント、実行したアプリケーションの**時系列履歴**を提供する Windows の機能です。

データベースはパス `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` にあります。このデータベースは SQLite ツール、または[**2 つのファイルを生成し、ツールで開ける**](https://github.com/EricZimmerman/WxTCmd) [**WxTCmd**](https://ericzimmerman.github.io/#!index.md) で開くことができます。[**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md)

### ADS (Alternate Data Streams)

ダウンロードされたファイルには、イントラネット、インターネットなどから**どのように****ダウンロードされたか**を示す **ADS Zone.Identifier** が含まれている場合があります。一部のソフトウェア（ブラウザなど）は通常、ファイルがダウンロードされた**URL**など、さらに**多くの****情報**も追加します。

## **File Backups**

### Recycle Bin

Vista/Win7/Win8/Win10 では、**Recycle Bin** はドライブのルートにあるフォルダー **`$Recycle.bin`**（`C:\$Recycle.bin`）にあります。\
このフォルダー内でファイルが削除されると、2 つの特定のファイルが作成されます。

- `$I{id}`: ファイル情報（削除された日時}
- `$R{id}`: ファイルの内容

![File Backups - Recycle Bin: $R{id}: ファイルの内容](<../../../images/image (1029).png>)

これらのファイルがあれば、[**Rifiuti**](https://github.com/abelcheung/rifiuti2) ツールを使用して、削除されたファイルの元の場所と削除日時を取得できます（Vista ～ Win10 では `rifiuti-vista.exe` を使用します）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy は Microsoft Windows に含まれるテクノロジーで、使用中のコンピューター上のファイルやボリュームであっても、**バックアップコピー**またはスナップショットを作成できます。

これらのバックアップは通常、ファイルシステムのルートにある `\System Volume Information` に保存され、名前は次の画像に示す **UIDs** で構成されます。

![Recycle Bin - Volume Shadow Copies: これらのバックアップは通常、ファイルシステムのルートにある System Volume Information に保存され、名前は画像に示す UIDs で構成されます...](<../../../images/image (94).png>)

**ArsenalImageMounter** でフォレンジックイメージをマウントすると、[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) を使用して shadow copy を調査し、shadow copy のバックアップから**ファイルを抽出**することもできます。

![Recycle Bin - Volume Shadow Copies: ArsenalImageMounter でフォレンジックイメージをマウントすると、ShadowCopyView を使用して shadow copy を調査し、ファイルを抽出することもできます...](<../../../images/image (576).png>)

レジストリエントリ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` には、**バックアップ対象外とするファイルおよびキー**が含まれています。

![Recycle Bin - Volume Shadow Copies: レジストリエントリ HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore には、バックアップ対象外とするファイルおよびキーが含まれています](<../../../images/image (254).png>)

レジストリ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` にも、`Volume Shadow Copies` に関する構成情報が含まれています。

### Office AutoSaved Files

office の自動保存ファイルは次の場所にあります: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

shell item は、別のファイルへのアクセス方法に関する情報を含む項目です。

### Recent Documents (LNK)

Windows は、ユーザーが次の場所で**ファイルを開く、使用する、または作成する**と、これらの**ショートカット**を**自動的に****作成**します。

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダーが作成されると、そのフォルダー、親フォルダー、および祖父母フォルダーへのリンクも作成されます。

これらの自動的に作成されたリンクファイルには、それが**ファイル**か**フォルダー**か、ファイルの **MAC** **時刻**、ファイルが保存されている**ボリューム情報**、および**対象ファイルのフォルダー**など、**元のファイルに関する情報**が含まれています。この情報は、ファイルが削除された場合に復元するために役立ちます。

また、リンクファイルの**作成日時**は元のファイルが**最初に****使用された**最初の**時刻であり、リンクファイルの**更新日時**は元のファイルが使用された**最後の**時刻です。

これらのファイルを調査するには、[**LinkParser**](http://4discovery.com/our-tools/) を使用できます。

このツールでは、**2 セット**のタイムスタンプを確認できます。

- **First Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Second Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

1 つ目のタイムスタンプセットは、**ファイル自体のタイムスタンプ**を示します。2 つ目のセットは、リンクされたファイルの**タイムスタンプ**を示します。

Windows CLI tool の [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) を実行しても、同じ情報を取得できます。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
この場合、情報は CSV ファイル内に保存されます。

### Jumplists

これらは、アプリケーションごとに示される最近使用したファイルです。各アプリケーションでアクセスできる、**アプリケーションが最近使用したファイル**の一覧です。**自動またはカスタム**で作成できます。

**自動的に作成された jumplists** は `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` に保存されます。jumplists は `{id}.autmaticDestinations-ms` という形式で命名されます。先頭の ID はアプリケーションの ID です。

カスタム jumplists は `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` に保存されます。通常、ファイルに**重要な変更**があった場合（お気に入りとしてマークされた場合など）に、アプリケーションによって作成されます。

jumplist の**作成時刻**は、ファイルに**初めてアクセスした時刻**を示し、**変更時刻は最後にアクセスした時刻**を示します。

[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) を使用して jumplists を調査できます。

![Recent Documents (LNK) - Jumplists: JumplistExplorer を使用して jumplists を調査できます](<../../../images/image (168).png>)

(_JumplistExplorer が提供するタイムスタンプは、jumplist ファイル自体に関連するものであることに注意してください_)

### Shellbags

[**shellbags について知るには、このリンクを参照してください。**](interesting-windows-registry-keys.md#shellbags)

## Windows USB の使用

以下の作成により、USB デバイスが使用されたことを特定できます。

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

一部の LNK ファイルは元のパスを指す代わりに、WPDNSE フォルダーを指していることに注意してください。

![Shellbags - Use of Windows USBs: 一部の LNK ファイルは元のパスを指す代わりに、WPDNSE フォルダーを指していることに注意してください](<../../../images/image (218).png>)

WPDNSE フォルダー内のファイルは元のファイルのコピーであるため、PC の再起動後は残りません。また、GUID は shellbag から取得されます。

### Registry Information

USB 接続デバイスに関する興味深い情報を含むレジストリキーについては、[このページを確認してください](interesting-windows-registry-keys.md#usb-information)。

### setupapi

USB 接続が行われた時刻に関するタイムスタンプを取得するには、`C:\Windows\inf\setupapi.dev.log` ファイルを確認します（`Section start` を検索してください）。

![Registry Information - setupapi: USB 接続が行われた時刻に関するタイムスタンプを取得するには、ファイル C: Windows inf setupapi.dev.log を確認してください（Section start を検索）](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) を使用すると、イメージに接続されたことのある USB デバイスに関する情報を取得できます。

![setupapi - USB Detective: USBDetective を使用すると、イメージに接続されたことのある USB デバイスに関する情報を取得できます](<../../../images/image (452).png>)

### Plug and Play Cleanup

「Plug and Play Cleanup」と呼ばれるスケジュールタスクは、主に古いドライバーバージョンを削除するために設計されています。最新のドライバーパッケージバージョンを保持するという指定された目的とは異なり、online sources では、30 日間非アクティブだったドライバーも対象になるとされています。その結果、過去 30 日間に接続されていない removable devices のドライバーは削除される可能性があります。<sup>[[1]](#references)</sup>

このタスクは次のパスにあります: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`

タスクの内容を示すスクリーンショットを以下に示します: ![USB Detective - Plug and Play Cleanup: このタスクは次のパスにあります: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**タスクの主要なコンポーネントと設定:**

- **pnpclean.dll**: この DLL が実際の cleanup process を担当します。
- **UseUnifiedSchedulingEngine**: `TRUE` に設定されており、generic task scheduling engine を使用することを示します。
- **MaintenanceSettings**:
- **Period ('P1M')**: 通常の Automatic maintenance 中に、Task Scheduler が毎月 cleanup task を開始するよう指示します。
- **Deadline ('P2M')**: task が 2 か月連続で失敗した場合、emergency Automatic maintenance 中に task を実行するよう Task Scheduler に指示します。

この設定により、ドライバーの定期的な maintenance と cleanup が行われ、連続して失敗した場合には task を再試行できます。

**詳細については次を確認してください:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Emails

Emails には、**2 つの興味深い部分、headers と email の content** が含まれています。**headers** には、次のような情報があります。

- Emails の送信者（email address、email を redirect した IP、mail servers）
- Email が送信された時刻

また、`References` および `In-Reply-To` headers 内には、messages の ID があります。

![Plug and Play Cleanup - Emails: Email が送信された時刻](<../../../images/image (593).png>)

### Windows Mail App

この application は Emails を HTML または text として保存します。Emails は `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` 内の subfolders にあります。Emails は `.dat` extension で保存されます。

Emails の **metadata** と **contacts** は、**EDB database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` 内にあります。

ファイルの**extension を変更**して `.vol` から `.edb` にすると、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) を使用して開くことができます。`Message` table 内で Emails を確認できます。

### Microsoft Outlook

Exchange servers または Outlook clients が使用される場合、いくつかの MAPI headers が存在します。

- `Mapi-Client-Submit-Time`: Email が送信されたシステム時刻
- `Mapi-Conversation-Index`: thread の child messages 数と、thread 内の各 message の timestamp
- `Mapi-Entry-ID`: Message identifier。
- `Mappi-Message-Flags` および `Pr_last_Verb-Executed`: MAPI client に関する情報（message は read か、未読か、responded か、redirected か、out of the office か）

Microsoft Outlook client では、送受信したすべての messages、contacts data、calendar data が PST file に保存されています。

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` は、使用されている file を示します。

PST file は [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) を使用して開くことができます。

![Windows Mail App - Microsoft Outlook: Kernel PST Viewer を使用して PST file を開くことができます](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** は、Microsoft Outlook が **IMAP** または **Exchange** server 用に設定されている場合に生成され、PST file と同様の情報を保存します。この file は server と同期され、**最大 50GB** のサイズまで、**過去 12 か月間**の data を保持します。PST file と同じ directory にあります。OST file を表示するには、[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) を使用できます。

### Retrieving Attachments

失われた attachments は、次の場所から復元できる場合があります。

- **IE10** の場合: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 以降**の場合: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** は data の保存に **MBOX files** を使用します。これらは `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` にあります。

### Image Thumbnails

- **Windows XP および 8-8.1**: thumbnails のある folder にアクセスすると、削除後も image previews を保存する `thumbs.db` file が生成されます。
- **Windows 7/10**: UNC path 経由で network 上からアクセスした場合に `thumbs.db` が作成されます。
- **Windows Vista 以降**: Thumbnail previews は `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` に一元化され、**thumbcache_xxx.db** という名前の files に保存されます。[**Thumbsviewer**](https://thumbsviewer.github.io) と [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) は、これらの files を表示するための tools です。

### Windows Registry Information

広範な system および user activity data を保存する Windows Registry は、次の files に含まれています。

- 各種 `HKEY_LOCAL_MACHINE` subkeys: `%windir%\System32\Config`
- `HKEY_CURRENT_USER`: `%UserProfile%{User}\NTUSER.DAT`
- Windows Vista 以降の versions は、`HKEY_LOCAL_MACHINE` registry files を `%Windir%\System32\Config\RegBack\` に backup します。
- さらに、Windows Vista および Windows 2008 Server 以降では、program execution information が `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` に保存されます。

### Tools

registry files の分析には、いくつかの tools が役立ちます。

- **Registry Editor**: Windows にインストールされています。現在の session の Windows registry を GUI で navigate するためのものです。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): registry file を load し、GUI で navigate できます。また、興味深い情報を含む keys を強調表示する Bookmarks も備えています。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): 同様に、load した registry を navigate できる GUI を備えています。また、load した registry 内の興味深い情報を強調表示する plugins も含まれています。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): load した registry から重要な情報を抽出できる、別の GUI application です。

### Recovering Deleted Element

key を削除すると削除済みとしてマークされますが、その key が占有している space が必要になるまでは削除されません。そのため、**Registry Explorer** などの tools を使用すれば、これらの削除された keys を復元できます。

### Last Write Time

各 Key-Value には、最後に変更された時刻を示す **timestamp** が含まれています。

### SAM

file/hive **SAM** には、system の **users、groups、users passwords** の hashes が含まれています。

`SAM\Domains\Account\Users` では、username、RID、last login、last failed logon、login counter、password policy、account が作成された時刻を取得できます。**hashes** を取得するには、file/hive **SYSTEM** も**必要**です。

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[この post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) では、suspicious behaviours を検出するために、一般的な Windows processes について学べます。<sup>[[2]](#references)</sup>

### Windows Recent APPs

registry `NTUSER.DAT` 内の `Software\Microsoft\Current Version\Search\RecentApps` パスには、**実行された application**、**最後に実行された時刻**、**起動された回数**に関する情報を含む subkeys があります。

### BAM (Background Activity Moderator)

registry editor で `SYSTEM` file を開き、`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` パス内を確認すると、**各 user によって実行された applications**（パス内の `{SID}` に注意）と、それらが実行された**時刻**（時刻は registry の Data value 内にあります）を確認できます。

### Windows Prefetch

Prefetch は、user が**近い将来にアクセスする可能性のある** content を表示するために必要な resources を、computer がひそかに**取得できるようにする** technique です。これにより、resources により速くアクセスできます。

Windows prefetch は、実行された programs の **caches** を作成し、より速く load できるようにします。これらの caches は、`C:\Windows\Prefetch` パス内に `.pf` files として作成されます。XP/VISTA/WIN7 では 128 files、Win8/Win10 では 1024 files の上限があります。

file name は `{program_name}-{hash}.pf` として作成されます（hash は executable の path と arguments に基づきます）。W10 では、これらの files は compressed です。file が存在するだけで、**その program が過去のある時点で実行された**ことを示す点に注意してください。

`C:\Windows\Prefetch\Layout.ini` file には、prefetch された files がある **folders の names** が含まれています。この file には、**実行回数**、実行の**dates**、および program によって**open** された **files** に関する**情報**が含まれています。

これらの files を調査するには、[**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) tool を使用できます。
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** は prefetch と同じ目的、つまり次にロードされるものを予測して **プログラムをより速くロードする** ことを目的としています。ただし、prefetch service を置き換えるものではありません。\
この service は `C:\Windows\Prefetch\Ag*.db` に database files を生成します。

これらの database には、**プログラム** の **名前**、**実行回数**、**開かれた** **files**、**アクセスされた** **volume**、**完全な** **path**、**期間**、**timestamps** が記録されています。

この情報には [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) tool を使用してアクセスできます。

### SRUM

**System Resource Usage Monitor** (SRUM) は、**process によって** **消費された** **resources** を **監視** します。W8 で登場し、`C:\Windows\System32\sru\SRUDB.dat` にある ESE database にデータを保存します。

以下の情報を提供します。

- AppID and Path
- process を実行した User
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

この情報は 60 分ごとに更新されます。

この file から日付を取得するには、[**srum_dump**](https://github.com/MarkBaggett/srum-dump) tool を使用できます。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**（**ShimCache** とも呼ばれます）は、アプリケーション互換性の問題に対処するために **Microsoft** が開発した **Application Compatibility Database** の一部です。このシステムコンポーネントには、次のようなファイルメタデータが記録されます。

- ファイルの完全パス
- ファイルサイズ
- **$Standard_Information**（SI）における最終変更時刻
- ShimCache の最終更新時刻
- プロセス実行フラグ

このデータは、オペレーティングシステムのバージョンに応じて、レジストリ内の特定の場所に保存されます。

- XP では、データは `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` に保存され、96 エントリまで格納できます。
- Server 2003、および Windows 2008、2012、2016、7、8、10 では、保存先は `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` で、格納できるエントリ数はそれぞれ 512 および 1024 です。

保存された情報を parse するには、[**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) の使用が推奨されます。

![SRUM - AppCompatCache (ShimCache): 保存された情報を parse するには、AppCompatCacheParser tool の使用が推奨されます](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** ファイルは、システム上で実行されたアプリケーションの詳細を記録する registry hive です。通常、`C:\Windows\AppCompat\Programas\Amcache.hve` にあります。

このファイルには、実行された最近のプロセスの記録が保存されており、実行ファイルへのパスや SHA1 ハッシュなどが含まれます。この情報は、システム上のアプリケーションのアクティビティを追跡するうえで非常に有用です。

**Amcache.hve** からデータを抽出して分析するには、[**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool を使用できます。次のコマンドは、AmcacheParser を使用して **Amcache.hve** ファイルの内容を parse し、結果を CSV 形式で出力する方法の例です。
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
生成された CSV ファイルの中でも、`Amcache_Unassociated file entries` は、unassociated file entries に関する豊富な情報を提供するため、特に注目に値します。

生成される CVS ファイルの中で最も興味深いものは、`Amcache_Unassociated file entries` です。

### RecentFileCache

この artifact は W7 の `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` にのみ存在し、一部の binary の最近の実行に関する情報が含まれています。

ファイルの parse には [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) tool を使用できます。

### Scheduled tasks

`C:\Windows\Tasks` または `C:\Windows\System32\Tasks` から抽出し、XML として読み取ることができます。

### Services

Registry の `SYSTEM\ControlSet001\Services` にあります。何が実行されるか、またいつ実行されるかを確認できます。

### **Windows Store**

インストールされている applications は `\ProgramData\Microsoft\Windows\AppRepository\`\
にあります。
この repository には、database **`StateRepository-Machine.srd`** 内に、system にインストールされた**各 application** の **log** があります。

この database の Application table では、"Application ID"、"PackageNumber"、"Display Name" の columns を確認できます。これらの columns には pre-installed および installed applications に関する情報が含まれており、インストールされた applications の ID は連番になるはずなので、一部の applications が uninstall されたかどうかを確認できます。

Registry path `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
から**インストールされた application** を確認することもできます。
また、**uninstall された** **applications** は `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\` にあります。

## Windows Events

Windows events 内に現れる情報は次のとおりです。

- 発生した内容
- Timestamp (UTC + 0)
- 関係する Users
- 関係する Hosts (hostname、IP)
- Access された Assets (files、folder、printer、services)

Logs は、Windows Vista より前では `C:\Windows\System32\config` に、Windows Vista 以降では `C:\Windows\System32\winevt\Logs` にあります。Windows Vista より前では event logs は binary format でしたが、それ以降は **XML format** で、**.evtx** extension を使用します。

Event files の location は、SYSTEM registry の **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** にあります。

Windows Event Viewer (**`eventvwr.msc`**) または [**Event Log Explorer**](https://eventlogxp.com) **や** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** などの他の tools で表示できます。**

## Windows Security Event Logging の理解

Access events は `C:\Windows\System32\winevt\Security.evtx` にある security configuration file に記録されます。この file の size は調整可能で、capacity に達すると古い events が上書きされます。記録される events には、user logins と logoffs、user actions、security settings の変更、file、folder、shared asset への access などが含まれます。

### User Authentication における主な Event IDs:

- **EventID 4624**: User が正常に authenticated されたことを示します。
- **EventID 4625**: Authentication failure を示します。
- **EventIDs 4634/4647**: User logoff events を表します。
- **EventID 4672**: Administrative privileges での login を示します。

#### EventID 4634/4647 内の Sub-types:

- **Interactive (2)**: User による直接 login。
- **Network (3)**: Shared folders への access。
- **Batch (4)**: Batch processes の実行。
- **Service (5)**: Service の launch。
- **Proxy (6)**: Proxy authentication。
- **Unlock (7)**: Password による screen の unlock。
- **Network Cleartext (8)**: Clear text password の送信。多くの場合 IIS から行われます。
- **New Credentials (9)**: Access に別の credentials を使用。
- **Remote Interactive (10)**: Remote desktop または terminal services による login。
- **Cache Interactive (11)**: Domain controller に contact せず、cached credentials で login。
- **Cache Remote Interactive (12)**: Cached credentials による remote login。
- **Cached Unlock (13)**: Cached credentials による unlock。

#### EventID 4625 の Status および Sub Status Codes:

- **0xC0000064**: User name が存在しない - Username enumeration attack を示す可能性があります。
- **0xC000006A**: 正しい user name だが password が間違っている - Password guessing または brute-force attempt の可能性があります。
- **0xC0000234**: User account が locked out - 複数回の failed logins による brute-force attack の後に発生する可能性があります。
- **0xC0000072**: Account が disabled - Disabled accounts への unauthorized attempts。
- **0xC000006F**: 許可された時間外の logon - 設定された login hours 外からの access attempt を示し、unauthorized access の兆候である可能性があります。
- **0xC0000070**: Workstation restrictions の違反 - Unauthorized location から login を試みた可能性があります。
- **0xC0000193**: Account expiration - Expired user accounts による access attempts。
- **0xC0000071**: Expired password - 古い passwords による login attempts。
- **0xC0000133**: Time sync issues - Client と server 間の大きな時刻差は、pass-the-ticket などのより高度な attacks を示している可能性があります。
- **0xC0000224**: Mandatory password change が必要 - 頻繁な mandatory changes は、account security を不安定化させる attempt を示唆する可能性があります。
- **0xC0000225**: Security issue ではなく system bug を示します。
- **0xC000015b**: Denied logon type - User が service logon を実行しようとする場合など、unauthorized logon type による access attempt。

#### EventID 4616:

- **Time Change**: System time の modification。Events の timeline を不明瞭にする可能性があります。

#### EventID 6005 および 6006:

- **System Startup and Shutdown**: EventID 6005 は system の startup を、EventID 6006 は shutdown を示します。

#### EventID 1102:

- **Log Deletion**: Security logs が clear されたことを示します。これは illicit activities を隠蔽するための red flag であることが多いです。

#### USB Device Tracking 用の EventIDs:

- **20001 / 20003 / 10000**: USB device の初回 connection。
- **10100**: USB driver の update。
- **EventID 112**: USB device の insertion 時刻。

これらの login types と credential dumping opportunities を simulate する実践例については、[Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) を参照してください。

Event details には status および sub-status codes などが含まれ、event の原因に関する詳細な insight を提供します。これは特に Event ID 4625 で注目されます。

### Windows Events の復元

Deleted Windows Events を recover できる可能性を高めるには、suspect computer の電源を直接 unplug して切ることが推奨されます。`.evtx` extension を指定する recovery tool **Bulk_extractor** は、このような events の recovery を試みるために推奨されます。

### Windows Events による一般的な Attacks の特定

Windows Event IDs を使用して一般的な cyber attacks を特定する方法については、[Red Team Recipe](https://redteamrecipe.com/event-codes/) を参照してください。

#### Brute Force Attacks

複数の EventID 4625 records に続き、attack が成功した場合は EventID 4624 が記録されることで特定できます。

#### Time Change

EventID 4616 に記録されます。System time の変更は forensic analysis を複雑にする可能性があります。

#### USB Device Tracking

USB device tracking に役立つ System EventIDs には、初回使用を示す 20001/20003/10000、driver updates を示す 10100、insertion timestamps を示す DeviceSetupManager の EventID 112 があります。

#### System Power Events

EventID 6005 は system startup を、EventID 6006 は shutdown を示します。

#### Log Deletion

Security EventID 1102 は logs の deletion を示します。これは forensic analysis における critical event です。

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
