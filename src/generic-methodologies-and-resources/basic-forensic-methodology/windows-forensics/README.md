# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

パス `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` に、データベース `appdb.dat`（Windows anniversary以前）または `wpndatabase.db`（Windows Anniversary以降）があります。

この SQLite データベース内には、興味深いデータを含む可能性があるすべての通知（XML形式）が格納された `Notification` テーブルがあります。

### Timeline

Timeline は、アクセスした Web ページ、編集したドキュメント、実行したアプリケーションの**時系列履歴**を提供する Windows の機能です。

データベースはパス `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` にあります。このデータベースは SQLite ツール、または[**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md)で開ける**2つのファイルを生成するツール**[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)で開くことができます。

### ADS (Alternate Data Streams)

ダウンロードしたファイルには、イントラネット、インターネットなどから**どのようにダウンロードされたか**を示す**ADS Zone.Identifier**が含まれている場合があります。一部のソフトウェア（ブラウザなど）は通常、ファイルのダウンロード元の**URL**など、さらに多くの**情報**も記録します。

## **File Backups**

### Recycle Bin

Vista/Win7/Win8/Win10では、**Recycle Bin**はドライブのルートにあるフォルダー **`$Recycle.bin`**（`C:\$Recycle.bin`）にあります。\
このフォルダー内のファイルが削除されると、次の2つのファイルが作成されます。

- `$I{id}`: ファイル情報（削除日時}
- `$R{id}`: ファイルの内容

![File Backups - Recycle Bin: $R{id}: ファイルの内容](<../../../images/image (1029).png>)

これらのファイルがあれば、[**Rifiuti**](https://github.com/abelcheung/rifiuti2)を使用して、削除されたファイルの元の場所と削除日時を取得できます（Vista – Win10では `rifiuti-vista.exe` を使用）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy は Microsoft Windows に含まれるテクノロジーで、使用中のコンピューターのファイルやボリュームであっても、**backup copies** やスナップショットを作成できます。

これらのバックアップは通常、ファイルシステムのルートにある `\System Volume Information` に保存され、名前は次の画像に示す **UIDs** で構成されます。

![Recycle Bin - Volume Shadow Copies: これらのバックアップは通常、ファイルシステムのルートにある System Volume Information に保存され、名前は画像に示す UIDs で構成されます](<../../../images/image (94).png>)

**ArsenalImageMounter** でフォレンジックイメージをマウントすると、[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) を使用して shadow copy を調査したり、shadow copy のバックアップから**ファイルを抽出**したりできます。

![Recycle Bin - Volume Shadow Copies: ArsenalImageMounter でフォレンジックイメージをマウントすると、ShadowCopyView を使用して shadow copy を調査したり、ファイルを抽出したりできます](<../../../images/image (576).png>)

レジストリエントリ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` には、**バックアップ対象外とするファイルおよびキー**が含まれています。

![Recycle Bin - Volume Shadow Copies: レジストリエントリ HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore には、バックアップ対象外とするファイルおよびキーが含まれています](<../../../images/image (254).png>)

レジストリ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` には、`Volume Shadow Copies` に関する設定情報も含まれています。

### Office AutoSaved Files

Office の自動保存ファイルは次の場所にあります: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

shell item は、別のファイルへのアクセス方法に関する情報を含むアイテムです。

### Recent Documents (LNK)

Windows は、ユーザーが次の場所で**ファイルを開く、使用する、または作成する**と、これらの**ショートカット**を**自動的に****作成**します。

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダーが作成されると、そのフォルダー、親フォルダー、および祖父母フォルダーへのリンクも作成されます。

これらの自動的に作成されたリンクファイルには、それが**ファイル**か**フォルダー**か、ファイルの **MAC** **times**、ファイルが保存されている**ボリューム情報**、および**対象ファイルのフォルダー**など、**元のファイルに関する情報**が含まれています。この情報は、ファイルが削除された場合に復元するために役立ちます。

また、リンクファイルの**作成日時**は元のファイルが**初めて****使用された**最初の**時刻**であり、リンクファイルの**更新日時**は元のファイルが最後に使用された**時刻**です。

これらのファイルを調査するには、[**LinkParser**](http://4discovery.com/our-tools/) を使用できます。

このツールでは、**2 sets** のタイムスタンプを確認できます。

- **First Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Second Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

1 つ目のタイムスタンプセットは、**ファイル自体のタイムスタンプ**を示します。2 つ目のセットは、リンクされたファイルの**タイムスタンプ**を示します。

Windows CLI ツール [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) を実行しても、同じ情報を取得できます。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
この場合、情報は CSV ファイル内に保存されます。

### Jumplists

これらは、アプリケーションごとに示される最近使用したファイルです。各アプリケーションでアクセスできる、**アプリケーションが最近使用したファイルの一覧**です。**自動またはカスタム**で作成されます。

自動的に作成された **jumplists** は `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` に保存されます。jumplists は `{id}.autmaticDestinations-ms` という形式で命名されます。先頭の ID はアプリケーションの ID です。

カスタム jumplists は `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` に保存されます。通常、ファイルに関して**重要な出来事**（お気に入りとしてマークされた場合など）が発生したため、アプリケーションによって作成されます。

jumplist の**作成日時**は、ファイルに**初めてアクセスした時刻**を示し、**変更日時**は最後にアクセスした時刻を示します。

[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) を使用して jumplists を調査できます。

![Recent Documents (LNK) - Jumplists: JumplistExplorer を使用して jumplists を調査できます](<../../../images/image (168).png>)

（_JumplistExplorer が提供するタイムスタンプは、jumplist ファイル自体に関連するものであることに注意してください_）

### Shellbags

[**shellbags について学ぶには、このリンクを参照してください。**](interesting-windows-registry-keys.md#shellbags)

## Windows USB の使用

以下の作成によって、USB デバイスが使用されたことを特定できます。

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

一部の LNK ファイルは、元のパスを指す代わりに WPDNSE フォルダーを指していることに注意してください。

![Shellbags - Use of Windows USBs: 一部の LNK ファイルは、元のパスを指す代わりに WPDNSE フォルダーを指していることに注意してください](<../../../images/image (218).png>)

WPDNSE フォルダー内のファイルは元のファイルのコピーです。そのため、PC の再起動後は残らず、GUID は shellbag から取得されます。

### Registry Information

USB 接続デバイスに関する興味深い情報を含むレジストリキーについては、[このページを確認してください](interesting-windows-registry-keys.md#usb-information)。

### setupapi

USB 接続が行われた時刻に関するタイムスタンプを取得するには、`C:\Windows\inf\setupapi.dev.log` ファイルを確認します（`Section start` を検索します）。

![Registry Information - setupapi: USB 接続が行われた時刻に関するタイムスタンプを取得するには、ファイル C: Windows inf setupapi.dev.log を確認します（Section start を検索します）](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) を使用すると、イメージに接続されたことのある USB デバイスに関する情報を取得できます。

![setupapi - USB Detective: USBDetective を使用すると、イメージに接続されたことのある USB デバイスに関する情報を取得できます](<../../../images/image (452).png>)

### Plug and Play Cleanup

「Plug and Play Cleanup」と呼ばれる scheduled task は、主に古い driver version の削除を目的としています。最新の driver package version を保持するという指定された目的とは反対に、online sources では、30 日間 inactive だった driver も対象にするとされています。そのため、過去 30 日間接続されていない removable device 用の driver は削除される可能性があります。<sup>[[1]](#references)</sup>

task は次の path にあります：`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

task の内容を示す screenshot は次のとおりです：![USB Detective - Plug and Play Cleanup: task は次の path にあります：C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**task の主な component と設定：**

- **pnpclean.dll**：実際の cleanup process を担当する DLL です。
- **UseUnifiedSchedulingEngine**：`TRUE` に設定されており、generic task scheduling engine を使用することを示します。
- **MaintenanceSettings**：
- **Period ('P1M')**：通常の Automatic maintenance 中に、Task Scheduler が毎月 cleanup task を開始するように指示します。
- **Deadline ('P2M')**：task が 2 か月連続で失敗した場合、emergency Automatic maintenance 中に task を実行するよう Task Scheduler に指示します。

この設定により、driver の定期的な maintenance と cleanup が保証され、連続して失敗した場合に task を再試行する仕組みも提供されます。

**詳細については、次を確認してください：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Emails には、**2 つの興味深い部分があります：headers と email の content** です。**headers** には、次のような情報があります。

- Emails を送信した**人物**（email address、IP、email を redirect した mail server）
- Email が送信された**時刻**

また、`References` と `In-Reply-To` headers 内には、messages の ID があります。

![Plug and Play Cleanup - Emails: Email が送信された時刻](<../../../images/image (593).png>)

### Windows Mail App

この application は emails を HTML または text として保存します。Emails は `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` 内の subfolder にあります。Emails は `.dat` extension で保存されます。

Emails の **metadata** と **contacts** は **EDB database**：` \Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` 内にあります。

ファイルの **extension を `.vol` から `.edb` に変更**すると、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) を使用して開くことができます。`Message` table 内で emails を確認できます。

### Microsoft Outlook

Exchange server または Outlook client を使用している場合、いくつかの MAPI headers があります。

- `Mapi-Client-Submit-Time`：Email が送信されたシステム時刻
- `Mapi-Conversation-Index`：thread の child message 数、および thread 内の各 message の timestamp
- `Mapi-Entry-ID`：Message identifier
- `Mappi-Message-Flags` と `Pr_last_Verb-Executed`：MAPI client に関する情報（message は read されたか、未読か、返信されたか、redirect されたか、out of the office か）

Microsoft Outlook client では、送受信したすべての messages、contacts data、calendar data が、次の場所にある PST file に保存されます。

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

registry path `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` は、使用されている file を示します。

PST file は [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) を使用して開くことができます。

![Windows Mail App - Microsoft Outlook: Kernel PST Viewer を使用して PST file を開くことができます](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file** は、**IMAP** または **Exchange** server を使用するよう Microsoft Outlook が設定されている場合に生成され、PST file と同様の情報を保存します。この file は server と同期され、**過去 12 か月分**の data を保持します。最大 size は **50GB** で、PST file と同じ directory にあります。OST file を表示するには、[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) を使用できます。

### Retrieving Attachments

失われた attachments は、次の場所から recovery できる可能性があります。

- **IE10** の場合：`%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 以降**の場合：`%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** は data の保存に **MBOX files** を使用します。これらは `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` にあります。

### Image Thumbnails

- **Windows XP と 8-8.1**：thumbnail のある folder にアクセスすると、削除後も image preview を保存する `thumbs.db` file が生成されます。
- **Windows 7/10**：UNC path 経由で network 上の folder にアクセスした場合に `thumbs.db` が作成されます。
- **Windows Vista 以降**：thumbnail preview は `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` に集中管理され、**thumbcache_xxx.db** という名前の files に保存されます。[**Thumbsviewer**](https://thumbsviewer.github.io) と [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) は、これらの files を表示するための tools です。

### Windows Registry Information

広範な system および user activity data を保存する Windows Registry は、次の files に含まれています。

- さまざまな `HKEY_LOCAL_MACHINE` subkey：`%windir%\System32\Config`
- `HKEY_CURRENT_USER`：`%UserProfile%{User}\NTUSER.DAT`
- Windows Vista 以降の version では、`HKEY_LOCAL_MACHINE` registry files の backup が `%Windir%\System32\Config\RegBack\` に保存されます。
- さらに、program execution information は Windows Vista および Windows 2008 Server 以降、`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` に保存されます。

### Tools

registry files の分析には、次の tools が役立ちます。

- **Registry Editor**：Windows に install されています。現在の session の Windows registry を GUI で移動するための tool です。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：registry file を load し、GUI でその中を移動できます。また、興味深い情報を含む keys を強調表示する Bookmarks も含まれています。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：これにも、load した registry 内を移動できる GUI があり、load した registry 内の興味深い情報を強調表示する plugins も含まれています。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：load した registry から重要な情報を抽出できる、別の GUI application です。

### Recovering Deleted Element

key を削除すると削除済みとしてマークされますが、その key が占有している space が必要になるまでは削除されません。そのため、**Registry Explorer** などの tools を使用すれば、これらの削除された keys を recovery できます。

### Last Write Time

各 Key-Value には、最後に変更された時刻を示す**timestamp**が含まれています。

### SAM

file/hive **SAM** には、system の**users、groups、users の password hashes** が含まれています。

`SAM\Domains\Account\Users` では、username、RID、last login、last failed logon、login counter、password policy、account の作成時刻を取得できます。**hashes** を取得するには、file/hive **SYSTEM** も**必要**です。

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[この post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) では、不審な behaviours を検出するために、一般的な Windows processes について学ぶことができます。

### Windows Recent APPs

registry `NTUSER.DAT` 内の path `Software\Microsoft\Current Version\Search\RecentApps` には、**実行された application**、その**最後の実行時刻**、および**起動回数**に関する情報を含む subkeys があります。

### BAM (Background Activity Moderator)

registry editor で `SYSTEM` file を開き、path `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` 内を確認すると、**各 user が実行した applications**（path 内の `{SID}` に注意）と、それらが**実行された時刻**を確認できます（時刻は registry の Data value 内にあります）。

### Windows Prefetch

Prefetch は、user が**近い将来にアクセスする可能性のある content を表示するために必要な resources を、コンピューターがバックグラウンドで取得**し、より高速に resources にアクセスできるようにする technique です。

Windows prefetch は、**実行された programs の cache** を作成して、より高速に load できるようにします。これらの cache は、path `C:\Windows\Prefetch` 内に `.pf` files として作成されます。XP/VISTA/WIN7 では 128 files、Win8/Win10 では 1024 files という上限があります。

file name は `{program_name}-{hash}.pf` として作成されます（hash は executable の path と arguments に基づきます）。W10 では、これらの files は compressed されています。file が存在するだけで、**その program が過去のある時点で実行された**ことを示す点に注意してください。

`C:\Windows\Prefetch\Layout.ini` file には、prefetch された files の**folder 名**が含まれています。この file には、**実行回数**、実行の**dates**、および program によって**open** された **files** に関する情報が含まれています。

これらの files を調査するには、[**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) tool を使用できます。
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** は prefetch と同じ目的、つまり次にロードされるものを予測して **プログラムをより速くロードする** ことを目的としています。ただし、prefetch service を置き換えるものではありません。\
この service は `C:\Windows\Prefetch\Ag*.db` に database files を生成します。

これらの database では、**program** の **name**、**executions** の **number**、**opened** **files**、アクセスされた **volume**、**complete** **path**、**timeframes**、**timestamps** を確認できます。

この情報には [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) tool を使用してアクセスできます。

### SRUM

**System Resource Usage Monitor** (SRUM) は、**process によって消費された** **resources** を **monitor** します。W8 で登場し、データは `C:\Windows\System32\sru\SRUDB.dat` にある ESE database に保存されます。

次の情報が得られます。

- AppID and Path
- process を実行した User
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

この情報は 60 分ごとに更新されます。

この file から date を取得するには、[**srum_dump**](https://github.com/MarkBaggett/srum-dump) tool を使用できます。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**（**ShimCache** とも呼ばれます）は、アプリケーションの互換性問題に対処するために **Microsoft** が開発した **Application Compatibility Database** の一部です。このシステムコンポーネントには、次のようなファイルメタデータが記録されます。

- ファイルのフルパス
- ファイルサイズ
- **$Standard_Information**（SI）における最終変更時刻
- ShimCache の最終更新時刻
- プロセス実行フラグ

このデータは、オペレーティングシステムのバージョンに応じて、レジストリ内の特定の場所に保存されます。

- XP では、データは `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` に保存され、96 件まで格納できます。
- Server 2003、および Windows 2008、2012、2016、7、8、10 では、保存先は `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` で、それぞれ 512 件および 1024 件を格納できます。

保存された情報を解析するには、[**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) の使用が推奨されます。

![SRUM - AppCompatCache (ShimCache): 保存された情報を解析するには、AppCompatCacheParser tool の使用が推奨されます](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** ファイルは、システム上で実行されたアプリケーションの詳細を記録するレジストリハイブです。通常、`C:\Windows\AppCompat\Programas\Amcache.hve` にあります。

このファイルには、最近実行されたプロセスの記録が保存されます。これには、実行可能ファイルへのパスや SHA1 ハッシュなどが含まれます。この情報は、システム上のアプリケーションの活動を追跡するうえで非常に有用です。

**Amcache.hve** からデータを抽出して分析するには、[**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool を使用できます。以下のコマンドは、AmcacheParser を使用して **Amcache.hve** ファイルの内容を解析し、結果を CSV 形式で出力する方法の例です：
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
生成された CSV ファイルの中でも、`Amcache_Unassociated file entries` は、unassociated file entries に関する豊富な情報を提供するため、特に注目に値します。

生成される最も興味深い CSV ファイルは `Amcache_Unassociated file entries` です。

### RecentFileCache

この artifact は W7 の `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` にのみ存在し、一部のバイナリの最近の実行に関する情報が含まれています。

ファイルの解析には [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) ツールを使用できます。

### Scheduled tasks

`C:\Windows\Tasks` または `C:\Windows\System32\Tasks` から抽出し、XML として読み取ることができます。

### Services

レジストリの `SYSTEM\ControlSet001\Services` にあります。何が実行されるか、またいつ実行されるかを確認できます。

### **Windows Store**

インストールされたアプリケーションは `\ProgramData\Microsoft\Windows\AppRepository\`\
にあります。

この repository には、データベース **`StateRepository-Machine.srd`** 内に、システムにインストールされた**各アプリケーション**の **log** があります。

このデータベースの Application table では、"Application ID"、"PackageNumber"、"Display Name" の列を確認できます。これらの列には、pre-installed およびインストール済みアプリケーションに関する情報が含まれており、インストールされたアプリケーションの ID は連番になっているはずなので、一部のアプリケーションがアンインストールされたかどうかを確認できます。

レジストリ パス `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
から**インストールされたアプリケーション**を確認することもできます。\
また、**アンインストールされた** **アプリケーション**は `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\` にあります。

## Windows Events

Windows events に表示される情報は次のとおりです。

- 発生した内容
- Timestamp (UTC + 0)
- 関係する Users
- 関係する Hosts (hostname、IP)
- アクセスされた Assets (files、folder、printer、services)

Logs は、Windows Vista より前では `C:\Windows\System32\config` に、Windows Vista 以降では `C:\Windows\System32\winevt\Logs` にあります。Windows Vista より前では event logs は binary format でしたが、それ以降は **XML format** で、**.evtx** 拡張子が使用されます。

event files の場所は、SYSTEM registry の **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** にあります。

Windows Event Viewer (**`eventvwr.msc`**) または [**Event Log Explorer**](https://eventlogxp.com) **や** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** などのツールで表示できます。**

## Windows Security Event Logging の理解

Access events は、`C:\Windows\System32\winevt\Security.evtx` にある security configuration file に記録されます。このファイルのサイズは調整可能で、容量に達すると古い events が上書きされます。記録される events には、user logins と logoffs、user actions、security settings の変更、さらに files、folders、shared assets へのアクセスが含まれます。

### User Authentication における主要な Event IDs:

- **EventID 4624**: User が正常に authentication されたことを示します。
- **EventID 4625**: authentication の失敗を示します。
- **EventIDs 4634/4647**: user logoff events を表します。
- **EventID 4672**: administrative privileges での login を示します。

#### EventID 4634/4647 内の Sub-types:

- **Interactive (2)**: User による直接の login。
- **Network (3)**: shared folders への access。
- **Batch (4)**: batch processes の実行。
- **Service (5)**: services の起動。
- **Proxy (6)**: proxy authentication。
- **Unlock (7)**: password による screen の unlock。
- **Network Cleartext (8)**: clear text password の送信。多くの場合 IIS から送信されます。
- **New Credentials (9)**: access に異なる credentials を使用。
- **Remote Interactive (10)**: Remote Desktop または terminal services による login。
- **Cache Interactive (11)**: domain controller に contact せず、cached credentials で login。
- **Cache Remote Interactive (12)**: cached credentials による remote login。
- **Cached Unlock (13)**: cached credentials による unlock。

#### EventID 4625 の Status および Sub Status Codes:

- **0xC0000064**: User name が存在しません - username enumeration attack を示している可能性があります。
- **0xC000006A**: 正しい user name ですが password が誤っています - password guessing または brute-force attempt の可能性があります。
- **0xC0000234**: User account が lockout されています - 複数の failed logins を伴う brute-force attack の後に発生する可能性があります。
- **0xC0000072**: Account が disabled です - disabled accounts への unauthorized attempts。
- **0xC000006F**: 許可された時間外の logon - 設定された login hours 外からの access attempt を示し、unauthorized access の兆候である可能性があります。
- **0xC0000070**: workstation restrictions への違反 - unauthorized location から login しようとした可能性があります。
- **0xC0000193**: Account の expiration - expired user accounts による access attempts。
- **0xC0000071**: Expired password - outdated passwords による login attempts。
- **0xC0000133**: Time sync issues - client と server 間の大きな時間差は、pass-the-ticket など、より高度な attacks を示している可能性があります。
- **0xC0000224**: Mandatory password change が必要 - 頻繁な mandatory changes は、account security を不安定化させようとする試みを示している可能性があります。
- **0xC0000225**: Security issue ではなく、system bug を示します。
- **0xC000015b**: Denied logon type - user が service logon など、許可されていない logon type で access を試みたことを示します。

#### EventID 4616:

- **Time Change**: system time の変更。events の timeline を隠すために使用される可能性があります。

#### EventID 6005 および 6006:

- **System Startup and Shutdown**: EventID 6005 は system の起動を示し、EventID 6006 は shutdown を示します。

#### EventID 1102:

- **Log Deletion**: Security logs が clear されたことを示します。これは illicit activities の隠蔽でよく見られる red flag です。

#### USB Device Tracking の EventIDs:

- **20001 / 20003 / 10000**: USB device の初回接続。
- **10100**: USB driver の更新。
- **EventID 112**: USB device が挿入された時刻。

これらの login types と credential dumping opportunities をシミュレートする実践的な例については、[Altered Security の詳細な guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them) を参照してください。

Event details には status および sub-status codes が含まれており、events の原因についてさらに詳しく知ることができます。特に Event ID 4625 で重要です。

### Windows Events の復元

削除された Windows Events を復元できる可能性を高めるには、対象 computer の電源を直接 unplugging して切ることが推奨されます。`.evtx` 拡張子を指定できる recovery tool **Bulk_extractor** を使用して、このような events の復元を試みることが推奨されます。

### Windows Events による一般的な Attacks の特定

Windows Event IDs を使用して一般的な cyber attacks を特定する方法については、[Red Team Recipe](https://redteamrecipe.com/event-codes/) の包括的な guide を参照してください。

#### Brute Force Attacks

複数の EventID 4625 records によって特定でき、attack が成功した場合は、その後に EventID 4624 が記録されます。

#### Time Change

EventID 4616 によって記録されます。system time の変更は forensic analysis を複雑にする可能性があります。

#### USB Device Tracking

USB device tracking に役立つ System EventIDs には、initial use 用の 20001/20003/10000、driver updates 用の 10100、挿入 timestamp 用の DeviceSetupManager の EventID 112 があります。

#### System Power Events

EventID 6005 は system startup を示し、EventID 6006 は shutdown を示します。

#### Log Deletion

Security EventID 1102 は logs の削除を示し、forensic analysis における重要な event です。

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
