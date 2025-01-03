# Windows アーティファクト

## Windows アーティファクト

{{#include ../../../banners/hacktricks-training.md}}

## 一般的な Windows アーティファクト

### Windows 10 通知

パス `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` には、データベース `appdb.dat`（Windows アニバーサリー前）または `wpndatabase.db`（Windows アニバーサリー後）があります。

この SQLite データベース内には、興味深いデータを含む可能性のあるすべての通知（XML 形式）の `Notification` テーブルがあります。

### タイムライン

タイムラインは、訪問したウェブページ、編集した文書、実行したアプリケーションの **時系列履歴** を提供する Windows の特徴です。

データベースは、パス `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` にあります。このデータベースは SQLite ツールまたはツール [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **を使用して開くことができ、2 つのファイルが生成され、ツール** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **で開くことができます。**

### ADS (代替データストリーム)

ダウンロードされたファイルには、**ADS Zone.Identifier** が含まれており、**どのように** インターネット、イントラネットなどから **ダウンロードされたか** を示しています。一部のソフトウェア（ブラウザなど）は、ファイルがダウンロードされた**URL**など、さらに**多くの** **情報**を提供することがよくあります。

## **ファイルバックアップ**

### ごみ箱

Vista/Win7/Win8/Win10 では、**ごみ箱**はドライブのルートにあるフォルダー **`$Recycle.bin`** にあります（`C:\$Recycle.bin`）。\
このフォルダー内でファイルが削除されると、2 つの特定のファイルが作成されます：

- `$I{id}`: ファイル情報（削除された日時）
- `$R{id}`: ファイルの内容

![](<../../../images/image (1029).png>)

これらのファイルがあれば、ツール [**Rifiuti**](https://github.com/abelcheung/rifiuti2) を使用して削除されたファイルの元のアドレスと削除された日時を取得できます（Vista – Win10 には `rifiuti-vista.exe` を使用）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### ボリュームシャドウコピー

シャドウコピーは、使用中のコンピュータファイルやボリュームの**バックアップコピー**やスナップショットを作成できるMicrosoft Windowsに含まれる技術です。

これらのバックアップは通常、ファイルシステムのルートから`\System Volume Information`にあり、名前は以下の画像に示されている**UID**で構成されています。

![](<../../../images/image (94).png>)

**ArsenalImageMounter**を使用してフォレンジックイメージをマウントすると、ツール[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html)を使用してシャドウコピーを検査し、シャドウコピーのバックアップから**ファイルを抽出**することもできます。

![](<../../../images/image (576).png>)

レジストリエントリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`には、**バックアップしない**ファイルとキーが含まれています。

![](<../../../images/image (254).png>)

レジストリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`にも、`ボリュームシャドウコピー`に関する構成情報が含まれています。

### Office自動保存ファイル

Officeの自動保存ファイルは次の場所にあります: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## シェルアイテム

シェルアイテムは、別のファイルにアクセスする方法に関する情報を含むアイテムです。

### 最近の文書 (LNK)

Windowsは、ユーザーが次の場所で**ファイルを開いたり、使用したり、作成したり**すると、これらの**ショートカット**を**自動的に****作成**します:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダーが作成されると、フォルダーへのリンク、親フォルダーへのリンク、および祖父フォルダーへのリンクも作成されます。

これらの自動的に作成されたリンクファイルは、**ファイル**か**フォルダー**か、**MAC** **タイム**、ファイルが保存されている**ボリューム情報**、および**ターゲットファイルのフォルダー**など、**起源に関する情報**を**含んでいます**。この情報は、ファイルが削除された場合にそれらを回復するのに役立ちます。

また、リンクファイルの**作成日**は、元のファイルが**最初に**使用された**時間**であり、リンクファイルの**最終更新日**は、元のファイルが使用された**最後の時間**です。

これらのファイルを検査するには、[**LinkParser**](http://4discovery.com/our-tools/)を使用できます。

このツールでは、**2セット**のタイムスタンプが見つかります:

- **最初のセット:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **2番目のセット:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

最初のセットのタイムスタンプは**ファイル自体のタイムスタンプ**を参照します。2番目のセットは**リンクされたファイルのタイムスタンプ**を参照します。

同じ情報は、Windows CLIツール[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)を実行することで取得できます。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
この場合、情報はCSVファイルに保存されます。

### ジャンプリスト

これらはアプリケーションごとに示される最近のファイルです。各アプリケーションでアクセスできる**アプリケーションによって使用された最近のファイルのリスト**です。これらは**自動的に作成されるか、カスタムで作成される**ことがあります。

自動的に作成された**ジャンプリスト**は`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`に保存されます。ジャンプリストは`{id}.autmaticDestinations-ms`という形式で名付けられ、最初のIDはアプリケーションのIDです。

カスタムジャンプリストは`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`に保存され、通常はファイルに**重要な**ことが起こったためにアプリケーションによって作成されます（お気に入りとしてマークされたかもしれません）。

任意のジャンプリストの**作成時間**は**ファイルが最初にアクセスされた時間**を示し、**修正時間は最後にアクセスされた時間**を示します。

ジャンプリストは[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)を使用して検査できます。

![](<../../../images/image (168).png>)

（_JumplistExplorerによって提供されるタイムスタンプは、ジャンプリストファイル自体に関連しています_）

### シェルバッグ

[**このリンクをフォローしてシェルバッグについて学んでください。**](interesting-windows-registry-keys.md#shellbags)

## Windows USBの使用

USBデバイスが使用されたことを特定することは、以下の作成によって可能です：

- Windows Recent Folder
- Microsoft Office Recent Folder
- ジャンプリスト

一部のLNKファイルは、元のパスを指すのではなく、WPDNSEフォルダーを指しています：

![](<../../../images/image (218).png>)

WPDNSEフォルダー内のファイルは元のファイルのコピーであり、PCの再起動では生き残らず、GUIDはシェルバッグから取得されます。

### レジストリ情報

[このページをチェックして](interesting-windows-registry-keys.md#usb-information) USB接続デバイスに関する興味深い情報を含むレジストリキーを学んでください。

### setupapi

USB接続が行われた時刻に関するタイムスタンプを取得するには、ファイル`C:\Windows\inf\setupapi.dev.log`を確認してください（`Section start`を検索）。

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)を使用して、画像に接続されたUSBデバイスに関する情報を取得できます。

![](<../../../images/image (452).png>)

### プラグアンドプレイのクリーンアップ

「プラグアンドプレイのクリーンアップ」として知られるスケジュールされたタスクは、主に古いドライバーバージョンの削除を目的としています。最新のドライバーパッケージバージョンを保持するという指定された目的とは対照的に、オンラインソースは、30日間非アクティブなドライバーも対象にしていることを示唆しています。したがって、過去30日間接続されていないリムーバブルデバイスのドライバーは削除される可能性があります。

タスクは次のパスにあります：`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

タスクの内容を示すスクリーンショットが提供されています： ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**タスクの主要コンポーネントと設定：**

- **pnpclean.dll**：このDLLは実際のクリーンアッププロセスを担当します。
- **UseUnifiedSchedulingEngine**：`TRUE`に設定されており、一般的なタスクスケジューリングエンジンの使用を示します。
- **MaintenanceSettings**：
- **Period ('P1M')**：タスクスケジューラに、定期的な自動メンテナンス中に毎月クリーンアップタスクを開始するよう指示します。
- **Deadline ('P2M')**：タスクスケジューラに、タスクが2か月連続して失敗した場合、緊急自動メンテナンス中にタスクを実行するよう指示します。

この構成により、ドライバーの定期的なメンテナンスとクリーンアップが確保され、連続して失敗した場合のタスクの再試行のための規定が設けられています。

**詳細については次を確認してください：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## メール

メールには**2つの興味深い部分があります：ヘッダーとメールの内容**。**ヘッダー**には次のような情報が含まれています：

- **誰が**メールを送信したか（メールアドレス、IP、メールサーバーがリダイレクトしたメール）
- **いつ**メールが送信されたか

また、`References`および`In-Reply-To`ヘッダー内にはメッセージのIDが含まれています：

![](<../../../images/image (593).png>)

### Windowsメールアプリ

このアプリケーションは、メールをHTMLまたはテキストで保存します。メールは`Users\<username>\AppData\Local\Comms\Unistore\data\3\`内のサブフォルダーにあります。メールは`.dat`拡張子で保存されます。

メールの**メタデータ**と**連絡先**は、**EDBデータベース**内にあります：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

ファイルの拡張子を`.vol`から`.edb`に変更すると、ツール[**ESEDatabaseView**](https://www.nirsoft.net/utils/ese_database_view.html)を使用して開くことができます。`Message`テーブル内でメールを見ることができます。

### Microsoft Outlook

ExchangeサーバーまたはOutlookクライアントが使用されると、いくつかのMAPIヘッダーが存在します：

- `Mapi-Client-Submit-Time`：メールが送信されたときのシステムの時間
- `Mapi-Conversation-Index`：スレッドの子メッセージの数と各メッセージのタイムスタンプ
- `Mapi-Entry-ID`：メッセージ識別子。
- `Mappi-Message-Flags`および`Pr_last_Verb-Executed`：MAPIクライアントに関する情報（メッセージは読まれたか？未読か？応答されたか？リダイレクトされたか？不在か？）

Microsoft Outlookクライアントでは、送信/受信されたすべてのメッセージ、連絡先データ、およびカレンダーデータは、次の場所にあるPSTファイルに保存されます：

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook`（WinXP）
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`は、使用されているファイルを示します。

PSTファイルは、ツール[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)を使用して開くことができます。

![](<../../../images/image (498).png>)

### Microsoft Outlook OSTファイル

**OSTファイル**は、Microsoft Outlookが**IMAP**または**Exchange**サーバーで構成されているときに生成され、PSTファイルと同様の情報を保存します。このファイルはサーバーと同期され、**過去12か月間**のデータを保持し、**最大サイズは50GB**で、PSTファイルと同じディレクトリにあります。OSTファイルを表示するには、[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)を利用できます。

### 添付ファイルの取得

失われた添付ファイルは、以下から回復可能かもしれません：

- **IE10**の場合：`%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11以降**の場合：`%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOXファイル

**Thunderbird**は**MBOXファイル**を使用してデータを保存し、`Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`にあります。

### 画像サムネイル

- **Windows XPおよび8-8.1**：サムネイルを含むフォルダーにアクセスすると、削除後も画像プレビューを保存する`thumbs.db`ファイルが生成されます。
- **Windows 7/10**：UNCパスを介してネットワーク上でアクセスすると`thumbs.db`が作成されます。
- **Windows Vista以降**：サムネイルプレビューは`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`に集中管理され、**thumbcache_xxx.db**という名前のファイルが作成されます。[**Thumbsviewer**](https://thumbsviewer.github.io)および[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)は、これらのファイルを表示するためのツールです。

### Windowsレジストリ情報

Windowsレジストリは、広範なシステムおよびユーザー活動データを保存し、次のファイルに含まれています：

- `%windir%\System32\Config`は、さまざまな`HKEY_LOCAL_MACHINE`サブキー用です。
- `%UserProfile%{User}\NTUSER.DAT`は、`HKEY_CURRENT_USER`用です。
- Windows Vista以降のバージョンでは、`HKEY_LOCAL_MACHINE`レジストリファイルが`%Windir%\System32\Config\RegBack\`にバックアップされます。
- さらに、プログラム実行情報は、Windows VistaおよびWindows 2008 Server以降の`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`に保存されます。

### ツール

レジストリファイルを分析するために役立つツールがいくつかあります：

- **レジストリエディタ**：Windowsにインストールされています。現在のセッションのWindowsレジストリをナビゲートするためのGUIです。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：レジストリファイルをロードし、GUIでナビゲートすることができます。また、興味深い情報を持つキーをハイライトするブックマークも含まれています。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：再び、ロードされたレジストリをナビゲートできるGUIを持ち、ロードされたレジストリ内の興味深い情報をハイライトするプラグインも含まれています。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：レジストリから重要な情報を抽出できる別のGUIアプリケーションです。

### 削除された要素の回復

キーが削除されると、そのようにマークされますが、占有しているスペースが必要になるまで削除されません。したがって、**Registry Explorer**のようなツールを使用すると、これらの削除されたキーを回復することが可能です。

### 最終書き込み時間

各キー-値には、**最後に修正された時間**を示す**タイムスタンプ**が含まれています。

### SAM

ファイル/ハイブ**SAM**には、システムの**ユーザー、グループ、およびユーザーパスワード**のハッシュが含まれています。

`SAM\Domains\Account\Users`で、ユーザー名、RID、最終ログイン、最終失敗ログオン、ログインカウンター、パスワードポリシー、およびアカウントが作成された時期を取得できます。**ハッシュ**を取得するには、ファイル/ハイブ**SYSTEM**も**必要**です。

### Windowsレジストリの興味深いエントリ

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## 実行されたプログラム

### 基本的なWindowsプロセス

[この投稿](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)では、疑わしい動作を検出するための一般的なWindowsプロセスについて学ぶことができます。

### Windows Recent APPs

レジストリ`NTUSER.DAT`内のパス`Software\Microsoft\Current Version\Search\RecentApps`には、**実行されたアプリケーション**、**最後に実行された時間**、および**起動された回数**に関する情報を含むサブキーがあります。

### BAM（バックグラウンドアクティビティモデレーター）

レジストリエディタで`SYSTEM`ファイルを開き、パス`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`内で、**各ユーザーによって実行されたアプリケーション**に関する情報（パス内の`{SID}`に注意）と**実行された時間**を見つけることができます（時間はレジストリのデータ値内にあります）。

### Windowsプリフェッチ

プリフェッチは、コンピュータがユーザーが**近い将来にアクセスする可能性のあるコンテンツを表示するために必要なリソースを静かに**取得することを可能にする技術です。これにより、リソースに迅速にアクセスできるようになります。

Windowsプリフェッチは、**実行されたプログラムのキャッシュを作成**して、より迅速にロードできるようにします。これらのキャッシュは、パス`C:\Windows\Prefetch`内に`.pf`ファイルとして作成されます。XP/VISTA/WIN7では128ファイル、Win8/Win10では1024ファイルの制限があります。

ファイル名は`{program_name}-{hash}.pf`として作成されます（ハッシュは実行可能ファイルのパスと引数に基づいています）。W10では、これらのファイルは圧縮されています。ファイルの存在は、**プログラムが実行された**ことを示しています。

ファイル`C:\Windows\Prefetch\Layout.ini`には、**プリフェッチされたファイルのフォルダーの名前**が含まれています。このファイルには、**実行回数**、**実行日**、および**プログラムによって**開かれた**ファイルに関する情報が含まれています。

これらのファイルを検査するには、ツール[**PEcmd.exe**](https://github.com/EricZimmerman/PECmd)を使用できます。
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch**は、次に読み込まれるものを予測することによって**プログラムをより速く読み込む**という同じ目的を持っています。しかし、これはprefetchサービスの代わりにはなりません。\
このサービスは、`C:\Windows\Prefetch\Ag*.db`にデータベースファイルを生成します。

これらのデータベースには、**プログラム**の**名前**、**実行回数**、**開かれたファイル**、**アクセスされたボリューム**、**完全なパス**、**時間枠**、および**タイムスタンプ**が含まれています。

この情報には、ツール[**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/)を使用してアクセスできます。

### SRUM

**System Resource Usage Monitor** (SRUM)は、**プロセスによって消費されるリソース**を**監視**します。これはW8で登場し、`C:\Windows\System32\sru\SRUDB.dat`にESEデータベースとしてデータを保存します。

以下の情報を提供します：

- AppIDとパス
- プロセスを実行したユーザー
- 送信バイト
- 受信バイト
- ネットワークインターフェース
- 接続の持続時間
- プロセスの持続時間

この情報は60分ごとに更新されます。

このファイルから日付を取得するには、ツール[**srum_dump**](https://github.com/MarkBaggett/srum-dump)を使用できます。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**、別名 **ShimCache** は、**Microsoft** によって開発された **Application Compatibility Database** の一部であり、アプリケーションの互換性の問題に対処します。このシステムコンポーネントは、さまざまなファイルメタデータを記録します。これには以下が含まれます：

- ファイルのフルパス
- ファイルのサイズ
- **$Standard_Information** (SI) の最終変更時間
- ShimCache の最終更新時間
- プロセス実行フラグ

このデータは、オペレーティングシステムのバージョンに基づいて特定の場所にレジストリ内に保存されます：

- XPの場合、データは `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` に保存され、96エントリの容量があります。
- Server 2003 および Windows バージョン 2008、2012、2016、7、8、10 の場合、ストレージパスは `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` であり、それぞれ512および1024エントリを収容します。

保存された情報を解析するには、[**AppCompatCacheParser** tool](https://github.com/EricZimmerman/AppCompatCacheParser) の使用が推奨されます。

![](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** ファイルは、システム上で実行されたアプリケーションの詳細を記録するレジストリハイブです。通常、`C:\Windows\AppCompat\Programas\Amcache.hve` にあります。

このファイルは、最近実行されたプロセスの記録を保存することで注目されており、実行可能ファイルへのパスやその SHA1 ハッシュが含まれています。この情報は、システム上のアプリケーションの活動を追跡するために非常に貴重です。

**Amcache.hve** からデータを抽出して分析するには、[**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) ツールを使用できます。以下のコマンドは、AmcacheParser を使用して **Amcache.hve** ファイルの内容を解析し、結果を CSV 形式で出力する方法の例です：
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
生成されたCSVファイルの中で、`Amcache_Unassociated file entries`は、関連付けのないファイルエントリに関する豊富な情報を提供するため、特に注目に値します。

最も興味深いCVSファイルは、`Amcache_Unassociated file entries`です。

### RecentFileCache

このアーティファクトは、W7の`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`にのみ存在し、いくつかのバイナリの最近の実行に関する情報を含んでいます。

ファイルを解析するには、ツール[**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)を使用できます。

### スケジュールされたタスク

これらは`C:\Windows\Tasks`または`C:\Windows\System32\Tasks`から抽出でき、XMLとして読み取ることができます。

### サービス

これらはレジストリの`SYSTEM\ControlSet001\Services`にあります。何が実行されるか、いつ実行されるかを見ることができます。

### **Windows Store**

インストールされたアプリケーションは、`\ProgramData\Microsoft\Windows\AppRepository\`にあります。このリポジトリには、データベース**`StateRepository-Machine.srd`**内に**システム内の各アプリケーションの**ログがあります。

このデータベースのアプリケーションテーブル内には、「Application ID」、「PackageNumber」、「Display Name」という列があり、これらの列には、プレインストールされたアプリケーションとインストールされたアプリケーションに関する情報が含まれています。また、インストールされたアプリケーションのIDは連続している必要があるため、いくつかのアプリケーションがアンインストールされたかどうかを確認できます。

インストールされたアプリケーションは、レジストリパス`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`内でも見つけることができます。また、アンインストールされたアプリケーションは、`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`にあります。

## Windowsイベント

Windowsイベントに表示される情報は次のとおりです：

- 何が起こったか
- タイムスタンプ（UTC + 0）
- 関与したユーザー
- 関与したホスト（ホスト名、IP）
- アクセスされた資産（ファイル、フォルダー、プリンター、サービス）

ログは、Windows Vista以前は`C:\Windows\System32\config`にあり、Windows Vista以降は`C:\Windows\System32\winevt\Logs`にあります。Windows Vista以前は、イベントログはバイナリ形式であり、以降は**XML形式**で、**.evtx**拡張子を使用しています。

イベントファイルの場所は、SYSTEMレジストリの**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**で見つけることができます。

これらはWindowsイベントビューア（**`eventvwr.msc`**）または[**Event Log Explorer**](https://eventlogxp.com) **または** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**を使用して視覚化できます。

## Windowsセキュリティイベントログの理解

アクセスイベントは、`C:\Windows\System32\winevt\Security.evtx`にあるセキュリティ構成ファイルに記録されます。このファイルのサイズは調整可能で、容量に達すると古いイベントが上書きされます。記録されたイベントには、ユーザーログインとログオフ、ユーザーアクション、セキュリティ設定の変更、ファイル、フォルダー、および共有資産へのアクセスが含まれます。

### ユーザー認証のための主要なイベントID：

- **EventID 4624**：ユーザーが正常に認証されたことを示します。
- **EventID 4625**：認証の失敗を示します。
- **EventIDs 4634/4647**：ユーザーログオフイベントを表します。
- **EventID 4672**：管理者権限でのログインを示します。

#### EventID 4634/4647内のサブタイプ：

- **インタラクティブ (2)**：直接ユーザーログイン。
- **ネットワーク (3)**：共有フォルダーへのアクセス。
- **バッチ (4)**：バッチプロセスの実行。
- **サービス (5)**：サービスの起動。
- **プロキシ (6)**：プロキシ認証。
- **ロック解除 (7)**：パスワードで画面がロック解除されました。
- **ネットワーククリアテキスト (8)**：クリアテキストパスワードの送信、通常はIISから。
- **新しい資格情報 (9)**：アクセスのために異なる資格情報を使用。
- **リモートインタラクティブ (10)**：リモートデスクトップまたはターミナルサービスのログイン。
- **キャッシュインタラクティブ (11)**：ドメインコントローラーに連絡せずにキャッシュされた資格情報でログイン。
- **キャッシュリモートインタラクティブ (12)**：キャッシュされた資格情報でのリモートログイン。
- **キャッシュロック解除 (13)**：キャッシュされた資格情報でのロック解除。

#### EventID 4625のステータスおよびサブステータスコード：

- **0xC0000064**：ユーザー名が存在しない - ユーザー名列挙攻撃を示す可能性があります。
- **0xC000006A**：正しいユーザー名だがパスワードが間違っている - パスワード推測またはブルートフォース攻撃の可能性。
- **0xC0000234**：ユーザーアカウントがロックアウトされました - 複数の失敗したログインの結果としてブルートフォース攻撃が続く可能性があります。
- **0xC0000072**：アカウントが無効 - 無効なアカウントへの不正アクセスの試み。
- **0xC000006F**：許可された時間外のログオン - 設定されたログイン時間外のアクセスの試みを示し、不正アクセスの可能性があります。
- **0xC0000070**：ワークステーション制限の違反 - 不正な場所からのログインの試みの可能性があります。
- **0xC0000193**：アカウントの有効期限切れ - 有効期限切れのユーザーアカウントへのアクセスの試み。
- **0xC0000071**：パスワードの有効期限切れ - 古いパスワードでのログインの試み。
- **0xC0000133**：時間同期の問題 - クライアントとサーバー間の大きな時間の不一致は、パス・ザ・チケットのようなより高度な攻撃を示す可能性があります。
- **0xC0000224**：必須のパスワード変更が必要 - 頻繁な必須変更は、アカウントセキュリティを不安定にしようとする試みを示唆するかもしれません。
- **0xC0000225**：セキュリティの問題ではなく、システムバグを示します。
- **0xC000015b**：拒否されたログオンタイプ - サービスログオンを実行しようとするユーザーなど、不正なログオンタイプでのアクセスの試み。

#### EventID 4616：

- **時間変更**：システム時間の変更、イベントのタイムラインを隠す可能性があります。

#### EventID 6005および6006：

- **システムの起動とシャットダウン**：EventID 6005はシステムの起動を示し、EventID 6006はシャットダウンを示します。

#### EventID 1102：

- **ログ削除**：セキュリティログがクリアされることは、違法行為を隠蔽するための赤信号です。

#### USBデバイストラッキングのためのイベントID：

- **20001 / 20003 / 10000**：USBデバイスの最初の接続。
- **10100**：USBドライバーの更新。
- **EventID 112**：USBデバイス挿入の時間。

これらのログインタイプや資格情報ダンプの機会をシミュレートする実用的な例については、[Altered Securityの詳細ガイド](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)を参照してください。

イベントの詳細、ステータスおよびサブステータスコードは、特にEvent ID 4625でのイベントの原因に関するさらなる洞察を提供します。

### Windowsイベントの回復

削除されたWindowsイベントを回復する可能性を高めるために、疑わしいコンピュータの電源を直接抜いてシャットダウンすることをお勧めします。**Bulk_extractor**は、`.evtx`拡張子を指定する回復ツールで、これらのイベントを回復しようとする際に推奨されます。

### Windowsイベントを通じて一般的な攻撃を特定する

一般的なサイバー攻撃を特定するためにWindowsイベントIDを利用する包括的なガイドについては、[Red Team Recipe](https://redteamrecipe.com/event-codes/)を訪れてください。

#### ブルートフォース攻撃

複数のEventID 4625レコードによって識別され、攻撃が成功した場合はEventID 4624が続きます。

#### 時間変更

EventID 4616によって記録され、システム時間の変更はフォレンジック分析を複雑にする可能性があります。

#### USBデバイストラッキング

USBデバイストラッキングに役立つシステムイベントIDには、初回使用のための20001/20003/10000、ドライバー更新のための10100、挿入タイムスタンプのためのEventID 112が含まれます。

#### システム電源イベント

EventID 6005はシステムの起動を示し、EventID 6006はシャットダウンを示します。

#### ログ削除

セキュリティEventID 1102はログの削除を示し、フォレンジック分析にとって重要なイベントです。

{{#include ../../../banners/hacktricks-training.md}}
