# Windows Artifacts

## Windows Artifacts

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 一般的なWindows Artifacts

### Windows 10 通知

パス`\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`には、データベース`appdb.dat`（Windows記念日前）または`wpndatabase.db`（Windows記念日後）が見つかります。

このSQLiteデータベース内には、興味深いデータを含む可能性があるすべての通知（XML形式）を含む`Notification`テーブルがあります。

### タイムライン

タイムラインは、訪問したWebページ、編集されたドキュメント、実行されたアプリケーションの**時系列の履歴**を提供するWindowsの特徴です。

データベースはパス`\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`にあります。このデータベースはSQLiteツールで開くことも、ツール[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)を使用して生成された2つのファイルをツール[**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md)で開くこともできます。

### ADS (Alternate Data Streams)

ダウンロードされたファイルには、イントラネット、インターネットなどから**ダウンロードされた方法**を示す**ADS Zone.Identifier**が含まれている場合があります。一部のソフトウェア（ブラウザなど）は、ファイルがダウンロードされた**URL**など、さらに**多くの情報**を通常置きます。

## **ファイルバックアップ**

### ゴミ箱

Vista/Win7/Win8/Win10では、**ゴミ箱**はドライブのルート（`C:\$Recycle.bin`）のフォルダー**`$Recycle.bin`**で見つけることができます。\
このフォルダーでファイルが削除されると、2つの特定のファイルが作成されます：

* `$I{id}`: ファイル情報（削除された日付）
* `$R{id}`: ファイルの内容

![](<../../../.gitbook/assets/image (486).png>)

これらのファイルを持っている場合、ツール[**Rifiuti**](https://github.com/abelcheung/rifiuti2)を使用して、削除されたファイルの元のアドレスと削除された日付を取得できます（Vista – Win10の場合は`rifiuti-vista.exe`を使用）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
```markdown
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### ボリューム シャドウ コピー

シャドウ コピーは、使用中であってもコンピュータ ファイルやボリュームの**バックアップ コピー**またはスナップショットを作成できる、Microsoft Windowsに含まれる技術です。

これらのバックアップは通常、ファイル システムのルートから `\System Volume Information` に位置しており、名前は以下の画像に示されている**UID**で構成されています：

![](<../../../.gitbook/assets/image (520).png>)

**ArsenalImageMounter**でフォレンジック イメージをマウントすると、[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) ツールを使用してシャドウ コピーを検査し、シャドウ コピー バックアップから**ファイルを抽出**することもできます。

![](<../../../.gitbook/assets/image (521).png>)

レジストリ エントリ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` には、**バックアップしない**ファイルとキーが含まれています：

![](<../../../.gitbook/assets/image (522).png>)

レジストリ `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` にも `Volume Shadow Copies` に関する設定情報が含まれています。

### Office 自動保存ファイル

Officeの自動保存ファイルは次の場所にあります： `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## シェル アイテム

シェル アイテムは、別のファイルにアクセスする方法に関する情報を含むアイテムです。

### 最近使ったドキュメント (LNK)

Windowsは、ユーザーがファイルを**開く、使用する、または作成する**ときに、以下の場所にこれらの**ショートカット**を**自動的に作成**します：

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダが作成されると、そのフォルダ、親フォルダ、および祖父母フォルダへのリンクも作成されます。

これらの自動的に作成されたリンクファイルには、それが**ファイル**か**フォルダ**か、そのファイルの**MAC** **タイム**、ファイルが保存されている**ボリューム情報**、および**ターゲットファイルのフォルダ**に関する情報が含まれています。この情報は、削除された場合にそれらのファイルを回復するのに役立つ可能性があります。

また、リンクファイルの**作成日**は元のファイルが**初めて使用された時**、リンクファイルの**変更日**は元のファイルが最後に使用された**時**です。

これらのファイルを検査するには、[**LinkParser**](http://4discovery.com/our-tools/)を使用できます。

このツールでは、タイムスタンプの**2セット**が見つかります：

* **第一セット:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **第二セット:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

第一セットのタイムスタンプは**ファイル自体のタイムスタンプ**を参照します。第二セットは**リンクされたファイルのタイムスタンプ**を参照します。

同じ情報を取得するには、Windows CLIツール：[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)を実行します。
```
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
```markdown
この情報はCSVファイル内に保存されます。

### Jumplists

これらは、アプリケーションごとに示される最近使用したファイルです。**アプリケーションによって使用された最近のファイルのリスト**で、各アプリケーションでアクセスできます。**自動的に作成されるか、カスタムで作成される**ことがあります。

自動的に作成される**jumplists**は`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`に保存されます。jumplistsは`{id}.autmaticDestinations-ms`という形式で名付けられ、初期IDはアプリケーションのIDです。

カスタムjumplistsは`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`に保存され、通常はファイルに何か**重要な**ことが起こったとき（お気に入りとしてマークされた場合など）にアプリケーションによって作成されます。

jumplistの**作成時間**は**ファイルが初めてアクセスされた時間**を示し、**変更時間は最後にアクセスされた時間**です。

[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)を使用してjumplistsを調査できます。

![](<../../../.gitbook/assets/image (474).png>)

(_JumplistExplorerによって提供されるタイムスタンプはjumplistファイル自体に関連していることに注意してください_)

### Shellbags

[**このリンクをたどってshellbagsについて学びましょう。**](interesting-windows-registry-keys.md#shellbags)

## Windows USBの使用

USBデバイスが使用されたことを以下の作成によって特定できます：

* Windows Recent Folder
* Microsoft Office Recent Folder
* Jumplists

LNKファイルが元のパスを指している代わりにWPDNSEフォルダを指していることに注意してください：

![](<../../../.gitbook/assets/image (476).png>)

WPDNSEフォルダ内のファイルは元のファイルのコピーであり、PCの再起動には耐えられず、GUIDはshellbagから取得されます。

### レジストリ情報

[このページをチェックして](interesting-windows-registry-keys.md#usb-information) USB接続デバイスに関する興味深い情報を含むレジストリキーを学びましょう。

### setupapi

`C:\Windows\inf\setupapi.dev.log`ファイルをチェックして、USB接続が行われたタイムスタンプを取得します（`Section start`を検索）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)を使用して、イメージに接続されたUSBデバイスに関する情報を取得できます。

![](<../../../.gitbook/assets/image (483).png>)

### Plug and Play Cleanup

「Plug and Play Cleanup」として知られるスケジュールされたタスクは、主に古いドライババージョンの削除を目的として設計されています。最新のドライバパッケージバージョンを保持するという指定された目的に反して、オンラインソースは30日間非アクティブだったドライバも対象になることを示唆しています。したがって、過去30日間接続されていない取り外し可能なデバイスのドライバは削除される可能性があります。

タスクは次のパスにあります：
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

タスクの内容を示すスクリーンショットが提供されています：
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**タスクの主要なコンポーネントと設定：**
- **pnpclean.dll**: 実際のクリーンアッププロセスを担当するDLLです。
- **UseUnifiedSchedulingEngine**: `TRUE`に設定されており、汎用タスクスケジューリングエンジンの使用を示しています。
- **MaintenanceSettings**:
- **Period ('P1M')**: タスクスケジューラに、通常の自動メンテナンス中に毎月クリーンアップタスクを開始するよう指示します。
- **Deadline ('P2M')**: タスクが2か月連続で失敗した場合、タスクスケジューラに緊急自動メンテナンス中にタスクを実行するよう指示します。

この設定は、ドライバの定期的なメンテナンスとクリーンアップを保証し、連続して失敗した場合にタスクを再試行するための措置を提供します。

**詳細については、次をチェックしてください：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## メール

メールには**2つの興味深い部分があります：ヘッダーとメールの内容**です。**ヘッダー**内では、以下の情報を見つけることができます：

* **誰が**メールを送ったか（メールアドレス、IP、メールを転送したメールサーバー）
* **いつ**メールが送信されたか

また、`References`と`In-Reply-To`ヘッダー内では、メッセージのIDを見つけることができます：

![](<../../../.gitbook/assets/image (484).png>)

### Windows Mail App

このアプリケーションはメールをHTMLまたはテキストで保存します。メールは`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`内のサブフォルダ内に見つけることができます。メールは`.dat`拡張子で保存されます。

メールの**メタデータ**と**連絡先**は**EDBデータベース**内にあります：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

ファイルの拡張子を`.vol`から`.edb`に**変更**し、[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)ツールを使用して開きます。`Message`テーブル内でメールを見ることができます。

### Microsoft Outlook

ExchangeサーバーまたはOutlookクライアントが使用されている場合、いくつかのMAPIヘッダーが存在します：

* `Mapi-Client-Submit-Time`: メールが送信されたときのシステムの時間
* `Mapi-Conversation-Index`: スレッドの子メッセージの数とスレッドの各メッセージのタイムスタンプ
* `Mapi-Entry-ID`: メッセージ識別子。
* `Mappi-Message-Flags`と`Pr_last_Verb-Executed`: MAPIクライアントに関する情報（メッセージは読まれたか？読まれていないか？返信されたか？転送されたか？不在中か？）

Microsoft Outlookクライアントでは、送受信されたすべてのメッセージ、連絡先データ、カレンダーデータがPSTファイルに保存されています：

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`は使用中のファイルを示しています。

[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)ツールを使用してPSTファイルを開くことができます。

![](<../../../.gitbook/assets/image (485).png>)

### Outlook OST

Microsoft Outlookが**IMAP**を使用して設定されている場合、または**Exchange**サーバーを使用している場合、ほぼ同じ情報をPSTファイルとして保存する**OST**ファイルを生成します。ファイルはサーバーと**過去12ヶ月間**同期され、**最大ファイルサイズは50GB**で、PSTファイルが保存されている**同じフォルダ**にあります。このファイルは[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)を使用して調査できます。

### 添付ファイルの回復

以下のフォルダで見つけることができるかもしれません：

* `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
* `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird**は情報を**MBOX** **ファイル**に保存し、`\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`フォルダ内にあります。

## サムネイル

ユーザーがフォルダにアクセスしてサムネイルを使用して整理すると、`thumbs.db`ファイルが作成されます。このdbは、削除されたとしてもフォルダの画像の**サムネイルを保存**します。WinXPおよびWin 8-8.1ではこのファイルは自動的に作成されます。Win7/Win10では、UNCパス（\IP\folder...）経由でアクセスされた場合に自動的に作成されます。

このファイルは[**Thumbsviewer**](https://thumbsviewer.github.io)ツールで読むことができます。

### Thumbcache

Windows Vista以降、**サムネイルプレビューはシステム上の中央の場所に保存されます**。これにより、システムは画像の場所に関係なく画像にアクセスでき、Thumbs.dbファイルの局所性に関する問題に対処します。キャッシュは**`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`**にいくつかのファイルとして保存され、**thumbcache\_xxx.db**（サイズ別に番号付け）としてラベル付けされたファイルと、各サイズのデータベース内のサムネイルを見つけるために使用されるインデックスがあります。

* Thumbcache\_32.db -> 小さい
* Thumbcache\_96.db -> 中
* Thumbcache\_256.db -> 大
* Thumbcache\_1024.db -> 特大

このファイルは[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)を使用して読むことができます。

## Windowsレジストリ

Windowsレジストリには、**システムとユーザーの行動に関する多くの情報**が含まれています。

レジストリを含むファイルは以下の場所にあります：

* %windir%\System32\Config\*_SAM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SECURITY\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SYSTEM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SOFTWARE\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_DEFAULT\*_: `HKEY_LOCAL_MACHINE`
* %UserProfile%{User}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

Windows VistaおよびWindows 2008 Server以降では、`HKEY_LOCAL_MACHINE`レジストリファイルのバックアップが**`%Windir%\System32\Config\RegBack\`**にあります。

また、これらのバージョンから、レジストリファイル**`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`**が作成され、プログラム実行に関する情報が保存されます。

### ツール

レジストリファイルを分析するのに役立つツールがいくつかあります：

* **レジストリエディタ**: Windowsにインストールされています。現在のセッションのWindowsレジストリをGUIでナビゲートするためのものです。
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): レジストリファイルをロードしてGUIでナビゲートすることができます。興味深い情報をハイライトするブックマークも含まれています。
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): GUIを持ち、ロードされたレジストリをナビゲートすることができ、ロードされたレジストリ内の興味深い情報をハイライトするプラグインも含まれています。
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): ロードされたレジストリから重要な情報を抽出することができる別のGUIアプリケーションです。

### 削除された要素の回復

キーが削除されるとそのようにマークされますが、そのスペースが必要になるまで削除されません。したがって、**Registry Explorer**のようなツールを使用して、これらの削除されたキーを回復することが可能です。

### 最終書き込み時間

各キー値には、最後に変更された時間を示す**タイムスタンプ**が含まれています。

### SAM

ファイル/ハイブ**SAM**には、システムの**ユーザー、グループ、およびユーザーパスワード**ハッシュが含まれています。

`SAM\Domains\Account\Users`で、ユーザー名、
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
```markdown
![](<../../../.gitbook/assets/image (487).png>)

### スーパープリフェッチ

**スーパープリフェッチ**は、次にロードされるものを予測することで、**プログラムをより速くロードする**ことを目的としています。しかし、プリフェッチサービスを置き換えるものではありません。
このサービスは `C:\Windows\Prefetch\Ag*.db` にデータベースファイルを生成します。

これらのデータベースには、**プログラム**の**名前**、**実行**の**回数**、**開かれた** **ファイル**、**アクセスされた** **ボリューム**、**完全な** **パス**、**時間枠**、**タイムスタンプ**が含まれています。

この情報には、ツール [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) を使用してアクセスできます。

### SRUM

**システムリソース使用モニター** (SRUM) は、プロセスによって**消費される** **リソース**を**監視**します。これはW8で登場し、データは `C:\Windows\System32\sru\SRUDB.dat` にあるESEデータベースに保存されます。

以下の情報を提供します：

* AppIDとパス
* プロセスを実行したユーザー
* 送信バイト数
* 受信バイト数
* ネットワークインターフェース
* 接続期間
* プロセス期間

この情報は60分ごとに更新されます。

このファイルからデータを取得するには、ツール [**srum\_dump**](https://github.com/MarkBaggett/srum-dump) を使用できます。
```
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**Shimcache**、または **AppCompatCache** は、**Microsoft** によって作成された **アプリケーション互換性データベース** の一部で、オペレーティングシステムがアプリケーションの互換性問題を識別するために使用されます。

キャッシュは、オペレーティングシステムに応じて様々なファイルメタデータを保存します。例えば：

* ファイルの完全なパス
* ファイルサイズ
* **$Standard\_Information** (SI) 最終変更時間
* ShimCache 最終更新時間
* プロセス実行フラグ

この情報はレジストリ内にあります：

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
* XP (96 エントリ)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
* Server 2003 (512 エントリ)
* 2008/2012/2016 Win7/Win8/Win10 (1024 エントリ)

この情報を解析するには、ツール [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) を使用できます。

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve** ファイルは、実行されたアプリケーションの情報を保存するレジストリファイルです。`C:\Windows\AppCompat\Programas\Amcache.hve` に位置しています。

**Amcache.hve** は、実行された最近のプロセスを記録し、実行されたファイルのパスをリストアップします。これを使用して、実行されたプログラムを見つけることができます。また、プログラムの SHA1 も記録します。

この情報を解析するには、ツール [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser) を使用できます。
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
最も興味深いCVSファイルは、`Amcache_Unassociated file entries`です。

### RecentFileCache

このアーティファクトはW7の`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`で見つけることができ、最近実行されたいくつかのバイナリに関する情報が含まれています。

ファイルを解析するために、[**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)ツールを使用できます。

### スケジュールされたタスク

これらは`C:\Windows\Tasks`または`C:\Windows\System32\Tasks`から抽出でき、XMLとして読むことができます。

### サービス

これらはレジストリの`SYSTEM\ControlSet001\Services`下で見つけることができます。何が実行されるか、いつ実行されるかを確認できます。

### **Windows Store**

インストールされたアプリケーションは`\ProgramData\Microsoft\Windows\AppRepository\`にあります。\
このリポジトリには、データベース**`StateRepository-Machine.srd`**内のシステムにインストールされた**各アプリケーション**に関する**ログ**があります。

このデータベースのアプリケーションテーブル内では、"Application ID"、"PackageNumber"、"Display Name"の列を見つけることができます。これらの列には、プリインストールされたアプリケーションとインストールされたアプリケーションに関する情報が含まれており、インストールされたアプリケーションのIDは連続しているはずなので、アンインストールされたアプリケーションがあるかどうかを確認できます。

また、レジストリパス`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`内で**インストールされたアプリケーション**を**見つける**ことができます。\
そして、`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`で**アンインストールされた** **アプリケーション**を見つけることができます。

## Windowsイベント

Windowsイベント内に表示される情報は以下の通りです：

* 何が起こったか
* タイムスタンプ（UTC + 0）
* 関与したユーザー
* 関与したホスト（ホスト名、IP）
* アクセスされたアセット（ファイル、フォルダ、プリンター、サービス）

ログはWindows Vista以前では`C:\Windows\System32\config`に、Windows Vista以降では`C:\Windows\System32\winevt\Logs`に位置しています。Windows Vista以前ではイベントログはバイナリ形式で、それ以降は**XML形式**を使用し、**.evtx**拡張子を使用します。

イベントファイルの場所はSYSTEMレジストリの**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**で見つけることができます。

Windowsイベントビューア（**`eventvwr.msc`**）または[**Event Log Explorer**](https://eventlogxp.com) **や** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**などの他のツールから視覚化できます。**

### セキュリティ

これはアクセスイベントを記録し、`C:\Windows\System32\winevt\Security.evtx`で見つけることができるセキュリティ設定に関する情報を提供します。

イベントファイルの**最大サイズ**は設定可能であり、最大サイズに達すると古いイベントの上書きが始まります。

登録されたイベントは以下の通りです：

* ログイン/ログオフ
* ユーザーのアクション
* ファイル、フォルダ、共有アセットへのアクセス
* セキュリティ設定の変更

ユーザー認証に関連するイベント：

| EventID   | 説明                          |
| --------- | ---------------------------- |
| 4624      | 認証成功                      |
| 4625      | 認証エラー                    |
| 4634/4647 | ログオフ                      |
| 4672      | 管理者権限でのログイン        |

EventID 4634/4647内には興味深いサブタイプがあります：

* **2 (interactive)**: キーボードまたはVNCや`PSexec -U-`のようなソフトウェアを使用して対話型でログインしました
* **3 (network)**: 共有フォルダへの接続
* **4 (Batch)**: 実行されたプロセス
* **5 (service)**: サービスコントロールマネージャーによって開始されたサービス
* **6 (proxy):** プロキシログイン
* **7 (Unlock)**: パスワードを使用して画面のロックを解除
* **8 (network cleartext)**: ユーザーがクリアテキストパスワードを送信して認証しました。このイベントは通常IISから来ます
* **9 (new credentials)**: `RunAs`コマンドが使用されたとき、またはユーザーが異なる資格情報でネットワークサービスにアクセスしたときに生成されます。
* **10 (remote interactive)**: ターミナルサービスまたはRDPを介した認証
* **11 (cache interactive)**: ドメインコントローラーに連絡できなかったため、最後にキャッシュされた資格情報を使用してアクセス
* **12 (cache remote interactive)**: キャッシュされた資格情報を使用してリモートでログイン（10と11の組み合わせ）。
* **13 (cached unlock)**: キャッシュされた資格情報を使用してロックされたマシンのロックを解除。

この投稿では、これらのログインタイプをどのように模倣し、どのタイプからメモリから資格情報をダンプできるかを見つけることができます：[https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

イベントのステータスとサブステータス情報は、イベントの原因についての詳細を示すことができます。例えば、Event ID 4625の以下のステータスとサブステータスコードを見てください：

![](<../../../.gitbook/assets/image (455).png>)

### Windowsイベントの復旧

Windowsイベントの回復可能性を最大化するために、怪しいPCを**プラグを抜いて**オフにすることを強く推奨します。もし削除されていた場合、[**Bulk_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor)ツールが**evtx**拡張子を指定して回復を試みるのに役立つかもしれません。

## Windowsイベントで一般的な攻撃を特定する

* [https://redteamrecipe.com/event-codes/](https://redteamrecipe.com/event-codes/)

### ブルートフォース攻撃

ブルートフォース攻撃は、**複数のEventIDs 4625が表示される**ため、簡単に識別できます。攻撃が**成功した**場合、EventIDs 4625の後に**EventID 4624が表示されます**。

### 時間変更

これはフォレンジックチームにとって非常に悪いことです、なぜならすべてのタイムスタンプが変更されるからです。このイベントはセキュリティイベントログ内のEventID 4616によって記録されます。

### USBデバイス

以下のシステムEventIDsが役立ちます：

* 20001 / 20003 / 10000: 初めて使用された時
* 10100: ドライバー更新

EventID 112のDeviceSetupManagerには、挿入された各USBデバイスのタイムスタンプが含まれています。

### オフ/オン

"Event Log"サービスのID 6005はPCがオンになったことを示します。ID 6006はオフになったことを示します。

### ログ削除

セキュリティイベントID 1102はログが削除されたことを示します。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
