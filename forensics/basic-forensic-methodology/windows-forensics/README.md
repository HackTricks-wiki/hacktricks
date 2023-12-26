# Windows Artifacts

## Windows Artifacts

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## 一般的なWindows Artifacts

### Windows 10 通知

パス `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` には、データベース `appdb.dat`（Windows記念日前）または `wpndatabase.db`（Windows記念日後）が見つかります。

このSQLiteデータベース内には、興味深いデータを含む可能性があるすべての通知（XML形式）を含む `Notification` テーブルがあります。

### タイムライン

タイムラインは、訪問したウェブページ、編集したドキュメント、実行したアプリケーションの**時系列の履歴**を提供するWindowsの特徴です。

データベースはパス `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` にあります。このデータベースはSQLiteツールで開くことも、ツール [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) を使用して生成された2つのファイルをツール [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) で開くこともできます。

### ADS (Alternate Data Streams)

ダウンロードされたファイルには、イントラネット、インターネットなどから**ダウンロードされた方法**を示す **ADS Zone.Identifier** が含まれている場合があります。一部のソフトウェア（ブラウザなど）は、ダウンロードされたファイルの**URL**など、さらに**多くの情報**を通常追加します。

## **ファイルバックアップ**

### ゴミ箱

Vista/Win7/Win8/Win10では、**ゴミ箱**はドライブのルート（`C:\$Recycle.bin`）にあるフォルダー **`$Recycle.bin`** で見つけることができます。\
このフォルダーでファイルが削除されると、2つの特定のファイルが作成されます：

* `$I{id}`: ファイル情報（削除された日付）
* `$R{id}`: ファイルの内容

![](<../../../.gitbook/assets/image (486).png>)

これらのファイルを持っている場合、ツール [**Rifiuti**](https://github.com/abelcheung/rifiuti2) を使用して、削除されたファイルの元のアドレスと削除された日付を取得できます（Vista – Win10用に `rifiuti-vista.exe` を使用）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
### ボリュームシャドウコピー

シャドウコピーは、使用中であってもコンピュータファイルやボリュームの**バックアップコピー**またはスナップショットを作成できる、Microsoft Windowsに含まれている技術です。

これらのバックアップは通常、ファイルシステムのルートから`\System Volume Information`に位置しており、名前は以下の画像に示されている**UID**で構成されています：

![](<../../../.gitbook/assets/image (520).png>)

**ArsenalImageMounter**でフォレンジックイメージをマウントすると、[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html)ツールを使用してシャドウコピーを検査し、シャドウコピーのバックアップから**ファイルを抽出**することもできます。

![](<../../../.gitbook/assets/image (521).png>)

レジストリエントリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`には、**バックアップしない**ファイルとキーが含まれています：

![](<../../../.gitbook/assets/image (522).png>)

レジストリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`にも`Volume Shadow Copies`に関する設定情報が含まれています。

### Office自動保存ファイル

Officeの自動保存ファイルは次の場所にあります：`C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## シェルアイテム

シェルアイテムは、別のファイルにアクセスする方法についての情報を含むアイテムです。

### 最近使ったドキュメント (LNK)

Windowsは、ユーザーがファイルを**開く、使用する、または作成する**ときに、以下の場所に**自動的に**これらの**ショートカット**を**作成**します：

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダが作成されると、そのフォルダ、親フォルダ、および祖父母フォルダへのリンクも作成されます。

これらの自動生成されたリンクファイルには、それが**ファイル**であるか**フォルダ**であるか、そのファイルの**MAC** **タイム**、ファイルが保存されている**ボリューム情報**、および**ターゲットファイルのフォルダ**についての情報が含まれています。この情報は、削除された場合にそれらのファイルを回復するのに役立つことがあります。

また、リンクファイルの**作成日**は元のファイルが**初めて使用された時**であり、リンクファイルの**変更日**は元のファイルが最後に使用された**時**です。

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

同じ情報をWindows CLIツール：[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)を実行して取得できます。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
```markdown
この情報はCSVファイル内に保存されます。

### ジャンプリスト

これらは、アプリケーションごとに示される最近使用したファイルです。**アプリケーションによって最近使用されたファイルのリスト**で、各アプリケーションでアクセスできます。**自動的に作成されるかカスタムで作成される**ことがあります。

自動的に作成される**ジャンプリスト**は`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`に保存されます。ジャンプリストは`{id}.autmaticDestinations-ms`という形式で名付けられ、初期IDはアプリケーションのIDです。

カスタムジャンプリストは`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`に保存され、通常はファイルに何か**重要な**ことが起こった場合（お気に入りとしてマークされた場合など）にアプリケーションによって作成されます。

任意のジャンプリストの**作成時間**は、**ファイルが初めてアクセスされた時間**を示し、**変更時間は最後にアクセスされた時間**を示します。

[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)を使用してジャンプリストを調査できます。

![](<../../../.gitbook/assets/image (474).png>)

（_ジャンプリストエクスプローラーによって提供されるタイムスタンプは、ジャンプリストファイル自体に関連していることに注意してください_）

### シェルバッグ

[**シェルバッグについて学ぶには、このリンクをたどってください。**](interesting-windows-registry-keys.md#shellbags)

## Windows USBの使用

USBデバイスが使用されたことを以下の作成によって特定できます：

* Windows Recent Folder
* Microsoft Office Recent Folder
* ジャンプリスト

LNKファイルが元のパスを指している代わりに、WPDNSEフォルダを指していることに注意してください：

![](<../../../.gitbook/assets/image (476).png>)

WPDNSEフォルダ内のファイルは元のファイルのコピーであり、PCの再起動には耐えられず、GUIDはシェルバッグから取得されます。

### レジストリ情報

[このページをチェックして](interesting-windows-registry-keys.md#usb-information)、USB接続デバイスに関する興味深い情報を含むレジストリキーを学びます。

### setupapi

`C:\Windows\inf\setupapi.dev.log`ファイルをチェックして、USB接続が行われたときのタイムスタンプを取得します（`Section start`を検索）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)を使用して、イメージに接続されたUSBデバイスに関する情報を取得できます。

![](<../../../.gitbook/assets/image (483).png>)

### プラグアンドプレイのクリーンアップ

「プラグアンドプレイのクリーンアップ」スケジュールされたタスクは、ドライバーの古いバージョンを**クリア**する責任があります。オンラインでの報告に基づくと、その説明には「各ドライバーパッケージの最新バージョンが保持されます」と記載されているにもかかわらず、**30日間使用されていないドライバーも削除される**ことがあります。したがって、**30日間接続されていない取り外し可能なデバイスは、そのドライバーが削除される可能性があります**。

スケジュールされたタスク自体は「C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup」にあり、その内容は以下に表示されます：

![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

タスクは「pnpclean.dll」を参照しており、これはクリーンアップ活動を実行する責任があります。さらに、「UseUnifiedSchedulingEngine」フィールドが「TRUE」に設定されていることがわかります。これは、汎用タスクスケジューリングエンジンがタスクの管理に使用されることを指定しています。「MaintenanceSettings」内の「Period」と「Deadline」の値「P1M」と「P2M」は、タスクスケジューラに、通常の自動メンテナンス中に毎月1回タスクを実行し、2か月連続で失敗した場合は、緊急自動メンテナンス中にタスクの試行を開始するよう指示します。**このセクションは**[**ここからコピーされました**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)**。**

## 電子メール

電子メールには**2つの興味深い部分があります：ヘッダーと電子メールの内容**。**ヘッダー**では、以下のような情報を見つけることができます：

* **誰が**電子メールを送ったか（電子メールアドレス、IP、電子メールをリダイレクトしたメールサーバー）
* **いつ**電子メールが送信されたか

また、`References`と`In-Reply-To`ヘッダー内では、メッセージのIDを見つけることができます：

![](<../../../.gitbook/assets/image (484).png>)

### Windowsメールアプリ

このアプリケーションは電子メールをHTMLまたはテキストで保存します。`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`内のサブフォルダ内で電子メールを見つけることができます。電子メールは`.dat`拡張子で保存されます。

電子メールの**メタデータ**と**連絡先**は、**EDBデータベース**内で見つけることができます：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

ファイルの拡張子を`.vol`から`.edb`に**変更**し、[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)ツールを使用して開きます。`Message`テーブル内で電子メールを見ることができます。

### Microsoft Outlook

ExchangeサーバーまたはOutlookクライアントが使用されている場合、いくつかのMAPIヘッダーが存在します：

* `Mapi-Client-Submit-Time`：電子メールが送信されたときのシステムの時間
* `Mapi-Conversation-Index`：スレッドの子メッセージの数とスレッドの各メッセージのタイムスタンプ
* `Mapi-Entry-ID`：メッセージ識別子。
* `Mappi-Message-Flags`と`Pr_last_Verb-Executed`：MAPIクライアントに関する情報（メッセージは読まれたか？読まれていないか？返信されたか？転送されたか？不在中か？）

Microsoft Outlookクライアントでは、送受信されたすべてのメッセージ、連絡先データ、カレンダーデータがPSTファイルに保存されています：

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`は、使用されているファイルを示しています。

[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)ツールを使用してPSTファイルを開くことができます。

![](<../../../.gitbook/assets/image (485).png>)

### Outlook OST

Microsoft Outlookが**IMAP**を使用して設定されている場合、または**Exchange**サーバーを使用している場合、ほぼPSTファイルと同じ情報を格納する**OST**ファイルが生成されます。これは、**過去12ヶ月間**のファイルをサーバーと同期させ、**最大ファイルサイズは50GB**で、PSTファイルが保存されている**同じフォルダ**に保管されます。このファイルは[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)を使用して調査できます。

### 添付ファイルの回復

以下のフォルダで見つけることができるかもしれません：

* `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
* `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird**は情報を**MBOX** **ファイル**に保存し、`\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`フォルダ内にあります。

## サムネイル

ユーザーがフォルダにアクセスしてサムネイルを使用して整理すると、`thumbs.db`ファイルが作成されます。このdbは、削除された画像であっても、フォルダの画像の**サムネイルを保存**します。WinXPおよびWin 8-8.1ではこのファイルが自動的に作成されます。Win7/Win10では、UNCパス（\IP\folder...）経由でアクセスされた場合に自動的に作成されます。

このファイルは[**Thumbsviewer**](https://thumbsviewer.github.io)ツールで読むことができます。

### サムネイルキャッシュ

Windows Vista以降、**サムネイルプレビューはシステム上の中央集中型の場所に保存されます**。これにより、システムは画像の場所に関係なく画像にアクセスでき、Thumbs.dbファイルの局所性に関する問題が解決されます。キャッシュは**`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`**にいくつかのファイルとして保存され、サイズごとに番号付けされた**thumbcache\_xxx.db**（小さい、中、大、特大）と、各サイズのデータベースでサムネイルを見つけるために使用されるインデックスがあります。

* Thumbcache\_32.db -> 小さい
* Thumbcache\_96.db -> 中
* Thumbcache\_256.db -> 大
* Thumbcache\_1024.db -> 特大

このファイルは[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)を使用して読むことができます。

## Windowsレジストリ

Windowsレジストリには、**システムとユーザーの行動**に関する多くの**情報**が含まれています。

レジストリを含むファイルは以下の場所にあります：

* %windir%\System32\Config\*_SAM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SECURITY\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SYSTEM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SOFTWARE\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_DEFAULT\*_: `HKEY_LOCAL_MACHINE`
* %UserProfile%{User}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

Windows VistaおよびWindows 2008 Server以降では、`HKEY_LOCAL_MACHINE`レジストリファイルのバックアップが**`%Windir%\System32\Config\RegBack\`**にいくつかあります。

また、これらのバージョンから、レジストリファイル**`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`**が作成され、プログラム実行に関する情報が保存されます。

### ツール

レジストリファイルを分析するのに役立つツールがいくつかあります：

* **レジストリエディタ**：Windowsにインストールされています。現在のセッションのWindowsレジストリをナビゲートするためのGUIです。
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：レジストリファイルをロードして、GUIでナビゲートすることができます。興味深い情報をハイライトするブックマークも含まれています。
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：ロードされたレジストリをナビゲートするGUIがあり、ロードされたレジストリ内の興味深い情報をハイライトするプラグインも含まれています。
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：ロードされたレジストリから重要な情報を抽出することができるGUIアプリケーションです。

### 削除された要素の回復

キーが削除されるとそのようにマークされますが、そのスペースが必要になるまで削除されません。したがって、**Registry Explorer**のようなツールを使用して、これらの削除されたキーを回復することが可能です。

### 最終書き込み時間

各キー値には、最後に変更された時間を示す**タ
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
```markdown
![](<../../../.gitbook/assets/image (487).png>)

### スーパープリフェッチ

**スーパープリフェッチ**はプリフェッチと同じ目的を持っています。次にロードされるものを予測することで、**プログラムをより速くロードする**ことです。しかし、プリフェッチサービスを置き換えるものではありません。
このサービスは `C:\Windows\Prefetch\Ag*.db` にデータベースファイルを生成します。

これらのデータベースには、**プログラム**の**名前**、**実行**の**回数**、**開かれた** **ファイル**、**アクセスされた** **ボリューム**、**完全な** **パス**、**時間枠**、**タイムスタンプ**が含まれています。

この情報にはツール [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) を使用してアクセスできます。

### SRUM

**システムリソース使用モニター** (SRUM) はプロセスによって**消費される** **リソース**を**監視**します。これはW8で登場し、データは `C:\Windows\System32\sru\SRUDB.dat` にあるESEデータベースに保存されます。

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

**Shimcache**、または **AppCompatCache** は、**Microsoft** によって作成された **Application Compatibility Database** の一部で、オペレーティングシステムがアプリケーションの互換性問題を特定するために使用されます。

キャッシュは、オペレーティングシステムに応じて様々なファイルメタデータを保存します。例えば：

* ファイルの完全パス
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

この情報を解析するためにツール [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) を使用できます。

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve** ファイルは、実行されたアプリケーションの情報を保存するレジストリファイルです。`C:\Windows\AppCompat\Programas\Amcache.hve` に位置しています。

**Amcache.hve** は最近実行されたプロセスを記録し、実行されたファイルのパスをリストアップします。これにより、実行されたプログラムを見つけることができます。また、プログラムの SHA1 も記録します。

この情報を解析するためにツール [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser) を使用できます。
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
```markdown
最も興味深いCVSファイルは、`Amcache_Unassociated file entries`です。

### RecentFileCache

このアーティファクトはW7の`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`で見つけることができ、いくつかのバイナリの最近の実行に関する情報が含まれています。

ファイルを解析するために、ツール[**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)を使用できます。

### スケジュールされたタスク

これらは`C:\Windows\Tasks`または`C:\Windows\System32\Tasks`から抽出でき、XMLとして読むことができます。

### サービス

レジストリの`SYSTEM\ControlSet001\Services`で見つけることができます。何が実行されるか、いつ実行されるかを確認できます。

### **Windows Store**

インストールされたアプリケーションは`\ProgramData\Microsoft\Windows\AppRepository\`にあります。
このリポジトリには、データベース**`StateRepository-Machine.srd`**内のシステムにインストールされた**各アプリケーション**に関する**ログ**があります。

このデータベースのアプリケーションテーブル内では、"Application ID"、"PackageNumber"、"Display Name"の列を見つけることができます。これらの列には、プリインストールされたアプリケーションとインストールされたアプリケーションに関する情報が含まれており、アプリケーションがアンインストールされたかどうかを確認できます。なぜなら、インストールされたアプリケーションのIDは連続しているべきだからです。

また、レジストリパス`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`内で**インストールされたアプリケーション**を**見つける**ことができます。
そして、`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`で**アンインストールされた** **アプリケーション**を見つけることができます。

## Windowsイベント

Windowsイベント内に表示される情報は以下の通りです：

* 何が起こったか
* タイムスタンプ (UTC + 0)
* 関与したユーザー
* 関与したホスト (ホスト名、IP)
* アクセスされたアセット (ファイル、フォルダ、プリンター、サービス)

ログはWindows Vista以前では`C:\Windows\System32\config`に、Windows Vista以降では`C:\Windows\System32\winevt\Logs`に位置しています。Windows Vista以前ではイベントログはバイナリ形式で、それ以降は**XML形式**を使用し、**.evtx**拡張子を使用します。

イベントファイルの場所はSYSTEMレジストリの**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**で見つけることができます。

Windowsイベントビューア（**`eventvwr.msc`**）または[**Event Log Explorer**](https://eventlogxp.com) **や** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**などの他のツールから可視化できます。**

### セキュリティ

これはアクセスイベントを記録し、`C:\Windows\System32\winevt\Security.evtx`で見つけることができるセキュリティ設定に関する情報を提供します。

イベントファイルの**最大サイズ**は設定可能で、最大サイズに達すると古いイベントを上書きし始めます。

登録されたイベントは以下の通りです：

* ログイン/ログオフ
* ユーザーのアクション
* ファイル、フォルダ、共有アセットへのアクセス
* セキュリティ設定の変更

ユーザー認証に関連するイベント：

| EventID   | 説明                  |
| --------- | ---------------------------- |
| 4624      | 認証成功    |
| 4625      | 認証エラー         |
| 4634/4647 | ログオフ                      |
| 4672      | 管理者権限でのログイン |

EventID 4634/4647内には興味深いサブタイプがあります：

* **2 (対話型)**: キーボードまたはVNCや`PSexec -U-`のようなソフトウェアを使用して対話型でログインしました。
* **3 (ネットワーク)**: 共有フォルダへの接続
* **4 (バッチ)**: 実行されたプロセス
* **5 (サービス)**: サービスコントロールマネージャーによって開始されたサービス
* **6 (プロキシ):** プロキシログイン
* **7 (アンロック)**: パスワードを使用して画面のロックを解除
* **8 (ネットワーククリアテキスト)**: ユーザーがクリアテキストパスワードを送信して認証されました。このイベントは通常IISから来ます。
* **9 (新しい資格情報)**: `RunAs`コマンドが使用されたり、ユーザーが異なる資格情報でネットワークサービスにアクセスしたときに生成されます。
* **10 (リモート対話型)**: ターミナルサービスまたはRDPを介した認証
* **11 (キャッシュ対話型)**: ドメインコントローラーに連絡できなかったため、最後にキャッシュされた資格情報を使用してアクセスしました。
* **12 (キャッシュリモート対話型)**: キャッシュされた資格情報を使用してリモートでログイン（10と11の組み合わせ）。
* **13 (キャッシュアンロック)**: キャッシュされた資格情報を使用してロックされたマシンのロックを解除します。

この投稿では、これらのログインタイプをどのように模倣し、どのタイプでメモリから資格情報をダンプできるかを見つけることができます：[https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

イベントのステータスとサブステータス情報は、イベントの原因についての詳細を示すことができます。例えば、Event ID 4625の以下のステータスとサブステータスコードを見てください：

![](<../../../.gitbook/assets/image (455).png>)

### Windowsイベントの復旧

疑わしいPCを**プラグを抜いて**オフにすることを強く推奨します。これにより、Windowsイベントを復旧する可能性が最大化されます。削除された場合、**evtx**拡張子を指定して試してみると便利なツールは[**Bulk_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor)です。

## Windowsイベントで一般的な攻撃を特定する

* [https://redteamrecipe.com/event-codes/](https://redteamrecipe.com/event-codes/)

### ブルートフォース攻撃

ブルートフォース攻撃は、**複数のEventIDs 4625が表示される**ため、簡単に識別できます。攻撃が**成功した**場合、EventIDs 4625の後に**EventID 4624が表示されます**。

### 時間変更

これはフォレンジックチームにとって非常に悪いことです。なぜなら、すべてのタイムスタンプが変更されるからです。このイベントはセキュリティイベントログ内のEventID 4616によって記録されます。

### USBデバイス

以下のシステムEventIDsが役立ちます：

* 20001 / 20003 / 10000: 初めて使用されたとき
* 10100: ドライバー更新

EventID 112のDeviceSetupManagerには、挿入された各USBデバイスのタイムスタンプが含まれています。

### オフ/オン

"Event Log"サービスのID 6005は、PCがオンになったことを示します。ID 6006は、オフになったことを示します。

### ログの削除

セキュリティイベントID 1102は、ログが削除されたことを示します。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksであなたの会社を広告したい**ですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。
* **ハッキングのトリックを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
```
