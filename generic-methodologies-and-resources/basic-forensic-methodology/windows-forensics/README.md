# Windows Artifacts

## Windows Artifacts

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は**、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする。
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリにPRを提出する。**

</details>

## 一般的なWindowsアーティファクト

### Windows 10通知

パス`\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`には、Windows Anniversaryより前の`appdb.dat`またはWindows Anniversary以降の`wpndatabase.db`というデータベースがあります。

このSQLiteデータベース内には、興味深いデータを含む可能性があるすべての通知（XML形式）を含む`Notification`テーブルがあります。

### タイムライン

タイムラインは、訪れたWebページ、編集されたドキュメント、実行されたアプリケーションの**時間順の履歴**を提供するWindowsの特性です。

データベースは、パス`\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`にあります。このデータベースは、SQLiteツールまたは[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)というツールで開くことができます。**これにより、2つのファイルが生成され、[**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md)で開くことができます。**

### ADS（代替データストリーム）

ダウンロードされたファイルには、**ADS Zone.Identifier**が含まれており、それがイントラネット、インターネットなどから**どのように**ダウンロードされたかを示しています。一部のソフトウェア（ブラウザなど）は、通常、ファイルがダウンロードされたURLなどの**さらに多くの情報**を追加します。

## **ファイルのバックアップ**

### リサイクルビン

Vista/Win7/Win8/Win10では、**リサイクルビン**はドライブのルートにあるフォルダ**`$Recycle.bin`**にあります（`C:\$Recycle.bin`）。\
このフォルダでファイルが削除されると、2つの特定のファイルが作成されます：

* `$I{id}`: ファイル情報（削除された日付）
* `$R{id}`: ファイルの内容

![](<../../../.gitbook/assets/image (486).png>)

これらのファイルを使用して、ツール[**Rifiuti**](https://github.com/abelcheung/rifiuti2)を使用して、削除されたファイルの元のアドレスと削除された日付を取得できます（Vista – Win10用に`rifiuti-vista.exe`を使用します）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### ボリュームシャドウコピー

Shadow Copyは、Microsoft Windowsに含まれる技術で、コンピュータファイルやボリュームの**バックアップコピー**やスナップショットを作成できます。これは、使用中であっても可能です。

これらのバックアップは通常、ファイルシステムのルートにある`\System Volume Information`にあり、名前は以下の画像に示す**UID**で構成されています:

![](<../../../.gitbook/assets/image (520).png>)

**ArsenalImageMounter**を使用してフォレンジックイメージをマウントすると、ツール[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html)を使用してシャドウコピーを検査し、シャドウコピーのバックアップからファイルを**抽出**することができます。

![](<../../../.gitbook/assets/image (521).png>)

レジストリエントリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`には、バックアップしないファイルとキーが含まれています:

![](<../../../.gitbook/assets/image (522).png>)

レジストリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`には、`Volume Shadow Copies`に関する構成情報も含まれています。

### Officeの自動保存ファイル

Officeの自動保存ファイルは、次の場所にあります: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## シェルアイテム

シェルアイテムは、別のファイルにアクセスする方法に関する情報を含むアイテムです。

### 最近のドキュメント（LNK）

Windowsは、ユーザーがファイルを**開いたり使用したり作成したり**すると、これらの**ショートカット**を**自動的に作成**します:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダが作成されると、そのフォルダへのリンク、親フォルダへのリンク、祖父フォルダへのリンクも作成されます。

これら自動的に作成されたリンクファイルには、**ファイル**か**フォルダ**か、そのファイルの**MACタイム**、ファイルが保存されている場所の**ボリューム情報**、**ターゲットファイルのフォルダ**が含まれる情報があります。これらの情報は、削除された場合にこれらのファイルを回復するのに役立ちます。

また、リンクファイルの**作成日**は、元のファイルが**最初に使用された時間**であり、リンクファイルの**変更日**は、元のファイルが**最後に使用された時間**です。

これらのファイルを検査するには、[**LinkParser**](http://4discovery.com/our-tools/)を使用できます。

このツールでは、**2つのセット**のタイムスタンプが見つかります:

* **最初のセット:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **2番目のセット:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

最初のセットのタイムスタンプは、**ファイル自体のタイムスタンプ**を参照します。2番目のセットは、**リンクされたファイルのタイムスタンプ**を参照します。

同じ情報を取得するには、Windows CLIツール[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)を実行できます。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### ジャンプリスト

これは、**アプリケーションごとに示される最近使用されたファイル**のリストです。各アプリケーションでアクセスできる**最近使用されたファイルのリスト**です。これらは**自動的に作成されるか、カスタムで作成**されることがあります。

**自動的に作成されたジャンプリスト**は、`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`に保存されます。ジャンプリストは、初期IDがアプリケーションのIDである形式に従って名前が付けられます。

カスタムジャンプリストは、`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`に保存され、通常はアプリケーションによって作成されます。これは、ファイルに何か**重要なこと**が起こったためかもしれません（お気に入りとしてマークされたかもしれません）。

どのジャンプリストの**作成時刻**は、**ファイルにアクセスされた最初の時間**を示し、**変更時刻**は最後の時間を示します。

[JumplistExplorer](https://ericzimmerman.github.io/#!index.md)を使用してジャンプリストを調査できます。

![](<../../../.gitbook/assets/image (474).png>)

（_JumplistExplorerによって提供されるタイムスタンプは、ジャンプリストファイル自体に関連しています_）

### シェルバッグ

[**こちらのリンク**](interesting-windows-registry-keys.md#shellbags)を参照して、シェルバッグとは何かを学びます。

## Windows USBの使用

USBデバイスが使用されたことを特定することが可能です。これは次のようにして行われます：

* Windows最近使用したフォルダ
* Microsoft Office最近使用したフォルダ
* ジャンプリスト

一部のLNKファイルは、元のパスを指す代わりにWPDNSEフォルダを指します：

![](<../../../.gitbook/assets/image (476).png>)

フォルダWPDNSE内のファイルは、元のファイルのコピーであり、したがってPCの再起動を行うと消えます。GUIDはシェルバッグから取得されます。

### レジストリ情報

USB接続されたデバイスに関する興味深い情報を含むレジストリキーを確認するには、[このページ](interesting-windows-registry-keys.md#usb-information)を参照してください。

### setupapi

USB接続が行われたタイムスタンプを取得するには、ファイル`C:\Windows\inf\setupapi.dev.log`を確認してください（`Section start`を検索）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)を使用して、イメージに接続されたUSBデバイスに関する情報を取得できます。

![](<../../../.gitbook/assets/image (483).png>)

### プラグアンドプレイのクリーンアップ

「プラグアンドプレイのクリーンアップ」として知られるスケジュールされたタスクは、古いドライバーバージョンを削除するために主に設計されています。最新のドライバーパッケージバージョンを保持することが明示されているにもかかわらず、オンラインソースによると、過去30日間非アクティブだったドライバーも対象となる可能性があります。その結果、過去30日間接続されていないリムーバブルデバイスのドライバーは削除の対象となる可能性があります。

このタスクは次の場所にあります：
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

タスクの内容を示すスクリーンショットが提供されています：
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**タスクの主要なコンポーネントと設定:**
- **pnpclean.dll**: このDLLは実際のクリーンアッププロセスを担当しています。
- **UseUnifiedSchedulingEngine**: `TRUE`に設定されており、一般的なタスクスケジューリングエンジンが使用されていることを示しています。
- **MaintenanceSettings**:
- **Period ('P1M')**: タスクスケジューラに、定期的な自動メンテナンス中に月次のクリーンアップタスクを開始するよう指示します。
- **Deadline ('P2M')**: タスクスケジューラに、2か月連続でタスクが失敗した場合、緊急時の自動メンテナンス中にタスクを実行するよう指示します。

この構成により、ドライバーの定期的なメンテナンスとクリーンアップが確保され、連続した失敗の場合にタスクを再試行するための規定があります。

**詳細はこちらを参照:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## メール

メールには**2つの興味深い部分が含まれます: ヘッダーとコンテンツ**です。**ヘッダー**には次のような情報が含まれます：

* メールを送信した**誰**（メールアドレス、IP、メールをリダイレクトしたメールサーバー）
* メールがいつ送信されたか

また、`References`と`In-Reply-To`ヘッダー内には、メッセージのIDが含まれています：

![](<../../../.gitbook/assets/image (484).png>)

### Windowsメールアプリ

このアプリケーションは、メールをHTMLまたはテキストで保存します。メールは`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`内のサブフォルダ内に保存され、`.dat`拡張子で保存されます。

メールの**メタデータ**と**連絡先**は、**EDBデータベース**内で見つけることができます：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

ファイルの拡張子を`.vol`から`.edb`に変更し、[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)ツールを使用して開くことができます。`Message`テーブル内でメールを確認できます。

### Microsoft Outlook

ExchangeサーバーやOutlookクライアントが使用されている場合、いくつかのMAPIヘッダーが存在します：

* `Mapi-Client-Submit-Time`: メールが送信されたシステムの時間
* `Mapi-Conversation-Index`: スレッドの子メッセージ数とスレッドの各メッセージのタイムスタンプ
* `Mapi-Entry-ID`: メッセージ識別子
* `Mappi-Message-Flags`および`Pr_last_Verb-Executed`: MAPIクライアントに関する情報（メッセージが読まれたか、未読か、返信済みか、リダイレクトされたか、オフィスを外出中かなど）

Microsoft Outlookクライアントでは、送信/受信したメッセージ、連絡先データ、カレンダーデータが次の場所に保存されます：

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook`（WinXP）
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`は使用されているファイルを示します。

PSTファイルを開くには、[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)ツールを使用できます。

![](<../../../.gitbook/assets/image (485).png>)

### Microsoft Outlook OSTファイル

Microsoft Outlookが**IMAP**または**Exchange**サーバーと構成されている場合、**OSTファイル**が生成され、PSTファイルと同様の情報が保存されます。このファイルはサーバーと同期され、**過去12か月間**のデータを最大**50GB**まで保持し、PSTファイルと同じディレクトリに保存されます。OSTファイルを表示するには、[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)を利用できます。

### 添付ファイルの取得

失われた添付ファイルは次の場所から回復できる場合があります：

- **IE10**の場合：`%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11以降**の場合：`%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOXファイル

**Thunderbird**はデータを保存するために**MBOXファイル**を使用し、`\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`に保存されます。

### 画像サムネイル

- **Windows XPおよび8-8.1**：サムネイルが表示されるフォルダにアクセスすると、削除後も画像プレビューを保存する`thumbs.db`ファイルが生成されます。
- **Windows 7/10**：UNCパスを介してネットワーク経由でアクセスすると、`thumbs.db`が作成されます。
- **Windows Vista以降**：サムネイルプレビューは`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`に集約され、**thumbcache\_xxx.db**という名前のファイルに保存されます。これらのファイルを表示するためのツールとして、[**Thumbsviewer**](https://thumbsviewer.github.io)と[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)があります。

### Windowsレジストリ情報

Windowsレジストリは、広範なシステムおよびユーザーのアクティビティデータを保存しており、次の場所にファイルが保存されています：

- `HKEY_LOCAL_MACHINE`のさまざまなサブキーに対しては`%windir%\System32\Config`
- `HKEY_CURRENT_USER`に対しては`%UserProfile%{User}\NTUSER.DAT`
- Windows Vista以降では、`HKEY_LOCAL_MACHINE`レジストリファイルは`%Windir%\System32\Config\RegBack\`にバックアップされます。
- さらに、プログラムの実行情報は、Windows VistaおよびWindows 2008 Server以降では`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`に保存されます。

### ツール

いくつかのツールがレジストリファイルを分析するのに役立ちます：

* **レジストリエディタ**: Windowsにインストールされています。現在のセッションのWindowsレジストリをナビゲートするためのGUIです。
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): レジストリファイルをロードし、GUIでナビゲートすることができます。興味深い情報を含むキーをハイライトするブックマークが含まれています。
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): ロードされたレジストリをナビゲートするためのGUIがあり、ロードされたレジストリ内の興味深い情報をハイライトするプラグインも含まれています。
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): ロードされたレジストリから重要な情報を抽出できる別のGUIアプリケーションです。

### 削除された要素の回復

キーが削除されると、そのようにマークされますが、そのスペースが必要になるまで削除されません。そのため、**Registry Explorer**などのツールを使用すると、これらの削除されたキーを回復することが可能です。

### 最終書き込み時刻

各キー値には、最後に変更された時刻を示す**タイムスタンプ**が含まれています。

### SAM

ファイル/ハイブ**SAM**には、システムの**ユーザー、グループ、ユーザーパスワード**のハッシュが含まれています。

`SAM\Domains\Account\Users`では、ユーザー名、RID、最終ログイン、最終失敗ログオン、ログインカウンター、パスワードポリシー、アカウント作成日時を取得できます。**ハッシュ**を取得するには、ファイル/ハイブ**SYSTEM**も必要です。

### Windowsレジストリの興味深いエントリ

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## 実行されたプログラム

### 基本的なWindowsプロセス

[この記事](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)では、疑わしい動作を検出するための一般的なWindowsプロセスに
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch**は、prefetchと同じ目標を持ち、**次に読み込まれるものを予測して**プログラムを**高速に読み込む**ことです。ただし、prefetchサービスを置き換えるものではありません。\
このサービスは、`C:\Windows\Prefetch\Ag*.db`にデータベースファイルを生成します。

これらのデータベースには、**プログラムの名前**、**実行回数**、**開かれたファイル**、**アクセスされたボリューム**、**完全なパス**、**時間枠**、**タイムスタンプ**が含まれています。

この情報には、[**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/)ツールを使用してアクセスできます。

### SRUM

**System Resource Usage Monitor**（SRUM）は、**プロセスによって消費されるリソースを監視**します。W8に登場し、データは`C:\Windows\System32\sru\SRUDB.dat`にあるESEデータベースに保存されます。

次の情報が提供されます：

* AppIDとパス
* プロセスを実行したユーザー
* 送信バイト数
* 受信バイト数
* ネットワークインターフェース
* 接続期間
* プロセス期間

この情報は60分ごとに更新されます。

このファイルからデータを取得するには、[**srum_dump**](https://github.com/MarkBaggett/srum-dump)ツールを使用できます。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**、または**ShimCache**としても知られるものは、**Microsoft**が開発した**Application Compatibility Database**の一部であり、アプリケーションの互換性の問題に対処するためのものです。このシステムコンポーネントは、次のファイルメタデータを記録します:

- ファイルの完全なパス
- ファイルのサイズ
- **$Standard\_Information**（SI）の下の最終更新時刻
- ShimCacheの最終更新時刻
- プロセス実行フラグ

このようなデータは、オペレーティングシステムのバージョンに基づいてレジストリ内の特定の場所に保存されます:

- XPの場合、データは`SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`に保存され、96エントリを格納できます。
- Server 2003、およびWindowsバージョン2008、2012、2016、7、8、および10の場合、ストレージパスは`SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`で、それぞれ512および1024エントリを収容します。

保存された情報を解析するには、[**AppCompatCacheParser**ツール](https://github.com/EricZimmerman/AppCompatCacheParser)の使用をお勧めします。

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve**ファイルは、システムで実行されたアプリケーションの詳細を記録するレジストリハイブです。通常、`C:\Windows\AppCompat\Programas\Amcache.hve`にあります。

このファイルは、実行されたプロセスの記録、実行可能ファイルへのパス、およびそれらのSHA1ハッシュを保存するために注目されています。この情報は、システム上のアプリケーションの活動を追跡するために貴重です。

**Amcache.hve**からデータを抽出して分析するには、[**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser)ツールを使用できます。次のコマンドは、**Amcache.hve**ファイルの内容を解析し、結果をCSV形式で出力するための使用例です:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
### 最も興味深いCSVファイルは、`Amcache_Unassociated file entries`です。

### RecentFileCache

このアーティファクトは、W7にのみ`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`にあり、一部のバイナリの最近の実行に関する情報を含んでいます。

ファイルを解析するには、[**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)ツールを使用できます。

### スケジュールされたタスク

これらは`C:\Windows\Tasks`または`C:\Windows\System32\Tasks`から抽出し、XMLとして読むことができます。

### サービス

これらは`SYSTEM\ControlSet001\Services`のレジストリ内にあります。実行される内容と実行されるタイミングを確認できます。

### **Windowsストア**

インストールされたアプリケーションは`\ProgramData\Microsoft\Windows\AppRepository\`にあります。\
このリポジトリには、データベース内の**`StateRepository-Machine.srd`**という名前の**各インストールされたアプリケーション**に関する**ログ**があります。

このデータベースのApplicationテーブル内には、"Application ID"、"PackageNumber"、"Display Name"という列があります。これらの列には、プリインストールされたアプリケーションとインストールされたアプリケーションに関する情報が含まれており、インストールされたアプリケーションのIDが連続しているかどうかを確認できます。

また、レジストリパス`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`内に**インストールされたアプリケーション**を見つけることができます。\
そして、**アンインストールされたアプリケーション**は`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`にあります。

## Windowsイベント

Windowsイベントに表示される情報は次のとおりです：

* 何が起こったか
* タイムスタンプ（UTC + 0）
* 関与するユーザー
* 関与するホスト（ホスト名、IP）
* アクセスされたアセット（ファイル、フォルダ、プリンター、サービス）

ログは、Windows Vistaより前では`C:\Windows\System32\config`に、Windows Vista以降では`C:\Windows\System32\winevt\Logs`にあります。Windows Vistaより前では、イベントログはバイナリ形式であり、その後は**XML形式**であり、**.evtx**拡張子を使用します。

イベントファイルの場所は、SYSTEMレジストリ内の**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**にあります。

Windowsイベントビューアー（**`eventvwr.msc`**）や[**Event Log Explorer**](https://eventlogxp.com)や[**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)などの他のツールで表示できます。

## Windowsセキュリティイベントの理解

セキュリティ構成ファイルに記録されるアクセスイベントは、`C:\Windows\System32\winevt\Security.evtx`にあります。このファイルのサイズは調整可能であり、容量が達すると古いイベントが上書きされます。記録されるイベントには、ユーザーログインとログオフ、ユーザーアクション、セキュリティ設定の変更、ファイル、フォルダ、共有アセットへのアクセスが含まれます。

### ユーザー認証のための主要なイベントID：

- **EventID 4624**: ユーザーが正常に認証されたことを示します。
- **EventID 4625**: 認証の失敗を示します。
- **EventIDs 4634/4647**: ユーザーログオフイベントを表します。
- **EventID 4672**: 管理特権でのログインを示します。

#### EventID 4634/4647内のサブタイプ：

- **Interactive (2)**: 直接ユーザーログイン。
- **Network (3)**: 共有フォルダへのアクセス。
- **Batch (4)**: バッチプロセスの実行。
- **Service (5)**: サービスの起動。
- **Proxy (6)**: プロキシ認証。
- **Unlock (7)**: パスワードで画面のロック解除。
- **Network Cleartext (8)**: 明示的なパスワード送信、主にIISから。
- **New Credentials (9)**: アクセスのための異なる資格情報の使用。
- **Remote Interactive (10)**: リモートデスクトップまたはターミナルサービスへのログイン。
- **Cache Interactive (11)**: ドメインコントローラーに連絡せずにキャッシュされた資格情報でのログイン。
- **Cache Remote Interactive (12)**: キャッシュされた資格情報でのリモートログイン。
- **Cached Unlock (13)**: キャッシュされた資格情報でのロック解除。

#### EventID 4625のステータスおよびサブステータスコード：

- **0xC0000064**: ユーザー名が存在しない - ユーザー名の列挙攻撃を示す可能性があります。
- **0xC000006A**: 正しいユーザー名が間違ったパスワード - パスワードの推測または総当たり攻撃の試行が考えられます。
- **0xC0000234**: ユーザーアカウントがロックアウトされている - 多数の失敗したログインをもたらす総当たり攻撃の結果として発生する可能性があります。
- **0xC0000072**: アカウントが無効になっている - 無効になったアカウントへの不正アクセス試行。
- **0xC000006F**: 許可された時間外のログオン - 設定されたログイン時間外にアクセスを試みることは、不正アクセスの可能性を示すかもしれません。
- **0xC0000070**: ワークステーションの制限の違反 - 許可されていない場所からのログイン試行。
- **0xC0000193**: アカウントの有効期限切れ - 期限切れのユーザーアカウントでのアクセス試行。
- **0xC0000071**: パスワードの有効期限切れ - 期限切れのパスワードでのログイン試行。
- **0xC0000133**: 時間同期の問題 - クライアントとサーバー間の大きな時間のずれは、パスザチケットなどの高度な攻撃の兆候となる可能性があります。
- **0xC0000224**: 強制的なパスワード変更が必要 - 頻繁な強制的な変更は、アカウントセキュリティを不安定にする試みを示す可能性があります。
- **0xC0000225**: セキュリティ問題ではなく、システムのバグを示します。
- **0xC000015b**: 拒否されたログオンタイプ - ユーザーがサービスログオンを実行しようとするなど、許可されていないログオンタイプでのアクセス試行。

#### EventID 4616:
- **時間の変更**: システム時間の変更、イベントのタイムラインを曖昧にする可能性があります。

#### EventID 6005および6006:
- **システムの起動およびシャットダウン**: EventID 6005はシステムの起動を示し、EventID 6006はシャットダウンを示します。

#### EventID 1102:
- **ログの削除**: 不正行為を隠すための赤信号であるセキュリティログのクリア。

#### USBデバイストラッキングのためのEventID：
- **20001 / 20003 / 10000**: USBデバイスの初回接続。
- **10100**: USBドライバーの更新。
- **EventID 112**: USBデバイスの挿入時刻。

これらのログインタイプや資格情報ダンプの機会をシミュレートする実践的な例については、[Altered Securityの詳細ガイド](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)を参照してください。

イベントの詳細、特にEvent ID 4625でのステータスおよびサブステータスコードは、イベントの原因に関するさらなる洞察を提供します。

### Windowsイベントの回復

削除されたWindowsイベントを回復する可能性を高めるためには、疑わしいコンピューターの電源を直接抜いて電源を切ることをお勧めします。`.evtx`拡張子を指定する回復ツールである**Bulk_extractor**を使用して、このようなイベントを回復しようとすることをお勧めします。

### Windowsイベントを通じた一般的な攻撃の特定

一般的なサイバー攻撃を特定するためにWindowsイベントIDを利用する包括的なガイドについては、[Red Team Recipe](https://redteamrecipe.com/event-codes/)を参照してください。

#### 総当たり攻撃

複数のEventID 4625レコードによって識別され、攻撃が成功した場合はEventID 4624が続きます。

#### 時間の変更

EventID 4616によって記録され、システム時間の変更はフォレンジック分析を複雑にします。

#### USBデバイストラッキング

USBデバイストラッキングのための有用なシステムイベントIDには、初回使用のための20001/20003/10000、ドライバー更新のための10100、および挿入タイムスタンプのためのDeviceSetupManagerからのEventID 112が含まれます。

#### システム電源イベント

EventID 6005はシステムの起動を示し、EventID 6006はシャットダウンを示します。

#### ログの削除

セキュリティEventID 1102はログの削除を示し、フォレンジック分析にとって重要なイベントです。
