# Windowsのアーティファクト

## Windowsのアーティファクト

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 一般的なWindowsのアーティファクト

### Windows 10の通知

パス `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` には、データベース `appdb.dat` (Windows Anniversaryより前) または `wpndatabase.db` (Windows Anniversary以降) があります。

このSQLiteデータベース内には、興味深いデータを含むすべての通知（XML形式）が含まれる `Notification` テーブルがあります。

### タイムライン

タイムラインは、訪れたウェブページ、編集されたドキュメント、実行されたアプリケーションの**時系列の履歴**を提供するWindowsの特徴です。

データベースはパス `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` にあります。このデータベースはSQLiteツールまたはツール[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)で開くことができます。このツールは、2つのファイルを生成し、ツール[**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md)で開くことができます。

### ADS（Alternate Data Streams）

ダウンロードされたファイルには、イントラネット、インターネットなどからの**ダウンロード方法**を示す**ADS Zone.Identifier**が含まれている場合があります。一部のソフトウェア（ブラウザなど）は、ファイルのダウンロード元の**URL**などの**さらなる情報**を通常含んでいます。

## **ファイルのバックアップ**

### ゴミ箱

Vista/Win7/Win8/Win10では、**ゴミ箱**はドライブのルートにあるフォルダ**`$Recycle.bin`**にあります（`C:\$Recycle.bin`）。
このフォルダでファイルが削除されると、2つの特定のファイルが作成されます：

* `$I{id}`：ファイル情報（削除された日付）
* `$R{id}`：ファイルの内容

![](<../../../.gitbook/assets/image (486).png>)

これらのファイルを使用して、ツール[**Rifiuti**](https://github.com/abelcheung/rifiuti2)を使用して、削除されたファイルの元のアドレスと削除された日付を取得できます（Vista - Win10の場合は`rifiuti-vista.exe`を使用します）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### ボリュームシャドウコピー

シャドウコピーは、使用中のコンピュータファイルやボリュームの**バックアップコピー**またはスナップショットを作成できるMicrosoft Windowsに含まれる技術です。

これらのバックアップは通常、ファイルシステムのルートの`\System Volume Information`にあり、次の画像に示すような**UID**で構成された名前です。

![](<../../../.gitbook/assets/image (520).png>)

**ArsenalImageMounter**を使用してフォレンジックイメージをマウントすると、ツール[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html)を使用してシャドウコピーを検査し、シャドウコピーのバックアップから**ファイルを抽出**することができます。

![](<../../../.gitbook/assets/image (521).png>)

レジストリエントリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`には、**バックアップしない**ファイルとキーが含まれています。

![](<../../../.gitbook/assets/image (522).png>)

レジストリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`には、`Volume Shadow Copies`に関する構成情報も含まれています。

### オフィスの自動保存ファイル

オフィスの自動保存ファイルは、次の場所にあります：`C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## シェルアイテム

シェルアイテムは、別のファイルにアクセスする方法に関する情報を含むアイテムです。

### 最近のドキュメント（LNK）

Windowsは、ユーザーがファイルを**開いたり使用したり作成したりする**ときに、これらの**ショートカット**を**自動的に作成**します。

* Win7-Win10：`C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office：`C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダが作成されると、そのフォルダへのリンク、親フォルダへのリンク、および祖父フォルダへのリンクも作成されます。

これらの自動作成されたリンクファイルには、**ファイル**または**フォルダ**であるか、そのファイルの**MACタイム**、ファイルが保存されている**ボリューム情報**、および**ターゲットファイルのフォルダ**に関する情報が含まれています。これらの情報は、削除された場合にこれらのファイルを回復するのに役立ちます。

また、リンクファイルの**作成日**は、元のファイルが**最初に使用された時間**であり、リンクファイルの**変更日**は、元のファイルが最後に使用された**時間**です。

これらのファイルを検査するには、[**LinkParser**](http://4discovery.com/our-tools/)を使用できます。

このツールでは、**2つのセット**のタイムスタンプが見つかります：

* **最初のセット：**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **2番目のセット：**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

最初のセットのタイムスタンプは、**ファイル自体のタイムスタンプ**を参照します。2番目のセットは、**リンクされたファイルのタイムスタンプ**を参照します。

同じ情報を取得するには、WindowsのCLIツール[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)を実行できます。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
この場合、情報はCSVファイルに保存されます。

### ジャンプリスト

これは、アプリケーションごとに示される最近使用されたファイルのリストです。各アプリケーションでアクセスできる**アプリケーションが使用した最近のファイル**のリストです。これらは**自動的に作成されるか、カスタムで作成**されることがあります。

自動的に作成される**ジャンプリスト**は、`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`に保存されます。ジャンプリストは、初期IDがアプリケーションのIDである`{id}.autmaticDestinations-ms`という形式に従って名前が付けられます。

カスタムジャンプリストは、`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`に保存され、通常はアプリケーションによって作成されます。これは、ファイルに何か**重要なことが起こった**場合に行われることがあります（お気に入りとしてマークされたかもしれません）。

ジャンプリストの**作成時刻**は、ファイルが**最初にアクセスされた時刻**を示し、**変更時刻**は最後のアクセス時刻を示します。

[JumplistExplorer](https://ericzimmerman.github.io/#!index.md)を使用してジャンプリストを調査することができます。

![](<../../../.gitbook/assets/image (474).png>)

（_JumplistExplorerによって提供されるタイムスタンプは、ジャンプリストファイル自体に関連しています_）

### シェルバッグ

[**シェルバッグについては、こちらのリンクを参照してください。**](interesting-windows-registry-keys.md#shellbags)

## Windows USBの使用

USBデバイスが使用されたことを特定することができます。その証拠として以下が作成されます。

* Windowsの最近のフォルダ
* Microsoft Officeの最近のフォルダ
* ジャンプリスト

注意：一部のLNKファイルは、元のパスの代わりにWPDNSEフォルダを指す場合があります。

![](<../../../.gitbook/assets/image (476).png>)

フォルダWPDNSE内のファイルは、元のファイルのコピーです。したがって、PCを再起動するとファイルは残りません。GUIDはシェルバッグから取得されます。

### レジストリ情報

USB接続デバイスに関する興味深い情報が含まれているレジストリキーは、[こちらのページを参照してください。](interesting-windows-registry-keys.md#usb-information)

### setupapi

USB接続が行われたタイムスタンプを取得するには、ファイル`C:\Windows\inf\setupapi.dev.log`を確認します（`Section start`を検索）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)を使用すると、イメージに接続されたUSBデバイスに関する情報を取得できます。

![](<../../../.gitbook/assets/image (483).png>)

### プラグアンドプレイのクリーンアップ

「プラグアンドプレイのクリーンアップ」というスケジュールされたタスクは、古いバージョンのドライバを**クリア**する責任を持っています。オンラインの報告に基づくと、「各ドライバパッケージの最新バージョンが保持される」と説明されているにもかかわらず、30日間使用されていないドライバも削除されるようです。したがって、30日間接続されていないリムーバブルデバイスのドライバが削除される可能性があります。

スケジュールされたタスク自体は、`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`にあり、その内容は以下の通りです：

![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

タスクは、クリーンアップのアクティビティを実行する`pnpclean.dll`を参照しています。また、`UseUnifiedSchedulingEngine`フィールドが`TRUE`に設定されていることがわかります。これは、ジェネリックなタスクスケジューリングエンジンがタスクを管理するために使用されることを指定しています。`MaintenanceSettings`内の`Period`と`Deadline`の値が'P1M'と'P2M'であるため、タスクスケジューラは通常の自動メンテナンス中に1か月に1回タスクを実行し、2か月連続で失敗した場合は緊急の自動メンテナンス中にタスクを実行し始めます。**このセクションは**[**こちらからコピーされました**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)**。**

## メール

メールには、**ヘッダー**とメールの**コンテンツ**の2つの興味深い部分が含まれています。**ヘッダー**には、次のような情報が含まれています。

* メールを送信した**誰**（メールアドレス、IP、メールをリダイレクトしたメールサーバー）
* メールが送信された**時刻**

また、`References`と`In-Reply-To`ヘッダーの中には、メッセージのIDが含まれています。

![](<../../../.gitbook/assets/image (484).png>)

### Windowsメールアプリ

このアプリケーションは、メールをHTMLまたはテキスト形式で保存します。メールは、`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`内のサブフォルダに保存されます。メールは`.dat`拡張子で保存されます。

メールの**メタデータ**と**連絡先**は、**EDBデータベース**内にあります：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

ファイルの拡張子を`.vol`から`.edb`に変更し、ツール[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)を使用して開くことができます。`Message`テーブルの中にメールが表示されます。

### Microsoft Outlook

ExchangeサーバーやOutlookクライアントを使用する場合、いくつかのMAPIヘッダーが表示されます。

* `Mapi-Client-Submit-Time`：メールが送信されたシステムの時刻
* `Mapi-Conversation-Index`：スレッドの子メッセージの数と各メッセージのタイムスタンプ
* `Mapi-Entry-ID`：メッセージの識別子
* `Mappi-Message-Flags`および`Pr_last_Verb-Executed`：MAPIクライアントに関する情報（メッセージを読んだ？読まない？返信済み？リダイレクト済み？外出中？）

Microsoft Outlookクライアントでは、送受信したメッセージ、連絡先データ、カレンダーデータは、
### Outlook OST

Microsoft Outlookが**IMAP**または**Exchange**サーバーを使用して設定されている場合、ほぼ同じ情報を保存する**OST**ファイルが生成されます。このファイルは、**最後の12ヶ月間**サーバーと同期され、**最大ファイルサイズは50GB**で、**PST**ファイルと同じフォルダに保存されます。[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)を使用してこのファイルを検査することができます。

### 添付ファイルの回復

これらのファイルは次のフォルダに見つけることができるかもしれません：

* `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
* `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird**は、**MBOX**ファイルに情報を保存します。これらのファイルは、`\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`フォルダに保存されます。

## サムネイル

ユーザーがフォルダにアクセスし、サムネイルを使用して整理すると、`thumbs.db`ファイルが作成されます。このdbは、削除された場合でも、フォルダの画像のサムネイルを保存します。WinXPおよびWin 8-8.1では、このファイルは自動的に作成されます。Win7/Win10では、UNCパス（\IP\folder...）経由でアクセスされる場合に自動的に作成されます。

ツール[**Thumbsviewer**](https://thumbsviewer.github.io)を使用してこのファイルを読み取ることができます。

### Thumbcache

Windows Vista以降、**サムネイルプレビューはシステム上の集中的な場所に保存**されます。これにより、サムネイルの場所に関する問題が解決され、Thumbs.dbファイルの局所性の問題が解決されます。キャッシュは、**`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`**にいくつかのファイルとして保存されます。これらのファイルには、サイズごとに番号付けされた**thumbcache\_xxx.db**というラベルが付いています。

* Thumbcache\_32.db -> 小
* Thumbcache\_96.db -> 中
* Thumbcache\_256.db -> 大
* Thumbcache\_1024.db -> 特大

ツール[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)を使用してこのファイルを読み取ることができます。

## Windowsレジストリ

Windowsレジストリには、**システムとユーザーのアクションに関する多くの情報**が含まれています。

レジストリを含むファイルは次の場所にあります：

* %windir%\System32\Config\*_SAM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SECURITY\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SYSTEM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SOFTWARE\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_DEFAULT\*_: `HKEY_LOCAL_MACHINE`
* %UserProfile%{User}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

Windows VistaおよびWindows 2008 Server以降では、`HKEY_LOCAL_MACHINE`レジストリファイルのバックアップが**`%Windir%\System32\Config\RegBack\`**にあります。

また、これらのバージョンからは、レジストリファイル**`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`**が作成され、プログラムの実行に関する情報が保存されます。

### ツール

いくつかのツールがレジストリファイルの解析に役立ちます：

* **レジストリエディタ**：Windowsにインストールされています。現在のセッションのWindowsレジストリをナビゲートするためのGUIです。
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：レジストリファイルをロードし、GUIでそれらをナビゲートすることができます。興味深い情報を持つキーをハイライトするブックマークも含まれています。
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：再び、ロードされたレジストリをナビゲートすることができるGUIを持ち、ロードされたレジストリ内の興味深い情報をハイライトするプラグインも含まれています。
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：レジストリから重要な情報を抽出することができる別のGUIアプリケーションです。

### 削除された要素の回復

キーが削除されると、それが削除されたことがマークされますが、そのスペースが必要になるまで削除されません。したがって、**Registry Explorer**などのツールを使用すると、これらの削除されたキーを回復することができます。

### 最終更新時刻

各キーと値には、最後に変更された時刻を示す**タイムスタンプ**が含まれています。

### SAM

ファイル/ハイブ**SAM**には、システムの**ユーザー、グループ、およびユーザーパスワード**のハッシュが含まれています。

`SAM\Domains\Account\Users`には、ユーザー名、RID、最終ログイン、最後の失敗したログオン、ログインカウンター、パスワードポリシー、アカウントの作成日などが含まれています。ハッシュを取得するには、ファイル/ハイブ**SYSTEM**も必要です。

### Windowsレジストリの興味深いエントリ

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## 実行されたプログラム

### 基本的なWindowsプロセス

次のページでは、疑わしい動作を検出するための基本的なWindowsプロセスについて学ぶことができます：

{% content-ref url="windows-processes.md" %}
[windows-processes.md](windows-processes.md)
{% endcontent-ref %}

### Windows最近のアプリ

レジストリの`NTUSER.DAT`内のパス`Software\Microsoft\Current Version\Search\RecentApps`には、**実行されたアプリケーション**、**最後に実行された時間**、**実行回数**に関する情報が含まれているサブキーがあります。

### BAM（Background Activity Moderator）

レジストリエディタで`SYSTEM`ファイルを開き、パス`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`の中には、**各ユーザーが実行したアプリケーション**の情報があります（パス内の`{SID}`に注意してください）。また、**実行された時間**もレジストリのData値の中にあります。

### Windows Prefetch

プリフェッチは、コンピュータがユーザーが**近い将来アクセスする可能性のあるコンテンツ**を表示するために必要なリソースを静かに**取得する**技術であり、リソースにより速くアクセスできるようにします。

Windowsプリフェッチは、実行されたプログラムのキャッシュを作成して、それらをより速くロードできるようにします。これらのキャッシュは、`C:\Windows\Prefetch`パス内に`.pf`ファイルとして作成されます。XP/VISTA/WIN7では128ファイルの制限があり、Win8/Win10では1024ファイルの制限があります。

ファイル名は`{program_name}-{hash}.pf`として作成されます（ハッシュは実行可能ファイルのパスと引数に基づいています）。W10では、これらのファイルは圧縮されます。ファイルの存在のみで、**プログラムが実行された**ことを示しています。

ファイル`C:\Windows\
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### スーパープリフェッチ

**スーパープリフェッチ**は、プリフェッチと同じ目的を持ち、次に読み込まれるものを予測して**プログラムの読み込みを高速化**します。ただし、プリフェッチサービスを置き換えるものではありません。\
このサービスは、`C:\Windows\Prefetch\Ag*.db`にデータベースファイルを生成します。

これらのデータベースには、**プログラムの名前**、**実行回数**、**開かれたファイル**、**アクセスされたボリューム**、**完全なパス**、**時間枠**、および**タイムスタンプ**が含まれています。

この情報には、[**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/)というツールを使用してアクセスできます。

### SRUM

**システムリソース使用モニター**（SRUM）は、**プロセスが消費するリソース**を**監視**します。これはW8に登場し、データは`C:\Windows\System32\sru\SRUDB.dat`にあるESEデータベースに保存されます。

次の情報を提供します：

* AppIDとパス
* プロセスを実行したユーザー
* 送信バイト数
* 受信バイト数
* ネットワークインターフェース
* 接続の期間
* プロセスの期間

この情報は60分ごとに更新されます。

このファイルからデータを取得するには、[**srum\_dump**](https://github.com/MarkBaggett/srum-dump)というツールを使用できます。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache（ShimCache）

**Shimcache**、または**AppCompatCache**は、**Microsoft**によって作成され、オペレーティングシステムがアプリケーションの互換性の問題を特定するために使用する**Application Compatibility Database**のコンポーネントです。

キャッシュは、オペレーティングシステムによって異なるファイルのメタデータを保存します。以下の情報が含まれます。

- ファイルの完全なパス
- ファイルサイズ
- **$Standard\_Information**（SI）の最終更新時刻
- ShimCacheの最終更新時刻
- プロセスの実行フラグ

この情報は、レジストリ内の次の場所にあります。

- `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
- XP（96エントリ）
- `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
- Server 2003（512エントリ）
- 2008/2012/2016 Win7/Win8/Win10（1024エントリ）

この情報を解析するために、[**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser)ツールを使用できます。

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve**ファイルは、実行されたアプリケーションの情報を保存するレジストリファイルです。場所は`C:\Windows\AppCompat\Programas\Amcache.hve`です。

**Amcache.hve**は、実行されたプロセスの最近の履歴を記録し、実行されたプログラムを見つけるために使用されるファイルのパスをリストアップします。また、プログラムのSHA1も記録します。

この情報を解析するために、[**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)ツールを使用できます。
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
最も興味深い生成されたCSVファイルは、「Amcache_Unassociated file entries」です。

### RecentFileCache

このアーティファクトは、W7の`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`にのみ存在し、一部のバイナリの最近の実行に関する情報を含んでいます。

ツール[**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)を使用してファイルを解析できます。

### スケジュールされたタスク

これらは`C:\Windows\Tasks`または`C:\Windows\System32\Tasks`から抽出し、XMLとして読み取ることができます。

### サービス

これらはレジストリの`SYSTEM\ControlSet001\Services`にあります。実行される内容と実行時刻を確認できます。

### **Windowsストア**

インストールされたアプリケーションは`\ProgramData\Microsoft\Windows\AppRepository\`にあります。\
このリポジトリには、データベース**`StateRepository-Machine.srd`**内のシステムにインストールされた**各アプリケーション**の**ログ**があります。

このデータベースのApplicationテーブル内には、「Application ID」、「PackageNumber」、「Display Name」という列があります。これらの列には、プリインストールされたアプリケーションとインストールされたアプリケーションに関する情報が含まれており、インストールされたアプリケーションのIDは連続しているはずです。

また、レジストリパス`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`内には、**インストールされたアプリケーション**が見つかります。\
そして、**アンインストールされたアプリケーション**は`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`にあります。

## Windowsイベント

Windowsイベントに表示される情報は次のとおりです。

* 発生したこと
* タイムスタンプ（UTC + 0）
* 関与したユーザー
* 関与したホスト（ホスト名、IP）
* アクセスされたアセット（ファイル、フォルダ、プリンター、サービス）

ログは、Windows Vistaより前では`C:\Windows\System32\config`に、Windows Vista以降では`C:\Windows\System32\winevt\Logs`にあります。Windows Vistaより前では、イベントログはバイナリ形式であり、それ以降は**XML形式**であり、**.evtx**拡張子を使用します。

イベントファイルの場所は、SYSTEMレジストリの**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**に記載されています。

Windowsイベントビューア（**`eventvwr.msc`**）や[**Event Log Explorer**](https://eventlogxp.com)や[**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)****などの他のツールで表示することができます。

### セキュリティ

これにはアクセスイベントが登録され、セキュリティ設定に関する情報が`C:\Windows\System32\winevt\Security.evtx`に見つかります。

イベントファイルの**最大サイズ**は設定可能であり、最大サイズに達すると古いイベントが上書きされます。

次のように登録されるイベント：

* ログイン/ログオフ
* ユーザーの操作
* ファイル、フォルダ、共有アセットへのアクセス
* セキュリティ設定の変更

ユーザー認証に関連するイベント：

| EventID   | 説明                         |
| --------- | ---------------------------- |
| 4624      | 認証成功                     |
| 4625      | 認証エラー                   |
| 4634/4647 | ログオフ                     |
| 4672      | 管理者権限でのログイン       |

EventID 4634/4647には興味深いサブタイプがあります：

* **2 (interactive)**: キーボードやVNC、`PSexec -U-`などのソフトウェアを使用した対話型のログイン
* **3 (network)**: 共有フォルダへの接続
* **4 (Batch)**: 実行されたプロセス
* **5 (service)**: サービスがサービス制御マネージャーによって開始された
* **6 (proxy):** プロキシログイン
* **7 (Unlock)**: パスワードを使用して画面のロックを解除
* **8 (network cleartext)**: クリアテキストパスワードを送信して認証されたユーザー。このイベントは以前はIISから来ていました
* **9 (new credentials)**: `RunAs`コマンドが使用された場合や、ユーザーが異なる資格情報でネットワークサービスにアクセスした場合に生成されます。
* **10 (remote interactive)**: ターミナルサービスまたはRDPを介した認証
* **11 (cache interactive)**: ドメインコントローラに連絡できなかったため、最後にキャッシュされた資格情報を使用してアクセス
* **12 (cache remote interactive)**: キャッシュされた資格情報を使用してリモートでログイン（10と11の組み合わせ）
* **13 (cached unlock)**: キャッシュされた資格情報を使用してロックされたマシンを解除

この記事では、これらのログインタイプをすべて模倣する方法と、どのログインタイプでメモリから資格情報をダンプできるかを見つけることができます：[https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

イベントのステータスとサブステータス情報は、イベントの原因に関する詳細を示す場合があります。たとえば、Event ID 4625の次のステータスとサブステータスコードを参照してください：

![](<../../../.gitbook/assets/image (455).png>)

### Windowsイベントの回復

Windowsイベントを回復するためには、不審なPCの電源を**抜く**ことを強くお勧めします。削除された場合、[**Bulk\_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor)というツールを使用して回復を試みることができます。拡張子は**evtx**です。

## Windowsイベントでの一般的な攻撃の特定

### ブルートフォース攻撃

ブルートフォース攻撃は、**複数のEventID 4625が表示される**ため、簡単に特定できます。攻撃が**成功した場合**、EventID 4625の後に**EventID 4624が表示されます**。

### 時間の変更

これはフォレンジックチームにとって非常に困難であり、すべてのタイムスタンプが変更されます。このイベントは、セキュリティイベントログ内のEventID 4616に記録されます。

### USBデバイス

次のシステムイベントIDが役立ちます：

* 20001 / 20003 / 10000: 初めて使用されたとき
* 10100: ドライバの更新

DeviceSetupManagerのイベントID 112には、挿入された各USBデバイスのタイムスタ
* [💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、[Twitter](https://twitter.com/hacktricks_live)で私をフォローしてください[🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[@carlospolopm](https://twitter.com/hacktricks\_live)。

* ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。
