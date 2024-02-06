# Windows Artifacts

## Windows Artifacts

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は**、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>

## 一般的なWindowsアーティファクト

### Windows 10通知

パス`\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`には、Windows Anniversaryより前の`appdb.dat`またはWindows Anniversary以降の`wpndatabase.db`というデータベースがあります。

このSQLiteデータベース内には、興味深いデータを含む可能性があるすべての通知（XML形式）を含む`Notification`テーブルがあります。

### タイムライン

タイムラインは、訪れたWebページ、編集されたドキュメント、実行されたアプリケーションの**時間順の履歴**を提供するWindowsの特性です。

データベースは、パス`\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`にあります。このデータベースは、SQLiteツールまたは[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)というツールで開くことができ、[**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md)というツールで開くことができる**2つのファイルが生成されます**。

### ADS（代替データストリーム）

ダウンロードされたファイルには、**ADS Zone.Identifier**が含まれており、それがイントラネット、インターネットなどから**どのように**ダウンロードされたかを示しています。一部のソフトウェア（ブラウザなど）は、通常、ファイルがダウンロードされた**URL**などの**さらなる情報**を追加します。

## **ファイルのバックアップ**

### リサイクルビン

Vista/Win7/Win8/Win10では、**リサイクルビン**はドライブのルートにあるフォルダ**`$Recycle.bin`**にあります（`C:\$Recycle.bin`）。

このフォルダでファイルが削除されると、2つの特定のファイルが作成されます：

* `$I{id}`：ファイル情報（削除された日付）
* `$R{id}`：ファイルの内容

![](<../../../.gitbook/assets/image (486).png>)

これらのファイルを使用して、ツール[**Rifiuti**](https://github.com/abelcheung/rifiuti2)を使用して、削除されたファイルの元のアドレスと削除された日付を取得できます（Vista – Win10用に`rifiuti-vista.exe`を使用してください）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### ボリュームシャドウコピー

Shadow Copyは、Microsoft Windowsに含まれる技術で、コンピュータファイルやボリュームの**バックアップコピー**やスナップショットを作成できます。これは、それらが使用中であっても可能です。

これらのバックアップは通常、ファイルシステムのルートにある`\System Volume Information`にあり、名前は以下の画像に示されている**UID**で構成されています:

![](<../../../.gitbook/assets/image (520).png>)

**ArsenalImageMounter**を使用してフォレンジックイメージをマウントすると、ツール[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html)を使用してシャドウコピーを検査し、シャドウコピーのバックアップから**ファイルを抽出**することができます。

![](<../../../.gitbook/assets/image (521).png>)

レジストリエントリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`には、**バックアップしない**ファイルとキーが含まれています:

![](<../../../.gitbook/assets/image (522).png>)

レジストリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`には、`Volume Shadow Copies`に関する構成情報も含まれています。

### Office自動保存ファイル

Officeの自動保存ファイルは、`C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`にあります。

## シェルアイテム

シェルアイテムは、別のファイルにアクセスする方法に関する情報を含むアイテムです。

### 最近のドキュメント（LNK）

Windowsは、ユーザーがファイルを**開いたり使用したり作成したり**すると、これらの**ショートカット**を**自動的に作成**します:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダが作成されると、そのフォルダへのリンク、親フォルダへのリンク、祖父フォルダへのリンクも作成されます。

これら自動的に作成されたリンクファイルには、**ファイル**または**フォルダ**であるか、そのファイルの**MACタイム**、ファイルが保存されている場所の**ボリューム情報**、**ターゲットファイルのフォルダ**が含まれる情報があります。これらの情報は、削除された場合にこれらのファイルを回復するのに役立ちます。

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

USBデバイスが使用されたことを特定することが可能です。これは次のようなものによって作成されます：

- Windows最近使用したフォルダ
- Microsoft Office最近使用したフォルダ
- ジャンプリスト

一部のLNKファイルは、元のパスを指す代わりにWPDNSEフォルダを指します。

![](<../../../.gitbook/assets/image (476).png>)

WPDNSEフォルダ内のファイルは、元のファイルのコピーであり、したがってPCの再起動を行うと消えます。GUIDはシェルバッグから取得されます。

### レジストリ情報

USB接続されたデバイスに関する興味深い情報を含むレジストリキーを確認するには、[このページ](interesting-windows-registry-keys.md#usb-information)を参照してください。

### setupapi

USB接続が行われたタイムスタンプを取得するには、ファイル`C:\Windows\inf\setupapi.dev.log`を確認してください（`Section start`を検索）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)を使用して、接続されたUSBデバイスに関する情報を取得できます。

![](<../../../.gitbook/assets/image (483).png>)
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch**は、prefetchと同じ目標を持ち、**次に読み込まれるものを予測して**プログラムを高速に読み込むことを目指しています。ただし、prefetchサービスを置き換えるものではありません。\
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

**Shimcache**, also known as **AppCompatCache**, is a component of the **Application Compatibility Database**, which was created by **Microsoft** and used by the operating system to identify application compatibility issues.

The cache stores various file metadata depending on the operating system, such as:

* File Full Path
* File Size
* **$Standard\_Information** (SI) Last Modified time
* ShimCache Last Updated time
* Process Execution Flag

This information can be found in the registry in:

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
* XP (96 entries)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
* Server 2003 (512 entries)
* 2008/2012/2016 Win7/Win8/Win10 (1024 entries)

You can use the tool [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) to parse this information.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

The **Amcache.hve** file is a registry file that stores the information of executed applications. It's located in `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** records the recent processes that were run and list the path of the files that are executed which can then be used to find the executed program. It also records the SHA1 of the program.

You can parse this information with the tool [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
最も興味深い生成されたCSVファイルは、`Amcache_Unassociated file entries`です。

### RecentFileCache

このアーティファクトは、`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`内のW7でのみ見つけることができ、いくつかのバイナリの最近の実行に関する情報を含んでいます。

ファイルを解析するために、[**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)ツールを使用できます。

### スケジュールされたタスク

これらは`C:\Windows\Tasks`または`C:\Windows\System32\Tasks`から抽出し、XMLとして読むことができます。

### サービス

これらは`SYSTEM\ControlSet001\Services`のレジストリ内に見つけることができます。実行される内容と実行されるタイミングを確認できます。

### **Windowsストア**

インストールされたアプリケーションは`\ProgramData\Microsoft\Windows\AppRepository\`内に見つけることができます。\
このリポジトリには、データベース内の**`StateRepository-Machine.srd`**という名前の**各アプリケーションのインストール**に関する**ログ**が含まれています。

このデータベースのApplicationテーブル内には、"Application ID"、"PackageNumber"、"Display Name"という列があります。これらの列には、プリインストールされたアプリケーションとインストールされたアプリケーションに関する情報が含まれており、インストールされたアプリケーションのIDは連続しているはずです。

また、レジストリパス内に**インストールされたアプリケーション**を見つけることも可能です：`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
そして**アンインストールされたアプリケーション**はこちらにあります：`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windowsイベント

Windowsイベント内に表示される情報は以下の通りです：

* 何が起こったか
* タイムスタンプ（UTC + 0）
* 関与するユーザー
* 関与するホスト（ホスト名、IP）
* アクセスされたアセット（ファイル、フォルダ、プリンター、サービス）

ログは、Windows Vistaより前では`C:\Windows\System32\config`に、Windows Vista以降では`C:\Windows\System32\winevt\Logs`にあります。Windows Vistaより前では、イベントログはバイナリ形式であり、その後は**XML形式**であり、**.evtx**拡張子を使用します。

イベントファイルの場所は、SYSTEMレジストリ内の**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**にあります。

Windowsイベントビューアー（**`eventvwr.msc`**）や[**Event Log Explorer**](https://eventlogxp.com) **や** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**などの他のツールで**これらを視覚化できます。**

### セキュリティ

これはアクセスイベントを登録し、セキュリティ構成に関する情報を提供します。これは`C:\Windows\System32\winevt\Security.evtx`に見つけることができます。

イベントファイルの**最大サイズ**は設定可能であり、最大サイズに達すると古いイベントを上書きし始めます。

登録されるイベントには以下があります：

* ログイン/ログオフ
* ユーザーのアクション
* ファイル、フォルダ、共有アセットへのアクセス
* セキュリティ構成の変更

ユーザー認証に関連するイベント：

| EventID   | Description                  |
| --------- | ---------------------------- |
| 4624      | 認証成功    |
| 4625      | 認証エラー         |
| 4634/4647 | ログオフ                      |
| 4672      | 管理者権限でのログイン |

EventID 4634/4647には興味深いサブタイプがあります：

* **2 (interactive)**: キーボードやVNC、`PSexec -U-`などのソフトウェアを使用して対話的にログインされた
* **3 (network)**: 共有フォルダへの接続
* **4 (Batch)**: 実行されたプロセス
* **5 (service)**: サービスがサービス制御マネージャによって開始された
* **6 (proxy):** プロキシログイン
* **7 (Unlock)**: パスワードを使用して画面のロックを解除
* **8 (network cleartext)**: ユーザーがクリアテキストパスワードを送信して認証された。このイベントは以前はIISから来ていました
* **9 (new credentials)**: `RunAs`コマンドが使用された場合や、ユーザーが異なる資格情報でネットワークサービスにアクセスした場合に生成されます。
* **10 (remote interactive)**: ターミナルサービスやRDPを介した認証
* **11 (cache interactive)**: ドメインコントローラに連絡できなかったため、最後にキャッシュされた資格情報を使用してアクセスされた
* **12 (cache remote interactive)**: キャッシュされた資格情報を使用してリモートでログイン（10と11の組み合わせ）
* **13 (cached unlock)**: キャッシュされた資格情報を使用してロックされたマシンをアンロック

この投稿では、これらのログインタイプをすべて模倣し、どれでメモリから資格情報をダンプできるかを見つけることができます：[https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

イベントのステータスとサブステータス情報は、イベントの原因に関する詳細を示すことができます。たとえば、Event ID 4625の次のステータスとサブステータスコードを見てみてください：

![](<../../../.gitbook/assets/image (455).png>)

### Windowsイベントの回復

Windowsイベントを回復するためには、疑わしいPCの電源を**抜く**ことを強くお勧めします。削除された場合、[**Bulk\_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor)というツールが役立つ可能性があります。**evtx**拡張子を指定しています。

## Windowsイベントでの一般的な攻撃の特定

* [https://redteamrecipe.com/event-codes/](https://redteamrecipe.com/event-codes/)

### ブルートフォース攻撃

ブルートフォース攻撃は、**複数のEventID 4625が表示**されるため、簡単に特定できます。攻撃が**成功した**場合、EventID 4624の後に**EventID 4624が表示**されます。

### 時間の変更

これはフォレンジックチームにとって非常に困難であり、すべてのタイムスタンプが変更されます。このイベントは、セキュリティイベントログ内のEventID 4616によって記録されます。

### USBデバイス

次のSystem EventIDsが役立ちます：

* 20001 / 20003 / 10000: 初めて使用された時
* 10100: ドライバーの更新

DeviceSetupManagerのEventID 112には、挿入された各USBデバイスのタイムスタンプが含まれています。

### 電源のオフ / オン

"Event Log"サービスのID 6005はPCがオンになったことを示します。ID 6006はPCがオフになったことを示します。

### ログの削除

セキュリティEventID 1102は、ログが削除されたことを示します。
