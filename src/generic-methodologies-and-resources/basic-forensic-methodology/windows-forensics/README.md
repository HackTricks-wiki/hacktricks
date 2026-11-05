# Windows アーティファクト

{{#include ../../../banners/hacktricks-training.md}}

## Windows の一般的なアーティファクト

### Windows 10 の通知

ユーザーごとの通知データベースは `%LOCALAPPDATA%\Microsoft\Windows\Notifications` にあります（例: `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`）。初期の Windows 10 リリースでは `appdb.dat` が使われていましたが、Anniversary Update (1607) で `wpndatabase.db` が導入されました。SQLite データベースには、通知ペイロードとタイミング情報を含む `Notification` テーブルがあります。ただし、保持期間や利用可能なデータは、リリースやクリーンアップポリシーによって異なります。<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline はアクティビティ履歴機能で、対応アプリケーション、ドキュメント、その他のユーザーアクティビティの記録を含む場合があります。記録範囲は、アプリケーションと Windows のバージョンによって異なります。<sup>[[4]](#references)</sup>

データベースは `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` にあります。SQLite で開くか、[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) で解析できます。出力は [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) で確認できます。<sup>[[4]](#references)[[5]](#references)</sup>

### Windows Recall のスナップショット（Copilot+ PC）

Recall は、対応する Windows 11 Copilot+ PC でオプトイン方式です。現在のビルドでは、スナップショットとそのインデックスは Windows Hello と VBS エンクレーブに紐づいたキーで暗号化されます。ストアのオフラインコピーを平文の SQLite データベースとして扱わないでください。2024 年のプレビュー版とリリース版では、アクセス特性が異なります。<sup>[[77]](#references)</sup>

**Recall が有効なライブセッション**では、同一ユーザーとして動作する `AIXHost.exe` のレンダリングプロセスが別のアクセス手段になります。TotalRecall Reloaded の概念実証では、このプロセスに DLL をインジェクトし、Recall の COM インターフェースを呼び出します。履歴全体の抽出には、引き続きユーザーによる Windows Hello 認証が必要です。これはオフライン復号でも Hello のバイパスでもありません。研究者は Windows 11 ARM64 でこのツールを実証しているため、利用する前に対象ビルドとの互換性を確認してください。<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` は `GetRecentCaptureThumbnail` を使用し、Hello を使わずに最新のキャプチャの高解像度版を要求します。認証後、`--wait` を使うと、スクリーンショット、OCR テキスト、アプリケーションやウィンドウのコンテキストを含むキャプチャごとのメタデータを抽出できます。出力はタイムスタンプ付きの `extraction_*` ディレクトリに保存されます。これらは PoC で確認されたビルド依存の調査結果であり、Recall が有効になっていることや、すべての画面がキャプチャされていることを保証するものではありません。<sup>[[78]](#references)</sup>

### ADS (代替データストリーム)

ローカルの信頼境界外からダウンロードされたファイルには、ゾーン情報を記録する **`Zone.Identifier` 代替データストリーム** が含まれる場合があります。これには URL などの送信元メタデータが含まれることがあります。存在の有無やフィールドは、生成元とシステムポリシーによって異なります。<sup>[[6]](#references)</sup>

## **ファイルのバックアップ**

### ごみ箱

Vista 以降では、ドライブのルートにある **`$Recycle.bin`** フォルダー（例: `C:\$Recycle.bin`）に **ごみ箱** があります。\
このフォルダー内のファイルを削除すると、次の 2 つのファイルが作成されます。

- `$I{id}`: 削除時刻や元のパスなどのファイル情報
- `$R{id}`: ファイルの内容

![ファイルのバックアップ - ごみ箱: $R{id}: ファイルの内容](<../../../images/image (1029).png>)

これらのファイルがあれば、[**Rifiuti2**](https://github.com/abelcheung/rifiuti2) を使って元のパスと削除時刻を抽出できます（対象の Windows リリースに適したバージョンを使用してください）。<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![ファイルバックアップ - ごみ箱: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) は、ファイルの使用中にボリュームの特定時点のシャドウコピーを作成できます。シャドウコピーはフォレンジックイメージの代わりにはなりません。<sup>[[8]](#references)</sup>

コピーのメタデータは通常、ボリュームのルートにある `\System Volume Information` に関連付けられています。識別子はシステムによって異なります。

![ごみ箱 - Volume Shadow Copies: これらのバックアップは通常、ファイルシステムのルートにある System Volume Information に保存され、名前は...に表示された UID で構成されます](<../../../images/image (94).png>)

適切なフォレンジックマウンターでイメージをマウントした後、[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) を使用して、利用可能な VSS スナップショットを列挙し、その中のファイルを閲覧またはコピーできます。<sup>[[9]](#references)</sup>

![ごみ箱 - Volume Shadow Copies: ArsenalImageMounter でフォレンジックイメージをマウントすると、ShadowCopyView を使ってシャドウコピーを調査し、ファイルを抽出することもできます...](<../../../images/image (576).png>)

VSS registry writer の構成には `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` が含まれ、バックアップ対象から除外するファイルやキーを指定できます。<sup>[[10]](#references)[[11]](#references)</sup>

![ごみ箱 - Volume Shadow Copies: レジストリエントリ HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore には、バックアップ対象外のファイルとキーが含まれています](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` キーには、VSS サービスの構成も含まれています。<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover の保存場所は Office アプリケーション、バージョン、構成によって異なります。Word の場合、Microsoft は `%APPDATA%\Microsoft\Word` をデフォルトの保存場所として記載しています。現在の保存先はアプリケーションの設定で確認してください。<sup>[[12]](#references)</sup>

## Shell Items

shell item は、別のファイルへのアクセス方法に関する情報を含む項目です。

### Recent Documents (LNK)

Windows は一般に、ユーザーが項目を開く、またはその他の方法でアクセスすると、最近使った項目へのショートカットを作成します。

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

フォルダーにアクセスすると、そのフォルダーや関連する親フォルダーへのリンクも作成される場合があります。

これらのリンクファイルには、ターゲットの種類、ターゲットの MAC times、ボリューム情報、ターゲットのパスが含まれることがあります。このメタデータは削除されたターゲットの特定に役立つ場合がありますが、その項目が特定のユーザーによって開かれたことの証明にはなりません。<sup>[[13]](#references)[[14]](#references)</sup>

LNK 自体のファイルシステムタイムスタンプと、埋め込まれたターゲットのタイムスタンプは別物です。裏付けとなる他のアーティファクトなしに、リンクの作成を初回使用、リンクの変更を最終使用と解釈しないでください。この形式では、ターゲットのタイムスタンプはリンクファイル自体のタイムスタンプとは別に保存されます。<sup>[[13]](#references)[[14]](#references)</sup>

既存の [**LinkParser**](http://4discovery.com/our-tools/) へのリンクは、過去の選択肢として残していますが、レビュー時にそのドキュメントを確認できませんでした。ドキュメントが整備されたコマンドラインパーサーには、[**LECmd**](https://github.com/EricZimmerman/LECmd) を使用してください。<sup>[[15]](#references)</sup>

これらのツールでは、一般に次の2種類のタイムスタンプが表示されます。

- **ターゲットのタイムスタンプ:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **リンクファイルのタイムスタンプ:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

最初のセットはターゲット、2番目のセットは LNK ファイル自体を指します。パーサーのドキュメントとファイルシステムの状況を踏まえて、両方を解釈してください。<sup>[[14]](#references)[[15]](#references)</sup>

Windows CLI ツール [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) を実行しても、同じ情報を取得できます。<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

この場合、情報はCSVファイルに保存されます。

### Jumplists

Jump Listsは、アプリケーションごとの最近使った項目やタスク固有の項目のリストで、自動またはカスタムで作成されます。<sup>[[13]](#references)</sup>

Automatic Jump Listsは`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`に保存され、`{id}.automaticDestinations-ms`などの名前が付けられます。IDはアプリケーションを識別します。

Custom Jump Listsは`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`に保存されます。アプリケーションが、作成するタスクや項目のエントリを制御します。

ファイルシステムの作成日時と更新日時が示すのはJump Listファイル自体の日時であり、リスト内のすべての対象への初回アクセスや最終アクセスを自動的に示すものではありません。解析したエントリを、ファイルのタイムスタンプや他のアーティファクトと照合してください。<sup>[[13]](#references)</sup>

[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)を使ってJump Listsを調査できます。<sup>[[5]](#references)</sup>

![最近使ったドキュメント（LNK） - Jumplists: JumplistExplorerを使ってJump Listsを調査できます](<../../../images/image (168).png>)

(_JumplistExplorerが示すタイムスタンプは、Jump Listファイル自体に関連する点に注意してください_)

### Shellbags

[**このリンクからShellbagsについて学べます。**](interesting-windows-registry-keys.md#shellbags)

## Windows USBの使用

USBの使用は、リムーバブルメディア上のファイルにアクセスした際に作成される次のようなアーティファクトによって、裏付けられる場合があります。

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com)などのツールは、これらのアーティファクトをUSBデバイスの記録と照合します。ただし、アーティファクトの有無はWindowsのバージョンやアプリケーションによって異なります。<sup>[[18]](#references)</sup>

Windows XPおよびWindows 7のMTPワークフローについて記録されたテストでは、一部のLNKが元のパスではなく`WPDNSE`フォルダーを指していました。<sup>[[16]](#references)</sup>

![Shellbags - Windows USBの使用: 一部のLNKファイルは元のパスではなくWPDNSEフォルダーを指す点に注意してください](<../../../images/image (218).png>)

その調査では、`%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`以下にコピーが作成されていることが確認されました。テストでは一時ファイルは再起動後に残らず、GUIDはShellbagsのデータと照合できました。この挙動はOS、デバイス、アプリケーションによって異なるため、普遍的な規則として扱わないでください。<sup>[[16]](#references)</sup>

### レジストリ情報

[このページで、](interesting-windows-registry-keys.md#usb-information)USB接続デバイスに関する興味深い情報を含むレジストリキーを確認できます。

### setupapi

Vista以降では、デバイスのインストール状況を調べるために`C:\Windows\inf\setupapi.dev.log`を確認してください。セクションヘッダーには`Section start`のタイムスタンプが含まれます。これらはセットアップ処理を記録したものであり、正確な物理的挿入時刻として扱うのではなく、他の接続証拠と照合してください。<sup>[[17]](#references)</sup>

![レジストリ情報 - setupapi: USB接続がいつ行われたかのタイムスタンプを確認するには、ファイルC: Windows inf setupapi.dev.logを調べてください（Section startを検索）](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)を使うと、イメージに接続されたことのあるUSBデバイスの情報を取得できます。<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetectiveを使うと、イメージに接続されたことのあるUSBデバイスの情報を取得できます](<../../../images/image (452).png>)

### Plug and Play Cleanup

`Plug and Play Cleanup`というスケジュールタスクは、古いドライバーのバージョンを削除します。Adam Harrisonが記録したWindows 10のタスク定義では、30日間使用されていないドライバーも対象とされています。そのため、リムーバブルデバイスのドライバーに関する証拠が削除される可能性があります。この挙動を一般化する前に、対象システムのタスク定義とWindowsビルドを確認してください。<sup>[[1]](#references)</sup>

このタスクは次のパスにあります。`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`

![Windows Plug and Play CleanupスケジュールタスクのXML定義](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**タスクの主なコンポーネントと設定:**

- **pnpclean.dll**: 実際のクリーンアップ処理を担うDLLです。
- **UseUnifiedSchedulingEngine**: `TRUE`に設定されており、汎用タスクスケジューリングエンジンを使用することを示します。
- **MaintenanceSettings**:
  - **Period ('P1M')**: 通常の自動メンテナンス中に、タスクスケジューラが毎月クリーンアップタスクを開始するよう指定します。
  - **Deadline ('P2M')**: タスクが2か月連続で失敗した場合、緊急自動メンテナンス中に実行するようタスクスケジューラに指示します。

この設定では定期メンテナンスがスケジュールされ、連続して失敗した場合に再試行されます。正確なXMLと挙動はバージョンによって異なります。<sup>[[1]](#references)</sup>

**詳しくは以下を確認してください:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## メール

メールには、**ヘッダーと本文という2つの重要な部分**があります。**ヘッダー**からは、次のような情報を確認できます。

- メールの**送信者**（メールアドレス、IP、メールを転送したメールサーバー）
- メールの**送信日時**

また、`References`ヘッダーと`In-Reply-To`ヘッダーには、返信を会話に関連付けるためのメッセージIDが含まれる場合があります。<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - メール: メールの送信日時](<../../../images/image (593).png>)

### Windows Mail App

このアプリケーションは、メール本文を補助的なテキストファイルまたはHTMLファイルとして、`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`などのパスに保存します。番号付きフォルダーやファイルの正確な構成は、アーティファクトによって異なる場合があります。<sup>[[75]](#references)</sup>

メールの**メタデータ**と**連絡先**は、**ESEデータベース**`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`にあります。<sup>[[75]](#references)</sup>

`store.vol`はExtensible Storage Engine（ESE）形式を使用します。コピーを使い、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)などのESEパーサーで調査してください。ツールが`.edb`拡張子を必要とする場合はコピーだけをリネームし、`Message`テーブルに依存する前にテーブルスキーマを確認してください。<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

OutlookのMAPIプロパティを調査する際は、次の標準プロパティを確認できます。

- `PidTagClientSubmitTime`: クライアントがメッセージを送信したUTC時刻。
- `PidTagConversationIndex`: 会話スレッド内でのメッセージの相対位置。
- `PidTagEntryId`: メッセージオブジェクトの識別子。
- `PidTagMessageFlags`: 送信済み、既読、未読、添付ファイルの有無などを示すステータスフラグ。
- `PidTagLastVerbExecuted`: 開く、返信する、転送するなど、メッセージに対して最後に記録された操作。<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlookデータファイルの場所は、バージョンやアカウントの種類によって異なります。Microsoftは、PST/OSTファイルの一般的な場所として次を挙げています。

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス`HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`から、Outlookプロファイルと関連するデータファイルの設定を特定できる場合があります。

PSTファイルには、メッセージ、連絡先、予定表データ、その他のOutlookアイテムが含まれることがあります。[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)でコピーを調査できます。<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Kernel PST Viewerツールを使ってPSTファイルを開けます](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OSTファイル**は、ExchangeまたはMicrosoft 365アカウント用のローカルキャッシュです。Cached Exchange ModeはPOPアカウントやIMAPアカウントには適用されません。オフライン期間は設定可能で、デフォルトは通常12か月です。PST/OSTのサイズ制限は、それとは別に設定できる項目です。OSTファイルを表示するには、[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)を利用できます。<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### 添付ファイルの復元

失われた添付ファイルは、次の場所から復元できる可能性があります。

- 旧式のOutlook/IE構成の場合: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- 新しいOutlook/IE11構成の場合: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`。<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird**はプロファイルデータを`%APPDATA%\Thunderbird\Profiles`以下に保存します。メールフォルダーには、アカウントごとの`Mail`または`ImapMail`ディレクトリ内にある、拡張子のないmboxファイルが一般的に使われます。<sup>[[29]](#references)[[30]](#references)</sup>

### 画像のサムネイル

- **Windows XP**: サムネイルプレビューは、フォルダーごとの`thumbs.db`ファイルに保存されることが一般的でした。
- **ネットワークフォルダー**: 該当するサムネイル機能が有効な場合、UNCフォルダーにも`thumbs.db`ファイルが作成されることがあります。すべてのWindowsバージョンやポリシーで作成されると想定しないでください。
- **Windows Vista以降**: システムのサムネイルキャッシュは`%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`以下に一元管理され、**thumbcache_xxx.db**などのファイルが使われます。[**Thumbsviewer**](https://thumbsviewer.github.io)は旧形式の`Thumbs.db`を解析でき、[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)は新しいサムネイルキャッシュデータベースを解析できます。<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windowsレジストリ情報

システムとユーザーの構成データを保存するWindowsレジストリは、次の場所にあるハイブファイルに含まれています。

- `%WINDIR%\System32\Config`: 各種`HKEY_LOCAL_MACHINE`サブキーを支えるコンピューターのハイブ。
- `%USERPROFILE%\NTUSER.DAT`: ユーザーの`HKEY_CURRENT_USER`ハイブ。
- 古いWindowsインストールの一部では、`%WINDIR%\System32\Config\RegBack\`にコピーが保存されています。Windows 10 version 1803以降では、定期バックアップを有効にしない限り、このディレクトリにファイルは自動保存されません。<sup>[[34]](#references)[[35]](#references)</sup>
- 最近のWindowsでは、ユーザーごとのShellおよびクラス登録データも一般に`%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat`に保存されます。<sup>[[34]](#references)[[66]](#references)</sup>

### ツール

レジストリハイブの解析に役立つツールがあります。出力を信頼する前に、各ツールが対応するハイブ形式とバージョンを確認してください。

- **Registry Editor**: Windowsにインストールされています。現在のセッションのWindowsレジストリをGUIで閲覧できます。
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): レジストリファイルを読み込み、GUIで閲覧できます。興味深い情報を含むキーを示すブックマークも用意されています。
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): 読み込んだレジストリを閲覧するためのGUIを備え、読み込んだレジストリ内の興味深い情報を強調表示するプラグインも含まれています。
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): 読み込んだレジストリハイブから情報を抽出できる、もう1つのGUIアプリケーションです。<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### 削除された要素の復元

削除されたハイブセルは、その領域が再利用されるまで残存する場合があります。ただし、復元の可否はハイブの状態やパーサーによって異なります。復元された削除済みキーは、確実な記録ではなく、検証が必要な証拠として扱ってください。

### 最終書き込み時刻

レジストリキーには最終書き込み時刻が記録されます。Windowsが提供するのはキー、またはその値エントリの最終書き込み時刻であり、値に独立した更新時刻があるとは限りません。<sup>[[69]](#references)</sup>

### SAM

**SAM**ハイブには、ローカルユーザーアカウントとグループアカウントのデータが含まれます。これには、システムのboot-key情報で保護されたパスワードハッシュも含まれます。<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users`から、アカウント識別子や一部のログオンおよびポリシー関連フィールドを取得できます。オフラインでハッシュを抽出するには、関連するboot-key情報を復元するために`SYSTEM`ハイブも必要です。<sup>[[38]](#references)[[39]](#references)</sup>

### Windowsレジストリ内の興味深いエントリ


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## 実行されたプログラム

### Windowsの基本的なプロセス

[一般的なWindowsプロセスに関する記事](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)を補足資料として掲載しています。プロセスの挙動に関する主張は、最新のWindowsドキュメントやローカルの証拠と照合してください。<sup>[[2]](#references)</sup>

### Windowsの最近使ったアプリ

この機能を備えたWindows 10のバージョンでは、`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`にアプリケーションごとのサブキーがあり、最終使用時刻や起動回数などのフィールドが含まれます。このアーティファクトは後のリリースで削除されたため、対象ビルドを確認してください。<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Background Activity Moderatorを備えたシステムでは、`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`または新しいパス`...\bam\State\UserSettings\{SID}`を調査してください。値はユーザーSIDごとに記録され、追跡された実行ファイルのパスやFILETIME形式に似た実行データを含む場合があります。このアーティファクトはバージョンによって異なるため、他の証拠と照合してください。<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetchはリソースと起動メタデータをキャッシュし、プログラムをより速く起動できるようにします。

Prefetchファイルは`C:\Windows\Prefetch`に`.pf`ファイルとして保存されます。形式、保持期間、ファイル数の上限はWindowsのバージョンによって異なります。Microsoftの説明では、Windows 8以降は直近8回分の実行時刻と最大1024個のファイルが保持されます。そのため、古い固定上限に関する説明を一般化しないでください。<sup>[[13]](#references)</sup>

ファイル名は一般に`{program_name}-{hash}.pf`という形式で、ハッシュはパスや引数などの実行コンテキストから生成されます。Windows 10以降ではファイルが圧縮される場合があります。ファイルの存在は実行の有用な証拠ですが、それだけでユーザーが実行したことの証明にはならないため、他のアーティファクトと照合してください。<sup>[[13]](#references)</sup>

これらのファイルの調査には[**PECmd.exe**](https://github.com/EricZimmerman/PECmd)を使用できます。このツールは、ディレクトリ解析、CSV/HTML出力、および該当するWindows 10 Prefetchファイルの展開に対応しています。<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** は、過去の使用パターンを利用して読み込みを改善し、Prefetch を補完します。これらのファイルを生成するシステムでは、データベースファイルは通常 `C:\Windows\Prefetch\Ag*.db` にあります。形式とファイルの有無は、Windows のバージョンによって異なります。<sup>[[41]](#references)</sup>

これらのデータベースには、アプリケーション名、使用回数、アクセスされたファイルやボリューム、パス、時間範囲が含まれる場合がありますが、正確な実行ログとして扱うべきではありません。<sup>[[41]](#references)</sup>

既存の [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) のリンクは、パーサーの候補としてそのまま残しています。使用前に、ツールのドキュメントで現在の利用可否と対応する出力形式を確認してください。

### SRUM

**System Resource Usage Monitor** (SRUM) は、アプリケーションとユーザーによるリソース使用状況を記録します。Windows 8 で導入され、ESE データベース `C:\Windows\System32\sru\SRUDB.dat` にデータを保存します。<sup>[[13]](#references)</sup>

以下の情報が得られます。

- AppID と Path
- レコードに関連付けられた User/SID
- 送信バイト数
- 受信バイト数
- ネットワークインターフェイス
- 接続時間
- プロセス実行時間

データ収集の頻度と保持期間は実装によって異なります。すべてのレコードが正確に 60 分間の実行間隔を表すと想定しないでください。<sup>[[13]](#references)</sup>

[**srum_dump**](https://github.com/MarkBaggett/srum-dump) を使ってデータを抽出・確認できます。オプションは、現在のツールバージョンのドキュメントに従ってください。<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**（**ShimCache**とも呼ばれます）は、Windowsのアプリケーション互換性インフラストラクチャの一部であり、互換性判断に使用するファイルメタデータを記録します。ハイブのパス、レコード形式、保持容量、フィールドはWindowsのリリースによって異なります。最新のWindowsでは、ShimCacheだけではユーザーがファイルを実行したことを証明できません。該当する`SYSTEM`ハイブを[**AppCompatCacheParser** tool](https://github.com/EricZimmerman/AppCompatCacheParser)で解析し、その出力を実行痕跡と照合してください。<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): 保存された情報を解析するには、AppCompatCacheParser toolの使用が推奨されます](<../../../images/image (75).png>)

### Amcache

**Amcache.hve**ファイルは、Windowsが確認したアプリケーションとファイルのインベントリを記録するレジストリハイブです。通常、`C:\Windows\AppCompat\Programs\Amcache.hve`にあります。

関連付けられたファイルエントリと関連付けられていないファイルエントリ、パス、SHA1値が含まれる場合がありますが、このファイルの存在はインベントリの証拠であり、それだけでプロセスが実行されたことを証明するものではありません。<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve**を抽出して分析するには、[**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) toolを使用します。このコマンドはハイブを解析し、CSV形式で出力します。<sup>[[44]](#references)</sup>

たとえば:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

生成されたCSVファイルのうち、`Amcache_Unassociated file entries`は、認識済みプログラムに関連付けられていないファイルを調査する際に役立つ場合があります。<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7システムでは、`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`に、最近確認されたバイナリに関する情報が含まれている場合があります。ただし、利用可能かどうかやその意味は、バージョンによって異なります。

[**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser)を使って、このファイルを解析できます。<sup>[[45]](#references)</sup>

### Scheduled tasks

スケジュールされたタスクの証拠は、最新のタスクの場合は`C:\Windows\System32\Tasks`、レガシータスクの場合は`.job`ファイルがある`C:\Windows\Tasks`に見つかることがあります。OSに適したタスク定義形式を確認してください。<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Service Control Managerのデータベースは`SYSTEM\CurrentControlSet\Services`にあります（オフラインのSYSTEM hiveでは、対応するcontrol-setキーを確認してください）。ここには、実行ファイルのパスや開始タイプなど、サービスおよびドライバーの構成が含まれています。<sup>[[72]](#references)</sup>

### **Windows Store**

インストール済みのWindows Storeアプリケーションは、データベース**`StateRepository-Machine.srd`**などを含む`\ProgramData\Microsoft\Windows\AppRepository\`に記録されている場合があります。スキーマとパスはWindowsのリリースによって異なります。<sup>[[71]](#references)</sup>

データベースには、アプリケーション識別子、パッケージ番号、表示名が含まれる場合があります。識別子に欠番があることだけでは、アプリケーションがアンインストールされた証拠にはなりません。パッケージとレジストリの状態を照合してください。

パッケージ登録情報は、`HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`にも存在する場合があります。削除されたプロビジョニング済みアプリについて、Microsoftはバージョン固有の`Deprovisioned`サブキーを説明しています。すべてのビルドに`Deleted`サブキーが存在すると想定しないでください。<sup>[[70]](#references)</sup>

## Windows Events

プロバイダーによっては、Windowsイベントに次の情報が含まれることがあります。

- 何が起きたか
- イベントスキーマとホストの時刻コンテキストに照らして解釈する必要がある`TimeCreated`タイムスタンプ
- 関係したユーザー
- 関係したホスト（ホスト名、IP）
- アクセスされた資産（ファイル、フォルダー、プリンター、サービス）。<sup>[[49]](#references)</sup>

Windows Vistaより前のイベントログは、通常`C:\Windows\System32\config`以下のレガシーなバイナリ形式を使用していました。Vista以降ではWindows Event Log形式が使用され、通常は`C:\Windows\System32\winevt\Logs`以下に`.evtx`ファイルとして保存され、イベントデータはXMLとして表示されます。<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEMレジストリには、**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**以下にチャネル構成が保存されており、設定されたファイルパスや保持設定などが含まれます。<sup>[[47]](#references)</sup>

Windows Event Viewer（**`eventvwr.msc`**）や、[**Event Log Explorer**](https://eventlogxp.com)、[**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)などのツールで表示できます。<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Windows Security Event Loggingの理解

Vista以降では、Securityチャネルは一般に`C:\Windows\System32\winevt\Logs\Security.evtx`に保存されます。最大サイズと保持ポリシーは設定可能です。循環ログの場合、ファイルが上限に達すると古いレコードが上書きされることがあります。関連する監査が有効になっている場合、このチャネルには認証、ログオフ、特権、監査ポリシー、オブジェクトアクセスのイベントが記録されます。<sup>[[46]](#references)[[47]](#references)</sup>

### ユーザー認証に関する主なEvent ID:

- **Event ID 4624**: アカウントへのログオンが成功したことを示します。<sup>[[50]](#references)</sup>
- **Event ID 4625**: アカウントへのログオンが失敗したことを示します。<sup>[[51]](#references)</sup>
- **Event ID 4634**: ログオンセッションが終了したことを示します。<sup>[[52]](#references)</sup>
- **Event ID 4647**: ユーザーがログオフを開始したことを示します。<sup>[[53]](#references)</sup>
- **Event ID 4672**: 新しいログオンに特別な特権が割り当てられたことを示します。システムアカウントや管理者アカウントではよく発生するため、このイベントだけでは悪意ある活動の証拠になりません。<sup>[[54]](#references)</sup>

#### 4624、4625、4634、4647に一般的に記録されるログオンタイプ:

- **Interactive (2)**: 対話型のローカルログオン。
- **Network (3)**: 共有リソースへのアクセス。
- **Batch (4)**: バッチプロセスのログオン。
- **Service (5)**: サービスのログオン。
- **Unlock (7)**: ワークステーションのロック解除。
- **NetworkCleartext (8)**: 認証パッケージに平文の資格情報を渡すネットワークログオン。
- **NewCredentials (9)**: 外向きの接続に、指定された別の資格情報を使用するログオン。
- **RemoteInteractive (10)**: Remote DesktopまたはTerminal Servicesのログオン。
- **CachedInteractive (11)**: キャッシュされたドメイン資格情報を使用する対話型ログオン。
- **CachedRemoteInteractive (12)**: キャッシュされたリモート対話型ログオン。
- **CachedUnlock (13)**: キャッシュされた資格情報を使用するロック解除。<sup>[[50]](#references)[[51]](#references)</sup>

#### EventID 4625のStatusおよびSub Statusコード:

- **0xC0000064**: 該当するユーザーが存在しません。
- **0xC000006A**: ユーザー名は正しいものの、パスワードが間違っています。
- **0xC0000234**: アカウントがロックアウトされています。
- **0xC0000072**: アカウントが無効になっています。
- **0xC000006F**: 許可された時間外のログオンです。
- **0xC0000070**: ワークステーション制限への違反です。
- **0xC0000193**: アカウントの有効期限が切れています。
- **0xC0000071**: パスワードの有効期限が切れています。
- **0xC0000133**: クライアントとサーバーの時刻差が大きすぎます。
- **0xC0000224**: アカウントのパスワード変更が必要です。
- **0xC0000225**: `STATUS_NOT_FOUND`。このコードだけでは、システムのバグや攻撃を特定できません。
- **0xC000015B**: 要求されたログオンタイプが、そのアカウントに許可されていません。<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **時刻変更**: システム時刻が変更されました。多くのイベントは通常の時刻サービスによる補正を反映するため、改ざんと判断する前に、実行者と時刻ソースを照合してください。<sup>[[56]](#references)</sup>

#### Event ID 12、13、1074、6005、6006、6008、6009:

- **電源およびサービスの状況**: Event 12はOSの起動、13はOSのシャットダウン、1074は計画されたシャットダウンまたは再起動、6008は予期しないシャットダウン、6009は起動時のWindowsバージョンを記録します。Event 6005と6006はそれぞれEvent Logサービスの開始と停止を示します。これらのイベントだけでは、OSの起動やシャットダウンの証拠にはなりません。<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **ログの削除**: Event 1102はSecurity監査ログが消去されたことを記録します。このイベントだけで意図を決めつけず、実行者と前後のイベントを調査してください。<sup>[[62]](#references)</sup>

#### USBデバイスの追跡に関するEventID:

- **20001 / 20003**: `UserPnp`のデバイスインストールイベント。初回使用またはインストールの活動を特定する手掛かりになります。
- **10000 / 10100**: デバイスの活動に伴って記録されることがある`DriverFrameworks-UserMode`のイベント。
- **Event ID 112**: 挿入に関連するタイムスタンプを示す場合がある`DeviceSetupManager/Admin`の活動。
- プロバイダー、チャネル、イベントの意味はWindowsのバージョンによって異なります。意味を判断する前に、プロバイダー名とイベントのペイロードを確認してください。<sup>[[59]](#references)</sup>

ログオンタイプと、それに関連する資格情報データの実践例については、[Altered Securityの詳細ガイド](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)を参照してください。<sup>[[60]](#references)</sup>

ログオンタイプ、status、substatus、送信元アドレス、プロセスフィールドなどのイベント詳細は、Event ID 4625の状況を把握する手掛かりになります。statusコードや繰り返される失敗パターンは調査の端緒であり、結論ではありません。<sup>[[51]](#references)[[55]](#references)</sup>

### Windows Eventsの復元

イベントログは一般に循環するため、ロガーによって上書きされたレコードは復元できない場合があります。稼働中のシステムを操作する前に、フォレンジックイメージまたは作業用コピーを保全してください。**Bulk_extractor**などの検証済みパーサーまたはカーバーは、ツールのバージョンが対象の`.evtx`データに対応していることを確認してから使用してください。また、イベントの復元を試すためだけに、稼働中のシステムの電源プラグを抜かないでください。<sup>[[46]](#references)</sup>

### Windows Eventsによる一般的な攻撃の特定

実用的なEvent IDの参照資料については、既存の[Red Team Recipe](https://redteamrecipe.com/event-codes/)のリンクを参照し、上記のプロバイダードキュメントと照らして例を検証してください。

#### Brute Force攻撃

Event ID 4625の繰り返される失敗を、その後の4624成功イベント、ログオンタイプ、status、送信元、アカウントの状況と照合してください。この一連の流れは調査の指標であり、攻撃の証拠ではありません。<sup>[[50]](#references)[[51]](#references)</sup>

#### 時刻変更

Event ID 4616はシステム時刻の変更を記録するため、タイムライン分析が複雑になる場合があります。時刻サービスとホストの証拠を照合してください。<sup>[[56]](#references)</sup>

#### USBデバイスの追跡

USBのEvent IDはプロバイダーによって異なります。`UserPnp`の20001/20003、`DriverFrameworks-UserMode`の10000/10100、`DeviceSetupManager/Admin`の112を、SetupAPIおよびレジストリのアーティファクトと照合してください。<sup>[[17]](#references)[[59]](#references)</sup>

#### システム電源イベント

OSの起動、シャットダウン、再起動、予期しない電源断の状況を把握するには、12/13/1074/6008/6009を使用してください。6005/6006はEvent Logサービスの開始と停止を示します。<sup>[[57]](#references)[[58]](#references)</sup>

#### ログの削除

Security Event ID 1102はSecurity監査ログが消去されたことを記録します。原因となったアカウントおよびプロセスと照合してください。<sup>[[62]](#references)</sup>



## References

- [1] [Windows Plug and Playのクリーンアップ](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - 一般的なWindowsプロセスの調査](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10の通知に関するデジタルフォレンジックの視点](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmermanのフォレンジックツール](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.IdentifierとAlternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSSでのレジストリのバックアップおよび復元操作](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [バックアップと復元用のレジストリキー](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecoverの場所に関するWordのパフォーマンス問題](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [インシデント対応ガイドブック](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Linkバイナリファイル形式](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTPフォレンジック: データ持ち出しアーティファクトの特定](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPIのデバイスインストールログエントリ](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryIDと関連する型](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlookデータファイルの検索と転送](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Modeを有効にする](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [一部のアイテムしか同期されない](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlookデータファイルのサイズ制限を構成する](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [プロファイル - Thunderbirdがユーザーデータを保存する場所](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbirdのアカウント設定とmboxディレクトリ](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCacheインターフェイス](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [レジストリハイブ](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [システムレジストリがRegBackにバックアップされない](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [レジストリをリモートで編集する](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [パスワードの技術概要](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetchの証拠](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [イベントログファイル形式](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlogレジストリキー](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreatedイベントプロパティ](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS値](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [システムイベントログを使用した予期しない再起動のトラブルシューティング](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [処理中のシャットダウンのトラブルシューティング](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10のUSBストレージデバイスフォレンジック](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Windowsのログオンタイプと資格情報の所在](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [バックグラウンドアクティビティモデレーター](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [レジストリ - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook DesktopでPDF添付ファイルのクイック印刷ができなくなる](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windowsレジストリファイル](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [更新中に削除したアプリが再びインストールされないようにする](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTKおよびRegistry Viewerのテスト結果](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [インストール済みサービスのデータベース](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [タスク](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Task Schedulerサービスが利用できないエラーによるスケジュールタスクの失敗](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mailデータベースの調査](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [WindowsクライアントのRecallを管理する](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
