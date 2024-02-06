# インタレスティングなWindowsレジストリキー

## インタレスティングなWindowsレジストリキー

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**か**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する：[**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## **Windowsシステム情報**

### バージョン

- **`Software\Microsoft\Windows NT\CurrentVersion`**: Windowsのバージョン、Service Pack、インストール時間、登録所有者

### ホスト名

- **`System\ControlSet001\Control\ComputerName\ComputerName`**: ホスト名

### タイムゾーン

- **`System\ControlSet001\Control\TimeZoneInformation`**: タイムゾーン

### 最終アクセス時刻

- **`System\ControlSet001\Control\Filesystem`**: 最終アクセス時刻（デフォルトでは`NtfsDisableLastAccessUpdate=1`で無効になっていますが、`0`の場合は有効）。
- 有効にするには：`fsutil behavior set disablelastaccess 0`

### シャットダウン時刻

- `System\ControlSet001\Control\Windows`: シャットダウン時刻
- `System\ControlSet001\Control\Watchdog\Display`: シャットダウン回数（XPのみ）

### ネットワーク情報

- **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: ネットワークインターフェース
- **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: ネットワーク接続が行われた最初と最後の時刻、VPN経由の接続
- **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}`（XP用） & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: ネットワークタイプ（0x47-ワイヤレス、0x06-ケーブル、0x17-3G）とカテゴリ（0-パブリック、1-プライベート/ホーム、2-ドメイン/ワーク）、最終接続

### 共有フォルダ

- **`System\ControlSet001\Services\lanmanserver\Shares\`**: 共有フォルダとその構成。**クライアントサイドキャッシュ**（CSCFLAGS）が有効になっている場合、共有ファイルのコピーがクライアントとサーバーの`C:\Windows\CSC`に保存されます。
- CSCFlag=0 -> ユーザーはデフォルトでキャッシュするファイルを指定する必要があります
- CSCFlag=16 -> ドキュメントの自動キャッシュ。共有フォルダからユーザーが開くすべてのファイルとプログラムが、「パフォーマンスを最適化」のチェックを外して「オフラインで使用可能」になります。
- CSCFlag=32 -> 前のオプションと同様ですが、「パフォーマンスを最適化」のチェックが入っています
- CSCFlag=48 -> キャッシュが無効になっています。
- CSCFlag=2048: この設定はWin 7＆8にのみあり、[「シンプルなファイル共有」を無効にするか、「詳細」共有オプションを使用するまでデフォルトの設定です。また、「ホームグループ」のデフォルト設定のようです。
- CSCFlag=768 -> この設定は共有プリンタデバイスでのみ見られました。

### 自動起動プログラム

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `Software\Microsoft\Windows\CurrentVersion\Runonce`
- `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
- `Software\Microsoft\Windows\CurrentVersion\Run`

### エクスプローラ検索

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`: エクスプローラ/ヘルパーを使用してユーザーが検索した内容。`MRU=0`のアイテムが最後のものです。

### 入力パス

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: エクスプローラで入力されたパス（W10のみ）

### 最近のドキュメント

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: ユーザーが最近開いたドキュメント
- `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word}\FileMRU`:最近のオフィスドキュメント。バージョン：
  - 14.0 Office 2010
  - 12.0 Office 2007
  - 11.0 Office 2003
  - 10.0 Office X
- `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word} UserMRU\LiveID_###\FileMRU`: 最近のオフィスドキュメント。バージョン：
  - 15.0 Office 2013
  - 16.0 Office 2016

### MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

実行された実行可能ファイルのパスを示します

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU`（XP）
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

開かれたウィンドウ内のファイルを示します

### 最後に実行されたコマンド

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### User AssistKey

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

GUIDはアプリケーションのIDです。保存されるデータ：

- 最終実行時刻
- 実行回数
- GUIアプリケーション名（絶対パスなどの情報を含む）
- フォーカス時間とフォーカス名

## Shellbags

ディレクトリを開くと、Windowsはそのディレクトリの視覚化方法に関するデータをレジストリに保存します。これらのエントリはShellbagsとして知られています。

エクスプローラアクセス：

- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

デスクトップアクセス：

- `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

Shellbagsを分析するには、[**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md)を使用でき、フォルダの**MAC時刻**と、フォルダがアクセスされた**最初の時刻と最後の時刻**に関連する**作成日時と変更日時**を見つけることができます。

以下の画像から2つの重要な点を把握してください：

1. **E:に挿入されたUSBのフォルダ名**がわかります
2. **シェルバッグが作成および変更された時刻**とフォルダが作成およびアクセスされた時刻がわかります

![](<../../../.gitbook/assets/image (475).png>)

## USB情報

### デバイス情報

レジストリ`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`はPCに接続された各USBデバイスを監視します。\
このレジストリ内で次の情報を見つけることができます：

- メーカー名
- 製品名とバージョン
- デバイスクラスID
- ボリューム名（次の画像ではハイライトされたサブキーがボリューム名です）

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

さらに、レジストリ`HKLM\SYSTEM\ControlSet001\Enum\USB`をチェックし、サブキーの値を比較することでVID値を見つけることができます。

![](<../../../.gitbook/assets/image (478).png>)

前述の情報を使用して、レジストリ`SOFTWARE\Microsoft\Windows Portable Devices\Devices`から**`{GUID}`**を取得できます：

![](<../../../.gitbook/assets/image (480).png>)

### デバイスを使用したユーザー

デバイスの**{GUID}**を持っていると、**すべてのユーザーのNTUDER.DATハイブをチェック**し、GUIDを検索して、その中の1つで見つかるまで探すことができます（`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`）。

![](<../../../.gitbook/assets/image (481).png>)

### 最後にマウントされたデバイス

レジストリ`System\MoutedDevices`をチェックすると、**最後にマウントされたデバイス**を見つけることができます。次の画像では、`E:`に最後にマウントされたデバイスがToshibaであることがわかります（ツールRegistry Explorerを使用）。

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### ボリュームシリアル番号

`Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`にはボリュームシリアル番号が含まれています。**ボリューム名とボリュームシリアル番号を知ることで、その情報を使用するLNKファイルからの情報を関連付ける**ことができます。

USBデバイスがフォーマットされると：

- 新しいボリューム名が作成されます
- 新しいボリュームシリアル番号が作成されます
- 物理シリアル番号は保持されます

### タイムスタンプ

`System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\`には、デバイスが接続された最初と最後の時刻が記載されています：

- 0064 -- 最初の接続
- 0066 -- 最後の接続
- 0067 -- 切断

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**か**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する：[**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
