# 興味深いWindowsレジストリキー

## 興味深いWindowsレジストリキー

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## **Windowsシステム情報**

### バージョン

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Windowsのバージョン、サービスパック、インストール時間、登録された所有者

### ホスト名

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: ホスト名

### タイムゾーン

* **`System\ControlSet001\Control\TimeZoneInformation`**: タイムゾーン

### 最終アクセス時間

* **`System\ControlSet001\Control\Filesystem`**: 最終アクセス時間（デフォルトでは`NtfsDisableLastAccessUpdate=1`で無効になっていますが、`0`の場合は有効です）。
* 有効にするには: `fsutil behavior set disablelastaccess 0`

### シャットダウン時間

* `System\ControlSet001\Control\Windows`: シャットダウン時間
* `System\ControlSet001\Control\Watchdog\Display`: シャットダウン回数（XPのみ）

### ネットワーク情報

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: ネットワークインターフェース
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: ネットワーク接続が初めて行われた時間と最後の時間、VPNを通じた接続
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}` (XP用) & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: ネットワークタイプ（0x47-無線、0x06-ケーブル、0x17-3G）とカテゴリー（0-パブリック、1-プライベート/ホーム、2-ドメイン/ワーク）および最後の接続

### 共有フォルダ

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: 共有フォルダとその設定。**クライアントサイドキャッシング**（CSCFLAGS）が有効になっている場合、共有ファイルのコピーがクライアントとサーバーの`C:\Windows\CSC`に保存されます
* CSCFlag=0 -> デフォルトではユーザーがキャッシュしたいファイルを指定する必要があります
* CSCFlag=16 -> 自動キャッシングドキュメント。"共有フォルダからユーザーが開いたすべてのファイルとプログラムは、自動的にオフラインで利用可能です"で、"パフォーマンスの最適化"がオフになっています。
* CSCFlag=32 -> 前のオプションと同様ですが、"パフォーマンスの最適化"がオンになっています
* CSCFlag=48 -> キャッシュは無効です。
* CSCFlag=2048: この設定はWin 7 & 8でのみあり、"シンプルファイル共有"を無効にするか、"高度な"共有オプションを使用するまでのデフォルト設定です。また、"ホームグループ"のデフォルト設定でもあるようです。
* CSCFlag=768 -> この設定は共有プリントデバイスでのみ見られました。

### 自動起動プログラム

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### エクスプローラー検索

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`: ユーザーがエクスプローラー/ヘルパーを使用して検索した内容。`MRU=0`の項目が最後のものです。

### 入力されたパス

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: エクスプローラーに入力されたパス（W10のみ）

### 最近のドキュメント

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: ユーザーが最近開いたドキュメント
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word}\FileMRU`: 最近のオフィスドキュメント。バージョン:
* 14.0 Office 2010
* 12.0 Office 2007
* 11.0 Office 2003
* 10.0 Office X
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word} UserMRU\LiveID_###\FileMRU`: 最近のオフィスドキュメント。バージョン:
* 15.0 office 2013
* 16.0 Office 2016

### MRU

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

実行された実行可能ファイルのパスを示します

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU` (XP)
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

開かれたウィンドウ内で開かれたファイルを示します

### 最後に実行されたコマンド

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### User AssistKey

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

GUIDはアプリケーションのIDです。保存されたデータ:

* 最後に実行された時間
* 実行回数
* GUIアプリケーション名（これには絶対パスとその他の情報が含まれます）
* フォーカス時間とフォーカス名

## Shellbags

ディレクトリを開くと、Windowsはレジストリにそのディレクトリを視覚化する方法に関するデータを保存します。これらのエントリはShellbagsとして知られています。

エクスプローラーアクセス:

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

デスクトップアクセス:

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

Shellbagsを分析するには、[**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md)を使用できます。そこでは、フォルダの**MAC時間**と、フォルダが初めてアクセスされた時間と最後にアクセスされた時間に関連するshellbagの作成日と変更日を見つけることができます。

次の画像から2つのことに注意してください:

1. **E:**に挿入されたUSBの**フォルダ名**がわかります
2. **shellbagが作成および変更された時**とフォルダが作成およびアクセスされた時がわかります

![](<../../../.gitbook/assets/image (475).png>)

## USB情報

### デバイス情報

レジストリ`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`は、PCに接続された各USBデバイスを監視します。\
このレジストリ内で見つけることができるのは:

* メーカー名
* 製品名とバージョン
* デバイスクラスID
* ボリューム名（次の画像ではボリューム名は強調表示されたサブキーです）

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

さらに、レジストリ`HKLM\SYSTEM\ControlSet001\Enum\USB`をチェックし、サブキーの値を比較することで、VID値を見つけることができます。

![](<../../../.gitbook/assets/image (478).png>)

前述の情報を使用して、レジストリ`SOFTWARE\Microsoft\Windows Portable Devices\Devices`から**`{GUID}`**を取得できます。

![](<../../../.gitbook/assets/image (480).png>)

### デバイスを使用したユーザー

デバイスの**{GUID}**を持っていると、すべてのNTUDER.DATハイブを**すべてのユーザー**でチェックし、その中の1つでGUIDを見つけるまで検索することができます（`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`）。

![](<../../../.gitbook/assets/image (481).png>)

### 最後にマウントされた

レジストリ`System\MoutedDevices`をチェックすると、**最後にマウントされたデバイス**がどれであるかがわかります。次の画像では、`E:`に最後にマウントされたデバイスがToshibaであることを、ツールRegistry Explorerを使用して確認してください。

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### ボリュームシリアル番号

`Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`では、ボリュームシリアル番号を見つけることができます。**ボリューム名とボリュームシリアル番号を知っていれば、その情報を使用するLNKファイルの情報と相関させることができます**。

USBデバイスがフォーマットされると:

* 新しいボリューム名が作成されます
* 新しいボリュームシリアル番号が作成されます
* 物理的なシリアル番号は保持されます

### タイムスタンプ

`System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\`では、デバイスが接続された最初と最後の時間を見つけることができます:

* 0064 -- 最初の接続
* 0066 -- 最後の接続
* 0067 -- 切断

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
