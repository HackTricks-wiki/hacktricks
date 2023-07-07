# おもしろいWindowsレジストリキー

## おもしろいWindowsレジストリキー

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## **Windowsシステム情報**

### バージョン

* **`Software\Microsoft\Windows NT\CurrentVersion`**: Windowsのバージョン、Service Pack、インストール時間、登録所有者

### ホスト名

* **`System\ControlSet001\Control\ComputerName\ComputerName`**: ホスト名

### タイムゾーン

* **`System\ControlSet001\Control\TimeZoneInformation`**: タイムゾーン

### 最終アクセス時刻

* **`System\ControlSet001\Control\Filesystem`**: 最終アクセス時刻（デフォルトでは`NtfsDisableLastAccessUpdate=1`で無効化されていますが、`0`の場合は有効です）。
* 有効にするには: `fsutil behavior set disablelastaccess 0`

### シャットダウン時刻

* `System\ControlSet001\Control\Windows`: シャットダウン時刻
* `System\ControlSet001\Control\Watchdog\Display`: シャットダウン回数（XPのみ）

### ネットワーク情報

* **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**: ネットワークインターフェース
* **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed` & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**: ネットワーク接続が行われた最初と最後の時刻、およびVPN経由の接続
* **`Software\Microsoft\WZCSVC\Parameters\Interfaces{GUID}`（XP用） & `Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`**: ネットワークの種類（0x47-ワイヤレス、0x06-ケーブル、0x17-3G）とカテゴリ（0-パブリック、1-プライベート/ホーム、2-ドメイン/ワーク）および最後の接続

### 共有フォルダ

* **`System\ControlSet001\Services\lanmanserver\Shares\`**: 共有フォルダとその設定。**クライアントサイドキャッシュ**（CSCFLAGS）が有効になっている場合、共有ファイルのコピーがクライアントとサーバーの`C:\Windows\CSC`に保存されます。
* CSCFlag=0 -> ユーザーはキャッシュするファイルを指定する必要があります（デフォルト）。
* CSCFlag=16 -> ドキュメントの自動キャッシュ。共有フォルダからユーザーが開くすべてのファイルとプログラムがオフラインで自動的に利用可能になります（「パフォーマンス向上のために最適化」はチェックされていません）。
* CSCFlag=32 -> 前のオプションと同様ですが、「パフォーマンス向上のために最適化」がチェックされています。
* CSCFlag=48 -> キャッシュが無効になっています。
* CSCFlag=2048: この設定はWin 7および8のみで、[「シンプルファイル共有」を無効にするか、「詳細」な共有オプションを使用するまでのデフォルト設定です。また、「ホームグループ」のデフォルト設定のようです。
* CSCFlag=768 -> この設定は共有プリントデバイスでのみ見られました。

### 自動起動プログラム

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `Software\Microsoft\Windows\CurrentVersion\Runonce`
* `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
* `Software\Microsoft\Windows\CurrentVersion\Run`

### エクスプローラーの検索

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordwheelQuery`: エクスプローラー/ヘルパーを使用してユーザーが検索した内容。`MRU=0`の項目が最後の検索です。

### 入力済みパス

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: エクスプローラーでのパスの入力済みタイプ（W10のみ）

### 最近のドキュメント

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: ユーザーが最近開いたドキュメント
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word}\FileMRU`: 最近のOfficeドキュメント。バージョン:
* 14.0 Office 2010
* 12.0 Office 2007
* 11.0 Office 2003
* 10.0 Office X
* `NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word} UserMRU\LiveID_###\FileMRU`: 最近のOfficeドキュメント。バージョン:
* 15.0 Office 2013
* 16.0 Office 2016
### MRUs

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LasVisitedPidlMRU`

実行された実行可能ファイルのパスを示します。

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSaveMRU` (XP)
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\Op enSavePidlMRU`

開かれたウィンドウ内で開かれたファイルを示します。

### 最後に実行されたコマンド

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Policies\RunMR`

### User AssistKey

* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

GUIDはアプリケーションのIDです。保存されるデータ：

* 最後の実行時刻
* 実行回数
* GUIアプリケーション名（絶対パスとその他の情報を含む）
* フォーカス時間とフォーカス名

## Shellbags

ディレクトリを開くと、Windowsはレジストリにディレクトリの表示方法に関するデータを保存します。これらのエントリはShellbagsとして知られています。

エクスプローラアクセス：

* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`

デスクトップアクセス：

* `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
* `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

Shellbagsを分析するには、[**Shellbag Explorer**](https://ericzimmerman.github.io/#!index.md)を使用することができます。これにより、フォルダのMAC時刻と、シェルバッグの作成日時と変更日時（フォルダの最初のアクセス時刻と最後のアクセス時刻に関連する）を見つけることができます。

以下の画像から2つのことに注意してください：

1. **E：**に挿入された**USBのフォルダ名**がわかります。
2. **シェルバッグが作成および変更された**時期と、フォルダが作成およびアクセスされた時期がわかります。

![](<../../../.gitbook/assets/image (475).png>)

## USB情報

### デバイス情報

レジストリ`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`は、PCに接続された各USBデバイスを監視します。\
このレジストリ内で次の情報を見つけることができます：

* メーカー名
* 製品名とバージョン
* デバイスクラスID
* ボリューム名（以下の画像ではボリューム名がハイライトされています）

![](<../../../.gitbook/assets/image (477).png>)

![](<../../../.gitbook/assets/image (479) (1).png>)

さらに、レジストリ`HKLM\SYSTEM\ControlSet001\Enum\USB`をチェックし、サブキーの値を比較することで、VID値を見つけることができます。

![](<../../../.gitbook/assets/image (478).png>)

前の情報を使用して、レジストリ`SOFTWARE\Microsoft\Windows Portable Devices\Devices`から**`{GUID}`**を取得できます。

![](<../../../.gitbook/assets/image (480).png>)

### デバイスを使用したユーザー

デバイスの**{GUID}**を持っている場合、**すべてのユーザーのNTUDER.DATハイブ**をチェックし、GUIDを見つけるまで検索することができます（`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Mountpoints2`）。

![](<../../../.gitbook/assets/image (481).png>)

### 最後にマウントされたデバイス

レジストリ`System\MoutedDevices`をチェックすると、**最後にマウントされたデバイス**がわかります。次の画像では、ツールRegistry Explorerを使用して、`E:`にマウントされた最後のデバイスがToshibaであることがわかります。

![](<../../../.gitbook/assets/image (483) (1) (1).png>)

### ボリュームシリアル番号

`Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`にボリュームシリアル番号が記載されています。**ボリューム名とボリュームシリアル番号を知ることで、その情報を使用するLNKファイルからの情報を関連付ける**ことができます。

USBデバイスがフォーマットされると次のことが行われます：

* 新しいボリューム名が作成されます
* 新しいボリュームシリアル番号が作成されます
* 物理的なシリアル番号は保持されます

### タイムスタンプ

`System\ControlSet001\Enum\USBSTOR{VEN_PROD_VERSION}{USB serial}\Properties{83da6326-97a6-4088-9453-a1923f573b29}\`には、デバイスが接続された最初の時間と最後の時間が記載されています：

* 0064 -- 最初の接続
* 0066 -- 最後の接続
* 0067 -- 切断

![](<../../../.gitbook/assets/image (482).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有する**ために、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>
