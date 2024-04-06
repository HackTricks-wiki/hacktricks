# インタレスティングなWindowsレジストリキー

### インタレスティングなWindowsレジストリキー

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私たちをフォローする [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>


### **Windowsバージョンと所有者情報**
- **`Software\Microsoft\Windows NT\CurrentVersion`**にあるWindowsバージョン、Service Pack、インストール時間、登録所有者の名前が簡単に見つかります。

### **コンピューター名**
- ホスト名は**`System\ControlSet001\Control\ComputerName\ComputerName`**の下にあります。

### **タイムゾーン設定**
- システムのタイムゾーンは**`System\ControlSet001\Control\TimeZoneInformation`**に保存されています。

### **アクセス時間の追跡**
- デフォルトでは、最終アクセス時間の追跡はオフになっています（**`NtfsDisableLastAccessUpdate=1`**）。有効にするには、次のコマンドを使用します：
`fsutil behavior set disablelastaccess 0`

### WindowsバージョンとService Pack
- **Windowsバージョン**はエディション（たとえば、Home、Pro）とリリース（たとえば、Windows 10、Windows 11）を示し、**Service Pack**は修正と時に新機能を含む更新です。

### 最終アクセス時間の有効化
- 最終アクセス時間の追跡を有効にすると、ファイルが最後に開かれた時刻がわかり、フォレンジック分析やシステムモニタリングに重要です。

### ネットワーク情報の詳細
- レジストリには、ネットワーク構成に関する包括的なデータが保存されており、**ネットワークの種類（無線、ケーブル、3G）**や**ネットワークのカテゴリ（Public、Private/Home、Domain/Work）**などが含まれており、ネットワークセキュリティ設定と権限を理解する上で重要です。

### クライアントサイドキャッシュ（CSC）
- **CSC**は共有ファイルのキャッシュを使用してオフラインファイルアクセスを向上させます。異なる**CSCFlags**設定は、どのファイルがどのようにキャッシュされるかを制御し、特に一時的な接続がある環境ではパフォーマンスやユーザーエクスペリエンスに影響します。

### 自動起動プログラム
- `Run`および`RunOnce`レジストリキーにリストされているプログラムは、自動的に起動され、システムの起動時間に影響を与え、マルウェアや不要なソフトウェアの特定に興味を持つポイントになる可能性があります。

### Shellbags
- **Shellbags**はフォルダビューの設定だけでなく、フォルダへのアクセスのフォレンジック証拠も提供します。フォルダがもはや存在しなくても、他の手段では明らかでないユーザーのアクティビティを明らかにするために貴重です。

### USB情報とフォレンジック
- USBデバイスに関するレジストリに保存されている詳細は、コンピューターに接続されたデバイスを追跡するのに役立ち、機密ファイルの転送や不正アクセスのインシデントにデバイスを関連付ける可能性があります。

### ボリュームシリアル番号
- **ボリュームシリアル番号**は、ファイルシステムの特定のインスタンスを追跡するために重要であり、ファイルの起源を異なるデバイス間で確立する必要があるフォレンジックシナリオで役立ちます。

### **シャットダウンの詳細**
- シャットダウン時刻とカウント（XPの場合のみ）は、**`System\ControlSet001\Control\Windows`**および**`System\ControlSet001\Control\Watchdog\Display`**に保存されています。

### **ネットワーク構成**
- 詳細なネットワークインターフェイス情報については、**`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**を参照してください。
- VPN接続を含む最初と最後のネットワーク接続時刻は、**`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**のさまざまなパスにログが記録されます。

### **共有フォルダ**
- 共有フォルダと設定は**`System\ControlSet001\Services\lanmanserver\Shares`**にあります。クライアントサイドキャッシュ（CSC）の設定はオフラインファイルの利用可能性を決定します。

### **自動的に起動するプログラム**
- **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`**などのパスや`Software\Microsoft\Windows\CurrentVersion`の類似エントリには、起動時に実行されるプログラムの詳細が記載されています。

### **検索と入力されたパス**
- エクスプローラーの検索と入力されたパスは、**`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`**のWordwheelQueryおよびTypedPathsの下にレジストリで追跡されます。

### **最近使用したドキュメントとOfficeファイル**
- アクセスした最近のドキュメントとOfficeファイルは、`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`および特定のOfficeバージョンのパスに記録されます。

### **最近使用した（MRU）アイテム**
- 最近のファイルパスとコマンドを示すMRUリストは、`NTUSER.DAT`のさまざまな`ComDlg32`および`Explorer`のサブキーに保存されています。

### **ユーザーアクティビティの追跡**
- ユーザーアシスト機能は、**`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**で、実行回数や最終実行時刻などの詳細なアプリケーション使用統計を記録します。

### **Shellbags分析**
- フォルダアクセスの詳細を明らかにするShellbagsは、`USRCLASS.DAT`および`NTUSER.DAT`の`Software\Microsoft\Windows\Shell`に保存されています。分析には**[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)**を使用してください。

### **USBデバイス履歴**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`**および**`HKLM\SYSTEM\ControlSet001\Enum\USB`**には、接続されたUSBデバイスに関する詳細な情報が含まれており、製造元、製品名、接続時刻などが記載されています。
- 特定のUSBデバイスに関連付けられたユーザーは、デバイスの**{GUID}**を検索して`NTUSER.DAT`ハイブから特定できます。
- 最後にマウントされたデバイスとそのボリュームシリアル番号は、それぞれ`System\MountedDevices`および`Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`を通じて追跡できます。

このガイドは、Windowsシステムでの詳細なシステム、ネットワーク、およびユーザーアクティビティ情報にアクセスするための重要なパスと方法を簡潔かつ使いやすくまとめたものです。
