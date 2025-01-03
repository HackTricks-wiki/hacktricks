# 興味深いWindowsレジストリキー

### 興味深いWindowsレジストリキー

{{#include ../../../banners/hacktricks-training.md}}

### **Windowsバージョンと所有者情報**

- **`Software\Microsoft\Windows NT\CurrentVersion`**に位置し、Windowsのバージョン、サービスパック、インストール時間、登録された所有者の名前が簡潔に表示されます。

### **コンピュータ名**

- ホスト名は**`System\ControlSet001\Control\ComputerName\ComputerName`**の下にあります。

### **タイムゾーン設定**

- システムのタイムゾーンは**`System\ControlSet001\Control\TimeZoneInformation`**に保存されています。

### **アクセス時間の追跡**

- デフォルトでは、最終アクセス時間の追跡はオフになっています（**`NtfsDisableLastAccessUpdate=1`**）。これを有効にするには、次のコマンドを使用します：
`fsutil behavior set disablelastaccess 0`

### Windowsバージョンとサービスパック

- **Windowsバージョン**はエディション（例：Home、Pro）とそのリリース（例：Windows 10、Windows 11）を示し、**サービスパック**は修正や時には新機能を含む更新です。

### 最終アクセス時間の有効化

- 最終アクセス時間の追跡を有効にすると、ファイルが最後に開かれた時刻を確認でき、法医学的分析やシステム監視にとって重要です。

### ネットワーク情報の詳細

- レジストリには、**ネットワークの種類（無線、ケーブル、3G）**や**ネットワークカテゴリ（パブリック、プライベート/ホーム、ドメイン/ワーク）**を含む、ネットワーク構成に関する広範なデータが保持されており、ネットワークセキュリティ設定や権限を理解するために重要です。

### クライアントサイドキャッシング（CSC）

- **CSC**は、共有ファイルのコピーをキャッシュすることでオフラインファイルアクセスを向上させます。異なる**CSCFlags**設定は、どのファイルがどのようにキャッシュされるかを制御し、特に接続が不安定な環境でのパフォーマンスやユーザー体験に影響を与えます。

### 自動起動プログラム

- 様々な`Run`および`RunOnce`レジストリキーにリストされているプログラムは、起動時に自動的に起動され、システムのブート時間に影響を与え、マルウェアや不要なソフトウェアを特定するための興味のあるポイントとなる可能性があります。

### シェルバッグ

- **シェルバッグ**はフォルダビューの設定を保存するだけでなく、フォルダが存在しなくてもフォルダアクセスの法医学的証拠を提供します。これは、他の手段では明らかでないユーザー活動を明らかにするため、調査にとって非常に貴重です。

### USB情報と法医学

- レジストリに保存されたUSBデバイスに関する詳細は、どのデバイスがコンピュータに接続されていたかを追跡するのに役立ち、デバイスを機密ファイル転送や不正アクセスのインシデントに関連付ける可能性があります。

### ボリュームシリアル番号

- **ボリュームシリアル番号**は、ファイルシステムの特定のインスタンスを追跡するのに重要であり、異なるデバイス間でファイルの起源を確立する必要がある法医学的シナリオで役立ちます。

### **シャットダウンの詳細**

- シャットダウン時間とカウント（後者はXPのみ）は、**`System\ControlSet001\Control\Windows`**および**`System\ControlSet001\Control\Watchdog\Display`**に保持されています。

### **ネットワーク構成**

- 詳細なネットワークインターフェース情報については、**`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**を参照してください。
- 最初と最後のネットワーク接続時間（VPN接続を含む）は、**`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**のさまざまなパスに記録されています。

### **共有フォルダ**

- 共有フォルダと設定は**`System\ControlSet001\Services\lanmanserver\Shares`**の下にあります。クライアントサイドキャッシング（CSC）設定はオフラインファイルの可用性を決定します。

### **自動的に起動するプログラム**

- **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`**のようなパスや、`Software\Microsoft\Windows\CurrentVersion`の下の類似のエントリは、起動時に実行されるプログラムを詳細に示しています。

### **検索と入力されたパス**

- エクスプローラーの検索と入力されたパスは、**`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`**の下でWordwheelQueryおよびTypedPathsとして追跡されます。

### **最近の文書とOfficeファイル**

- 最近アクセスされた文書とOfficeファイルは、`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`および特定のOfficeバージョンのパスに記録されています。

### **最も最近使用された（MRU）アイテム**

- 最近のファイルパスやコマンドを示すMRUリストは、`NTUSER.DAT`のさまざまな`ComDlg32`および`Explorer`サブキーに保存されています。

### **ユーザー活動の追跡**

- ユーザーアシスト機能は、実行回数や最終実行時間を含む詳細なアプリケーション使用統計を**`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**に記録します。

### **シェルバッグ分析**

- フォルダアクセスの詳細を明らかにするシェルバッグは、`USRCLASS.DAT`および`NTUSER.DAT`の下の`Software\Microsoft\Windows\Shell`に保存されています。分析には**[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)**を使用してください。

### **USBデバイスの履歴**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`**および**`HKLM\SYSTEM\ControlSet001\Enum\USB`**には、接続されたUSBデバイスに関する豊富な詳細が含まれており、製造元、製品名、接続タイムスタンプが含まれます。
- 特定のUSBデバイスに関連付けられたユーザーは、デバイスの**{GUID}**を検索することで特定できます。
- 最後にマウントされたデバイスとそのボリュームシリアル番号は、それぞれ`System\MountedDevices`および`Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`を通じて追跡できます。

このガイドは、Windowsシステム上の詳細なシステム、ネットワーク、およびユーザー活動情報にアクセスするための重要なパスと方法を要約し、明確さと使いやすさを目指しています。

{{#include ../../../banners/hacktricks-training.md}}
