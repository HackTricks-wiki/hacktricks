# BloodHound & Other AD Enum Tools

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社を宣伝**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、ハッキングのコツを共有してください。**

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)はSysinternal Suiteからのものです：

> AD Explorerは、高度なActive Directory (AD) ビューアおよびエディタです。AD Explorerを使用して、ADデータベースを簡単にナビゲートし、お気に入りの場所を定義し、ダイアログボックスを開かずにオブジェクトのプロパティや属性を表示し、権限を編集し、オブジェクトのスキーマを表示し、保存して再実行できる洗練された検索を実行できます。

### スナップショット

AD ExplorerはADのスナップショットを作成できるため、オフラインでチェックできます。\
これは、オフラインで脆弱性を発見するため、または時間をかけてAD DBの異なる状態を比較するために使用できます。

ユーザー名、パスワード、接続先の指示が必要になります（任意のADユーザーが必要です）。

ADのスナップショットを撮るには、`File` --> `Create Snapshot`に移動し、スナップショットに名前を入力します。

## ADRecon

****[**ADRecon**](https://github.com/adrecon/ADRecon)は、AD環境から様々なアーティファクトを抽出し組み合わせるツールです。この情報は、分析を容易にし、対象のAD環境の現状を全体的に把握するための指標を含む要約ビューで、特別にフォーマットされたMicrosoft Excel **レポート**に表示されます。
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHoundは、組み込みのReactフロントエンドと[Sigma.js](https://www.sigmajs.org/)、[Go](https://go.dev/)ベースのREST APIバックエンドで構成された一枚岩のウェブアプリケーションです。[Postgresql](https://www.postgresql.org/)アプリケーションデータベースと[Neo4j](https://neo4j.com)グラフデータベースを使用してデプロイされ、[SharpHound](https://github.com/BloodHoundAD/SharpHound)と[AzureHound](https://github.com/BloodHoundAD/AzureHound)のデータコレクターによってデータが供給されます。
>
>BloodHoundはグラフ理論を使用して、Active DirectoryまたはAzure環境内の隠された、しばしば意図しない関係を明らかにします。攻撃者はBloodHoundを使用して、それ以外ではすぐに特定することが不可能な非常に複雑な攻撃パスを簡単に特定できます。防御者はBloodHoundを使用して、それらの攻撃パスを特定し排除することができます。青チームと赤チームの両方がBloodHoundを使用して、Active DirectoryまたはAzure環境の特権関係をより深く理解することができます。
>
>BloodHound CEは[BloodHound Enterprise Team](https://bloodhoundenterprise.io)によって作成および維持されています。オリジナルのBloodHoundは[@\_wald0](https://www.twitter.com/\_wald0)、[@CptJesus](https://twitter.com/CptJesus)、[@harmj0y](https://twitter.com/harmj0y)によって作成されました。
>
>[https://github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound)より

[Bloodhound](https://github.com/SpecterOps/BloodHound)は、ドメインを自動的に列挙し、すべての情報を保存し、潜在的な特権昇格パスを見つけ、グラフを使用してすべての情報を表示することができる素晴らしいツールです。

Booldhoundは、**インジェスタ**と**視覚化アプリケーション**の2つの主要な部分で構成されています。

**インジェスタ**は、**ドメインを列挙し、視覚化アプリケーションが理解できる形式ですべての情報を抽出するために使用されます**。

**視覚化アプリケーションはneo4jを使用して**、すべての情報がどのように関連しているか、およびドメイン内での特権昇格の異なる方法を表示します。

### インストール
BloodHound CEの作成後、Dockerを使用して使いやすくするためにプロジェクト全体が更新されました。始める最も簡単な方法は、事前に設定されたDocker Compose構成を使用することです。

1. Docker Composeをインストールします。これは[Docker Desktop](https://www.docker.com/products/docker-desktop/)のインストールに含まれているはずです。
2. 実行：
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Docker Composeのターミナル出力でランダムに生成されたパスワードを見つけます。
4. ブラウザでhttp://localhost:8080/ui/loginに移動します。ユーザー名にadminと入力し、ログから取得したランダムに生成されたパスワードでログインします。

これを行った後、ランダムに生成されたパスワードを変更する必要があり、新しいインターフェースが準備されます。そこから直接インジェスターをダウンロードできます。

### SharpHound

いくつかのオプションがありますが、ドメインに参加しているPCからSharpHoundを実行し、現在のユーザーを使用してすべての情報を抽出したい場合は次のようにします：
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> **CollectionMethod**とループセッションについての詳細は[こちら](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)で読むことができます。

異なる資格情報を使用してSharpHoundを実行したい場合は、CMD netonlyセッションを作成し、そこからSharpHoundを実行できます：
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhoundについてもっと学ぶにはired.teamをご覧ください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## レガシーBloodhound
### インストール

1. Bloodhound

視覚化アプリケーションをインストールするには、**neo4j**と**bloodhoundアプリケーション**をインストールする必要があります。\
これを行う最も簡単な方法は次の通りです:
```
apt-get install bloodhound
```
```markdown
**neo4jのコミュニティバージョンは[こちら](https://neo4j.com/download-center/#community)からダウンロードできます。**

1. インジェスター

インジェスターは以下からダウンロードできます：

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. グラフからパスを学ぶ

Bloodhoundには、機密性の高い侵害パスを強調表示するための様々なクエリが含まれています。カスタムクエリを追加して、オブジェクト間の検索と相関を強化することも可能です！

このリポジトリにはクエリの素晴らしいコレクションがあります：https://github.com/CompassSecurity/BloodHoundQueries

インストールプロセス：
```
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### 可視化アプリの実行

必要なアプリケーションをダウンロード/インストールした後、それらを開始しましょう。\
まず最初に、**neo4jデータベースを起動する**必要があります：
```bash
./bin/neo4j start
#or
service neo4j start
```
データベースを初めて起動する際には、[http://localhost:7474/browser/](http://localhost:7474/browser/)にアクセスする必要があります。デフォルトの資格情報（neo4j:neo4j）が求められ、**パスワードの変更が必須**となりますので、変更して忘れないようにしてください。

次に、**bloodhoundアプリケーション**を起動します：
```bash
./BloodHound-linux-x64
#or
bloodhound
```
データベースの資格情報を求められます: **neo4j:\<あなたの新しいパスワード>**

そしてbloodhoundはデータの取り込みの準備ができます。

![](<../../.gitbook/assets/image (171) (1).png>)

### **Python bloodhound**

ドメイン資格情報を持っている場合、Windowsに依存することなく、**任意のプラットフォームからpython bloodhoundインジェスターを実行**できます。
[https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) からダウンロードするか、`pip3 install bloodhound`を実行します。
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
プロキシチェーンを通して実行する場合は、プロキシを介したDNS解決が機能するように `--dns-tcp` を追加してください。
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

このスクリプトは、LDAPを通じて**静かにActive Directoryドメインを列挙**し、ユーザー、管理者、グループなどを解析します。

[**SilentHound github**](https://github.com/layer8secure/SilentHound)でチェックしてください。

### RustHound

Rustで書かれたBloodHound、[**こちらをチェック**](https://github.com/OPENCYBER-FR/RustHound)。

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) **** は、Active Directoryに関連する**グループポリシー**の**脆弱性**を見つけるツールです。\
ドメイン内のホストから**任意のドメインユーザー**を使用して**group3rを実行**する必要があります。
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

**[**PingCastle**](https://www.pingcastle.com/documentation/)** はAD環境のセキュリティ状態を評価し、グラフ付きの詳細な**レポート**を提供します。

実行するには、バイナリ `PingCastle.exe` を実行すると、オプションのメニューが表示される**インタラクティブセッション**が開始されます。デフォルトオプションは **`healthcheck`** で、**ドメイン**の基本的な**概要**を確立し、**誤設定**と**脆弱性**を見つけます。&#x20;

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したり、**HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを手に入れましょう。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手しましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
