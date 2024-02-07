# BloodHound & 他のAD Enumツール

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または**PEASSの最新バージョンにアクセス**したいですか？または**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングトリックを共有するために、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) はSysinternal Suiteから：

> 高度なActive Directory（AD）ビューアーおよびエディターです。AD Explorerを使用して、ADデータベースを簡単にナビゲートしたり、お気に入りの場所を定義したり、オブジェクトのプロパティや属性をダイアログボックスを開かずに表示したり、アクセス許可を編集したり、オブジェクトのスキーマを表示したり、保存および再実行できる複雑な検索を実行したりできます。

### スナップショット

AD ExplorerはADのスナップショットを作成してオフラインで確認できます。\
オフラインで脆弱性を発見したり、ADデータベースの異なる状態を比較したりするために使用できます。

ADのスナップショットを取るには、`File` --> `Create Snapshot`に移動し、スナップショットの名前を入力します。

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) は、AD環境からさまざまなアーティファクトを抽出して組み合わせるツールです。情報は、**特別にフォーマットされた**Microsoft Excel **レポート**にまとめられ、分析を容易にし、対象のAD環境の現在の状態の包括的な画像を提供するためのメトリクス付きのサマリービューが含まれています。
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHoundは、埋め込みReactフロントエンドと[Sigma.js](https://www.sigmajs.org/)、[Go](https://go.dev/)ベースのREST APIバックエンドから構成されるモノリシックWebアプリケーションです。[Postgresql](https://www.postgresql.org/)アプリケーションデータベースと[Neo4j](https://neo4j.com)グラフデータベースで展開され、[SharpHound](https://github.com/BloodHoundAD/SharpHound)と[AzureHound](https://github.com/BloodHoundAD/AzureHound)データ収集ツールによってデータが供給されます。
>
>BloodHoundは、グラフ理論を使用してActive DirectoryまたはAzure環境内の隠れた関係や意図しない関係を明らかにします。攻撃者はBloodHoundを使用して、通常素早く特定することが不可能な非常に複雑な攻撃経路を簡単に特定できます。防御者はBloodHoundを使用して、同じ攻撃経路を特定して排除できます。青チームと赤チームの両方が、Active DirectoryまたはAzure環境内の特権関係をより深く理解するのにBloodHoundを使用できます。
>
>BloodHound CEは、[BloodHound Enterprise Team](https://bloodhoundenterprise.io)によって作成および維持されています。元のBloodHoundは、[@\_wald0](https://www.twitter.com/\_wald0)、[@CptJesus](https://twitter.com/CptJesus)、および[@harmj0y](https://twitter.com/harmj0y)によって作成されました。
>
>From [https://github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound)

したがって、[Bloodhound](https://github.com/SpecterOps/BloodHound)は、ドメインを自動的に列挙し、すべての情報を保存し、特権昇格経路を見つけ、グラフを使用してすべての情報を表示できる素晴らしいツールです。

Bloodhoundは、**インジェスタ**と**可視化アプリケーション**の2つの主要な部分で構成されています。

**インジェスタ**は、**ドメインを列挙し、すべての情報を抽出**するために使用されます。

**可視化アプリケーションはneo4jを使用**して、情報がどのように関連しているかを示し、ドメイン内で特権を昇格させるさまざまな方法を示します。

### インストール
BloodHound CEの作成後、プロジェクト全体がDockerを使用した利便性のために更新されました。最も簡単な方法は、事前に構成されたDocker Compose構成を使用することです。

1. Docker Composeをインストールします。これは[Docker Desktop](https://www.docker.com/products/docker-desktop/)のインストールに含まれるはずです。
2. 実行:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Docker Composeのターミナル出力からランダムに生成されたパスワードを見つけます。
4. ブラウザで、http://localhost:8080/ui/login に移動します。ユーザー名をadmin、ログから生成されたランダムなパスワードでログインします。

その後、ランダムに生成されたパスワードを変更する必要があり、新しいインターフェースが準備され、そこから直接インジェスタをダウンロードできます。

### SharpHound

いくつかのオプションがありますが、ドメインに参加したPCからSharpHoundを実行し、現在のユーザーを使用してすべての情報を抽出したい場合は、次のようにします：
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> **CollectionMethod** について詳しくは、[こちら](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained) を参照してください。

異なる資格情報を使用して SharpHound を実行したい場合は、CMD netonly セッションを作成し、そこから SharpHound を実行できます。
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhoundについて詳しくはired.teamをご覧ください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Legacy Bloodhound
### インストール

1. Bloodhound

視覚化アプリケーションをインストールするには、**neo4j**と**bloodhoundアプリケーション**をインストールする必要があります。\
これを行う最も簡単な方法は、次のようにします:
```
apt-get install bloodhound
```
**Neo4jのコミュニティ版**は[こちら](https://neo4j.com/download-center/#community)からダウンロードできます。

1. インジェスタ

以下からインジェスタをダウンロードできます：

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. グラフからのパスの学習

Bloodhoundには、機密性の高い侵害経路を強調するためのさまざまなクエリが付属しています。カスタムクエリを追加して、オブジェクト間の検索と相関関係を強化することが可能です！

このリポジトリには、クエリの素敵なコレクションがあります：https://github.com/CompassSecurity/BloodHoundQueries

インストールプロセス:
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### 可視化アプリの実行

必要なアプリケーションをダウンロード/インストールした後、それらを起動します。\
まず最初に、**neo4jデータベースを起動する必要があります**:
```bash
./bin/neo4j start
#or
service neo4j start
```
最初にこのデータベースを起動する際は、[http://localhost:7474/browser/](http://localhost:7474/browser/) にアクセスする必要があります。デフォルトの資格情報（neo4j:neo4j）が求められ、**パスワードの変更が必要**ですので、変更して忘れないようにしてください。

それでは、**bloodhoundアプリケーション**を起動してください。
```bash
./BloodHound-linux-x64
#or
bloodhound
```
You will be prompted for the database credentials: **neo4j:\<Your new password>**

And bloodhound will be ready to ingest data.

![](<../../.gitbook/assets/image (171) (1).png>)


### **Python bloodhound**

If you have domain credentials you can run a **python bloodhound ingestor from any platform** so you don't need to depend on Windows.\
Download it from [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) or doing `pip3 install bloodhound`
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
もしproxychainsを介して実行している場合は、DNS解決がプロキシを介して機能するように`--dns-tcp`を追加してください。
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

このスクリプトは、LDAPを介してActive Directoryドメインを**静かに列挙**し、ユーザー、管理者、グループなどを解析します。

[**SilentHound github**](https://github.com/layer8secure/SilentHound) で確認してください。

### RustHound

RustでのBloodHound、[**こちらで確認してください**](https://github.com/OPENCYBER-FR/RustHound)。

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) は、Active Directoryに関連する**グループポリシー**で**脆弱性**を見つけるためのツールです。\
**任意のドメインユーザー**を使用して、**ドメイン内のホストからgroup3rを実行する必要があります**。
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

****[**PingCastle**](https://www.pingcastle.com/documentation/) **は、AD環境のセキュリティポストを評価**し、グラフ付きの**レポート**を提供します。

実行するには、バイナリ`PingCastle.exe`を実行し、**インタラクティブセッション**を開始し、オプションのメニューを表示します。使用するデフォルトオプションは**`healthcheck`**で、**ドメイン**のベースライン**概要**を確立し、**設定ミス**と**脆弱性**を見つけます。&#x20;
