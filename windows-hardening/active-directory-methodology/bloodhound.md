# BloodHound & 他のAD Enumツール

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)はSysinternal Suiteから提供されています：

> 高度なActive Directory（AD）ビューアおよびエディターです。AD Explorerを使用して、ADデータベースを簡単にナビゲートしたり、お気に入りの場所を定義したり、オブジェクトのプロパティや属性をダイアログボックスを開かずに表示したり、アクセス許可を編集したり、オブジェクトのスキーマを表示したり、保存および再実行できる高度な検索を実行したりすることができます。

### スナップショット

AD ExplorerはADのスナップショットを作成することができます。\
オフラインでチェックするために使用することができます。\
オフラインで脆弱性を発見したり、AD DBの異なる状態を比較したりすることができます。

スナップショットを取るには、`File` --> `Create Snapshot`に移動し、スナップショットの名前を入力します。

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon)は、AD環境からさまざまなアーティファクトを抽出して組み合わせるツールです。情報は、分析を容易にし、対象のAD環境の現在の状態の包括的なイメージを提供するためのメトリックを含む、**特別にフォーマットされた**Microsoft Excel **レポート**で表示することができます。
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHoundは、[Linkurious](http://linkurio.us)をベースにしたシングルページのJavaScriptウェブアプリケーションで、[Electron](http://electron.atom.io)でコンパイルされ、PowerShellのインジェストツールによって供給される[Neo4j](https://neo4j.com)データベースを使用しています。

> BloodHoundは、グラフ理論を使用してActive Directory環境内の隠れた関係や意図しない関係を明らかにします。攻撃者は、BloodHoundを使用して、通常は素早く特定することができない非常に複雑な攻撃経路を簡単に特定することができます。防御側は、BloodHoundを使用して、同じ攻撃経路を特定し、排除することができます。ブルーチームとレッドチームの両方は、BloodHoundを使用して、Active Directory環境の特権関係をより深く理解することができます。

> BloodHoundは、[\_wald0](https://www.twitter.com/\_wald0)、[@CptJesus](https://twitter.com/CptJesus)、[@harmj0y](https://twitter.com/harmj0y)によって開発されています。

> From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

したがって、[Bloodhound](https://github.com/BloodHoundAD/BloodHound)は、ドメインを自動的に列挙し、すべての情報を保存し、特権エスカレーションの可能な経路を見つけ、グラフを使用してすべての情報を表示することができる素晴らしいツールです。

Bloodhoundは、**インジェストツール**と**可視化アプリケーション**の2つの主要な部分で構成されています。

**インジェストツール**は、ドメインを列挙し、可視化アプリケーションが理解できる形式ですべての情報を抽出するために使用されます。

**可視化アプリケーションはneo4jを使用**して、情報の関連性を表示し、ドメイン内で特権をエスカレーションするための異なる方法を示します。

### インストール

1. Bloodhound

可視化アプリケーションをインストールするには、**neo4j**と**bloodhoundアプリケーション**をインストールする必要があります。\
これを簡単に行う方法は、次のようにします：
```
apt-get install bloodhound
```
**ダウンロード**は[こちら](https://neo4j.com/download-center/#community)から**neo4jのコミュニティ版**をダウンロードできます。

1. インジェスター

インジェスターは以下からダウンロードできます：

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. グラフからパスを学ぶ

Bloodhoundには、機密性の高い侵害経路を強調するためのさまざまなクエリが用意されています。カスタムクエリを追加して、オブジェクト間の検索と相関関係を向上させることも可能です！

このリポジトリには、素晴らしいクエリのコレクションがあります：https://github.com/CompassSecurity/BloodHoundQueries

インストール手順：
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### 可視化アプリの実行

必要なアプリケーションをダウンロード/インストールした後、それらを起動しましょう。\
まず、**neo4jデータベースを起動する必要があります**:
```bash
./bin/neo4j start
#or
service neo4j start
```
初めてこのデータベースを起動する際には、[http://localhost:7474/browser/](http://localhost:7474/browser/) にアクセスする必要があります。デフォルトの資格情報（neo4j:neo4j）が求められ、**パスワードの変更が必要**ですので、変更して忘れないようにしてください。

さて、**bloodhoundアプリケーション**を起動します。
```bash
./BloodHound-linux-x64
#or
bloodhound
```
データベースの資格情報を入力するように求められます: **neo4j:\<新しいパスワード>**

そして、Bloodhoundはデータを取り込む準備ができます。

![](<../../.gitbook/assets/image (171) (1).png>)

### SharpHound

いくつかのオプションがありますが、ドメインに参加しているPCからSharpHoundを実行し、現在のユーザーを使用してすべての情報を抽出する場合は、次のようにします:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> **CollectionMethod**についての詳細は[こちら](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html)で読むことができます。

異なる資格情報を使用してSharpHoundを実行したい場合は、CMD netonlyセッションを作成し、そこからSharpHoundを実行することができます。
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhoundについて詳しくは、ired.teamを参照してください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

**Windows Silent**

### **Python bloodhound**

ドメインの資格情報を持っている場合、**どのプラットフォームからでもPythonのBloodhoundインジェストツールを実行**することができるため、Windowsに依存する必要はありません。\
[https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)からダウンロードするか、`pip3 install bloodhound`を実行してください。
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
もしproxychainsを使って実行している場合は、DNS解決がプロキシを通じて動作するように`--dns-tcp`を追加してください。
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

このスクリプトは、LDAPを介してActive Directoryドメインを**静かに列挙**し、ユーザー、管理者、グループなどを解析します。

[**SilentHoundのgithub**](https://github.com/layer8secure/SilentHound)で確認してください。

### RustHound

Rustで作られたBloodHound、[**こちらで確認してください**](https://github.com/OPENCYBER-FR/RustHound)。

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r)は、Active Directoryに関連する**グループポリシー**の**脆弱性**を見つけるためのツールです。\
**ドメイン内のホストから任意のドメインユーザー**を使用して、group3rを実行する必要があります。
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

****[**PingCastle**](https://www.pingcastle.com/documentation/) **はAD環境のセキュリティポストを評価**し、グラフを含む**素晴らしいレポート**を提供します。

実行するには、バイナリの`PingCastle.exe`を実行し、**対話セッション**が開始され、オプションのメニューが表示されます。使用するデフォルトのオプションは**`healthcheck`**で、**ドメイン**のベースライン**概要**を確立し、**設定ミス**と**脆弱性**を見つけます。&#x20;

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
