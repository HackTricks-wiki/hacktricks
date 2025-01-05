# BloodHound & Other AD Enum Tools

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) は Sysinternal Suite の一部です：

> 高度な Active Directory (AD) ビューアおよびエディタです。AD Explorer を使用すると、AD データベースを簡単にナビゲートし、お気に入りの場所を定義し、ダイアログボックスを開かずにオブジェクトのプロパティや属性を表示し、権限を編集し、オブジェクトのスキーマを表示し、保存して再実行できる高度な検索を実行できます。

### Snapshots

AD Explorer は AD のスナップショットを作成できるため、オフラインで確認できます。\
オフラインで脆弱性を発見したり、時間の経過に伴う AD DB の異なる状態を比較するために使用できます。

接続するためには、ユーザー名、パスワード、および方向が必要です（任意の AD ユーザーが必要です）。

AD のスナップショットを取得するには、`File` --> `Create Snapshot` に移動し、スナップショットの名前を入力します。

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) は、AD 環境からさまざまなアーティファクトを抽出して統合するツールです。この情報は、分析を容易にし、ターゲット AD 環境の現在の状態の全体像を提供するためのメトリックを含む要約ビューを含む **特別にフォーマットされた** Microsoft Excel **レポート** で提示できます。
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHoundは、[Linkurious](http://linkurio.us/)の上に構築された単一ページのJavascriptウェブアプリケーションで、[Electron](http://electron.atom.io/)でコンパイルされ、C#データコレクターによって供給される[Neo4j](https://neo4j.com/)データベースを持っています。

BloodHoundは、グラフ理論を使用して、Active DirectoryまたはAzure環境内の隠れた、しばしば意図しない関係を明らかにします。攻撃者はBloodHoundを使用して、迅速に特定することが不可能な非常に複雑な攻撃経路を簡単に特定できます。防御者はBloodHoundを使用して、同じ攻撃経路を特定し排除することができます。ブルーチームとレッドチームの両方が、Active DirectoryまたはAzure環境内の特権関係を深く理解するためにBloodHoundを簡単に使用できます。

したがって、[Bloodhound](https://github.com/BloodHoundAD/BloodHound)は、ドメインを自動的に列挙し、すべての情報を保存し、可能な特権昇格経路を見つけ、グラフを使用してすべての情報を表示する素晴らしいツールです。

BloodHoundは、**ingestors**と**visualisation application**の2つの主要な部分で構成されています。

**ingestors**は、**ドメインを列挙し、視覚化アプリケーションが理解できる形式で情報を抽出するために使用されます**。

**visualisation applicationはneo4jを使用して**、すべての情報がどのように関連しているかを示し、ドメイン内で特権を昇格させるさまざまな方法を示します。

### Installation

BloodHound CEの作成後、プロジェクト全体がDockerを使用しやすく更新されました。始める最も簡単な方法は、事前に構成されたDocker Compose構成を使用することです。

1. Docker Composeをインストールします。これは[Docker Desktop](https://www.docker.com/products/docker-desktop/)のインストールに含まれているはずです。
2. 実行します:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Docker Composeのターミナル出力でランダムに生成されたパスワードを見つけます。  
4. ブラウザで http://localhost:8080/ui/login に移動します。ユーザー名にadmin、ログからのランダムに生成されたパスワードでログインします。

その後、ランダムに生成されたパスワードを変更する必要があり、新しいインターフェースが準備されます。そこから直接ingestorsをダウンロードできます。

### SharpHound

いくつかのオプションがありますが、ドメインに参加しているPCからSharpHoundを実行し、現在のユーザーを使用してすべての情報を抽出したい場合は、次のようにできます：
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> **CollectionMethod** とループセッションについては、[こちら](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)で詳しく読むことができます。

異なる資格情報を使用してSharpHoundを実行したい場合は、CMD netonlyセッションを作成し、そこからSharpHoundを実行できます：
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhoundについて詳しく学ぶには、ired.teamをご覧ください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) は、**グループポリシー**に関連するActive Directoryの**脆弱性**を見つけるためのツールです。 \
**任意のドメインユーザー**を使用して、ドメイン内のホストから**group3rを実行する**必要があります。
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **はAD環境のセキュリティ姿勢を評価**し、グラフ付きの素晴らしい**レポート**を提供します。

実行するには、バイナリ`PingCastle.exe`を実行すると、オプションのメニューを表示する**インタラクティブセッション**が開始されます。使用するデフォルトオプションは**`healthcheck`**で、**ドメイン**の**概要**を確立し、**誤設定**や**脆弱性**を見つけます。

{{#include ../../banners/hacktricks-training.md}}
