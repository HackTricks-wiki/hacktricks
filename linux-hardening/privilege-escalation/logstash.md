<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>


# 基本情報

Logstashは、ログの収集、変換、出力に使用されます。これは、入力、フィルター、出力モジュールを含む**パイプライン**を使用して実現されます。サービスは、Logstashをサービスとして実行しているマシンが侵害された場合に興味深くなります。

## パイプライン

パイプライン設定ファイル **/etc/logstash/pipelines.yml** は、アクティブなパイプラインの場所を指定します：
```bash
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
以下には、設定されたパイプラインを含む **.conf** ファイルへのパスが記載されています。**Elasticsearch 出力モジュール**が使用されている場合、**パイプライン**にはElasticsearchインスタンスの有効な**資格情報**が含まれる可能性が高いです。LogstashはElasticsearchにデータを書き込む必要があるため、これらの資格情報はしばしばより多くの権限を持っています。ワイルドカードが使用されている場合、Logstashはそのフォルダ内のワイルドカードに一致するすべてのパイプラインを実行しようとします。

## 書き込み可能なパイプラインを使った権限昇格

自分の権限を昇格させる前に、logstashサービスを実行しているユーザーを確認する必要があります。なぜなら、その後そのユーザーを所有することになるからです。デフォルトでは、logstashサービスは**logstash**ユーザーの権限で実行されます。

以下のいずれかの必要な権限を持っているか確認してください：

* パイプラインの **.conf** ファイルに**書き込み権限**がある **または**
* **/etc/logstash/pipelines.yml** にワイルドカードが含まれており、指定されたフォルダに書き込む権限がある

さらに、以下の要件の**いずれか**を満たす必要があります：

* logstashサービスを再起動できる **または**
* **/etc/logstash/logstash.yml** に **config.reload.automatic: true** のエントリが含まれている

ワイルドカードが指定されている場合、そのワイルドカードに一致するファイルを作成してみてください。以下の内容をファイルに書き込むことでコマンドを実行できます：
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
**インターバル**は秒単位で指定します。この例では、**whoami** コマンドが120秒ごとに実行されます。コマンドの出力は **/tmp/output.log** に保存されます。

もし **/etc/logstash/logstash.yml** に **config.reload.automatic: true** のエントリが含まれている場合、Logstashは新しいパイプライン設定ファイルや既存のパイプライン設定の変更を自動的に認識するので、コマンドが実行されるまで待つだけです。そうでない場合は、logstashサービスを再起動してトリガーしてください。

ワイルドカードが使用されていない場合、既存のパイプライン設定にこれらの変更を適用することができます。**物事を壊さないように注意してください！**

# 参考文献

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには、</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTコレクション**](https://opensea.io/collection/the-peass-family)をチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* **HackTricks**のGitHubリポジトリ[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
