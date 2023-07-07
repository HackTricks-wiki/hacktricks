<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したい**ですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


# 基本情報

Logstashはログの収集、変換、出力に使用されます。これは、入力、フィルタ、出力モジュールを含む**パイプライン**を使用して実現されます。Logstashをサービスとして実行しているマシンを侵害した場合、このサービスは興味深くなります。

## パイプライン

パイプラインの設定ファイルである**/etc/logstash/pipelines.yml**は、アクティブなパイプラインの場所を指定します：
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
ここでは、設定されたパイプラインを含む**.conf**ファイルのパスを見つけることができます。**Elasticsearch出力モジュール**が使用されている場合、**パイプライン**にはElasticsearchインスタンスの有効な**資格情報**が含まれる可能性があります。これらの資格情報は、LogstashがElasticsearchにデータを書き込む必要があるため、通常はより高い特権を持っています。ワイルドカードが使用されている場合、Logstashはワイルドカードに一致するそのフォルダにあるすべてのパイプラインを実行しようとします。

## 書き込み可能なパイプラインによる特権昇格

自分の特権を昇格させる前に、logstashサービスを実行しているユーザーを確認する必要があります。なぜなら、それがあなたが後で所有するユーザーになるからです。デフォルトでは、logstashサービスは**logstash**ユーザーの特権で実行されます。

次のいずれかの権限を持っているかどうかを確認してください：

* パイプラインの**.conf**ファイルに**書き込み権限**があるか、
* **/etc/logstash/pipelines.yml**にワイルドカードが含まれており、指定されたフォルダに書き込みが許可されているか

さらに、次のいずれかの要件を満たす必要があります：

* logstashサービスを再起動できるか、
* **/etc/logstash/logstash.yml**にエントリ**config.reload.automatic: true**が含まれているか

ワイルドカードが指定されている場合は、そのワイルドカードに一致するファイルを作成してみてください。以下の内容をファイルに書き込むと、コマンドを実行できます：
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
**interval**は秒単位の時間を指定します。この例では、**whoami**コマンドが120秒ごとに実行されます。コマンドの出力は**/tmp/output.log**に保存されます。

**/etc/logstash/logstash.yml**にエントリ**config.reload.automatic: true**が含まれている場合、コマンドが実行されるまで待つだけで十分です。Logstashは自動的に新しいパイプライン構成ファイルや既存のパイプライン構成の変更を認識します。それ以外の場合は、logstashサービスを再起動してください。

ワイルドカードを使用しない場合、既存のパイプライン構成にこれらの変更を適用することができます。**何かを壊さないように注意してください！**

# 参考文献

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出**してください。

</details>
