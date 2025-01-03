{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash는 **로그를 수집, 변환 및 전송**하는 데 사용되는 시스템인 **파이프라인**을 통해 작동합니다. 이러한 파이프라인은 **입력**, **필터**, 및 **출력** 단계로 구성됩니다. Logstash가 손상된 머신에서 작동할 때 흥미로운 측면이 발생합니다.

### Pipeline Configuration

파이프라인은 **/etc/logstash/pipelines.yml** 파일에서 구성되며, 여기에는 파이프라인 구성의 위치가 나열됩니다:
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
이 파일은 파이프라인 구성 정보를 포함하는 **.conf** 파일이 어디에 위치하는지를 보여줍니다. **Elasticsearch output module**을 사용할 때, **pipelines**에 **Elasticsearch credentials**가 포함되는 것이 일반적이며, 이는 Logstash가 Elasticsearch에 데이터를 쓰기 위해 필요한 권한이 광범위하기 때문입니다. 구성 경로의 와일드카드는 Logstash가 지정된 디렉토리에서 모든 일치하는 파이프라인을 실행할 수 있도록 합니다.

### 쓰기 가능한 파이프라인을 통한 권한 상승

권한 상승을 시도하려면 먼저 Logstash 서비스가 실행 중인 사용자를 식별해야 하며, 일반적으로 **logstash** 사용자입니다. 다음 기준 중 **하나**를 충족해야 합니다:

- 파이프라인 **.conf** 파일에 **쓰기 권한**을 가지고 있거나
- **/etc/logstash/pipelines.yml** 파일이 와일드카드를 사용하고, 대상 폴더에 쓸 수 있는 경우

또한, 다음 조건 중 **하나**를 충족해야 합니다:

- Logstash 서비스를 재시작할 수 있는 능력 **또는**
- **/etc/logstash/logstash.yml** 파일에 **config.reload.automatic: true**가 설정되어 있는 경우

구성에 와일드카드가 주어지면, 이 와일드카드와 일치하는 파일을 생성하여 명령을 실행할 수 있습니다. 예를 들어:
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
여기서, **interval**은 초 단위로 실행 빈도를 결정합니다. 주어진 예에서 **whoami** 명령은 120초마다 실행되며, 그 출력은 **/tmp/output.log**로 전송됩니다.

**/etc/logstash/logstash.yml**에 **config.reload.automatic: true**가 설정되어 있으면, Logstash는 자동으로 새로운 또는 수정된 파이프라인 구성을 감지하고 적용하며, 재시작이 필요하지 않습니다. 와일드카드가 없으면 기존 구성에 대한 수정이 여전히 가능하지만, 중단을 피하기 위해 주의가 필요합니다.

## References

{{#include ../../banners/hacktricks-training.md}}
