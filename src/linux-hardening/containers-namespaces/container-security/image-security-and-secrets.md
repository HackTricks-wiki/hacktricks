# Image 보안, Signing 및 Secrets

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Container 보안은 workload가 launch되기 전에 시작됩니다. Image는 어떤 binary, interpreter, library, startup script 및 embedded configuration이 production에 도달하는지를 결정합니다. Image에 backdoor가 삽입되어 있거나 오래되었거나, secrets가 image에 baked in된 상태로 build되었다면 이후에 적용되는 runtime hardening은 이미 compromised된 artifact를 대상으로 작동하게 됩니다.

이 때문에 image provenance, vulnerability scanning, signature verification 및 secret handling은 namespaces 및 seccomp와 함께 다뤄져야 합니다. 이러한 요소는 lifecycle의 서로 다른 단계를 보호하지만, 여기서 발생한 failure가 이후 runtime이 contain해야 하는 attack surface를 결정하는 경우가 많습니다.

## Image Registries 및 Trust

Image는 Docker Hub와 같은 public registry 또는 조직이 운영하는 private registry에서 가져올 수 있습니다. 보안 문제는 단순히 image가 어디에 저장되어 있는지가 아니라, team이 provenance와 integrity를 입증할 수 있는지에 있습니다. public source에서 unsigned 또는 제대로 추적되지 않는 image를 pull하면 malicious하거나 tampered된 content가 production에 유입될 위험이 증가합니다. 내부에서 운영되는 registry도 명확한 ownership, review 및 trust policy가 필요합니다.

Docker Content Trust는 역사적으로 Notary 및 TUF 개념을 사용하여 signed image를 요구했습니다. 정확한 ecosystem은 발전했지만, 지속적으로 유용한 교훈은 다음과 같습니다. Image identity와 integrity는 추정하는 것이 아니라 검증할 수 있어야 합니다.

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
이 예의 요점은 모든 팀이 여전히 동일한 tooling을 사용해야 한다는 것이 아니라, signing과 key management가 추상적인 이론이 아닌 운영 작업이라는 점입니다.

## Vulnerability Scanning

Image scanning은 서로 다른 두 가지 질문에 답하는 데 도움이 됩니다. 첫째, image에 알려진 취약한 package 또는 library가 포함되어 있는가? 둘째, image에 attack surface를 확장하는 불필요한 software가 포함되어 있는가? debugging tool, shell, interpreter 및 오래된 package로 가득 찬 image는 exploit하기도 더 쉽고 파악하기도 더 어렵습니다.

일반적으로 사용되는 scanner의 예는 다음과 같습니다:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
이러한 도구의 결과는 신중하게 해석해야 합니다. 사용되지 않는 package의 vulnerability는 노출된 RCE 경로와 위험도가 동일하지 않지만, 둘 다 hardening 결정과 관련이 있습니다.

## Build-Time Secrets

container build pipeline에서 가장 오래된 실수 중 하나는 secrets를 image에 직접 포함하거나, 나중에 `docker inspect`, build logs 또는 복구된 layers를 통해 노출되는 environment variables로 전달하는 것입니다. Build-time secrets는 image filesystem에 복사하는 대신 build 중에 일시적으로 mount해야 합니다.

BuildKit은 전용 build-time secret 처리를 지원하여 이 모델을 개선했습니다. secret을 layer에 기록하는 대신 build step에서 일시적으로 사용할 수 있습니다:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
이는 image layer가 영구적인 artifact이기 때문에 중요합니다. Secret이 일단 commit된 layer에 들어가면, 이후 다른 layer에서 해당 파일을 삭제하더라도 image history에 남은 최초의 disclosure가 실제로 제거되지는 않습니다.

## Runtime Secrets

실행 중인 workload에 필요한 Secret 역시 가능한 한 plain environment variables와 같은 임시방편 패턴을 피해야 합니다. Volumes, 전용 secret-management 통합, Docker secrets, Kubernetes Secrets가 일반적인 메커니즘입니다. 특히 attacker가 이미 workload에서 code execution 권한을 가진 경우에는 이러한 방법 중 어느 것도 모든 risk를 제거하지 못하지만, credentials를 image에 영구적으로 저장하거나 inspection tooling을 통해 무심코 노출하는 것보다는 여전히 바람직합니다.

간단한 Docker Compose 스타일의 secret 선언은 다음과 같습니다:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
In Kubernetes에서 Secret objects, projected volumes, service-account tokens, cloud workload identities는 더 광범위하고 강력한 모델을 만들지만, host mounts, broad RBAC 또는 취약한 Pod 설계를 통한 accidental exposure의 가능성도 높입니다.

## Abuse

target을 검토할 때의 목표는 secrets가 image에 baked되었는지, layers로 leak되었는지 또는 예측 가능한 runtime locations에 mount되었는지를 확인하는 것입니다:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
이 명령어들은 서로 다른 세 가지 문제를 구분하는 데 도움이 됩니다: 애플리케이션 configuration leak, image-layer leak, runtime에서 주입된 secret 파일입니다. secret이 `/run/secrets`, projected volume 또는 cloud identity token path 아래에 나타난다면, 다음 단계는 해당 secret이 현재 workload에만 접근 권한을 부여하는지, 아니면 훨씬 더 광범위한 control plane에 대한 접근 권한을 부여하는지 파악하는 것입니다.

### 전체 예시: 이미지 파일시스템에 포함된 Secret

build pipeline이 `.env` 파일이나 credential을 최종 이미지에 복사했다면, post-exploitation은 간단해집니다:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
영향은 애플리케이션에 따라 다르지만, 이미지에 포함된 signing key, JWT secret 또는 cloud credential은 컨테이너 compromise를 API compromise, lateral movement 또는 신뢰된 애플리케이션 token 위조로 쉽게 이어지게 할 수 있습니다.

### 전체 예시: Build-Time Secret Leak 점검

이미지 history에 secret이 포함된 layer가 기록된 것이 우려되는 경우:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
이러한 종류의 검토가 유용한 이유는 최종 filesystem view에서는 secret이 삭제되었더라도 이전 layer 또는 build metadata에 여전히 남아 있을 수 있기 때문입니다.

## Checks

이러한 Checks는 runtime 이전에 image 및 secret-handling pipeline이 attack surface를 증가시켰을 가능성이 있는지 확인하기 위한 것입니다.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
여기서 중요한 점:

- 의심스러운 build 기록에는 복사된 credentials, SSH 자료 또는 안전하지 않은 build 단계가 드러날 수 있습니다.
- projected volume 경로 아래의 Secrets는 로컬 애플리케이션 접근뿐 아니라 cluster 또는 cloud 접근으로 이어질 수 있습니다.
- plaintext credentials가 포함된 configuration 파일이 많다면, 일반적으로 image 또는 deployment 모델이 필요 이상으로 많은 trust material을 전달하고 있음을 의미합니다.

## 런타임 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 |
| --- | --- | --- | --- |
| Docker / BuildKit | 보안성이 높은 build-time secret mount를 지원하지만 자동으로 활성화되지는 않음 | `build` 중에 Secrets를 일시적으로 mount할 수 있지만, image signing 및 scanning에는 명시적인 workflow 선택이 필요함 | Secrets를 image에 복사, `ARG` 또는 `ENV`로 Secrets 전달, provenance 검사 비활성화 |
| Podman / Buildah | OCI-native build 및 secret-aware workflow 지원 | 강력한 build workflow를 사용할 수 있지만, 운영자가 이를 의도적으로 선택해야 함 | Containerfile에 Secrets 삽입, 광범위한 build context 사용, build 중 permissive bind mount 사용 |
| Kubernetes | Native Secret object 및 projected volume 제공 | Runtime Secret 전달이 first-class 기능이지만, 노출 여부는 RBAC, pod 설계 및 host mount에 따라 달라짐 | 과도하게 광범위한 Secret mount, service-account token 오용, kubelet이 관리하는 volume에 대한 `hostPath` 접근 |
| Registries | 강제되지 않는 한 integrity는 선택 사항 | Public 및 private registry 모두 policy, signing 및 admission 결정에 의존함 | 서명되지 않은 image를 자유롭게 pull, 취약한 admission control, 부실한 key management |
{{#include ../../../banners/hacktricks-training.md}}
