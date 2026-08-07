# Image 보안, Signing 및 Secrets

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Container 보안은 workload가 시작되기 전에 시작됩니다. Image는 어떤 binaries, interpreters, libraries, startup scripts 및 embedded configuration이 production에 도달하는지를 결정합니다. Image에 backdoor가 삽입되어 있거나, 오래되었거나, secrets가 image에 직접 포함된 상태로 build되었다면 이후에 적용되는 runtime hardening은 이미 compromised artifact를 대상으로 동작하게 됩니다.

이 때문에 image provenance, vulnerability scanning, signature verification 및 secret handling은 namespaces 및 seccomp와 함께 다루어야 합니다. 이러한 요소들은 lifecycle의 서로 다른 단계를 보호하지만, 이 단계에서 발생한 문제는 runtime이 이후에 제한해야 하는 attack surface를 결정하는 경우가 많습니다.

## Image Registries 및 Trust

Images는 Docker Hub와 같은 public registries에서 가져오거나, 조직이 운영하는 private registries에서 가져올 수 있습니다. 보안상 중요한 질문은 단순히 image가 어디에 있는지가 아니라, 팀이 provenance 및 integrity를 입증할 수 있는지 여부입니다. Public sources에서 unsigned 또는 제대로 추적되지 않은 images를 pull하면 malicious하거나 tampered된 content가 production에 유입될 위험이 증가합니다. 내부에서 운영되는 registries에도 명확한 ownership, review 및 trust policy가 필요합니다.

Docker Content Trust는 과거에 Notary 및 TUF concepts를 사용하여 signed images를 요구했습니다. 정확한 ecosystem은 발전했지만, 지속적으로 유효한 교훈은 다음과 같습니다. Image identity 및 integrity는 추정하는 것이 아니라 검증할 수 있어야 합니다.

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
이 예시의 요점은 모든 팀이 여전히 동일한 tooling을 사용해야 한다는 것이 아니라, signing과 key management가 추상적인 이론이 아닌 operational task라는 것입니다.

## 취약점 Scanning

Image scanning은 서로 다른 두 가지 질문에 답하는 데 도움이 됩니다. 첫째, image에 알려진 취약한 package나 library가 포함되어 있는가? 둘째, image가 attack surface를 확장하는 불필요한 software를 포함하고 있는가? debugging tool, shell, interpreter, 오래된 package로 가득 찬 image는 exploit하기 더 쉬울 뿐 아니라 분석하기도 더 어렵습니다.

일반적으로 사용되는 scanner의 예는 다음과 같습니다:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
이러한 tools의 결과는 신중하게 해석해야 합니다. 사용하지 않는 package의 vulnerability는 노출된 RCE 경로와 위험도가 동일하지 않지만, 둘 다 hardening 결정을 내릴 때 여전히 중요합니다.

## Build-Time Secrets

container build pipeline에서 가장 오래된 실수 중 하나는 secret을 image에 직접 삽입하거나, 이후 `docker inspect`, build log 또는 복구된 layer를 통해 노출될 수 있는 environment variable을 통해 전달하는 것입니다. Build-time secret은 image filesystem에 복사하는 대신 build 중 일시적으로 mount해야 합니다.

BuildKit은 전용 build-time secret handling을 지원하여 이 모델을 개선했습니다. secret을 layer에 기록하는 대신 build step에서 일시적으로 사용할 수 있습니다:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
이는 image layer가 지속되는 artifact이기 때문에 중요합니다. secret이 committed layer에 한 번 들어가면, 이후 다른 layer에서 해당 파일을 삭제하더라도 image history에서 원래 disclosure가 실제로 제거되지는 않습니다.

## Runtime Secrets

실행 중인 workload에 필요한 secret도 가능한 경우 plain environment variables 같은 임시방편 패턴을 피해야 합니다. Volumes, 전용 secret-management integrations, Docker secrets, Kubernetes Secrets가 일반적인 메커니즘입니다. 특히 attacker가 이미 workload에서 code execution을 확보한 경우에는 이들 중 어느 것도 모든 risk를 제거하지 못하지만, credentials를 image에 영구적으로 저장하거나 inspection tooling을 통해 부주의하게 노출하는 것보다는 여전히 선호할 만합니다.

간단한 Docker Compose 스타일의 secret declaration은 다음과 같습니다:
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
Kubernetes에서 Secret objects, projected volumes, service-account tokens 및 cloud workload identities는 더 광범위하고 강력한 모델을 제공하지만, host mounts, 광범위한 RBAC 또는 취약한 Pod 설계로 인해 실수로 노출될 가능성도 높아집니다.

## Abuse

target을 검토할 때의 목적은 secrets가 image에 bake되었는지, layers로 leak되었는지 또는 예측 가능한 runtime 위치에 mount되었는지를 확인하는 것입니다:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
이 명령어들은 세 가지 서로 다른 문제를 구분하는 데 도움이 됩니다: application configuration leak, image-layer leak, runtime-injected secret files. Secret이 `/run/secrets`, projected volume 또는 cloud identity token path에 나타난다면, 다음 단계는 해당 secret이 현재 workload에만 access를 부여하는지, 아니면 훨씬 더 큰 control plane에 access를 부여하는지 파악하는 것입니다.

### 전체 예시: Image Filesystem에 포함된 Secret

Build pipeline에서 `.env` 파일이나 credentials를 final image에 복사했다면 post-exploitation은 간단해집니다:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
영향은 애플리케이션에 따라 다르지만, 내장된 서명 키, JWT secrets 또는 cloud credentials는 container compromise를 API compromise, lateral movement 또는 신뢰된 애플리케이션 토큰 위조로 쉽게 이어지게 할 수 있습니다.

### 전체 예시: Build-Time Secret Leakage Check

문제가 image history에 secret이 포함된 레이어가 기록된 것이라면:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
이러한 검토가 유용한 이유는 최종 filesystem view에서는 secret이 삭제되었더라도 이전 layer 또는 build metadata에 여전히 남아 있을 수 있기 때문입니다.

## 점검

이러한 점검은 image 및 secret-handling pipeline이 runtime 이전에 attack surface를 증가시켰을 가능성이 있는지 확인하기 위한 것입니다.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
여기서 흥미로운 점:

- 의심스러운 build history는 복사된 credentials, SSH material 또는 안전하지 않은 build step을 드러낼 수 있습니다.
- projected volume 경로 아래의 Secrets는 단순한 로컬 애플리케이션 접근이 아니라 cluster 또는 cloud 접근으로 이어질 수 있습니다.
- plaintext credentials가 포함된 configuration file이 대량으로 존재한다면, 일반적으로 image 또는 deployment model이 필요한 수준보다 많은 trust material을 전달하고 있음을 나타냅니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | 안전한 build-time secret mount를 지원하지만 자동으로 활성화되지는 않음 | `build` 중 Secrets를 일시적으로 mount할 수 있지만, image signing과 scanning에는 명시적인 workflow 선택이 필요함 | Secrets를 image에 복사, `ARG` 또는 `ENV`를 통해 Secrets 전달, provenance check 비활성화 |
| Podman / Buildah | OCI-native build와 secret-aware workflow 지원 | 강력한 build workflow를 사용할 수 있지만, 운영자가 의도적으로 선택해야 함 | Containerfile에 Secrets 삽입, 광범위한 build context, build 중 permissive bind mount |
| Kubernetes | Native Secret object와 projected volume | Runtime secret delivery가 first-class이지만, 노출 여부는 RBAC, pod 설계 및 host mount에 따라 달라짐 | 과도하게 광범위한 Secret mount, service-account token 오용, kubelet이 관리하는 volume에 대한 `hostPath` 접근 |
| Registries | 강제로 적용하지 않는 한 무결성 검증은 선택 사항 | Public 및 private registry 모두 policy, signing 및 admission 결정에 의존함 | 서명되지 않은 image를 자유롭게 pull, 취약한 admission control, 부실한 key management |

{{#include ../../../banners/hacktricks-training.md}}
