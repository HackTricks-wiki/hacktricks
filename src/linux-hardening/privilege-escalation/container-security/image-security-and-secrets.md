# 이미지 보안, 서명 및 비밀

{{#include ../../../banners/hacktricks-training.md}}

## 개요

컨테이너 보안은 워크로드가 실행되기 전에 시작됩니다. 이미지가 어떤 바이너리, 인터프리터, 라이브러리, 시작 스크립트 및 포함된 구성을 프로덕션으로 가져갈지를 결정합니다. 이미지에 백도어가 있거나, 오래되었거나, 비밀이 빌트인 된 상태로 만들어졌다면 이후의 runtime hardening은 이미 손상된 아티팩트 위에서 작동하게 됩니다.

이 때문에 이미지 출처(provenance), 취약점 스캐닝(vulnerability scanning), 서명 검증(signature verification), 비밀 처리(secret handling)는 namespaces and seccomp와 같은 논의 안에 포함되어야 합니다. 이들은 라이프사이클의 다른 단계를 보호하지만, 여기서의 실패는 종종 이후 runtime이 제어해야 하는 공격면을 결정합니다.

## 이미지 레지스트리와 신뢰

이미지는 Docker Hub와 같은 공개 레지스트리에서 올 수도 있고, 조직이 운영하는 사설 레지스트리에서 올 수도 있습니다. 보안상의 문제는 단순히 이미지가 어디에 위치하느냐가 아니라 팀이 출처와 무결성을 확립할 수 있느냐입니다. 공개 소스에서 서명되지 않았거나 추적이 부실한 이미지를 끌어오면 악성 또는 변조된 콘텐츠가 프로덕션에 유입될 위험이 커집니다. 내부에 호스팅된 레지스트리조차 명확한 소유권, 검토, 신뢰 정책이 필요합니다.

Docker Content Trust는 역사적으로 Notary와 TUF 개념을 사용하여 서명된 이미지를 요구했습니다. 정확한 생태계는 진화했지만, 남아있는 교훈은 유용합니다: 이미지의 정체성과 무결성은 가정해서는 안 되며 검증 가능해야 합니다.

예시 역사적 Docker Content Trust 워크플로우:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
The point of the example is not that every team must still use the same tooling, but that signing and key management are operational tasks, not abstract theory.

## Vulnerability Scanning

이미지 스캐닝은 두 가지 서로 다른 질문에 답하는 데 도움이 된다. 첫째, 이미지에 알려진 취약한 패키지나 라이브러리가 포함되어 있는가? 둘째, 이미지에 공격 표면을 넓히는 불필요한 소프트웨어가 포함되어 있는가? 디버깅 도구, 셸, 인터프리터 및 오래된 패키지로 가득 찬 이미지는 악용하기 더 쉽고 이해하기 더 어렵다.

일반적으로 사용되는 scanners의 예로는 다음이 있다:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
이들 도구의 결과는 신중하게 해석해야 합니다. 사용하지 않는 패키지의 취약점이 노출된 RCE 경로와 동일한 수준의 위험을 의미하지는 않지만, 둘 다 하드닝 결정을 내릴 때 여전히 고려해야 할 사항입니다.

## 빌드 타임 시크릿

컨테이너 빌드 파이프라인에서 가장 오래된 실수 중 하나는 시크릿을 이미지에 직접 포함시키거나 나중에 `docker inspect`, 빌드 로그, 또는 복구된 레이어를 통해 노출되는 환경 변수로 전달하는 것입니다. 빌드 타임 시크릿은 이미지 파일 시스템에 복사하는 대신 빌드 중에 일시적으로 마운트되어야 합니다.

BuildKit은 전용 빌드 타임 시크릿 처리를 허용하여 이 모델을 개선했습니다. 시크릿을 레이어에 기록하는 대신, 빌드 단계에서 이를 일시적으로 소비할 수 있습니다:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
This matters because image layers are durable artifacts. Once a secret enters a committed layer, later deleting the file in another layer does not truly remove the original disclosure from the image history.

## Runtime Secrets

실행 중인 워크로드에 필요한 Secrets는 가능한 한 plain environment variables 같은 ad hoc 패턴을 피해야 합니다. Volumes, 전용 secret-management 통합, Docker secrets, 그리고 Kubernetes Secrets가 일반적인 메커니즘입니다. 이들 방법이 모든 위험을 제거하지는 못합니다 — 특히 공격자가 이미 워크로드에서 코드 실행 권한을 가지고 있는 경우에는 — 하지만 자격 증명을 이미지에 영구적으로 저장하거나 inspection tooling을 통해 무심코 노출하는 것보다는 여전히 더 낫습니다.

A simple Docker Compose style secret declaration looks like:
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
Kubernetes에서는 Secret objects, projected volumes, service-account tokens 및 cloud workload identities가 더 넓고 강력한 모델을 형성하지만, 동시에 host mounts, broad RBAC 또는 weak Pod design을 통한 우발적 노출 기회도 증가합니다.

## 악용

타깃을 검토할 때, 목적은 secrets가 이미지에 baked into 되어 있는지, layers로 leaked 되어 있는지, 또는 예측 가능한 runtime locations에 mounted 되어 있는지를 확인하는 것입니다:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
이 명령들은 세 가지 다른 문제를 구분하는 데 도움이 됩니다: 애플리케이션 구성 leaks, 이미지 레이어 leaks, 그리고 런타임에 주입된 secret 파일. 만약 비밀이 `/run/secrets`, a projected volume, 또는 cloud identity token path 아래에 나타난다면, 다음 단계는 그것이 현재 워크로드에만 접근 권한을 주는지 아니면 훨씬 더 큰 컨트롤 플레인에 대한 접근을 허용하는지 파악하는 것입니다.

### 전체 예시: 이미지 파일시스템에 포함된 Embedded Secret

빌드 파이프라인이 `.env` 파일이나 자격 증명을 최종 이미지에 복사했다면, post-exploitation은 간단해집니다:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
영향은 애플리케이션에 따라 다르지만, embedded signing keys, JWT secrets 또는 cloud credentials가 노출되면 container compromise가 쉽게 API compromise, lateral movement 또는 trusted application tokens의 forgery로 이어질 수 있습니다.

### 전체 예시: Build-Time Secret Leakage Check

이미지 히스토리가 secret-bearing layer를 캡처했을 가능성이 우려되는 경우:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
이러한 검토는 secret가 최종 파일시스템 뷰에서 삭제되었더라도 이전 레이어나 빌드 메타데이터에 여전히 남아있을 수 있기 때문에 유용합니다.

## 점검

이러한 점검은 image와 secret-handling 파이프라인이 런타임 이전에 attack surface를 증가시켰을 가능성이 있는지를 확인하기 위한 것입니다.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
여기서 주목할 점:

- 의심스러운 빌드 기록은 복사된 자격 증명, SSH 관련 자료, 또는 안전하지 않은 빌드 단계를 드러낼 수 있다.
- 프로젝티드 볼륨 경로 아래의 Secrets는 로컬 애플리케이션 접근뿐 아니라 클러스터나 클라우드 접근으로 이어질 수 있다.
- 평문 자격 증명을 포함한 많은 수의 설정 파일은 보통 이미지나 배포 모델이 필요 이상으로 많은 신뢰 정보를 담고 있음을 나타낸다.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | 보안된 빌드 시 Secret 마운트를 지원하지만 자동으로 활성화되지는 않음 | Secret은 `build` 동안 일시적으로 마운트될 수 있다; 이미지 서명 및 스캐닝은 명시적인 워크플로 선택을 요구한다 | Secrets를 이미지에 복사, `ARG` 또는 `ENV`로 Secrets 전달, 출처 검증(provenance checks) 비활성화 |
| Podman / Buildah | OCI-native 빌드 및 시크릿 인식 워크플로를 지원 | 강력한 빌드 워크플로가 가능하지만 운영자는 여전히 의도적으로 선택해야 함 | Containerfiles에 Secrets 포함, 광범위한 빌드 컨텍스트, 빌드 중 관대하게 허용된 bind 마운트 |
| Kubernetes | 네이티브 Secret 객체 및 projected volumes | 런타임 Secret 전달은 우선 기능이지만, 노출은 RBAC, pod 설계, 및 호스트 마운트에 따라 달라짐 | 과도하게 넓은 Secret 마운트, service-account token 오용, `hostPath`를 통한 kubelet-관리 볼륨 접근 |
| Registries | 강제되지 않으면 무결성은 선택사항임 | 공개 및 비공개 레지스트리는 정책, 서명, 및 admission 결정에 의존함 | 서명되지 않은 이미지 자유 풀링, 약한 admission 제어, 부실한 키 관리 |
{{#include ../../../banners/hacktricks-training.md}}
