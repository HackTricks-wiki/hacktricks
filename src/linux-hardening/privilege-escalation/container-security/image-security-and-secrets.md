# 이미지 보안, 서명, 그리고 시크릿

{{#include ../../../banners/hacktricks-training.md}}

## 개요

컨테이너 보안은 워크로드가 시작되기 전부터 시작된다. 이미지는 어떤 바이너리, 인터프리터, 라이브러리, 시작 스크립트 및 임베디드 구성(configuration)이 프로덕션에 도달하는지를 결정한다. 이미지에 백도어가 있거나 오래되어 있거나 시크릿이 이미지에 빌트인되어 빌드되었다면, 이후의 런타임 하드닝은 이미 손상된 아티팩트 위에서 작동하는 것이다.

이 때문에 이미지 provenance, 취약점 스캐닝, 서명 검증, 시크릿 처리 등은 namespaces 및 seccomp와 같은 주제와 동일한 대화에 포함되어야 한다. 이들은 라이프사이클의 다른 단계를 보호하지만, 여기서의 실패는 종종 이후 런타임이 봉쇄해야 할 공격 표면을 규정한다.

## 이미지 레지스트리와 신뢰

이미지는 Docker Hub와 같은 공개 레지스트리에서 오거나 조직이 운영하는 프라이빗 레지스트리에서 올 수 있다. 보안의 문제는 단순히 이미지가 어디에 있는지가 아니라 팀이 그 이미지의 provenance와 무결성을 입증할 수 있는지 여부이다. 공개 소스에서 서명되지 않았거나 추적이 부실한 이미지를 끌어오면 악의적이거나 변조된 콘텐츠가 프로덕션에 유입될 위험이 증가한다. 내부에 호스팅된 레지스트리조차도 명확한 소유권, 검토 절차 및 신뢰 정책이 필요하다.

Docker Content Trust는 역사적으로 Notary 및 TUF 개념을 사용하여 서명된 이미지를 요구했다. 생태계는 발전했지만 지속되는 교훈은 유효하다: 이미지의 식별성과 무결성은 가정해서는 안 되며 검증 가능해야 한다.

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
The point of the example is not that every team must still use the same tooling, but that signing and key management are operational tasks, not abstract theory.

## 취약점 스캐닝

이미지 스캐닝은 두 가지 다른 질문에 답하는 데 도움을 준다. 첫째, 이미지에 알려진 취약한 패키지나 라이브러리가 포함되어 있는가? 둘째, 이미지에 공격 표면을 확장시키는 불필요한 소프트웨어가 포함되어 있는가? 디버깅 도구, 셸, 인터프리터, 그리고 오래된 패키지로 가득한 이미지는 악용하기 쉽고 이해하기도 어렵다.

일반적으로 사용되는 스캐너의 예는 다음과 같다:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Results from these tools should be interpreted carefully. A vulnerability in an unused package is not identical in risk to an exposed RCE path, but both are still relevant to hardening decisions.

## 빌드 타임 시크릿

컨테이너 빌드 파이프라인에서 가장 오래된 실수 중 하나는 시크릿을 이미지에 직접 포함시키거나 나중에 `docker inspect`, 빌드 로그, 또는 복구된 레이어를 통해 노출될 수 있는 환경 변수로 전달하는 것이다. 빌드 시 시크릿은 이미지 파일시스템에 복사하는 대신 빌드 동안 일시적으로 마운트되어야 한다.

BuildKit은 전용 빌드 타임 시크릿 처리를 허용해 이 모델을 개선했다. 시크릿을 레이어에 기록하는 대신, 빌드 단계에서 일시적으로 시크릿을 소비할 수 있다:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
이것은 이미지 레이어가 영구적인 아티팩트이기 때문에 중요합니다. 비밀이 커밋된 레이어에 들어가면, 이후 다른 레이어에서 파일을 삭제하더라도 이미지 히스토리에서 원본 노출을 완전히 제거하지는 않습니다.

## Runtime Secrets

실행 중인 워크로드에서 필요한 Secrets는 가능한 한 임시방편적인 패턴(예: 일반 환경 변수)을 피해야 합니다. 볼륨, 전용 비밀 관리 통합, Docker secrets, 그리고 Kubernetes Secrets가 흔히 사용되는 메커니즘입니다. 이러한 방법들이 모든 위험을 제거해 주지는 않으며, 특히 공격자가 이미 워크로드에서 코드 실행 권한을 가진 경우에는 더욱 그렇습니다. 그럼에도 불구하고 이미지에 자격 증명을 영구적으로 저장하거나 검사 도구를 통해 무심코 노출하는 것보다는 이러한 방법들을 사용하는 것이 더 낫습니다.

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
Kubernetes에서는 Secret objects, projected volumes, service-account tokens, and cloud workload identities가 더 폭넓고 강력한 모델을 제공하지만, host mounts, 광범위한 RBAC 또는 취약한 Pod 설계를 통해 의도치 않은 노출 기회가 더 많이 발생합니다.

## 악용

대상을 검토할 때 목표는 secrets가 baked into the image인지, leaked into layers인지, 또는 mounted into predictable runtime locations인지 여부를 발견하는 것입니다:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
이 명령들은 애플리케이션 구성 leaks, 이미지 레이어 leaks, 그리고 런타임에 주입된 비밀 파일의 세 가지 다른 문제를 구분하는 데 도움이 됩니다. 비밀이 `/run/secrets`, projected volume, 또는 cloud identity token path에 나타난다면, 다음 단계는 그것이 현재 워크로드에만 접근 권한을 주는지 아니면 훨씬 더 큰 control plane에 대한 접근 권한을 주는지를 파악하는 것입니다.

### Full Example: Embedded Secret In Image Filesystem

빌드 파이프라인이 `.env` 파일이나 자격증명을 최종 이미지에 복사했다면, post-exploitation은 단순해집니다:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
영향은 애플리케이션에 따라 달라지지만, embedded signing keys, JWT secrets 또는 cloud credentials는 container compromise를 API compromise, lateral movement 또는 trusted application tokens의 위조로 쉽게 전환시킬 수 있습니다.

### 전체 예제: Build-Time Secret Leakage Check

이미지 히스토리가 secret-bearing layer를 캡처했을 가능성이 우려된다면:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
이런 종류의 검토는 유용합니다. secret이 최종 파일시스템 뷰에서 삭제되었더라도 이전 레이어나 build metadata에 여전히 남아 있을 수 있기 때문입니다.

## 점검

이 점검들은 image와 secret-handling 파이프라인이 런타임 이전에 attack surface를 증가시켰을 가능성이 있는지를 판단하기 위한 것입니다.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
여기서 흥미로운 점:

- 의심스러운 빌드 히스토리는 복사된 인증 정보, SSH 자료, 또는 안전하지 않은 빌드 단계를 드러낼 수 있습니다.
- 프로젝트된 볼륨 경로 아래의 Secrets는 로컬 애플리케이션 접근뿐만 아니라 클러스터나 클라우드 접근으로 이어질 수 있습니다.
- 평문(plaintext) 인증 정보를 포함한 다수의 구성 파일은 대개 이미지나 배포 모델이 필요 이상으로 많은 신뢰 정보를 담고 있음을 나타냅니다.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time secret mounts, but not automatically | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Strong build workflows are available, but operators must still choose them intentionally | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, but exposure depends on RBAC, pod design, and host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity is optional unless enforced | Public and private registries both depend on policy, signing, and admission decisions | pulling unsigned images freely, weak admission control, poor key management |
