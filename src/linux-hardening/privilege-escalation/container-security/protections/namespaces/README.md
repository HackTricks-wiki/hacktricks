# 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

命名空间是内核特性，使得一个容器看起来像“它自己的机器”，尽管它实际上只是宿主进程树。它们不会创建新的内核，也不会对所有东西做虚拟化，但它们允许内核向不同的进程组展示已选择资源的不同视图。这就是容器幻觉的核心：工作负载看到的文件系统、进程表、网络栈、主机名、IPC 资源以及用户/组身份模型看起来是本地的，尽管底层系统是共享的。

这就是为什么命名空间是大多数人在学习容器工作原理时首先遇到的概念。与此同时，它们也是最常被误解的概念之一，因为读者常常假设“有命名空间”就意味着“安全隔离”。实际上，命名空间只隔离它为之设计的特定类别资源。一个进程可以有私有的 PID 命名空间，但仍然危险，因为它有可写的主机 bind mount。它可以有私有的 network namespace，但仍然危险，因为它保留了 `CAP_SYS_ADMIN` 并且在没有 seccomp 的情况下运行。命名空间是基础，但它们只是最终边界中的一层。

## 命名空间类型

Linux 容器通常同时依赖多种命名空间类型。**mount namespace** 为进程提供了独立的挂载表，从而得到受控的文件系统视图。**PID namespace** 改变进程的可见性和编号，使工作负载看到它自己的进程树。**network namespace** 隔离接口、路由、套接字和防火墙状态。**IPC namespace** 隔离 SysV IPC 和 POSIX 消息队列。**UTS namespace** 隔离主机名和 NIS 域名。**user namespace** 重新映射用户和组 ID，使得容器内的 root 不一定意味着宿主的 root。**cgroup namespace** 虚拟化可见的 cgroup 层级，**time namespace** 在较新的内核中虚拟化选定的时钟。

这些命名空间各自解决不同的问题。这就是为什么实际的容器安全分析常常归结为检查哪些命名空间被隔离，以及哪些命名空间被故意与宿主共享。

## 主机命名空间共享

许多容器逃逸并不是从内核漏洞开始的，而是始于操作者故意削弱隔离模型。示例 `--pid=host`、`--network=host` 和 `--userns=host` 是 **Docker/Podman-style CLI flags**，这里用作主机命名空间共享的具体例子。其他运行时以不同方式表达相同的概念。在 Kubernetes 中，等价项通常以 Pod 设置出现，例如 `hostPID: true`、`hostNetwork: true` 或 `hostIPC: true`。在较底层的运行时栈（例如 containerd 或 CRI-O）中，相同行为通常通过生成的 OCI 运行时配置实现，而不是通过具有相同名称的面向用户的标志。在所有这些情况下，结果相似：工作负载不再接收默认的隔离命名空间视图。

这就是为什么命名空间审查绝不应该停留在“进程位于某个命名空间中”这一点。重要的问题是该命名空间是私有于容器、与同级容器共享，还是直接加入宿主。在 Kubernetes 中同样的想法以诸如 `hostPID`、`hostNetwork` 和 `hostIPC` 之类的标志出现。平台之间名称会变化，但风险模式相同：共享的主机命名空间会让容器剩余的权限和可达的宿主状态变得更有意义。

## Inspection

最简单的概览是：
```bash
ls -l /proc/self/ns
```
每个条目都是一个带有类似 inode 标识符的符号链接。如果两个进程指向相同的命名空间标识符，它们就在该类型的同一命名空间中。这使得 `/proc` 成为比较当前进程与机器上其他有趣进程的非常有用的位置。

以下这些快速命令通常足以开始：
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
从那里，下一步是将容器进程与主机或相邻进程进行比较，并判断某个命名空间是否确实是私有的。

### 从主机枚举命名空间实例

当你已经具有主机访问权限并想要了解某个类型的命名空间存在多少个不同行时，`/proc` 提供了一个快速清单：
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
如果你想找出属于某个特定命名空间标识符的进程，请将 `readlink` 换成 `ls -l` 并使用 `grep` 搜索目标命名空间编号：
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
这些命令很有用，因为它们可以让你判断主机是在运行单个独立的工作负载、多个独立的工作负载，还是混合了共享和私有命名空间实例的情况。

### 进入目标命名空间

当调用者具有足够权限时，`nsenter` 是加入另一个进程命名空间的标准方法：
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
The point of listing these forms together is not that every assessment needs all of them, but that namespace-specific post-exploitation often becomes much easier once the operator knows the exact entry syntax instead of remembering only the all-namespaces form.

## Pages

The following pages explain each namespace in more detail:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

As you read them, keep two ideas in mind. First, each namespace isolates only one kind of view. Second, a private namespace is useful only if the rest of the privilege model still makes that isolation meaningful.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

The main portability rule is simple: the **concept** of host namespace sharing is common across runtimes, but the **syntax** is runtime-specific.
{{#include ../../../../../banners/hacktricks-training.md}}
