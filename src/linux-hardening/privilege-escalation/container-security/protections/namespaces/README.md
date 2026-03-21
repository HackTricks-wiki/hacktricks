# 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

命名空间是让容器看起来像“它自己的机器”的内核特性，尽管它实际上只是宿主的一个进程树。它们不会创建新的内核，也不会对所有东西进行虚拟化，但它们确实允许内核向不同的进程组展示选定资源的不同视图。这就是容器幻觉的核心：工作负载看到的文件系统、进程表、网络栈、主机名、IPC 资源以及用户/组身份模型似乎都是本地的，即便底层系统是共享的。

这就是为什么命名空间是大多数人在学习容器工作原理时首先接触到的概念。与此同时，它们也是最常被误解的概念之一，因为读者常常假设“有命名空间”就意味着“安全隔离”。事实上，命名空间只隔离它为之设计的那一类资源。一个进程可以拥有私有的 PID 命名空间，但如果它有可写的宿主绑定挂载仍然可能很危险。它可以拥有私有的网络命名空间，但如果它保留了 `CAP_SYS_ADMIN` 并且没有启用 seccomp，仍然可能很危险。命名空间是基础，但它们只是最终边界中的一层。

## 命名空间类型

Linux 容器通常同时依赖几种命名空间类型。**mount namespace** 为进程提供单独的挂载表，因此提供可控的文件系统视图。**PID namespace** 改变进程可见性和编号，使工作负载看到自己的进程树。**network namespace** 隔离接口、路由、套接字和防火墙状态。**IPC namespace** 隔离 SysV IPC 和 POSIX 消息队列。**UTS namespace** 隔离主机名和 NIS 域名。**user namespace** 重映射用户和组 ID，使得容器内的 root 不一定意味着宿主上的 root。**cgroup namespace** 虚拟化可见的 cgroup 层级，**time namespace** 在更新的内核中虚拟化选定的时钟。

这些命名空间各自解决不同的问题。这就是为什么实际的容器安全分析通常归结为检查 **哪些命名空间被隔离** 以及 **哪些命名空间被故意与宿主共享**。

## 与宿主共享命名空间

许多容器突破并不是从内核漏洞开始的。而是从操作员故意削弱隔离模型开始的。示例 `--pid=host`、`--network=host` 和 `--userns=host` 是 **Docker/Podman-style CLI flags**，在这里作为与宿主共享命名空间的具体示例。其他运行时以不同方式表达相同的想法。在 Kubernetes 中等效项通常以 Pod 设置出现，例如 `hostPID: true`、`hostNetwork: true` 或 `hostIPC: true`。在较低层级的运行时栈（如 containerd 或 CRI-O）中，同样的行为通常通过生成的 OCI runtime 配置而不是通过具有相同名称的用户可见标志来实现。在所有这些情况下，结果相似：工作负载不再接收默认的隔离命名空间视图。

这就是为什么命名空间审查不应仅停留在“进程处在某个命名空间”这点上。重要的问题是该命名空间是容器私有、与兄弟容器共享，还是直接加入到宿主。在 Kubernetes 中相同的想法以 `hostPID`、`hostNetwork` 和 `hostIPC` 等标志出现。各平台的名称会变化，但风险模式相同：共享的宿主命名空间会使容器剩余的权限和可达的宿主状态变得更为重要。

## 检查

最简单的概览是：
```bash
ls -l /proc/self/ns
```
每个条目都是带有类似 inode 标识符的符号链接。如果两个进程指向相同的命名空间标识符，那么它们就在同一类型的命名空间中。这使得 `/proc` 成为一个非常有用的位置，用来将当前进程与机器上其他有趣的进程进行比较。

以下这些快速命令通常足以作为起点：
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
从那里，下一步是将 container process 与 host 或相邻的 processes 进行比较，并确定该 namespace 是否实际上是私有的。

### 从 Host 枚举 Namespace 实例

当你已经获得 host 访问权限并想了解某一类型存在多少个不同的 namespace 时，`/proc` 提供了一个快速清单：
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
如果你想查找属于某个特定命名空间标识符的进程，可以将 `readlink` 换成 `ls -l`，并使用 grep 来搜索目标命名空间编号：
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
这些命令很有用，因为它们可以让你判断主机是在运行单个隔离的工作负载、多个隔离的工作负载，还是共享与私有命名空间实例的混合。

### 进入目标命名空间

当调用者拥有足够的权限时，`nsenter` 是加入另一个进程的命名空间的标准方式：
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
将这些形式一同列出并非意味着每次评估都需要全部使用，而是因为一旦操作者知道确切的进入语法（而不是仅记住“所有命名空间”形式），命名空间特定的后利用通常会更加容易。

## Pages

以下页面对每个命名空间进行了更详细的说明：

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

在阅读时，请记住两点。首先，每个命名空间只隔离一种视图。其次，只有在其余的权限模型仍然使该隔离有意义的情况下，私有命名空间才有用。

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | 默认会创建新的 mount、PID、network、IPC 和 UTS 命名空间；user namespaces 可用，但在标准的 rootful 设置中默认未启用 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | 默认会创建新的命名空间；rootless Podman 会自动使用 user namespace；cgroup namespace 的默认值取决于 cgroup 版本 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods 默认不与主机共享 PID、network 或 IPC；Pod 网络对于整个 Pod 是私有的，而不是对单个容器私有；在支持的集群上，user namespaces 通过使用 `spec.hostUsers: false` 进行选择性启用 | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, 特权工作负载设置 |
| containerd / CRI-O under Kubernetes | 通常遵循 Kubernetes Pod 的默认设置 | 与 Kubernetes 行相同；直接的 CRI/OCI 规范也可以请求加入主机命名空间 |

主要的可移植性规则很简单：主机命名空间共享的**概念**在各运行时中是通用的，但**语法**是运行时特有的。
