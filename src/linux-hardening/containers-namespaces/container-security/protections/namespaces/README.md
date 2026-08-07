# 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

命名空间是内核的一项功能，它让容器感觉像是“自己的机器”，尽管容器实际上只是主机进程树中的一部分。命名空间不会创建新的内核，也不会对所有内容进行虚拟化，但它们确实允许内核向不同的进程组呈现所选资源的不同视图。这正是容器假象的核心：工作负载看到的文件系统、进程表、网络栈、主机名、IPC 资源以及用户/组身份模型看起来都是本地的，尽管底层系统仍然是共享的。

这也是为什么人们学习容器工作原理时，命名空间通常是最先接触的概念。同时，命名空间也是最容易被误解的概念之一，因为读者经常会认为“有命名空间”就意味着“实现了安全隔离”。实际上，命名空间只会隔离其设计目标所对应的特定资源类别。进程可以拥有私有的 PID 命名空间，但如果它具有可写的主机 bind mount，仍然可能很危险。它可以拥有私有的 network 命名空间，但如果保留了 `CAP_SYS_ADMIN` 且未使用 seccomp，仍然可能很危险。命名空间是基础组件，但它们只是最终边界中的一层。

## 命名空间类型

Linux 容器通常会同时依赖多种命名空间类型。**mount 命名空间**为进程提供独立的 mount 表，从而提供受控的文件系统视图。**PID 命名空间**改变进程的可见性和编号，使工作负载看到自己的进程树。**network 命名空间**隔离网络接口、路由、套接字和 firewall 状态。**IPC 命名空间**隔离 SysV IPC 和 POSIX message queue。**UTS 命名空间**隔离主机名和 NIS domain name。**user 命名空间**重新映射用户和组 ID，因此容器内的 root 不一定意味着主机上的 root。**cgroup 命名空间**对可见的 cgroup 层级结构进行虚拟化，而较新内核中的 **time 命名空间**则会对选定的时钟进行虚拟化。

这些命名空间分别解决不同的问题。因此，实际的容器安全分析通常归结为检查**哪些命名空间已被隔离**，以及**哪些命名空间被有意地与主机共享**。

## 主机命名空间共享

许多容器 breakout 并不是从内核漏洞开始的，而是从操作员有意削弱隔离模型开始的。这里使用 `--pid=host`、`--network=host` 和 `--userns=host` 作为主机命名空间共享的具体示例，它们是 **Docker/Podman-style CLI flags**。其他 runtime 可能以不同方式表达相同的概念。在 Kubernetes 中，对应设置通常以 Pod 设置的形式出现，例如 `hostPID: true`、`hostNetwork: true` 或 `hostIPC: true`。在 containerd 或 CRI-O 等较底层的 runtime stack 中，通常是通过生成的 OCI runtime 配置实现相同的行为，而不是通过名称相同的面向用户 flag 实现。在所有这些情况下，结果都很相似：工作负载不再获得默认的隔离命名空间视图。

因此，命名空间审查绝不能止步于“进程处于某个命名空间中”。真正重要的问题是：该命名空间是容器私有的、与其他容器共享的，还是直接加入了主机。在 Kubernetes 中，同样的概念会通过 `hostPID`、`hostNetwork` 和 `hostIPC` 等 flags 表现出来。不同平台上的名称可能有所不同，但风险模式相同：共享主机命名空间会让容器剩余的权限以及可触及的主机状态变得更加重要。

## 检查

最简单的概览是：
```bash
ls -l /proc/self/ns
```
每个条目都是一个带有类似 inode 标识符的符号链接。如果两个进程指向同一个 namespace 标识符，那么它们就属于该类型的同一个 namespace。因此，`/proc` 是比较当前进程与机器上其他有趣进程的非常有用的位置。

以下这些快速命令通常就足以开始：
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
从这里开始，下一步是将容器进程与主机进程或相邻进程进行比较，并确定某个 namespace 是否确实是私有的。

### 从主机枚举 Namespace 实例

当你已经获得主机访问权限，并希望了解某种类型的独立 namespace 有多少个时，`/proc` 可以提供一个快速清单：
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
如果你想查找属于某个特定 namespace 标识符的进程，请将 `readlink` 替换为 `ls -l`，并 grep 目标 namespace 编号：
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
这些命令很有用，因为它们可以帮助你判断某个主机运行的是一个隔离的 workload、多个隔离的 workload，还是共享与私有 namespace 实例的混合环境。

### 进入目标 Namespace

当调用方拥有足够的权限时，`nsenter` 是加入另一个进程 namespace 的标准方式：
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
将这些形式列在一起，并不是说每次 assessment 都需要全部使用，而是因为一旦 operator 知道确切的 entry syntax，而不是只记得 all-namespaces 形式，针对特定 namespace 的 post-exploitation 往往会容易得多。

## 页面

以下页面将更详细地介绍各个 namespace：

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

阅读这些页面时，请牢记两个要点。第一，每个 namespace 只隔离一种视图。第二，只有当其余 privilege model 仍能使这种隔离具有实际意义时，private namespace 才有用。

## Runtime 默认设置

| Runtime / platform | 默认 namespace 状态 | 常见的手动弱化方式 |
| --- | --- | --- |
| Docker Engine | 默认创建新的 mount、PID、network、IPC 和 UTS namespaces；user namespaces 可用，但在标准的 rootful setup 中默认未启用 | `--pid=host`、`--network=host`、`--ipc=host`、`--uts=host`、`--userns=host`、`--cgroupns=host`、`--privileged` |
| Podman | 默认创建新的 namespaces；rootless Podman 自动使用 user namespace；cgroup namespace 的默认设置取决于 cgroup 版本 | `--pid=host`、`--network=host`、`--ipc=host`、`--uts=host`、`--userns=host`、`--cgroupns=host`、`--privileged` |
| Kubernetes | Pods 默认**不会**共享 host PID、network 或 IPC；Pod networking 对 Pod 是私有的，而不是对其中的每个 container 分别私有；在受支持的 clusters 中，可通过 `spec.hostUsers: false` opt-in 使用 user namespaces | `hostPID: true`、`hostNetwork: true`、`hostIPC: true`、`spec.hostUsers: true` / 省略 user-namespace opt-in、privileged workload 设置 |
| Kubernetes 下的 containerd / CRI-O | 通常遵循 Kubernetes Pod 默认设置 | 与 Kubernetes 行相同；直接使用的 CRI/OCI specs 也可以请求加入 host namespaces |

主要的 portability rule 很简单：host namespace sharing 这一**概念**在各个 runtimes 中是通用的，但具体的**语法**取决于 runtime。

{{#include ../../../../../banners/hacktricks-training.md}}
