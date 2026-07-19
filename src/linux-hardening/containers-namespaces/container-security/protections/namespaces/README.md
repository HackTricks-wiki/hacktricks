# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces 是 kernel 的一项功能，它让 container 感觉像是“自己的机器”，尽管它实际上只是 host process tree。它们不会创建新的 kernel，也不会将所有内容进行 virtualize，但会让 kernel 向不同的 process groups 呈现所选 resources 的不同视图。这正是 container illusion 的核心：workload 看到的 filesystem、process table、network stack、hostname、IPC resources 以及 user/group identity model 看起来都属于本地，即使底层 system 仍然是共享的。

这就是为什么 namespaces 是大多数人在学习 containers 工作原理时最先接触的概念。同时，它们也是最常被误解的概念之一，因为读者经常以为“has namespaces”就意味着“is safely isolated”。实际上，一个 namespace 只会隔离其设计用于隔离的特定 resources。一个 process 可以拥有 private PID namespace，但仍然很危险，因为它有 writable host bind mount。它可以拥有 private network namespace，但仍然很危险，因为它保留了 `CAP_SYS_ADMIN` 且运行时没有 seccomp。Namespaces 是基础，但它们只是最终 boundary 中的一层。

## Namespace Types

Linux containers 通常会同时依赖多种 namespace types。**mount namespace** 为 process 提供单独的 mount table，从而提供受控的 filesystem view。**PID namespace** 改变 process visibility 和 numbering，使 workload 看到自己的 process tree。**network namespace** 隔离 interfaces、routes、sockets 和 firewall state。**IPC namespace** 隔离 SysV IPC 和 POSIX message queues。**UTS namespace** 隔离 hostname 和 NIS domain name。**user namespace** remap user 和 group IDs，因此 container 内的 root 不一定意味着 host 上的 root。**cgroup namespace** virtualize 可见的 cgroup hierarchy，而较新 kernel 中的 **time namespace** 会 virtualize 选定的 clocks。

每种 namespace 都解决不同的问题。因此，实际的 container security analysis 通常归结为检查**哪些 namespaces 已被隔离**以及**哪些 namespaces 被有意与 host 共享**。

## Host Namespace Sharing

许多 container breakouts 并不是从 kernel vulnerability 开始的，而是从 operator 有意削弱 isolation model 开始的。示例 `--pid=host`、`--network=host` 和 `--userns=host` 是这里用于说明 host namespace sharing 的 **Docker/Podman-style CLI flags**。其他 runtimes 会以不同方式表达相同的概念。在 Kubernetes 中，对应设置通常以 Pod settings 的形式出现，例如 `hostPID: true`、`hostNetwork: true` 或 `hostIPC: true`。在 containerd 或 CRI-O 等 lower-level runtime stacks 中，通常是通过生成的 OCI runtime configuration 达到相同效果，而不是通过名称相同的 user-facing flag。在所有这些情况下，结果都很相似：workload 不再获得默认的 isolated namespace view。

这就是为什么 namespace reviews 绝不能止步于“process 位于某个 namespace 中”。重要的问题是：该 namespace 是 container 私有的、与 sibling containers 共享的，还是直接加入 host 的。在 Kubernetes 中，同样的概念会通过 `hostPID`、`hostNetwork` 和 `hostIPC` 等 flags 出现。不同 platforms 的名称可能不同，但 risk pattern 是相同的：共享 host namespace 会使 container 剩余的 privileges 以及可访问的 host state 变得更加重要。

## Inspection

最简单的概览是：
```bash
ls -l /proc/self/ns
```
每个条目都是一个带有类似 inode 标识符的 symbolic link。如果两个进程指向同一个 namespace 标识符，那么它们就属于同一类型的 namespace。由此，`/proc` 成为了比较当前进程与机器上其他有趣进程的非常有用的位置。

以下这些快速命令通常足以开始：
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
从这里开始，下一步是将 container process 与 host 或相邻的 processes 进行比较，并确定某个 namespace 是否确实为 private。

### 从 Host 枚举 Namespace 实例

当你已经获得 host access，并希望了解某种给定类型的 distinct namespaces 数量时，`/proc` 可提供一个快速清单：
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
如果你想查找属于某个特定 namespace 标识符的进程，请将 `readlink` 替换为 `ls -l`，然后 grep 目标 namespace 编号：
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
这些命令很有用，因为它们可以帮助你判断一台主机上运行的是一个隔离的工作负载、多个隔离的工作负载，还是共享命名空间实例与私有命名空间实例的混合环境。

### 进入目标命名空间

当调用者拥有足够的权限时，`nsenter` 是加入其他进程命名空间的标准方式：
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
列出这些形式的目的，并不是说每次 assessment 都需要全部使用，而是因为一旦 operator 知道确切的 entry syntax，而不是只记得 all-namespaces 形式，针对特定 namespace 的 post-exploitation 往往会容易得多。

## 页面

以下页面将更详细地说明各个 namespace：

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

阅读这些内容时，请记住两点。第一，每个 namespace 只隔离一种视图。第二，只有当其余 privilege model 仍能使这种隔离具有实际意义时，private namespace 才有用。

## Runtime 默认设置

| Runtime / platform | 默认 namespace 状态 | 常见的手动削弱方式 |
| --- | --- | --- |
| Docker Engine | 默认创建新的 mount、PID、network、IPC 和 UTS namespace；user namespace 可用，但在标准 rootful setup 中默认未启用 | `--pid=host`、`--network=host`、`--ipc=host`、`--uts=host`、`--userns=host`、`--cgroupns=host`、`--privileged` |
| Podman | 默认创建新的 namespace；rootless Podman 会自动使用 user namespace；cgroup namespace 的默认设置取决于 cgroup 版本 | `--pid=host`、`--network=host`、`--ipc=host`、`--uts=host`、`--userns=host`、`--cgroupns=host`、`--privileged` |
| Kubernetes | 默认情况下，Pod **不会**共享 host PID、network 或 IPC；Pod networking 对 Pod 是私有的，而不是对其中每个 container 分别私有；在受支持的 cluster 中，可通过 `spec.hostUsers: false` opt-in 使用 user namespace | `hostPID: true`、`hostNetwork: true`、`hostIPC: true`、`spec.hostUsers: true` / 省略 user-namespace opt-in、启用 privileged workload 的设置 |
| containerd / CRI-O under Kubernetes | 通常遵循 Kubernetes Pod 默认设置 | 与 Kubernetes 行相同；直接使用 CRI/OCI spec 时，也可以请求加入 host namespace |

主要的 portability 规则很简单：host namespace sharing 这一**概念**在各个 runtime 中都很常见，但其**语法**取决于具体 runtime。
{{#include ../../../../../banners/hacktricks-training.md}}
