# cgroup 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

cgroup 命名空间不会替代 cgroups，也不会自行强制执行资源限制。相反，它会改变 cgroup 层级结构对进程的**呈现方式**。换句话说，它会虚拟化可见的 cgroup 路径信息，使 workload 看到的是以 container 为范围的视图，而不是完整的 host 层级结构。

这主要是一项可见性和信息缩减功能。它有助于让环境看起来更加自包含，并减少暴露 host 的 cgroup 布局。这听起来可能比较有限，但仍然很重要，因为对 host 结构的不必要可见性可能有助于侦察，并简化依赖环境的 exploit chain。

## 操作

没有私有 cgroup 命名空间时，进程可能会看到以 host 为基准的 cgroup 路径，从而暴露出超出实际需要的机器层级结构。使用私有 cgroup 命名空间后，`/proc/self/cgroup` 以及相关观察结果会更加局限于 container 自身的视图。这对于希望 workload 看到更整洁、较少暴露 host 信息的现代 runtime stack 尤其有帮助。

这种虚拟化也会影响 `/proc/<pid>/mountinfo`，而不仅仅是 `/proc/<pid>/cgroup`。当你从不同的 cgroup-namespace 视角读取另一个进程时，位于你的 namespace root 之外的路径会显示为带有前置 `../` 组件，这可以作为一个有用线索，表明你正在查看 delegated subtree 之上的内容。对于 lab 和 post-exploitation，需要注意的一点是：新创建的 cgroup 命名空间通常需要在该 namespace 内执行一次 **cgroupfs remount**，之后 `mountinfo` 才会正确反映新的 root。否则，你可能仍然会看到类似 `/..` 的 mount root，这意味着 inherited mount 仍在暴露以 ancestor 为 root 的视图，尽管 namespace 本身已经发生变化。<sup>[[1]](#references)</sup>

## 实验

你可以使用以下命令检查 cgroup 命名空间：
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
如果希望 `mountinfo` 更清晰地显示新的 cgroup-namespace 根目录，可以从新 namespace 内重新挂载 cgroup 文件系统，然后再次进行比较：
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
并比较运行时行为与：
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
这一变化主要涉及进程能够看到什么，而不是 cgroup enforcement 是否存在。

## 安全影响

cgroup namespace 最好理解为一种**可见性加固层**。单靠它并不能阻止 breakout，尤其是在容器具有可写的 cgroup mounts、广泛的 capabilities，或处于危险的 cgroup v1 环境中时。不过，如果共享了 host cgroup namespace，进程就能了解到更多系统组织方式，并且可能更容易将以 host 为相对参照的 cgroup 路径与其他观察结果对应起来。

在 **cgroup v2** 上，由于 delegation 规则更加严格，该 namespace 的作用会稍微更大一些。如果层级以 `nsdelegate` 挂载，kernel 会将 cgroup namespaces 视为 delegation 边界：祖先 control files 应保持在 delegatee 的可访问范围之外，并且 namespace root 中的写操作会被限制为 `cgroup.procs`、`cgroup.threads` 和 `cgroup.subtree_control` 等符合 delegation 安全要求的文件。<sup>[[2]](#references)</sup> 这仍然不会使该 namespace 本身成为 escape primitive，但会改变 compromised workload 能够检查的内容，以及它可以安全创建 sub-cgroups 的位置。

因此，虽然这个 namespace 通常不是 container breakout writeup 中的主角，但它仍有助于实现减少 host 信息泄露并限制 cgroup delegation 这一更广泛的目标。

## 滥用

其直接的滥用价值主要在于 reconnaissance。如果共享了 host cgroup namespace，可以比较可见路径，并查找能够暴露 host 的层级细节：
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
如果还暴露了可写的 cgroup 路径，请将这种可见性与对危险 legacy interfaces 的搜索结合起来：
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace 本身很少能立即实现 escape，但它通常会让环境映射变得更容易，从而便于测试基于 cgroup 的 abuse primitives。

快速检查 runtime 的实际情况也有助于确定 attack path 的优先级。Docker 提供 `--cgroupns=host|private`，而 Podman 支持 `host`、`private`、`container:<id>` 和 `ns:<path>`。具体来说，在 Podman 中，默认值通常是：**cgroup v1 上为 `host`**，**cgroup v2 上为 `private`**。因此，仅识别 cgroup 版本，就能在检查完整 OCI config 之前，判断更可能采用哪种 namespace posture。

### Modern v2 Recon：这是一个 Delegated Subtree 吗？

在现代主机上，关键问题通常不再是 `release_agent`，而是当前进程是否位于一个具有足够可见性或写入权限的 delegated **cgroup v2** subtree 中，以便创建 nested groups：
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
实用解读：

- `cgroup2fs` 表示你位于统一的 v2 层级中，因此经典的仅适用于 v1 的 `release_agent` 链不应再作为首要判断。
- `cgroup.controllers` 显示父级可用的 controllers，因此也表示当前 subtree 理论上可以向子级扩展哪些 controllers。
- `cgroup.subtree_control` 显示后代实际启用的 controllers。
- `cgroup.events` 暴露 `populated=0/1`，便于监控某个 subtree 是否已变为空，但它**不是**类似 v1 `release_agent` 的 host-code-execution 原语。

如果你已经拥有足够的权限，可以直接检查另一个进程的 namespace，请使用以下方式比较视图：
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### 完整示例：共享 cgroup Namespace + 可写 cgroup v1

单独使用 cgroup namespace 通常不足以实现 escape。当暴露主机信息的 cgroup 路径与可写的 cgroup v1 接口结合时，才会发生实际的权限提升：
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
如果这些文件可访问且可写入，请立即根据 [cgroups.md](../cgroups.md) 进入完整的 `release_agent` exploitation flow。其影响是从 container 内执行 host code。

如果 cgroup interfaces 不可写入，其影响通常仅限于 reconnaissance。

## Checks

这些命令的目的是确认进程是否拥有 private cgroup namespace view，或者是否了解了超出实际需求的 host hierarchy。
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
这里值得关注的内容：

- 如果 namespace identifier 与你关注的 host process 匹配，则 cgroup namespace 可能是共享的。
- `/proc/self/cgroup` 中暴露 host 信息的路径，或 `mountinfo` 中以 ancestor 为根的条目，即使不能直接利用，也可用于 reconnaissance。
- 如果正在使用 `cgroup2fs`，应重点关注 delegation、可见的 controllers 以及可写的 subtrees，而不是假设旧版 v1 primitives 仍然存在。
- 如果 cgroup mounts 同样可写，那么 visibility 问题就变得更加重要。

cgroup namespace 应被视为 visibility-hardening layer，而不是主要的 escape-prevention mechanism。毫无必要地暴露 host cgroup 结构，会为 attacker 增加 reconnaissance 价值。

## 参考资料

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
