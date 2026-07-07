# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

cgroup namespace 不会替代 cgroups，也不会自行强制执行资源限制。相反，它改变的是进程看到的 **cgroup 层级结构的呈现方式**。换句话说，它对可见的 cgroup 路径信息做了虚拟化，让 workload 看到的是容器范围内的视图，而不是完整的主机层级。

这主要是一个可见性和信息减少的特性。它有助于让环境看起来是自包含的，并暴露更少的主机 cgroup 布局信息。听起来影响不大，但仍然很重要，因为对主机结构的不必要可见性可能有助于侦察，并简化依赖环境的 exploit 链。

## Operation

如果没有私有的 cgroup namespace，进程可能会看到主机相关的 cgroup 路径，暴露出比实际有用信息更多的机器层级结构。使用私有 cgroup namespace 时，`/proc/self/cgroup` 以及相关观察结果会更局限于容器自身的视图。这在现代 runtime 栈中特别有用，这类栈希望 workload 看到一个更干净、较少暴露主机信息的环境。

这种虚拟化也会影响 `/proc/<pid>/mountinfo`，不仅仅是 `/proc/<pid>/cgroup`。当你从不同的 cgroup-namespace 视角读取另一个进程时，位于你命名空间根之外的路径会以带有前导 `../` 组件的形式显示，这很好地提示你当前看到的是被委派子树之上的内容。对于实验环境和 post-exploitation 来说，一个有用的细节是：新创建的 cgroup namespace 往往需要在该 namespace 内部执行一次 **cgroupfs remount**，之后 `mountinfo` 才会干净地反映新的根。否则你可能仍然会看到类似 `/..` 的挂载根，这意味着继承来的挂载仍在暴露一个以祖先为根的视图，即使 namespace 本身已经发生了变化。

## Lab

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
如果你希望 `mountinfo` 更清楚地显示新的 cgroup-namespace root，请在新的 namespace 内重新挂载 cgroup 文件系统，然后再比较一次：
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
并与以下内容的运行时行为进行比较：
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
这个变化主要关系到进程能看到什么，而不是是否存在 cgroup enforcement。

## Security Impact

cgroup namespace 最好被理解为一种 **visibility-hardening layer**。它本身不会阻止 breakout，如果 container 具有可写的 cgroup mounts、较广的 capabilities，或者危险的 cgroup v1 environment，它并不能单独提供保护。然而，如果 host cgroup namespace 是共享的，进程会了解更多系统是如何组织的，并且可能更容易把 host-relative cgroup paths 与其他观察结果对应起来。

在 **cgroup v2** 上，namespace 会更重要一点，因为 delegation rules 更严格。如果层级以 `nsdelegate` 挂载，kernel 会把 cgroup namespaces 视为 delegation boundaries：祖先 control files 应该保持在被委托方的可达范围之外，而且在 namespace root 的写入仅限于 delegation-safe files，例如 `cgroup.procs`、`cgroup.threads` 和 `cgroup.subtree_control`。这仍然不会让这个 namespace 本身成为 escape primitive，但它会改变受 compromise 的 workload 能检查什么，以及它可以在哪里安全地创建子 cgroups。

所以，虽然这个 namespace 通常不会成为 container breakout writeups 的主角，但它仍然有助于更广泛地最小化 host information leakage 并约束 cgroup delegation。

## Abuse

最直接的 abuse 价值主要是 reconnaissance。如果 host cgroup namespace 是共享的，比较可见 paths，并查找会暴露 host 的 hierarchy details：
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
如果同时暴露了可写的 cgroup 路径，就将该可见性与对危险 legacy interfaces 的搜索结合起来：
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace 本身很少会直接给你 instant escape，但它通常会让环境更容易被梳理，从而在测试基于 cgroup 的 abuse primitives 之前先做 mapping。

快速做一次 runtime 现实检查也有助于优先排序 attack path。Docker 暴露 `--cgroupns=host|private`，而 Podman 支持 `host`、`private`、`container:<id>` 和 `ns:<path>`。尤其是在 Podman 上，默认通常是 **cgroup v1 时为 `host`**、**cgroup v2 时为 `private`**，所以仅仅识别 cgroup 版本，就已经能在你查看完整 OCI config 之前告诉你哪种 namespace posture 更可能存在。

### Modern v2 Recon: Is This A Delegated Subtree?

在现代主机上，真正值得关注的往往不是 `release_agent`，而是当前进程是否位于一个 delegated 的 **cgroup v2** subtree 中，并且具备足够的 visibility 或 write access 来构建 nested groups：
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
有用的解释：

- `cgroup2fs` 表示你处于统一的 v2 层级中，因此经典的仅 v1 `release_agent` 链应该不再是你的首选。
- `cgroup.controllers` 显示父级可用的 controller，因此当前子树理论上可以向子级展开到哪些 controller。
- `cgroup.subtree_control` 显示实际为后代启用的 controller。
- `cgroup.events` 暴露 `populated=0/1`，这对于观察一个子树是否已变空很有用，但它**不是**像 v1 `release_agent` 那样的 host-code-execution primitive。

如果你已经有足够的权限直接检查另一个 process namespace，用以下方式比较视图：
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### 完整示例：共享 cgroup namespace + 可写 cgroup v1

仅有 cgroup namespace 通常不足以逃逸。真正可行的提权发生在 host-revealing cgroup 路径与可写的 cgroup v1 接口结合时：
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
如果这些文件可访问且可写，立即转入 [cgroups.md](../cgroups.md) 中完整的 `release_agent` 利用流程。其影响是在容器内实现主机代码执行。

如果没有可写的 cgroup 接口，影响通常仅限于侦察。

## Checks

这些命令的目的，是查看进程是否拥有私有的 cgroup namespace 视图，或者是否比实际需要更多地了解主机层次结构。
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
这里有几个值得注意的点：

- 如果 namespace 标识符与您关心的 host process 匹配，那么 cgroup namespace 可能是共享的。
- `/proc/self/cgroup` 中暴露 host 的路径，或 `mountinfo` 中以 ancestor-rooted 的条目，即使不能直接利用，也很适合作为 reconnaissance。
- 如果正在使用 `cgroup2fs`，应关注 delegation、可见 controllers，以及可写子树，而不是假设旧的 v1 primitives 仍然存在。
- 如果 cgroup mounts 也可写，那么可见性问题就变得更加重要。

cgroup namespace 应被视为一层 visibility-hardening，而不是主要的 escape-prevention 机制。不必要地暴露 host cgroup 结构，会给攻击者增加 reconnaissance 价值。

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
