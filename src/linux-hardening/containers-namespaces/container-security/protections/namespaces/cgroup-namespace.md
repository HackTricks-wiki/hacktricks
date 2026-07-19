# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

cgroup namespace 不会替代 cgroups，也不会自行强制实施资源限制。相反，它会改变 **cgroup 层级结构对进程的呈现方式**。换句话说，它会虚拟化可见的 cgroup 路径信息，使 workload 看到的是以容器为范围的视图，而不是完整的 host 层级结构。

这主要是一项可见性和信息缩减功能。它有助于让环境看起来更加自包含，并减少 host cgroup 布局的暴露。这听起来可能作用有限，但仍然很重要，因为不必要地暴露 host 结构可能有助于侦察，并简化依赖环境的 exploit chain。

## 操作

如果没有私有 cgroup namespace，进程可能会看到以 host 为相对基准的 cgroup 路径，从而暴露超出实际用途的机器层级结构。使用私有 cgroup namespace 后，`/proc/self/cgroup` 及相关观察结果会更加局限于容器自身的视图。这对于希望 workload 看到更干净、较少暴露 host 信息的现代 runtime stack 尤其有帮助。

这种虚拟化也会影响 `/proc/<pid>/mountinfo`，而不仅仅是 `/proc/<pid>/cgroup`。当你从不同的 cgroup-namespace 视角读取另一个进程时，位于 namespace root 之外的路径会显示为带有前导 `../` 组件的形式，这是一个很有用的线索，表明你正在查看 delegated subtree 之上的内容。对于 labs 和 post-exploitation，一个值得注意的细节是：新创建的 cgroup namespace 通常需要在该 namespace 内执行 **cgroupfs remount**，之后 `mountinfo` 才会干净地反映新的 root。否则，你可能仍会看到类似 `/..` 的 mount root，这意味着即使 namespace 本身已经发生变化，继承的 mount 仍在暴露以 ancestor 为 root 的视图。

## 实验

你可以使用以下方式检查 cgroup namespace：
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
如果你希望 `mountinfo` 更清晰地显示新的 cgroup-namespace root，请从新 namespace 内重新挂载 cgroup filesystem，然后再次进行比较：
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
并将运行时行为与以下内容进行比较：
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
这一变更主要影响进程能够看到的内容，而不是 cgroup enforcement 是否存在。

## Security Impact

cgroup namespace 最好理解为一种**visibility-hardening layer**。它本身无法阻止 breakout，尤其是在容器具有可写的 cgroup 挂载、过于宽泛的 capabilities，或处于危险的 cgroup v1 环境中时。不过，如果共享 host cgroup namespace，进程就能了解更多系统组织方式，并且可能更容易将相对于 host 的 cgroup 路径与其他观察结果对应起来。

在 **cgroup v2** 上，由于 delegation 规则更加严格，namespace 的作用会更明显一些。如果层级以 `nsdelegate` 挂载，kernel 会将 cgroup namespaces 视为 delegation 边界：祖先 control files 应保持在 delegatee 的访问范围之外，并且 namespace root 中的写入操作会限制为 `cgroup.procs`、`cgroup.threads` 和 `cgroup.subtree_control` 等符合 delegation 安全要求的文件。这仍然不意味着 namespace 本身就是 escape primitive，但它会改变被攻陷 workload 能够检查的内容，以及它可以安全创建 sub-cgroups 的位置。

因此，虽然这个 namespace 通常不是 container breakout writeups 的主角，但它仍有助于实现最大限度减少 host information leakage 并限制 cgroup delegation 的总体目标。

## Abuse

其直接的滥用价值主要在 reconnaissance。如果共享 host cgroup namespace，可以比较可见路径，并查找能够暴露 host 的层级细节：
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
如果同时暴露了可写的 cgroup 路径，请将这种可见性与对危险 legacy interfaces 的搜索结合起来：
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
该 namespace 本身很少会直接提供 escape，但它通常能让你在测试基于 cgroup 的 abuse primitives 之前，更容易对环境进行映射。

快速检查 runtime 的实际情况也有助于确定 attack path 的优先级。Docker 提供 `--cgroupns=host|private`，而 Podman 支持 `host`、`private`、`container:<id>` 和 `ns:<path>`。具体来说，在 Podman 中，默认值通常是：**cgroup v1 使用 `host`**，而 cgroup v2 使用 **`private`**。因此，仅确定 cgroup 版本，就能在检查完整 OCI config 之前，判断哪种 namespace posture 更有可能存在。

### Modern v2 Recon：这是一个 Delegated Subtree 吗？

在现代主机上，关键问题通常不再是 `release_agent`，而是当前进程是否位于一个具有足够可见性或写入权限的 delegated **cgroup v2** subtree 中，以便创建嵌套 group：
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
有用的解读：

- `cgroup2fs` 表示你位于统一的 v2 hierarchy 中，因此经典的仅适用于 v1 的 `release_agent` chains 不应再作为首要猜测。
- `cgroup.controllers` 显示 parent 提供了哪些 controllers，因此也表示当前 subtree 理论上可以向其 children 分配哪些 controllers。
- `cgroup.subtree_control` 显示 descendants 实际启用了哪些 controllers。
- `cgroup.events` 暴露 `populated=0/1`，便于监控某个 subtree 是否已变为空，但它**不是**像 v1 `release_agent` 那样的 host-code-execution primitive。

如果你已经拥有足够的 privilege，可以直接检查另一个 process namespace，请使用以下内容比较视图：
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### 完整示例：Shared cgroup Namespace + Writable cgroup v1

单独的 cgroup namespace 通常不足以实现 escape。当暴露 host 信息的 cgroup 路径与可写的 cgroup v1 interfaces 结合时，才会发生实际的权限提升：
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
如果这些文件可访问且可写入，请立即根据 [cgroups.md](../cgroups.md) 执行完整的 `release_agent` exploitation 流程。其影响是从 container 内执行 host 代码。

如果没有可写入的 cgroup interfaces，影响通常仅限于 reconnaissance。

## Checks

这些命令用于确认进程是否拥有私有的 cgroup namespace 视图，或者是否获知了超出实际所需范围的 host hierarchy。
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
这里值得关注的是：

- 如果 namespace identifier 与你关注的 host process 匹配，则 cgroup namespace 可能是共享的。
- `/proc/self/cgroup` 中暴露 host 信息的路径，或 `mountinfo` 中以 ancestor 为根的条目，即使无法直接利用，也能提供有价值的 reconnaissance 信息。
- 如果正在使用 `cgroup2fs`，应重点关注 delegation、可见的 controllers 以及可写的 subtrees，而不要假设旧版 v1 primitives 仍然存在。
- 如果 cgroup mounts 同样可写，visibility 问题就会变得更加重要。

cgroup namespace 应被视为 visibility-hardening layer，而不是主要的 escape-prevention mechanism。无必要地暴露 host cgroup 结构，会为 attacker 增加 reconnaissance 价值。

## 参考资料

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
