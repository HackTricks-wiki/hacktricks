# cgroup 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

cgroup 命名空间并不替代 cgroups，也不会自身强制执行资源限制。它改变的是进程看到 **cgroup 层级如何呈现**。换句话说，它对可见的 cgroup 路径信息进行虚拟化，使得工作负载看到的是一个容器作用域的视图，而不是完整的主机层级。

这主要是一个可见性和信息减少的特性。它有助于让环境看起来更自包含，并减少关于主机 cgroup 布局的暴露。这听起来可能微不足道，但仍然重要，因为对主机结构的不必要可见性可能会帮助 reconnaissance 并简化依赖环境的 exploit chains。

## 工作原理

如果没有独立的 cgroup 命名空间，进程可能会看到以主机为相对路径的 cgroup 路径，从而暴露比实际需要更多的机器层级信息。使用独立的 cgroup 命名空间后，/proc/self/cgroup 和相关的观测结果会更局限于容器自身的视图。这对于想让工作负载看到更干净、较少暴露主机信息的现代 runtime 堆栈尤其有用。

## 实验

你可以使用以下方法检查 cgroup 命名空间：
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
并比较运行时行为与：
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
这个改变主要与进程能够看到的内容有关，而不是 cgroup enforcement 是否存在。

## 安全影响

cgroup namespace 最好被理解为一个 **visibility-hardening layer（可见性强化层）**。单独存在时，如果容器有可写的 cgroup mounts、宽泛的 capabilities，或危险的 cgroup v1 环境，它并不能阻止 breakout。然而，如果共享了 host cgroup namespace，进程会了解到系统的组织方式，并可能更容易将基于主机的 cgroup paths 与其他观测结果对齐。

因此，尽管这个 namespace 通常不是 container breakout 报告中的主角，但它仍有助于实现最小化 host information leakage 的更广泛目标。

## 滥用

直接的滥用价值主要是侦察。如果共享了 host cgroup namespace，比较可见的 paths 并查找能暴露主机信息的层级细节：
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
如果可写的 cgroup 路径也被暴露，将该可见性与对危险遗留接口的搜索结合起来：
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
该 namespace 本身很少会立即导致 escape，但它通常在测试 cgroup-based abuse primitives 之前使环境更容易被映射。

### 完整示例：Shared cgroup Namespace + Writable cgroup v1

单独的 cgroup namespace 通常不足以实现 escape。实际的提权发生在 host-revealing cgroup paths 与 writable cgroup v1 interfaces 结合时：
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
如果这些文件可访问且可写，请立即转到来自 [cgroups.md](../cgroups.md) 的完整 `release_agent` 利用流程。该影响是从 container 内部对主机的代码执行。

如果没有可写的 cgroup 接口，影响通常仅限于侦察。

## Checks

这些命令的目的是查看进程是否拥有私有的 cgroup namespace 视图，或是否在了解比它实际需要的更多主机层次结构信息。
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
这里有几点有趣的地方：

- 如果命名空间标识符与某个你关心的主机进程匹配，则该 cgroup 命名空间可能是共享的。
- 即使它们不能直接被利用，`/proc/self/cgroup` 中暴露主机信息的路径对于 reconnaissance 仍然有用。
- 如果 cgroup 的挂载点也是可写的，那么可见性的问题就变得更加重要。

cgroup 命名空间应被视为一个可见性加固层，而不是主要的 escape-prevention 机制。无谓地暴露主机的 cgroup 结构会为攻击者增加 reconnaissance 价值。
{{#include ../../../../../banners/hacktricks-training.md}}
