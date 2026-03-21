# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

cgroup namespace 并不替代 cgroups，也不会自身强制执行资源限制。相反，它改变了进程看到 cgroup 层级的方式（how the cgroup hierarchy appears）。换句话说，它对可见的 cgroup 路径信息进行虚拟化，使工作负载看到的是一个以容器为范围的视图，而不是完整的主机层级。

这主要是一个可见性和信息减少的特性。它有助于使环境看起来自包含，并减少对主机 cgroup 布局的暴露。听起来可能微不足道，但这很重要，因为不必要的主机结构可见性会帮助侦察并简化依赖环境的漏洞利用链。

## 工作原理

如果没有私有的 cgroup namespace，进程可能会看到相对于主机的 cgroup 路径，从而暴露出比实际需要更多的机器层级。拥有私有 cgroup namespace 时，/proc/self/cgroup 和相关观察将更本地化于容器自身的视图。这在现代运行时栈中尤其有用，它们希望工作负载看到更干净、较少暴露主机信息的环境。

## 实验

你可以使用以下方式检查 cgroup namespace：
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
并将运行时行为与以下进行比较：
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
此更改主要涉及进程能看到的内容，而不是 cgroup enforcement 是否存在。

## 安全影响

cgroup namespace 最好被理解为一个 **可见性强化层**。单独看它不会阻止 breakout——如果容器有可写的 cgroup mounts、广泛的 capabilities，或危险的 cgroup v1 环境，breakout 仍然可能发生。不过，如果 host cgroup namespace 被共享，进程会更多地了解系统如何组织，并可能更容易将 host-relative cgroup paths 与其他观测结果对齐。

因此，尽管这个 namespace 通常不是 container breakout writeups 的主角，但它仍有助于实现最小化主机信息 leakage 的更广泛目标。

## 滥用

立即的滥用价值主要是 reconnaissance。如果 host cgroup namespace 被共享，比较可见的路径并查找 host-revealing hierarchy details：
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
如果可写的 cgroup 路径也被暴露，请将该可见性与对危险的遗留接口的搜索结合起来：
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace 本身很少能立即导致 escape，但它常常在测试基于 cgroup 的 abuse primitives 之前，使环境更容易被映射。

### 完整示例：共享 cgroup Namespace + 可写 cgroup v1

仅有 cgroup namespace 通常不足以实现 escape。实际的提权发生在暴露主机信息的 cgroup paths 与可写的 cgroup v1 interfaces 结合时：
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
如果那些文件可访问且可写，请立即切换到来自 [cgroups.md](../cgroups.md) 的完整 `release_agent` 利用流程。其影响是从容器内在宿主机上执行代码。

如果 cgroup 接口不可写，影响通常仅限于侦察。

## 检查

这些命令的目的是查看该进程是否具有私有的 cgroup 命名空间视图，或是否正在获取比其实际需要更多的宿主机层级信息。
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
这里有几点有意思的地方：

- 如果命名空间标识符与你关心的主机进程匹配，cgroup namespace 可能会被共享。
- 即使不能被直接利用，`/proc/self/cgroup` 中能揭示主机信息的路径在侦察时也很有用。
- 如果 cgroup mounts 也是可写的，可见性的问题就变得更加重要。

cgroup namespace 应被视为一种可见性加固层，而不是主要的逃逸预防机制。非必要地暴露主机的 cgroup 结构会为攻击者增加侦察价值。
