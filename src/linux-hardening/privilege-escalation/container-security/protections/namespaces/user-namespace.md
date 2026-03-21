# 用户命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

用户命名空间通过让内核将命名空间内部看到的用户和组 ID 映射到外部不同的 ID，从而改变了这些 ID 的含义。这是现代容器保护中最重要的机制之一，因为它直接解决了传统容器的最大历史问题：**容器内部的 root 曾经与宿主上的 root 近得令人不安**。

在用户命名空间中，进程可以在容器内以 UID 0 运行，同时在宿主上对应一个非特权的 UID 范围。也就是说，该进程在容器内可以像 root 一样执行许多任务，但从宿主的角度来看其权限要低得多。这并不能解决所有容器安全问题，但会显著改变容器被攻破时的后果。

## 工作原理

用户命名空间包含映射文件，例如 `/proc/self/uid_map` 和 `/proc/self/gid_map`，用于描述命名空间 ID 如何映射到父 ID。如果命名空间内的 root 映射到宿主上的非特权 UID，那么那些本应需要宿主上真实 root 的操作就不会具有同等的影响力。这就是为什么用户命名空间是 **rootless containers** 的核心，也为什么它们是旧的 rootful 容器默认设置与更现代的最小权限设计之间的最大区别之一。

这一点微妙但至关重要：容器内的 root 并没有被消除，而是被**转换**。进程在本地仍然体验到类似 root 的环境，但宿主不应将其视为完整的 root。

## 实验

一个手动测试是：
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
这会使当前用户在命名空间内看起来像 root，但在外部宿主机上仍然不是 root。它是理解为什么用户命名空间如此有价值的最简单且最好的示例之一。

在容器中，你可以将可见映射与以下内容进行比较：
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
具体输出取决于引擎是否使用 user namespace remapping，或更传统的 rootful 配置。

你也可以从宿主机端读取映射：
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## 运行时用法

Rootless Podman 是将用户命名空间作为一等安全机制的最明显例子之一。Rootless Docker 也依赖它们。Docker 的 userns-remap 支持也提高了在 rootful daemon 部署中的安全性，尽管历史上许多部署出于兼容性原因将其禁用。Kubernetes 对用户命名空间的支持已有所改进，但按运行时、发行版和集群策略的不同，采纳情况和默认设置各异。Incus/LXC 系统也大量依赖 UID/GID shifting 和 idmapping 的理念。

总体趋势很明显：认真使用用户命名空间的环境通常比不使用的环境更能准确回答“container root 实际上意味着什么？”这个问题。

## 高级映射细节

当一个非特权进程写入 `uid_map` 或 `gid_map` 时，内核会施加比对有特权的父命名空间写入者更严格的规则。只允许有限的映射，并且对于 `gid_map`，写入者通常需要先禁用 `setgroups(2)`：
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
这一点很重要，因为它解释了为什么 user-namespace 的设置在 rootless 实验中有时会失败，以及为什么 runtimes 需要在 UID/GID 委派上有谨慎的辅助逻辑。

另一个高级特性是 **ID-mapped mount**。ID-mapped mount 并不改变磁盘上的所有权，而是将一个 user-namespace 映射应用到一个 mount，使得通过该 mount 查看时所有权看起来被翻译了。这在 rootless 和现代 runtime 设置中尤其相关，因为它允许使用共享的 host 路径而无需递归执行 `chown` 操作。从安全角度看，该特性改变了从 namespace 内部看到的 bind mount 的可写性，尽管它并不重写底层文件系统的元数据。

最后，记住当一个进程创建或进入一个新的 user namespace 时，它会在**该 namespace 内部**获得一整套 capabilities。 这并不意味着它突然获得了对 host 全局的权限。意思是这些 capabilities 只能在 namespace 模型和其他保护允许的范围内使用。这就是为什么 `unshare -U` 能够突然使得挂载或 namespace 本地的特权操作变为可能，而不会直接让 host root 边界消失的原因。

## 误配置

主要的弱点就是在可行的环境中没有使用 user namespaces。如果 container root 与 host root 映射得过于直接，可写的 host mounts 和特权的 kernel 操作就会变得更加危险。另一个问题是为了兼容性强制共享 host user namespace 或禁用 remapping，而没有意识到这会在多大程度上改变信任边界。

User namespaces 还需要与模型的其他部分一并考虑。即便它们处于启用状态，广泛的 runtime API 暴露或非常薄弱的 runtime 配置仍然可能通过其他路径允许 privilege escalation。但如果没有它们，许多旧的 breakout 类别会变得更容易被利用。

## 滥用

如果容器是 rootful 且没有 user namespace 隔离，可写的 host bind mount 会变得极其危险，因为进程可能真的以 host root 的身份写入。危险的 capabilities 也因此更有意义。攻击者不再需要那么努力去对抗翻译边界，因为翻译边界几乎不存在。

在评估 container breakout 路径时，应尽早检查 user namespace 的存在与否。它不能回答所有问题，但能立即显示“root in container”是否与 host 有直接关联。

最实用的滥用模式是先确认映射，然后立即测试 host-mounted 内容在 host 相关的权限下是否可写：
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
如果该文件以真实 host root 身份创建，则对该路径的 user namespace 隔离实际上不存在。到那时，经典的 host-file abuses 就变得现实可行：
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
在现场评估中，更安全的确认方法是在不修改关键文件的情况下写入一个无害的标记：
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
这些检查很重要，因为它们能快速回答真正的问题：容器内的 root 是否与主机的 root 映射得足够接近，以至于一个可写的主机挂载会立即成为主机妥协的路径？

### 完整示例：恢复命名空间内的权限

如果 seccomp 允许 `unshare` 且环境允许创建一个新的用户命名空间，进程可能会在该新命名空间内恢复一整套权限：
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
这本身并不是一次 host escape。之所以重要，是因为 user namespaces 可能重新启用具有特权的 namespace-local 操作，而这些操作可能随后与 weak mounts、vulnerable kernels 或暴露不当的 runtime surfaces 结合。

## Checks

这些命令用于回答本页最重要的问题：container 内的 root 在 host 上映射为谁？
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- 如果进程是 UID 0 且 maps 显示了一个直接或非常接近的 host-root mapping，那么该容器的危险性要高得多。
- 如果 root 映射到 unprivileged host range，那就是一个更安全的基线，通常表明真实的 user namespace isolation。
- mapping files 比单独的 `id` 更有价值，因为 `id` 只能显示 namespace-local identity。

如果 workload 以 UID 0 运行并且 mapping 显示这与 host root 紧密对应，则应对容器其余的权限做更严格的解读。
