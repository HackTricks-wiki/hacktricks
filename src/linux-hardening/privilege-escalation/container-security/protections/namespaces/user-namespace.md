# 用户命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

用户命名空间通过允许内核将命名空间内部看到的用户和组 ID 映射到外部的不同 ID，从而改变了这些 ID 的含义。这是现代容器中最重要的防护措施之一，因为它直接解决了经典容器中最大的历史性问题：**容器内的 root 曾经与宿主机的 root 过于接近**。

使用用户命名空间时，进程在容器内可以以 UID 0 运行，但在宿主机上对应的是非特权的 UID 范围。也就是说，该进程在容器内对许多任务表现得像 root，但从宿主机角度看其权限要小得多。这并不能解决所有容器安全问题，但会显著改变容器被攻破后的后果。

## 运行原理

用户命名空间有映射文件，比如 `/proc/self/uid_map` 和 `/proc/self/gid_map`，用来描述命名空间内的 ID 如何转换为父命名空间的 ID。如果命名空间内的 root 被映射到宿主机上的非特权 UID，那么那些本来需要真正宿主机 root 的操作就不再具有同样的重量。这就是为什么用户命名空间是 **rootless containers** 的核心，也是旧版以 root 为默认的容器与更现代的最小权限设计之间最大差异之一。

这一点微妙但至关重要：容器内的 root 并没有被消除，而是被**转换**。进程在本地仍然感受到类似 root 的环境，但宿主机不应将其视为完整的 root。

## 实验

手动测试示例：
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
这会使当前用户在 namespace 内看起来像 root，但在外部仍然不是主机的 root。它是理解为什么 user namespaces 如此有价值的最佳简单示例之一。

在容器中，你可以比较可见的映射：
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
确切的输出取决于引擎是否使用 user namespace remapping 或更传统的 rootful 配置。

你也可以从主机端读取映射，方法如下：
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## 运行时用法

Rootless Podman 是将用户命名空间视为一等安全机制的最明显示例之一。Rootless Docker 也依赖它们。Docker 的 userns-remap 支持也能在有特权守护进程的部署中提高安全性，尽管历史上许多部署出于兼容性原因将其禁用。Kubernetes 对用户命名空间的支持已有改进，但不同 runtime、distro 和集群策略的采用情况与默认设置各不相同。Incus/LXC 系统也在很大程度上依赖 UID/GID shifting 和 idmapping 的思想。

## 高级映射细节

当非特权进程向 `uid_map` 或 `gid_map` 写入时，内核会对其应用比对特权父命名空间写入者更严格的规则。只允许有限的映射，并且对于 `gid_map`，写入者通常需要先禁用 `setgroups(2)`：
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
这个细节很重要，因为它解释了为什么在 rootless 实验中 user-namespace 的设置有时会失败，以及为什么运行时需要围绕 UID/GID 委派的细致辅助逻辑。

另一个高级特性是 **ID 映射挂载**。与修改磁盘上所有者不同，ID 映射挂载会将一个用户命名空间映射应用到一个挂载点，使得通过该挂载看到的所有权被翻译显示。这在 rootless 和现代运行时设置中特别相关，因为它允许使用共享宿主路径而无需递归执行 `chown` 操作。从安全性角度看，该特性改变了从命名空间内部看一个 bind 挂载点的可写性，尽管它并不会重写底层文件系统的元数据。

最后，记住当一个进程创建或进入一个新的用户命名空间时，它会在该命名空间内获得一整套能力（capabilities）。这并不意味着它突然获得了对主机全局的权限。这意味着这些能力只能在命名空间模型和其他保护允许的范围内使用。因此 `unshare -U` 能够突然让挂载或命名空间范围内的特权操作变为可能，但这并不直接使主机的 root 边界消失。

## 错误配置

主要弱点是没有在可行的环境中使用用户命名空间。如果容器内的 root 与宿主机的 root 映射得过于直接，可写的宿主机挂载点和特权的内核操作就会变得更加危险。另一个问题是为了兼容而强制共享宿主的用户命名空间或禁用重映射，而没有认识到这会大幅改变信任边界。

用户命名空间还需要与模型的其余部分一并考虑。即便它们被启用，宽泛的运行时 API 暴露或非常薄弱的运行时配置仍然可能允许通过其他路径进行权限提升。但如果没有用户命名空间，许多旧有的逃逸类别就会更容易被利用。

## 滥用

如果容器是 rootful 且没有用户命名空间隔离，可写的宿主机 bind 挂载就变得极其危险，因为进程可能真的以宿主机 root 的身份在写入。危险的能力（capabilities）也因此变得更有意义。攻击者不再需要对抗翻译边界那么多，因为这种翻译边界几乎不存在。

在评估容器逃逸路径时，应及早检查用户命名空间的存在与否。它不能回答所有问题，但能立刻表明“容器内的 root”是否直接与宿主机相关。

最实用的滥用模式是先确认映射，然后立即测试宿主机挂载的内容是否可以用对宿主机有意义的权限写入：
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
如果该文件被以宿主机上的真实 root 身份创建，那么在该路径上 user namespace 隔离实际上不存在。到那时，经典的宿主机文件滥用就变得现实可行：
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
在现场评估中，更安全的确认方法是写入一个无害的标记，而不是修改关键文件：
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
这些检查很重要，因为它们可以快速回答一个关键问题：容器内的 root 是否与宿主机的 root 映射得足够接近，以至于一个可写的宿主挂载点会立即成为宿主被攻陷的路径？

### 完整示例：重新获取 Namespace-Local Capabilities

如果 seccomp 允许 `unshare` 且环境允许创建一个新的 user namespace，那么进程可能会在该新命名空间内重新获得完整的 capability 集：
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
这本身并不是一次主机逃逸。重要性在于 user namespaces 可以重新启用有特权的命名空间本地操作，而这些操作随后可能与弱挂载、存在漏洞的内核或暴露不当的运行时接口结合。

## 检查

这些命令旨在回答本页面中最重要的问题：该容器内的 root 在宿主机上映射为何？
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- 如果进程是 UID 0 并且 maps 显示一个直接或非常接近的 host-root mapping，则该容器要危险得多。
- 如果 root 映射到 unprivileged host range，那是一个更安全的基线，通常表明真实的 user namespace 隔离。
- 映射文件比单独的 `id` 更有价值，因为 `id` 只显示命名空间内的身份。

如果工作负载以 UID 0 运行并且映射显示这与 host root 非常接近，则你应更严格地解读容器其余的权限。
{{#include ../../../../../banners/hacktricks-training.md}}
