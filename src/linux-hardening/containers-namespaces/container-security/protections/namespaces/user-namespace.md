# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

user namespace 通过让 kernel 将 namespace 内看到的 user 和 group ID 映射到 namespace 外的不同 ID，从而改变 user 和 group ID 的含义。这是现代 container protection 中最重要的机制之一，因为它直接解决了 classic container 历史上最大的问题：**container 内的 root 曾经与 host 上的 root 过于接近**。

借助 user namespace，一个 process 可以在 container 内以 UID 0 运行，同时仍对应 host 上的 unprivileged UID 范围。这意味着该 process 可以像 root 一样执行许多 container 内的任务，但从 host 的角度看，其权限要小得多。这并不能解决所有 container security 问题，但会显著改变 container compromise 的后果。

## Operation

user namespace 具有 `/proc/self/uid_map` 和 `/proc/self/gid_map` 等 mapping file，用于描述 namespace ID 如何转换为 parent ID。如果 namespace 内的 root 映射到 host 上的 unprivileged UID，那么需要真正 host root 权限的操作就不再具有同等的权限。这正是 user namespace 成为 **rootless containers** 核心机制的原因，也是旧式 rootful container 默认配置与更现代的 least-privilege design 之间最大的区别之一。

这里的关键点很微妙，但非常重要：container 内的 root 并没有被消除，而是被**转换**了。该 process 在本地仍然会处于类似 root 的环境中，但 host 不应将其视为完整 root。

## 实验

手动测试方法如下：
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
这会让当前用户在 namespace 内看起来像 root，同时在 namespace 外仍不是 host root。这是理解 user namespaces 为什么如此有价值的最佳简单示例之一。

在 containers 中，你可以使用以下内容对比可见的映射：
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
具体输出取决于引擎使用的是 user namespace remapping 还是更传统的 rootful 配置。

你也可以从 host 端读取该映射：
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## 运行时使用

Rootless Podman 是将 user namespaces 视为一等安全机制的最清晰示例之一。Rootless Docker 也依赖它们。Docker 的 userns-remap 支持也能提高 rootful daemon 部署的安全性，不过出于兼容性原因，历史上许多部署都将其禁用。Kubernetes 对 user namespaces 的支持已有所改善，但其采用情况和默认设置会因 runtime、distro 和 cluster policy 而异。Incus/LXC 系统也高度依赖 UID/GID shifting 和 idmapping 思路。

总体趋势很明显：认真使用 user namespaces 的环境，通常比不使用它们的环境更能回答“container root 到底意味着什么？”这一问题。

## 高级映射细节

当 unprivileged process 写入 `uid_map` 或 `gid_map` 时，kernel 会应用比 privileged parent namespace writer 更严格的规则。只允许有限的 mappings；对于 `gid_map`，writer 通常需要先禁用 `setgroups(2)`：
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
这一细节很重要，因为它解释了为什么 user-namespace setup 有时会在 rootless 实验中失败，以及为什么 runtimes 需要围绕 UID/GID delegation 编写谨慎的 helper logic。

另一个 advanced feature 是 **ID-mapped mount**。它不会修改磁盘上的 ownership，而是将 user-namespace mapping 应用到某个 mount，使 ownership 通过该 mount view 显示为经过转换的形式。这一点在 rootless 和现代 runtime setup 中尤其重要，因为它允许使用共享的 host paths，而无需执行递归的 `chown` 操作。从安全角度看，该 feature 会改变 bind mount 从 namespace 内部看起来有多大 writable 权限，尽管它不会重写底层 filesystem metadata。

最后，请记住，当某个 process 创建或进入新的 user namespace 时，它会在**该 namespace 内部**获得完整的 capability set。这并不意味着它突然获得了 host-global power，而是意味着这些 capabilities 只能在 namespace model 和其他 protections 允许的范围内使用。这正是 `unshare -U` 能够突然使 mounting 或 namespace-local privileged operations 成为可能，却不会直接让 host root boundary 消失的原因。

## Misconfigurations

最主要的 weakness 只是：在本可以使用 user namespaces 的环境中没有使用它们。如果 container root 过于直接地映射到 host root，那么 writable host mounts 和 privileged kernel operations 会变得危险得多。另一个问题是，为了兼容性而强制共享 host user namespace 或禁用 remapping，却没有意识到这会在多大程度上改变 trust boundary。

User namespaces 也需要与其余 model 一起考虑。即使它们处于 active 状态，广泛暴露的 runtime API 或非常薄弱的 runtime configuration 仍可能通过其他路径导致 privilege escalation。但如果没有它们，许多旧的 breakout classes 会更容易被 exploit。

## Abuse

如果 container 是 rootful 且没有 user namespace separation，那么 writable host bind mount 会危险得多，因为该 process 可能实际上是以 host root 身份写入。危险的 capabilities 同样会变得更有意义。Attacker 不再需要尽力对抗 translation boundary，因为 translation boundary 几乎不存在。

在评估 container breakout path 时，应尽早检查 user namespace 是否存在。它不能回答所有问题，但可以立即显示“root in container”是否与 host 直接相关。

最实用的 abuse pattern 是确认 mapping，然后立即测试 host-mounted content 是否能以与 host 相关的 privileges 写入：
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
如果该文件是以真实的 host root 身份创建的，那么对于该路径而言，user namespace 隔离实际上并不存在。此时，传统的 host 文件滥用就变得切实可行：
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
在进行中的 assessment 中，更安全的确认方式是写入无害的标记，而不是修改关键文件：
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
这些检查很重要，因为它们能快速回答真正的问题：此容器中的 root 是否与主机 root 映射得足够接近，以至于一个可写的主机挂载会立即成为入侵主机的路径？

### 完整示例：重新获得命名空间本地 capabilities

如果 seccomp 允许 `unshare`，且环境允许创建新的 user namespace，则进程可能会在该新命名空间内重新获得完整的 capability 集合：
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
这本身并不是一次 host escape。它之所以重要，是因为 user namespaces 可以重新启用特权 namespace-local 操作，而这些操作之后可能与配置薄弱的挂载、存在漏洞的内核或暴露不当的 runtime surfaces 结合。

## 检查

这些命令旨在回答本页面中最重要的问题：此 container 内部的 root 会映射到 host 上的哪个身份？
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
这里有哪些值得关注的内容：

- 如果进程的 UID 为 0，并且映射显示其直接映射到宿主机 root，或与宿主机 root 非常接近，那么该容器的危险性会高得多。
- 如果 root 映射到宿主机上的非特权范围，这是更安全的基线，通常表明存在真正的 user namespace 隔离。
- 映射文件比单独查看 `id` 更有价值，因为 `id` 只显示 namespace 内的本地身份。

如果 workload 以 UID 0 运行，并且映射表明该 UID 与宿主机 root 密切对应，那么你应当更加严格地评估该容器的其他权限。

{{#include ../../../../../banners/hacktricks-training.md}}
