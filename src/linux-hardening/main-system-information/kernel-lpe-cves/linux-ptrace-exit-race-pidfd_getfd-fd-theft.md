# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

一种实用的 **Linux kernel privesc pattern** 是将 **ptrace authorization bug** 转化为从 privileged process **file descriptor theft**。

在 Qualys 的 `__ptrace_may_access()` case study（CVE-2026-46333）中，attacker 与一个正在退出或 dropping credentials 的 **privileged process** 进行 race，并使用 `pidfd_getfd()` 将一个 FD duplicate 到 attacker process 中。<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` 会从另一个 process duplicate 一个 file descriptor，但首先会针对 target 执行 ptrace-style permissions 检查。<sup>[[3]](#references)</sup> 如果该 authorization 在 **teardown window** 期间被错误授予，unprivileged attacker 就可以复制：

- privileged helper 已打开的 **sensitive files** 的 FDs
- 已作为 root 完成 authorization 的 **authenticated IPC channels** 的 FDs

这会将 kernel-side authorization bug 转化为一个非常实用的 userspace primitive。<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

该 attack **不需要 privileged helper 自身存在 bug**。helper 只需要暂时持有有价值的对象：

- `/etc/shadow`
- `/etc/ssh/*_key`
- privileged D-Bus / systemd connection
- 任何其他已经打开的 secret 或 authorized channel

一旦 duplicate 到 attacker process 中，该 duplicate 会指向同一个 open file description，因此后续的 reads 或 IPC requests 会使用已经打开的 FD，而不是重新打开原始 pathname 或启动新的 authentication flow。<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. 识别一个会打开 sensitive files 或保持有用 IPC connections 的 **setuid / setgid / file-capability binary** 或 **root daemon**。<sup>[[2]](#references)</sup>
2. 建立一种 relationship，使其满足 target path 上相关的 ptrace policy checks（例如，在 permissive YAMA settings 下，成为 spawned privileged child 的 **parent**）。<sup>[[2]](#references)[[4]](#references)</sup>
3. 在 process **exiting**、**dropping credentials** 或以其他方式进入 ptrace access 本应变为不可用的状态时，对其进行 race。<sup>[[2]](#references)</sup>
4. 使用 `pidfd_open()` + `pidfd_getfd()`，在狭窄的 authorization window 期间 duplicate target FD。<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. 在 unprivileged context 中复用 stolen FD。<sup>[[2]](#references)</sup>
- 从 privileged file descriptor `read()` secrets
- 通过 stolen authenticated IPC channel 发送 requests，以获取 **root-side actions**

Minimal primitive shape。<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## 要重点审计的实际目标

优先关注那些即使只是短暂执行以下操作之一的 binaries 和 daemons：<sup>[[1]](#references)[[2]](#references)</sup>

- 在完成 privilege transitions 前打开仅 root 可访问的文件
- 连接到 **system bus** 并保持一个已经授权的 channel
- 跨 helper 边界传递 privileged FDs
- 在接近 `do_exit()` 的 teardown 阶段执行 security-sensitive 工作

适合重点检查的候选目标：<sup>[[1]](#references)</sup>

- password / account management helpers
- SSH helpers
- PolicyKit / D-Bus mediated helpers
- 暴露 D-Bus methods 的 root desktop daemons

## YAMA 作为 exploit gate

`kernel.yama.ptrace_scope` 是 ptrace-family abuse 的一个主要 practical gate：<sup>[[3]](#references)[[4]](#references)</sup>

- `0`：经典的 same-UID ptrace 行为
- `1`：通常允许 parent -> child tracing，这可以使部分 public exploit paths 保持可达
- `2`：attach-style access 需要 `CAP_SYS_PTRACE`，并阻止此路径中的 unprivileged `pidfd_getfd()` abuse
- `3`：完全禁用 ptrace attach，直到 reboot

对于该 technique，`ptrace_scope=2` 是一种强力的 **temporary mitigation**，因为它会使 public `pidfd_getfd()` exploitation path 对 unprivileged users 返回 `-EPERM`，从而失效。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## 检测 / review 思路

审计 privileged Linux software 时，重点查找以下组合：

- **privileged child process** + **attacker-controlled parent**。<sup>[[2]](#references)[[4]](#references)</sup>
- 临时访问 **valuable open files**
- 临时访问 **authenticated D-Bus/systemd channels**。<sup>[[2]](#references)</sup>
- 在经典 `ptrace(2)` 之外复用 **ptrace-style authorization** 的 security decisions
- 可以 **duplicate、inherit 或 re-export** 现有 privileged FDs 的 kernel APIs

审计 kernel 时，任何在 **task teardown** 期间执行 **ptrace-equivalent authorization** 的路径都应视为 high risk，尤其是在成功后可以直接访问 `task->files` 或其他已授权 process resources 的情况下。<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333：Linux Kernel ptrace Path 中的 Local Root Privilege Escalation 和 Credential Disclosure（Qualys）](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
