# Linux ptrace exit-race `pidfd_getfd()` FD 窃取

一种实用的 **Linux kernel privesc pattern**，是将 **ptrace authorization bug** 转化为从 privileged process **窃取 file descriptor**。

在 Qualys 的 `__ptrace_may_access()` case study（CVE-2026-46333）中，attacker 会与一个正在退出或 dropping credentials 的 **privileged process** 进行 race，并使用 `pidfd_getfd()` 将一个 FD duplicate 到 attacker process 中。<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` 会从另一个 process duplicate 一个 file descriptor，但首先会针对 target 执行 ptrace-style permissions 检查。<sup>[[3]](#references)</sup> 如果该 authorization 在 **teardown window** 期间被错误授予，unprivileged attacker 就可以复制：

- privileged helper 已经打开的 **sensitive files** 的 FDs
- 已经以 root 身份完成 authorization 的 **authenticated IPC channels** 的 FDs

这会将 kernel-side authorization bug 转化为一个非常实用的 userspace primitive。<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

该 attack **不需要 privileged helper 本身存在 bug**。helper 只需要暂时持有某些有价值的对象：

- `/etc/shadow`
- `/etc/ssh/*_key`
- 一个 privileged D-Bus / systemd connection
- 任何其他已经打开的 secret 或 authorized channel

一旦 duplicate 到 attacker process 中，该 duplicate 会指向同一个 open file description，因此后续的 reads 或 IPC requests 会使用已经打开的 FD，而不是重新打开原始 pathname，或启动全新的 authentication flow。<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. Identify 一个会打开 sensitive files 或保持有用 IPC connections 的 **setuid / setgid / file-capability binary** 或 **root daemon**。<sup>[[2]](#references)</sup>
2. 建立一种满足 target path 相关 ptrace policy checks 的关系（例如，在 permissive YAMA settings 下，成为 spawned privileged child 的 **parent**）。<sup>[[2]](#references)[[4]](#references)</sup>
3. 在 process **exiting**、**dropping credentials** 或以其他方式进入 ptrace access 本应变为 unavailable 的状态时，与其进行 race。<sup>[[2]](#references)</sup>
4. 使用 `pidfd_open()` + `pidfd_getfd()`，在狭窄的 authorization window 内 duplicate target FD。<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. 从 unprivileged context 重用被窃取的 FD。<sup>[[2]](#references)</sup>
- 从 privileged file descriptor `read()` secrets
- 通过被窃取的 authenticated IPC channel 发送 requests，以获取 **root-side actions**

Minimal primitive shape。<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## 要审计的实际目标

优先检查那些即使只是短暂执行，也会进行以下操作之一的 binaries 和 daemons：<sup>[[1]](#references)[[2]](#references)</sup>

- 在完成权限转换前打开仅限 root 访问的文件
- 连接到 **system bus** 并保留已授权的 channel
- 跨 helper 边界传递特权 FD
- 在临近 `do_exit()` 的 teardown 期间执行安全敏感操作

值得重点检查的目标：<sup>[[1]](#references)</sup>

- password / account management helpers
- SSH helpers
- PolicyKit / D-Bus mediated helpers
- 暴露 D-Bus methods 的 root desktop daemons

## YAMA 作为 exploit gate

`kernel.yama.ptrace_scope` 是 ptrace-family abuse 的重要实际 gate：<sup>[[3]](#references)[[4]](#references)</sup>

- `0`：经典的 same-UID ptrace 行为
- `1`：通常允许 parent -> child tracing，因此一些公开 exploit 路径仍可能可用
- `2`：attach-style access 需要 `CAP_SYS_PTRACE`，并阻止此路径中的 unprivileged `pidfd_getfd()` abuse
- `3`：完全禁用 ptrace attach，直到 reboot

对于此 technique，`ptrace_scope=2` 是一种有效的 **temporary mitigation**，因为它会使 unprivileged users 的公开 `pidfd_getfd()` exploitation path 以 `-EPERM` 失败。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Detection / review ideas

审计特权 Linux software 时，寻找以下组合：

- **privileged child process** + **attacker-controlled parent**。<sup>[[2]](#references)[[4]](#references)</sup>
- 对 **valuable open files** 的临时访问权限
- 对 **authenticated D-Bus/systemd channels** 的临时访问权限。<sup>[[2]](#references)</sup>
- 在经典 `ptrace(2)` 之外复用 **ptrace-style authorization** 的安全决策
- 能够 **duplicate、inherit 或 re-export** 现有特权 FD 的 kernel APIs

审计 kernel 时，应将任何在 **task teardown** 期间执行 **ptrace-equivalent authorization** 的路径视为高风险，尤其是在成功后可直接访问 `task->files` 或其他已获授权的 process resources 的情况下。<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333：Linux Kernel ptrace Path 中的 Local Root Privilege Escalation and Credential Disclosure（Qualys）](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) 手册页](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama 文档](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) 手册页](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
