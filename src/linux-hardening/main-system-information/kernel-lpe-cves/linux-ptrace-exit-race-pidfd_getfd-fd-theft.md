# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

一种实用的 **Linux kernel privesc pattern**，是将 **ptrace authorization bug** 转化为从 privileged process 中进行 **file descriptor theft**。

在 Qualys 的 `__ptrace_may_access()` case study（CVE-2026-46333）中，attacker 会与一个正在退出或 dropping credentials 的 **privileged process** 进行 race，并使用 `pidfd_getfd()` 将一个 FD duplicate 到 attacker process 中。

## Core idea

`pidfd_getfd()` 会从另一个 process duplicate 一个 file descriptor，但在此之前会针对 target 执行 ptrace-style permissions 检查。如果该 authorization 在 **teardown window** 期间被错误授予，那么 unprivileged attacker 就能复制：

- privileged helper 已打开的 **sensitive files** 对应的 FDs
- 已以 root 身份完成 authorization 的 **authenticated IPC channels** 对应的 FDs

这会将 kernel-side authorization bug 转化为非常实用的 userspace primitive。

## Why the primitive is dangerous

该 attack **不需要 privileged helper 本身存在 bug**。helper 只需要暂时持有有价值的对象：

- `/etc/shadow`
- `/etc/ssh/*_key`
- 一个 privileged D-Bus / systemd connection
- 任何其他已打开的 secret 或 authorized channel

一旦 FD 被 duplicate 到 attacker process 中，kernel 会基于 **stolen FD** 强制执行操作，而不是基于原始 pathname 或新的 authentication flow。

## Exploitation pattern

1. 识别一个会打开 sensitive files 或保持有用 IPC connections 的 **setuid / setgid / file-capability binary** 或 **root daemon**。
2. 建立一种能够满足 target path 相关 ptrace policy checks 的关系（例如，在 permissive YAMA settings 下，成为 spawned privileged child 的 **parent**）。
3. 在 process **exiting**、**dropping credentials** 或以其他方式进入 ptrace access 本应已不可用的状态时，对其进行 race。
4. 使用 `pidfd_open()` + `pidfd_getfd()`，在狭窄的 authorization window 内 duplicate target FD。
5. 在 unprivileged context 中复用 stolen FD：
- 从 privileged file descriptor 中通过 `read()` 读取 secrets
- 通过 stolen authenticated IPC channel 发送 requests，以获取 **root-side actions**

最小 primitive 形式：
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## 要审计的实际目标

优先检查那些即使只是短暂时间内也会执行以下操作之一的 binaries 和 daemons：

- 在完成权限转换前打开仅 root 可访问的文件
- 连接到 **system bus** 并保留一个已经完成授权的 channel
- 跨 helper 边界传递特权 FDs
- 在 `do_exit()` 附近的 teardown 期间执行安全敏感操作

值得重点检查的候选对象：

- password / account management helpers
- SSH helpers
- PolicyKit / D-Bus mediated helpers
- 暴露 D-Bus methods 的 root desktop daemons

## YAMA 作为 exploit gate

`kernel.yama.ptrace_scope` 是 ptrace-family abuse 的一个重要实际 gate：

- `0`：经典的 same-UID ptrace 行为
- `1`：通常允许 parent -> child tracing，这可以使一些 public exploit paths 保持可用
- `2`：attach-style access 需要 `CAP_SYS_PTRACE`，并阻止此路径中的 unprivileged `pidfd_getfd()` abuse
- `3`：完全禁用 ptrace attach，直到 reboot

对于这种 technique，`ptrace_scope=2` 是一种有效的 **temporary mitigation**，因为它会通过向 unprivileged users 返回 `-EPERM`，阻断 public `pidfd_getfd()` exploitation path。

## Detection / review ideas

审计特权 Linux software 时，寻找以下组合：

- **privileged child process** + **attacker-controlled parent**
- 临时访问 **valuable open files**
- 临时访问 **authenticated D-Bus/systemd channels**
- 在经典 `ptrace(2)` 之外，复用 **ptrace-style authorization** 的安全决策
- 可以 **duplicate、inherit 或 re-export** 现有特权 FDs 的 kernel APIs

审计 kernel 时，任何在 **task teardown** 期间执行 **ptrace-equivalent authorization** 的路径都应视为高风险，尤其是在成功后可以直接访问 `task->files` 或其他已经完成授权的 process resources 的情况下。

## References

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
