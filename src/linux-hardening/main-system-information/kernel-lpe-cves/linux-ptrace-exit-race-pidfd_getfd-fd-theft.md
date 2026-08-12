# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

A useful **Linux kernel privesc pattern** is to turn a **ptrace authorization bug** into **file descriptor theft** from a privileged process.

In the Qualys `__ptrace_may_access()` case study (CVE-2026-46333), the attacker races a **privileged process that is exiting or dropping credentials** and uses `pidfd_getfd()` to duplicate an FD into the attacker process.<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` duplicates a file descriptor from another process, but first checks ptrace-style permissions against the target.<sup>[[3]](#references)</sup> If that authorization is incorrectly granted during a **teardown window**, an unprivileged attacker can copy:

- FDs for **sensitive files** already opened by a privileged helper
- FDs for **authenticated IPC channels** already authorized as root

This transforms a kernel-side authorization bug into a very practical userspace primitive.<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

The attack does **not** need a bug in the privileged helper itself. The helper only needs to temporarily hold something valuable:

- `/etc/shadow`
- `/etc/ssh/*_key`
- a privileged D-Bus / systemd connection
- any other already-open secret or authorized channel

Once duplicated into the attacker process, the duplicate refers to the same open file description, so subsequent reads or IPC requests use the already-open FD rather than reopening the original pathname or starting a fresh authentication flow.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. Identify a **setuid / setgid / file-capability binary** or **root daemon** that opens sensitive files or keeps useful IPC connections.<sup>[[2]](#references)</sup>
2. Gain a relationship that satisfies the relevant ptrace policy checks for the target path (for example, being the **parent** of a spawned privileged child under permissive YAMA settings).<sup>[[2]](#references)[[4]](#references)</sup>
3. Race the process while it is **exiting**, **dropping credentials**, or otherwise entering a state where ptrace access should have become unavailable.<sup>[[2]](#references)</sup>
4. Use `pidfd_open()` + `pidfd_getfd()` to duplicate the target FD during the narrow authorization window.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Reuse the stolen FD from the unprivileged context.<sup>[[2]](#references)</sup>
   - `read()` secrets from a privileged file descriptor
   - send requests over a stolen authenticated IPC channel to get **root-side actions**

Minimal primitive shape.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```

## Practical targets to audit

Prioritize binaries and daemons that, even briefly, do one of these:<sup>[[1]](#references)[[2]](#references)</sup>

- open root-only files before finishing privilege transitions
- connect to the **system bus** and keep an already-authorized channel
- pass privileged FDs across helper boundaries
- perform security-sensitive work during `do_exit()`-adjacent teardown

Good hunting candidates:<sup>[[1]](#references)</sup>

- password / account management helpers
- SSH helpers
- PolicyKit / D-Bus mediated helpers
- root desktop daemons that expose D-Bus methods

## YAMA as an exploit gate

`kernel.yama.ptrace_scope` is a major practical gate for ptrace-family abuse:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: classical same-UID ptrace behavior
- `1`: typically allows parent -> child tracing, which can keep some public exploit paths reachable
- `2`: requires `CAP_SYS_PTRACE` for attach-style access and blocks unprivileged `pidfd_getfd()` abuse in this path
- `3`: disables ptrace attach entirely until reboot

For this technique, `ptrace_scope=2` is a strong **temporary mitigation** because it breaks the public `pidfd_getfd()` exploitation path with `-EPERM` for unprivileged users.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Detection / review ideas

When auditing privileged Linux software, look for these combinations:

- **privileged child process** + **attacker-controlled parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- temporary access to **valuable open files**
- temporary access to **authenticated D-Bus/systemd channels**.<sup>[[2]](#references)</sup>
- security decisions that reuse **ptrace-style authorization** outside classic `ptrace(2)`
- kernel APIs that can **duplicate, inherit, or re-export** existing privileged FDs

When auditing the kernel, treat any path that does **ptrace-equivalent authorization** during **task teardown** as high risk, especially if success yields direct access to `task->files` or other already-authorized process resources.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)

{{#include ../../../banners/hacktricks-training.md}}
