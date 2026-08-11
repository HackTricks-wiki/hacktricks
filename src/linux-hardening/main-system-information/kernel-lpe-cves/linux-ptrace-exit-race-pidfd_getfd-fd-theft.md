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
## Malengo ya vitendo ya kukagua

Tanguliza binaries na daemons ambazo, hata kwa muda mfupi, hufanya mojawapo ya mambo haya:<sup>[[1]](#references)[[2]](#references)</sup>

- kufungua files za root-only kabla ya kukamilisha mabadiliko ya privileges
- kuunganisha kwenye **system bus** na kuhifadhi channel ambayo tayari imeidhinishwa
- kupitisha privileged FDs kupitia mipaka ya helpers
- kufanya kazi nyeti za usalama wakati wa teardown iliyo karibu na `do_exit()`

Wagombea wazuri wa hunting:<sup>[[1]](#references)</sup>

- helpers za usimamizi wa passwords / accounts
- SSH helpers
- helpers zinazosimamiwa kupitia PolicyKit / D-Bus
- root desktop daemons zinazotoa methods za D-Bus

## YAMA kama kizuizi cha exploit

`kernel.yama.ptrace_scope` ni kizuizi kikuu cha kiutendaji dhidi ya matumizi mabaya ya ptrace-family:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: tabia ya classical same-UID ptrace
- `1`: kwa kawaida huruhusu tracing ya parent -> child, ambayo inaweza kuweka baadhi ya public exploit paths zikiwa reachable
- `2`: huhitaji `CAP_SYS_PTRACE` kwa access ya aina ya attach na huzuia matumizi mabaya ya `pidfd_getfd()` na users wasio na privileges katika path hii
- `3`: huzima ptrace attach kabisa hadi reboot

Kwa technique hii, `ptrace_scope=2` ni **temporary mitigation** imara kwa sababu huvunja public `pidfd_getfd()` exploitation path kwa `-EPERM` kwa users wasio na privileges.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Mawazo ya detection / review

Unapokagua Linux software yenye privileges, tafuta michanganyiko hii:

- **privileged child process** + **attacker-controlled parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- access ya muda kwa **valuable open files**
- access ya muda kwa **authenticated D-Bus/systemd channels**.<sup>[[2]](#references)</sup>
- maamuzi ya usalama yanayotumia tena **ptrace-style authorization** nje ya `ptrace(2)` ya kawaida
- kernel APIs zinazoweza **ku-duplicate, ku-inherit, au ku-re-export** privileged FDs zilizopo

Unapokagua kernel, chukulia path yoyote inayofanya **ptrace-equivalent authorization** wakati wa **task teardown** kuwa high risk, hasa ikiwa mafanikio yanatoa access ya moja kwa moja kwa `task->files` au resources nyingine za process ambazo tayari zimeidhinishwa.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Kuongezeka kwa Privilege ya Local Root na Kufichuliwa kwa Credentials katika Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [TXT ya advisory ya Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Ukurasa wa mwongozo wa pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Nyaraka za Linux kernel Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Ukurasa wa mwongozo wa pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
