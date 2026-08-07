# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

**Linux kernel privesc pattern** yenye manufaa ni kubadilisha **ptrace authorization bug** kuwa **file descriptor theft** kutoka kwenye privileged process.

Katika case study ya Qualys ya `__ptrace_may_access()` (CVE-2026-46333), attacker hushindana na **privileged process inayomaliza kazi au kuacha credentials** na kutumia `pidfd_getfd()` ku-duplicate FD ndani ya attacker process.<sup>[[1]](#references)[[2]](#references)</sup>

## Wazo kuu

`pidfd_getfd()` hu-duplicate file descriptor kutoka kwenye process nyingine, lakini kwanza hukagua ptrace-style permissions dhidi ya target. Ikiwa authorization hiyo imetolewa kimakosa wakati wa **teardown window**, attacker asiye na privileges anaweza kunakili:

- FDs za **sensitive files** ambazo tayari zimefunguliwa na privileged helper
- FDs za **authenticated IPC channels** ambazo tayari zimeidhinishwa kama root

Hii hubadilisha kernel-side authorization bug kuwa primitive ya vitendo sana ya userspace.<sup>[[1]](#references)</sup>

## Kwa nini primitive hii ni hatari

Attack haihitaji bug ndani ya privileged helper yenyewe. Helper inahitaji tu kushikilia kwa muda kitu chenye thamani:

- `/etc/shadow`
- `/etc/ssh/*_key`
- privileged D-Bus / systemd connection
- secret nyingine yoyote iliyofunguliwa tayari au authorized channel

Baada ya ku-duplicate ndani ya attacker process, kernel hutekeleza operations kwenye **stolen FD**, si kwenye pathname ya awali au authentication flow mpya.<sup>[[1]](#references)</sup>

## Muundo wa exploitation

1. Tambua **setuid / setgid / file-capability binary** au **root daemon** inayofungua sensitive files au kuhifadhi IPC connections zenye manufaa.
2. Pata relationship inayokidhi ptrace policy checks husika kwa target path (kwa mfano, kuwa **parent** wa privileged child aliyeanzishwa chini ya permissive YAMA settings).
3. Shindana na process wakati **inamaliza kazi**, **inaacha credentials**, au inaingia katika state ambayo ptrace access ilipaswa kuwa haipatikani tena.
4. Tumia `pidfd_open()` + `pidfd_getfd()` ku-duplicate target FD wakati wa narrow authorization window.
5. Tumia tena stolen FD kutoka kwenye unprivileged context:
- `read()` secrets kutoka kwenye privileged file descriptor
- tuma requests kupitia stolen authenticated IPC channel ili kupata **root-side actions**<sup>[[1]](#references)</sup>

Muundo wa chini kabisa wa primitive:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Malengo ya vitendo ya kufanya audit

Panga kwa kipaumbele binaries na daemons ambazo, hata kwa muda mfupi, hufanya mojawapo ya haya:<sup>[[1]](#references)</sup>

- kufungua files za root-only kabla ya kumaliza privilege transitions
- kuunganisha kwenye **system bus** na kuweka channel iliyoidhinishwa tayari
- kupitisha FDs zenye privileges kupitia mipaka ya helpers
- kufanya kazi nyeti za security wakati wa teardown iliyo karibu na `do_exit()`

Wagombea wazuri wa hunting:<sup>[[1]](#references)</sup>

- helpers za password / account management
- SSH helpers
- helpers zinazopatanishwa na PolicyKit / D-Bus
- root desktop daemons zinazowasilisha D-Bus methods

## YAMA kama exploit gate

`kernel.yama.ptrace_scope` ni gate muhimu ya vitendo dhidi ya ptrace-family abuse:<sup>[[4]](#references)</sup>

- `0`: tabia ya classical same-UID ptrace
- `1`: kwa kawaida huruhusu parent -> child tracing, ambayo inaweza kuweka baadhi ya public exploit paths zikiwa reachable
- `2`: huhitaji `CAP_SYS_PTRACE` kwa access ya aina ya attach na huzuia unprivileged `pidfd_getfd()` abuse katika path hii
- `3`: huzima ptrace attach kabisa hadi reboot

Kwa technique hii, `ptrace_scope=2` ni **temporary mitigation** yenye nguvu kwa sababu huvunja public `pidfd_getfd()` exploitation path kwa `-EPERM` kwa users wasio na privileges.<sup>[[1]](#references)</sup>

## Mawazo ya Detection / review

Wakati wa kufanya audit ya privileged Linux software, tafuta mchanganyiko huu:

- **privileged child process** + **attacker-controlled parent**
- access ya muda kwa **valuable open files**
- access ya muda kwa **authenticated D-Bus/systemd channels**
- security decisions zinazotumia tena **ptrace-style authorization** nje ya classic `ptrace(2)`
- kernel APIs zinazoweza **duplicate, inherit, au re-export** privileged FDs zilizopo

Wakati wa kufanya audit ya kernel, chukulia path yoyote inayofanya **ptrace-equivalent authorization** wakati wa **task teardown** kuwa high risk, hasa ikiwa success inatoa access ya moja kwa moja kwa `task->files` au process resources nyingine ambazo tayari zimeidhinishwa.

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
