# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

**Linux kernel privesc pattern** yenye manufaa ni kubadilisha **ptrace authorization bug** kuwa **file descriptor theft** kutoka kwa process yenye privileges.

Katika case study ya Qualys ya `__ptrace_may_access()` (CVE-2026-46333), attacker hushindana na **privileged process inayomaliza au kuacha credentials** na hutumia `pidfd_getfd()` kunakili FD kwenda kwenye attacker process.

## Wazo kuu

`pidfd_getfd()` hunakili file descriptor kutoka process nyingine, lakini kwanza hukagua permissions za mtindo wa ptrace dhidi ya target. Ikiwa authorization hiyo itatolewa kimakosa wakati wa **teardown window**, attacker asiye na privileges anaweza kunakili:

- FDs za **sensitive files** ambazo tayari zimefunguliwa na privileged helper
- FDs za **authenticated IPC channels** ambazo tayari zimeidhinishwa kama root

Hii hubadilisha kernel-side authorization bug kuwa userspace primitive yenye matumizi ya moja kwa moja.

## Kwa nini primitive hii ni hatari

Attack haihitaji bug ndani ya privileged helper yenyewe. Helper inahitaji tu kushikilia kwa muda kitu chenye thamani:

- `/etc/shadow`
- `/etc/ssh/*_key`
- connection ya privileged D-Bus / systemd
- secret nyingine yoyote iliyofunguliwa tayari au channel iliyoidhinishwa

Baada ya kunakiliwa kwenye attacker process, kernel hutekeleza operations kwenye **stolen FD**, si kwenye pathname ya awali au authentication flow mpya.

## Muundo wa exploitation

1. Tambua **setuid / setgid / file-capability binary** au **root daemon** inayofungua sensitive files au kuhifadhi IPC connections zenye manufaa.
2. Pata relationship inayotimiza ptrace policy checks husika kwa target path (kwa mfano, kuwa **parent** wa privileged child aliyezalishwa chini ya permissive YAMA settings).
3. Shindana na process wakati **inamaliza**, **inaacha credentials**, au inaingia katika hali nyingine ambayo ptrace access ilipaswa kutopatikana tena.
4. Tumia `pidfd_open()` + `pidfd_getfd()` kunakili target FD wakati wa narrow authorization window.
5. Tumia tena stolen FD kutoka kwenye unprivileged context:
- `read()` secrets kutoka kwenye privileged file descriptor
- tuma requests kupitia stolen authenticated IPC channel ili kupata **root-side actions**

Minimal primitive shape:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Malengo ya vitendo ya kukagua

Tanguliza binaries na daemons ambazo, hata kwa muda mfupi, hufanya mojawapo ya mambo haya:

- kufungua files za root-only kabla ya kukamilisha mabadiliko ya privileges
- kuunganishwa kwenye **system bus** na kuhifadhi channel ambayo tayari imeidhinishwa
- kupitisha FDs zenye privileges kupitia mipaka ya helpers
- kufanya kazi nyeti za usalama wakati wa teardown iliyo karibu na `do_exit()`

Waombaji wazuri wa hunting:

- helpers za password / account management
- SSH helpers
- helpers zinazosimamiwa kupitia PolicyKit / D-Bus
- root desktop daemons zinazotoa D-Bus methods

## YAMA kama exploit gate

`kernel.yama.ptrace_scope` ni gate muhimu ya kivitendo dhidi ya matumizi mabaya ya ptrace-family:

- `0`: tabia ya classical ya ptrace kwa same-UID
- `1`: kwa kawaida huruhusu tracing kutoka parent -> child, ambayo inaweza kuweka baadhi ya public exploit paths zikiwa zinafikiwa
- `2`: inahitaji `CAP_SYS_PTRACE` kwa access ya aina ya attach na huzuia matumizi mabaya ya `pidfd_getfd()` na users wasio na privileges katika path hii
- `3`: huzima ptrace attach kabisa hadi reboot

Kwa technique hii, `ptrace_scope=2` ni **temporary mitigation** imara kwa sababu huvunja public `pidfd_getfd()` exploitation path kwa `-EPERM` kwa users wasio na privileges.

## Mawazo ya detection / review

Wakati wa kukagua Linux software yenye privileges, tafuta mchanganyiko huu:

- **privileged child process** + **attacker-controlled parent**
- access ya muda mfupi kwa **valuable open files**
- access ya muda mfupi kwa **authenticated D-Bus/systemd channels**
- security decisions zinazotumia tena **ptrace-style authorization** nje ya classic `ptrace(2)`
- kernel APIs zinazoweza **duplicate, inherit, au re-export** FDs zilizopo zenye privileges

Wakati wa kukagua kernel, chukulia path yoyote inayofanya **ptrace-equivalent authorization** wakati wa **task teardown** kuwa hatari kubwa, hasa ikiwa mafanikio yanatoa access ya moja kwa moja kwa `task->files` au resources nyingine za process ambazo tayari zimeidhinishwa.

## Marejeo

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
