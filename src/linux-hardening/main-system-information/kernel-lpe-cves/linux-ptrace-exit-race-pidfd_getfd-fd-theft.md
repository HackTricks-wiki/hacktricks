# Wizi wa FD kupitia Linux ptrace exit-race `pidfd_getfd()`

**Linux kernel privesc pattern** muhimu ni kubadilisha **ptrace authorization bug** kuwa **file descriptor theft** kutoka kwa process yenye privileges.

Katika case study ya Qualys ya `__ptrace_may_access()` (CVE-2026-46333), attacker ana-race **privileged process inayomaliza au inayopunguza credentials** na kutumia `pidfd_getfd()` ku-duplicate FD ndani ya attacker process.<sup>[[1]](#references)[[2]](#references)</sup>

## Wazo kuu

`pidfd_getfd()` ina-duplicate file descriptor kutoka process nyingine, lakini kwanza hukagua ptrace-style permissions dhidi ya target.<sup>[[3]](#references)</sup> Ikiwa authorization hiyo itatolewa kimakosa wakati wa **teardown window**, attacker asiye na privileges anaweza kunakili:

- FDs za **sensitive files** ambazo tayari zimefunguliwa na privileged helper
- FDs za **authenticated IPC channels** ambazo tayari zimeidhinishwa kama root

Hii hubadilisha kernel-side authorization bug kuwa userspace primitive inayoweza kutumika kwa urahisi.<sup>[[1]](#references)</sup>

## Kwa nini primitive hii ni hatari

Attack haihitaji bug ndani ya privileged helper yenyewe. Helper inahitaji tu kushikilia kwa muda kitu chenye thamani:

- `/etc/shadow`
- `/etc/ssh/*_key`
- privileged D-Bus / systemd connection
- secret nyingine yoyote iliyofunguliwa tayari au authorized channel

Baada ya ku-duplicate ndani ya attacker process, duplicate hurejelea open file description ileile, kwa hiyo reads au IPC requests zinazofuata hutumia FD iliyofunguliwa tayari badala ya kufungua upya pathname ya awali au kuanzisha fresh authentication flow.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. Tambua **setuid / setgid / file-capability binary** au **root daemon** inayofungua sensitive files au kuhifadhi useful IPC connections.<sup>[[2]](#references)</sup>
2. Pata relationship inayotimiza relevant ptrace policy checks kwa target path (kwa mfano, kuwa **parent** wa privileged child aliye-spawn chini ya permissive YAMA settings).<sup>[[2]](#references)[[4]](#references)</sup>
3. Race process wakati **inamaliza**, **inapunguza credentials**, au inaingia katika hali nyingine ambayo ptrace access ilipaswa kuwa haipatikani tena.<sup>[[2]](#references)</sup>
4. Tumia `pidfd_open()` + `pidfd_getfd()` ku-duplicate target FD wakati wa narrow authorization window.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Tumia tena stolen FD kutoka unprivileged context.<sup>[[2]](#references)</sup>
- `read()` secrets kutoka privileged file descriptor
- tuma requests kupitia stolen authenticated IPC channel ili kupata **root-side actions**

Muundo wa msingi wa primitive.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Malengo ya ukaguzi wa vitendo

Pangilia kwa kipaumbele binaries na daemons ambazo, hata kwa muda mfupi, hufanya mojawapo ya mambo haya:<sup>[[1]](#references)[[2]](#references)</sup>

- kufungua files za root-only kabla ya kukamilisha mabadiliko ya privilege
- kuunganisha kwenye **system bus** na kuhifadhi channel ambayo tayari imeidhinishwa
- kupitisha privileged FDs kupitia mipaka ya helpers
- kufanya kazi nyeti za usalama wakati wa teardown iliyo karibu na `do_exit()`

Wagombea wazuri wa hunting:<sup>[[1]](#references)</sup>

- helpers za password / account management
- SSH helpers
- helpers zinazosimamiwa na PolicyKit / D-Bus
- root desktop daemons zinazofichua methods za D-Bus

## YAMA kama kizuizi cha exploit

`kernel.yama.ptrace_scope` ni kizuizi kikuu cha vitendo dhidi ya matumizi mabaya ya ptrace-family:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: tabia ya classical same-UID ptrace
- `1`: kwa kawaida huruhusu tracing ya parent -> child, ambayo inaweza kuweka baadhi ya public exploit paths zikiwa bado zinafikiwa
- `2`: huhitaji `CAP_SYS_PTRACE` kwa access ya aina ya attach na huzuia matumizi mabaya ya `pidfd_getfd()` na users wasio na privilege katika path hii
- `3`: huzima ptrace attach kabisa hadi reboot

Kwa technique hii, `ptrace_scope=2` ni **temporary mitigation** thabiti kwa sababu huvunja public `pidfd_getfd()` exploitation path kwa `-EPERM` kwa users wasio na privilege.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Mawazo ya detection / review

Unapokagua software yenye privilege kwenye Linux, tafuta mchanganyiko huu:

- **privileged child process** + **attacker-controlled parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- access ya muda kwa **valuable open files**
- access ya muda kwa **authenticated D-Bus/systemd channels**.<sup>[[2]](#references)</sup>
- maamuzi ya usalama yanayotumia tena **ptrace-style authorization** nje ya `ptrace(2)` ya kawaida
- kernel APIs zinazoweza **duplicate, inherit, au re-export** privileged FDs zilizopo

Unapokagua kernel, chukulia path yoyote inayofanya **ptrace-equivalent authorization** wakati wa **task teardown** kuwa high risk, hasa ikiwa mafanikio yanatoa access ya moja kwa moja kwa `task->files` au resources nyingine za process ambazo tayari zimeidhinishwa.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Ushauri wa Qualys katika TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Ukurasa wa manual wa pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Nyaraka za Linux kernel Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Ukurasa wa manual wa pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
