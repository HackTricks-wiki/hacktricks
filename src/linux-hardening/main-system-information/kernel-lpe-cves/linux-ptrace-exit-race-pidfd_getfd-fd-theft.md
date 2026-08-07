# Linux ptrace exit-race `pidfd_getfd()` FD-diefstal

{{#include ../../../banners/hacktricks-training.md}}

'n Nuttige **Linux kernel privesc-patroon** is om 'n **ptrace authorization bug** in **file descriptor theft** vanaf 'n bevoorregte proses te omskep.

In die Qualys `__ptrace_may_access()`-gevallestudie (CVE-2026-46333) jaag die aanvaller 'n **bevoorregte proses wat besig is om te termineer of credentials te laat vaar** en gebruik `pidfd_getfd()` om 'n FD na die aanvaller se proses te dupliseer.<sup>[[1]](#references)[[2]](#references)</sup>

## Kernidee

`pidfd_getfd()` dupliseer 'n file descriptor vanaf 'n ander proses, maar kontroleer eers ptrace-styl toestemmings teenoor die teiken. As daardie authorization verkeerdelik gedurende 'n **teardown window** toegestaan word, kan 'n unprivileged aanvaller die volgende kopieer:

- FDs vir **sensitive files** wat reeds deur 'n bevoorregte helper oopgemaak is
- FDs vir **authenticated IPC channels** wat reeds as root geauthorizeer is

Dit omskep 'n kernel-side authorization bug in 'n baie praktiese userspace primitive.<sup>[[1]](#references)</sup>

## Waarom die primitive gevaarlik is

Die aanval benodig **nie** 'n bug in die bevoorregte helper self nie. Die helper hoef slegs tydelik iets waardevols te hou:

- `/etc/shadow`
- `/etc/ssh/*_key`
- 'n bevoorregte D-Bus / systemd-verbinding
- enige ander reeds-oopgemaakte secret of authorized channel

Sodra dit in die aanvaller se proses gedupliseer is, pas die kernel operasies op die **stolen FD** toe, nie op die oorspronklike pathname of op 'n nuwe authentication flow nie.<sup>[[1]](#references)</sup>

## Exploitation-patroon

1. Identifiseer 'n **setuid / setgid / file-capability binary** of **root daemon** wat sensitive files oopmaak of nuttige IPC-connections behou.
2. Verkry 'n verhouding wat aan die relevante ptrace policy checks vir die teikenpad voldoen (byvoorbeeld om die **parent** van 'n spawned privileged child onder permissive YAMA-settings te wees).
3. Jaag die proses terwyl dit **exiting** is, **credentials laat vaar**, of andersins 'n toestand binnegaan waar ptrace access nie meer beskikbaar behoort te wees nie.
4. Gebruik `pidfd_open()` + `pidfd_getfd()` om die target FD gedurende die nou authorization window te dupliseer.
5. Hergebruik die stolen FD vanuit die unprivileged context:
- `read()` secrets vanaf 'n bevoorregte file descriptor
- stuur requests oor 'n stolen authenticated IPC channel om **root-side actions** te verkry<sup>[[1]](#references)</sup>

Minimal primitive-vorm:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktiese teikens om te oudit

Prioritiseer binaries en daemons wat, selfs kortliks, een van die volgende doen:<sup>[[1]](#references)</sup>

- root-only-lêers oopmaak voordat privilege transitions voltooi is
- aan die **system bus** koppel en ’n reeds-geauthoriseerde kanaal behou
- gepriviligeerde FDs oor helper boundaries stuur
- security-sensitive werk tydens `do_exit()`-aangrensende teardown uitvoer

Goeie kandidate om te ondersoek:<sup>[[1]](#references)</sup>

- password- / account management helpers
- SSH helpers
- PolicyKit- / D-Bus-gemedieerde helpers
- root desktop daemons wat D-Bus-metodes blootstel

## YAMA as ’n exploit-gate

`kernel.yama.ptrace_scope` is ’n belangrike praktiese gate vir ptrace-family abuse:<sup>[[4]](#references)</sup>

- `0`: klassieke same-UID ptrace-gedrag
- `1`: laat tipies parent -> child tracing toe, wat sommige publieke exploit-paaie bereikbaar kan hou
- `2`: vereis `CAP_SYS_PTRACE` vir attach-style access en blokkeer onbevoegde `pidfd_getfd()` abuse in hierdie pad
- `3`: deaktiveer ptrace attach heeltemal totdat daar herlaai word

Vir hierdie tegniek is `ptrace_scope=2` ’n sterk **tydelike mitigation**, omdat dit die publieke `pidfd_getfd()` exploitation path met `-EPERM` vir onbevoegde gebruikers breek.<sup>[[1]](#references)</sup>

## Detection / review-idees

Wanneer gepriviligeerde Linux-sagteware geoudit word, let op hierdie kombinasies:

- **gepriviligeerde child process** + **attacker-controlled parent**
- tydelike toegang tot **waardevolle oop lêers**
- tydelike toegang tot **geauthentiseerde D-Bus/systemd-kanale**
- security decisions wat **ptrace-style authorization** buite klassieke `ptrace(2)` hergebruik
- kernel-API’s wat bestaande gepriviligeerde FDs kan **dupliseer, erf of heruitvoer**

Wanneer die kernel geoudit word, beskou enige pad wat **ptrace-equivalent authorization** tydens **task teardown** uitvoer as hoë risiko, veral indien sukses direkte toegang tot `task->files` of ander reeds-geauthoriseerde process resources bied.

## Verwysings

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
