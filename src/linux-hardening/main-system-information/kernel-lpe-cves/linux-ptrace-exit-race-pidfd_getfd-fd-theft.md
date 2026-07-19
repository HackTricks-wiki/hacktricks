# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

'n Nuttige **Linux kernel privesc-patroon** is om 'n **ptrace authorization bug** in **file descriptor theft** vanaf 'n gepriviligeerde proses te omskep.

In die Qualys `__ptrace_may_access()`-gevallestudie (CVE-2026-46333) jaag die aanvaller 'n **gepriviligeerde proses wat besig is om uit te tree of credentials af te staan** en gebruik `pidfd_getfd()` om 'n FD na die aanvaller se proses te dupliseer.

## Kernidee

`pidfd_getfd()` dupliseer 'n file descriptor vanaf 'n ander proses, maar kontroleer eers ptrace-styl-permissies teenoor die teiken. As daardie authorization verkeerdelik tydens 'n **teardown-venster** toegestaan word, kan 'n onbevoorregte aanvaller die volgende kopieer:

- FDs vir **sensitiewe lêers** wat reeds deur 'n gepriviligeerde helper oopgemaak is
- FDs vir **geauthentiseerde IPC-kanale** wat reeds as root gemagtig is

Dit omskep 'n kernel-kant authorization bug in 'n baie praktiese userspace primitive.

## Waarom die primitive gevaarlik is

Die aanval **benodig nie 'n bug in die gepriviligeerde helper self nie**. Die helper hoef slegs tydelik iets waardevols te hou:

- `/etc/shadow`
- `/etc/ssh/*_key`
- 'n gepriviligeerde D-Bus / systemd-verbinding
- enige ander reeds-oopgemaakte geheim of gemagtigde kanaal

Sodra dit na die aanvaller se proses gedupliseer is, pas die kernel bewerkings op die **gesteelde FD** toe, nie op die oorspronklike pathname of op 'n nuwe authentication flow nie.

## Exploitation-patroon

1. Identifiseer 'n **setuid / setgid / file-capability binary** of **root daemon** wat sensitiewe lêers oopmaak of nuttige IPC-verbindings behou.
2. Verkry 'n verhouding wat aan die relevante ptrace-policy checks vir die teikenpad voldoen (byvoorbeeld om die **ouer** van 'n spawned gepriviligeerde child te wees onder permissiewe YAMA-instellings).
3. Jaag die proses terwyl dit **uittree**, **credentials laat vaar**, of andersins 'n toestand binnegaan waar ptrace-toegang nie meer beskikbaar behoort te wees nie.
4. Gebruik `pidfd_open()` + `pidfd_getfd()` om die teiken-FD tydens die nou authorization-venster te dupliseer.
5. Hergebruik die gesteelde FD vanuit die onbevoorregte konteks:
- `read()` geheime vanaf 'n gepriviligeerde file descriptor
- stuur requests oor 'n gesteelde geauthentiseerde IPC-kanaal om **root-kant aksies** te verkry

Minimum primitive-vorm:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktiese teikens om te oudit

Prioritiseer binaries en daemons wat, selfs net kortliks, een van hierdie dinge doen:

- root-only-lêers oopmaak voordat bevoorregtingsoorgange voltooi is
- aan die **system bus** koppel en 'n reeds gemagtigde kanaal behou
- bevoorregte FDs oor helper-grense heen deurgee
- sekuriteitsensitiewe werk tydens `do_exit()`-aangrensende teardown uitvoer

Goeie kandidate om te ondersoek:

- wagwoord-/rekeningbestuurhelpers
- SSH-helpers
- PolicyKit / D-Bus-gemedieerde helpers
- root-werkskermdaemons wat D-Bus-metodes blootstel

## YAMA as 'n exploit-poort

`kernel.yama.ptrace_scope` is 'n belangrike praktiese poort vir ptrace-familie-misbruik:

- `0`: klassieke same-UID ptrace-gedrag
- `1`: laat gewoonlik tracing van ouer -> kind toe, wat sommige publieke exploit-paaie bereikbaar kan hou
- `2`: vereis `CAP_SYS_PTRACE` vir attach-styl-toegang en blokkeer onbevoorregte `pidfd_getfd()`-misbruik in hierdie pad
- `3`: deaktiveer ptrace attach heeltemal totdat daar herlaai word

Vir hierdie tegniek is `ptrace_scope=2` 'n sterk **tydelike versagting**, omdat dit die openbare `pidfd_getfd()`-exploit-pad met `-EPERM` vir onbevoorregte gebruikers verbreek.

## Opsporings-/hersieningsidees

Wanneer bevoorregte Linux-sagteware geoudit word, soek hierdie kombinasies:

- **bevoorregte child-proses** + **aanvallerbeheerde parent**
- tydelike toegang tot **waardevolle oop lêers**
- tydelike toegang tot **geauthentiseerde D-Bus/systemd-kanale**
- sekuriteitsbesluite wat **ptrace-styl-magtiging** buite klassieke `ptrace(2)` hergebruik
- kernel-API's wat bestaande bevoorregte FDs kan **dupliseer, erf of heruitvoer**

Wanneer die kernel geoudit word, beskou enige pad wat **ptrace-ekwivalente magtiging** tydens **task-teardown** uitvoer as 'n hoë risiko, veral indien sukses direkte toegang tot `task->files` of ander reeds gemagtigde prosesbronne lewer.

## Verwysings

- [Qualys-blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys-advies TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [`pidfd_getfd(2)`-handleidingbladsy](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama-dokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
