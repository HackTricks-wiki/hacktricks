# Linux ptrace exit-race `pidfd_getfd()` FD-diefstal

{{#include ../../../banners/hacktricks-training.md}}

’n Nuttige **Linux kernel privesc-patroon** is om ’n **ptrace-autorisasiefout** in **file descriptor-diefstal** vanaf ’n bevoorregte proses te omskep.

In die Qualys `__ptrace_may_access()`-gevallestudie (CVE-2026-46333) jaag die aanvaller ’n **bevoorregte proses wat besig is om te beëindig of credentials prys te gee** en gebruik `pidfd_getfd()` om ’n FD na die aanvallerproses te dupliseer.<sup>[[1]](#references)[[2]](#references)</sup>

## Kernidee

`pidfd_getfd()` dupliseer ’n file descriptor vanaf ’n ander proses, maar kontroleer eers ptrace-styltoestemmings teenoor die teiken.<sup>[[3]](#references)</sup> As daardie autorisasie verkeerdelik tydens ’n **teardown-venster** toegestaan word, kan ’n onbevoorregte aanvaller die volgende kopieer:

- FDs vir **sensitiewe lêers** wat reeds deur ’n bevoorregte helper oopgemaak is
- FDs vir **geauthentiseerde IPC-kanale** wat reeds as root gemagtig is

Dit omskep ’n kernel-kant-autorisasiefout in ’n baie praktiese userspace-primitief.<sup>[[1]](#references)</sup>

## Waarom die primitief gevaarlik is

Die aanval benodig **nie ’n fout in die bevoorregte helper self nie**. Die helper hoef slegs tydelik iets waardevols te hou:

- `/etc/shadow`
- `/etc/ssh/*_key`
- ’n bevoorregte D-Bus / systemd-verbinding
- enige ander reeds-oop geheim of gemagtigde kanaal

Sodra dit na die aanvallerproses gedupliseer is, verwys die duplikaat na dieselfde oop file description. Daaropvolgende leesbewerkings of IPC-versoeke gebruik dus die reeds-oop FD, eerder as om die oorspronklike pathname weer oop te maak of ’n nuwe authentication flow te begin.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation-patroon

1. Identifiseer ’n **setuid / setgid / file-capability binary** of **root daemon** wat sensitiewe lêers oopmaak of nuttige IPC-verbindings behou.<sup>[[2]](#references)</sup>
2. Verkry ’n verhouding wat aan die relevante ptrace-beleidskontroles vir die teikenpad voldoen (byvoorbeeld om die **ouer** van ’n voortgebringde bevoorregte child te wees onder permissiewe YAMA-instellings).<sup>[[2]](#references)[[4]](#references)</sup>
3. Jaag die proses terwyl dit besig is om **te beëindig**, **credentials prys te gee**, of andersins ’n toestand binnegaan waarin ptrace-toegang nie meer beskikbaar behoort te wees nie.<sup>[[2]](#references)</sup>
4. Gebruik `pidfd_open()` + `pidfd_getfd()` om die teiken-FD gedurende die noue autorisasievenster te dupliseer.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Hergebruik die gesteelde FD vanuit die onbevoorregte konteks.<sup>[[2]](#references)</sup>
- `read()` geheime vanaf ’n bevoorregte file descriptor
- stuur versoeke oor ’n gesteelde geauthentiseerde IPC-kanaal om **root-side aksies** te verkry

Minimale primitiefvorm.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktiese teikens om te oudit

Prioritiseer binaries en daemons wat, selfs kortstondig, enige van die volgende doen:<sup>[[1]](#references)[[2]](#references)</sup>

- root-only-lêers oopmaak voordat privilege-oorgange voltooi is
- aan die **system bus** koppel en ’n reeds-gemagtigde kanaal behou
- bevoorregte FDs oor helper-grense stuur
- sekuriteitsensitiewe werk tydens `do_exit()`-aangrensende afbreekwerk uitvoer

Goeie kandidate om te ondersoek:<sup>[[1]](#references)</sup>

- wagwoord- / rekeningbestuurhelpers
- SSH-helpers
- PolicyKit- / D-Bus-gemedieerde helpers
- root-desktop-daemons wat D-Bus-metodes blootstel

## YAMA as exploit-poort

`kernel.yama.ptrace_scope` is ’n belangrike praktiese poort vir ptrace-familie-misbruik:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: klassieke same-UID ptrace-gedrag
- `1`: laat gewoonlik tracing van ouer -> kind toe, wat sommige publieke exploit-paaie bereikbaar kan hou
- `2`: vereis `CAP_SYS_PTRACE` vir attach-styl-toegang en blokkeer onbevoorregte `pidfd_getfd()`-misbruik in hierdie pad
- `3`: deaktiveer ptrace attach heeltemal totdat daar herlaai word

Vir hierdie tegniek is `ptrace_scope=2` ’n sterk **tydelike mitigering** omdat dit die publieke `pidfd_getfd()`-exploit-pad met `-EPERM` vir onbevoorregte gebruikers breek.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Opsporings- / hersieningsidees

Wanneer bevoorregte Linux-sagteware geoudit word, let op hierdie kombinasies:

- **bevoorregte child-proses** + **aanvaller-beheerde ouer**.<sup>[[2]](#references)[[4]](#references)</sup>
- tydelike toegang tot **waardevolle oop lêers**
- tydelike toegang tot **geauthentiseerde D-Bus/systemd-kanale**.<sup>[[2]](#references)</sup>
- sekuriteitsbesluite wat **ptrace-styl-magtiging** buite klassieke `ptrace(2)` hergebruik
- kernel-API’s wat bestaande bevoorregte FDs kan **dupliseer, oorerf of heruitvoer**

Wanneer die kernel geoudit word, behandel enige pad wat **ptrace-ekwivalente magtiging** tydens **taakafbreekwerk** uitvoer as hoërisiko, veral indien sukses direkte toegang tot `task->files` of ander reeds-gemagtigde prosesbronne verleen.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Plaaslike root-privilege-eskalasie en credential-onthulling in die Linux-kernel se ptrace-pad (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys-advies TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2)-handleiding](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux-kernel se YAMA-dokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2)-handleiding](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
