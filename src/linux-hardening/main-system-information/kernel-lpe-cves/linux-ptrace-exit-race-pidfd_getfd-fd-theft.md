# Linux ptrace exit-race `pidfd_getfd()` krađa FD-a

{{#include ../../../banners/hacktricks-training.md}}

Koristan **Linux kernel privesc obrazac** jeste pretvaranje **ptrace authorization bug-a** u **krađu file descriptor-a** iz privilegovanog procesa.

U Qualys studiji slučaja `__ptrace_may_access()` (CVE-2026-46333), napadač vrši race nad **privilegovanim procesom koji se gasi ili odbacuje credentials** i koristi `pidfd_getfd()` da duplicira FD u napadačev proces.<sup>[[1]](#references)[[2]](#references)</sup>

## Osnovna ideja

`pidfd_getfd()` duplicira file descriptor iz drugog procesa, ali prethodno proverava ptrace-style permissions nad targetom. Ako se ta authorization pogrešno odobri tokom **teardown window-a**, unprivileged attacker može da kopira:

- FD-ove za **sensitive files** koje je privileged helper već otvorio
- FD-ove za **authenticated IPC channels** koji su već autorizovani kao root

Ovo pretvara kernel-side authorization bug u veoma praktičan userspace primitive.<sup>[[1]](#references)</sup>

## Zašto je primitive opasan

Za napad nije potreban bug u samom privileged helper-u. Helper samo treba da privremeno drži nešto vredno:

- `/etc/shadow`
- `/etc/ssh/*_key`
- privilegovanu D-Bus / systemd konekciju
- bilo koji drugi već otvoren secret ili authorized channel

Kada se duplicira u attacker process, kernel sprovodi operacije nad **stolen FD-om**, a ne nad originalnom putanjom ili kroz novi authentication flow.<sup>[[1]](#references)</sup>

## Exploitation pattern

1. Identifikujte **setuid / setgid / file-capability binary** ili **root daemon** koji otvara sensitive files ili održava korisne IPC konekcije.
2. Uspostavite odnos koji zadovoljava relevantne ptrace policy checks za target path (na primer, budite **parent** spawn-ovanog privileged child-a uz permissive YAMA settings).
3. Izvršite race nad procesom dok se **gasi**, **odbacuje credentials** ili na drugi način ulazi u stanje u kojem je ptrace access trebalo da postane nedostupan.
4. Koristite `pidfd_open()` + `pidfd_getfd()` da duplicirate target FD tokom uskog authorization window-a.
5. Ponovo upotrebite stolen FD iz unprivileged context-a:
- `read()` secrets iz privileged file descriptor-a
- šaljite requests preko stolen authenticated IPC channel-a da biste dobili **root-side actions**<sup>[[1]](#references)</sup>

Minimalni oblik primitive-a:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktične mete za audit

Prioritetno proverite binarne fajlove i daemone koji, čak i nakratko, rade nešto od sledećeg:<sup>[[1]](#references)</sup>

- otvaraju fajlove dostupne samo root korisniku pre završetka tranzicije privilegija
- povezuju se na **system bus** i zadržavaju već autorizovani kanal
- prosleđuju privilegovane FD-ove preko helper procesa
- obavljaju bezbednosno osetljive operacije tokom teardown-a bliskog funkciji `do_exit()`

Dobri kandidati za proveru:<sup>[[1]](#references)</sup>

- helperi za upravljanje lozinkama / nalozima
- SSH helperi
- PolicyKit / D-Bus posredovani helperi
- root desktop daemoni koji izlažu D-Bus metode

## YAMA kao prepreka za exploit

`kernel.yama.ptrace_scope` predstavlja glavnu praktičnu prepreku za abuse ptrace porodice mehanizama:<sup>[[4]](#references)</sup>

- `0`: klasično ptrace ponašanje za isti UID
- `1`: obično dozvoljava praćenje parent -> child procesa, što može održati neke javno dostupne exploit putanje dostupnim
- `2`: zahteva `CAP_SYS_PTRACE` za attach pristup i blokira neprivilegovani `pidfd_getfd()` abuse u ovoj putanji
- `3`: u potpunosti onemogućava ptrace attach do reboot-a

Za ovu tehniku, `ptrace_scope=2` predstavlja snažnu **privremenu mitigaciju** jer prekida javno dostupnu `pidfd_getfd()` exploitation putanju sa greškom `-EPERM` za neprivilegovane korisnike.<sup>[[1]](#references)</sup>

## Ideje za detekciju / pregled

Prilikom audita privilegovanog Linux software-a, tražite sledeće kombinacije:

- **privilegovani child proces** + **parent kojim upravlja attacker**
- privremeni pristup **vrednim otvorenim fajlovima**
- privremeni pristup **autentifikovanim D-Bus/systemd kanalima**
- bezbednosne odluke koje ponovo koriste **ptrace-style autorizaciju** izvan klasičnog `ptrace(2)`
- kernel API-je koji mogu da **dupliraju, nasleđuju ili ponovo izvezu** postojeće privilegovane FD-ove

Prilikom audita kernela, svaku putanju koja obavlja **ptrace-ekvivalentnu autorizaciju** tokom **gašenja task-a** tretirajte kao visokorizičnu, posebno ako uspeh omogućava direktan pristup `task->files` ili drugim već autorizovanim resursima procesa.

## Reference

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
