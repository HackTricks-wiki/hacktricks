# Linux ptrace exit-race `pidfd_getfd()` krađa FD-a

{{#include ../../../banners/hacktricks-training.md}}

Korisni **Linux kernel privesc obrazac** jeste pretvaranje **ptrace autorizacione greške** u **krađu deskriptora datoteka** iz privilegovanog procesa.

U Qualys `__ptrace_may_access()` case study-ju (CVE-2026-46333), napadač se utrkuje sa **privilegovanim procesom koji se gasi ili odbacuje credentials** i koristi `pidfd_getfd()` da duplicira FD u napadačev proces.

## Osnovna ideja

`pidfd_getfd()` duplicira file descriptor iz drugog procesa, ali prethodno proverava ptrace-style dozvole nad targetom. Ako je ta autorizacija pogrešno odobrena tokom **teardown prozora**, neprivilegovani napadač može da kopira:

- FD-ove za **osetljive datoteke** koje je privilegovani helper već otvorio
- FD-ove za **autentifikovane IPC kanale** koji su već autorizovani kao root

Ovim se kernel-side autorizaciona greška pretvara u veoma praktičan userspace primitive.

## Zašto je primitive opasan

Za napad nije potrebna greška u samom privilegovanom helperu. Helper samo treba privremeno da drži nešto vredno:

- `/etc/shadow`
- `/etc/ssh/*_key`
- privilegovanu D-Bus / systemd konekciju
- bilo koju drugu već otvorenu tajnu ili autorizovani kanal

Kada se duplicira u napadačev proces, kernel primenjuje operacije nad **ukradenim FD-om**, a ne nad originalnom putanjom ili kroz novi authentication flow.

## Obrazac eksploatacije

1. Identifikujte **setuid / setgid / file-capability binary** ili **root daemon** koji otvara osetljive datoteke ili održava korisne IPC konekcije.
2. Uspostavite relationship koji zadovoljava relevantne ptrace policy provere za target path (na primer, budite **parent** spawned privileged child procesa uz permissive YAMA settings).
3. Utrkujte se sa procesom dok se **gasi**, **odbacuje credentials** ili na drugi način ulazi u stanje u kojem je ptrace pristup trebalo da postane nedostupan.
4. Koristite `pidfd_open()` + `pidfd_getfd()` da duplicirate target FD tokom uskog authorization window-a.
5. Ponovo koristite ukradeni FD iz unprivileged konteksta:
- `read()` tajne iz privilegovanog file descriptor-a
- šaljite zahteve preko ukradenog autentifikovanog IPC kanala da biste dobili **root-side actions**

Minimalni oblik primitiva:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktične mete za audit

Prioritet dajte binarnim datotekama i daemonima koji, čak i nakratko, rade nešto od sledećeg:

- otvaraju datoteke dostupne samo root korisniku pre završetka tranzicije privilegija
- povezuju se na **system bus** i zadržavaju već autorizovani kanal
- prosleđuju privilegovane FD-ove između pomoćnih procesa
- obavljaju bezbednosno osetljiv posao tokom teardown-a povezanog sa `do_exit()`

Dobri kandidati za pretragu:

- pomoćni programi za upravljanje lozinkama / nalozima
- SSH pomoćni programi
- pomoćni programi posredovani preko PolicyKit / D-Bus-a
- root desktop daemoni koji izlažu D-Bus metode

## YAMA kao exploit gate

`kernel.yama.ptrace_scope` predstavlja glavnu praktičnu prepreku za abuse ptrace porodice:

- `0`: klasično ptrace ponašanje za isti UID
- `1`: obično dozvoljava praćenje parent -> child procesa, čime neki javno dostupni exploit putevi mogu ostati dostupni
- `2`: zahteva `CAP_SYS_PTRACE` za attach pristup i blokira abuse neprivilegovanog `pidfd_getfd()` u ovom putu
- `3`: u potpunosti onemogućava ptrace attach do reboot-a

Za ovu tehniku, `ptrace_scope=2` predstavlja snažnu **privremenu mitigaciju**, jer za neprivilegovane korisnike prekida javno dostupni exploit put za `pidfd_getfd()` sa greškom `-EPERM`.

## Ideje za detekciju / pregled

Prilikom audita privilegovanog Linux software-a, tražite sledeće kombinacije:

- **privileged child process** + **attacker-controlled parent**
- privremeni pristup **vrednim otvorenim datotekama**
- privremeni pristup **autentifikovanim D-Bus/systemd kanalima**
- bezbednosne odluke koje ponovo koriste autorizaciju u stilu **ptrace-a** izvan klasičnog `ptrace(2)`
- kernel API-je koji mogu da **dupliraju, nasleđuju ili ponovo izlože** postojeće privilegovane FD-ove

Prilikom audita kernela, svaki put koji obavlja **autorizaciju ekvivalentnu ptrace-u** tokom **task teardown-a** tretirajte kao visokorizičan, naročito ako uspeh omogućava direktan pristup `task->files` ili drugim već autorizovanim resursima procesa.

## Reference

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) stranica priručnika](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama dokumentacija](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
