# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Korisni **Linux kernel privesc obrazac** jeste pretvaranje **greške u ptrace autorizaciji** u **krađu deskriptora datoteka** iz privilegovanog procesa.

U Qualys `__ptrace_may_access()` studiji slučaja (CVE-2026-46333), napadač se utrkuje sa **privilegovanim procesom koji se gasi ili odbacuje privilegije** i koristi `pidfd_getfd()` za dupliciranje FD-a u napadačev proces.<sup>[[1]](#references)[[2]](#references)</sup>

## Osnovna ideja

`pidfd_getfd()` duplicira deskriptor datoteke iz drugog procesa, ali prethodno proverava ptrace-style dozvole nad ciljem.<sup>[[3]](#references)</sup> Ako je ta autorizacija pogrešno odobrena tokom **prozora gašenja**, neprivilegovani napadač može da kopira:

- FD-ove za **osetljive datoteke** koje je privilegovani helper već otvorio
- FD-ove za **autentifikovane IPC kanale** koji su već autorizovani kao root

Ovim se greška u autorizaciji na strani kernela pretvara u veoma praktičan userspace primitive.<sup>[[1]](#references)</sup>

## Zašto je primitive opasan

Za napad nije potrebna greška u samom privilegovanom helperu. Helper samo treba privremeno da drži nešto vredno:

- `/etc/shadow`
- `/etc/ssh/*_key`
- privilegovanu D-Bus / systemd konekciju
- bilo koju drugu već otvorenu tajnu ili autorizovani kanal

Kada se duplikat prebaci u napadačev proces, on upućuje na isti open file description, pa se naknadna čitanja ili IPC zahtevi izvršavaju preko već otvorenog FD-a, umesto ponovnog otvaranja originalne putanje ili pokretanja novog procesa autentifikacije.<sup>[[2]](#references)[[3]](#references)</sup>

## Obrazac eksploatacije

1. Identifikujte **setuid / setgid / file-capability binary** ili **root daemon** koji otvara osetljive datoteke ili održava korisne IPC konekcije.<sup>[[2]](#references)</sup>
2. Uspostavite odnos koji ispunjava relevantne ptrace policy provere za ciljnu putanju (na primer, budite **parent** pokrenutog privilegovanog child procesa uz permisivna YAMA podešavanja).<sup>[[2]](#references)[[4]](#references)</sup>
3. Utrkujte se sa procesom dok se **gasi**, **odbacuje privilegije** ili na drugi način prelazi u stanje u kom je ptrace pristup trebalo da postane nedostupan.<sup>[[2]](#references)</sup>
4. Koristite `pidfd_open()` + `pidfd_getfd()` da duplicirate ciljni FD tokom uskog autorizacionog prozora.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Ponovo koristite ukradeni FD iz neprivilegovanog konteksta.<sup>[[2]](#references)</sup>
- `read()` tajne iz privilegovanog file descriptor-a
- slanje zahteva preko ukradenog autentifikovanog IPC kanala radi dobijanja **root-side actions**

Minimalni oblik primitive-a.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktične mete za audit

Prioritet dajte binarnim datotekama i daemonima koji, čak i nakratko, rade nešto od sledećeg:<sup>[[1]](#references)[[2]](#references)</sup>

- otvaraju datoteke dostupne samo root korisniku pre završetka tranzicije privilegija
- povezuju se na **system bus** i zadržavaju već autorizovani kanal
- prosleđuju privilegovane FD-ove između helper procesa
- obavljaju bezbednosno osetljive radnje tokom teardown-a povezanog sa `do_exit()`

Dobri kandidati za hunting:<sup>[[1]](#references)</sup>

- helperi za upravljanje lozinkama / nalozima
- SSH helperi
- PolicyKit / D-Bus mediated helperi
- root desktop daemoni koji izlažu D-Bus metode

## YAMA kao exploit gate

`kernel.yama.ptrace_scope` je važan praktični gate za abuse ptrace familije:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: klasično ptrace ponašanje za isti UID
- `1`: obično dozvoljava praćenje parent -> child procesa, što neke public exploit putanje može održati dostupnim
- `2`: zahteva `CAP_SYS_PTRACE` za attach-style pristup i blokira abuse neprivilegovanog `pidfd_getfd()` u ovoj putanji
- `3`: u potpunosti onemogućava ptrace attach do reboot-a

Za ovu tehniku, `ptrace_scope=2` je snažna **privremena mitigacija** jer prekida javnu `pidfd_getfd()` exploitation putanju sa `-EPERM` za neprivilegovane korisnike.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ideje za detekciju / review

Prilikom audita privilegovanog Linux softvera, tražite sledeće kombinacije:

- **privilegovani child proces** + **parent pod kontrolom napadača**.<sup>[[2]](#references)[[4]](#references)</sup>
- privremeni pristup **vrednim otvorenim datotekama**
- privremeni pristup **autentifikovanim D-Bus/systemd kanalima**.<sup>[[2]](#references)</sup>
- bezbednosne odluke koje ponovo koriste **ptrace-style autorizaciju** izvan klasičnog `ptrace(2)`
- kernel API-je koji mogu da **dupliraju, naslede ili ponovo izlože** postojeće privilegovane FD-ove

Prilikom audita kernela, svaku putanju koja obavlja **ptrace-ekvivalentnu autorizaciju** tokom **teardown-a task-a** tretirajte kao visokorizičnu, naročito ako uspeh omogućava direktan pristup `task->files` ili drugim već autorizovanim resursima procesa.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Lokalna eskalacija root privilegija i otkrivanje kredencijala u Linux kernel ptrace putanji (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys TXT savet](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) stranica priručnika](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama dokumentacija](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) stranica priručnika](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
