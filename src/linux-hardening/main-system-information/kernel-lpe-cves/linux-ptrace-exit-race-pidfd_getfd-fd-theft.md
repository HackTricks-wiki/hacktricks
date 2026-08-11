# Linux ptrace exit-race `pidfd_getfd()` krađa FD-a

Korisni **Linux kernel privesc obrazac** jeste pretvaranje **greške u ptrace autorizaciji** u **krađu deskriptora datoteka** iz privilegovanog procesa.

U Qualys studiji slučaja za `__ptrace_may_access()` (CVE-2026-46333), napadač pravi race sa **privilegovanim procesom koji se gasi ili odbacuje privilegije** i koristi `pidfd_getfd()` da duplira FD u napadačev proces.<sup>[[1]](#references)[[2]](#references)</sup>

## Osnovna ideja

`pidfd_getfd()` duplira deskriptor datoteke iz drugog procesa, ali prethodno proverava ptrace-style dozvole nad ciljem.<sup>[[3]](#references)</sup> Ako se ta autorizacija pogrešno odobri tokom **teardown window-a**, neprivilegovani napadač može da kopira:

- FD-ove za **osetljive datoteke** koje je privilegovani helper već otvorio
- FD-ove za **autentifikovane IPC kanale** koji su već autorizovani kao root

Ovo pretvara kernel-side grešku u autorizaciji u veoma praktičan userspace primitive.<sup>[[1]](#references)</sup>

## Zašto je primitive opasan

Napad ne zahteva grešku u samom privilegovanom helper-u. Helper samo treba privremeno da drži nešto vredno:

- `/etc/shadow`
- `/etc/ssh/*_key`
- privilegovanu D-Bus / systemd konekciju
- bilo koju drugu već otvorenu tajnu ili autorizovani kanal

Kada se duplikat kopira u napadačev proces, on referiše na isti open file description, pa naredna čitanja ili IPC zahtevi koriste već otvoreni FD umesto ponovnog otvaranja originalne putanje ili pokretanja novog authentication flow-a.<sup>[[2]](#references)[[3]](#references)</sup>

## Obrazac eksploatacije

1. Identifikovati **setuid / setgid / file-capability binary** ili **root daemon** koji otvara osetljive datoteke ili održava korisne IPC konekcije.<sup>[[2]](#references)</sup>
2. Uspostaviti odnos koji ispunjava relevantne ptrace policy provere za ciljnu putanju (na primer, biti **parent** pokrenutog privilegovanog child procesa uz permisivne YAMA postavke).<sup>[[2]](#references)[[4]](#references)</sup>
3. Napraviti race sa procesom dok se **gasi**, **odbacuje privilegije** ili na drugi način ulazi u stanje u kojem je ptrace pristup trebalo da postane nedostupan.<sup>[[2]](#references)</sup>
4. Koristiti `pidfd_open()` + `pidfd_getfd()` za dupliranje ciljnog FD-a tokom uskog authorization window-a.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Ponovo koristiti ukradeni FD iz neprivilegovanog konteksta.<sup>[[2]](#references)</sup>
- `read()` tajne iz privilegovanog file descriptor-a
- slati zahteve preko ukradenog autentifikovanog IPC kanala radi dobijanja **root-side akcija**

Minimalni oblik primitive-a.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktične ciljeve za audit

Prioritetno analizirajte binarne datoteke i daemone koji, makar nakratko, rade nešto od sledećeg:<sup>[[1]](#references)[[2]](#references)</sup>

- otvaraju datoteke dostupne samo root-u pre završetka tranzicije privilegija
- povezuju se na **system bus** i zadržavaju već autorizovani kanal
- prosleđuju privilegovane FD-ove preko granica helper-a
- obavljaju bezbednosno osetljiv posao tokom teardown-a povezanog sa `do_exit()`

Dobri kandidati za analizu:<sup>[[1]](#references)</sup>

- helper-i za upravljanje lozinkama / nalozima
- SSH helper-i
- PolicyKit / D-Bus posredovani helper-i
- root desktop daemoni koji izlažu D-Bus metode

## YAMA kao exploit gate

`kernel.yama.ptrace_scope` je važan praktični gate za zloupotrebu ptrace-family funkcionalnosti:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: klasično ptrace ponašanje za isti UID
- `1`: obično dozvoljava praćenje parent -> child procesa, što može održati dostupnim neke javne exploit putanje
- `2`: zahteva `CAP_SYS_PTRACE` za attach-style pristup i blokira neprivilegovanu zloupotrebu `pidfd_getfd()` u ovoj putanji
- `3`: potpuno onemogućava ptrace attach do reboot-a

Za ovu tehniku, `ptrace_scope=2` predstavlja snažnu **privremenu mitigaciju**, jer neprivilegovanim korisnicima prekida javnu `pidfd_getfd()` exploitation putanju sa greškom `-EPERM`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ideje za detekciju / review

Prilikom audita privilegovanog Linux softvera, tražite sledeće kombinacije:

- **privilegovani child proces** + **parent proces pod kontrolom napadača**.<sup>[[2]](#references)[[4]](#references)</sup>
- privremeni pristup **vrednim otvorenim datotekama**
- privremeni pristup **autentifikovanim D-Bus/systemd kanalima**.<sup>[[2]](#references)</sup>
- bezbednosne odluke koje ponovo koriste **ptrace-style autorizaciju** izvan klasičnog `ptrace(2)`
- kernel API-je koji mogu da **dupliraju, nasleđuju ili ponovo izlože** postojeće privilegovane FD-ove

Prilikom audita kernela, svaku putanju koja obavlja **ptrace-ekvivalentnu autorizaciju** tokom **teardown-a task-a** tretirajte kao visokorizičnu, naročito ako uspeh omogućava direktan pristup `task->files` ili drugim već autorizovanim resursima procesa.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Lokalna eskalacija root privilegija i otkrivanje kredencijala u Linux kernel ptrace putanji (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys savetodavni TXT dokument](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) stranica priručnika](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Dokumentacija Linux kernela za Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) stranica priručnika](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
