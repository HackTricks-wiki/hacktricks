# Linux ptrace exit-race: kradzież FD przez `pidfd_getfd()`

Przydatny **wzorzec Linux kernel privesc** polega na przekształceniu **błędu autoryzacji ptrace** w **kradzież deskryptora pliku** z uprzywilejowanego procesu.

W analizie przypadku Qualys dotyczącej `__ptrace_may_access()` (CVE-2026-46333) attacker ściga się z **uprzywilejowanym procesem, który kończy działanie lub obniża uprawnienia**, i używa `pidfd_getfd()` do zduplikowania FD do procesu attackera.<sup>[[1]](#references)[[2]](#references)</sup>

## Główna idea

`pidfd_getfd()` duplikuje deskryptor pliku z innego procesu, ale najpierw sprawdza uprawnienia w stylu ptrace względem celu.<sup>[[3]](#references)</sup> Jeśli ta autoryzacja zostanie nieprawidłowo przyznana podczas **okna teardown**, unprivileged attacker może skopiować:

- FD do **wrażliwych plików** już otwartych przez uprzywilejowanego helpera
- FD do **uwierzytelnionych kanałów IPC** już autoryzowanych jako root

Przekształca to błąd autoryzacji po stronie kernela w bardzo praktyczny prymityw userspace.<sup>[[1]](#references)</sup>

## Dlaczego ten prymityw jest niebezpieczny

Atak **nie wymaga błędu w samym uprzywilejowanym helperze**. Helper musi jedynie tymczasowo przechowywać coś wartościowego:

- `/etc/shadow`
- `/etc/ssh/*_key`
- uprzywilejowane połączenie D-Bus / systemd
- dowolny inny już otwarty sekret lub autoryzowany kanał

Po zduplikowaniu do procesu attackera duplikat odnosi się do tego samego open file description, więc kolejne odczyty lub żądania IPC używają już otwartego FD zamiast ponownie otwierać oryginalną ścieżkę lub rozpoczynać nowy proces uwierzytelniania.<sup>[[2]](#references)[[3]](#references)</sup>

## Wzorzec eksploatacji

1. Zidentyfikuj **binarkę setuid / setgid / z file capabilities** lub **daemon root**, który otwiera wrażliwe pliki albo utrzymuje przydatne połączenia IPC.<sup>[[2]](#references)</sup>
2. Uzyskaj relację spełniającą odpowiednie kontrole polityki ptrace dla danej ścieżki celu (na przykład będąc **parentem** uruchomionego uprzywilejowanego child process przy zezwalających ustawieniach YAMA).<sup>[[2]](#references)[[4]](#references)</sup>
3. Ścigaj się z procesem, gdy **kończy działanie**, **obniża uprawnienia** lub w inny sposób przechodzi do stanu, w którym dostęp ptrace powinien stać się niedostępny.<sup>[[2]](#references)</sup>
4. Użyj `pidfd_open()` + `pidfd_getfd()` do zduplikowania docelowego FD podczas wąskiego okna autoryzacji.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Ponownie użyj skradzionego FD z unprivileged context.<sup>[[2]](#references)</sup>
- `read()` sekretów z uprzywilejowanego deskryptora pliku
- wysyłanie żądań przez skradziony, uwierzytelniony kanał IPC w celu uzyskania **działań po stronie root**

Minimalny kształt prymitywu.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktyczne cele do audytu

Priorytetowo traktuj binaries i daemons, które choćby przez chwilę wykonują jedną z tych czynności:<sup>[[1]](#references)[[2]](#references)</sup>

- otwierają pliki dostępne wyłącznie dla root przed zakończeniem przejść uprawnień
- łączą się z **system bus** i utrzymują już autoryzowany kanał
- przekazują uprzywilejowane FD między helperami
- wykonują operacje związane z bezpieczeństwem podczas teardownu sąsiadującego z `do_exit()`

Dobre cele do wyszukania:<sup>[[1]](#references)</sup>

- helpery do zarządzania hasłami / kontami
- helpery SSH
- helpery obsługiwane przez PolicyKit / D-Bus
- root desktop daemons udostępniające metody D-Bus

## YAMA jako bramka exploita

`kernel.yama.ptrace_scope` jest główną praktyczną bramką dla nadużyć z rodziny ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: klasyczne zachowanie ptrace dla tego samego UID
- `1`: zazwyczaj zezwala na tracing parent -> child, co może pozostawiać dostępne niektóre publiczne ścieżki exploitów
- `2`: wymaga `CAP_SYS_PTRACE` dla dostępu typu attach i blokuje nadużycie `pidfd_getfd()` przez unprivileged users w tej ścieżce
- `3`: całkowicie wyłącza ptrace attach do czasu rebootu

W przypadku tej techniki `ptrace_scope=2` jest silnym **temporary mitigation**, ponieważ przerywa publiczną ścieżkę exploitation `pidfd_getfd()` przez `-EPERM` dla unprivileged users.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Pomysły dotyczące detekcji / przeglądu

Podczas audytu uprzywilejowanego Linux software szukaj następujących kombinacji:

- **privileged child process** + **attacker-controlled parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- tymczasowy dostęp do **valuable open files**
- tymczasowy dostęp do **authenticated D-Bus/systemd channels**.<sup>[[2]](#references)</sup>
- decyzje dotyczące bezpieczeństwa, które ponownie wykorzystują autoryzację w stylu **ptrace** poza klasycznym `ptrace(2)`
- kernel APIs, które mogą **duplikować, dziedziczyć lub ponownie eksportować** istniejące uprzywilejowane FD

Podczas audytu kernela traktuj każdą ścieżkę wykonującą **ptrace-equivalent authorization** podczas **task teardown** jako wysokiego ryzyka, szczególnie jeśli powodzenie zapewnia bezpośredni dostęp do `task->files` lub innych już autoryzowanych zasobów procesu.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Poradnik Qualys TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [strona podręcznika pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Dokumentacja Yama Linux kernel](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [strona podręcznika pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
