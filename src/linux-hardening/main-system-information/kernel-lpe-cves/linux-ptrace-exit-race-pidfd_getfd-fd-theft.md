# Kradzież FD przez exit-race `pidfd_getfd()` w Linux ptrace

{{#include ../../../banners/hacktricks-training.md}}

Przydatnym **wzorem Linux kernel privesc** jest przekształcenie **błędu autoryzacji ptrace** w **kradzież deskryptora pliku** z uprzywilejowanego procesu.

W analizie przypadku Qualys dotyczącej `__ptrace_may_access()` (CVE-2026-46333) attacker wykonuje race z **uprzywilejowanym procesem, który kończy działanie lub porzuca uprawnienia**, i używa `pidfd_getfd()` do zduplikowania FD do procesu attackera.<sup>[[1]](#references)[[2]](#references)</sup>

## Główna idea

`pidfd_getfd()` duplikuje deskryptor pliku z innego procesu, ale najpierw sprawdza uprawnienia w stylu ptrace względem procesu docelowego.<sup>[[3]](#references)</sup> Jeśli ta autoryzacja zostanie nieprawidłowo przyznana podczas **okna teardown**, nieuprzywilejowany attacker może skopiować:

- FD dla **wrażliwych plików** już otwartych przez uprzywilejowanego helpera
- FD dla **uwierzytelnionych kanałów IPC** już autoryzowanych jako root

Przekształca to błąd autoryzacji po stronie kernela w bardzo praktyczny prymityw userspace.<sup>[[1]](#references)</sup>

## Dlaczego ten prymityw jest niebezpieczny

Atak **nie wymaga** błędu w samym uprzywilejowanym helperze. Helper musi jedynie tymczasowo przechowywać coś wartościowego:

- `/etc/shadow`
- `/etc/ssh/*_key`
- uprzywilejowane połączenie D-Bus / systemd
- dowolny inny już otwarty sekret lub autoryzowany kanał

Po zduplikowaniu do procesu attackera duplikat odnosi się do tego samego open file description, więc kolejne odczyty lub żądania IPC używają już otwartego FD zamiast ponownie otwierać oryginalną ścieżkę albo rozpoczynać nowy proces uwierzytelniania.<sup>[[2]](#references)[[3]](#references)</sup>

## Wzorzec exploitacji

1. Zidentyfikuj **binarkę setuid / setgid / z file capabilities** lub **root daemon**, który otwiera wrażliwe pliki albo utrzymuje przydatne połączenia IPC.<sup>[[2]](#references)</sup>
2. Uzyskaj relację spełniającą odpowiednie sprawdzenia polityki ptrace dla ścieżki do celu (na przykład będąc **parentem** uruchomionego uprzywilejowanego childa przy liberalnych ustawieniach YAMA).<sup>[[2]](#references)[[4]](#references)</sup>
3. Wykonaj race z procesem, gdy **kończy działanie**, **porzuca uprawnienia** lub w inny sposób przechodzi do stanu, w którym dostęp ptrace powinien stać się niedostępny.<sup>[[2]](#references)</sup>
4. Użyj `pidfd_open()` + `pidfd_getfd()`, aby zduplikować FD procesu docelowego podczas krótkiego okna autoryzacji.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Ponownie użyj skradzionego FD z nieuprzywilejowanego kontekstu.<sup>[[2]](#references)</sup>
- `read()` sekretów z uprzywilejowanego deskryptora pliku
- wysyłanie żądań przez skradziony uwierzytelniony kanał IPC w celu uzyskania **działań po stronie root**

Minimalny kształt prymitywu.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktyczne cele do audytu

Nadaj priorytet plikom binarnym i daemonóm, które choćby przez krótki czas wykonują jedną z tych czynności:<sup>[[1]](#references)[[2]](#references)</sup>

- otwierają pliki dostępne wyłącznie dla roota przed zakończeniem przejść uprawnień
- łączą się z **system bus** i utrzymują już autoryzowany kanał
- przekazują uprzywilejowane FD między helperami
- wykonują operacje wrażliwe z punktu widzenia bezpieczeństwa podczas zwalniania zasobów w pobliżu `do_exit()`

Dobre cele do sprawdzenia:<sup>[[1]](#references)</sup>

- helpery do zarządzania hasłami / kontami
- helpery SSH
- helpery obsługiwane przez PolicyKit / D-Bus
- root desktop daemons udostępniające metody D-Bus

## YAMA jako bramka exploita

`kernel.yama.ptrace_scope` jest ważną praktyczną bramką dla nadużyć z rodziny ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: klasyczne zachowanie ptrace dla tego samego UID
- `1`: zazwyczaj pozwala na śledzenie parent -> child, dzięki czemu niektóre publiczne ścieżki exploitów pozostają dostępne
- `2`: wymaga `CAP_SYS_PTRACE` w przypadku dostępu typu attach i blokuje nadużycie `pidfd_getfd()` przez unprivileged users w tej ścieżce
- `3`: całkowicie wyłącza ptrace attach do czasu ponownego uruchomienia

W przypadku tej techniki `ptrace_scope=2` jest silnym **tymczasowym środkiem zaradczym**, ponieważ przerywa publiczną ścieżkę eksploatacji `pidfd_getfd()` błędem `-EPERM` dla unprivileged users.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Pomysły dotyczące wykrywania / przeglądu

Podczas audytowania uprzywilejowanego oprogramowania Linux szukaj następujących kombinacji:

- **uprzywilejowany proces child** + **parent kontrolowany przez attackera**.<sup>[[2]](#references)[[4]](#references)</sup>
- tymczasowy dostęp do **wartościowych otwartych plików**
- tymczasowy dostęp do **uwierzytelnionych kanałów D-Bus/systemd**.<sup>[[2]](#references)</sup>
- decyzje dotyczące bezpieczeństwa, które wykorzystują ponownie **autoryzację w stylu ptrace** poza klasycznym `ptrace(2)`
- kernel APIs, które mogą **duplikować, dziedziczyć lub ponownie eksportować** istniejące uprzywilejowane FD

Podczas audytowania kernela traktuj każdą ścieżkę, która wykonuje **autoryzację równoważną ptrace** podczas **zwalniania zasobów taska**, jako wysokiego ryzyka, zwłaszcza jeśli powodzenie zapewnia bezpośredni dostęp do `task->files` lub innych już autoryzowanych zasobów procesu.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Lokalne podniesienie uprawnień roota i ujawnienie danych uwierzytelniających w ścieżce ptrace kernela Linux (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Poradnik Qualys w formacie TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [strona podręcznika pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Dokumentacja kernela Linux dotycząca YAMA](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [strona podręcznika pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
