# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Przydatny **wzorzec Linux kernel privesc** polega na przekształceniu **błędu autoryzacji ptrace** w **kradzież file descriptorów** z uprzywilejowanego procesu.

W analizie przypadku Qualys dotyczącej `__ptrace_may_access()` (CVE-2026-46333) attacker wykonuje race z **uprzywilejowanym procesem, który kończy działanie lub porzuca uprawnienia**, i używa `pidfd_getfd()` do skopiowania FD do procesu attackera.

## Core idea

`pidfd_getfd()` duplikuje file descriptor z innego procesu, ale najpierw sprawdza uprawnienia w stylu ptrace względem targetu. Jeśli ta autoryzacja zostanie nieprawidłowo przyznana podczas **okna teardown**, unprivileged attacker może skopiować:

- FD dla **wrażliwych plików** już otwartych przez uprzywilejowanego helpera
- FD dla **uwierzytelnionych kanałów IPC** już autoryzowanych jako root

Przekształca to błąd autoryzacji po stronie kernela w bardzo praktyczny userspace primitive.

## Why the primitive is dangerous

Atak **nie wymaga błędu w samym uprzywilejowanym helperze**. Helper musi jedynie tymczasowo przechowywać coś wartościowego:

- `/etc/shadow`
- `/etc/ssh/*_key`
- uprzywilejowane połączenie D-Bus / systemd
- dowolny inny już otwarty sekret lub autoryzowany kanał

Po zduplikowaniu do procesu attackera kernel egzekwuje operacje na **skradzionym FD**, a nie na oryginalnej pathname ani w ramach nowego procesu uwierzytelniania.

## Exploitation pattern

1. Zidentyfikuj **setuid / setgid / file-capability binary** lub **root daemon**, który otwiera wrażliwe pliki albo utrzymuje użyteczne połączenia IPC.
2. Uzyskaj relację spełniającą odpowiednie kontrole polityki ptrace dla ścieżki targetu (na przykład będąc **parentem** uruchomionego uprzywilejowanego childa przy permissive ustawieniach YAMA).
3. Wykonuj race z procesem, gdy ten **kończy działanie**, **porzuca uprawnienia** lub w inny sposób przechodzi do stanu, w którym dostęp ptrace powinien stać się niedostępny.
4. Użyj `pidfd_open()` + `pidfd_getfd()`, aby zduplikować FD targetu podczas wąskiego okna autoryzacji.
5. Wykorzystaj skradziony FD z unprivileged context:
- `read()` secrets z uprzywilejowanego file descriptora
- wysyłaj requesty przez skradziony, uwierzytelniony kanał IPC, aby uzyskać **root-side actions**

Minimalny kształt primitive:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktyczne cele do audytu

Nadaj priorytet binariom i daemonom, które choćby przez krótki czas wykonują jedną z tych czynności:

- otwierają pliki dostępne wyłącznie dla root przed zakończeniem przejść uprawnień
- łączą się z **system bus** i utrzymują już autoryzowany kanał
- przekazują uprzywilejowane FD między helperami
- wykonują operacje wrażliwe z punktu widzenia bezpieczeństwa podczas teardownu sąsiadującego z `do_exit()`

Dobrzy kandydaci do analizy:

- helpery do zarządzania hasłami / kontami
- helpery SSH
- helpery obsługiwane przez PolicyKit / D-Bus
- rootowe demony desktopowe udostępniające metody D-Bus

## YAMA jako bramka exploita

`kernel.yama.ptrace_scope` jest istotną praktyczną bramką dla abuse z rodziny ptrace:

- `0`: klasyczne zachowanie ptrace dla tego samego UID
- `1`: zazwyczaj pozwala na śledzenie parent -> child, dzięki czemu niektóre publiczne ścieżki exploita pozostają dostępne
- `2`: wymaga `CAP_SYS_PTRACE` do dostępu w stylu attach i blokuje abuse `pidfd_getfd()` przez unprivileged users w tej ścieżce
- `3`: całkowicie wyłącza ptrace attach do czasu rebootu

W przypadku tej techniki `ptrace_scope=2` jest silnym **tymczasowym środkiem zaradczym**, ponieważ przerywa publiczną ścieżkę exploita `pidfd_getfd()`, zwracając `-EPERM` dla unprivileged users.

## Pomysły dotyczące detekcji / przeglądu

Podczas audytowania uprzywilejowanego software'u Linux szukaj następujących kombinacji:

- **uprzywilejowany proces child** + **parent kontrolowany przez attackera**
- tymczasowy dostęp do **wartościowych otwartych plików**
- tymczasowy dostęp do **uwierzytelnionych kanałów D-Bus/systemd**
- decyzje dotyczące bezpieczeństwa, które ponownie wykorzystują **autoryzację w stylu ptrace** poza klasycznym `ptrace(2)`
- kernel APIs, które mogą **duplikować, dziedziczyć lub ponownie eksportować** istniejące uprzywilejowane FD

Podczas audytowania kernela traktuj każdą ścieżkę wykonującą **autoryzację równoważną ptrace** podczas **teardownu taska** jako wysokiego ryzyka, szczególnie jeśli sukces zapewnia bezpośredni dostęp do `task->files` lub innych już autoryzowanych zasobów procesu.

## Referencje

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
