# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Przydatnym **Linux kernel privesc pattern** jest przekształcenie **ptrace authorization bug** w **file descriptor theft** z uprzywilejowanego procesu.

W case study Qualys dotyczącym `__ptrace_may_access()` (CVE-2026-46333) attacker wykonuje race z **uprzywilejowanym procesem, który kończy działanie lub obniża uprawnienia**, i używa `pidfd_getfd()`, aby zduplikować FD do procesu attackera.<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` duplikuje file descriptor z innego procesu, ale wcześniej sprawdza uprawnienia w stylu ptrace względem celu. Jeśli ta autoryzacja zostanie nieprawidłowo przyznana podczas **teardown window**, unprivileged attacker może skopiować:

- FD dla **wrażliwych plików**, które zostały już otwarte przez uprzywilejowanego helpera
- FD dla **uwierzytelnionych kanałów IPC**, które zostały już autoryzowane jako root

Przekształca to kernel-side authorization bug w bardzo praktyczny userspace primitive.<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

Atak **nie wymaga błędu w samym uprzywilejowanym helperze**. Helper musi jedynie tymczasowo posiadać coś wartościowego:

- `/etc/shadow`
- `/etc/ssh/*_key`
- uprzywilejowane połączenie D-Bus / systemd
- dowolny inny już otwarty secret lub autoryzowany kanał

Po zduplikowaniu do procesu attackera kernel egzekwuje operacje na **skradzionym FD**, a nie na oryginalnej ścieżce ani w ramach nowego flow uwierzytelniania.<sup>[[1]](#references)</sup>

## Exploitation pattern

1. Zidentyfikuj **setuid / setgid / file-capability binary** lub **root daemon**, który otwiera wrażliwe pliki albo utrzymuje przydatne połączenia IPC.
2. Uzyskaj relację spełniającą odpowiednie checks polityki ptrace dla ścieżki celu (na przykład będąc **parent** uruchomionego uprzywilejowanego child process przy permissive YAMA settings).
3. Wykonaj race z procesem, gdy **kończy działanie**, **obniża uprawnienia** lub w inny sposób przechodzi do stanu, w którym dostęp ptrace powinien stać się niedostępny.
4. Użyj `pidfd_open()` + `pidfd_getfd()`, aby zduplikować target FD podczas wąskiego authorization window.
5. Wykorzystaj skradziony FD z unprivileged context:
- `read()` secrets z uprzywilejowanego file descriptor
- wysyłaj requests przez skradziony uwierzytelniony kanał IPC, aby uzyskać **root-side actions**<sup>[[1]](#references)</sup>

Minimal primitive shape:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktyczne cele do audytu

Nadaj priorytet binariom i daemon om, które choćby przez krótki czas wykonują jedną z poniższych czynności:<sup>[[1]](#references)</sup>

- otwierają pliki dostępne wyłącznie dla roota przed zakończeniem przejścia uprawnień
- łączą się z **system bus** i utrzymują już autoryzowany kanał
- przekazują uprzywilejowane FD między helperami
- wykonują operacje wrażliwe z punktu widzenia bezpieczeństwa podczas teardownu w pobliżu `do_exit()`

Dobre cele do poszukiwań:<sup>[[1]](#references)</sup>

- helpery do zarządzania hasłami / kontami
- helpery SSH
- helpery pośredniczące przez PolicyKit / D-Bus
- rootowe daemony desktopowe udostępniające metody D-Bus

## YAMA jako bramka exploita

`kernel.yama.ptrace_scope` jest ważną praktyczną bramką dla abuse z rodziny ptrace:<sup>[[4]](#references)</sup>

- `0`: klasyczne zachowanie ptrace dla tego samego UID
- `1`: zazwyczaj pozwala na śledzenie parent -> child, dzięki czemu niektóre publiczne ścieżki exploita pozostają dostępne
- `2`: wymaga `CAP_SYS_PTRACE` do dostępu w stylu attach i blokuje abuse nieuprzywilejowanego `pidfd_getfd()` w tej ścieżce
- `3`: całkowicie wyłącza ptrace attach do czasu rebootu

Dla tej techniki `ptrace_scope=2` jest silnym **tymczasowym środkiem zaradczym**, ponieważ przerywa publiczną ścieżkę exploita `pidfd_getfd()`, zwracając `-EPERM` użytkownikom nieuprzywilejowanym.<sup>[[1]](#references)</sup>

## Pomysły dotyczące wykrywania / przeglądu

Podczas audytowania uprzywilejowanego oprogramowania Linux szukaj następujących kombinacji:

- **uprzywilejowany proces child** + **parent kontrolowany przez attackera**
- tymczasowy dostęp do **wartościowych otwartych plików**
- tymczasowy dostęp do **uwierzytelnionych kanałów D-Bus/systemd**
- decyzje dotyczące bezpieczeństwa, które wykorzystują ponownie **autoryzację w stylu ptrace** poza klasycznym `ptrace(2)`
- kernel APIs, które mogą **duplikować, dziedziczyć lub ponownie eksportować** istniejące uprzywilejowane FD

Podczas audytowania kernela traktuj każdą ścieżkę wykonującą **autoryzację równoważną ptrace** podczas **teardownu taska** jako wysokiego ryzyka, szczególnie jeśli sukces zapewnia bezpośredni dostęp do `task->files` lub innych już autoryzowanych zasobów procesu.

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
