# Linux ptrace exit-race `pidfd_getfd()`-FD-Diebstahl

{{#include ../../../banners/hacktricks-training.md}}

Ein nützliches **Linux kernel privesc pattern** besteht darin, einen **ptrace authorization bug** in **file descriptor theft** aus einem privilegierten Prozess umzuwandeln.

Im Qualys-Fallbeispiel zu `__ptrace_may_access()` (CVE-2026-46333) lässt der Angreifer einen **privilegierten Prozess, der beendet wird oder Berechtigungen abgibt**, in eine Race Condition laufen und verwendet `pidfd_getfd()`, um einen FD in den Angreiferprozess zu duplizieren.

## Grundidee

`pidfd_getfd()` dupliziert einen Dateideskriptor aus einem anderen Prozess, prüft zuvor jedoch Berechtigungen nach dem ptrace-Modell gegenüber dem Ziel. Wird diese Autorisierung während eines **teardown window** fälschlicherweise gewährt, kann ein unprivilegierter Angreifer Folgendes kopieren:

- FDs für **sensible Dateien**, die von einem privilegierten Helper bereits geöffnet wurden
- FDs für **authentifizierte IPC-Kanäle**, die bereits als root autorisiert wurden

Dadurch wird ein kernel-seitiger Authorization Bug in ein sehr praktisches Userspace-Primitive umgewandelt.

## Warum das Primitive gefährlich ist

Der Angriff benötigt **keinen Bug im privilegierten Helper selbst**. Der Helper muss lediglich vorübergehend etwas Wertvolles halten:

- `/etc/shadow`
- `/etc/ssh/*_key`
- eine privilegierte D-Bus- / systemd-Verbindung
- jeden anderen bereits geöffneten geheimen oder autorisierten Kanal

Sobald der FD in den Angreiferprozess dupliziert wurde, erzwingt der Kernel die Operationen auf dem **gestohlenen FD** und nicht auf dem ursprünglichen Pfad oder über einen neuen Authentifizierungsablauf.

## Exploitation pattern

1. Identifiziere eine **setuid- / setgid- / file-capability-Binary** oder einen **root-Daemon**, der sensible Dateien öffnet oder nützliche IPC-Verbindungen aufrechterhält.
2. Stelle eine Beziehung her, die die relevanten ptrace policy checks für den Zielpfad erfüllt (beispielsweise der **Parent** eines gestarteten privilegierten Childs unter permissiven YAMA-Einstellungen zu sein).
3. Lass den Prozess in eine Race Condition laufen, während er sich **beendet**, **Berechtigungen abgibt** oder anderweitig in einen Zustand eintritt, in dem ptrace-Zugriff nicht mehr verfügbar sein sollte.
4. Verwende `pidfd_open()` + `pidfd_getfd()`, um den Ziel-FD während des engen Autorisierungsfensters zu duplizieren.
5. Verwende den gestohlenen FD aus dem unprivilegierten Kontext erneut:
- Lies mit `read()` Secrets aus einem privilegierten Dateideskriptor
- Sende Anfragen über einen gestohlenen authentifizierten IPC-Kanal, um **rootseitige Aktionen** auszuführen

Minimale Form des Primitives:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktische Ziele für ein Audit

Priorisiere Binaries und Daemons, die – selbst kurzzeitig – eines dieser Dinge tun:

- root-only-Dateien öffnen, bevor sie Privilegübergänge abschließen
- sich mit dem **system bus** verbinden und einen bereits autorisierten Kanal offenhalten
- privilegierte FDs über Helper-Grenzen hinweg weitergeben
- sicherheitsrelevante Arbeiten während eines an `do_exit()` angrenzenden Teardowns ausführen

Gute Kandidaten für die Suche:

- Helfer für Passwort- / Accountverwaltung
- SSH-Helfer
- durch PolicyKit / D-Bus vermittelte Helfer
- root-Desktop-Daemons, die D-Bus-Methoden bereitstellen

## YAMA als Exploit-Gate

`kernel.yama.ptrace_scope` ist ein wichtiges praktisches Gate gegen ptrace-Familienmissbrauch:

- `0`: klassisches ptrace-Verhalten für dieselbe UID
- `1`: erlaubt typischerweise das Tracing von Parent -> Child, wodurch einige öffentliche Exploit-Pfade erreichbar bleiben können
- `2`: erfordert `CAP_SYS_PTRACE` für Attach-Zugriffe und blockiert den Missbrauch von `pidfd_getfd()` durch unprivilegierte Benutzer in diesem Pfad
- `3`: deaktiviert ptrace attach vollständig bis zum Reboot

Für diese Technik ist `ptrace_scope=2` eine starke **temporäre Mitigation**, da es den öffentlichen `pidfd_getfd()`-Exploitation-Pfad für unprivilegierte Benutzer mit `-EPERM` unterbricht.

## Ideen für Detection / Review

Achte beim Audit privilegierter Linux-Software auf diese Kombinationen:

- **privilegierter Child-Prozess** + **vom Angreifer kontrollierter Parent**
- temporärer Zugriff auf **wertvolle geöffnete Dateien**
- temporärer Zugriff auf **authentifizierte D-Bus/systemd-Kanäle**
- Sicherheitsentscheidungen, die **ptrace-artige Autorisierung** außerhalb des klassischen `ptrace(2)` wiederverwenden
- Kernel-APIs, die bereits vorhandene privilegierte FDs **duplizieren, erben oder erneut exportieren** können

Behandle beim Audit des Kernels jeden Pfad als hohes Risiko, der während des **Task-Teardowns** eine **ptrace-äquivalente Autorisierung** durchführt, insbesondere wenn der Erfolg direkten Zugriff auf `task->files` oder andere bereits autorisierte Prozessressourcen ermöglicht.

## Referenzen

- [Qualys-Blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys-Advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2)-Manpage](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux-Kernel-Yama-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
