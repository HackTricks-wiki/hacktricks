# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Ein nützliches **Linux-kernel-privesc pattern** besteht darin, einen **ptrace authorization bug** in **file descriptor theft** aus einem privilegierten Prozess umzuwandeln.

In der Qualys-Fallstudie zu `__ptrace_may_access()` (CVE-2026-46333) lässt der Angreifer einen **privileged process, der beendet wird oder Credentials abgibt**, eine Race Condition durchlaufen und verwendet `pidfd_getfd()`, um einen FD in den Angreiferprozess zu duplizieren.<sup>[[1]](#references)[[2]](#references)</sup>

## Grundidee

`pidfd_getfd()` dupliziert einen File Descriptor aus einem anderen Prozess, prüft jedoch zuvor ptrace-artige Berechtigungen gegenüber dem Ziel. Wenn diese Autorisierung während eines **teardown window** fälschlicherweise gewährt wird, kann ein unprivilegierter Angreifer Folgendes kopieren:

- FDs für **sensitive files**, die bereits von einem privilegierten Helper geöffnet wurden
- FDs für **authenticated IPC channels**, die bereits als root autorisiert wurden

Dadurch wird ein Authorization-Bug auf Kernel-Seite in ein sehr praktisches Userspace-Primitive umgewandelt.<sup>[[1]](#references)</sup>

## Warum das Primitive gefährlich ist

Der Angriff benötigt keinen Bug im privilegierten Helper selbst. Der Helper muss lediglich vorübergehend etwas Wertvolles halten:

- `/etc/shadow`
- `/etc/ssh/*_key`
- eine privilegierte D-Bus- / systemd-Verbindung
- jedes andere bereits geöffnete Secret oder jeden anderen autorisierten Channel

Sobald dieser in den Angreiferprozess dupliziert wurde, erzwingt der Kernel Operationen auf dem **gestohlenen FD**, nicht auf dem ursprünglichen Pfad oder über einen neuen Authentication-Flow.<sup>[[1]](#references)</sup>

## Exploitation pattern

1. Identifiziere eine **setuid- / setgid- / file-capability binary** oder einen **root daemon**, der sensitive files öffnet oder nützliche IPC-Verbindungen aufrechterhält.
2. Stelle eine Beziehung her, die die relevanten ptrace policy checks für den Zielpfad erfüllt (beispielsweise der **parent** eines gestarteten privilegierten Child-Prozesses unter permissiven YAMA-Einstellungen zu sein).
3. Führe eine Race Condition mit dem Prozess durch, während er **beendet wird**, **Credentials abgibt** oder anderweitig in einen Zustand übergeht, in dem ptrace-Zugriff nicht mehr verfügbar sein sollte.
4. Verwende `pidfd_open()` + `pidfd_getfd()`, um den Ziel-FD während des engen Autorisierungsfensters zu duplizieren.
5. Verwende den gestohlenen FD aus dem unprivilegierten Kontext erneut:
- Lies mit `read()` Secrets aus einem privilegierten File Descriptor
- Sende Requests über einen gestohlenen authentifizierten IPC-Channel, um **root-seitige Aktionen** auszuführen<sup>[[1]](#references)</sup>

Minimale Form des Primitives:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktische Ziele für das Audit

Priorisiert Binaries und Daemons, die auch nur kurzzeitig eine dieser Aktionen ausführen:<sup>[[1]](#references)</sup>

- root-only-Dateien öffnen, bevor Privilege-Transitions abgeschlossen sind
- sich mit dem **system bus** verbinden und einen bereits autorisierten Channel offen halten
- privilegierte FDs über Helper-Grenzen hinweg übergeben
- sicherheitsrelevante Aktionen während eines an `do_exit()` angrenzenden Teardowns ausführen

Geeignete Kandidaten für die Suche:<sup>[[1]](#references)</sup>

- Helper für Passwort- und Account-Management
- SSH-Helper
- durch PolicyKit / D-Bus vermittelte Helper
- root-Desktop-Daemons, die D-Bus-Methoden bereitstellen

## YAMA als Exploit-Gate

`kernel.yama.ptrace_scope` ist ein wichtiges praktisches Gate gegen Missbrauch der ptrace-Familie:<sup>[[4]](#references)</sup>

- `0`: klassisches ptrace-Verhalten für dieselbe UID
- `1`: erlaubt typischerweise das Tracing von Parent -> Child, wodurch einige öffentliche Exploit-Pfade erreichbar bleiben können
- `2`: erfordert `CAP_SYS_PTRACE` für Attach-Zugriffe und blockiert den Missbrauch von `pidfd_getfd()` durch unprivilegierte Benutzer in diesem Pfad
- `3`: deaktiviert ptrace attach vollständig bis zum Reboot

Für diese Technik ist `ptrace_scope=2` eine starke **temporäre Mitigation**, da der öffentliche `pidfd_getfd()`-Exploitation-Pfad für unprivilegierte Benutzer mit `-EPERM` unterbrochen wird.<sup>[[1]](#references)</sup>

## Ideen für Detection / Review

Beim Audit privilegierter Linux-Software sollte nach diesen Kombinationen gesucht werden:

- **privileged child process** + **attacker-controlled parent**
- temporärer Zugriff auf **wertvolle geöffnete Dateien**
- temporärer Zugriff auf **authentifizierte D-Bus/systemd-Channels**
- Sicherheitsentscheidungen, die **ptrace-style authorization** außerhalb des klassischen `ptrace(2)` wiederverwenden
- Kernel-APIs, die vorhandene privilegierte FDs **duplizieren, erben oder erneut exportieren** können

Beim Audit des Kernels sollte jeder Pfad, der während des **Task-Teardowns** eine **ptrace-equivalent authorization** durchführt, als hohes Risiko behandelt werden, insbesondere wenn der Erfolg direkten Zugriff auf `task->files` oder andere bereits autorisierte Prozessressourcen ermöglicht.

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
