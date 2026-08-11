# Linux-ptrace-exit-race-`pidfd_getfd()`-FD-Diebstahl

Ein nützliches **Linux-Kernel-privesc-Muster** besteht darin, einen **ptrace authorization bug** in **file descriptor theft** aus einem privilegierten Prozess umzuwandeln.

In der Qualys-Fallstudie zu `__ptrace_may_access()` (CVE-2026-46333) lässt der Angreifer einen **privilegierten Prozess racen, der beendet wird oder Credentials abgibt**, und verwendet `pidfd_getfd()`, um einen FD in den Angreiferprozess zu duplizieren.<sup>[[1]](#references)[[2]](#references)</sup>

## Grundidee

`pidfd_getfd()` dupliziert einen File Descriptor aus einem anderen Prozess, prüft jedoch zuvor Berechtigungen im Stil von ptrace für das Ziel.<sup>[[3]](#references)</sup> Wenn diese Autorisierung während eines **Teardown-Fensters** fälschlicherweise gewährt wird, kann ein unprivilegierter Angreifer Folgendes kopieren:

- FDs für **sensitive Dateien**, die bereits von einem privilegierten Helper geöffnet wurden
- FDs für **authentifizierte IPC-Kanäle**, die bereits als root autorisiert wurden

Dadurch wird ein Authorization-Bug auf Kernel-Seite in ein sehr praktisches Userspace-Primitive umgewandelt.<sup>[[1]](#references)</sup>

## Warum das Primitive gefährlich ist

Der Angriff benötigt keinen Bug im privilegierten Helper selbst. Der Helper muss lediglich vorübergehend etwas Wertvolles halten:

- `/etc/shadow`
- `/etc/ssh/*_key`
- eine privilegierte D-Bus- / systemd-Verbindung
- jeden anderen bereits geöffneten geheimen oder autorisierten Kanal

Nach der Duplizierung in den Angreiferprozess verweist das Duplikat auf dieselbe Open File Description. Nachfolgende Reads oder IPC-Requests verwenden daher den bereits geöffneten FD, anstatt den ursprünglichen Path erneut zu öffnen oder einen neuen Authentication-Flow zu starten.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation-Muster

1. Identifiziere ein **setuid- / setgid- / File-Capability-Binary** oder einen **root-Daemon**, der sensitive Dateien öffnet oder nützliche IPC-Verbindungen aufrechterhält.<sup>[[2]](#references)</sup>
2. Erlange eine Beziehung, die die relevanten ptrace-Policy-Checks für den Zielpfad erfüllt (zum Beispiel als **Parent** eines gestarteten privilegierten Child-Prozesses unter permissiven YAMA-Einstellungen).<sup>[[2]](#references)[[4]](#references)</sup>
3. Race den Prozess, während er **beendet wird**, **Credentials abgibt** oder anderweitig in einen Zustand übergeht, in dem ptrace-Zugriff nicht mehr verfügbar sein sollte.<sup>[[2]](#references)</sup>
4. Verwende `pidfd_open()` + `pidfd_getfd()`, um den Ziel-FD während des kurzen Authorization-Fensters zu duplizieren.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Verwende den gestohlenen FD aus dem unprivilegierten Kontext erneut.<sup>[[2]](#references)</sup>
- Lies mit `read()` Geheimnisse aus einem privilegierten File Descriptor
- Sende Requests über einen gestohlenen authentifizierten IPC-Kanal, um **root-seitige Aktionen** auszulösen

Minimale Form des Primitives.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktische Ziele für das Audit

Priorisieren Sie Binaries und Daemons, die, selbst nur kurzzeitig, eines dieser Dinge tun:<sup>[[1]](#references)[[2]](#references)</sup>

- root-only-Dateien öffnen, bevor Privilegübergänge abgeschlossen sind
- sich mit dem **system bus** verbinden und einen bereits autorisierten Kanal offen halten
- privilegierte FDs über Helfer-Grenzen hinweg übergeben
- sicherheitsrelevante Arbeit während eines an `do_exit()` angrenzenden Teardowns ausführen

Gute Kandidaten für die Suche:<sup>[[1]](#references)</sup>

- Helfer für Passwort- / Accountverwaltung
- SSH-Helfer
- durch PolicyKit / D-Bus vermittelte Helfer
- root-Desktop-Daemons, die D-Bus-Methoden bereitstellen

## YAMA als Exploit-Sperre

`kernel.yama.ptrace_scope` ist eine wichtige praktische Sperre für ptrace-Familienmissbrauch:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: klassisches ptrace-Verhalten für dieselbe UID
- `1`: erlaubt typischerweise das Tracing von Parent -> Child, wodurch einige öffentliche Exploit-Pfade erreichbar bleiben können
- `2`: erfordert `CAP_SYS_PTRACE` für Attach-artigen Zugriff und blockiert unprivilegierten `pidfd_getfd()`-Missbrauch in diesem Pfad
- `3`: deaktiviert ptrace attach vollständig bis zum Neustart

Für diese Technik ist `ptrace_scope=2` eine starke **temporäre Mitigation**, da sie den öffentlichen `pidfd_getfd()`-Exploitation-Pfad für unprivilegierte Benutzer mit `-EPERM` unterbricht.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ideen für Detection / Review

Achten Sie beim Audit privilegierter Linux-Software auf diese Kombinationen:

- **privilegierter Child-Prozess** + **vom Angreifer kontrollierter Parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- temporärer Zugriff auf **wertvolle geöffnete Dateien**
- temporärer Zugriff auf **authentifizierte D-Bus/systemd-Kanäle**.<sup>[[2]](#references)</sup>
- Sicherheitsentscheidungen, die **ptrace-artige Autorisierung** außerhalb des klassischen `ptrace(2)` wiederverwenden
- Kernel-APIs, die vorhandene privilegierte FDs **duplizieren, erben oder erneut exportieren** können

Behandeln Sie beim Audit des Kernels jeden Pfad als hohes Risiko, der während des **Task-Teardowns** eine **ptrace-äquivalente Autorisierung** durchführt, insbesondere wenn der Erfolg direkten Zugriff auf `task->files` oder andere bereits autorisierte Prozessressourcen ermöglicht.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Lokale Root-Privilege-Eskalation und Offenlegung von Credentials im ptrace-Pfad des Linux-Kernels (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys-Advisory im TXT-Format](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2)-Handbuchseite](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Yama-Dokumentation des Linux-Kernels](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2)-Handbuchseite](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
