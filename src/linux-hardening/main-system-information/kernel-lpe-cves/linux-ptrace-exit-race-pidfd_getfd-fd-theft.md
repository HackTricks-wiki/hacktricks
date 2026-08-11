# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Ein nützliches **Linux kernel privesc pattern** besteht darin, einen **ptrace authorization bug** in **file descriptor theft** aus einem privilegierten Prozess umzuwandeln.

Im Qualys-Fallbeispiel zu `__ptrace_may_access()` (CVE-2026-46333) führt der Angreifer einen Race gegen einen **privileged process, der beendet wird oder Credentials abgibt**, und verwendet `pidfd_getfd()`, um einen FD in den Angreiferprozess zu duplizieren.<sup>[[1]](#references)[[2]](#references)</sup>

## Grundidee

`pidfd_getfd()` dupliziert einen File Descriptor aus einem anderen Prozess, prüft jedoch zuvor die ptrace-artigen Berechtigungen für das Ziel.<sup>[[3]](#references)</sup> Wenn diese Autorisierung während eines **teardown window** fälschlicherweise gewährt wird, kann ein unprivilegierter Angreifer Folgendes kopieren:

- FDs für **sensitive files**, die bereits von einem privilegierten Helper geöffnet wurden
- FDs für **authenticated IPC channels**, die bereits als root autorisiert sind

Dadurch wird ein kernel-seitiger Autorisierungsfehler in ein sehr praktisches Userspace-Primitive umgewandelt.<sup>[[1]](#references)</sup>

## Warum das Primitive gefährlich ist

Der Angriff benötigt keinen Bug im privilegierten Helper selbst. Der Helper muss lediglich vorübergehend etwas Wertvolles geöffnet halten:

- `/etc/shadow`
- `/etc/ssh/*_key`
- eine privilegierte D-Bus- / systemd-Verbindung
- jeden anderen bereits geöffneten Secret- oder autorisierten Channel

Sobald der FD in den Angreiferprozess dupliziert wurde, verweist das Duplikat auf dieselbe Open File Description. Nachfolgende Lesevorgänge oder IPC-Anfragen verwenden daher den bereits geöffneten FD, anstatt den ursprünglichen Pfad erneut zu öffnen oder einen neuen Authentication Flow zu starten.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. Identifiziere ein **setuid / setgid / file-capability binary** oder einen **root daemon**, der sensitive files öffnet oder nützliche IPC-Verbindungen offen hält.<sup>[[2]](#references)</sup>
2. Stelle eine Beziehung her, die die relevanten ptrace policy checks für den Zielpfad erfüllt (zum Beispiel der **parent** eines gestarteten privilegierten Child-Prozesses unter permissiven YAMA-Einstellungen zu sein).<sup>[[2]](#references)[[4]](#references)</sup>
3. Führe einen Race gegen den Prozess aus, während er sich **beendet**, **Credentials abgibt** oder anderweitig in einen Zustand übergeht, in dem ptrace access nicht mehr verfügbar sein sollte.<sup>[[2]](#references)</sup>
4. Verwende `pidfd_open()` + `pidfd_getfd()`, um den Ziel-FD während des engen Autorisierungsfensters zu duplizieren.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Verwende den gestohlenen FD aus dem unprivilegierten Kontext erneut.<sup>[[2]](#references)</sup>
- Lies mit `read()` Secrets aus einem privilegierten File Descriptor
- Sende Requests über einen gestohlenen authentifizierten IPC-Channel, um **root-side actions** auszulösen

Minimale Form des Primitives.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Praktische Ziele für ein Audit

Priorisiere Binaries und Daemons, die, selbst kurzzeitig, eines dieser Dinge tun:<sup>[[1]](#references)[[2]](#references)</sup>

- root-only-Dateien öffnen, bevor Privilegübergänge abgeschlossen sind
- sich mit dem **system bus** verbinden und einen bereits autorisierten Kanal offenhalten
- privilegierte FDs über Helper-Grenzen hinweg übergeben
- sicherheitsrelevante Arbeiten während des an `do_exit()` angrenzenden Teardowns ausführen

Gute Kandidaten für die Suche:<sup>[[1]](#references)</sup>

- Helper für Passwort- / Account-Management
- SSH-Helper
- durch PolicyKit / D-Bus vermittelte Helper
- root-Desktop-Daemons, die D-Bus-Methoden bereitstellen

## YAMA als Exploit-Schranke

`kernel.yama.ptrace_scope` ist eine wichtige praktische Schranke gegen ptrace-family-Abuse:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: klassisches Same-UID-ptrace-Verhalten
- `1`: erlaubt typischerweise Tracing von Parent -> Child, wodurch einige öffentliche Exploit-Pfade erreichbar bleiben können
- `2`: erfordert `CAP_SYS_PTRACE` für Attach-Zugriff und blockiert unprivilegierten `pidfd_getfd()`-Abuse in diesem Pfad
- `3`: deaktiviert ptrace attach vollständig bis zum Reboot

Für diese Technik ist `ptrace_scope=2` eine starke **temporäre Mitigation**, da es den öffentlichen `pidfd_getfd()`-Exploitation-Pfad für unprivilegierte Benutzer mit `-EPERM` unterbricht.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ideen für Detection / Review

Beim Audit privilegierter Linux-Software sollte nach diesen Kombinationen gesucht werden:

- **privilegierter Child-Prozess** + **vom Angreifer kontrollierter Parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- temporärer Zugriff auf **wertvolle geöffnete Dateien**
- temporärer Zugriff auf **authentifizierte D-Bus-/systemd-Kanäle**.<sup>[[2]](#references)</sup>
- Sicherheitsentscheidungen, die **ptrace-artige Autorisierung** außerhalb des klassischen `ptrace(2)` wiederverwenden
- Kernel-APIs, die bestehende privilegierte FDs **duplizieren, erben oder erneut exportieren** können

Beim Audit des Kernels sollte jeder Pfad, der während des **Task-Teardowns** eine **ptrace-äquivalente Autorisierung** durchführt, als hohes Risiko behandelt werden, insbesondere wenn der Erfolg direkten Zugriff auf `task->files` oder andere bereits autorisierte Prozessressourcen ermöglicht.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Lokale Root-Privilegieneskalation und Offenlegung von Credentials im ptrace-Pfad des Linux-Kernels (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys-Beratung TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2)-Handbuchseite](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Dokumentation zum Linux-Kernel-Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2)-Handbuchseite](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
