# Dateisysteme, Inodes und Wiederherstellung

{{#include ../../banners/hacktricks-training.md}}

Der Missbrauch von Dateisystemen besteht oft darin, die Beziehung zwischen einem sichtbaren Pfad und dem dahinterliegenden Objekt zu verwirren.

Festplatten-Images können ein weiteres Dateisystem verbergen.<sup>[[1]](#references)</sup> Beschreibbare Mounts können von privilegierten Jobs verwendet werden.

Hardlinks können denselben Inode unter einem anderen Namen zugänglich machen.<sup>[[3]](#references)</sup> Gelöschte Dateien können über einen offenen File Descriptor weiterhin lesbar sein.<sup>[[5]](#references)[[6]](#references)</sup>

Diese Seite konzentriert sich auf die Technik und nicht auf ein bestimmtes Lab oder Ziel.

## Festplatten-Images und Loop-Mounts

Eine reguläre Datei kann ein vollständiges Dateisystem enthalten, sodass ein Festplatten-Image beim Mounten einen zweiten Dateisystembaum zugänglich machen kann.<sup>[[1]](#references)</sup>

Backup-Images, kopierte Blockgeräte, VM-Artefakte oder umbenannte Blobs können daher Zugangsdaten, Scripts, SSH-Keys, Konfigurationsdateien oder Flags enthalten, selbst wenn sie von außen nicht nützlich aussehen.

Identifiziere wahrscheinliche Images mit `file`, um einen Kandidaten zu klassifizieren, mit `blkid`, um erkannte Dateisystem-Metadaten zu untersuchen, und mit `strings -a`, um die gesamte Datei nach druckbaren Zeichenfolgen zu durchsuchen.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Wenn das Mounten erlaubt ist, verwende ein Loop-Mount mit `ro`, sodass das Image schreibgeschützt eingebunden wird; der unten stehende Befehl `find` begrenzt die Untersuchungstiefe und den Dateityp.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Wenn das Einhängen nicht verfügbar ist und das Image ext2/ext3/ext4 verwendet, untersuchen Sie seine Metadaten direkt mit `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Die Technik ist nützlich, weil sie eine normal aussehende Datei in einen zweiten Dateisystembaum verwandelt.<sup>[[1]](#references)</sup> Betrachte sie als Möglichkeit, versteckte Daten wiederherzustellen, nicht als eigenständige Privilege Escalation.

## Writable Mount Abuse

Ein beschreibbarer Mount wird gefährlich, wenn ein privilegierterer Kontext später etwas darin vertraut. Die wichtige Frage lautet nicht nur: „Kann ich hier schreiben?“, sondern auch: „Wer liest, führt später daraus aus, importiert daraus oder lädt daraus?“

Verwende `findmnt`, um gemountete Dateisysteme und deren Optionen zu untersuchen.<sup>[[9]](#references)</sup>

Finde beschreibbare Mounts und verdächtige Verbraucher mit den dokumentierten `find`-Prädikaten für Berechtigungen, Typen und Dateisystemgrenzen. Verwende anschließend rekursives `grep`, um nach wahrscheinlichen Konfigurationen der Verbraucher zu suchen.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Häufige Missbrauchsmuster:

- Ein Cron-Job oder systemd-Service führt ein beschreibbares Skript aus dem Mount aus.<sup>[[13]](#references)[[14]](#references)</sup>
- Ein privilegierter Service lädt Plugins, Konfigurationen, Templates oder Hilfs-Binaries aus dem Mount.
- Ein Mount enthält SUID-Dateien und ermöglicht deren Änderung, Ersetzung oder die Manipulation von Pfaden.
- Ein Container oder chroot stellt einen hostbasierten Pfad bereit, der aus der eingeschränkten Umgebung beschreibbar ist. Mount-Namespaces stellen separate Mount-Hierarchien bereit, während `chroot()` nur die Auflösung von Pfadnamen ändert und keine vollständige Sandbox darstellt.<sup>[[15]](#references)[[16]](#references)</sup>

Generisches Validierungsmuster unter Verwendung derselben `find`-Prädikate.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Bei der Nachweisführung der Auswirkungen in einem autorisierten Lab sollte die Payload beobachtbar und minimal gehalten werden, beispielsweise indem die Ausgabe von `id` in eine temporäre Datei geschrieben wird.<sup>[[23]](#references)</sup> Die grundlegende Technik besteht in der verzögerten Ausführung über einen vertrauenswürdigen, beschreibbaren Speicherort.

## Inodes und Pfadverwechslung

Ein Inode ist das Dateisystemobjekt; ein Pfad ist lediglich ein Name, der auf dieses Objekt verweist. Geräte- und Inode-Metadaten ermöglichen es, Objekte über Dateisysteme hinweg zu unterscheiden, während Link-Zähler mehrere Hardlinks sichtbar machen.<sup>[[3]](#references)</sup> Ein gelöschter Pfadname bedeutet nicht immer, dass die Daten verschwunden sind, solange ein Prozess die Datei noch geöffnet hat.<sup>[[5]](#references)</sup>

Die folgenden `find`-Prädikate vergleichen die Inode-Identität, Link-Zähler, Gerätegrenzen und Zeitstempel.<sup>[[4]](#references)</sup>

Vergleiche Dateien anhand von Inode und Gerät mit `ls -i` und Metadatenformaten von `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Finde jeden sichtbaren Pfadnamen für denselben Inode mit `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Suchen Sie direkt anhand der Inode-Nummer mit `find -inum`, wenn Sie nur Metadaten haben.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Diese Technik ist nützlich, wenn eine Datei unter einem unerwarteten Namen erscheint, wenn eine Anwendung einen Pfad validiert, aber einen anderen verwendet oder wenn ein privilegierter Wrapper mit einem Inode interagiert, der auch an anderer Stelle erreichbar ist.

## Hardlink Abuse

Hardlinks erstellen mehrere Namen für denselben Inode. Sie verweisen nicht wie Symlinks auf einen Zielpfad, sondern sind gleichwertige Namen für dasselbe Dateiobjekt.<sup>[[3]](#references)</sup>

Finde SUID-Dateien mit mehreren Hardlinks mithilfe der Berechtigungs- und Linkanzahl-Prädikate von `find`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Untersuchen Sie eine verdächtige Datei mit `stat` und `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Warum es wichtig ist:

- Eine sensible Datei kann über einen weniger offensichtlichen Pfad erreichbar sein.
- Ein SUID wrapper kann sich hinter einem Namen verbergen, der nicht privilegiert wirkt.
- Eine Bereinigung, die einen Pfadnamen entfernt, kann einen anderen Hardlink bestehen lassen.

Linux' `fs.protected_hardlinks` sysctl kann die Erstellung von Hardlinks über Privilege-Grenzen hinweg einschränken.<sup>[[7]](#references)</sup> Vorhandene Hardlinks sollten dennoch überprüft werden.

## Wiederherstellung gelöschter Dateien über offene FDs

Wenn ein Prozess eine Datei geöffnet hält, bleibt die Datei nach dem Entfernen ihres letzten Pfadnamens bestehen, bis der letzte Descriptor geschlossen wird; Linux stellt diese Descriptors unter `/proc/<pid>/fd/` bereit.<sup>[[5]](#references)[[6]](#references)</sup>

Finde gelöschte offene Dateien, indem du die Descriptors unter `/proc` auflistest und die Ausgabe geöffneter Dateien filterst.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Die Wiederherstellung über diese Links ist abhängig von den Berechtigungen, da das Dereferenzieren von `/proc/<pid>/fd` den ptrace-Zugriffskontrollen und Dateiberechtigungen unterliegt.<sup>[[6]](#references)</sup>

Wenn dies erlaubt ist, zeigt `readlink` das Ziel des Deskriptors an, und `cp` kopiert dessen Inhalt.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
This is a practical technique for recovering deleted logs, temporary secrets, dropped binaries, rotated files, or scripts removed after execution.

## ext Recovery mit debugfs

Auf ext2/ext3/ext4-Dateisystemen kann `debugfs` inode metadata untersuchen und inode contents von einem Blockgerät oder Image ausgeben; ohne `-w` öffnet es das Dateisystem read-only.<sup>[[2]](#references)</sup> Arbeite nach Möglichkeit mit einer Kopie oder einem read-only Image.

Liste Einträge auf und untersuche inodes mit `debugfs`-Anfragen für directory listings, den inode status und inode-to-path checks.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Dumpen Sie einen bekannten Inode mit dem Befehl `debugfs dump` und klassifizieren Sie die wiederhergestellte Ausgabe mit `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Dies ist keine garantierte Wiederherstellung. Sie hängt vom Zustand des Dateisystems, davon, ob Blöcke wiederverwendet wurden, und davon ab, ob die Metadaten noch vorhanden sind. Für ext3/ext4 weist das Handbuch von `debugfs` darauf hin, dass die Wiederherstellung gelöschter Inodes fehlschlagen kann, weil freigegebene Inode-Datenblöcke nicht mehr verfügbar sind.<sup>[[2]](#references)</sup> Die Technik bleibt dennoch wertvoll, da sie die Untersuchung des Zustands auf Inode-Ebene ermöglicht, ohne auf die normale Pfaddurchquerung angewiesen zu sein.

## Inode-Erschöpfung und Reihenfolge

Inode-Erschöpfung tritt auf, wenn einem Dateisystem die Dateiknoten ausgehen, obwohl weiterhin freier Speicherplatz vorhanden ist.<sup>[[8]](#references)[[17]](#references)</sup> Dies verursacht normalerweise Zuverlässigkeitsfehler, kann aber auch ungewöhnliches Verhalten während der Incident Response oder der Triage in einem Lab erklären.

Verwende `df -i`, um Inode-Informationen statt der Blocknutzung auszugeben.<sup>[[8]](#references)</sup>

Überprüfe den Inode-Druck mit `df` und einer `find`-Zählung der übergeordneten Verzeichnisse.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode-Nummern und Zeitstempel können ebenfalls dabei helfen, Aktivitäten in einfachen Laborumgebungen zu rekonstruieren.

Die folgenden `find`-Formatdirektiven machen diese Felder sichtbar.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Behandle die Reihenfolge als Hinweis, nicht als Beweis. Kopiervorgänge, Archivextraktion, der Dateisystemtyp, Wiederherstellungen und gleichzeitige Schreibvorgänge können die Zuordnungsmuster verändern.

## Defensive Notes

- Binde unbekannte Images während der Analyse schreibgeschützt ein.<sup>[[1]](#references)</sup>
- Bewahre privilegierte Scripts, Service-Units, Plugins und Hilfspfade außerhalb von Mounts auf, die von Benutzern beschrieben werden können.
- Verwende `nosuid`, `nodev` und `noexec`, wo dies betrieblich angemessen ist; diese Optionen deaktivieren die Ausführung von Set-ID-/Capability-Programmen, die Interpretation von Geräten bzw. die direkte Ausführung von Binärdateien auf dem Mount.<sup>[[1]](#references)</sup> Betrachte sie nicht als vollständige Grenze.
- Beschränke den Zugriff auf `/proc/<pid>/fd`; das Dereferenzieren dieser Links wird durch ptrace-Zugriffsprüfungen und Dateiberechtigungen kontrolliert.<sup>[[6]](#references)</sup> Beschränke, wo möglich, umfassendere Prozessmetadaten und die Inspektion über Benutzergrenzen hinweg.
- Überwache beschreibbare Mountpoints, unerwartete Hardlinks auf privilegierte Dateien sowie gelöschte, aber noch geöffnete sensible Dateien.

## References

- [1] [mount(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Dokumentation für /proc/sys/fs/ — Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
