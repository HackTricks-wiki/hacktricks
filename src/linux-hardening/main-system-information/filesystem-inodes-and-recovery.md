# Dateisysteme, Inodes und Wiederherstellung

{{#include ../../banners/hacktricks-training.md}}

Beim Missbrauch von Dateisystemen geht es oft darum, die Beziehung zwischen einem sichtbaren Pfad und dem dahinterliegenden Objekt zu verwirren. Disk Images können ein weiteres Dateisystem verbergen, beschreibbare Mounts können von privilegierten Jobs verwendet werden, Hardlinks können denselben Inode unter einem anderen Namen zugänglich machen, und gelöschte Dateien können über einen offenen File Descriptor weiterhin gelesen werden.

Diese Seite konzentriert sich auf die Technik und nicht auf ein bestimmtes Lab oder Target.

## Disk Images und Loop-Mounts

Eine reguläre Datei kann ein vollständiges Dateisystem enthalten. Backup-Images, kopierte Blockgeräte, VM-Artefakte oder umbenannte Blobs können daher Credentials, Skripte, SSH-Keys, Konfigurationsdateien oder Flags enthalten, selbst wenn sie von außen nicht nützlich aussehen.

Identifiziere wahrscheinliche Images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Wenn das Mounten erlaubt ist, unbekannte Images zunächst schreibgeschützt mounten:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Wenn das Einhängen nicht verfügbar ist, untersuche die Dateisystem-Metadaten direkt:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Die Technik ist nützlich, weil sie eine normal aussehende Datei in einen zweiten filesystem tree verwandelt. Betrachte sie als Möglichkeit, verborgene Daten wiederherzustellen, nicht als eigenständige privilege escalation.

## Writable Mount Abuse

Ein writable mount wird gefährlich, wenn ein privilegierterer Kontext später etwas darin vertraut. Die wichtige Frage lautet nicht nur: „Kann ich hier schreiben?“, sondern auch: „Wer liest, führt aus, importiert oder lädt später von hier?“

Finde writable mounts und verdächtige consumers:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Häufige Missbrauchsmuster:

- Ein privilegierter cron- oder systemd-Dienst führt ein beschreibbares Skript aus dem mount aus.
- Ein privilegierter Dienst lädt Plugins, Konfigurationen, Templates oder Hilfsprogramme aus dem mount.
- Ein mount enthält SUID-Dateien und erlaubt deren Änderung, Ersetzung oder Pf manipulateion.
- Ein Container oder chroot stellt einen hostbasierten Pfad bereit, der aus der eingeschränkten Umgebung beschreibbar ist.

Generisches Validierungsmuster:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Wenn du die Auswirkungen in einem autorisierten Labor nachweist, halte den payload beobachtbar und minimal, zum Beispiel indem du die Ausgabe von `id` in eine temporäre Datei schreibst. Die Kerntechnik ist die verzögerte Ausführung über einen vertrauenswürdigen beschreibbaren Ort.

## Inodes und Pfadverwechslung

Ein Inode ist das Dateisystemobjekt; ein Pfad ist lediglich ein Name, der auf dieses Objekt verweist. Das ist wichtig, weil zwei verschiedene Pfade auf denselben Inode verweisen können und ein gelöschter Pfadname nicht immer bedeutet, dass die Daten verschwunden sind.

Vergleiche Dateien anhand von Inode und Gerät:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Finde jeden sichtbaren Pfadnamen für denselben Inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Direkt anhand der Inode-Nummer suchen, wenn nur Metadaten vorhanden sind:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Diese Technik ist nützlich, wenn eine Datei unter einem unerwarteten Namen erscheint, wenn eine Anwendung einen Pfad validiert, aber einen anderen verwendet, oder wenn ein privilegierter Wrapper mit einem inode interagiert, der auch an anderer Stelle erreichbar ist.

## Hardlink Abuse

Hardlinks erstellen mehrere Namen für denselben inode. Sie zeigen nicht wie Symlinks auf einen Zielpfad; sie sind gleichwertige Namen für dasselbe Dateiobjekt.

Finde SUID-Dateien mit mehreren Hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Eine verdächtige Datei untersuchen:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Warum das wichtig ist:

- Eine sensible Datei kann über einen weniger offensichtlichen Pfad erreichbar sein.
- Ein SUID-Wrapper kann sich hinter einem Namen verbergen, der nicht privilegiert wirkt.
- Eine Bereinigung, die einen Pfadnamen entfernt, kann einen anderen aktiven Hardlink zurücklassen.

Moderne Kernel und Mount-Optionen können die Erstellung von Hardlinks einschränken, um diese Art des Missbrauchs zu reduzieren. Bereits vorhandene Hardlinks sind dennoch eine Überprüfung wert.

## Wiederherstellung gelöschter Dateien über offene FDs

Wenn ein Prozess eine Datei geöffnet hält, können die Dateidaten weiterhin verfügbar sein, selbst nachdem der Pfadname gelöscht wurde. Linux stellt diese offenen Deskriptoren unter `/proc/<pid>/fd/` bereit.

Gelöschte, geöffnete Dateien finden:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Daten wiederherstellen, wenn die Berechtigungen dies erlauben:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Dies ist eine praktische Technik zur Wiederherstellung gelöschter Logs, temporärer Secrets, abgelegter Binaries, rotierter Dateien oder nach der Ausführung entfernter Scripts.

## ext-Wiederherstellung mit debugfs

Auf ext-Dateisystemen kann `debugfs` die Inode-Metadaten untersuchen und manchmal Dateiinhalte aus einem Dateisystem-Image ausgeben. Arbeiten Sie nach Möglichkeit mit einer Kopie oder einem schreibgeschützten Image.

Einträge auflisten und Inodes untersuchen:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Einen bekannten Inode auslesen:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Dies ist keine garantierte Wiederherstellung. Sie hängt vom Zustand des Dateisystems, davon, ob Blöcke wiederverwendet wurden, und davon ab, ob die Metadaten noch vorhanden sind. Die Technik ist dennoch wertvoll, da sie die Untersuchung des Inode-Level-Zustands ermöglicht, ohne auf normale path traversal angewiesen zu sein.

## Inode-Erschöpfung und -Reihenfolge

Eine Inode-Erschöpfung tritt auf, wenn einem Dateisystem die Dateiobjekte ausgehen, obwohl weiterhin freier Speicherplatz vorhanden ist. Dies führt normalerweise zu Zuverlässigkeitsproblemen, kann aber auch ungewöhnliches Verhalten während der Incident Response oder der Analyse in einer Laborumgebung erklären.

Inode-Auslastung prüfen:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode-Nummern und Zeitstempel können ebenfalls dabei helfen, Aktivitäten in einfachen Laborumgebungen zu rekonstruieren:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Behandle die Reihenfolge als Hinweis, nicht als Beweis. Kopiervorgänge, das Entpacken von Archiven, der Dateisystemtyp, Wiederherstellungen und gleichzeitige Schreibvorgänge können die Belegungsmuster verändern.

## Hinweise zur Abwehr

- Binde unbekannte Images während der Analyse schreibgeschützt ein.
- Halte privilegierte Skripte, Service-Units, Plugins und Helper-Pfade außerhalb von Mounts, die für Benutzer beschreibbar sind.
- Verwende `nosuid`, `nodev` und `noexec`, sofern dies betrieblich angemessen ist, betrachte sie jedoch nicht als vollständige Grenze.
- Beschränke nach Möglichkeit den Zugriff auf `/proc/<pid>/fd`, Prozessmetadaten und die prozessübergreifende Inspektion von Prozessen anderer Benutzer.
- Überwache beschreibbare Mountpoints, unerwartete Hardlinks auf privilegierte Dateien sowie gelöschte, aber noch geöffnete sensible Dateien.
{{#include ../../banners/hacktricks-training.md}}
