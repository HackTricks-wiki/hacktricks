# Dateisysteme, Inodes und Wiederherstellung

{{#include ../../banners/hacktricks-training.md}}

Beim Missbrauch von Dateisystemen geht es häufig darum, die Beziehung zwischen einem sichtbaren Pfad und dem dahinterliegenden Objekt zu verwirren. Disk-Images können ein anderes Dateisystem verbergen, beschreibbare Mounts können von privilegierten Jobs verwendet werden, Hardlinks können über einen anderen Namen Zugriff auf dasselbe Inode ermöglichen, und gelöschte Dateien können über einen noch geöffneten File Descriptor weiterhin gelesen werden.

Diese Seite konzentriert sich auf die Technik und nicht auf ein bestimmtes Lab oder Target.

## Disk-Images und Loop-Mounts

Eine reguläre Datei kann ein vollständiges Dateisystem enthalten. Backup-Images, kopierte Blockgeräte, VM-Artefakte oder umbenannte Blobs können daher Credentials, Scripts, SSH-Keys, Konfigurationsdateien oder Flags enthalten, selbst wenn sie von außen nicht nützlich aussehen.

Identifiziere wahrscheinliche Images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Wenn das Einhängen erlaubt ist, unbekannte Images zuerst schreibgeschützt einhängen:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Wenn das Einhängen nicht verfügbar ist, untersuchen Sie die Dateisystem-Metadaten direkt:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Die Technik ist nützlich, weil sie eine normal aussehende Datei in einen zweiten Dateisystembaum verwandelt. Betrachte sie als Möglichkeit, versteckte Daten wiederherzustellen, nicht als eigenständige Privilege Escalation.

## Missbrauch beschreibbarer Mounts

Ein beschreibbarer Mount wird gefährlich, wenn ein privilegierterer Kontext später etwas darin vertraut. Die wichtige Frage ist nicht nur „kann ich hier schreiben?“, sondern auch „wer liest, führt aus, importiert oder lädt später von hier?“.

Finde beschreibbare Mounts und verdächtige Nutzer:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Häufige Missbrauchsmuster:

- Ein privilegierter cron- oder systemd-Dienst führt ein beschreibbares Script aus dem mount aus.
- Ein privilegierter Dienst lädt Plugins, Konfigurationen, Templates oder Hilfs-Binaries aus dem mount.
- Ein mount enthält SUID-Dateien und ermöglicht deren Änderung, Ersetzung oder Pfadmanipulation.
- Ein Container oder chroot stellt einen hostbasierten Pfad bereit, der aus der eingeschränkten Umgebung beschreibbar ist.

Allgemeines Validierungsmuster:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Wenn du die Auswirkungen in einem autorisierten Lab nachweist, halte die Payload beobachtbar und minimal, indem du beispielsweise die Ausgabe von `id` in eine temporäre Datei schreibst. Die Kerntechnik besteht in der verzögerten Ausführung über einen vertrauenswürdigen, beschreibbaren Speicherort.

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
Suchen Sie direkt anhand der Inode-Nummer, wenn Sie nur Metadaten haben:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Diese Technik ist nützlich, wenn eine Datei unter einem unerwarteten Namen erscheint, wenn eine Anwendung einen Pfad validiert, aber einen anderen verwendet oder wenn ein privilegierter Wrapper mit einem inode interagiert, der auch an anderer Stelle erreichbar ist.

## Hardlink Abuse

Hardlinks erstellen mehrere Namen für denselben inode. Sie verweisen nicht wie Symlinks auf einen Zielpfad, sondern sind gleichwertige Namen für dasselbe Dateiobjekt.

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

- Eine sensitive Datei kann über einen weniger offensichtlichen Pfad erreichbar sein.
- Ein SUID wrapper kann sich hinter einem Namen verbergen, der nicht privilegiert wirkt.
- Ein Cleanup, das einen einzelnen Pfadnamen entfernt, kann einen anderen aktiven hardlink hinterlassen.

Moderne Kernel und Mount-Optionen können die Erstellung von hardlinks einschränken, um diese Art des Missbrauchs zu reduzieren. Bereits vorhandene hardlinks sollten jedoch weiterhin überprüft werden.

## Wiederherstellung gelöschter Dateien über offene FDs

Wenn ein Prozess eine Datei geöffnet hält, können die Dateidaten weiterhin verfügbar sein, auch nachdem der Pfadname gelöscht wurde. Linux stellt diese offenen Deskriptoren unter `/proc/<pid>/fd/` bereit.

Gelöschte offene Dateien finden:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Stellen Sie die Daten wieder her, wenn die Berechtigungen dies zulassen:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Dies ist eine praktische Technik zur Wiederherstellung gelöschter Logs, temporärer Secrets, abgelegter Binaries, rotierter Dateien oder nach der Ausführung entfernter Scripts.

## ext-Wiederherstellung mit debugfs

Auf ext-Dateisystemen kann `debugfs` die Inode-Metadaten untersuchen und manchmal Dateiinhalte aus einem Dateisystem-Image ausgeben. Arbeite nach Möglichkeit mit einer Kopie oder einem schreibgeschützten Image.

Einträge auflisten und Inodes untersuchen:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Einen bekannten Inode ausgeben:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Dies ist keine garantierte Wiederherstellung. Sie hängt vom Zustand des Dateisystems, davon, ob Blöcke wiederverwendet wurden, und davon ab, ob die Metadaten noch vorhanden sind. Die Technik ist dennoch wertvoll, da sie die Untersuchung des Zustands auf Inode-Ebene ermöglicht, ohne auf normales path traversal angewiesen zu sein.

## Inode-Erschöpfung und -Reihenfolge

Eine Inode-Erschöpfung tritt auf, wenn einem Dateisystem die Dateiobjekte ausgehen, obwohl noch freier Speicherplatz vorhanden ist. Dies verursacht normalerweise Zuverlässigkeitsprobleme, kann aber auch ungewöhnliches Verhalten während der Incident Response oder der Triage in einer Laborumgebung erklären.

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
Behandle die Reihenfolge als Hinweis, nicht als Beweis. Kopiervorgänge, das Entpacken von Archiven, der Dateisystemtyp, Wiederherstellungen und gleichzeitige Schreibvorgänge können die Zuordnungsmuster verändern.

## Hinweise zur Abwehr

- Binde unbekannte Images während der Analyse schreibgeschützt ein.
- Halte privilegierte Skripte, Service-Units, Plugins und Hilfspfad außerhalb von Mounts, die von Benutzern beschreibbar sind.
- Verwende `nosuid`, `nodev` und `noexec`, sofern betrieblich angemessen, betrachte sie jedoch nicht als vollständige Sicherheitsgrenze.
- Beschränke nach Möglichkeit den Zugriff auf `/proc/<pid>/fd`, Prozessmetadaten und die Untersuchung von Prozessen anderer Benutzer.
- Überwache beschreibbare Mount-Punkte, unerwartete Hardlinks zu privilegierten Dateien sowie gelöschte, aber noch geöffnete sensible Dateien.
