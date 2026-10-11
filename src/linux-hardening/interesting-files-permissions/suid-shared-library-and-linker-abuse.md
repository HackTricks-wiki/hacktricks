# SUID Shared Library- und Linker-Missbrauch

{{#include ../../banners/hacktricks-training.md}}

SUID-Binärdateien werden normalerweise auf direkte Befehlsausführung überprüft, doch benutzerdefinierte SUID-Programme können auch über den dynamischen Linker verwundbar sein. Das gemeinsame Muster ist einfach: Eine privilegierte ausführbare Datei lädt Code aus einem Pfad oder einer Konfiguration, die ein Benutzer mit geringeren Rechten beeinflussen kann.<sup>[[1]](#references)</sup>

Diese Seite konzentriert sich auf generische Techniken: fehlende Bibliotheken, beschreibbare Bibliotheksverzeichnisse, `RPATH`/`RUNPATH`, `LD_PRELOAD` über sudo, Linker-Konfiguration und Verwechslungen mit SUID-Hardlinks.

Informationen zu den ELF-Programmköpfen, dem dynamischen Abschnitt und dem Loader-Verhalten, auf denen diese Prüfungen beruhen, findest du unter [ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Schnelle Enumeration

Suche zunächst nach ungewöhnlichen SUID-Dateien und prüfe, ob sie dynamisch gelinkt sind:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Verwende `readelf` für unbekannte ausführbare Dateien: [`ldd` führt möglicherweise einen nicht vertrauenswürdigen ELF-Interpreter aus](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` zeigt direkte Abhängigkeiten an. Prüfe daher separat, welchen Pfad der Loader tatsächlich auswählt.<sup>[[1]](#references)[[3]](#references)</sup>

Achte auf nicht standardmäßige Speicherorte, benutzerdefinierte Anwendungspfade, root gehörende Binärdateien außerhalb paketverwalteter Verzeichnisse und Abhängigkeiten, die aus beschreibbaren Verzeichnissen geladen werden.<sup>[[1]](#references)</sup>

Nützliche Prüfungen der Schreibrechte:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Manche benutzerdefinierten SUID-Binaries versuchen, ein Shared Object zu laden, das nicht existiert. Liegt der fehlende Pfad unter einem vom Angreifer kontrollierten Verzeichnis, lädt das Binary möglicherweise vom Angreifer bereitgestellten Code mit den Rechten des effektiven Benutzers.<sup>[[1]](#references)</sup>

Dieselbe Grenze gilt für ein **benutzerdefiniertes Binary, das über sudo ausgeführt werden darf**, wenn es `dlopen()` mit einem absoluten `.so`-Pfad unter einem vom Aufrufer beschreibbaren Home- oder Konfigurationsverzeichnis aufruft. Dieser späte Bibliotheksladevorgang taucht möglicherweise weder in `ldd` noch in den ELF-`NEEDED`-Einträgen auf. Eine begrenzte Prüfung mit `strings` oder das Nachverfolgen eines **unprivilegierten** Aufrufs kann den versuchten Pfad offenlegen; ein Anwendungspasswort oder eine Menüauswahl kann die Abfrage auslösen. Prüfe die effektive sudo-Regel, den genauen Pfad, die Berechtigungen des übergeordneten Verzeichnisses und ob der privilegierte Aufruf diese Abfrage erreicht, bevor du dies als Privilegienausweitung einstufst. Rufe das sudo-Ziel nicht allein zu dessen Auflistung auf.

Finde fehlgeschlagene Bibliothekssuchen mit dem Syscall-Filter von `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Wenn die Binärdatei in einem beschreibbaren Pfad nach libexample.so sucht, kann eine minimale Proof-Bibliothek einen Konstruktor verwenden. Halte den Proof-of-Impact während der Validierung harmlos:<sup>[[6]](#references)</sup>

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

Erstelle es unter exakt dem Dateinamen, den die Binärdatei zu laden versucht:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Die ausnutzbare Bedingung ist nicht allein die fehlende Bibliothek. Der Angreifer muss ein kompatibles shared object an einem Pfad ablegen können, den der privilegierte Loader akzeptiert.<sup>[[1]](#references)</sup>

## Schreibbares Bibliotheksverzeichnis

Manchmal sind alle Abhängigkeiten vorhanden, aber eines der Verzeichnisse, die zu ihrer Auflösung verwendet werden, ist beschreibbar. Dadurch kann eine geladene Bibliothek ersetzt oder eine Bibliothek gleichen Namens mit höherer Priorität platziert werden.<sup>[[1]](#references)</sup>

Dieselbe Prüfung gilt für ein benutzerdefiniertes ELF, das **über sudo zugelassen** ist, selbst wenn das ELF kein SUID-Bit hat und das erlaubte RunAs-Konto nicht root ist. Vergleiche die `DT_NEEDED`-Einträge mit dem Bibliothekspfad, den der Loader auflösen wird; prüfe dann, ob der aufrufende Benutzer diese Datei beschreiben oder über ein beschreibbares, durchsuchbares übergeordnetes Verzeichnis ersetzen kann. Bestätige die genaue sudo-RunAs-Regel, Symlinks und ACLs, die Loader-Richtlinie sowie, dass der Zielprozess die Bibliothek mit dem privilegierteren Konto lädt. Eine beschreibbare `.so` oder ein Abhängigkeitsname allein ist nur ein Hinweis; prüfe Metadaten, ohne den sudo-Befehl auszuführen.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Prüfe die Abhängigkeitspfade:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Wenn das Verzeichnis beschreibbar ist, überprüfe dies in einer Lab-Umgebung mit einem Ansatz, der die Originaldatei schützt. Das Ersetzen von Systembibliotheken auf einem Live-Host kann dazu führen, dass gleichzeitig startende Prozesse inkonsistente Bibliotheksversionen verwenden.<sup>[[8]](#references)</sup>

### Beschreibbare Bibliotheken innerhalb eines chroot

Ein chroot allein schließt keine geerbten Dateideskriptoren und schränkt nicht den gesamten Dateisystemzugriff ein. Wenn eine Sandbox einen Verzeichnisdeskriptor außerhalb ihrer neuen Root-Umgebung bestehen lässt und der eingesperrte Prozess diesen Deskriptor dereferenzieren kann (zum Beispiel über einen zugänglichen `/proc/<pid>/fd/`-Eintrag), können Host-Pfade weiterhin erreichbar sein. Dies ist ein Problem mit der Dateisystemgrenze; es verleiht für sich genommen keine Root-Rechte.<sup>[[11]](#references)[[12]](#references)</sup>

Prüfe separat, ob der eingesperrte Benutzer ein Bibliotheksverzeichnis beschreiben kann, das ein **Host-Root-SUID-Executable** beim Start aus dem Jail verwendet. Der Loader löst Abhängigkeiten in der Dateisystemansicht des Prozesses auf, sodass eine vom Angreifer kontrollierte Bibliothek dort mit der effektiven Identität des SUID-Programms ausgeführt werden kann. Bestätige das genaue Executable, sein SUID-Bit und die Mount-Richtlinie, das Ziel und die Zugriffsberechtigungen des Deskriptors, den Bibliothekssuchpfad des Jails und ob das Programm das Host-Executable tatsächlich erreichen kann. Eine Dateifähigkeit für den Sandbox-Launcher, ein beschreibbares Jail oder ein Host-SUID-Binary allein ist lediglich ein Hinweis; die vollständige Angriffskette hängt von der Implementierung der Sandbox ab.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH und RUNPATH

`RPATH` und `RUNPATH` sind Einträge im dynamischen Abschnitt, die dem Loader mitteilen, wo er nach Bibliotheken suchen soll. In SUID-Programmen sind sie gefährlich, wenn sie auf vom Angreifer beschreibbare Verzeichnisse verweisen.<sup>[[1]](#references)</sup>

Erkennen:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Beispiel für riskante Ausgabe:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Wenn `/opt/app/lib` beschreibbar ist und die Binärdatei `libcustom.so` benötigt, kann der Angreifer dort möglicherweise eine schädliche `libcustom.so` platzieren:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` und `RUNPATH` sind nicht in allen Details der Auflösung identisch, aber bei der Prüfung auf Privilegieneskalation stellt sich praktisch dieselbe Frage: Durchsucht das SUID-Binary ein vom Angreifer beschreibbares Verzeichnis nach einem Bibliotheksnamen?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH und SUID

Bei normalen Programmen können `LD_PRELOAD` und `LD_LIBRARY_PATH` das Laden von Shared Objects erzwingen oder beeinflussen. Bei SUID-Programmen wechselt der dynamische Loader normalerweise in den Secure-Execution-Modus und ignoriert gefährliche Umgebungsvariablen.<sup>[[1]](#references)</sup>

Das bedeutet, dass ein einfaches SUID-Binary normalerweise nicht allein deshalb verwundbar ist, weil der Benutzer `LD_PRELOAD` setzen kann:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Die häufige Ausnahme ist eine sudo-Richtlinie, die eine Zuweisung von Umgebungsvariablen über die Befehlszeile für das Ziel erlaubt, etwa ein `SETENV`-Tag oder eine entsprechende `setenv`-Option. Ist das Ziel dynamisch gelinkt und akzeptiert sudo `LD_PRELOAD=/path/to/library`, kann das Ziel vom Aufrufer kontrollierten Code laden. Prüfe die effektive Regel und die Identität des Ziels. `LD_PRELOAD` lediglich zu `env_keep` hinzuzufügen, reicht auf Systemen nicht aus, auf denen der dynamische Loader ein geerbtes `LD_PRELOAD` entfernt, bevor der SUID-`sudo`-Prozess startet; eine Zuweisung über die Befehlszeile wird von sudo erst nach dem eigenen Start ausgewertet.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Verwechseln Sie diese Fälle nicht; die Regeln für Loader und sudo unterscheiden sie:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` gegen ein normales SUID-Binary: wird bei sicherer Ausführung normalerweise blockiert.
- `LD_PRELOAD` als sudo-Befehlszeilen-Zuweisung für ein privilegiertes, dynamisch gelinktes Ziel akzeptiert: potenziell ausnutzbar.
- Fehlende `.so` in einem beschreibbaren Pfad: ausnutzbar, wenn das SUID-Binary diesen Pfad auf natürliche Weise lädt.
- `RPATH`/`RUNPATH` auf ein beschreibbares Verzeichnis: ausnutzbar, wenn sich eine benötigte Bibliothek kontrollieren lässt.
- Schreibzugriff auf `/etc/ld.so.preload` oder die Linker-Konfiguration: systemweit und mit hoher Auswirkung.

## Linker Configuration

`ld.so` verwendet den Linker-Cache und `/etc/ld.so.preload`; `ldconfig` erstellt diesen Cache aus `/etc/ld.so.conf` und den dort eingebundenen Dateien, üblicherweise aus `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Wichtige Prüfungen:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Schreibbare Linker-Konfigurationen sind meist schwerwiegender als eine einzelne anfällige SUID-Binärdatei, da sie viele dynamisch gelinkte Prozesse betreffen können. `/etc/ld.so.preload` ist besonders gefährlich, weil es ein Shared Object in privilegierte Prozesse laden kann.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID-Hardlink-Verwechslung

Hardlinks können dafür sorgen, dass derselbe SUID-Inode unter mehreren Namen erscheint.<sup>[[9]](#references)</sup> Das ist nützlich, um einen privilegierten Helper zu verbergen, die Bereinigung zu erschweren oder eine naive pfadbasierte Überprüfung zu umgehen.

SUID-Dateien mit mehr als einem Link finden:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Untersuche alle Pfade zur gleichen Inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Der Missbrauch besteht nicht darin, dass ein Hardlink Berechtigungen ändert. Es geht um Pfadverwechslung: Ein privilegierter Inode kann über einen Namen erreichbar sein, den Verteidiger oder Skripte nicht erwarten.<sup>[[9]](#references)</sup> Eine ausführlichere Erklärung zu Inodes und Hardlink-Workflows findest du unter [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- SUID-Binaries möglichst minimal halten, regelmäßig prüfen und nach Möglichkeit paketverwaltet installieren.
- `RPATH`-/`RUNPATH`-Einträge vermeiden, die auf beschreibbare oder anwendungsverwaltete Verzeichnisse verweisen.<sup>[[1]](#references)[[8]](#references)</sup>
- Bibliotheksverzeichnisse im Besitz von root halten und für reguläre Benutzer nicht beschreibbar machen.<sup>[[8]](#references)</sup>
- `LD_PRELOAD`, `LD_LIBRARY_PATH` oder ähnliche Loader-Variablen nicht über sudo hinweg beibehalten.<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` und unerwartete SUID-Dateien überwachen.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- SUID-Dateien mit Hardlinks prüfen und benutzerdefinierte SUID-Wrapper außerhalb der standardmäßigen Systempfade untersuchen.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux-Handbuchseite](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Allgemeine Attribute (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Härtung des dynamischen Linkers (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hardlinks (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
