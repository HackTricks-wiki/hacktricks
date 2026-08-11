# DDexec / EverythingExec

## Kontext

Unter Linux muss ein Programm, um ausgeführt werden zu können, als Datei existieren und auf irgendeine Weise über die Dateisystemhierarchie erreichbar sein (so funktioniert `execve()` nun einmal). Diese Datei kann auf der Festplatte oder im Arbeitsspeicher liegen (tmpfs, memfd), aber du benötigst einen Dateipfad. Dadurch lässt sich sehr leicht kontrollieren, was auf einem Linux-System ausgeführt wird. Außerdem können Bedrohungen und die Tools eines Angreifers leicht erkannt oder sie vollständig daran gehindert werden, überhaupt etwas auszuführen (_z. B._ indem nicht privilegierten Benutzern untersagt wird, ausführbare Dateien irgendwo abzulegen).

Diese Technik ist jedoch dazu gedacht, all das zu ändern. Wenn du den gewünschten Prozess nicht starten kannst ... **dann übernimmst du einfach einen bereits vorhandenen**.

Diese Technik ermöglicht es dir, **gängige Schutzmechanismen wie read-only, noexec, File-Name-Whitelisting und Hash-Whitelisting zu umgehen**.<sup>[[1]](#references)</sup>

## Abhängigkeiten

Das endgültige Skript benötigt die folgenden Tools, um zu funktionieren. Sie müssen auf dem von dir angegriffenen System zugänglich sein (standardmäßig findest du sie überall):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## Die Technik

Wenn du den Speicher eines Prozesses beliebig verändern kannst, kannst du ihn übernehmen. Dies kann verwendet werden, um einen bereits vorhandenen Prozess zu hijacken und durch ein anderes Programm zu ersetzen. Dies lässt sich entweder über den `ptrace()`-Syscall erreichen (dazu musst du Syscalls ausführen können oder `gdb` muss auf dem System verfügbar sein) oder, noch interessanter, durch Schreiben in `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Die Datei `/proc/$pid/mem` ist eine 1:1-Abbildung des gesamten Adressraums eines Prozesses (_z. B._ von `0x0000000000000000` bis `0x7ffffffffffff000` in x86-64). Das bedeutet, dass das Lesen aus oder Schreiben in diese Datei am Offset `x` dem Lesen oder Ändern des Inhalts an der virtuellen Adresse `x` entspricht.

Nun müssen wir uns mit vier grundlegenden Problemen befassen:

- Im Allgemeinen dürfen nur root und der Besitzer des Programms die Datei verändern.
- ASLR.
- Wenn wir versuchen, von einer Adresse zu lesen oder in eine Adresse zu schreiben, die nicht im Adressraum des Programms abgebildet ist, erhalten wir einen I/O-Fehler.

Für diese Probleme gibt es Lösungen, die zwar nicht perfekt, aber gut sind:

- Die meisten Shell-Interpreter erlauben die Erstellung von Dateideskriptoren, die anschließend von Child-Prozessen geerbt werden. Wir können einen fd erstellen, der mit Schreibberechtigungen auf die `mem`-Datei der Shell zeigt ... dadurch können Child-Prozesse, die diesen fd verwenden, den Speicher der Shell verändern.
- ASLR ist überhaupt kein Problem. Wir können die `maps`-Datei der Shell oder eine andere Datei aus dem procfs überprüfen, um Informationen über den Adressraum des Prozesses zu erhalten.
- Daher müssen wir `lseek()` für die Datei verwenden. Aus der Shell ist dies nicht möglich, außer man verwendet das berüchtigte `dd`.

### Im Detail

Die Schritte sind relativ einfach und erfordern keinerlei besondere Kenntnisse, um sie zu verstehen:<sup>[[1]](#references)</sup>

- Analysiere die Binary, die wir ausführen wollen, sowie den Loader, um herauszufinden, welche Mappings sie benötigen. Erstelle anschließend einen „Shell“code, der grob gesagt dieselben Schritte ausführt wie der Kernel bei jedem Aufruf von `execve()`:
- Erstelle die genannten Mappings.
- Lies die Binaries in diese Mappings ein.
- Richte die Berechtigungen ein.
- Initialisiere schließlich den Stack mit den Argumenten für das Programm und platziere den Auxiliary Vector (der vom Loader benötigt wird).
- Springe in den Loader und überlasse ihm den Rest (das Laden der vom Programm benötigten Libraries).
- Ermittle aus der `syscall`-Datei die Adresse, an die der Prozess nach dem Syscall zurückkehren wird, den er gerade ausführt.
- Überschreibe diese Stelle, die ausführbar sein wird, mit unserem Shellcode (über `mem` können wir nicht beschreibbare Pages ändern).
- Übergib das Programm, das wir ausführen wollen, an stdin des Prozesses (wird von diesem „Shell“code `read()`).
- An diesem Punkt ist es Aufgabe des Loaders, die notwendigen Libraries für unser Programm zu laden und in dieses zu springen.

**Siehe dir das Tool unter** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec) **an.**<sup>[[1]](#references)</sup>

## EverythingExec

Es gibt mehrere Alternativen zu `dd`, darunter `tail`, das derzeit standardmäßig verwendet wird, um mittels `lseek()` durch die `mem`-Datei zu navigieren (dies war der einzige Zweck der Verwendung von `dd`). Diese Alternativen sind:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Durch Setzen der Variable `SEEKER` können Sie den verwendeten Seeker ändern, _z. B._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Wenn du einen weiteren gültigen Seeker findest, der im Script nicht implementiert ist, kannst du ihn dennoch verwenden, indem du die Variable `SEEKER_ARGS` setzt:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blockiert das, EDRs.

## References

- [1] [DDexec: Eine Technik, um Binaries dateilos und unauffällig unter Linux auszuführen](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
