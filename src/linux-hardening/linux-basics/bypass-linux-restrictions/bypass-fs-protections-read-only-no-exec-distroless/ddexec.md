# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontext

Unter Linux muss ein Programm als Datei vorhanden sein, um ausgeführt werden zu können. Es muss auf irgendeine Weise über die Dateisystemhierarchie erreichbar sein (so funktioniert `execve()` nun einmal). Diese Datei kann auf der Festplatte oder im RAM liegen (tmpfs, memfd), aber du benötigst einen Dateipfad. Dadurch lässt sich sehr einfach kontrollieren, was auf einem Linux-System ausgeführt wird. Ebenso lassen sich Bedrohungen und die Tools von Angreifern leicht erkennen oder sie vollständig daran hindern, überhaupt etwas Eigenes auszuführen (_z. B._ indem nicht privilegierten Benutzern nicht erlaubt wird, irgendwo ausführbare Dateien abzulegen).

Diese Technik ist jedoch hier, um all das zu ändern. Wenn du den gewünschten Prozess nicht starten kannst ... **dann übernimmst du einen bereits vorhandenen**.

Diese Technik ermöglicht es dir, **gängige Schutztechniken wie read-only, noexec, File-Name-Whitelisting und Hash-Whitelisting zu umgehen**.<sup>[[1]](#references)</sup>

## Abhängigkeiten

Das abschließende Script hängt von den folgenden Tools ab, damit es funktioniert. Sie müssen auf dem von dir angegriffenen System erreichbar sein (standardmäßig wirst du sie überall finden):
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

Wenn du den Speicher eines Prozesses beliebig verändern kannst, kannst du ihn übernehmen. Dies kann verwendet werden, um einen bereits vorhandenen Prozess zu hijacken und durch ein anderes Programm zu ersetzen. Das lässt sich entweder durch den `ptrace()`-Syscall erreichen (dafür musst du Syscalls ausführen können oder `gdb` muss auf dem System verfügbar sein) oder, noch interessanter, durch das Schreiben in `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Die Datei `/proc/$pid/mem` ist eine Eins-zu-eins-Abbildung des gesamten Adressraums eines Prozesses (_z. B._ von `0x0000000000000000` bis `0x7ffffffffffff000` auf x86-64). Das bedeutet, dass das Lesen aus oder Schreiben in diese Datei am Offset `x` dem Lesen oder Ändern des Inhalts an der virtuellen Adresse `x` entspricht.

Nun stehen wir vor vier grundlegenden Problemen:

- Im Allgemeinen dürfen nur `root` und der Besitzer des Programms die Datei ändern.
- ASLR.
- Wenn wir versuchen, von einer Adresse zu lesen oder in eine Adresse zu schreiben, die nicht im Adressraum des Programms abgebildet ist, erhalten wir einen I/O-Fehler.

Für diese Probleme gibt es Lösungen, die zwar nicht perfekt, aber gut sind:

- Die meisten Shell-Interpreter erlauben die Erstellung von File Descriptors, die anschließend von Child-Prozessen geerbt werden. Wir können einen fd erstellen, der mit Schreibberechtigungen auf die `mem`-Datei der Shell zeigt ... dadurch können Child-Prozesse, die diesen fd verwenden, den Speicher der Shell ändern.
- ASLR ist nicht einmal ein Problem; wir können die `maps`-Datei der Shell oder eine andere Datei aus dem procfs überprüfen, um Informationen über den Adressraum des Prozesses zu erhalten.
- Daher müssen wir `lseek()` über die Datei ausführen. Von der Shell aus ist dies nur mit dem berüchtigten `dd` möglich.

### Im Detail

Die Schritte sind relativ einfach und erfordern keinerlei besondere Kenntnisse, um sie zu verstehen:<sup>[[1]](#references)</sup>

- Parse die Binärdatei, die wir ausführen möchten, und den Loader, um herauszufinden, welche Mappings sie benötigen. Erstelle anschließend einen `"shell"code`, der im Großen und Ganzen dieselben Schritte ausführt wie der Kernel bei jedem Aufruf von `execve()`:
- Erstelle die genannten Mappings.
- Lies die Binärdateien in diese Mappings ein.
- Richte die Berechtigungen ein.
- Initialisiere schließlich den Stack mit den Argumenten für das Programm und platziere den Auxiliary Vector (der vom Loader benötigt wird).
- Springe in den Loader und überlasse ihm den Rest (das Laden der vom Programm benötigten Libraries).
- Ermittle aus der `syscall`-Datei die Adresse, zu der der Prozess nach dem Syscall zurückkehren wird, den er gerade ausführt.
- Überschreibe diese Stelle, die ausführbar sein wird, mit unserem Shellcode (über `mem` können wir nicht beschreibbare Pages ändern).
- Übergebe das Programm, das wir ausführen möchten, an den stdin des Prozesses (wird von diesem `"shell"code` mittels `read()` gelesen).
- Ab diesem Punkt obliegt es dem Loader, die erforderlichen Libraries für unser Programm zu laden und in dieses zu springen.

**Siehe dir das Tool unter** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec) **an.**<sup>[[1]](#references)</sup>

## EverythingExec

Es gibt mehrere Alternativen zu `dd`, darunter `tail`, das derzeit standardmäßig zum Ausführen von `lseek()` durch die `mem`-Datei verwendet wird (dies war der einzige Grund für die Verwendung von `dd`). Diese Alternativen sind:<sup>[[1]](#references)</sup>
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
Wenn du einen weiteren gültigen Seeker findest, der noch nicht im Script implementiert ist, kannst du ihn trotzdem verwenden, indem du die Variable `SEEKER_ARGS` setzt:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blockiert dies, EDRs.

## References

- [1] [DDexec: Eine Technik, um Binärdateien dateilos und unauffällig unter Linux auszuführen](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
