# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontext

Unter Linux muss ein Programm, um ausgeführt werden zu können, als Datei existieren und auf irgendeine Weise über die Dateisystemhierarchie erreichbar sein (so funktioniert `execve()` einfach). Diese Datei kann auf der Festplatte oder im Arbeitsspeicher liegen (tmpfs, memfd), aber du benötigst einen Dateipfad. Dadurch lässt sich sehr einfach kontrollieren, was auf einem Linux-System ausgeführt wird. Außerdem können Bedrohungen und die Tools von Angreifern leicht erkannt oder daran gehindert werden, überhaupt etwas auszuführen (_z. B._ indem nicht privilegierten Benutzern untersagt wird, ausführbare Dateien irgendwo abzulegen).

Doch diese Technik soll all das ändern. Wenn du den gewünschten Prozess nicht starten kannst ... **dann hijackst du einen bereits vorhandenen**.

Diese Technik ermöglicht es dir, **gängige Schutzmechanismen wie read-only, noexec, Dateinamen-Whitelisting, Hash-Whitelisting ... zu umgehen.**

## Abhängigkeiten

Das endgültige Script hängt von den folgenden Tools ab, um zu funktionieren. Sie müssen auf dem System, das du angreifst, zugänglich sein (standardmäßig findest du sie überall):
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

Wenn du den Speicher eines Prozesses beliebig verändern kannst, kannst du ihn übernehmen. Dies kann verwendet werden, um einen bereits existierenden Prozess zu hijacken und durch ein anderes Programm zu ersetzen. Dies ist entweder mithilfe des `ptrace()`-Syscalls möglich (dafür musst du Syscalls ausführen können oder `gdb` muss auf dem System verfügbar sein) oder, noch interessanter, durch Schreiben nach `/proc/$pid/mem`.

Die Datei `/proc/$pid/mem` ist eine 1:1-Abbildung des gesamten Adressraums eines Prozesses (_z. B._ von `0x0000000000000000` bis `0x7ffffffffffff000` auf x86-64). Das bedeutet, dass das Lesen aus oder Schreiben in diese Datei am Offset `x` dem Lesen oder Ändern des Inhalts an der virtuellen Adresse `x` entspricht.

Nun müssen wir uns mit vier grundlegenden Problemen befassen:

- Im Allgemeinen dürfen nur root und der Besitzer der Datei diese ändern.
- ASLR.
- Wenn wir versuchen, eine Adresse zu lesen oder zu schreiben, die nicht im Adressraum des Programms abgebildet ist, erhalten wir einen I/O-Fehler.

Für diese Probleme gibt es Lösungen, die zwar nicht perfekt, aber ausreichend sind:

- Die meisten Shell-Interpreter erlauben die Erstellung von File Descriptors, die anschließend von Child-Prozessen geerbt werden. Wir können einen fd erstellen, der mit Schreibberechtigungen auf die `mem`-Datei der Shell zeigt ... dadurch können Child-Prozesse, die diesen fd verwenden, den Speicher der Shell verändern.
- ASLR ist nicht einmal ein Problem. Wir können die `maps`-Datei der Shell oder eine andere Datei aus dem procfs überprüfen, um Informationen über den Adressraum des Prozesses zu erhalten.
- Daher müssen wir `lseek()` für die Datei verwenden. Von der Shell aus ist dies nur mithilfe des berüchtigten `dd` möglich.

### Im Detail

Die Schritte sind relativ einfach und erfordern keinerlei besondere Expertise, um sie zu verstehen:

- Analysiere das Binary, das wir ausführen möchten, sowie den Loader, um herauszufinden, welche Mappings sie benötigen. Erstelle anschließend einen "shell"code, der grob gesagt dieselben Schritte ausführt, die der Kernel bei jedem Aufruf von `execve()` durchführt:
- Erstelle die genannten Mappings.
- Lies die Binaries in diese Mappings ein.
- Setze die Berechtigungen.
- Initialisiere schließlich den Stack mit den Argumenten für das Programm und platziere den Auxiliary Vector (der vom Loader benötigt wird).
- Springe in den Loader und überlasse ihm den Rest (das Laden der vom Programm benötigten Libraries).
- Ermittle aus der `syscall`-Datei die Adresse, zu der der Prozess nach dem Syscall zurückkehren wird, den er gerade ausführt.
- Überschreibe diese Stelle, die ausführbar sein wird, mit unserem shellcode (über `mem` können wir nicht beschreibbare Pages ändern).
- Übergib das Programm, das wir ausführen möchten, an stdin des Prozesses (wird von diesem "shell"code mittels `read()` gelesen).
- Ab diesem Punkt ist es Aufgabe des Loaders, die notwendigen Libraries für unser Programm zu laden und in dieses zu springen.

**Siehe dir das Tool unter** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec) **an.**

## EverythingExec

Es gibt mehrere Alternativen zu `dd`, darunter `tail`, das derzeit standardmäßig verwendete Programm, um mittels `lseek()` durch die `mem`-Datei zu navigieren (was der einzige Zweck der Verwendung von `dd` war). Diese Alternativen sind:
```bash
tail
hexdump
cmp
xxd
```
Durch Setzen der Variable `SEEKER` können Sie den verwendeten seeker ändern, _z. B._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Wenn du einen anderen gültigen, im Script nicht implementierten Seeker findest, kannst du ihn dennoch verwenden, indem du die Variable `SEEKER_ARGS` setzt:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blockiert dies, EDRs.

## Referenzen

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
