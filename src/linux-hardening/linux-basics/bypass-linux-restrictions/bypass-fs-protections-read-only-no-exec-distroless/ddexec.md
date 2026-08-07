# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontext

Unter Linux muss ein Programm als Datei existieren, um ausgeführt werden zu können. Es muss auf irgendeine Weise über die Dateisystemhierarchie erreichbar sein (so funktioniert `execve()` einfach). Diese Datei kann auf der Festplatte oder im RAM liegen (tmpfs, memfd), aber du benötigst einen Dateipfad. Dadurch lässt sich sehr einfach kontrollieren, was auf einem Linux-System ausgeführt wird. Außerdem lassen sich Bedrohungen und die Tools eines Angreifers leicht erkennen oder sie können vollständig an der Ausführung eigener Dateien gehindert werden (_z. B._ indem nicht privilegierten Benutzern das Platzieren ausführbarer Dateien an beliebigen Orten verboten wird).

Doch diese Technik ist hier, um all das zu ändern. Wenn du den gewünschten Prozess nicht starten kannst ... **dann hijackst du einen bereits vorhandenen**.

Diese Technik ermöglicht es dir, **gängige Schutzmechanismen wie read-only, noexec, file-name whitelisting, hash whitelisting ... zu umgehen.**<sup>[[1]](#references)</sup>

## Abhängigkeiten

Das endgültige Script hängt von den folgenden Tools ab, um zu funktionieren. Sie müssen auf dem von dir angegriffenen System erreichbar sein (standardmäßig wirst du sie überall finden):
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

Wenn du in der Lage bist, den Speicher eines Prozesses beliebig zu verändern, kannst du ihn übernehmen. Dies kann verwendet werden, um einen bereits existierenden Prozess zu hijacken und durch ein anderes Programm zu ersetzen. Wir können dies entweder mithilfe des `ptrace()`-syscalls erreichen (was die Fähigkeit voraussetzt, syscalls auszuführen, oder dass `gdb` auf dem System verfügbar ist) oder, noch interessanter, durch das Schreiben in `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Die Datei `/proc/$pid/mem` ist eine 1:1-Abbildung des gesamten Adressraums eines Prozesses (_z. B._ von `0x0000000000000000` bis `0x7ffffffffffff000` auf x86-64). Das bedeutet, dass das Lesen aus oder Schreiben in diese Datei an einem Offset `x` dasselbe ist wie das Lesen oder Verändern des Inhalts an der virtuellen Adresse `x`.

Nun stehen wir vor vier grundlegenden Problemen:

- Im Allgemeinen dürfen nur root und der Besitzer des Programms die Datei verändern.
- ASLR.
- Wenn wir versuchen, eine Adresse zu lesen oder zu beschreiben, die nicht im Adressraum des Programms abgebildet ist, erhalten wir einen I/O-Fehler.

Für diese Probleme gibt es Lösungen, die zwar nicht perfekt, aber brauchbar sind:

- Die meisten Shell-Interpreter erlauben die Erstellung von File Descriptors, die anschließend von Child-Prozessen geerbt werden. Wir können einen fd erstellen, der mit Schreibberechtigungen auf die `mem`-Datei der Shell zeigt ... dadurch können Child-Prozesse, die diesen fd verwenden, den Speicher der Shell verändern.
- ASLR ist nicht einmal ein Problem; wir können die `maps`-Datei der Shell oder eine andere Datei aus dem procfs prüfen, um Informationen über den Adressraum des Prozesses zu erhalten.
- Daher müssen wir `lseek()` über die Datei ausführen. Aus der Shell heraus ist dies nur mit dem berüchtigten `dd` möglich.

### Im Detail

Die Schritte sind relativ einfach und erfordern keinerlei besondere Expertise, um sie zu verstehen:<sup>[[1]](#references)</sup>

- Analysiere das Binary, das wir ausführen möchten, sowie den Loader, um herauszufinden, welche Mappings sie benötigen. Erstelle anschließend einen "shell"code, der grob gesagt dieselben Schritte ausführt wie der Kernel bei jedem Aufruf von `execve()`:
- Erstelle diese Mappings.
- Lies die Binaries in sie ein.
- Richte die Berechtigungen ein.
- Initialisiere schließlich den Stack mit den Argumenten für das Programm und platziere den auxiliary vector (der vom Loader benötigt wird).
- Springe in den Loader und überlasse ihm den Rest (das Laden der vom Programm benötigten Libraries).
- Ermittle aus der Datei `syscall` die Adresse, zu der der Prozess nach dem von ihm ausgeführten syscall zurückkehren wird.
- Überschreibe diese Stelle, die ausführbar sein wird, mit unserem shellcode (über `mem` können wir nicht beschreibbare Pages verändern).
- Übergib das Programm, das wir ausführen möchten, an stdin des Prozesses (wird von diesem "shell"code mittels `read()` eingelesen).
- Ab diesem Punkt ist es Aufgabe des Loaders, die erforderlichen Libraries für unser Programm zu laden und in dieses zu springen.

**Siehe dir das Tool unter** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)<sup>[[1]](#references)</sup>

## EverythingExec

Es gibt mehrere Alternativen zu `dd`, darunter `tail`, das derzeit standardmäßig verwendete Programm zum Ausführen von `lseek()` über die `mem`-Datei (was der einzige Zweck der Verwendung von `dd` war). Diese Alternativen sind:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Durch Setzen der Variable `SEEKER` kann der verwendete seeker geändert werden, _z. B._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Wenn du einen anderen gültigen Seeker findest, der im Script nicht implementiert ist, kannst du ihn trotzdem verwenden, indem du die Variable `SEEKER_ARGS` setzt:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blockiert dies, EDRs.

## Referenzen

- [1] [DDexec: Eine Technik zum dateilosen und unauffälligen Ausführen von Binärdateien unter Linux](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
