# DDexec / EverythingExec

{{#include ../../../banners/hacktricks-training.md}}

## Kontext

In Linux muss ein Programm, um ausgeführt zu werden, als Datei existieren und auf irgendeine Weise über die Dateisystemhierarchie zugänglich sein (so funktioniert `execve()`). Diese Datei kann sich auf der Festplatte oder im RAM (tmpfs, memfd) befinden, aber Sie benötigen einen Dateipfad. Dies hat es sehr einfach gemacht, zu kontrollieren, was auf einem Linux-System ausgeführt wird, es erleichtert die Erkennung von Bedrohungen und Werkzeugen von Angreifern oder verhindert, dass sie versuchen, irgendetwas von ihnen auszuführen (_z. B._ unprivilegierten Benutzern zu verbieten, ausführbare Dateien irgendwo abzulegen).

Aber diese Technik ist hier, um all dies zu ändern. Wenn Sie den Prozess, den Sie möchten, nicht starten können... **dann übernehmen Sie einen bereits vorhandenen**.

Diese Technik ermöglicht es Ihnen, **häufige Schutztechniken wie schreibgeschützt, noexec, Dateinamen-Whitelisting, Hash-Whitelisting... zu umgehen**.

## Abhängigkeiten

Das endgültige Skript hängt von den folgenden Tools ab, die im System, das Sie angreifen, zugänglich sein müssen (standardmäßig finden Sie sie überall):
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

Wenn Sie in der Lage sind, den Speicher eines Prozesses beliebig zu modifizieren, können Sie ihn übernehmen. Dies kann verwendet werden, um einen bereits bestehenden Prozess zu übernehmen und ihn durch ein anderes Programm zu ersetzen. Wir können dies entweder durch die Verwendung des `ptrace()`-Syscalls erreichen (was erfordert, dass Sie die Fähigkeit haben, Syscalls auszuführen oder gdb auf dem System verfügbar ist) oder, interessanterweise, durch das Schreiben in `/proc/$pid/mem`.

Die Datei `/proc/$pid/mem` ist eine Eins-zu-eins-Abbildung des gesamten Adressraums eines Prozesses (_z. B._ von `0x0000000000000000` bis `0x7ffffffffffff000` in x86-64). Das bedeutet, dass das Lesen von oder Schreiben in diese Datei an einem Offset `x` dasselbe ist wie das Lesen von oder Modifizieren des Inhalts an der virtuellen Adresse `x`.

Jetzt haben wir vier grundlegende Probleme zu bewältigen:

- Im Allgemeinen dürfen nur root und der Programm-Eigentümer der Datei sie modifizieren.
- ASLR.
- Wenn wir versuchen, an eine Adresse zu lesen oder zu schreiben, die im Adressraum des Programms nicht abgebildet ist, erhalten wir einen I/O-Fehler.

Diese Probleme haben Lösungen, die, obwohl sie nicht perfekt sind, gut sind:

- Die meisten Shell-Interpreter erlauben die Erstellung von Dateideskriptoren, die dann von Kindprozessen geerbt werden. Wir können einen fd erstellen, der auf die `mem`-Datei der Shell mit Schreibberechtigungen zeigt... sodass Kindprozesse, die diesen fd verwenden, in der Lage sind, den Speicher der Shell zu modifizieren.
- ASLR ist nicht einmal ein Problem, wir können die `maps`-Datei der Shell oder eine andere aus dem procfs überprüfen, um Informationen über den Adressraum des Prozesses zu erhalten.
- Daher müssen wir über die Datei `lseek()`. Dies kann von der Shell aus nicht getan werden, es sei denn, man verwendet das berüchtigte `dd`.

### Im Detail

Die Schritte sind relativ einfach und erfordern keine Art von Fachwissen, um sie zu verstehen:

- Analysieren Sie die Binärdatei, die wir ausführen möchten, und den Loader, um herauszufinden, welche Abbildungen sie benötigen. Dann erstellen Sie einen "Shell"-Code, der, grob gesagt, die gleichen Schritte ausführt, die der Kernel bei jedem Aufruf von `execve()` durchführt:
- Erstellen Sie die genannten Abbildungen.
- Lesen Sie die Binärdateien in diese ein.
- Richten Sie Berechtigungen ein.
- Initialisieren Sie schließlich den Stack mit den Argumenten für das Programm und platzieren Sie den Hilfsvektor (benötigt vom Loader).
- Springen Sie in den Loader und lassen Sie ihn den Rest erledigen (benötigte Bibliotheken für das Programm laden).
- Erhalten Sie aus der `syscall`-Datei die Adresse, zu der der Prozess nach dem Ausführen des Syscalls zurückkehren wird.
- Überschreiben Sie diesen Ort, der ausführbar sein wird, mit unserem Shellcode (durch `mem` können wir nicht beschreibbare Seiten modifizieren).
- Übergeben Sie das Programm, das wir ausführen möchten, an den stdin des Prozesses (wird von said "Shell"-Code `read()`).
- An diesem Punkt liegt es am Loader, die notwendigen Bibliotheken für unser Programm zu laden und in es zu springen.

**Überprüfen Sie das Tool unter** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Es gibt mehrere Alternativen zu `dd`, von denen eine, `tail`, derzeit das Standardprogramm ist, das verwendet wird, um durch die `mem`-Datei zu `lseek()` (was der einzige Zweck für die Verwendung von `dd` war). Diese Alternativen sind:
```bash
tail
hexdump
cmp
xxd
```
Durch das Setzen der Variablen `SEEKER` können Sie den verwendeten Seeker ändern, _z. B._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Wenn Sie einen anderen gültigen Seeker finden, der im Skript nicht implementiert ist, können Sie ihn weiterhin verwenden, indem Sie die Variable `SEEKER_ARGS` festlegen:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blockiere dies, EDRs.

## Referenzen

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../banners/hacktricks-training.md}}
