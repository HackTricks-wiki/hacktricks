# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Kontext

Linux führt Programme normalerweise aus ausführbaren Dateien aus, die auf dem Datenträger oder im Arbeitsspeicher gespeichert sind. Es kann eine ausführbare Datei anhand ihres Pfadnamens oder Dateideskriptors erkennen, daher ist ein normaler Dateisystempfad nicht immer erforderlich.<sup>[[2]](#references)</sup>

DDexec / EverythingExec nutzt den Speicher eines **bereits laufenden Prozesses**. Die Seite [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) behandelt die Ausführung aus anonymen Dateien sowie die zugehörige Erkennung und forensische Datensammlung; die [Übersicht zu Memory Bypasses](index.html#memory-bypasses) verweist außerdem auf MemExec und Memdlopen.<sup>[[1]](#references)</sup>

Diese Technik ermöglicht es, **gängige Schutzmaßnahmen wie Schreibschutz, noexec, Dateinamen-Whitelisting und Hash-Whitelisting zu umgehen**.<sup>[[1]](#references)</sup>

## Abhängigkeiten

Damit das endgültige Skript funktioniert, benötigt es die folgenden Werkzeuge. Sie müssen auf dem angegriffenen System verfügbar sein (standardmäßig sind sie überall vorhanden):

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

Wenn du den Arbeitsspeicher eines Prozesses beliebig ändern kannst, kannst du ihn übernehmen. Damit lässt sich ein bereits laufender Prozess kapern und durch ein anderes Programm ersetzen. Das ist entweder mit dem `ptrace()`-Syscall möglich (dafür musst du Syscalls ausführen können oder `gdb` muss auf dem System verfügbar sein) oder, was interessanter ist, durch Schreiben nach `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Die Datei `/proc/$pid/mem` bildet den gesamten Adressraum eines Prozesses eins zu eins ab (_z. B._ von `0x0000000000000000` bis `0x7ffffffffffff000` bei x86-64). Das bedeutet: Aus dieser Datei an Offset `x` zu lesen oder in sie zu schreiben entspricht dem Lesen beziehungsweise Ändern des Inhalts an der virtuellen Adresse `x`.

Nun müssen wir vier grundlegende Probleme bewältigen:

- Im Allgemeinen können nur `root` und der Programmeigentümer die Datei ändern.
- ASLR.
- Wenn wir versuchen, eine Adresse zu lesen oder zu beschreiben, die im Adressraum des Programms nicht gemappt ist, erhalten wir einen I/O-Fehler.

Für diese Probleme gibt es Lösungen, die zwar nicht perfekt, aber gut genug sind:

- Die meisten Shell-Interpreter ermöglichen das Erstellen von Dateideskriptoren, die anschließend an Kindprozesse vererbt werden. Wir können einen fd mit Schreibberechtigungen auf die `mem`-Datei der Shell zeigen lassen ... dann können Kindprozesse, die diesen fd verwenden, den Arbeitsspeicher der Shell ändern.
- ASLR ist nicht einmal ein Problem: Wir können die `maps`-Datei der Shell oder eine andere Datei aus procfs prüfen, um Informationen über den Adressraum des Prozesses zu erhalten.
- Daher müssen wir mit `lseek()` durch die Datei navigieren. Von der Shell aus geht das nur mit dem berüchtigten `dd`.

### Im Detail

Die Schritte sind relativ einfach und erfordern kein besonderes Fachwissen, um sie zu verstehen:<sup>[[1]](#references)</sup>

- Analysiere die Binärdatei, die wir ausführen wollen, und den Loader, um herauszufinden, welche Mappings sie benötigen. Erstelle anschließend einen „Shell“-Code, der grob gesagt dieselben Schritte ausführt wie der Kernel bei jedem Aufruf von `execve()`:
  - Erstelle die entsprechenden Mappings.
  - Lies die Binärdateien hinein.
  - Richte die Berechtigungen ein.
  - Initialisiere schließlich den Stack mit den Argumenten für das Programm und platziere den Auxiliary Vector (den der Loader benötigt).
  - Springe zum Loader und überlasse ihm den Rest (das Laden der vom Programm benötigten Bibliotheken).
- Ermittle in der Datei `syscall` die Adresse, zu der der Prozess nach dem ausgeführten Syscall zurückkehrt.
- Überschreibe diese Stelle, die ausführbar sein wird, mit unserem Shellcode (über `mem` können wir nicht beschreibbare Seiten ändern).
- Übergib das auszuführende Programm über stdin an den Prozess (es wird von diesem „Shell“-Code mit `read()` gelesen).
- Nun muss der Loader nur noch die erforderlichen Bibliotheken für unser Programm laden und zu ihm springen.

**Sieh dir das Tool unter** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec) **an.**<sup>[[1]](#references)</sup>

## EverythingExec

Es gibt mehrere Alternativen zu `dd`. Eine davon, `tail`, ist derzeit das Standardprogramm, mit dem durch die `mem`-Datei navigiert wird (das war der einzige Zweck von `dd`). Zu diesen Alternativen gehören:<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

Durch Setzen der Variable `SEEKER` kannst du den verwendeten Seeker ändern, _z. B._:

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Wenn du einen weiteren gültigen Seeker findest, der nicht im Skript implementiert ist, kannst du ihn dennoch verwenden, indem du die Variable `SEEKER_ARGS` setzt:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Blockiert das, EDRs.

## References

- [1] [DDexec: Eine Technik, um Binärdateien dateilos und unauffällig unter Linux auszuführen](https://github.com/arget13/DDexec)
- [2] [execveat(2) — Linux-Handbuchseite](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
