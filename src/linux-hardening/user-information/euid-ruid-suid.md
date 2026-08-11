# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variablen zur Benutzeridentifikation

- **`ruid`**: Die **reale Benutzer-ID** bezeichnet den Benutzer, der den Prozess gestartet hat.<sup>[[1]](#references)</sup>
- **`euid`**: Die sogenannte **effektive Benutzer-ID** repräsentiert die Benutzeridentität, anhand derer das System die Prozessberechtigungen bestimmt. Im Allgemeinen entspricht `euid` der `ruid`, außer in Fällen wie der Ausführung einer SetUID-Binärdatei (wenn der Set-User-ID-Übergang berücksichtigt wird), bei der `euid` die Identität des Dateibesitzers übernimmt und dadurch bestimmte operative Berechtigungen erhält.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Diese **gespeicherte Benutzer-ID** ist entscheidend, wenn ein Prozess mit hohen Berechtigungen (typischerweise als root ausgeführt) seine Berechtigungen vorübergehend abgeben muss, um bestimmte Aufgaben auszuführen, und anschließend seinen ursprünglichen erhöhten Status wiedererlangen soll.<sup>[[1]](#references)</sup>

#### Wichtiger Hinweis

Ein unprivilegierter Prozess kann seine `euid` nur so ändern, dass sie der aktuellen `ruid`, `euid` oder `suid` entspricht.<sup>[[3]](#references)</sup>

### Verständnis der set\*uid-Funktionen

- **`setuid`**: Entgegen der ursprünglichen Annahme setzt `setuid` die `euid` des aufrufenden Prozesses. Bei einem privilegierten Prozess setzt es außerdem `ruid` und `suid` auf den angegebenen Benutzer; nachdem alle IDs auf root gesetzt wurden, kann der Prozess seine vorherige Identität nicht mehr mit `setuid` wiedererlangen. Detaillierte Informationen finden sich auf der [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** und **`setresuid`**: `setreuid` ändert `ruid` und `euid`, während `setresuid` alle drei IDs ändert. Für einen unprivilegierten Prozess beschränkt `setresuid` jedes Ziel auf die aktuelle `ruid`, `euid` oder `suid`; `setreuid` beschränkt `euid` auf diese Werte und `ruid` auf die aktuelle `ruid` oder `euid`. Ein Prozess mit `CAP_SETUID` kann den von jedem Aufruf unterstützten IDs beliebige Werte zuweisen. Weitere Informationen finden sich auf der [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) und der [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Diese Funktionen sind nicht als Sicherheitsmechanismus gedacht, sondern sollen den vorgesehenen Ablauf ermöglichen, etwa wenn ein Programm die Identität eines anderen Benutzers übernimmt, indem es seine effektive Benutzer-ID ändert.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Bemerkenswert ist, dass ein privilegierter Aufruf von `setuid` alle drei IDs setzen kann, während `setreuid` und `setresuid` unterschiedliche Steuerungsmöglichkeiten bieten; die Unterscheidung dieser Funktionen ist entscheidend für das Verständnis von Benutzer-ID-Übergängen.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Mechanismen zur Programmausführung unter Linux

#### **`execve` Systemaufruf**

- **Funktionalität**: `execve` startet ein durch das erste Argument bestimmtes Programm. Es akzeptiert zwei Array-Argumente: `argv` für die Argumente und `envp` für die Umgebung.<sup>[[5]](#references)</sup>
- **Verhalten**: Der Speicherbereich des Aufrufers bleibt erhalten, während Stack, Heap und Datensegmente aktualisiert werden. Der Programmcode wird durch das neue Programm ersetzt.<sup>[[5]](#references)</sup>
- **Erhaltung der Benutzer-IDs**:
- `ruid` und zusätzliche Gruppen-IDs bleiben unverändert.<sup>[[5]](#references)</sup>
- `euid` bleibt normalerweise unverändert, kann sich jedoch ändern, wenn das neue Programm das SetUID-Bit gesetzt hat.<sup>[[5]](#references)</sup>
- `suid` wird nach der Ausführung aus `euid` aktualisiert.<sup>[[5]](#references)</sup>
- **Dokumentation**: Detaillierte Informationen finden sich auf der [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system`-Funktion**

- **Funktionalität**: Im Gegensatz zu `execve` verhält sich `system` so, als würde es mithilfe von `fork` einen Kindprozess erstellen und den Befehl innerhalb dieses Kindprozesses mit `execl` ausführen.<sup>[[6]](#references)</sup>
- **Befehlsausführung**: Der Befehl wird über `sh` mit `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` ausgeführt.<sup>[[6]](#references)</sup>
- **Verhalten**: Da `execl` zu den Aufrufen der `exec`-Familie gehört, arbeitet es ähnlich wie `execve`, jedoch im Kontext eines neuen Kindprozesses.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Dokumentation**: Weitere Informationen finden sich auf der [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Verhalten von `bash` und `sh` mit SUID**

- **`bash`**:
- Verfügt über eine `-p`-Option, die beeinflusst, wie `euid` und `ruid` behandelt werden.<sup>[[7]](#references)</sup>
- Ohne `-p` setzt `bash` `euid` auf `ruid`, wenn sie sich anfänglich unterscheiden.<sup>[[7]](#references)</sup>
- Mit `-p` bleibt die anfängliche `euid` erhalten.<sup>[[7]](#references)</sup>
- Weitere Details finden sich auf der [`bash` man page](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX-`sh` definiert keine Bash-ähnliche `-p`-Option zur Erhaltung von Berechtigungen.<sup>[[8]](#references)</sup>
- Die POSIX-Optionsliste enthält `-i`, wodurch der interaktive Modus ausgewählt wird und das möglicherweise abgelehnt wird, wenn sich reale und effektive IDs unterscheiden.<sup>[[8]](#references)</sup>
- Zusätzliche Informationen finden sich auf der [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Diese Mechanismen unterscheiden sich in ihrer Funktionsweise und bieten eine vielseitige Auswahl an Möglichkeiten zur Ausführung und zum Übergang zwischen Programmen, mit spezifischen Besonderheiten bei der Verwaltung und Erhaltung von Benutzer-IDs.

### Testen des Verhaltens von Benutzer-IDs bei Ausführungen

Beispiele aus https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; weitere Informationen finden sich dort.<sup>[[1]](#references)</sup>

#### Fall 1: Verwendung von `setuid` mit `system`

**Ziel**: Die Auswirkungen von `setuid` in Kombination mit `system` und `bash` als `sh` verstehen.

**C-Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Kompilierung und Berechtigungen:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse:**

- `ruid` und `euid` beginnen jeweils mit 99 (nobody) beziehungsweise 1000 (frank).
- In diesem unprivilegierten Kontext belässt `setuid(1000)` `ruid` bei 99 und `euid` bei 1000.<sup>[[1]](#references)</sup>
- `system` führt aufgrund des symlinks von sh zu bash `/bin/bash -c id` aus.
- `bash` passt `euid` ohne `-p` an `ruid` an, sodass beide den Wert 99 (nobody) haben.<sup>[[1]](#references)</sup>

#### Fall 2: Verwendung von setreuid mit system

**C-Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Kompilierung und Berechtigungen:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Ausführung und Ergebnis:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse:**

- `setreuid` setzt sowohl ruid als auch euid auf 1000.
- `system` ruft bash auf, das die Benutzer-IDs aufgrund ihrer Gleichheit beibehält und effektiv als frank arbeitet.<sup>[[1]](#references)</sup>

#### Fall 3: Verwendung von setuid mit execve

Ziel: Untersuchung der Interaktion zwischen setuid und execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Ausführung und Ergebnis:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse:**

- `ruid` bleibt 99, aber euid wird auf 1000 gesetzt, entsprechend der Wirkung von setuid.<sup>[[1]](#references)</sup>

**C-Codebeispiel 2 (Aufruf von Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Ausführung und Ergebnis:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse:**

- Obwohl `euid` durch `setuid` auf 1000 gesetzt wird, setzt `bash` euid aufgrund des Fehlens von `-p` auf `ruid` (99) zurück.<sup>[[1]](#references)</sup>

**C-Codebeispiel 3 (Verwendung von bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Ausführung und Ergebnis:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man-Seite](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man-Seite](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man-Seite](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man-Seite](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system man-Seite](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash man-Seite](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh man-Seite](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
