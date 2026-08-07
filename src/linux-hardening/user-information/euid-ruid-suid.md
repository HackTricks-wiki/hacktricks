# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variablen zur Benutzeridentifikation

- **`ruid`**: Die **reale Benutzer-ID** bezeichnet den Benutzer, der den Prozess gestartet hat.
- **`euid`**: Bekannt als **effektive Benutzer-ID**, repräsentiert sie die Benutzeridentität, die vom System zur Ermittlung der Prozessberechtigungen verwendet wird. Im Allgemeinen entspricht `euid` dem `ruid`, außer in Fällen wie der Ausführung einer SetUID-Binärdatei, bei der `euid` die Identität des Dateibesitzers annimmt und dadurch bestimmte Berechtigungen für Operationen gewährt.
- **`suid`**: Diese **gespeicherte Benutzer-ID** ist entscheidend, wenn ein Prozess mit hohen Berechtigungen (typischerweise als root) seine Berechtigungen vorübergehend abgeben muss, um bestimmte Aufgaben auszuführen, und später seinen ursprünglichen erhöhten Status wiedererlangen soll.

#### Wichtiger Hinweis

Ein Prozess, der nicht unter root läuft, kann seine `euid` nur so ändern, dass sie der aktuellen `ruid`, `euid` oder `suid` entspricht.

### Die Funktionen set\*uid verstehen

- **`setuid`**: Entgegen der anfänglichen Annahme verändert `setuid` hauptsächlich die `euid` und nicht die `ruid`. Bei privilegierten Prozessen setzt es insbesondere `ruid`, `euid` und `suid` auf den angegebenen Benutzer, häufig root, wodurch diese IDs aufgrund der überschreibenden `suid` effektiv dauerhaft festgelegt werden. Detaillierte Informationen finden sich auf der [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** und **`setresuid`**: Diese Funktionen ermöglichen eine differenzierte Anpassung von `ruid`, `euid` und `suid`. Ihre Möglichkeiten hängen jedoch von der Berechtigungsstufe des Prozesses ab. Bei nicht-root-Prozessen sind Änderungen auf die aktuellen Werte von `ruid`, `euid` und `suid` beschränkt. Im Gegensatz dazu können root-Prozesse oder Prozesse mit der Fähigkeit `CAP_SETUID` beliebige Werte für diese IDs festlegen. Weitere Informationen finden sich auf der [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) und der [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Diese Funktionen sind nicht als Sicherheitsmechanismus gedacht, sondern sollen den vorgesehenen Ablauf erleichtern, beispielsweise wenn ein Programm die Identität eines anderen Benutzers übernimmt, indem es seine effektive Benutzer-ID ändert.

Obwohl `setuid` häufig zur Rechteausweitung auf root verwendet wird (da alle IDs auf root gesetzt werden), ist die Unterscheidung zwischen diesen Funktionen entscheidend, um das Verhalten von Benutzer-IDs in verschiedenen Szenarien zu verstehen und zu beeinflussen.

### Mechanismen zur Programmausführung unter Linux

#### **`execve` System Call**

- **Funktionalität**: `execve` startet ein durch das erste Argument bestimmtes Programm. Es übernimmt zwei Array-Argumente: `argv` für Argumente und `envp` für die Umgebung.
- **Verhalten**: Der Speicherbereich des Aufrufers bleibt erhalten, während Stack, Heap und Datensegmente erneuert werden. Der Code des Programms wird durch das neue Programm ersetzt.
- **Erhalt der Benutzer-IDs**:
- `ruid`, `euid` und zusätzliche Gruppen-IDs bleiben unverändert.
- `euid` kann sich geringfügig ändern, wenn das neue Programm das SetUID-Bit gesetzt hat.
- `suid` wird nach der Ausführung aus `euid` aktualisiert.
- **Dokumentation**: Detaillierte Informationen finden sich auf der [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Funktionalität**: Im Gegensatz zu `execve` erstellt `system` mithilfe von `fork` einen Kindprozess und führt in diesem Kindprozess mithilfe von `execl` einen Befehl aus.
- **Befehlsausführung**: Der Befehl wird über `sh` mit `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` ausgeführt.
- **Verhalten**: Da `execl` eine Form von `execve` ist, arbeitet es ähnlich, jedoch im Kontext eines neuen Kindprozesses.
- **Dokumentation**: Weitere Informationen finden sich auf der [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Verhalten von `bash` und `sh` mit SUID**

- **`bash`**:
- Verfügt über eine Option `-p`, die beeinflusst, wie `euid` und `ruid` behandelt werden.
- Ohne `-p` setzt `bash` `euid` auf `ruid`, wenn sie sich anfangs unterscheiden.
- Mit `-p` bleibt die ursprüngliche `euid` erhalten.
- Weitere Details finden sich auf der [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Verfügt über keinen Mechanismus, der `-p` in `bash` entspricht.
- Das Verhalten in Bezug auf Benutzer-IDs wird nicht ausdrücklich erwähnt, außer bei der Option `-i`, bei der die Gleichheit von `euid` und `ruid` betont wird.
- Weitere Informationen finden sich auf der [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Diese Mechanismen unterscheiden sich in ihrer Funktionsweise und bieten eine vielseitige Auswahl an Möglichkeiten zur Ausführung und zum Übergang zwischen Programmen, wobei es besondere Feinheiten beim Verwalten und Erhalten von Benutzer-IDs gibt.

### Testen des Verhaltens von Benutzer-IDs bei Ausführungen

Beispiele übernommen von https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; weitere Informationen finden sich dort<sup>[[1]](#references)</sup>

#### Fall 1: Verwendung von `setuid` mit `system`

**Ziel**: Das Verhalten von `setuid` in Kombination mit `system` und `bash` als `sh` verstehen.

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

- `ruid` und `euid` starten jeweils als 99 (nobody) bzw. 1000 (frank).
- `setuid` setzt beide auf 1000.
- `system` führt aufgrund des Symlinks von sh auf bash `/bin/bash -c id` aus.
- `bash` passt ohne `-p` `euid` an `ruid` an, wodurch beide den Wert 99 (nobody) erhalten.

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
- `system` ruft bash auf, das die Benutzer-IDs aufgrund ihrer Gleichheit beibehält und effektiv als frank arbeitet.

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

- `ruid` bleibt 99, aber `euid` wird auf 1000 gesetzt, entsprechend der Wirkung von setuid.

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

- Obwohl `euid` durch `setuid` auf 1000 gesetzt wird, setzt `bash` euid aufgrund des Fehlens von `-p` auf `ruid` (99) zurück.

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
uid=99(nobody) gid=99(nobody) euid=100
```
## Referenzen

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man-Seite](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man-Seite](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man-Seite](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man-Seite](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
