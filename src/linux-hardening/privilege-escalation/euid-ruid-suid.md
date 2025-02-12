# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Benutzeridentifikationsvariablen

- **`ruid`**: Die **echte Benutzer-ID** bezeichnet den Benutzer, der den Prozess initiiert hat.
- **`euid`**: Bekannt als die **effektive Benutzer-ID**, repräsentiert sie die Benutzeridentität, die vom System verwendet wird, um die Prozessprivilegien zu bestimmen. Im Allgemeinen spiegelt `euid` `ruid` wider, mit Ausnahme von Fällen wie der Ausführung einer SetUID-Binärdatei, bei der `euid` die Identität des Dateieigentümers annimmt und somit spezifische Betriebsberechtigungen gewährt.
- **`suid`**: Diese **gespeicherte Benutzer-ID** ist entscheidend, wenn ein hochprivilegierter Prozess (typischerweise als root ausgeführt) vorübergehend seine Privilegien abgeben muss, um bestimmte Aufgaben auszuführen, um später seinen ursprünglichen erhöhten Status wiederzuerlangen.

#### Wichtiger Hinweis

Ein Prozess, der nicht unter root läuft, kann seine `euid` nur so ändern, dass sie mit der aktuellen `ruid`, `euid` oder `suid` übereinstimmt.

### Verständnis der set\*uid-Funktionen

- **`setuid`**: Entgegen anfänglicher Annahmen ändert `setuid` hauptsächlich `euid` und nicht `ruid`. Insbesondere für privilegierte Prozesse richtet es `ruid`, `euid` und `suid` auf den angegebenen Benutzer, oft root, aus und festigt diese IDs aufgrund des übergeordneten `suid`. Detaillierte Informationen sind in der [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html) zu finden.
- **`setreuid`** und **`setresuid`**: Diese Funktionen ermöglichen die nuancierte Anpassung von `ruid`, `euid` und `suid`. Ihre Möglichkeiten hängen jedoch vom Privilegienniveau des Prozesses ab. Für Nicht-Root-Prozesse sind Änderungen auf die aktuellen Werte von `ruid`, `euid` und `suid` beschränkt. Im Gegensatz dazu können Root-Prozesse oder solche mit der `CAP_SETUID`-Berechtigung beliebige Werte für diese IDs zuweisen. Weitere Informationen sind in der [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) und der [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html) zu finden.

Diese Funktionen sind nicht als Sicherheitsmechanismus konzipiert, sondern um den beabsichtigten Betriebsablauf zu erleichtern, wie wenn ein Programm die Identität eines anderen Benutzers annimmt, indem es seine effektive Benutzer-ID ändert.

Es ist bemerkenswert, dass `setuid` zwar ein gängiges Mittel zur Erhöhung der Privilegien auf root sein kann (da es alle IDs auf root ausrichtet), das Unterscheiden zwischen diesen Funktionen entscheidend ist, um das Verhalten der Benutzer-IDs in unterschiedlichen Szenarien zu verstehen und zu manipulieren.

### Programmausführungsmechanismen in Linux

#### **`execve` Systemaufruf**

- **Funktionalität**: `execve` startet ein Programm, das durch das erste Argument bestimmt wird. Es nimmt zwei Array-Argumente, `argv` für Argumente und `envp` für die Umgebung.
- **Verhalten**: Es behält den Speicherbereich des Aufrufers bei, aktualisiert jedoch den Stack, Heap und die Datensegmente. Der Programmcode wird durch das neue Programm ersetzt.
- **Benutzer-ID-Erhaltung**:
- `ruid`, `euid` und zusätzliche Gruppen-IDs bleiben unverändert.
- `euid` kann nuancierte Änderungen aufweisen, wenn das neue Programm das SetUID-Bit gesetzt hat.
- `suid` wird nach der Ausführung von `euid` aktualisiert.
- **Dokumentation**: Detaillierte Informationen sind auf der [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html) zu finden.

#### **`system` Funktion**

- **Funktionalität**: Im Gegensatz zu `execve` erstellt `system` einen Kindprozess mit `fork` und führt einen Befehl innerhalb dieses Kindprozesses mit `execl` aus.
- **Befehlsausführung**: Führt den Befehl über `sh` mit `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` aus.
- **Verhalten**: Da `execl` eine Form von `execve` ist, funktioniert es ähnlich, jedoch im Kontext eines neuen Kindprozesses.
- **Dokumentation**: Weitere Einblicke sind in der [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html) zu erhalten.

#### **Verhalten von `bash` und `sh` mit SUID**

- **`bash`**:
- Hat eine `-p`-Option, die beeinflusst, wie `euid` und `ruid` behandelt werden.
- Ohne `-p` setzt `bash` `euid` auf `ruid`, wenn sie anfangs unterschiedlich sind.
- Mit `-p` wird das ursprüngliche `euid` beibehalten.
- Weitere Details sind auf der [`bash` man page](https://linux.die.net/man/1/bash) zu finden.
- **`sh`**:
- Verfügt nicht über einen Mechanismus ähnlich der `-p`-Option in `bash`.
- Das Verhalten bezüglich der Benutzer-IDs wird nicht ausdrücklich erwähnt, außer unter der `-i`-Option, die die Erhaltung der Gleichheit von `euid` und `ruid` betont.
- Zusätzliche Informationen sind auf der [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html) verfügbar.

Diese Mechanismen, die sich in ihrem Betrieb unterscheiden, bieten eine vielseitige Palette von Optionen zur Ausführung und zum Übergang zwischen Programmen, mit spezifischen Nuancen in der Verwaltung und Erhaltung von Benutzer-IDs.

### Testen des Benutzer-ID-Verhaltens in Ausführungen

Beispiele entnommen von https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, überprüfen Sie es für weitere Informationen

#### Fall 1: Verwendung von `setuid` mit `system`

**Ziel**: Verständnis der Auswirkungen von `setuid` in Kombination mit `system` und `bash` als `sh`.

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

- `ruid` und `euid` beginnen als 99 (nobody) und 1000 (frank) respektive.
- `setuid` richtet beide auf 1000 aus.
- `system` führt `/bin/bash -c id` aus, aufgrund des Symlinks von sh zu bash.
- `bash`, ohne `-p`, passt `euid` an `ruid` an, was dazu führt, dass beide 99 (nobody) sind.

#### Fall 2: Verwendung von setreuid mit system

**C Code**:
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
- `system` ruft bash auf, die die Benutzer-IDs aufgrund ihrer Gleichheit beibehält und effektiv als frank fungiert.

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

- `ruid` bleibt 99, aber euid wird auf 1000 gesetzt, entsprechend der Wirkung von setuid.

**C Code Beispiel 2 (Bash aufrufen):**
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

- Obwohl `euid` durch `setuid` auf 1000 gesetzt ist, setzt `bash` `euid` auf `ruid` (99) zurück, da `-p` fehlt.

**C Code Beispiel 3 (Verwendung von bash -p):**
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

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
