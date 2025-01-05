# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Grundinformationen

Ein cgroup-Namespace ist eine Funktion des Linux-Kernels, die **Isolation von cgroup-Hierarchien für Prozesse, die innerhalb eines Namespaces ausgeführt werden**, bereitstellt. Cgroups, kurz für **control groups**, sind eine Kernel-Funktion, die es ermöglicht, Prozesse in hierarchischen Gruppen zu organisieren, um **Grenzen für Systemressourcen** wie CPU, Speicher und I/O zu verwalten und durchzusetzen.

Während cgroup-Namensräume kein separater Namespace-Typ wie die anderen, die wir zuvor besprochen haben (PID, Mount, Netzwerk usw.), sind, stehen sie im Zusammenhang mit dem Konzept der Namespace-Isolation. **Cgroup-Namensräume virtualisieren die Sicht auf die cgroup-Hierarchie**, sodass Prozesse, die innerhalb eines cgroup-Namensraums ausgeführt werden, eine andere Sicht auf die Hierarchie haben als Prozesse, die im Host oder in anderen Namespaces ausgeführt werden.

### So funktioniert es:

1. Wenn ein neuer cgroup-Namespace erstellt wird, **beginnt er mit einer Sicht auf die cgroup-Hierarchie, die auf der cgroup des erstellenden Prozesses basiert**. Das bedeutet, dass Prozesse, die im neuen cgroup-Namespace ausgeführt werden, nur einen Teil der gesamten cgroup-Hierarchie sehen, der auf dem cgroup-Teilbaum basiert, der an der cgroup des erstellenden Prozesses verwurzelt ist.
2. Prozesse innerhalb eines cgroup-Namensraums werden **ihre eigene cgroup als Wurzel der Hierarchie sehen**. Das bedeutet, dass aus der Perspektive der Prozesse innerhalb des Namespaces ihre eigene cgroup als Wurzel erscheint und sie cgroups außerhalb ihres eigenen Teilbaums nicht sehen oder darauf zugreifen können.
3. Cgroup-Namensräume bieten nicht direkt Isolation von Ressourcen; **sie bieten nur Isolation der Sicht auf die cgroup-Hierarchie**. **Die Kontrolle und Isolation von Ressourcen werden weiterhin von den cgroup**-Subsystemen (z. B. CPU, Speicher usw.) selbst durchgesetzt.

Für weitere Informationen über CGroups siehe:

{{#ref}}
../cgroups.md
{{#endref}}

## Labor:

### Erstellen verschiedener Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Durch das Einhängen einer neuen Instanz des `/proc`-Dateisystems, wenn Sie den Parameter `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **genaue und isolierte Sicht auf die Prozessinformationen hat, die spezifisch für diesen Namespace sind**.

<details>

<summary>Fehler: bash: fork: Kann Speicher nicht zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler auf, der auf die Art und Weise zurückzuführen ist, wie Linux neue PID (Process ID) Namespaces behandelt. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problemerklärung**:

- Der Linux-Kernel erlaubt es einem Prozess, neue Namespaces mit dem Systemaufruf `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespace initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Das Ausführen von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird zu PID 1. Wenn dieser Prozess beendet wird, wird die Bereinigung des Namespaces ausgelöst, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Folge**:

- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` bei der Erstellung eines neuen Prozesses fehlschlägt, was den Fehler "Kann Speicher nicht zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann gelöst werden, indem die Option `-f` mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` einen neuen Prozess nach der Erstellung des neuen PID-Namespace forked.
- Das Ausführen von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, wodurch das vorzeitige Beenden von PID 1 verhindert wird und eine normale PID-Zuweisung ermöglicht wird.

Durch die Sicherstellung, dass `unshare` mit dem `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt aufrechterhalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Überprüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Alle CGroup-Namensräume finden
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Betreten Sie einen CGroup-Namespace
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Außerdem können Sie **nur in einen anderen Prozess-Namespace eintreten, wenn Sie root sind**. Und Sie **können** **nicht** **in** einen anderen Namespace **eintreten**, **ohne einen Deskriptor**, der darauf verweist (wie `/proc/self/ns/cgroup`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
