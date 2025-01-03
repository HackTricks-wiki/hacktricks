# PID-Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Grundinformationen

Der PID (Process IDentifier) Namespace ist eine Funktion im Linux-Kernel, die Prozessisolierung bietet, indem sie einer Gruppe von Prozessen ermöglicht, ihren eigenen Satz von einzigartigen PIDs zu haben, getrennt von den PIDs in anderen Namespaces. Dies ist besonders nützlich in der Containerisierung, wo Prozessisolierung für Sicherheit und Ressourcenmanagement entscheidend ist.

Wenn ein neuer PID-Namespace erstellt wird, erhält der erste Prozess in diesem Namespace die PID 1. Dieser Prozess wird zum "init"-Prozess des neuen Namespaces und ist verantwortlich für die Verwaltung anderer Prozesse innerhalb des Namespaces. Jeder nachfolgende Prozess, der innerhalb des Namespaces erstellt wird, hat eine einzigartige PID innerhalb dieses Namespaces, und diese PIDs sind unabhängig von PIDs in anderen Namespaces.

Aus der Perspektive eines Prozesses innerhalb eines PID-Namespace kann er nur andere Prozesse im selben Namespace sehen. Er ist sich der Prozesse in anderen Namespaces nicht bewusst und kann nicht mit ihnen interagieren, indem er traditionelle Prozessmanagement-Tools (z. B. `kill`, `wait` usw.) verwendet. Dies bietet ein Maß an Isolation, das hilft, zu verhindern, dass Prozesse sich gegenseitig stören.

### So funktioniert es:

1. Wenn ein neuer Prozess erstellt wird (z. B. durch Verwendung des `clone()`-Systemaufrufs), kann der Prozess einem neuen oder bestehenden PID-Namespace zugewiesen werden. **Wenn ein neuer Namespace erstellt wird, wird der Prozess zum "init"-Prozess dieses Namespaces**.
2. Der **Kernel** verwaltet eine **Zuordnung zwischen den PIDs im neuen Namespace und den entsprechenden PIDs** im übergeordneten Namespace (d. h. dem Namespace, aus dem der neue Namespace erstellt wurde). Diese Zuordnung **ermöglicht es dem Kernel, PIDs bei Bedarf zu übersetzen**, z. B. beim Senden von Signalen zwischen Prozessen in verschiedenen Namespaces.
3. **Prozesse innerhalb eines PID-Namespace können nur andere Prozesse im selben Namespace sehen und mit ihnen interagieren**. Sie sind sich der Prozesse in anderen Namespaces nicht bewusst, und ihre PIDs sind innerhalb ihres Namespaces einzigartig.
4. Wenn ein **PID-Namespace zerstört wird** (z. B. wenn der "init"-Prozess des Namespaces beendet wird), **werden alle Prozesse innerhalb dieses Namespaces beendet**. Dies stellt sicher, dass alle Ressourcen, die mit dem Namespace verbunden sind, ordnungsgemäß bereinigt werden.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Fehler: bash: fork: Kann Speicher nicht zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler auf, der auf die Art und Weise zurückzuführen ist, wie Linux neue PID (Prozess-ID) Namespaces behandelt. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problemerklärung**:

- Der Linux-Kernel erlaubt es einem Prozess, neue Namespaces mit dem Systemaufruf `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespace initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Das Ausführen von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird zu PID 1. Wenn dieser Prozess beendet wird, wird die Bereinigung des Namespaces ausgelöst, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Folge**:

- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` fehlschlägt, wenn versucht wird, eine neue PID zuzuweisen, was den Fehler "Kann Speicher nicht zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann gelöst werden, indem die Option `-f` mit `unshare` verwendet wird. Diese Option sorgt dafür, dass `unshare` einen neuen Prozess nach der Erstellung des neuen PID-Namespace forked.
- Das Ausführen von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, wodurch das vorzeitige Beenden von PID 1 verhindert wird und eine normale PID-Zuweisung ermöglicht wird.

Durch die Sicherstellung, dass `unshare` mit dem `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt aufrechterhalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler arbeiten können.

</details>

Durch das Einhängen einer neuen Instanz des `/proc`-Dateisystems, wenn Sie den Parameter `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **genaue und isolierte Sicht auf die Prozessinformationen hat, die spezifisch für diesen Namespace sind**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Überprüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Finde alle PID-Namensräume
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Beachten Sie, dass der Root-Benutzer aus dem ursprünglichen (Standard-)PID-Namespace alle Prozesse sehen kann, sogar die in neuen PID-Namensräumen, weshalb wir alle PID-Namensräume sehen können.

### Betreten eines PID-Namensraums
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Wenn Sie von dem Standard-Namespace in einen PID-Namespace eintreten, können Sie weiterhin alle Prozesse sehen. Und der Prozess aus diesem PID-Namespace wird in der Lage sein, die neue Bash im PID-Namespace zu sehen.

Außerdem können Sie **nur in einen anderen Prozess-PID-Namespace eintreten, wenn Sie root sind**. Und Sie **können nicht** **in einen anderen Namespace eintreten** **ohne einen Deskriptor**, der darauf verweist (wie `/proc/self/ns/pid`)

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
