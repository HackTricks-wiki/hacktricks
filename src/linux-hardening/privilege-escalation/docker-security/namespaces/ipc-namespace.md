# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Grundinformationen

Ein IPC (Inter-Process Communication) Namespace ist eine Funktion des Linux-Kernels, die **Isolation** von System V IPC-Objekten wie Nachrichtenwarteschlangen, gemeinsamen Speichersegmenten und Semaphoren bietet. Diese Isolation stellt sicher, dass Prozesse in **verschiedenen IPC-Namespaces nicht direkt auf die IPC-Objekte des jeweils anderen zugreifen oder diese ändern können**, was eine zusätzliche Sicherheitsebene und Privatsphäre zwischen Prozessgruppen bietet.

### So funktioniert es:

1. Wenn ein neuer IPC-Namespace erstellt wird, beginnt er mit einem **vollständig isolierten Satz von System V IPC-Objekten**. Das bedeutet, dass Prozesse, die im neuen IPC-Namespace ausgeführt werden, standardmäßig nicht auf die IPC-Objekte in anderen Namespaces oder im Host-System zugreifen oder diese stören können.
2. IPC-Objekte, die innerhalb eines Namespaces erstellt werden, sind sichtbar und **nur für Prozesse innerhalb dieses Namespaces zugänglich**. Jedes IPC-Objekt wird durch einen eindeutigen Schlüssel innerhalb seines Namespaces identifiziert. Obwohl der Schlüssel in verschiedenen Namespaces identisch sein kann, sind die Objekte selbst isoliert und können nicht über Namespaces hinweg zugegriffen werden.
3. Prozesse können zwischen Namespaces mit dem `setns()` Systemaufruf wechseln oder neue Namespaces mit den Systemaufrufen `unshare()` oder `clone()` unter Verwendung des `CLONE_NEWIPC`-Flags erstellen. Wenn ein Prozess in einen neuen Namespace wechselt oder einen erstellt, beginnt er, die mit diesem Namespace verbundenen IPC-Objekte zu verwenden.

## Labor:

### Erstellen verschiedener Namespaces

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Durch das Einhängen einer neuen Instanz des `/proc`-Dateisystems, wenn Sie den Parameter `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **genaue und isolierte Sicht auf die prozessspezifischen Informationen hat, die für diesen Namespace spezifisch sind**.

<details>

<summary>Fehler: bash: fork: Kann Speicher nicht zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler auf, der auf die Art und Weise zurückzuführen ist, wie Linux neue PID (Process ID) Namespaces behandelt. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problemerklärung**:

- Der Linux-Kernel erlaubt es einem Prozess, neue Namespaces mit dem Systemaufruf `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespace initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Das Ausführen von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird zu PID 1. Wenn dieser Prozess beendet wird, wird die Bereinigung des Namespaces ausgelöst, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Folge**:

- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` fehlschlägt, wenn versucht wird, eine neue PID zuzuweisen, was den Fehler "Kann Speicher nicht zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann gelöst werden, indem die Option `-f` mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` einen neuen Prozess nach der Erstellung des neuen PID-Namespace forked.
- Das Ausführen von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, wodurch das vorzeitige Beenden von PID 1 verhindert wird und eine normale PID-Zuweisung ermöglicht wird.

Durch die Sicherstellung, dass `unshare` mit dem `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt aufrechterhalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Überprüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Finde alle IPC-Namensräume
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Betreten Sie einen IPC-Namespace
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Außerdem können Sie **nur in einen anderen Prozess-Namespace eintreten, wenn Sie root sind**. Und Sie **können** **nicht** **in einen anderen Namespace eintreten** **ohne einen Deskriptor**, der darauf verweist (wie `/proc/self/ns/net`).

### IPC-Objekt erstellen
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Referenzen

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
