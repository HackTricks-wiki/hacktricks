# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Grundinformationen

Ein UTS (UNIX Time-Sharing System) Namespace ist eine Funktion des Linux-Kernels, die die **Isolation von zwei Systemidentifikatoren** bietet: dem **Hostname** und dem **NIS** (Network Information Service) Domänennamen. Diese Isolation ermöglicht es jedem UTS-Namespace, seinen **eigenen unabhängigen Hostnamen und NIS-Domänennamen** zu haben, was besonders in Containerisierungs-Szenarien nützlich ist, in denen jeder Container als separates System mit seinem eigenen Hostnamen erscheinen sollte.

### So funktioniert es:

1. Wenn ein neuer UTS-Namespace erstellt wird, beginnt er mit einer **Kopie des Hostnamens und des NIS-Domänennamens aus seinem übergeordneten Namespace**. Das bedeutet, dass der neue Namespace bei der Erstellung **die gleichen Identifikatoren wie sein übergeordneter Namespace teilt**. Änderungen am Hostnamen oder NIS-Domänennamen innerhalb des Namespaces wirken sich jedoch nicht auf andere Namespaces aus.
2. Prozesse innerhalb eines UTS-Namespace **können den Hostnamen und den NIS-Domänennamen** mithilfe der Systemaufrufe `sethostname()` und `setdomainname()` ändern. Diese Änderungen sind lokal für den Namespace und wirken sich nicht auf andere Namespaces oder das Hostsystem aus.
3. Prozesse können zwischen Namespaces mit dem Systemaufruf `setns()` wechseln oder neue Namespaces mit den Systemaufrufen `unshare()` oder `clone()` unter Verwendung des Flags `CLONE_NEWUTS` erstellen. Wenn ein Prozess in einen neuen Namespace wechselt oder einen erstellt, beginnt er, den Hostnamen und den NIS-Domänennamen zu verwenden, die mit diesem Namespace verbunden sind.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
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

- Das Verlassen von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` bei der Erstellung eines neuen Prozesses fehlschlägt, was den Fehler "Kann Speicher nicht zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann gelöst werden, indem die Option `-f` mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` einen neuen Prozess nach der Erstellung des neuen PID-Namespace forked.
- Das Ausführen von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, wodurch der vorzeitige Austritt von PID 1 verhindert wird und eine normale PID-Zuweisung ermöglicht wird.

Durch die Sicherstellung, dass `unshare` mit dem `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt aufrechterhalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Überprüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Finde alle UTS-Namensräume
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Betreten Sie einen UTS-Namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
