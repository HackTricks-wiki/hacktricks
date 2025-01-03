# Netzwerk-Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Grundinformationen

Ein Netzwerk-Namespace ist eine Funktion des Linux-Kernels, die die Isolation des Netzwerk-Stacks ermöglicht und **jedem Netzwerk-Namespace eine eigene unabhängige Netzwerkkonfiguration**, Schnittstellen, IP-Adressen, Routing-Tabellen und Firewall-Regeln zuweist. Diese Isolation ist in verschiedenen Szenarien nützlich, wie z.B. bei der Containerisierung, wo jeder Container seine eigene Netzwerkkonfiguration haben sollte, unabhängig von anderen Containern und dem Host-System.

### So funktioniert es:

1. Wenn ein neuer Netzwerk-Namespace erstellt wird, beginnt er mit einem **vollständig isolierten Netzwerk-Stack**, mit **keinen Netzwerk-Schnittstellen** außer der Loopback-Schnittstelle (lo). Das bedeutet, dass Prozesse, die im neuen Netzwerk-Namespace ausgeführt werden, standardmäßig nicht mit Prozessen in anderen Namespaces oder dem Host-System kommunizieren können.
2. **Virtuelle Netzwerk-Schnittstellen**, wie veth-Paare, können erstellt und zwischen Netzwerk-Namespaces verschoben werden. Dies ermöglicht die Herstellung einer Netzwerkverbindung zwischen Namespaces oder zwischen einem Namespace und dem Host-System. Zum Beispiel kann ein Ende eines veth-Paares im Netzwerk-Namespace eines Containers platziert werden, und das andere Ende kann mit einem **Bridge** oder einer anderen Netzwerkschnittstelle im Host-Namespace verbunden werden, um dem Container Netzwerkverbindung zu bieten.
3. Netzwerkschnittstellen innerhalb eines Namespace können ihre **eigenen IP-Adressen, Routing-Tabellen und Firewall-Regeln** haben, unabhängig von anderen Namespaces. Dies ermöglicht es Prozessen in verschiedenen Netzwerk-Namespaces, unterschiedliche Netzwerkkonfigurationen zu haben und so zu arbeiten, als ob sie auf separaten vernetzten Systemen ausgeführt werden.
4. Prozesse können zwischen Namespaces mit dem `setns()` Systemaufruf wechseln oder neue Namespaces mit den Systemaufrufen `unshare()` oder `clone()` mit dem `CLONE_NEWNET`-Flag erstellen. Wenn ein Prozess in einen neuen Namespace wechselt oder einen erstellt, beginnt er, die Netzwerkkonfiguration und Schnittstellen zu verwenden, die mit diesem Namespace verbunden sind.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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

- Das Verlassen von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING`-Flags. Dies führt dazu, dass die Funktion `alloc_pid` fehlschlägt, um eine neue PID zuzuweisen, wenn ein neuer Prozess erstellt wird, was den Fehler "Kann Speicher nicht zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann gelöst werden, indem die Option `-f` mit `unshare` verwendet wird. Diese Option bewirkt, dass `unshare` einen neuen Prozess nach der Erstellung des neuen PID-Namespace forked.
- Das Ausführen von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, wodurch der vorzeitige Austritt von PID 1 verhindert wird und eine normale PID-Zuweisung ermöglicht wird.

Indem sichergestellt wird, dass `unshare` mit dem `-f`-Flag ausgeführt wird, wird der neue PID-Namespace korrekt aufrechterhalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Überprüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Alle Netzwerk-Namensräume finden
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Betreten Sie einen Netzwerk-Namespace
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Außerdem können Sie **nur in einen anderen Prozess-Namespace eintreten, wenn Sie root sind**. Und Sie **können** **nicht** **in** einen anderen Namespace **eintreten**, **ohne einen Deskriptor**, der darauf verweist (wie `/proc/self/ns/net`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
