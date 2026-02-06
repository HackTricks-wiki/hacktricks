# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Ein UTS (UNIX Time-Sharing System) Namespace ist eine Funktion des Linux-Kernels, die i**Isolierung von zwei Systemkennungen** bereitstellt: die **hostname** und der **NIS** (Network Information Service) Domainname. Diese Isolierung ermöglicht es jedem UTS Namespace, sein **eigenes unabhängiges hostname- und NIS-Domainname** zu haben, was besonders in Containerisierungsszenarien nützlich ist, in denen jeder Container als separates System mit eigenem **hostname** erscheinen soll.

### Funktionsweise:

1. Wenn ein neuer UTS Namespace erstellt wird, beginnt er mit einer **Kopie des hostname- und NIS-Domainnamens aus dem übergeordneten Namespace**. Das bedeutet, dass das neue Namespace bei der Erstellung **die gleichen Kennungen wie sein übergeordnetes Namespace teilt**. Änderungen am hostname oder NIS-Domainnamen innerhalb des Namespace wirken sich jedoch nicht auf andere Namespaces aus.
2. Prozesse innerhalb eines UTS Namespace **können den hostname und den NIS-Domainnamen ändern** mit den Systemaufrufen `sethostname()` bzw. `setdomainname()`. Diese Änderungen sind lokal für das Namespace und wirken sich nicht auf andere Namespaces oder das Host-System aus.
3. Prozesse können zwischen Namespaces wechseln mit dem Systemaufruf `setns()` oder neue Namespaces erstellen mit `unshare()` oder `clone()` unter Verwendung des Flags `CLONE_NEWUTS`. Wenn ein Prozess in ein neues Namespace wechselt oder eines erstellt, verwendet er den hostname und den NIS-Domainnamen, die mit diesem Namespace verknüpft sind.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Indem Sie eine neue Instanz des `/proc`-Dateisystems mounten, wenn Sie den Parameter `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **exakte und isolierte Ansicht der prozessspezifischen Informationen für diesen Namespace** hat.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt aufgrund der Art und Weise, wie Linux mit neuen PID (Process ID)-Namespaces umgeht, ein Fehler auf. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problemerklärung**:

- Der Linux-Kernel erlaubt einem Prozess, neue Namespaces mittels des Systemaufrufs `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespaces initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Das Ausführen von %unshare -p /bin/bash% startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird PID 1. Wenn dieser Prozess beendet wird, löst das die Aufräumarbeiten für den Namespace aus, falls keine weiteren Prozesse vorhanden sind, da PID 1 die spezielle Rolle hat, Waisenprozesse aufzunehmen. Der Linux-Kernel deaktiviert dann die PID-Vergabe in diesem Namespace.

2. **Konsequenz**:

- Das Beenden von PID 1 in einem neuen Namespace führt zur Bereinigung des Flags `PIDNS_HASH_ADDING`. Dadurch schlägt die Funktion `alloc_pid` fehl, wenn sie versucht, einer neu erstellten Prozess eine PID zuzuweisen, und erzeugt den Fehler "Cannot allocate memory".

3. **Lösung**:
- Das Problem lässt sich durch Verwendung der Option `-f` mit `unshare` lösen. Diese Option veranlasst `unshare`, nach der Erstellung des neuen PID-Namespaces einen neuen Prozess zu forken.
- Das Ausführen von %unshare -fp /bin/bash% stellt sicher, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace eingeschlossen, wodurch ein vorzeitiges Beenden von PID 1 verhindert und die normale PID-Zuweisung ermöglicht wird.

Indem sichergestellt wird, dass `unshare` mit der Option `-f` ausgeführt wird, bleibt der neue PID-Namespace korrekt erhalten, sodass `/bin/bash` und seine Subprozesse ohne Auftreten des Speicherzuweisungsfehlers arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Prüfe, in welchem Namespace sich dein Prozess befindet
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Finde alle UTS-Namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### In einen UTS-Namespace eintreten
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Ausnutzung der Host-UTS-Freigabe

Wenn ein Container mit `--uts=host` gestartet wird, tritt er dem UTS-Namespace des Hosts bei, anstatt einen isolierten zu erhalten. Mit capabilities wie `--cap-add SYS_ADMIN` kann Code im Container den Host-Hostname/NIS-Namen über `sethostname()`/`setdomainname()` ändern:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Das Ändern des Hostnamens kann Logs oder Alerts manipulieren, die Clustererkennung verwirren oder TLS-/SSH-Konfigurationen, die auf den Hostnamen vertrauen, außer Funktion setzen.

### Container erkennen, die den UTS-Namespace mit dem Host teilen
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
