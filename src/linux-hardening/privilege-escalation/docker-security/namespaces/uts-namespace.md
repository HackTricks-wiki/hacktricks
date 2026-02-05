# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Ein UTS (UNIX Time-Sharing System) namespace ist eine Linux-Kernel-Funktion, die i**Isolierung von zwei Systemidentifikatoren** bereitstellt: den **Hostname** und den **NIS** (Network Information Service) Domänennamen. Diese Isolierung ermöglicht es jedem UTS namespace, seinen **eigenen unabhängigen Hostname und NIS-Domänennamen** zu haben, was besonders in Containerisierungsszenarien nützlich ist, in denen jeder Container als ein separates System mit eigenem Hostname erscheinen sollte.

### Wie es funktioniert:

1. Wenn ein neuer UTS namespace erstellt wird, beginnt er mit einer **Kopie des Hostname- und NIS-Domänennamens aus seinem übergeordneten Namespace**. Das bedeutet, dass der neue Namespace bei der Erstellung s**teilt die gleichen Identifikatoren mit seinem übergeordneten Namespace**. Allerdings wirken sich spätere Änderungen am Hostname oder NIS-Domänennamen innerhalb des Namespace nicht auf andere Namespaces aus.
2. Prozesse innerhalb eines UTS namespace **können den Hostname und den NIS-Domänennamen ändern** mit den Systemaufrufen `sethostname()` beziehungsweise `setdomainname()`. Diese Änderungen sind lokal für den Namespace und betreffen nicht andere Namespaces oder das Hostsystem.
3. Prozesse können zwischen Namespaces wechseln mit dem Systemaufruf `setns()` oder neue Namespaces erstellen mit den Systemaufrufen `unshare()` oder `clone()` und dem Flag `CLONE_NEWUTS`. Wenn ein Prozess in einen neuen Namespace wechselt oder einen erstellt, beginnt er den Hostname und den NIS-Domänennamen zu verwenden, die mit diesem Namespace verknüpft sind.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Indem Sie mit dem Parameter `--mount-proc` eine neue Instanz des `/proc`-Dateisystems mounten, stellen Sie sicher, dass das neue Mount-Namespace eine genaue und isolierte Sicht auf die prozessspezifischen Informationen dieses Namespace hat.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler auf, der durch die Art und Weise entsteht, wie Linux neue PID (Process ID) Namespaces handhabt. Die wichtigsten Details und die Lösung sind unten zusammengefasst:

1. **Problem-Erklärung**:

- Der Linux-Kernel erlaubt einem Prozess, neue Namespaces mittels des `unshare` Systemaufrufs zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespace initiiert (als "unshare"-Prozess bezeichnet), tritt jedoch nicht in das neue Namespace ein; nur seine Kindprozesse tun das.
- Das Ausführen von %unshare -p /bin/bash% startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird PID 1. Wenn dieser Prozess beendet wird, löst das die Aufräumarbeiten des Namespaces aus, falls keine weiteren Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu adoptieren. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Konsequenz**:

- Das Beenden von PID 1 in einem neuen Namespace führt zum Entfernen des `PIDNS_HASH_ADDING` Flags. Dadurch schlägt die Funktion `alloc_pid` fehl, wenn sie versucht, einer neu erstellten Prozess einen PID zuzuweisen, und es entsteht der Fehler "Cannot allocate memory".

3. **Lösung**:
- Das Problem lässt sich beheben, indem man `unshare` mit der Option `-f` ausführt. Diese Option veranlasst `unshare`, nach dem Erstellen des neuen PID-Namespace einen neuen Prozess zu forkieren.
- Das Ausführen von %unshare -fp /bin/bash% sorgt dafür, dass der `unshare`-Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse werden dann sicher innerhalb dieses neuen Namespaces gehalten, wodurch das vorzeitige Beenden von PID 1 verhindert und die normale PID-Zuweisung ermöglicht wird.

Wenn `unshare` mit dem Flag `-f` ausgeführt wird, bleibt das neue PID-Namespace korrekt erhalten, sodass `/bin/bash` und dessen Subprozesse ohne das Auftreten des Speicher-Allokationsfehlers arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Prüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Alle UTS-Namespaces finden
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### In ein UTS namespace eintreten
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Missbrauch der UTS-Freigabe des Hosts

Wenn ein Container mit `--uts=host` gestartet wird, tritt er dem UTS-Namespace des Hosts bei, anstatt einen isolierten zu erhalten. Mit Fähigkeiten wie `--cap-add SYS_ADMIN` kann Code im Container den Host-Hostname/NIS-Namen über `sethostname()`/`setdomainname()` ändern:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Das Ändern des host name kann logs/alerts verfälschen, cluster discovery stören oder TLS/SSH configs brechen, die den hostname pinnen.

### Erkennen von containers, die UTS mit dem host teilen
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
