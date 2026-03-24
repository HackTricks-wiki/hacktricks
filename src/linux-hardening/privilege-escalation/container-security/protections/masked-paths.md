# Maskierte Pfade

{{#include ../../../../banners/hacktricks-training.md}}

Maskierte Pfade sind Laufzeitschutzmechanismen, die besonders sensible, kernel‑nahe Dateisystempfade vor dem Container verbergen, indem sie mittels bind-mounting darüber gelegt oder auf andere Weise unzugänglich gemacht werden. Ziel ist es, zu verhindern, dass ein Workload direkt mit Schnittstellen interagiert, die normale Anwendungen nicht benötigen — insbesondere innerhalb von procfs.

Das ist wichtig, weil viele container escapes und host-beeinflussende Tricks damit beginnen, besondere Dateien unter `/proc` oder `/sys` zu lesen oder zu schreiben. Wenn diese Orte maskiert sind, verliert der Angreifer selbst nach dem Erlangen von Codeausführung im Container den direkten Zugriff auf einen nützlichen Teil der Kernel‑Kontrolloberfläche.

## Funktionsweise

Runtimes maskieren üblicherweise ausgewählte Pfade wie:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die genaue Liste hängt von der Runtime und der Hostkonfiguration ab. Wichtig ist, dass der Pfad aus Sicht des Containers unzugänglich wird oder ersetzt wird, obwohl er auf dem Host weiterhin existiert.

## Labor

Untersuche die von Docker bereitgestellte masked-path-Konfiguration:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Untersuche das tatsächliche Mount-Verhalten innerhalb des Workloads:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Sicherheitsauswirkung

Maskierung schafft nicht die primäre Isolationsgrenze, entfernt aber mehrere hochrangige post-exploitation-Ziele. Ohne Maskierung kann ein kompromittierter Container möglicherweise den Kernel-Zustand untersuchen, sensible Prozess- oder Schlüsselinformationen auslesen oder mit procfs/sysfs-Objekten interagieren, die der Anwendung niemals sichtbar sein sollten.

## Fehlkonfigurationen

Der Hauptfehler besteht darin, breite Klassen von Pfaden aus Bequemlichkeit oder zum Debugging zu entmaskieren. In Podman kann sich dies als `--security-opt unmask=ALL` oder als gezieltes unmasking zeigen. In Kubernetes kann eine zu breite Offenlegung von proc durch `procMount: Unmasked` auftreten. Ein weiteres ernstes Problem ist das Freilegen des Host-`/proc` oder `/sys` durch ein Bind-Mount, was die Idee einer reduzierten Containeransicht vollständig umgeht.

## Missbrauch

Wenn die Maskierung schwach oder nicht vorhanden ist, beginnen Sie damit, zu identifizieren, welche sensiblen procfs/sysfs-Pfade direkt erreichbar sind:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Wenn ein vermeintlich maskierter Pfad zugänglich ist, untersuche ihn sorgfältig:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Was diese Befehle offenbaren können:

- `/proc/timer_list` kann Host-Timer- und Scheduler-Daten offenlegen. Das ist größtenteils eine Aufklärungsprimitive, bestätigt aber, dass der Container kernel-nahe Informationen lesen kann, die normalerweise verborgen sind.
- `/proc/keys` ist deutlich sensibler. Abhängig von der Host-Konfiguration kann es Keyring-Einträge, Key-Beschreibungen und Beziehungen zwischen Host-Services offenlegen, die das Kernel-Keyring-Subsystem nutzen.
- `/sys/firmware` hilft dabei, den Boot-Modus, Firmware-Schnittstellen und Plattformdetails zu identifizieren, die für Host-Fingerprinting nützlich sind und um zu beurteilen, ob die Workload Host‑Zustand sieht.
- `/proc/config.gz` kann die laufende Kernel-Konfiguration offenlegen, was wertvoll ist, um Voraussetzungen öffentlicher Kernel-Exploits abzugleichen oder zu verstehen, warum ein bestimmtes Feature erreichbar ist.
- `/proc/sched_debug` legt Scheduler-Zustand offen und unterläuft oft die intuitive Erwartung, dass der PID-Namespace nicht zugehörige Prozessinformationen vollständig verbergen sollte.

Interessante Ergebnisse sind direkte Auslesungen dieser Dateien, Hinweise darauf, dass die Daten dem Host und nicht einer eingeschränkten Container-Sicht gehören, oder der Zugriff auf andere procfs/sysfs-Orte, die üblicherweise standardmäßig maskiert sind.

## Prüfungen

Ziel dieser Prüfungen ist festzustellen, welche Pfade die Runtime absichtlich ausgeblendet hat und ob die aktuelle Workload immer noch ein reduziertes kernel‑nahes Dateisystem sieht.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Was hier interessant ist:

- Eine lange masked-path-Liste ist in gehärteten Runtimes normal.
- Fehlende Maskierung sensibler procfs-Einträge sollte näher untersucht werden.
- Wenn ein sensibler Pfad zugänglich ist und der Container außerdem erweiterte capabilities oder weitreichende mounts hat, ist die Exposition relevanter.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Docker definiert eine standardmäßige masked-path-Liste | Freigabe von Host proc/sys mounts, `--privileged` |
| Podman | Standardmäßig aktiviert | Podman wendet standardmäßige masked paths an, sofern nicht manuell aufgehoben | `--security-opt unmask=ALL`, gezielte Aufhebung, `--privileged` |
| Kubernetes | Erbt die Runtime-Defaults | Verwendet das Masking-Verhalten der zugrunde liegenden Runtime, sofern Pod-Einstellungen die proc-Exposition nicht abschwächen | `procMount: Unmasked`, privilegierte Workload-Muster, weitreichende Host-Mounts |
| containerd / CRI-O under Kubernetes | Runtime-Standard | Wendet normalerweise OCI/runtime masked paths an, sofern nicht überschrieben | Direkte Änderungen an der Runtime-Konfiguration, gleiche Kubernetes-Abschwächungsmechanismen |

Masked paths sind in der Regel standardmäßig vorhanden. Das eigentliche operative Problem ist nicht das Fehlen in der Runtime, sondern das gezielte Aufheben der Maskierung oder Host-Bind-Mounts, die den Schutz aufheben.
{{#include ../../../../banners/hacktricks-training.md}}
