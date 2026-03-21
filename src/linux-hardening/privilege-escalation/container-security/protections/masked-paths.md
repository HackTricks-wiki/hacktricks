# Maskierte Pfade

{{#include ../../../../banners/hacktricks-training.md}}

Maskierte Pfade sind Laufzeitschutzmechanismen, die besonders sensible, kernel-exponierte Dateisystemorte vor dem Container verbergen, indem sie darüber gebind-mountet oder anderweitig unzugänglich gemacht werden. Der Zweck ist, zu verhindern, dass ein Workload direkt mit Schnittstellen interagiert, die gewöhnliche Anwendungen nicht benötigen — besonders innerhalb von procfs.

Das ist wichtig, weil viele container escapes und host-beeinflussende Tricks damit beginnen, spezielle Dateien unter `/proc` oder `/sys` zu lesen oder zu schreiben. Wenn diese Orte maskiert sind, verliert der Angreifer selbst nach Erlangen von Codeausführung innerhalb des Containers den direkten Zugriff auf einen nützlichen Teil der Kernel-Kontrollfläche.

## Funktionsweise

Runtimes maskieren üblicherweise ausgewählte Pfade wie:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die genaue Liste hängt von der Runtime und der Host-Konfiguration ab. Wichtig ist die Eigenschaft, dass der Pfad aus Sicht des Containers unzugänglich wird oder ersetzt ist, obwohl er auf dem Host weiterhin existiert.

## Lab

Untersuche die von Docker exponierte masked-path-Konfiguration:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Untersuche das tatsächliche mount-Verhalten innerhalb der Workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Sicherheitsauswirkungen

Masking schafft nicht die primäre Isolationsgrenze, entfernt aber mehrere hochwerte post-exploitation-Ziele. Ohne Masking kann ein kompromittierter container den Kernel-Zustand inspizieren, sensible Prozess- oder Schlüsselinformationen lesen oder mit procfs/sysfs-Objekten interagieren, die der Anwendung niemals hätten sichtbar sein dürfen.

## Fehlkonfigurationen

Der Hauptfehler ist das Entmaskieren breiter Pfadklassen aus Bequemlichkeit oder zum Debugging. In Podman kann sich das als `--security-opt unmask=ALL` oder als gezieltes Entmaskieren zeigen. In Kubernetes kann eine zu breite proc-Freigabe über `procMount: Unmasked` auftreten. Ein weiteres ernstes Problem ist das Exponieren des Host-`/proc` oder ` /sys` durch ein bind mount, was die Idee einer reduzierten Container-Ansicht vollständig umgeht.

## Missbrauch

Wenn Masking schwach oder nicht vorhanden ist, beginnen Sie damit zu identifizieren, welche sensiblen procfs/sysfs-Pfade direkt erreichbar sind:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Wenn ein angeblich maskierter Pfad zugänglich ist, untersuche ihn sorgfältig:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Was diese Befehle offenlegen können:

- `/proc/timer_list` kann Host-Timer- und Scheduler-Daten offenlegen. Dies ist hauptsächlich ein primitives Aufklärungswerkzeug, bestätigt jedoch, dass der Container kernel-nahe Informationen lesen kann, die normalerweise verborgen sind.
- `/proc/keys` ist deutlich sensibler. Je nach Host-Konfiguration kann es keyring-Einträge, Schlüsselbeschreibungen und Beziehungen zwischen Host-Diensten offenbaren, die das kernel keyring subsystem verwenden.
- `/sys/firmware` hilft beim Identifizieren des Boot-Modus, von Firmware-Schnittstellen und Plattformdetails, die nützlich für Host-Fingerprinting sind und um zu verstehen, ob die workload Host-Level-Zustand sieht.
- `/proc/config.gz` kann die laufende Kernel-Konfiguration offenbaren, was wertvoll ist, um öffentliche Kernel-Exploit-Voraussetzungen abzugleichen oder zu verstehen, warum ein bestimmtes Feature erreichbar ist.
- `/proc/sched_debug` legt Scheduler-Zustand offen und umgeht oft die intuitive Erwartung, dass der PID-Namespace nicht zusammenhängende Prozessinformationen vollständig verbergen sollte.

Interessante Befunde umfassen direkte Lesezugriffe auf diese Dateien, Hinweise darauf, dass die Daten dem Host und nicht einer eingeschränkten Container-Ansicht gehören, oder Zugriff auf andere procfs/sysfs-Pfade, die üblicherweise standardmäßig maskiert sind.

## Prüfungen

Der Zweck dieser Prüfungen ist zu bestimmen, welche Pfade die Runtime bewusst verborgen hat und ob die aktuelle workload weiterhin ein eingeschränktes kernel-nahes Dateisystem sieht.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Was hier interessant ist:

- Eine lange masked-path-Liste ist in gehärteten Runtimes normal.
- Fehlende Maskierung sensibler procfs-Einträge verdient eine genauere Prüfung.
- Wenn ein sensibler Pfad zugänglich ist und der Container außerdem umfangreiche capabilities oder breite mounts hat, ist die Exposition gravierender.

## Runtime-Standardeinstellungen

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Docker definiert eine Standardliste von masked paths | Freigabe von Host-proc/sys-Mounts, `--privileged` |
| Podman | Standardmäßig aktiviert | Podman wendet standardmäßige masked paths an, sofern diese nicht manuell unmasked werden | `--security-opt unmask=ALL`, gezieltes unmasking, `--privileged` |
| Kubernetes | Erbt die Runtime-Standardeinstellungen | Verwendet das Maskierungsverhalten des zugrunde liegenden Runtimes, sofern Pod-Einstellungen die proc-Exposition nicht abschwächen | `procMount: Unmasked`, privileged workload patterns, breite Host-Mounts |
| containerd / CRI-O unter Kubernetes | Runtime-Standard | Wendet in der Regel OCI/runtime masked paths an, sofern nicht überschrieben | direkte Änderungen der Runtime-Konfiguration, dieselben Kubernetes-Schwächungsmuster |

Masked paths sind in der Regel standardmäßig vorhanden. Das Hauptproblem im Betrieb ist nicht ihr Fehlen in der Runtime, sondern das gezielte unmasking oder Host-Bind-Mounts, die den Schutz aufheben.
