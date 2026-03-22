# Maskierte Pfade

{{#include ../../../../banners/hacktricks-training.md}}

Maskierte Pfade sind zur Laufzeit wirksame Schutzmechanismen, die gegenüber dem Container besonders sensitive, kernel-nahe Dateisystemorte verbergen, indem sie z. B. per bind-mount darüber gelegt oder anderweitig unzugänglich gemacht werden. Ziel ist es, zu verhindern, dass eine Workload direkt mit Schnittstellen interagiert, die normale Anwendungen nicht benötigen, insbesondere innerhalb von procfs.

Das ist wichtig, weil viele container escapes und host-impacting tricks damit beginnen, spezielle Dateien unter `/proc` oder `/sys` zu lesen oder zu schreiben. Wenn diese Orte maskiert sind, verliert der Angreifer selbst nach Erlangen von Codeausführung im Container den direkten Zugriff auf einen nützlichen Teil der Kontrolloberfläche des Kernels.

## Funktionsweise

Runtimes maskieren häufig ausgewählte Pfade wie zum Beispiel:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die genaue Liste hängt von der Runtime und der Host-Konfiguration ab. Wichtig ist, dass der Pfad aus Sicht des Containers unzugänglich oder ersetzt ist, obwohl er auf dem Host weiterhin existiert.

## Lab

Untersuche die von Docker exponierte masked-path-Konfiguration:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Untersuche das tatsächliche Mount-Verhalten innerhalb des Workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Sicherheitsauswirkungen

Maskierung erzeugt nicht die primäre Isolationsgrenze, entfernt jedoch mehrere hochwichtige Post-Exploitation-Ziele. Ohne Maskierung kann ein kompromittierter Container in der Lage sein, den Kernelzustand zu inspizieren, sensible Prozess- oder Schlüsselinformationen zu lesen oder mit procfs/sysfs-Objekten zu interagieren, die der Anwendung niemals hätten sichtbar sein dürfen.

## Fehlkonfigurationen

Der Hauptfehler besteht darin, breit angelegte Entmaskierungen von Pfaden aus Komfort- oder Debugging-Gründen vorzunehmen. Bei Podman kann sich das als `--security-opt unmask=ALL` oder als gezielte Entmaskierung zeigen. In Kubernetes kann eine zu breite Offenlegung von proc durch `procMount: Unmasked` auftreten. Ein weiteres ernstes Problem ist das Freigeben des Host-`/proc` oder ` /sys` über ein bind mount, wodurch die Idee einer reduzierten Containeransicht vollständig umgangen wird.

## Missbrauch

Wenn die Maskierung schwach oder nicht vorhanden ist, beginnen Sie damit zu identifizieren, welche sensiblen procfs/sysfs-Pfade direkt erreichbar sind:
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
What these commands can reveal:

- `/proc/timer_list` kann Host-Timer- und Scheduler-Daten offenlegen. Das ist hauptsächlich eine Aufklärungsprimitive, bestätigt aber, dass der Container kernel-nahe Informationen lesen kann, die normalerweise verborgen sind.
- `/proc/keys` ist deutlich sensibler. Je nach Host-Konfiguration kann es Keyring-Einträge, Schlüsselbeschreibungen und Beziehungen zwischen Host-Diensten offenbaren, die das Kernel-Keyring-Subsystem verwenden.
- `/sys/firmware` hilft, Boot-Modus, Firmware-Schnittstellen und Plattformdetails zu identifizieren, die für Host-Fingerprinting nützlich sind und um zu verstehen, ob die Workload Zustand auf Host-Ebene sieht.
- `/proc/config.gz` kann die laufende Kernel-Konfiguration offenlegen, was wertvoll ist, um sie mit öffentlichen Kernel-Exploit-Voraussetzungen abzugleichen oder zu verstehen, warum eine bestimmte Funktion erreichbar ist.
- `/proc/sched_debug` legt Scheduler-Zustand offen und umgeht oft die intuitive Erwartung, dass der PID-Namespace nicht verwandte Prozessinformationen vollständig verbergen sollte.

Interessante Ergebnisse beinhalten direkte Lesezugriffe auf diese Dateien, Hinweise darauf, dass die Daten zum Host und nicht zu einer eingeschränkten Container-Ansicht gehören, oder Zugriff auf andere procfs/sysfs-Pfade, die standardmäßig häufig maskiert sind.

## Checks

Der Zweck dieser Checks ist festzustellen, welche Pfade die Runtime bewusst verborgen hat und ob die aktuelle Workload noch ein reduziertes, kernel-nahes Dateisystem sieht.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Was hier interessant ist:

- Eine lange masked-path list ist in gehärteten runtimes normal.
- Fehlende Maskierung bei sensiblen procfs-Einträgen verdient genauere Untersuchung.
- Wenn ein sensibler Pfad zugänglich ist und der container außerdem starke capabilities oder breite mounts hat, ist die Exposition gravierender.

## Standardwerte der Runtime

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Docker definiert eine standardmäßige masked path list | Exponieren von host proc/sys mounts, `--privileged` |
| Podman | Standardmäßig aktiviert | Podman wendet standardmäßige masked paths an, sofern sie nicht manuell unmasked werden | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Erbt Runtime-Defaults | Verwendet das Maskierungsverhalten des zugrunde liegenden runtimes, sofern Pod-Einstellungen die proc exposure schwächen | `procMount: Unmasked`, privileged workload patterns, broad host mounts |
| containerd / CRI-O unter Kubernetes | Runtime-Standard | Wendet normalerweise OCI/runtime masked paths an, sofern nicht überschrieben | direkte Änderungen an der runtime-Konfiguration, gleiche Kubernetes-weakening-paths |

Masked paths sind in der Regel standardmäßig vorhanden. Das hauptsächliche betriebliche Problem ist nicht ihr Fehlen im runtime, sondern bewusstes unmasking oder Host-Bind-Mounts, die den Schutz aufheben.
{{#include ../../../../banners/hacktricks-training.md}}
