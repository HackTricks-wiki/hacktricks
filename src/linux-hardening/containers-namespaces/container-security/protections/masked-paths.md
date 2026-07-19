# Maskierte Pfade

{{#include ../../../../banners/hacktricks-training.md}}

Maskierte Pfade sind Laufzeitschutzmaßnahmen, die besonders sensible, kernelnahe Dateisystempfade vor dem Container verbergen, indem sie darüber Bind-Mounts erstellen oder sie anderweitig unzugänglich machen. Ziel ist es, zu verhindern, dass eine Workload direkt mit Schnittstellen interagiert, die gewöhnliche Anwendungen nicht benötigen, insbesondere innerhalb von procfs.

Das ist wichtig, weil viele Container-Escapes und hostbeeinflussende Tricks damit beginnen, spezielle Dateien unter `/proc` oder `/sys` zu lesen oder zu schreiben. Wenn diese Pfade maskiert sind, verliert der Angreifer direkten Zugriff auf einen nützlichen Teil der Kernel-Kontrolloberfläche, selbst nachdem er Codeausführung innerhalb des Containers erlangt hat.

## Funktionsweise

Runtimes maskieren häufig ausgewählte Pfade wie:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die genaue Liste hängt von der Runtime und der Host-Konfiguration ab. Die entscheidende Eigenschaft besteht darin, dass der Pfad aus Sicht des Containers unzugänglich oder ersetzt wird, obwohl er auf dem Host weiterhin existiert.

## Lab

Untersuche die von Docker bereitgestellte Konfiguration der maskierten Pfade:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Untersuchen Sie das tatsächliche Mount-Verhalten innerhalb der Workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Sicherheitsauswirkungen

Maskierung bildet nicht die zentrale Isolationsgrenze, entfernt jedoch mehrere hochwertige Post-Exploitation-Ziele. Ohne Maskierung kann ein kompromittierter Container möglicherweise den Kernel-Zustand untersuchen, vertrauliche Prozess- oder Keying-Informationen lesen oder mit procfs/sysfs-Objekten interagieren, die für die Anwendung niemals sichtbar sein sollten.

## Fehlkonfigurationen

Der häufigste Fehler besteht darin, breite Pfadklassen aus Bequemlichkeit oder zu Debugging-Zwecken von der Maskierung auszunehmen. In Podman kann dies als `--security-opt unmask=ALL` oder als gezielte Aufhebung der Maskierung auftreten. In Kubernetes kann eine übermäßig breite proc-Exposition durch `procMount: Unmasked` entstehen. Ein weiteres schwerwiegendes Problem ist die Freigabe von `/proc` oder `/sys` des Hosts über einen Bind-Mount, wodurch die Idee einer eingeschränkten Container-Ansicht vollständig umgangen wird.

## Missbrauch

Wenn die Maskierung schwach oder nicht vorhanden ist, sollte zunächst ermittelt werden, welche sensiblen procfs/sysfs-Pfade direkt erreichbar sind:
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

- `/proc/timer_list` kann Timer- und Scheduler-Daten des Hosts offenlegen. Dies ist hauptsächlich ein Reconnaissance-Primitiv, bestätigt aber, dass der Container kernelnahe Informationen lesen kann, die normalerweise verborgen sind.
- `/proc/keys` ist wesentlich sensibler. Abhängig von der Host-Konfiguration kann es Keyring-Einträge, Schlüsselbeschreibungen und Beziehungen zwischen Host-Diensten offenlegen, die das Kernel-Keyring-Subsystem verwenden.
- `/sys/firmware` hilft dabei, den Boot-Modus, Firmware-Schnittstellen und Plattformdetails zu identifizieren, die für das Fingerprinting des Hosts nützlich sind und dabei helfen zu verstehen, ob die Workload den Zustand auf Host-Ebene sieht.
- `/proc/config.gz` kann die Konfiguration des laufenden Kernels offenlegen. Dies ist wertvoll, um Voraussetzungen für öffentliche Kernel-Exploits abzugleichen oder zu verstehen, warum ein bestimmtes Feature erreichbar ist.
- `/proc/sched_debug` legt den Scheduler-Zustand offen und umgeht häufig die intuitive Erwartung, dass der PID namespace Informationen über nicht zugehörige Prozesse vollständig verbergen sollte.

Interessante Ergebnisse sind direkte Lesezugriffe auf diese Dateien, Hinweise darauf, dass die Daten vom Host statt aus einer eingeschränkten Container-Ansicht stammen, oder der Zugriff auf andere procfs/sysfs-Pfade, die standardmäßig häufig maskiert werden.

## Prüfungen

Der Zweck dieser Prüfungen besteht darin festzustellen, welche Pfade die Runtime absichtlich verborgen hat und ob die aktuelle Workload weiterhin ein reduziertes kernelnahes Dateisystem sieht.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Was hier interessant ist:

- Eine lange Liste maskierter Pfade ist in gehärteten Runtimes normal.
- Fehlende Maskierung bei sensiblen procfs-Einträgen verdient eine genauere Untersuchung.
- Wenn ein sensibler Pfad zugänglich ist und der Container außerdem über starke Capabilities oder weitreichende Mounts verfügt, ist die Offenlegung relevanter.

## Runtime-Defaults

| Runtime / Plattform | Standardstatus | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Docker definiert eine Standardliste maskierter Pfade | Offenlegen von Host-proc/sys-Mounts, `--privileged` |
| Podman | Standardmäßig aktiviert | Podman wendet standardmäßige maskierte Pfade an, sofern diese nicht manuell entmaskiert werden | `--security-opt unmask=ALL`, gezieltes Entmaskieren, `--privileged` |
| Kubernetes | Übernimmt Runtime-Defaults | Verwendet das Maskierungsverhalten der zugrunde liegenden Runtime, sofern Pod-Einstellungen die proc-Exposition nicht abschwächen | `procMount: Unmasked`, privilegierte Workload-Muster, weitreichende Host-Mounts |
| containerd / CRI-O unter Kubernetes | Runtime-Standard | Wendet normalerweise OCI-/Runtime-maskierte Pfade an, sofern dies nicht überschrieben wird | Direkte Änderungen an der Runtime-Konfiguration, dieselben Kubernetes-Abschwächungspfade |

Maskierte Pfade sind normalerweise standardmäßig vorhanden. Das wesentliche operative Problem ist nicht ihr Fehlen in der Runtime, sondern ein bewusstes Entmaskieren oder Host-Bind-Mounts, die den Schutz umgehen.
{{#include ../../../../banners/hacktricks-training.md}}
