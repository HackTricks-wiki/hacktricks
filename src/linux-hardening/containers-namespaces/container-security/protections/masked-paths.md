# Maskierte Pfade

{{#include ../../../../banners/hacktricks-training.md}}

Maskierte Pfade sind Laufzeitschutzmechanismen, die besonders sensible kernelnahe Dateisystempfade vor dem Container verbergen, indem sie darüber Bind-Mounts einhängen oder sie anderweitig unzugänglich machen. Dadurch soll verhindert werden, dass eine Workload direkt mit Schnittstellen interagiert, die gewöhnliche Anwendungen nicht benötigen, insbesondere innerhalb von procfs.

Das ist wichtig, weil viele Container-Escapes und Tricks mit Auswirkungen auf den Host damit beginnen, spezielle Dateien unter `/proc` oder `/sys` zu lesen oder zu schreiben. Wenn diese Pfade maskiert sind, verliert der Angreifer selbst nach der Erlangung von Codeausführung innerhalb des Containers den direkten Zugriff auf einen nützlichen Teil der Kernel-Kontrolloberfläche.

## Funktionsweise

Runtimes maskieren häufig ausgewählte Pfade wie:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die genaue Liste hängt von der Runtime und der Host-Konfiguration ab. Die wichtige Eigenschaft besteht darin, dass der Pfad aus Sicht des Containers unzugänglich oder ersetzt wird, obwohl er auf dem Host weiterhin existiert.

## Lab

Untersuche die von Docker bereitgestellte Konfiguration der maskierten Pfade:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Untersuche das tatsächliche Mount-Verhalten innerhalb des Workloads:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Sicherheitsauswirkungen

Maskierung bildet nicht die primäre Isolationsgrenze, entfernt jedoch mehrere hochwertige Ziele für die post-exploitation. Ohne Maskierung kann ein kompromittierter Container möglicherweise den Kernel-Zustand untersuchen, vertrauliche Prozess- oder Keying-Informationen lesen oder mit procfs/sysfs-Objekten interagieren, die für die Anwendung niemals sichtbar sein sollten.

## Fehlkonfigurationen

Der häufigste Fehler besteht darin, aus Gründen der Bequemlichkeit oder zu Debugging-Zwecken weitreichende Pfadklassen zu entmaskieren. In Podman kann dies als `--security-opt unmask=ALL` oder durch gezielte Entmaskierung auftreten. In Kubernetes kann eine übermäßig weitreichende proc-Freigabe durch `procMount: Unmasked` entstehen. Ein weiteres gravierendes Problem ist die Freigabe von Host-`/proc` oder `/sys` über einen Bind-Mount, wodurch die Idee einer eingeschränkten Container-Sicht vollständig umgangen wird.

## Missbrauch

Wenn die Maskierung schwach oder nicht vorhanden ist, sollte zunächst ermittelt werden, welche sensiblen procfs/sysfs-Pfade direkt erreichbar sind:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Wenn ein vermeintlich maskierter Pfad zugänglich ist, untersuchen Sie ihn sorgfältig:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Was diese Befehle offenlegen können:

- `/proc/timer_list` kann Timer- und Scheduler-Daten des Hosts offenlegen. Dies ist größtenteils ein Reconnaissance-Primitive, bestätigt jedoch, dass der Container auf kernelnahe Informationen zugreifen kann, die normalerweise verborgen sind.
- `/proc/keys` ist deutlich sensibler. Abhängig von der Host-Konfiguration kann die Datei Keyring-Einträge, Schlüsselbeschreibungen und Beziehungen zwischen Host-Services offenlegen, die das Kernel-Keyring-Subsystem verwenden.
- `/sys/firmware` hilft dabei, den Boot-Modus, Firmware-Schnittstellen und Plattformdetails zu identifizieren, die für das Host-Fingerprinting und zum Verständnis nützlich sind, ob die Workload den Status auf Host-Ebene sieht.
- `/proc/config.gz` kann die Konfiguration des laufenden Kernels offenlegen. Dies ist nützlich, um Voraussetzungen öffentlicher Kernel-Exploits abzugleichen oder zu verstehen, warum ein bestimmtes Feature erreichbar ist.
- `/proc/sched_debug` legt den Scheduler-Status offen und widerspricht häufig der intuitiven Erwartung, dass der PID namespace Informationen über nicht zugehörige Prozesse vollständig verbergen sollte.

Interessante Ergebnisse umfassen direkte Lesezugriffe auf diese Dateien, Hinweise darauf, dass die Daten vom Host und nicht aus einer eingeschränkten Container-Ansicht stammen, oder den Zugriff auf andere procfs-/sysfs-Pfade, die standardmäßig häufig maskiert werden.

## Checks

Der Zweck dieser Checks besteht darin festzustellen, welche Pfade die Runtime absichtlich verborgen hat und ob die aktuelle Workload weiterhin ein reduziertes kernelbezogenes Dateisystem sieht.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Was hier interessant ist:

- Eine lange Liste maskierter Pfade ist in gehärteten Runtimes normal.
- Fehlende Maskierung bei sensiblen procfs-Einträgen verdient eine genauere Untersuchung.
- Wenn ein sensibler Pfad zugänglich ist und der Container außerdem über starke Capabilities oder weitreichende Mounts verfügt, ist die Exposition relevanter.

## Runtime-Standards

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Docker definiert eine standardmäßige Liste maskierter Pfade | Host-Proc-/Sys-Mounts freigeben, `--privileged` |
| Podman | Standardmäßig aktiviert | Podman wendet standardmäßige maskierte Pfade an, sofern sie nicht manuell unmasked werden | `--security-opt unmask=ALL`, gezieltes Unmasking, `--privileged` |
| Kubernetes | Erbt die Runtime-Standards | Verwendet das Maskierungsverhalten der zugrunde liegenden Runtime, sofern Pod-Einstellungen die Proc-Exposition nicht abschwächen | `procMount: Unmasked`, privilegierte Workload-Muster, weitreichende Host-Mounts |
| containerd / CRI-O unter Kubernetes | Runtime-Standard | Wendet normalerweise OCI-/Runtime-masked paths an, sofern dies nicht überschrieben wird | Direkte Änderungen an der Runtime-Konfiguration, dieselben Kubernetes-Abschwächungspfade |

Masked paths sind normalerweise standardmäßig vorhanden. Das Hauptproblem im Betrieb ist nicht ihr Fehlen in der Runtime, sondern ein absichtliches Unmasking oder Host-Bind-Mounts, die den Schutz außer Kraft setzen.

{{#include ../../../../banners/hacktricks-training.md}}
