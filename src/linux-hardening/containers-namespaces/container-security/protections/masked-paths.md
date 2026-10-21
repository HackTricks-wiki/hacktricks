# Maskierte Pfade

{{#include ../../../../banners/hacktricks-training.md}}

Maskierte Pfade sind Laufzeitschutzmaßnahmen, die besonders sensible, kernelnahe Dateisystempfade vor dem Container verbergen, indem sie diese per Bind-Mount überdecken oder anderweitig unzugänglich machen. Die OCI-Runtime-Spezifikation definiert `maskedPaths` als absolute Pfade, die innerhalb des Containers nicht lesbar sein dürfen. <sup>[[1]](#references)</sup>

Das ist wichtig, weil viele Container-Escapes und Tricks mit Auswirkungen auf den Host damit beginnen, spezielle Dateien unter `/proc` oder `/sys` zu lesen oder zu schreiben. Sind diese Pfade maskiert, verliert der Angreifer direkten Zugriff auf einen nützlichen Teil der Kernel-Kontrollfläche – selbst wenn er bereits Code im Container ausführen kann.

## Funktionsweise

Runtimes maskieren häufig ausgewählte Pfade wie:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Die genaue Liste hängt von der Runtime und der Host-Konfiguration ab. Entscheidend ist, dass der Pfad aus Sicht des Containers unzugänglich oder ersetzt wird, obwohl er auf dem Host weiterhin existiert.

## Labor

Untersuche die von Docker offengelegte Konfiguration der maskierten Pfade:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Untersuche das tatsächliche Mount-Verhalten innerhalb des Workloads:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Ein aufgelisteter Pfad ist nicht zwangsläufig lesbar: runc kann eine Datei mit einem `/dev/null`-Bind-Mount und ein Verzeichnis mit einem schreibgeschützten, leeren tmpfs maskieren. Prüfe den genauen Mountpoint, nicht nur, ob `ls` erfolgreich ist. <sup>[[4]](#references)</sup>

## Sicherheitsauswirkungen

Maskierung schafft nicht die zentrale Isolationsgrenze, entfernt aber mehrere hochwertige Ziele für die Post-Exploitation. Ohne Maskierung kann ein kompromittierter Container möglicherweise den Kernelzustand untersuchen, sensible Prozess- oder Schlüsselungsinformationen lesen oder mit procfs-/sysfs-Objekten interagieren, die für die Anwendung niemals sichtbar sein sollten.

## Fehlkonfigurationen

Der häufigste Fehler ist, aus Gründen der Bequemlichkeit oder zum Debugging ganze Pfadklassen freizugeben. In Podman kann dies als `--security-opt unmask=ALL` oder gezieltes Unmaskieren auftreten. <sup>[[2]](#references)</sup> In Kubernetes kann eine übermäßig weitreichende proc-Freigabe über `procMount: Unmasked` erfolgen; aktuelle Kubernetes-Versionen verlangen für diese Einstellung `spec.hostUsers: false` (einen User Namespace), während Versionen 1.12–1.29 diese Anforderung nicht durchsetzten. <sup>[[3]](#references)</sup> Ein weiteres schwerwiegendes Problem ist die Freigabe des Host-`/proc` oder `/sys` über einen Bind-Mount, wodurch die Idee einer eingeschränkten Container-Ansicht vollständig umgangen wird.

## Missbrauch

Wenn die Maskierung schwach oder nicht vorhanden ist, ermittle zuerst, welche sensiblen procfs-/sysfs-Pfade direkt erreichbar sind:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Wenn ein vermeintlich maskierter Pfad zugänglich ist, untersuche ihn sorgfältig:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Was diese Befehle offenlegen können:

- `/proc/timer_list` kann Timer- und Scheduler-Daten des Hosts offenlegen. Dies ist hauptsächlich ein Reconnaissance-Primitiv, bestätigt aber, dass der Container kernelnahe Informationen lesen kann, die normalerweise verborgen sind.
- `/proc/keys` listet nur Metadaten zu Schlüsseln auf, für die der Leser **view**-Berechtigung hat und sofern die LSM-Prüfungen dies zulassen. Es kann Schlüsseltypen und Beschreibungen offenlegen, gibt aber keine Schlüssel-Payloads aus. <sup>[[6]](#references)</sup>
- `/sys/firmware` hilft dabei, den Bootmodus, Firmware-Schnittstellen und Plattformdetails zu ermitteln, die für das Fingerprinting des Hosts nützlich sind und Aufschluss darüber geben, ob der Workload den Zustand auf Host-Ebene sieht.
- `/proc/config.gz` kann die Konfiguration des laufenden Kernels offenlegen. Das ist nützlich, um Voraussetzungen für öffentliche Kernel-Exploits abzugleichen oder zu verstehen, warum eine bestimmte Funktion erreichbar ist.
- `/proc/sched_debug` legt den Scheduler-Zustand offen und umgeht häufig die intuitive Erwartung, dass der PID-Namespace Informationen über nicht zugehörige Prozesse vollständig verbergen sollte.

Interessante Ergebnisse sind direkte Lesezugriffe auf diese Dateien, Hinweise darauf, dass die Daten zum Host und nicht zu einer eingeschränkten Container-Ansicht gehören, oder Zugriff auf andere procfs-/sysfs-Pfade, die standardmäßig häufig maskiert sind.

### Race um die Maskierungsquelle während des Containerstarts

In anfälligen runc-Implementierungen hängen Dateimasken vom Inode des `/dev/null` des Containers ab. Ein Angreifer, der parallel gestartete Container mit gemeinsamen Mounts einrichten kann, darunter parallele BuildKit-Schritte, kann den Startvorgang ausnutzen und `/dev/null` entfernen, bevor runc die Datei über maskierte procfs-Dateien bindet. Die Laufzeitumgebung behandelt die fehlende **Quelle** dann so, als wäre ein Maskierungsziel nicht vorhanden, und überspringt diese Dateimasken stillschweigend. Der Fehler hängt von einem Race während der Laufzeitkonfiguration ab; das Entfernen von `/dev/null` nach dem Start hebt eine bereits eingerichtete Maske nicht auf. <sup>[[4]](#references)</sup>

Vergleiche nach einem kontrollierten Test die angeforderte Maskierungsliste mit den exakten Mountpoints im neuen Container. <sup>[[4]](#references)</sup> `findmnt -M` prüft den angegebenen Mountpoint, statt auf einen übergeordneten Mount zurückzufallen. Wenn `findmnt` fehlt, prüfe `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> Ein erfolgreicher `ls`-Aufruf oder ein leeres Ergebnis von `cat` beweist nicht, dass die Maske fehlt. <sup>[[4]](#references)</sup>

Verwende die [folgenden Prüfungen](#checks), um die angeforderten Masken mit den exakten Mounts im neuen Container abzugleichen.

Eine übersprungene Dateimaske kann procfs-Daten offenlegen, sofern normale Berechtigungen und die LSM-Richtlinie dies zulassen. Sie macht `/proc/sys` **nicht** von sich aus beschreibbar: Dafür gibt es eine separate Steuerung für [schreibgeschützte Pfade](read-only-paths.md). Die davon unabhängige Ersetzung des `/dev/null`-Symlinks, die einen Bind-Mount auf ein beschreibbares procfs-Ziel umleiten kann, wird unter [Race in der Laufzeitumgebung des PID-Namespace](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs) behandelt. <sup>[[4]](#references)</sup>

## Prüfungen

Mit diesen Prüfungen soll ermittelt werden, welche Pfade die Laufzeitumgebung absichtlich verborgen hat und ob der aktuelle Workload weiterhin ein eingeschränktes kernelbezogenes Dateisystem sieht.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Prüfe exakt, ob der Mount vorhanden ist, da eine maskierte Datei weiterhin existieren kann und ein Lesezugriff aus `/dev/null` ein leeres Ergebnis liefern kann. Ein fehlender Mountpoint ist ein Befund, der untersucht werden sollte, aber für sich genommen kein Beweis dafür, dass Host-Daten lesbar sind. <sup>[[4]](#references)[[5]](#references)</sup>

Was hier interessant ist:

- Eine lange Liste maskierter Pfade ist bei gehärteten Runtimes normal.
- Fehlende Maskierungen bei sensiblen procfs-Einträgen verdienen eine genauere Prüfung.
- Wenn ein sensibler Pfad zugänglich ist und der Container zudem über weitreichende Capabilities oder umfassende Mounts verfügt, ist die Offenlegung bedeutsamer.

## Runtime-Standards

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächungen |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Docker definiert eine Standardliste maskierter Pfade | Host-Mounts von proc/sys freigeben, `--privileged` |
| Podman | Standardmäßig aktiviert | Podman wendet standardmäßig maskierte Pfade an, sofern sie nicht manuell freigegeben werden | `--security-opt unmask=ALL`, gezieltes Aufheben der Maskierung, `--privileged` |
| Kubernetes | Übernimmt Runtime-Standards | Verwendet das Maskierungsverhalten der zugrunde liegenden Runtime, sofern Pod-Einstellungen die proc-Exposition nicht abschwächen | `procMount: Unmasked` (erfordert in aktuellen Releases `hostUsers: false`), Muster mit privilegierten Workloads, umfassende Host-Mounts |
| containerd / CRI-O unter Kubernetes | Runtime-Standard | Wendet normalerweise OCI-/Runtime-maskierte Pfade an, sofern sie nicht überschrieben werden | Direkte Änderungen der Runtime-Konfiguration, dieselben Abschwächungsmöglichkeiten in Kubernetes |

Maskierte Pfade sind normalerweise standardmäßig vorhanden. Das zentrale Betriebsproblem ist nicht ihr Fehlen in der Runtime, sondern das gezielte Aufheben der Maskierung oder Host-Bind-Mounts, die den Schutz aushebeln.

## References

- [1] [Open Container Initiative - Linux-Containerkonfiguration: Maskierte Pfade](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Podman-Dokumentation - Sicherheitsoptionen von `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Kubernetes-Dokumentation - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [runc-Sicherheitshinweis: Race Condition bei der Mount-Quelle maskierter Pfade](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Handbuch zu findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Handbuch zu keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
