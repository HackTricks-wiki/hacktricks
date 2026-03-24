# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

**seccomp** ist der Mechanismus, der dem Kernel erlaubt, einen Filter auf die syscalls anzuwenden, die ein Prozess aufrufen darf. In containerisierten Umgebungen wird seccomp normalerweise im Filtermodus verwendet, sodass der Prozess nicht einfach vage als "restricted" markiert wird, sondern stattdessen einer konkreten syscall-Policy unterliegt. Das ist wichtig, weil viele container breakouts das Erreichen sehr spezifischer Kernel-Schnittstellen erfordern. Kann der Prozess die relevanten syscalls nicht erfolgreich aufrufen, fällt eine große Klasse von Angriffen weg, noch bevor irgendeine nuance von namespaces oder capabilities relevant wird.

Das zentrale mentale Modell ist einfach: namespaces entscheiden, was der Prozess sehen kann, capabilities entscheiden, welche privilegierten Aktionen der Prozess nominal ausführen darf, und seccomp entscheidet, ob der Kernel den syscall-Einstiegspunkt für die versuchte Aktion überhaupt akzeptiert. Deshalb verhindert seccomp häufig Angriffe, die allein basierend auf capabilities möglich erscheinen würden.

## Security Impact

Eine große Menge gefährlicher Kernel-Oberfläche ist nur über eine relativ kleine Menge von syscalls erreichbar. Beispiele, die bei der Härtung von Containern immer wieder relevant sind, umfassen `mount`, `unshare`, `clone` oder `clone3` mit bestimmten Flags, `bpf`, `ptrace`, `keyctl` und `perf_event_open`. Ein Angreifer, der diese syscalls erreichen kann, kann möglicherweise neue namespaces erstellen, Kernel-Subsysteme manipulieren oder mit Angriffsflächen interagieren, die ein normaler Anwendungscontainer überhaupt nicht benötigt.

Deshalb sind die Standard-runtime-seccomp-Profile so wichtig. Sie sind nicht nur "zusätzliche Verteidigung". In vielen Umgebungen machen sie den Unterschied zwischen einem Container, der einen großen Teil der Kernel-Funktionalität ausüben kann, und einem, der auf eine syscall-Oberfläche beschränkt ist, die näher an dem liegt, was die Anwendung tatsächlich braucht.

## Modes And Filter Construction

seccomp hatte historisch einen Strict-Mode, in dem nur ein winziger Satz an syscalls verfügbar blieb, aber der Modus, der für moderne Container-Runtimes relevant ist, ist seccomp filter mode, oft seccomp-bpf genannt. In diesem Modell wertet der Kernel ein Filterprogramm aus, das entscheidet, ob ein syscall erlaubt, mit einem errno abgewiesen, trapped, geloggt oder der Prozess beendet wird. Container-Runtimes nutzen diesen Mechanismus, weil er ausdrucksstark genug ist, breite Klassen gefährlicher syscalls zu blockieren und gleichzeitig normales Anwendungsverhalten zuzulassen.

Zwei low-level Beispiele sind nützlich, weil sie den Mechanismus konkret statt mystisch machen. Der Strict-Mode demonstriert das alte Modell "nur eine minimale Menge an syscalls überlebt":
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
Der letzte `open` bewirkt, dass der Prozess beendet wird, weil er nicht zum minimalen Satz von strict mode gehört.

Ein libseccomp-Filterbeispiel zeigt das moderne Policy-Modell deutlicher:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Diese Art von Richtlinie ist das Bild, das sich die meisten Leser vorstellen sollten, wenn sie an runtime seccomp profiles denken.

## Labor

Eine einfache Möglichkeit, zu bestätigen, dass seccomp in einem Container aktiv ist, ist:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Sie können auch eine Operation ausprobieren, die Standardprofile häufig einschränken:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Wenn der Container unter einem normalen Standard-seccomp-Profil läuft, sind `unshare`-artige Operationen oft blockiert. Das ist eine nützliche Demonstration, da sie zeigt, dass selbst wenn das userspace-Tool im Image vorhanden ist, der dafür benötigte Kernel-Pfad trotzdem nicht verfügbar sein kann.
Wenn der Container unter einem normalen Standard-seccomp-Profil läuft, sind `unshare`-artige Operationen oft blockiert, selbst wenn das userspace-Tool im Image vorhanden ist.

Um den Prozessstatus allgemein zu prüfen, führen Sie aus:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Laufzeitnutzung

Docker unterstützt sowohl standardmäßige als auch benutzerdefinierte seccomp-Profile und erlaubt Administratoren, sie mit `--security-opt seccomp=unconfined` zu deaktivieren. Podman bietet ähnliche Unterstützung und kombiniert seccomp oft mit rootless execution in einer sehr sinnvollen Standardkonfiguration. Kubernetes stellt seccomp über die Workload-Konfiguration bereit, wobei `RuntimeDefault` meist die sinnvolle Baseline ist und `Unconfined` als Ausnahme betrachtet werden sollte, die einer Begründung bedarf, statt als bequemer Schalter.

In containerd- und CRI-O-basierten Umgebungen ist der genaue Weg stärker geschichtet, aber das Prinzip bleibt dasselbe: die höherstufige Engine oder der Orchestrator entscheidet, was passieren soll, und der runtime installiert schließlich die resultierende seccomp-Policy für den Containerprozess. Das Ergebnis hängt weiterhin von der finalen runtime-Konfiguration ab, die den Kernel erreicht.

### Beispiel für eine benutzerdefinierte Policy

Docker und ähnliche Engines können ein benutzerdefiniertes seccomp-Profil aus JSON laden. Ein minimales Beispiel, das `chmod` verweigert, während alles andere erlaubt ist, sieht folgendermaßen aus:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Angewendet mit:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Der Befehl schlägt fehl mit `Operation not permitted`, was zeigt, dass die Einschränkung von der syscall-Policy und nicht nur von gewöhnlichen Dateiberechtigungen stammt. Bei echter Härtung sind allowlists im Allgemeinen stärker als permissive defaults mit einer kleinen blacklist.

## Fehlkonfigurationen

Der grobste Fehler ist, seccomp auf **unconfined** zu setzen, weil eine Anwendung unter der Default-Policy fehlgeschlagen ist. Das passiert häufig während der Fehlersuche und ist als dauerhafte Lösung sehr gefährlich. Sobald der Filter weg ist, werden viele syscall-based breakout primitives wieder erreichbar, besonders wenn mächtige capabilities oder host namespace sharing vorhanden sind.

Ein weiteres häufiges Problem ist die Verwendung eines **custom permissive profile**, das von einem Blog oder einem internen Workaround kopiert wurde, ohne sorgfältig geprüft zu werden. Teams behalten manchmal fast alle gefährlichen syscalls bei, einfach weil das Profile um "die App am Absturz hindern" statt "nur das gewähren, was die App tatsächlich benötigt" gebaut wurde. Ein drittes Missverständnis ist anzunehmen, seccomp sei für non-root-Container weniger wichtig. In Wirklichkeit bleibt eine große Angriffsfläche des Kernels relevant, selbst wenn der Prozess nicht UID 0 ist.

## Missbrauch

Wenn seccomp fehlt oder stark abgeschwächt ist, kann ein Angreifer möglicherweise namespace-creation syscalls aufrufen, die erreichbare Kernel-Angriffsfläche über `bpf` oder `perf_event_open` erweitern, `keyctl` missbrauchen oder diese syscall-Pfade mit gefährlichen capabilities wie `CAP_SYS_ADMIN` kombinieren. In vielen realen Angriffen ist seccomp nicht die einzige fehlende Kontrolle, aber sein Fehlen verkürzt den Exploit-Pfad dramatisch, weil es eine der wenigen Abwehrmaßnahmen entfernt, die einen riskanten syscall stoppen können, bevor das restliche Privilegmodell überhaupt ins Spiel kommt.

Der praktischste Test ist, genau die syscall-Familien auszuprobieren, die Default-Profile üblicherweise blockieren. Wenn sie plötzlich funktionieren, hat sich die Sicherheitslage des Containers stark verändert:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Wenn `CAP_SYS_ADMIN` oder eine andere starke capability vorhanden ist, prüfe, ob seccomp die einzige fehlende Barriere vor mount-based abuse ist:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Bei manchen Zielen besteht der unmittelbare Nutzen nicht in einem full escape, sondern in der Informationsbeschaffung und der Erweiterung der kernel attack-surface. Diese Befehle helfen zu bestimmen, ob besonders sensible syscall-Pfade erreichbar sind:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Wenn seccomp fehlt und der Container außerdem auf andere Weise privilegiert ist, macht es Sinn, auf die spezifischeren breakout techniques umzuschwenken, die bereits in den legacy container-escape pages dokumentiert sind.

### Vollständiges Beispiel: seccomp war das Einzige, das `unshare` blockierte

Bei vielen Zielen ist die praktische Wirkung des Entfernens von seccomp, dass namespace-creation oder mount syscalls plötzlich funktionieren. Wenn der Container außerdem `CAP_SYS_ADMIN` besitzt, könnte die folgende Sequenz möglich werden:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
An sich ist das noch kein host escape, aber es demonstriert, dass seccomp die Barriere war, die mount-related exploitation verhinderte.

### Vollständiges Beispiel: seccomp deaktiviert + cgroup v1 `release_agent`

Wenn seccomp deaktiviert ist und der Container cgroup v1 Hierarchien mounten kann, wird die `release_agent`-Technik aus dem cgroups-Abschnitt erreichbar:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Dies ist kein reiner seccomp-Exploit. Der Punkt ist, dass sobald seccomp unconfined ist, syscall-heavy breakout chains, die zuvor blockiert wurden, möglicherweise genau wie geschrieben funktionieren.

## Prüfungen

Der Zweck dieser Prüfungen ist festzustellen, ob seccomp überhaupt aktiv ist, ob `no_new_privs` damit einhergeht und ob die Laufzeitkonfiguration seccomp explizit als deaktiviert anzeigt.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Was hier interessant ist:

- Ein von null verschiedener `Seccomp`-Wert bedeutet, dass Filterung aktiv ist; `0` bedeutet üblicherweise keinen seccomp-Schutz.
- Wenn die Runtime-Sicherheitsoptionen `seccomp=unconfined` enthalten, hat der Workload eine seiner nützlichsten Abwehrmaßnahmen auf Syscall-Ebene verloren.
- `NoNewPrivs` ist nicht seccomp selbst, aber das gemeinsame Vorhandensein beider weist in der Regel auf eine sorgfältigere Härtungshaltung hin als das Fehlen beider.

Wenn ein Container bereits verdächtige Mounts, breite capabilities oder geteilte host namespaces hat und seccomp ebenfalls unconfined ist, sollte diese Kombination als starkes Eskalationssignal gewertet werden. Der Container ist möglicherweise immer noch nicht trivial angreifbar, aber die Anzahl der für den Angreifer verfügbaren Kernel-Einstiegspunkte hat sich stark erhöht.

## Standardeinstellungen der Runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | In der Regel standardmäßig aktiviert | Verwendet das eingebaute Standard-seccomp-Profil von Docker, sofern nicht überschrieben | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | In der Regel standardmäßig aktiviert | Wendet das Runtime-Standard-seccomp-Profil an, sofern nicht überschrieben | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Nicht standardmäßig garantiert** | Wenn `securityContext.seccompProfile` nicht gesetzt ist, ist die Standardeinstellung `Unconfined`, es sei denn, der kubelet aktiviert `--seccomp-default`; `RuntimeDefault` oder `Localhost` müssen ansonsten explizit gesetzt werden | `securityContext.seccompProfile.type: Unconfined`, seccomp in Clustern ohne `seccompDefault` unbelegt lassen, `privileged: true` |
| containerd / CRI-O under Kubernetes | Folgt den Kubernetes-Knoten- und Pod-Einstellungen | Das Runtime-Profil wird verwendet, wenn Kubernetes `RuntimeDefault` anfordert oder wenn kubelet Seccomp-Defaulting aktiviert ist | Wie in der Kubernetes-Zeile; direkte CRI/OCI-Konfiguration kann seccomp ebenfalls vollständig weglassen |

Das Verhalten von Kubernetes ist das, das Betreiber am häufigsten überrascht. In vielen Clustern ist seccomp weiterhin nicht vorhanden, es sei denn, der Pod fordert es an oder der kubelet ist so konfiguriert, dass `RuntimeDefault` standardmäßig verwendet wird.
{{#include ../../../../banners/hacktricks-training.md}}
