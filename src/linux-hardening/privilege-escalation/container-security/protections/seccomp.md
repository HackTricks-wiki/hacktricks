# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

**seccomp** ist der Mechanismus, mit dem der Kernel einen Filter auf die syscalls anwenden kann, die ein Prozess aufrufen darf. In containerisierten Umgebungen wird seccomp normalerweise im Filter-Modus verwendet, sodass ein Prozess nicht nur vage als "restricted" markiert ist, sondern einer konkreten syscall-Policy unterliegt. Das ist wichtig, weil viele Container-Breakouts den Zugriff auf sehr spezifische Kernel-Schnittstellen erfordern. Wenn ein Prozess die relevanten syscalls nicht erfolgreich ausführen kann, fällt eine große Klasse von Angriffen weg, noch bevor Namespace- oder Capability-Details überhaupt relevant werden.

Das grundlegende Denkmodell ist einfach: Namespaces entscheiden **was der Prozess sehen kann**, Capabilities entscheiden **welche privilegierten Aktionen der Prozess nominal versuchen darf**, und seccomp entscheidet **ob der Kernel überhaupt den syscall-Einstiegspunkt für die versuchte Aktion akzeptiert**. Deshalb verhindert seccomp häufig Angriffe, die allein basierend auf Capabilities möglich erscheinen würden.

## Sicherheitsauswirkung

Ein großer Teil gefährlicher Kernel-Oberfläche ist nur über eine relativ kleine Menge an syscalls erreichbar. Beispiele, die bei der Härtung von Containern immer wieder wichtig sind, umfassen `mount`, `unshare`, `clone` oder `clone3` mit bestimmten Flags, `bpf`, `ptrace`, `keyctl` und `perf_event_open`. Ein Angreifer, der Zugang zu diesen syscalls hat, kann möglicherweise neue Namespaces erstellen, Kernel-Subsysteme manipulieren oder mit Angriffsflächen interagieren, die ein normales Anwendungs-Container gar nicht benötigt.

Deshalb sind die standardmäßigen Runtime-seccomp-Profile so wichtig. Sie sind nicht lediglich "zusätzliche Verteidigung". In vielen Umgebungen sind sie der Unterschied zwischen einem Container, der einen großen Teil der Kernel-Funktionalität nutzen kann, und einem, der auf eine syscall-Oberfläche beschränkt ist, die näher an dem liegt, was die Anwendung tatsächlich benötigt.

## Modi und Filteraufbau

seccomp hatte historisch einen Strict-Modus, in dem nur eine sehr kleine Menge an syscalls verfügbar blieb, aber der für moderne Container-Runtimes relevante Modus ist der seccomp-Filtermodus, oft **seccomp-bpf** genannt. In diesem Modell wertet der Kernel ein Filterprogramm aus, das entscheidet, ob ein syscall erlaubt, mit einem errno abgewiesen, eine Trap ausgelöst, protokolliert oder der Prozess beendet werden soll. Container-Runtimes nutzen diesen Mechanismus, weil er ausdrucksstark genug ist, um breite Klassen gefährlicher syscalls zu blockieren und gleichzeitig normales Anwendungsverhalten zuzulassen.

Zwei Low-Level-Beispiele sind nützlich, weil sie den Mechanismus konkret statt magisch machen. Der Strict-Modus zeigt das alte Modell "nur eine minimale Menge an syscalls überlebt":
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
Das letzte `open` führt dazu, dass der Prozess beendet wird, da es nicht zum minimalen Satz von strict mode gehört.

Ein libseccomp-Filterbeispiel zeigt das moderne Richtlinienmodell deutlicher:
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
Diese Art von Richtlinie ist das, was sich die meisten Leser vorstellen sollten, wenn sie an runtime seccomp-Profile denken.

## Labor

Eine einfache Möglichkeit, zu bestätigen, dass seccomp in einem Container aktiv ist, ist:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Sie können auch eine Operation ausprobieren, die von Standardprofilen üblicherweise eingeschränkt wird:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Wenn der Container unter einem normalen Standard-seccomp-Profil läuft, werden `unshare`-artige Operationen häufig blockiert. Das ist eine nützliche Demonstration, weil sie zeigt, dass selbst wenn das userspace-Tool im Image vorhanden ist, der Kernel-Pfad, den es benötigt, dennoch nicht verfügbar sein kann.

Wenn der Container unter einem normalen Standard-seccomp-Profil läuft, werden `unshare`-artige Operationen häufig blockiert, selbst wenn das userspace-Tool im Image vorhanden ist.

Um den Prozessstatus allgemeiner zu prüfen, führen Sie aus:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Laufzeitnutzung

Docker unterstützt sowohl Standard- als auch benutzerdefinierte seccomp-Profile und erlaubt Administratoren, diese mit `--security-opt seccomp=unconfined` zu deaktivieren. Podman bietet ähnliche Unterstützung und kombiniert seccomp häufig mit rootless-Ausführung in einer sehr sinnvollen Standardkonfiguration. Kubernetes stellt seccomp über die Workload-Konfiguration bereit, wobei `RuntimeDefault` in der Regel die sinnvolle Basislinie ist und `Unconfined` als Ausnahme betrachtet werden sollte, die eine Rechtfertigung erfordert, statt als bequemer Schalter.

In containerd- und CRI-O-basierten Umgebungen ist der genaue Weg mehrschichtig, aber das Prinzip bleibt dasselbe: die höherstufige Engine oder der Orchestrator entscheidet, was passieren soll, und die Runtime installiert schließlich die resultierende seccomp-Policy für den Containerprozess. Das Ergebnis hängt weiterhin von der finalen Runtime-Konfiguration ab, die den Kernel erreicht.

### Beispiel für eine benutzerdefinierte Policy

Docker und ähnliche Engines können ein benutzerdefiniertes seccomp-Profil aus JSON laden. Ein minimales Beispiel, das `chmod` verweigert und sonst alles erlaubt, sieht so aus:
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
Der Befehl schlägt mit `Operation not permitted` fehl, was zeigt, dass die Einschränkung von der syscall-Policy und nicht nur von normalen Dateiberechtigungen herrührt. Bei echter Härtung sind allowlists in der Regel strenger als permissive defaults mit einer kleinen blacklist.

## Fehlkonfigurationen

Der gröbste Fehler ist, seccomp auf **unconfined** zu setzen, weil eine Anwendung unter der Default-Policy fehlgeschlagen ist. Das passiert oft beim Troubleshooting und ist als dauerhafte Lösung sehr gefährlich. Sobald der Filter weg ist, werden viele syscall-basierte Breakout-Primitives wieder erreichbar, besonders wenn leistungsfähige capabilities oder host namespace sharing ebenfalls vorhanden sind.

Ein weiteres häufiges Problem ist die Verwendung eines **custom permissive profile**, das aus einem Blogpost oder einem internen Workaround kopiert wurde, ohne sorgfältig geprüft worden zu sein. Teams behalten manchmal fast alle gefährlichen syscalls bei, einfach weil das Profil darauf ausgelegt wurde, "stop the app from breaking" statt "grant only what the app actually needs". Ein dritter Irrglaube ist anzunehmen, dass seccomp für non-root containers weniger wichtig sei. Tatsächlich bleibt eine große Kernel-Angriffsfläche relevant, selbst wenn der Prozess nicht UID 0 ist.

## Missbrauch

Wenn seccomp fehlt oder stark abgeschwächt ist, kann ein Angreifer namespace-creation syscalls aufrufen, die erreichbare Kernel-Angriffsfläche über `bpf` oder `perf_event_open` erweitern, `keyctl` missbrauchen oder diese syscall-Pfade mit gefährlichen capabilities wie `CAP_SYS_ADMIN` kombinieren. In vielen realen Angriffen ist seccomp nicht die einzige fehlende Kontrolle, aber sein Fehlen verkürzt den Exploit-Pfad dramatisch, weil eine der wenigen Verteidigungen entfällt, die einen riskanten syscall stoppen können, bevor das restliche Privilege-Modell überhaupt greift.

Der praktischste Test ist, genau die syscall-Familien auszuprobieren, die Default-Profile normalerweise blockieren. Wenn diese plötzlich funktionieren, hat sich die Sicherheitslage des Containers stark verändert:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Wenn `CAP_SYS_ADMIN` oder eine andere starke Capability vorhanden ist, prüfen, ob seccomp die einzige fehlende Barriere vor mount-basiertem Missbrauch ist:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Bei manchen Zielen besteht der unmittelbare Wert nicht darin, einen vollständigen escape zu erreichen, sondern in der Informationsgewinnung und der Erweiterung der Angriffsfläche des Kernels. Diese Befehle helfen zu bestimmen, ob besonders sensible syscall-Pfade erreichbar sind:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Wenn seccomp nicht vorhanden ist und der Container außerdem in anderer Hinsicht privilegiert ist, dann ist es sinnvoll, zu den spezifischeren breakout techniques überzugehen, die bereits in den legacy container-escape pages dokumentiert sind.

### Vollständiges Beispiel: seccomp war das einzige, das `unshare` blockierte

Bei vielen Zielen ist die praktische Auswirkung des Entfernens von seccomp, dass namespace-creation- oder mount-syscalls plötzlich funktionieren. Wenn der Container außerdem `CAP_SYS_ADMIN` besitzt, kann die folgende Sequenz möglich werden:
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
An sich ist das noch kein host escape, aber es zeigt, dass seccomp die Barriere war, die mount-related exploitation verhindert hat.

### Vollständiges Beispiel: seccomp deaktiviert + cgroup v1 `release_agent`

Wenn seccomp deaktiviert ist und der container cgroup v1-Hierarchien mounten kann, wird die `release_agent`-Technik aus dem cgroups-Abschnitt erreichbar:
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
Dies ist kein seccomp-only-Exploit. Der Punkt ist, dass sobald seccomp unconfined ist, syscall-heavy breakout chains, die zuvor blockiert waren, möglicherweise genau wie geschrieben funktionieren.

## Prüfungen

Der Zweck dieser Prüfungen ist festzustellen, ob seccomp überhaupt aktiv ist, ob `no_new_privs` damit einhergeht und ob die Runtime-Konfiguration seccomp explizit als deaktiviert anzeigt.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Was hier interessant ist:

- Ein nicht-null `Seccomp`-Wert bedeutet, dass Filterung aktiv ist; `0` bedeutet normalerweise keinen seccomp-Schutz.
- Wenn die Runtime-Sicherheitsoptionen `seccomp=unconfined` enthalten, hat die Workload eine ihrer nützlichsten Abwehrmaßnahmen auf Syscall-Ebene verloren.
- `NoNewPrivs` ist nicht seccomp selbst, aber das gleichzeitige Vorhandensein beider weist in der Regel auf eine sorgfältigere Härtung hin als wenn keines von beiden gesetzt ist.

Wenn ein Container bereits verdächtige Mounts, weitreichende Capabilities oder gemeinsame Host-Namespaces hat und seccomp außerdem unconfined ist, sollte diese Kombination als ein starkes Eskalationssignal gewertet werden. Der Container ist möglicherweise trotzdem nicht trivial angreifbar, aber die Anzahl der Kernel-Einstiegspunkte, die einem Angreifer zur Verfügung stehen, ist stark angestiegen.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | In der Regel standardmäßig aktiviert | Verwendet Dockers eingebautes Standard-seccomp-Profil, sofern nicht überschrieben | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | In der Regel standardmäßig aktiviert | Wendet das Runtime-Standard-seccomp-Profil an, sofern nicht überschrieben | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Standardmäßig nicht garantiert** | Wenn `securityContext.seccompProfile` nicht gesetzt ist, ist der Standard `Unconfined`, es sei denn, der kubelet aktiviert `--seccomp-default`; `RuntimeDefault` oder `Localhost` müssen sonst explizit gesetzt werden | `securityContext.seccompProfile.type: Unconfined`, seccomp auf Clustern ohne `seccompDefault` unbelegt lassen, `privileged: true` |
| containerd / CRI-O under Kubernetes | Folgt den Kubernetes-Knoten- und Pod-Einstellungen | Das Runtime-Profil wird verwendet, wenn Kubernetes `RuntimeDefault` anfordert oder wenn kubelet Seccomp-Defaulting aktiviert ist | Wie in der Kubernetes-Zeile; direkte CRI/OCI-Konfiguration kann seccomp ebenfalls komplett weglassen |

Das Verhalten von Kubernetes überrascht Operatoren am häufigsten. In vielen Clustern fehlt seccomp weiterhin, sofern der Pod es nicht anfordert oder der kubelet so konfiguriert ist, dass er standardmäßig `RuntimeDefault` verwendet.
