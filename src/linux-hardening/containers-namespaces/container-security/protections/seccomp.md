# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Überblick

**seccomp** ist der Mechanismus, mit dem der Kernel einen Filter auf die syscalls anwendet, die ein Prozess aufrufen darf. In containerisierten Umgebungen wird seccomp normalerweise im Filtermodus verwendet, sodass der Prozess nicht einfach in einem vagen Sinn als „eingeschränkt“ markiert wird, sondern stattdessen einer konkreten syscall-Richtlinie unterliegt. Das ist wichtig, weil viele Container-Breakouts den Zugriff auf sehr spezifische Kernel-Schnittstellen erfordern. Wenn der Prozess die relevanten syscalls nicht erfolgreich aufrufen kann, verschwindet eine große Klasse von Angriffen, noch bevor irgendeine Nuance bezüglich Namespaces oder Capabilities relevant wird.

Das grundlegende mentale Modell ist einfach: Namespaces bestimmen, **was der Prozess sehen kann**, Capabilities bestimmen, **welche privilegierten Aktionen der Prozess dem Namen nach versuchen darf**, und seccomp bestimmt, **ob der Kernel den syscall-Einstiegspunkt für die versuchte Aktion überhaupt akzeptiert**. Deshalb verhindert seccomp häufig Angriffe, die allein auf Grundlage der Capabilities ansonsten möglich erscheinen würden.

## Sicherheitsauswirkungen

Ein großer Teil der gefährlichen Kernel-Oberfläche ist nur über eine relativ kleine Anzahl von syscalls erreichbar. Beispiele, die bei der Container-Härtung wiederholt relevant sind, umfassen `mount`, `unshare`, `clone` oder `clone3` mit bestimmten Flags, `bpf`, `ptrace`, `keyctl` und `perf_event_open`. Ein Angreifer, der diese syscalls erreichen kann, kann möglicherweise neue Namespaces erstellen, Kernel-Subsysteme manipulieren oder mit einer Angriffsfläche interagieren, die ein normaler Application-Container überhaupt nicht benötigt.

Deshalb sind standardmäßige seccomp-Profile der Runtime so wichtig. Sie sind nicht bloß eine „zusätzliche Schutzmaßnahme“. In vielen Umgebungen machen sie den Unterschied zwischen einem Container aus, der einen großen Teil der Kernel-Funktionalität nutzen kann, und einem Container, der auf eine syscall-Oberfläche beschränkt ist, die näher an dem liegt, was die Anwendung tatsächlich benötigt.

## Modi und Filterkonstruktion

seccomp verfügte historisch über einen strikten Modus, in dem nur eine sehr kleine Menge von syscalls verfügbar blieb. Der für moderne Container-Runtimes relevante Modus ist jedoch der seccomp-Filtermodus, der oft **seccomp-bpf** genannt wird. In diesem Modell wertet der Kernel ein Filterprogramm aus, das entscheidet, ob ein syscall erlaubt, mit einem errno verweigert, abgefangen, protokolliert oder der Prozess beendet werden soll. Container-Runtimes verwenden diesen Mechanismus, weil er ausdrucksstark genug ist, um breite Klassen gefährlicher syscalls zu blockieren und gleichzeitig normales Anwendungsverhalten zu ermöglichen.

Zwei Low-Level-Beispiele sind nützlich, weil sie den Mechanismus konkret und nicht magisch erscheinen lassen. Der strikte Modus veranschaulicht das alte Modell „nur eine minimale syscall-Menge bleibt übrig“:
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
Das abschließende `open` führt dazu, dass der Prozess beendet wird, da es nicht zum minimalen Satz des strict mode gehört.

Ein libseccomp-Filterbeispiel veranschaulicht das moderne Richtlinienmodell deutlicher:
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
Diese Art von Policy sollten sich die meisten Leser vorstellen, wenn sie an seccomp-Profile zur Laufzeit denken.

## Labor

Eine einfache Möglichkeit, zu bestätigen, dass seccomp in einem Container aktiv ist, lautet:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Sie können auch einen Vorgang ausprobieren, den Standardprofile häufig einschränken:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Wenn der Container unter einem normalen standardmäßigen seccomp-Profil ausgeführt wird, werden `unshare`-ähnliche Operationen häufig blockiert. Dies ist eine nützliche Demonstration, da sie zeigt, dass der benötigte Kernel-Pfad möglicherweise trotzdem nicht verfügbar ist, selbst wenn das Userspace-Tool im Image vorhanden ist.
Wenn der Container unter einem normalen standardmäßigen seccomp-Profil ausgeführt wird, werden `unshare`-ähnliche Operationen häufig blockiert, selbst wenn das Userspace-Tool im Image vorhanden ist.

Um den Prozessstatus allgemeiner zu überprüfen, führen Sie Folgendes aus:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Laufzeitverwendung

Docker unterstützt sowohl standardmäßige als auch benutzerdefinierte seccomp-Profile und ermöglicht Administratoren, diese mit `--security-opt seccomp=unconfined` zu deaktivieren. Podman bietet eine ähnliche Unterstützung und kombiniert seccomp häufig mit rootless execution, was eine sehr sinnvolle Standardkonfiguration ergibt. Kubernetes stellt seccomp über die Workload-Konfiguration bereit, wobei `RuntimeDefault` normalerweise die vernünftige Grundlage darstellt und `Unconfined` als Ausnahme behandelt werden sollte, die eine Begründung erfordert, und nicht als bequemer Umschalter.

In auf containerd und CRI-O basierenden Umgebungen ist der genaue Pfad stärker verschachtelt, aber das Prinzip bleibt gleich: Die übergeordnete Engine oder der Orchestrator entscheidet, was geschehen soll, und die Runtime installiert schließlich die daraus resultierende seccomp-Policy für den Containerprozess. Das Ergebnis hängt weiterhin von der endgültigen Runtime-Konfiguration ab, die den Kernel erreicht.

### Beispiel für eine benutzerdefinierte Policy

Docker und ähnliche Engines können ein benutzerdefiniertes seccomp-Profil aus JSON laden. Ein minimales Beispiel, das `chmod` verweigert und alles andere erlaubt, sieht so aus:
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
Der Befehl schlägt mit `Operation not permitted` fehl und zeigt damit, dass die Einschränkung von der syscall policy und nicht allein von gewöhnlichen Dateiberechtigungen stammt. Beim tatsächlichen Hardening sind Allowlists im Allgemeinen stärker als permissive Defaults mit einer kleinen Blacklist.

## Fehlkonfigurationen

Der gröbste Fehler besteht darin, seccomp auf **unconfined** zu setzen, weil eine Anwendung unter der Default policy fehlgeschlagen ist. Das kommt bei der Fehlersuche häufig vor und ist als dauerhafte Lösung sehr gefährlich. Sobald der Filter entfernt wurde, werden viele syscall-basierte Breakout-Primitives wieder erreichbar, insbesondere wenn außerdem weitreichende Capabilities verwendet oder Host-Namespaces gemeinsam genutzt werden.

Ein weiteres häufiges Problem ist die Verwendung eines **permissive custom profile**, das aus irgendeinem Blog oder einem internen Workaround kopiert wurde, ohne sorgfältig überprüft worden zu sein. Teams behalten manchmal fast alle gefährlichen syscalls bei, weil das Profil nach dem Prinzip „verhindere, dass die Anwendung abstürzt“ und nicht nach dem Prinzip „gewähre nur, was die Anwendung tatsächlich benötigt“ erstellt wurde. Ein drittes Missverständnis besteht in der Annahme, seccomp sei für Non-Root-Container weniger wichtig. Tatsächlich bleibt auch dann viel Kernel-Angriffsfläche relevant, wenn der Prozess nicht UID 0 ist.

## Missbrauch

Wenn seccomp fehlt oder stark geschwächt wurde, kann ein Angreifer möglicherweise Namespace-Erstellungs-syscalls aufrufen, die erreichbare Kernel-Angriffsfläche über `bpf` oder `perf_event_open` erweitern, `keyctl` missbrauchen oder diese syscall-Pfade mit gefährlichen Capabilities wie `CAP_SYS_ADMIN` kombinieren. Bei vielen realen Angriffen ist seccomp nicht die einzige fehlende Schutzmaßnahme, doch sein Fehlen verkürzt den Exploit-Pfad erheblich, da dadurch eine der wenigen Schutzmaßnahmen entfällt, die einen riskanten syscall blockieren kann, bevor das restliche Privilege-Modell überhaupt zum Tragen kommt.

Der nützlichste praktische Test besteht darin, genau die syscall-Familien auszuprobieren, die Default-Profile normalerweise blockieren. Wenn sie plötzlich funktionieren, hat sich die Container-Sicherheitslage deutlich verändert:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Wenn `CAP_SYS_ADMIN` oder eine andere starke Capability vorhanden ist, prüfe, ob seccomp die einzige noch fehlende Barriere vor mount-basiertem Missbrauch ist:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Auf manchen Zielen besteht der unmittelbare Wert nicht in einem vollständigen Escape, sondern in der Informationsgewinnung und der Erweiterung der Kernel-Angriffsfläche. Diese Befehle helfen festzustellen, ob besonders sensible Syscall-Pfade erreichbar sind:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Wenn seccomp fehlt und der Container außerdem auf andere Weise privilegiert ist, ist es sinnvoll, auf die spezifischeren Breakout-Techniken auszuweichen, die bereits auf den Legacy-Container-Escape-Seiten dokumentiert sind.

### Vollständiges Beispiel: seccomp war das Einzige, was `unshare` blockierte

Bei vielen Zielen besteht der praktische Effekt der Entfernung von seccomp darin, dass Namespace-Erstellungs- oder Mount-Syscalls plötzlich funktionieren. Wenn der Container außerdem über `CAP_SYS_ADMIN` verfügt, kann die folgende Sequenz möglich werden:
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
An sich handelt es sich hierbei noch nicht um einen host escape, aber dies zeigt, dass seccomp die Barriere war, die die mount-bezogene Exploitation verhindert hat.

### Vollständiges Beispiel: seccomp deaktiviert + cgroup v1 `release_agent`

Wenn seccomp deaktiviert ist und der Container cgroup-v1-Hierarchien mounten kann, wird die `release_agent`-Technik aus dem Abschnitt zu cgroups erreichbar:
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
Dies ist kein ausschließlich auf seccomp beschränkter Exploit. Der Punkt ist, dass syscall-intensive breakout chains, die zuvor blockiert wurden, möglicherweise genau wie beschrieben funktionieren, sobald seccomp unconfined ist.

## Prüfungen

Der Zweck dieser Prüfungen besteht darin festzustellen, ob seccomp überhaupt aktiv ist, ob `no_new_privs` damit einhergeht und ob die Runtime-Konfiguration zeigt, dass seccomp ausdrücklich deaktiviert wurde.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Was hier interessant ist:

- Ein Wert ungleich null bei `Seccomp` bedeutet, dass Filterung aktiv ist; `0` bedeutet normalerweise, dass kein seccomp-Schutz vorhanden ist.
- Wenn die Runtime-Sicherheitsoptionen `seccomp=unconfined` enthalten, hat der Workload eine seiner nützlichsten Abwehrmaßnahmen auf Syscall-Ebene verloren.
- `NoNewPrivs` ist nicht seccomp selbst, aber das gleichzeitige Auftreten beider Werte weist normalerweise auf eine sorgfältigere Hardening-Strategie hin als das Fehlen beider Werte.

Wenn ein Container bereits verdächtige Mounts, weitreichende Capabilities oder gemeinsam verwendete Host-Namespaces besitzt und seccomp ebenfalls auf unconfined gesetzt ist, sollte diese Kombination als starkes Signal für eine mögliche Privilege Escalation betrachtet werden. Der Container ist möglicherweise weiterhin nicht trivial zu kompromittieren, aber die Anzahl der für den Angreifer verfügbaren Kernel-Einstiegspunkte ist stark gestiegen.

## Standardwerte der Runtime

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Normalerweise standardmäßig aktiviert | Verwendet das integrierte Standard-seccomp-Profil von Docker, sofern es nicht überschrieben wird | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Normalerweise standardmäßig aktiviert | Wendet das Standard-seccomp-Profil der Runtime an, sofern es nicht überschrieben wird | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Standardmäßig nicht garantiert** | Wenn `securityContext.seccompProfile` nicht gesetzt ist, lautet der Standardwert `Unconfined`, sofern der kubelet nicht `--seccomp-default` aktiviert; andernfalls müssen `RuntimeDefault` oder `Localhost` explizit gesetzt werden | `securityContext.seccompProfile.type: Unconfined`, seccomp auf Clustern ohne `seccompDefault` nicht setzen, `privileged: true` |
| containerd / CRI-O unter Kubernetes | Folgt den Einstellungen des Kubernetes-Nodes und des Pods | Das Runtime-Profil wird verwendet, wenn Kubernetes `RuntimeDefault` anfordert oder das kubelet standardmäßig seccomp aktiviert | Wie in der Kubernetes-Zeile; bei direkter CRI/OCI-Konfiguration kann seccomp ebenfalls vollständig weggelassen werden |

Das Verhalten von Kubernetes überrascht Betreiber am häufigsten. In vielen Clustern fehlt seccomp weiterhin, sofern der Pod es nicht anfordert oder das kubelet so konfiguriert ist, dass standardmäßig `RuntimeDefault` verwendet wird.
{{#include ../../../../banners/hacktricks-training.md}}
