# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ist ein Kernel-Hardening-Feature, das verhindert, dass ein Prozess über `execve()` zusätzliche Privilegien erhält. In der Praxis bedeutet dies: Sobald das Flag gesetzt ist, gewährt die Ausführung eines setuid-Binaries, eines setgid-Binaries oder einer Datei mit Linux file capabilities keine zusätzlichen Privilegien über die bereits vorhandenen hinaus. In containerisierten Umgebungen ist dies wichtig, da viele Privilege-Escalation-Chains darauf beruhen, innerhalb des Images eine ausführbare Datei zu finden, die beim Start die Privilegien ändert.

Aus defensiver Sicht ist `no_new_privs` kein Ersatz für Namespaces, seccomp oder das Droppen von Capabilities. Es ist eine zusätzliche Schutzschicht. Sie blockiert eine bestimmte Klasse nachgelagerter Escalation, nachdem bereits Code Execution erlangt wurde. Dadurch ist sie besonders wertvoll in Umgebungen, in denen Images Helper-Binaries, Package-Manager-Artefakte oder Legacy-Tools enthalten, die in Kombination mit einer partiellen Kompromittierung andernfalls gefährlich wären.

## Funktionsweise

Das diesem Verhalten zugrunde liegende Kernel-Flag ist `PR_SET_NO_NEW_PRIVS`. Sobald es für einen Prozess gesetzt wurde, können spätere `execve()`-Aufrufe die Privilegien nicht erhöhen. Wichtig ist, dass der Prozess weiterhin Binaries ausführen kann; er kann diese Binaries lediglich nicht dazu verwenden, eine Privilege Boundary zu überschreiten, die der Kernel andernfalls berücksichtigen würde.

Das Kernel-Verhalten wird außerdem **vererbt und ist irreversibel**: Sobald ein Task `no_new_privs` setzt, wird das Bit über `fork()`, `clone()` und `execve()` vererbt und kann später nicht mehr deaktiviert werden. Dies ist bei Assessments nützlich, da ein einzelnes `NoNewPrivs: 1` beim Container-Prozess normalerweise bedeutet, dass auch Nachfahren in diesem Modus bleiben sollten, sofern nicht ein vollständig anderer Process Tree betrachtet wird.

In Kubernetes-orientierten Umgebungen bildet `allowPrivilegeEscalation: false` dieses Verhalten für den Container-Prozess ab. In Docker- und Podman-ähnlichen Runtimes wird das Äquivalent normalerweise explizit über eine Security Option aktiviert. Auf der OCI-Ebene erscheint dasselbe Konzept als `process.noNewPrivileges`.

## Wichtige Feinheiten

`no_new_privs` blockiert Privilege Gain **zur Ausführungszeit**, nicht jede Änderung von Privilegien. Insbesondere gilt:

- setuid- und setgid-Übergänge funktionieren über `execve()` nicht mehr
- File Capabilities werden bei `execve()` nicht zum Permitted Set hinzugefügt
- LSMs wie AppArmor oder SELinux lockern ihre Einschränkungen nach `execve()` nicht
- bereits vorhandene Privilegien bleiben weiterhin vorhanden

Der letzte Punkt ist aus operativer Sicht wichtig. Wenn der Prozess bereits als root läuft, bereits eine gefährliche Capability besitzt oder bereits Zugriff auf eine leistungsfähige Runtime-API oder einen beschreibbaren Host-Mount hat, neutralisiert das Setzen von `no_new_privs` diese Exposures nicht. Es entfernt lediglich einen häufigen **nächsten Schritt** in einer Privilege-Escalation-Chain.

Beachte außerdem, dass das Flag keine Privilege Changes blockiert, die nicht von `execve()` abhängen. Beispielsweise kann ein Task, der bereits ausreichend privilegiert ist, weiterhin direkt `setuid(2)` aufrufen oder einen privilegierten File Descriptor über einen Unix-Socket empfangen. Deshalb sollte `no_new_privs` zusammen mit [seccomp](seccomp.md), Capability Sets und der Namespace Exposure betrachtet werden und nicht als eigenständige Lösung.

## Lab

Untersuche den Status des aktuellen Prozesses:
```bash
grep NoNewPrivs /proc/self/status
```
Vergleichen Sie das mit einem Container, bei dem die Runtime das Flag aktiviert:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Bei einem gehärteten Workload sollte das Ergebnis `NoNewPrivs: 1` anzeigen.

Du kannst den tatsächlichen Effekt auch anhand einer setuid-Binärdatei demonstrieren:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Der Punkt des Vergleichs ist nicht, dass `su` universell ausnutzbar ist. Es geht darum, dass sich dasselbe Image sehr unterschiedlich verhalten kann, je nachdem, ob `execve()` weiterhin eine Privilege Boundary überschreiten darf.

## Sicherheitsauswirkungen

Wenn `no_new_privs` fehlt, kann ein Foothold innerhalb des Containers möglicherweise weiterhin über setuid-Helper oder Binaries mit File Capabilities erweitert werden. Ist es vorhanden, werden diese Privilege Changes nach `exec` unterbunden. Der Effekt ist besonders relevant bei umfangreichen Base Images, die viele Utilities enthalten, die die Anwendung überhaupt nicht benötigt.

Außerdem gibt es eine wichtige Seccomp-Interaktion. Unprivilegierte Tasks müssen `no_new_privs` im Allgemeinen gesetzt haben, bevor sie einen Seccomp-Filter im Filter Mode installieren können. Das ist ein Grund, warum gehärtete Container häufig sowohl `Seccomp` als auch `NoNewPrivs` aktiviert anzeigen. Aus Sicht eines Angreifers bedeutet das Vorhandensein beider Optionen normalerweise, dass die Umgebung absichtlich und nicht versehentlich konfiguriert wurde.

## Fehlkonfigurationen

Das häufigste Problem besteht schlicht darin, diese Kontrolle in Umgebungen nicht zu aktivieren, in denen sie kompatibel wäre. In Kubernetes ist es oft ein operativer Standardfehler, `allowPrivilegeEscalation` aktiviert zu lassen. In Docker und Podman hat das Weglassen der entsprechenden Security Option denselben Effekt. Ein weiterer wiederkehrender Fehler besteht in der Annahme, dass `exec`-basierte Privilege Transitions automatisch irrelevant sind, nur weil ein Container „nicht privileged“ ist.

Eine subtilere Kubernetes-Falle besteht darin, dass `allowPrivilegeEscalation: false` nicht so berücksichtigt wird, wie viele erwarten, wenn der Container `privileged` ist oder über `CAP_SYS_ADMIN` verfügt. Die Kubernetes API dokumentiert, dass `allowPrivilegeEscalation` in diesen Fällen effektiv immer auf true gesetzt ist. In der Praxis bedeutet das, dass dieses Feld als ein Signal innerhalb der finalen Posture betrachtet werden sollte, nicht als Garantie dafür, dass die Runtime letztendlich mit `NoNewPrivs: 1` lief.

## Missbrauch

Wenn `no_new_privs` nicht gesetzt ist, lautet die erste Frage, ob das Image Binaries enthält, die ihre Privileges noch erhöhen können:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante Ergebnisse umfassen:

- `NoNewPrivs: 0`
- setuid-Hilfsprogramme wie `su`, `mount`, `passwd` oder distributionsspezifische Admin-Tools
- Binaries mit File-Capabilities, die Netzwerk- oder Dateisystemberechtigungen gewähren

In einem realen Assessment beweisen diese Befunde allein noch keine funktionierende Privilege Escalation, sie identifizieren jedoch genau die Binaries, die als Nächstes getestet werden sollten.

In Kubernetes sollte außerdem überprüft werden, ob die Absicht des YAML mit der Realität des Kernels übereinstimmt:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Interessante Kombinationen sind:

- `allowPrivilegeEscalation: false` in der Pod-Spezifikation, aber `NoNewPrivs: 0` im Container
- `cap_sys_admin` ist vorhanden, wodurch das Kubernetes-Feld deutlich weniger vertrauenswürdig ist
- `Seccomp: 0` und `NoNewPrivs: 0`, was normalerweise auf eine allgemein geschwächte Runtime-Sicherheitslage statt auf einen einzelnen isolierten Fehler hindeutet

### Vollständiges Beispiel: Privilege Escalation innerhalb des Containers durch setuid

Diese Kontrolle verhindert normalerweise **Privilege Escalation innerhalb des Containers** und nicht direkt einen Host Escape. Wenn `NoNewPrivs` `0` ist und ein setuid-Helper existiert, teste ihn explizit:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Wenn eine bekannte setuid-Binärdatei vorhanden und funktionsfähig ist, versuche, sie so zu starten, dass der Privilegienübergang erhalten bleibt:
```bash
/bin/su -c id 2>/dev/null
```
Dies allein ermöglicht noch keinen Escape aus dem Container, kann jedoch einen niedrig privilegierten Foothold innerhalb des Containers in container-root umwandeln, was häufig die Voraussetzung für einen späteren Host-Escape über Mounts, Runtime-Sockets oder kernelnahe Schnittstellen ist.

## Checks

Das Ziel dieser Checks ist festzustellen, ob eine Privilegienerhöhung zur Ausführungszeit blockiert wird und ob das Image weiterhin Helper enthält, die relevant wären, falls dies nicht der Fall ist.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Was hier interessant ist:

- `NoNewPrivs: 1` ist normalerweise das sicherere Ergebnis.
- `NoNewPrivs: 0` bedeutet, dass setuid- und auf File-Cap basierende Escalation-Pfade weiterhin relevant sind.
- `NoNewPrivs: 1` zusammen mit `Seccomp: 2` ist ein häufiges Anzeichen für eine bewusstere Hardening-Strategie.
- Ein Kubernetes-Manifest mit `allowPrivilegeEscalation: false` ist hilfreich, aber der Kernel-Status ist die maßgebliche Quelle.
- Ein minimales Image mit wenigen oder keinen setuid-/File-Cap-Binaries bietet einem Angreifer weniger Post-Exploitation-Optionen, selbst wenn `no_new_privs` fehlt.

## Laufzeit-Standards

| Runtime / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Explizit mit `--security-opt no-new-privileges=true` aktiviert; ein daemonweiter Standard ist außerdem über `dockerd --no-new-privileges` möglich | Weglassen des Flags, `--privileged` |
| Podman | Standardmäßig nicht aktiviert | Explizit mit `--security-opt no-new-privileges` oder einer gleichwertigen Security-Konfiguration aktiviert | Weglassen der Option, `--privileged` |
| Kubernetes | Durch die Workload-Policy gesteuert | `allowPrivilegeEscalation: false` fordert diesen Effekt an, aber `privileged: true` und `CAP_SYS_ADMIN` sorgen dafür, dass er effektiv aktiviert bleibt | `allowPrivilegeEscalation: true`, `privileged: true`, Hinzufügen von `CAP_SYS_ADMIN` |
| containerd / CRI-O unter Kubernetes | Folgt den Kubernetes-Workload-Einstellungen / `OCI process.noNewPrivileges` | Wird normalerweise vom Pod-Security-Kontext übernommen und in die OCI-Runtime-Konfiguration übersetzt | wie in der Kubernetes-Zeile |

Diese Schutzmaßnahme fehlt oft einfach deshalb, weil sie niemand aktiviert hat, nicht weil die Runtime sie nicht unterstützt.

## Referenzen

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
