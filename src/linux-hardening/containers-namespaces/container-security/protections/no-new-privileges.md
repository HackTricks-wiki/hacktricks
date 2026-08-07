# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ist eine Kernel-Hardening-Funktion, die verhindert, dass ein Prozess über `execve()` weitere Privilegien erhält. In der Praxis bedeutet dies: Sobald das Flag gesetzt ist, gewährt das Ausführen einer setuid-Binärdatei, einer setgid-Binärdatei oder einer Datei mit Linux-Dateifunktionen keine zusätzlichen Privilegien über die bereits vorhandenen Prozessprivilegien hinaus. In containerisierten Umgebungen ist dies wichtig, da viele Privilege-Escalation-Chains darauf beruhen, eine ausführbare Datei innerhalb des Images zu finden, die beim Starten die Privilegien ändert.

Aus defensiver Sicht ist `no_new_privs` kein Ersatz für Namespaces, seccomp oder das Entfernen von Capabilities. Es ist eine zusätzliche Schutzschicht. Sie blockiert eine bestimmte Klasse nachgelagerter Privilege Escalation, nachdem bereits Code Execution erreicht wurde. Dadurch ist sie besonders wertvoll in Umgebungen, in denen Images Helper-Binärdateien, Artefakte von Package-Managern oder Legacy-Tools enthalten, die bei einer teilweisen Kompromittierung andernfalls gefährlich wären.

## Funktionsweise

Das diesem Verhalten zugrunde liegende Kernel-Flag ist `PR_SET_NO_NEW_PRIVS`. Sobald es für einen Prozess gesetzt wurde, können nachfolgende `execve()`-Aufrufe die Privilegien nicht erhöhen. Das wichtige Detail ist, dass der Prozess weiterhin Binärdateien ausführen kann; er kann diese Binärdateien lediglich nicht dazu verwenden, eine Privilege Boundary zu überschreiten, die der Kernel andernfalls berücksichtigen würde.<sup>[[1]](#references)</sup>

Das Verhalten des Kernels wird außerdem **vererbt und ist irreversibel**: Sobald ein Task `no_new_privs` setzt, wird das Bit über `fork()`, `clone()` und `execve()` vererbt und kann später nicht zurückgesetzt werden.<sup>[[1]](#references)</sup> Das ist bei Assessments nützlich, da ein einzelnes `NoNewPrivs: 1` beim Container-Prozess normalerweise bedeutet, dass auch Nachkommen in diesem Modus bleiben sollten, sofern nicht ein vollständig anderer Prozessbaum untersucht wird.

In Kubernetes-orientierten Umgebungen entspricht `allowPrivilegeEscalation: false` diesem Verhalten für den Container-Prozess.<sup>[[2]](#references)</sup> In Docker- und Podman-ähnlichen Runtimes wird das Äquivalent normalerweise explizit über eine Security-Option aktiviert. Auf der OCI-Ebene erscheint dasselbe Konzept als `process.noNewPrivileges`.

## Wichtige Besonderheiten

`no_new_privs` blockiert den Privilege Gain **zum Zeitpunkt von `exec`**, nicht jede Privilegienänderung.<sup>[[1]](#references)</sup> Insbesondere gilt:

- setuid- und setgid-Übergänge funktionieren über `execve()` nicht mehr
- File Capabilities werden bei `execve()` nicht zum Permitted Set hinzugefügt
- LSMs wie AppArmor oder SELinux lockern ihre Einschränkungen nach `execve()` nicht
- bereits vorhandene Privilegien bleiben weiterhin vorhanden

Der letzte Punkt ist für den Betrieb wichtig. Wenn der Prozess bereits als root läuft, bereits über eine gefährliche Capability verfügt oder bereits Zugriff auf eine leistungsfähige Runtime-API oder ein beschreibbares Host-Mount hat, neutralisiert das Setzen von `no_new_privs` diese Angriffsflächen nicht. Es entfernt lediglich einen häufigen **nächsten Schritt** in einer Privilege-Escalation-Chain.

Beachte außerdem, dass das Flag keine Privilegienänderungen blockiert, die nicht von `execve()` abhängen.<sup>[[1]](#references)</sup> Ein Task, der bereits über ausreichende Privilegien verfügt, kann beispielsweise weiterhin direkt `setuid(2)` aufrufen oder einen privilegierten File Descriptor über einen Unix-Socket erhalten. Deshalb sollte `no_new_privs` zusammen mit [seccomp](seccomp.md), Capability-Sets und der Namespace-Exposition betrachtet werden und nicht als eigenständige Lösung.

## Lab

Untersuche den Status des aktuellen Prozesses:
```bash
grep NoNewPrivs /proc/self/status
```
Vergleiche das mit einem Container, bei dem die Runtime das Flag aktiviert:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Bei einer gehärteten Workload sollte das Ergebnis `NoNewPrivs: 1` anzeigen.

Sie können den tatsächlichen Effekt auch anhand einer setuid-Binärdatei demonstrieren:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Der Punkt des Vergleichs ist nicht, dass `su` universell ausnutzbar ist. Es geht darum, dass sich dasselbe Image sehr unterschiedlich verhalten kann, je nachdem, ob `execve()` weiterhin eine Privilege Boundary überschreiten darf.

## Sicherheitsauswirkungen

Wenn `no_new_privs` fehlt, kann ein Foothold innerhalb des Containers möglicherweise weiterhin über setuid helpers oder Binaries mit File Capabilities erweitert werden. Wenn es gesetzt ist, werden diese Privilege Changes nach `exec` unterbunden. Der Effekt ist besonders relevant bei umfangreichen Base Images, die zahlreiche Utilities enthalten, die die Anwendung überhaupt nicht benötigt.

Außerdem gibt es eine wichtige Seccomp-Interaktion. Unprivilegierte Tasks müssen `no_new_privs` in der Regel setzen, bevor sie einen Seccomp Filter im Filter Mode installieren können.<sup>[[1]](#references)</sup> Das ist ein Grund, warum gehärtete Container häufig sowohl `Seccomp` als auch `NoNewPrivs` aktiviert anzeigen. Aus Sicht eines Angreifers bedeutet das Vorhandensein beider Einstellungen normalerweise, dass die Umgebung bewusst und nicht versehentlich konfiguriert wurde.

## Fehlkonfigurationen

Das häufigste Problem besteht schlicht darin, diese Einstellung in Umgebungen nicht zu aktivieren, in denen sie kompatibel wäre. In Kubernetes ist es oft ein operativer Standardfehler, `allowPrivilegeEscalation` aktiviert zu lassen. In Docker und Podman hat das Weglassen der entsprechenden Security Option denselben Effekt. Ein weiterer wiederkehrender Fehler besteht in der Annahme, dass Exec-Time Privilege Transitions automatisch irrelevant sind, nur weil ein Container „nicht privileged“ ist.

Eine subtilere Kubernetes-Falle besteht darin, dass `allowPrivilegeEscalation: false` nicht so berücksichtigt wird, wie viele erwarten, wenn der Container `privileged` ist oder über `CAP_SYS_ADMIN` verfügt. Die Kubernetes API dokumentiert, dass `allowPrivilegeEscalation` in diesen Fällen effektiv immer true ist.<sup>[[2]](#references)</sup> In der Praxis bedeutet dies, dass das Feld als ein Signal innerhalb der finalen Sicherheitslage betrachtet werden sollte und nicht als Garantie dafür, dass die Runtime letztlich `NoNewPrivs: 1` gesetzt hat.

## Missbrauch

Wenn `no_new_privs` nicht gesetzt ist, lautet die erste Frage, ob das Image Binaries enthält, die ihre Privileges weiterhin erhöhen können:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante Ergebnisse umfassen:

- `NoNewPrivs: 0`
- setuid-Hilfsprogramme wie `su`, `mount`, `passwd` oder distributionsspezifische Admin-Tools
- Binaries mit File-Capabilities, die Netzwerk- oder Dateisystemberechtigungen gewähren

In einem realen Assessment beweisen diese Befunde für sich genommen keine funktionierende Privilege Escalation, identifizieren jedoch genau die Binaries, die als Nächstes getestet werden sollten.

Prüfe in Kubernetes außerdem, ob die YAML-Absicht mit der Realität des Kernels übereinstimmt:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Interessante Kombinationen umfassen:

- `allowPrivilegeEscalation: false` in der Pod-Spezifikation, aber `NoNewPrivs: 0` im Container
- `cap_sys_admin` ist vorhanden, wodurch das Kubernetes-Feld deutlich weniger vertrauenswürdig ist
- `Seccomp: 0` und `NoNewPrivs: 0`, was normalerweise auf eine umfassend geschwächte Runtime-Konfiguration statt auf einen einzelnen isolierten Fehler hindeutet

### Vollständiges Beispiel: In-Container Privilege Escalation durch setuid

Diese Kontrolle verhindert normalerweise **in-container privilege escalation** und nicht direkt einen Host Escape. Wenn `NoNewPrivs` `0` ist und ein setuid-Helper existiert, sollte dieser explizit getestet werden:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Wenn ein bekanntes setuid-Binary vorhanden und funktionsfähig ist, versuche, es so zu starten, dass der Privilege-Übergang erhalten bleibt:
```bash
/bin/su -c id 2>/dev/null
```
Dies ermöglicht allein noch keinen Escape aus dem Container, kann jedoch einen Low-Privilege-Foothold innerhalb des Containers in Container-Root umwandeln, was häufig die Voraussetzung für einen späteren Escape auf den Host über Mounts, Runtime-Sockets oder kernelnahe Schnittstellen ist.

## Checks

Ziel dieser Checks ist es festzustellen, ob ein Privilege Gain zur Ausführungszeit blockiert wird und ob das Image weiterhin Helper enthält, die relevant wären, falls dies nicht der Fall ist.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Was ist hier interessant:

- `NoNewPrivs: 1` ist normalerweise das sicherere Ergebnis.
- `NoNewPrivs: 0` bedeutet, dass auf setuid- und file-cap-basierende Escalation-Pfade weiterhin relevant sind.
- `NoNewPrivs: 1` zusammen mit `Seccomp: 2` ist ein häufiges Zeichen für eine bewusstere Hardening-Strategie.
- Ein Kubernetes-Manifest mit `allowPrivilegeEscalation: false` ist nützlich, aber der Kernel-Status ist die maßgebliche Quelle.
- Ein minimales Image mit wenigen oder keinen setuid-/file-cap-Binaries bietet einem Angreifer weniger Post-Exploitation-Optionen, selbst wenn `no_new_privs` fehlt.

## Laufzeitstandards

| Laufzeit / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Explizit mit `--security-opt no-new-privileges=true` aktiviert; ein daemonweiter Standard ist auch über `dockerd --no-new-privileges` möglich | Weglassen des Flags, `--privileged` |
| Podman | Standardmäßig nicht aktiviert | Explizit mit `--security-opt no-new-privileges` oder einer gleichwertigen Sicherheitskonfiguration aktiviert | Weglassen der Option, `--privileged` |
| Kubernetes | Durch die Workload-Richtlinie gesteuert | `allowPrivilegeEscalation: false` fordert den Effekt an, aber `privileged: true` und `CAP_SYS_ADMIN` sorgen dafür, dass er effektiv aktiviert bleibt | `allowPrivilegeEscalation: true`, `privileged: true`, Hinzufügen von `CAP_SYS_ADMIN` |
| containerd / CRI-O unter Kubernetes | Folgt den Kubernetes-Workload-Einstellungen / `OCI`-`process.noNewPrivileges` | Wird normalerweise vom Pod-Sicherheitskontext übernommen und in die OCI-Runtime-Konfiguration übersetzt | wie in der Kubernetes-Zeile |

Dieser Schutz fehlt oft einfach deshalb, weil ihn niemand aktiviert hat, nicht weil die Runtime ihn nicht unterstützt.

## Referenzen

- [1] [Linux-Kernel-Dokumentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Sicherheitskontext für einen Pod oder Container konfigurieren](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
