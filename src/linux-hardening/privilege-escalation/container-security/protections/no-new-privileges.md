# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ist ein Kernel-Hardening-Feature, das verhindert, dass ein Prozess über `execve()` zusätzliche Privilegien erhält. Praktisch heißt das: Sobald das Flag gesetzt ist, verleiht das Ausführen eines setuid-Binaries, eines setgid-Binaries oder einer Datei mit Linux File Capabilities keine zusätzlichen Privilegien über das hinaus, was der Prozess bereits hatte. In containerisierten Umgebungen ist das wichtig, weil viele Privilege-Escalation-Chains darauf beruhen, ein ausführbares Programm im Image zu finden, das beim Start seine Privilegien ändert.

Aus defensiver Sicht ist `no_new_privs` kein Ersatz für Namespaces, seccomp oder Capability-Dropping. Es ist eine Verstärkungsschicht. Es blockiert eine bestimmte Klasse von nachgelagerten Eskalationen, nachdem Code Execution bereits erlangt wurde. Das macht es besonders wertvoll in Umgebungen, in denen Images Hilfs-Binaries, Package-Manager-Artefakte oder Legacy-Tools enthalten, die in Kombination mit einer teilweisen Kompromittierung sonst gefährlich wären.

## Operation

Das Kernel-Flag hinter diesem Verhalten ist `PR_SET_NO_NEW_PRIVS`. Sobald es für einen Prozess gesetzt ist, können spätere `execve()`-Aufrufe die Privilegien nicht erhöhen. Das wichtige Detail ist, dass der Prozess weiterhin Binaries ausführen kann; er kann diese Binaries nur nicht verwenden, um eine Privilegiengrenze zu überschreiten, die der Kernel sonst akzeptieren würde.

Das Kernel-Verhalten ist außerdem **vererbt und irreversibel**: Sobald eine Task `no_new_privs` setzt, wird das Bit über `fork()`, `clone()` und `execve()` hinweg vererbt und kann später nicht mehr zurückgesetzt werden. Das ist bei Assessments nützlich, weil ein einzelnes `NoNewPrivs: 1` beim Container-Prozess normalerweise bedeutet, dass auch Nachkommen in diesem Modus bleiben sollten, sofern du nicht einen völlig anderen Prozessbaum betrachtest.

In Kubernetes-orientierten Umgebungen wird `allowPrivilegeEscalation: false` auf dieses Verhalten für den Container-Prozess abgebildet. In Docker- und Podman-ähnlichen Runtimes wird das Äquivalent meist explizit über eine Security-Option aktiviert. Auf OCI-Ebene erscheint dasselbe Konzept als `process.noNewPrivileges`.

## Wichtige Nuancen

`no_new_privs` blockiert Privilege Gain zur **Exec-Zeit**, nicht jede Privilegänderung. Insbesondere:

- setuid- und setgid-Übergänge funktionieren über `execve()` nicht mehr
- File Capabilities werden dem Permitted Set bei `execve()` nicht hinzugefügt
- LSMs wie AppArmor oder SELinux lockern die Einschränkungen nach `execve()` nicht
- bereits vorhandene Privilegien bleiben weiterhin bereits vorhandene Privilegien

Der letzte Punkt ist betrieblich wichtig. Wenn der Prozess bereits als root läuft, bereits eine gefährliche Capability hat oder bereits Zugriff auf eine mächtige Runtime-API oder ein schreibbares Host-Mount hat, neutralisiert `no_new_privs` diese Angriffsflächen nicht. Es entfernt nur einen häufigen **nächsten Schritt** in einer Privilege-Escalation-Chain.

Beachte auch, dass das Flag keine Privilegänderungen blockiert, die nicht von `execve()` abhängen. Ein Prozess, der bereits ausreichend privilegiert ist, kann beispielsweise weiterhin direkt `setuid(2)` aufrufen oder einen privilegierten File Descriptor über ein Unix-Socket empfangen. Deshalb sollte `no_new_privs` zusammen mit [seccomp](seccomp.md), Capability-Sets und Namespace-Exponierung betrachtet werden und nicht als alleinige Lösung.

## Lab

Untersuche den aktuellen Prozesszustand:
```bash
grep NoNewPrivs /proc/self/status
```
Vergleiche das mit einem Container, in dem die Runtime das Flag aktiviert:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Auf einem gehärteten Workload sollte das Ergebnis `NoNewPrivs: 1` anzeigen.

Du kannst auch die tatsächliche Wirkung gegen ein setuid-Binary demonstrieren:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Der Punkt des Vergleichs ist nicht, dass `su` universell ausnutzbar ist. Es ist, dass dasselbe Image sich sehr unterschiedlich verhalten kann, je nachdem, ob `execve()` noch eine Privileggrenze überschreiten darf.

## Security Impact

Wenn `no_new_privs` fehlt, kann ein foothold innerhalb des Containers möglicherweise noch über setuid helpers oder binaries mit file capabilities eskaliert werden. Ist es gesetzt, werden diese Privilegänderungen nach `exec` unterbunden. Der Effekt ist besonders relevant bei breiten base images, die viele Utilities mitbringen, die die Anwendung ursprünglich gar nicht brauchte.

Es gibt auch eine wichtige seccomp-Interaktion. Nicht privilegierte Tasks benötigen im Allgemeinen `no_new_privs`, bevor sie einen seccomp filter im filter mode installieren können. Das ist ein Grund, warum gehärtete Container oft sowohl `Seccomp` als auch `NoNewPrivs` gemeinsam aktiviert zeigen. Aus Angreiferperspektive bedeutet beides meist, dass die Umgebung absichtlich und nicht versehentlich konfiguriert wurde.

## Misconfigurations

Das häufigste Problem ist einfach, die Kontrolle in Umgebungen nicht zu aktivieren, in denen sie kompatibel wäre. In Kubernetes ist das Belassen von `allowPrivilegeEscalation` aktiviert oft der Standard-Fehler im Betrieb. In Docker und Podman hat das Weglassen der relevanten security option denselben Effekt. Ein weiterer wiederkehrender Fehler ist die Annahme, dass `exec`-zeitliche Privilegübergänge automatisch irrelevant seien, nur weil ein Container "not privileged" ist.

Ein subtilerer Kubernetes-Fallstrick ist, dass `allowPrivilegeEscalation: false` **nicht** so berücksichtigt wird, wie viele erwarten, wenn der Container `privileged` ist oder `CAP_SYS_ADMIN` hat. Die Kubernetes API dokumentiert, dass `allowPrivilegeEscalation` in diesen Fällen faktisch immer true ist. In der Praxis bedeutet das, dass das Feld als ein Signal im finalen Gesamtbild behandelt werden sollte, nicht als Garantie dafür, dass die Runtime am Ende `NoNewPrivs: 1` gesetzt hat.

## Abuse

Wenn `no_new_privs` nicht gesetzt ist, lautet die erste Frage, ob das Image binaries enthält, die Privilegien noch erhöhen können:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante Ergebnisse umfassen:

- `NoNewPrivs: 0`
- setuid helpers wie `su`, `mount`, `passwd` oder distributionsspezifische Admin-Tools
- binaries mit file capabilities, die Netzwerk- oder Filesystem-Privilegien gewähren

In einer realen Assessment beweisen diese Findings für sich allein keine funktionierende Eskalation, aber sie identifizieren genau die binaries, die als Nächstes getestet werden sollten.

In Kubernetes solltest du außerdem verifizieren, dass die YAML-Intention mit der Kernel-Realität übereinstimmt:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Interessante Kombinationen sind:

- `allowPrivilegeEscalation: false` im Pod spec, aber `NoNewPrivs: 0` im Container
- `cap_sys_admin` vorhanden, was das Kubernetes-Feld deutlich weniger vertrauenswürdig macht
- `Seccomp: 0` und `NoNewPrivs: 0`, was meist auf eine insgesamt geschwächte Runtime-Position statt auf einen einzelnen isolierten Fehler hindeutet

### Vollständiges Beispiel: Privilege Escalation im Container durch setuid

Diese Kontrolle verhindert normalerweise **in-container privilege escalation** statt direkt host escape. Wenn `NoNewPrivs` `0` ist und ein setuid-Helper existiert, teste es explizit:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Wenn ein bekanntes setuid-Binary vorhanden und funktionsfähig ist, versuche, es so zu starten, dass der Privilegienwechsel erhalten bleibt:
```bash
/bin/su -c id 2>/dev/null
```
Dies allein entkommt nicht aus dem Container, aber es kann einen Low-Privilege-Foothold innerhalb des Containers in container-root verwandeln, was oft die Voraussetzung für einen späteren Host-Escape über mounts, Runtime-Sockets oder kernel-facing Interfaces wird.

## Checks

Das Ziel dieser Checks ist festzustellen, ob exec-time privilege gain blockiert ist und ob das Image noch Helper enthält, die relevant wären, falls dies nicht der Fall ist.
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
- `NoNewPrivs: 0` bedeutet, dass setuid- und file-cap-basierte Eskalationspfade weiterhin relevant sind.
- `NoNewPrivs: 1` zusammen mit `Seccomp: 2` ist ein häufiges Zeichen für eine bewusstere Hardening-Strategie.
- Ein Kubernetes-Manifest mit `allowPrivilegeEscalation: false` ist nützlich, aber der Kernel-Status ist die Quelle der Wahrheit.
- Ein minimales Image mit wenigen oder keinen setuid/file-cap-Binaries gibt einem Angreifer weniger post-exploitation Optionen, selbst wenn `no_new_privs` fehlt.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Nicht standardmäßig aktiviert | Explizit aktiviert mit `--security-opt no-new-privileges=true`; ein daemon-weiter Default existiert auch via `dockerd --no-new-privileges` | Weglassen des Flags, `--privileged` |
| Podman | Nicht standardmäßig aktiviert | Explizit aktiviert mit `--security-opt no-new-privileges` oder entsprechender Security-Konfiguration | Weglassen der Option, `--privileged` |
| Kubernetes | Durch Workload-Policy gesteuert | `allowPrivilegeEscalation: false` fordert den Effekt an, aber `privileged: true` und `CAP_SYS_ADMIN` halten es effektiv auf true | `allowPrivilegeEscalation: true`, `privileged: true`, Hinzufügen von `CAP_SYS_ADMIN` |
| containerd / CRI-O unter Kubernetes | Folgt den Kubernetes-Workload-Einstellungen / OCI `process.noNewPrivileges` | Normalerweise vom Pod Security Context geerbt und in die OCI-Runtime-Konfiguration übersetzt | wie in der Kubernetes-Zeile |

Diese Schutzmaßnahme fehlt oft einfach deshalb, weil niemand sie aktiviert hat, nicht weil die Runtime sie nicht unterstützt.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
