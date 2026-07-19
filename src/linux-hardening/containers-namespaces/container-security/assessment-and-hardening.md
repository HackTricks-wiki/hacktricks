# Bewertung und Härtung

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Eine gute Container-Bewertung sollte zwei parallele Fragen beantworten. Erstens: Was kann ein Angreifer aus der aktuellen Workload heraus tun? Zweitens: Welche Entscheidungen des Operators haben das ermöglicht? Enumeration-Tools helfen bei der ersten Frage, und Hardening-Guidance bei der zweiten. Beide Aspekte auf einer Seite zusammenzufassen, macht diesen Abschnitt als Feldreferenz nützlicher als einen reinen Katalog von Escape-Tricks.

Eine praktische Aktualisierung für moderne Umgebungen ist, dass viele ältere Container-Writeups stillschweigend von einer **rootful runtime**, **keiner User-Namespace-Isolation** und häufig von **cgroup v1** ausgehen. Diese Annahmen sind nicht mehr sicher. Bevor Zeit in alte Escape-Primitives investiert wird, sollte zunächst geprüft werden, ob die Workload rootless oder userns-remapped läuft, ob der Host cgroup v2 verwendet und ob Kubernetes oder die Runtime inzwischen standardmäßige seccomp- und AppArmor-Profile anwendet. Diese Details entscheiden häufig darüber, ob ein bekannter Breakout noch funktioniert.

## Enumeration-Tools

Eine Reihe von Tools ist weiterhin nützlich, um eine Container-Umgebung schnell zu charakterisieren:

- `linpeas` kann viele Container-Indikatoren, gemountete Sockets, Capability-Sets, gefährliche Filesystems und Hinweise auf Breakouts identifizieren.
- `CDK` konzentriert sich speziell auf Container-Umgebungen und umfasst Enumeration sowie einige automatisierte Escape-Checks.
- `amicontained` ist leichtgewichtig und nützlich, um Container-Einschränkungen, Capabilities, Namespace-Exposure und wahrscheinliche Breakout-Klassen zu identifizieren.
- `deepce` ist ein weiterer auf Container fokussierter Enumerator mit Breakout-orientierten Checks.
- `grype` ist nützlich, wenn die Bewertung neben der Runtime-Escape-Analyse auch eine Überprüfung auf Schwachstellen in Image-Paketen umfasst.
- `Tracee` ist nützlich, wenn **Runtime-Evidenz** statt ausschließlich einer statischen Bewertung benötigt wird, insbesondere für die Ausführung verdächtiger Prozesse, Dateizugriffe und die containerbewusste Erfassung von Events.
- `Inspektor Gadget` ist bei Untersuchungen in Kubernetes- und Linux-Host-Umgebungen nützlich, wenn eBPF-basierte Sichtbarkeit benötigt wird, die sich auf Pods, Container, Namespaces und andere übergeordnete Konzepte zurückführen lässt.

Der Wert dieser Tools liegt in Geschwindigkeit und Abdeckung, nicht in Gewissheit. Sie helfen dabei, die grundlegende Sicherheitslage schnell sichtbar zu machen, doch interessante Findings müssen weiterhin manuell anhand der tatsächlichen Runtime-, Namespace-, Capability- und Mount-Modelle interpretiert werden.

## Hardening-Prioritäten

Die wichtigsten Hardening-Prinzipien sind konzeptionell einfach, auch wenn ihre Umsetzung je nach Plattform variiert. Privilegierte Container sollten vermieden werden. Gemountete Runtime-Sockets sollten vermieden werden. Container sollten keine beschreibbaren Host-Pfade erhalten, sofern es dafür keinen sehr spezifischen Grund gibt. Verwende User-Namespaces oder eine rootless-Ausführung, sofern dies praktikabel ist. Entferne alle Capabilities und füge nur diejenigen wieder hinzu, die die Workload tatsächlich benötigt. Seccomp, AppArmor und SELinux sollten aktiviert bleiben, anstatt sie zur Behebung von Problemen mit der Anwendungskompatibilität zu deaktivieren. Begrenze Ressourcen, damit ein kompromittierter Container dem Host nicht ohne Weiteres den Dienst verweigern kann.

Image- und Build-Hygiene sind ebenso wichtig wie die Runtime-Sicherheitslage. Verwende minimale Images, baue sie regelmäßig neu, scanne sie, verlange, wo praktikabel, eine Provenance und halte Secrets aus den Layern heraus. Ein Container, der als non-root mit einem kleinen Image und einer begrenzten Syscall- und Capability-Oberfläche läuft, ist wesentlich einfacher zu verteidigen als ein großes Convenience-Image, das mit hostgleichwertigen Root-Rechten läuft und vorinstallierte Debugging-Tools enthält.

Für Kubernetes sind aktuelle Hardening-Baselines konkreter, als viele Operatoren noch annehmen. Die integrierten **Pod Security Standards** betrachten `restricted` als das Profil mit der "aktuellen Best Practice": `allowPrivilegeEscalation` sollte `false` sein, Workloads sollten als non-root laufen, seccomp sollte explizit auf `RuntimeDefault` oder `Localhost` gesetzt werden, und Capability-Sets sollten konsequent entfernt werden. Bei der Bewertung ist dies relevant, weil ein Cluster, der nur `warn`- oder `audit`-Labels verwendet, auf dem Papier gehärtet wirken kann, während er in der Praxis weiterhin riskante Pods zulässt.

## Moderne Triage-Fragen

Bevor du dich mit spezifischen Escape-Seiten beschäftigst, beantworte diese kurzen Fragen:

1. Läuft die Workload **rootful**, **rootless** oder **userns-remapped**?
2. Verwendet der Node **cgroup v1** oder **cgroup v2**?
3. Sind **seccomp** und **AppArmor/SELinux** explizit konfiguriert oder werden sie lediglich übernommen, wenn verfügbar?
4. Erzwingt der Namespace in Kubernetes tatsächlich `baseline` oder `restricted`, oder wird nur gewarnt bzw. auditiert?

Nützliche Checks:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
Was hier interessant ist:

- Wenn `/proc/self/uid_map` zeigt, dass Container-root einem **hohen Host-UID-Bereich** zugeordnet ist, sind viele ältere Writeups zu Host-root weniger relevant, da root im Container nicht mehr dem Host-root entspricht.
- Wenn `/sys/fs/cgroup` `cgroup2fs` ist, sollten alte, spezifische **cgroup v1**-Writeups wie der Missbrauch von `release_agent` nicht mehr deine erste Vermutung sein.
- Wenn seccomp und AppArmor nur implizit vererbt werden, kann die Portabilität schwächer sein als von Defenders erwartet. In Kubernetes ist das explizite Setzen von `RuntimeDefault` oft sicherer, als sich stillschweigend auf Node-Defaults zu verlassen.
- Wenn `supplementalGroupsPolicy` auf `Strict` gesetzt ist, sollte der Pod nicht stillschweigend zusätzliche Gruppenmitgliedschaften aus `/etc/group` innerhalb des Images übernehmen. Dadurch wird das Verhalten beim gruppenbasierten Volume- und Dateizugriff vorhersehbarer.
- Namespace-Labels wie `pod-security.kubernetes.io/enforce=restricted` sollten direkt überprüft werden. `warn` und `audit` sind nützlich, verhindern aber nicht, dass ein riskanter Pod erstellt wird.

## Runtime-Baseline-Triage

Eine Runtime-Baseline ist der schnelle Check, der dir zeigt, ob ein Container wie ein gewöhnlicher isolierter Workload oder wie ein Foothold in einer hostbeeinflussenden Control Plane wirkt. Dabei sollten genügend Fakten gesammelt werden, um die nächste zu prüfende Seite zu priorisieren: Missbrauch des Runtime-Sockets, Host-Mounts, Namespaces, cgroups, Capabilities oder die Überprüfung von Image-Secrets.

Nützliche Checks innerhalb eines Workloads:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Interpretation:

- Ein fehlendes oder unbegrenztes `memory.max` / `pids.max` weist auf schwache Kontrollen des Wirkungsradius hin, selbst wenn kein sauberer Escape möglich ist.
- Eine Root-Shell mit `NoNewPrivs: 0`, umfangreichen Capabilities und permissivem seccomp ist deutlich interessanter als ein eingeschränkter Non-Root-Workload.
- Runtime-Sockets und beschreibbare Host-Mounts sind meist höher zu priorisieren als Kernel-Exploits, da sie bereits einen Management- oder Dateisystem-Kontrollpfad offenlegen.
- Geteilte PID-, Netzwerk-, IPC- oder cgroup-Namespaces sind nicht immer allein vollständige Escapes, erleichtern jedoch das Finden des nächsten Schritts.

## Beispiele für Ressourcenerschöpfung

Ressourcenkontrollen sind nicht glamourös, gehören aber zur Containersicherheit, da sie den Wirkungsradius einer Kompromittierung begrenzen. Ohne Speicher-, CPU- oder PID-Limits kann eine einfache Shell ausreichen, um den Host oder benachbarte Workloads zu beeinträchtigen.

Beispiele für Tests mit Auswirkungen auf den Host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Diese Beispiele sind nützlich, weil sie zeigen, dass nicht jedes gefährliche Container-Ergebnis ein sauberer „escape“ ist. Schwache cgroup-Limits können Code execution dennoch in reale betriebliche Auswirkungen verwandeln.

Prüfe in Kubernetes-gestützten Umgebungen außerdem, ob überhaupt Ressourcenbeschränkungen vorhanden sind, bevor du DoS als theoretisch abtust:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening-Tools

Für Docker-zentrierte Umgebungen bleibt `docker-bench-security` eine nützliche hostseitige Grundlage für Audits, da es gängige Konfigurationsprobleme anhand weit verbreiteter Benchmark-Richtlinien prüft:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Das Tool ist kein Ersatz für Threat Modeling, aber dennoch wertvoll, um nachlässige Daemon-, Mount-, Netzwerk- und Runtime-Standardeinstellungen zu finden, die sich im Laufe der Zeit ansammeln.

Für Kubernetes- und Runtime-lastige Umgebungen sollten statische Prüfungen mit Runtime-Visibility kombiniert werden:

- `Tracee` eignet sich für die containerbewusste Runtime-Erkennung und schnelle Forensik, wenn bestätigt werden muss, worauf ein kompromittierter Workload tatsächlich zugegriffen hat.
- `Inspektor Gadget` eignet sich, wenn die Bewertung Kernel-Level-Telemetrie benötigt, die auf Pods, Container, DNS-Aktivitäten, Dateiausführung oder Netzwerkverhalten zurückgeführt wird.

## Checks

Verwende diese als schnelle Befehle für eine erste Prüfung während der Bewertung:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Was ist hier interessant:

- Ein Root-Prozess mit weitreichenden Capabilities und `Seccomp: 0` verdient sofortige Aufmerksamkeit.
- Ein Root-Prozess mit einer **1:1-UID-Map** ist weitaus interessanter als „Root“ innerhalb eines ordnungsgemäß isolierten User Namespace.
- `cgroup2fs` bedeutet normalerweise, dass viele ältere **cgroup-v1**-Escape-Ketten nicht der beste Ausgangspunkt sind, während fehlende `memory.max`- oder `pids.max`-Werte weiterhin auf schwache Kontrollen des Blast Radius hindeuten.
- Verdächtige Mounts und Runtime-Sockets bieten oft einen schnelleren Weg zu Auswirkungen als jeder Kernel-Exploit.
- Die Kombination aus schwachem Runtime-Status und schwachen Ressourcenlimits deutet normalerweise auf eine insgesamt permissive Container-Umgebung hin und nicht auf einen einzelnen isolierten Fehler.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
