# Bewertung und Härtung

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Eine gute Container-Bewertung sollte zwei parallele Fragen beantworten. Erstens: Was kann ein Angreifer aus der aktuellen Workload heraus tun? Zweitens: Welche Entscheidungen des Operators haben dies ermöglicht? Enumeration-Tools helfen bei der ersten Frage, und Hardening-Guidance bei der zweiten. Beide Aspekte auf einer Seite zusammenzufassen, macht diesen Abschnitt als praktische Referenz nützlicher und nicht nur zu einem Katalog von Escape-Tricks.

Eine praktische Anpassung für moderne Umgebungen besteht darin, dass viele ältere Container-Writeups stillschweigend von einer **rootful runtime**, **keiner User-Namespace-Isolation** und häufig **cgroup v1** ausgehen. Diese Annahmen sind heute nicht mehr sicher. Bevor du Zeit in alte Escape-Primitives investierst, prüfe zuerst, ob die Workload rootless oder userns-remapped ist, ob der Host cgroup v2 verwendet und ob Kubernetes oder die Runtime inzwischen standardmäßige seccomp- und AppArmor-Profile anwendet. Diese Details entscheiden oft darüber, ob ein bekannter Breakout noch funktioniert.

## Enumeration-Tools

Eine Reihe von Tools bleibt nützlich, um eine Container-Umgebung schnell zu charakterisieren:

- `linpeas` kann viele Container-Indikatoren, gemountete Sockets, Capability-Sets, gefährliche Dateisysteme und Hinweise auf Breakouts identifizieren.
- `CDK` konzentriert sich speziell auf Container-Umgebungen und umfasst Enumeration sowie einige automatisierte Escape-Checks.
- `amicontained` ist leichtgewichtig und nützlich, um Container-Einschränkungen, Capabilities, Namespace-Exposure und wahrscheinliche Breakout-Klassen zu identifizieren.
- `deepce` ist ein weiterer auf Container fokussierter Enumerator mit Breakout-orientierten Checks.
- `grype` ist nützlich, wenn die Bewertung eine Vulnerability-Prüfung von Image-Paketen statt ausschließlich einer Analyse von Runtime-Escapes umfasst.
- `Tracee` ist nützlich, wenn du **Runtime-Evidenz** statt nur statischer Sicherheitslage benötigst, insbesondere für verdächtige Prozessausführung, Dateizugriffe und eine Container-bewusste Event-Sammlung.
- `Inspektor Gadget` ist bei Untersuchungen in Kubernetes- und Linux-Hosts nützlich, wenn du eBPF-basierte Sichtbarkeit benötigst, die sich auf Pods, Container, Namespaces und andere übergeordnete Konzepte zurückführen lässt.

Der Wert dieser Tools liegt in Geschwindigkeit und Abdeckung, nicht in Gewissheit. Sie helfen dabei, die grundlegende Sicherheitslage schnell sichtbar zu machen, doch die interessanten Findings müssen weiterhin manuell anhand des tatsächlichen Runtime-, Namespace-, Capability- und Mount-Modells interpretiert werden.

## Hardening-Prioritäten

Die wichtigsten Hardening-Prinzipien sind konzeptionell einfach, auch wenn ihre Umsetzung je nach Plattform variiert. Vermeide privilegierte Container. Vermeide gemountete Runtime-Sockets. Gib Containern keine beschreibbaren Host-Pfade, sofern es keinen sehr konkreten Grund dafür gibt. Verwende nach Möglichkeit User Namespaces oder eine rootless-Ausführung. Entferne alle Capabilities und füge nur diejenigen wieder hinzu, die die Workload tatsächlich benötigt. Lass seccomp, AppArmor und SELinux aktiviert, anstatt sie zur Behebung von Problemen mit der Anwendungskompatibilität zu deaktivieren. Begrenze Ressourcen, damit ein kompromittierter Container dem Host nicht ohne Weiteres den Dienst verweigern kann.

Image- und Build-Hygiene sind ebenso wichtig wie die Runtime-Sicherheitslage. Verwende minimale Images, erstelle sie regelmäßig neu, scanne sie, fordere nach Möglichkeit Provenance und halte Secrets aus den Layern heraus. Ein Container, der als Non-Root mit einem kleinen Image und einer schmalen Syscall- und Capability-Oberfläche läuft, ist deutlich einfacher zu schützen als ein großes Convenience-Image, das mit vorinstallierten Debugging-Tools als hostäquivalenter Root ausgeführt wird.

Für Kubernetes sind aktuelle Hardening-Baselines stärker vorgegeben, als viele Operatoren weiterhin annehmen. Die integrierten **Pod Security Standards** behandeln `restricted` als das Profil mit der "aktuell besten Praxis": `allowPrivilegeEscalation` sollte `false` sein, Workloads sollten als Non-Root ausgeführt werden, seccomp sollte explizit auf `RuntimeDefault` oder `Localhost` gesetzt sein, und Capability-Sets sollten konsequent entfernt werden. Bei der Bewertung ist dies wichtig, da ein Cluster, der lediglich `warn`- oder `audit`-Labels verwendet, auf dem Papier gehärtet wirken kann, während er in der Praxis weiterhin riskante Pods zulässt.<sup>[[1]](#references)</sup>

## Moderne Triage-Fragen

Bevor du dich mit spezifischen Escape-Seiten befasst, beantworte diese kurzen Fragen:

1. Ist die Workload **rootful**, **rootless** oder **userns-remapped**?
2. Verwendet der Node **cgroup v1** oder **cgroup v2**?
3. Sind **seccomp** und **AppArmor/SELinux** explizit konfiguriert oder werden sie lediglich übernommen, sofern verfügbar?
4. Erzwingt der Namespace in Kubernetes tatsächlich `baseline` oder `restricted`, oder warnt bzw. auditiert er nur?

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
- Wenn `/sys/fs/cgroup` `cgroup2fs` ist, sollten alte, spezifisch auf **cgroup v1** ausgerichtete Writeups wie der Missbrauch von `release_agent` nicht mehr deine erste Vermutung sein.
- Wenn seccomp und AppArmor nur implizit geerbt werden, kann die Portabilität schwächer sein als von Defenders erwartet. In Kubernetes ist das explizite Setzen von `RuntimeDefault` oft sicherer, als sich stillschweigend auf Node-Defaults zu verlassen.
- Wenn `supplementalGroupsPolicy` auf `Strict` gesetzt ist, sollte der Pod nicht stillschweigend zusätzliche Gruppenmitgliedschaften aus `/etc/group` innerhalb des Images erben. Dadurch wird das Verhalten des gruppenbasierten Zugriffs auf Volumes und Dateien vorhersehbarer.
- Namespace-Labels wie `pod-security.kubernetes.io/enforce=restricted` sollten direkt überprüft werden. `warn` und `audit` sind nützlich, verhindern jedoch nicht, dass ein riskanter Pod erstellt wird.

## Runtime-Baseline-Triage

Eine Runtime-Baseline ist die schnelle Prüfung, anhand derer du feststellst, ob ein Container wie ein gewöhnlicher isolierter Workload oder wie ein Host-Impacting-Control-Plane-Foothold wirkt. Sie sollte genügend Fakten erfassen, um die nächste zu prüfende Seite zu priorisieren: Missbrauch des Runtime-Sockets, Host-Mounts, Namespaces, cgroups, Capabilities oder die Überprüfung von Image-Secrets.

Nützliche Prüfungen innerhalb eines Workloads:
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

- Fehlende oder unbegrenzte `memory.max` / `pids.max` weisen auf schwache Kontrollen des Schadensradius hin, selbst ohne einen sauberen Escape.
- Eine Root-Shell mit `NoNewPrivs: 0`, weitreichenden Capabilities und permissivem seccomp ist deutlich interessanter als eine eng begrenzte Non-Root-Workload.
- Runtime-Sockets und beschreibbare Host-Mounts sind Kernel-Exploits normalerweise vorzuziehen, da sie bereits einen Management- oder Dateisystem-Kontrollpfad offenlegen.
- Gemeinsame PID-, Netzwerk-, IPC- oder cgroup-Namespaces ermöglichen nicht immer allein vollständige Escapes, erleichtern jedoch das Auffinden des nächsten Schritts.

## Beispiele für Ressourcenerschöpfung

Ressourcenkontrollen sind nicht glamourös, gehören aber zur Container-Sicherheit, da sie den Schadensradius einer Kompromittierung begrenzen. Ohne Speicher-, CPU- oder PID-Limits kann eine einfache Shell ausreichen, um den Host oder benachbarte Workloads zu beeinträchtigen.

Beispiele für Tests mit Auswirkungen auf den Host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Diese Beispiele sind nützlich, weil sie zeigen, dass nicht jedes gefährliche Ergebnis eines Containers ein sauberer „escape“ ist. Schwache cgroup limits können Codeausführung dennoch in reale operative Auswirkungen verwandeln.

In Kubernetes-gestützten Umgebungen sollte außerdem geprüft werden, ob überhaupt Resource Controls vorhanden sind, bevor DoS als theoretisch betrachtet wird:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening-Tools

Für Docker-zentrierte Umgebungen bleibt `docker-bench-security` eine nützliche hostseitige Audit-Baseline, da es häufige Konfigurationsprobleme anhand weithin anerkannter Benchmark-Empfehlungen prüft:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Das Tool ist kein Ersatz für Threat Modeling, aber dennoch wertvoll, um nachlässige Daemon-, Mount-, Netzwerk- und Laufzeit-Standardeinstellungen zu finden, die sich im Laufe der Zeit ansammeln.

Für Kubernetes- und laufzeitintensive Umgebungen sollten statische Prüfungen mit Laufzeittransparenz kombiniert werden:

- `Tracee` eignet sich für containerbewusste Laufzeiterkennung und schnelle Forensik, wenn bestätigt werden muss, worauf ein kompromittierter Workload tatsächlich zugegriffen hat.
- `Inspektor Gadget` eignet sich, wenn die Bewertung Telemetrie auf Kernel-Ebene erfordert, die Pods, Container, DNS-Aktivitäten, Dateiausführung oder Netzwerkverhalten zugeordnet wird.

## Prüfungen

Verwende diese Befehle während der Bewertung als schnelle erste Prüfungen:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Was hier interessant ist:

- Ein root-Prozess mit weitreichenden Capabilities und `Seccomp: 0` verdient sofortige Aufmerksamkeit.
- Ein root-Prozess, der außerdem über ein **1:1-UID-Mapping** verfügt, ist weitaus interessanter als „root“ innerhalb eines ordnungsgemäß isolierten User Namespace.
- `cgroup2fs` bedeutet normalerweise, dass viele ältere **cgroup-v1**-Escape-Chains nicht der beste Ausgangspunkt sind, während fehlende `memory.max`- oder `pids.max`-Werte weiterhin auf schwache Kontrollen des Explosionsradius hinweisen.
- Verdächtige Mounts und Runtime-Sockets bieten oft einen schnelleren Weg zu Auswirkungen als jeder Kernel-Exploit.
- Die Kombination aus einer schwachen Runtime-Sicherheitslage und schwachen Ressourcenlimits deutet normalerweise auf eine allgemein permissive Container-Umgebung statt auf einen einzelnen isolierten Fehler hin.

## Referenzen

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
