# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Eine gute Container-Bewertung sollte zwei parallele Fragen beantworten. Erstens, was kann ein Angreifer aus dem aktuellen Workload heraus tun? Zweitens, welche Operator-Entscheidungen haben das möglich gemacht? Enumeration-Tools helfen bei der ersten Frage, und Hardening-Guidance hilft bei der zweiten. Beides auf einer Seite zu behalten, macht den Abschnitt nützlicher als Feldreferenz statt nur als Katalog von Escape-Tricks.

Ein praktisches Update für moderne Umgebungen ist, dass viele ältere Container-Writeups stillschweigend von einer **rootful runtime**, **no user namespace isolation** und oft **cgroup v1** ausgehen. Diese Annahmen sind heute nicht mehr sicher. Bevor man Zeit mit alten Escape-Primitives verbringt, sollte man zuerst bestätigen, ob der Workload rootless oder userns-remapped ist, ob der Host cgroup v2 verwendet und ob Kubernetes oder die runtime jetzt standardmäßig seccomp- und AppArmor-Profile anwendet. Diese Details entscheiden oft darüber, ob ein berühmter Breakout noch gilt.

## Enumeration Tools

Eine Reihe von Tools bleibt nützlich, um eine Container-Umgebung schnell zu charakterisieren:

- `linpeas` kann viele Container-Indikatoren, gemountete Sockets, Capability-Sets, gefährliche Filesystems und Breakout-Hinweise identifizieren.
- `CDK` konzentriert sich speziell auf Container-Umgebungen und umfasst Enumeration plus einige automatisierte Escape-Prüfungen.
- `amicontained` ist leichtgewichtig und nützlich, um Container-Einschränkungen, Capabilities, Namespace-Exposure und wahrscheinliche Breakout-Klassen zu identifizieren.
- `deepce` ist ein weiterer Container-fokussierter Enumerator mit breakout-orientierten Prüfungen.
- `grype` ist nützlich, wenn die Bewertung eine Prüfung der Image-Paket-Schwachstellen statt nur einer Runtime-Escape-Analyse umfasst.
- `Tracee` ist nützlich, wenn du **runtime evidence** statt nur statischer Lage brauchst, besonders bei verdächtiger Prozessausführung, Dateizugriffen und containerbewusster Event-Sammlung.
- `Inspektor Gadget` ist nützlich in Kubernetes- und Linux-Host-Untersuchungen, wenn du eBPF-gestützte Sichtbarkeit brauchst, die auf Pods, Container, Namespaces und andere höherstufige Konzepte zurückgeführt werden kann.

Der Wert dieser Tools liegt in Geschwindigkeit und Abdeckung, nicht in Gewissheit. Sie helfen, die grobe Lage schnell offenzulegen, aber die interessanten Funde müssen weiterhin manuell gegen das tatsächliche Runtime-, Namespace-, Capability- und Mount-Modell interpretiert werden.

## Hardening Priorities

Die wichtigsten Hardening-Prinzipien sind konzeptionell einfach, auch wenn ihre Umsetzung je nach Plattform variiert. Vermeide privileged containers. Vermeide gemountete runtime sockets. Gib Containern keine beschreibbaren Host-Pfade, außer es gibt dafür einen sehr spezifischen Grund. Nutze user namespaces oder rootless execution, wo immer möglich. Entferne alle Capabilities und füge nur die wieder hinzu, die der Workload wirklich benötigt. Lass seccomp, AppArmor und SELinux aktiviert, statt sie zu deaktivieren, um Probleme mit der Anwendungskompatibilität zu beheben. Begrenze Ressourcen, damit ein kompromittierter Container den Host nicht trivial lahmlegen kann.

Image- und Build-Hygiene sind genauso wichtig wie die Runtime-Lage. Verwende minimale Images, baue sie häufig neu, scanne sie, verlange Provenance, wo praktikabel, und halte Secrets aus Layers heraus. Ein Container, der als non-root mit einem kleinen Image und einer engen Syscall- und Capability-Angriffsfläche läuft, ist viel leichter zu verteidigen als ein großes Convenience-Image, das als host-equivalent root mit vorinstallierten Debugging-Tools läuft.

Für Kubernetes sind aktuelle Hardening-Baselines stärker opinionated, als viele Operatoren noch annehmen. Die eingebauten **Pod Security Standards** behandeln `restricted` als das Profil für die "current best practice": `allowPrivilegeEscalation` sollte `false` sein, Workloads sollten als non-root laufen, seccomp sollte explizit auf `RuntimeDefault` oder `Localhost` gesetzt sein, und Capability-Sets sollten aggressiv entfernt werden. Bei der Bewertung ist das wichtig, weil ein Cluster, der nur `warn`- oder `audit`-Labels verwendet, auf dem Papier gehärtet aussehen kann, in der Praxis aber trotzdem riskante Pods zulässt.

## Modern Triage Questions

Bevor du in escape-spezifische Seiten eintauchst, beantworte diese kurzen Fragen:

1. Ist der Workload **rootful**, **rootless** oder **userns-remapped**?
2. Nutzt der Node **cgroup v1** oder **cgroup v2**?
3. Sind **seccomp** und **AppArmor/SELinux** explizit konfiguriert oder nur übernommen, wenn verfügbar?
4. Wird in Kubernetes der Namespace tatsächlich **enforcing** `baseline` oder `restricted`, oder nur warning/auditing?

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

- Wenn `/proc/self/uid_map` zeigt, dass Container-root auf einen **hohen Host-UID-Bereich** gemappt ist, werden viele ältere Host-root-Writeups weniger relevant, weil root im Container nicht mehr gleichbedeutend mit Host-root ist.
- Wenn `/sys/fs/cgroup` `cgroup2fs` ist, sollten alte **cgroup v1**-spezifische Writeups wie `release_agent`-Missbrauch nicht mehr deine erste Vermutung sein.
- Wenn seccomp und AppArmor nur implizit geerbt werden, kann die Portabilität schwächer sein, als Verteidiger erwarten. In Kubernetes ist das explizite Setzen von `RuntimeDefault` oft stärker, als stillschweigend auf Node-Defaults zu vertrauen.
- Wenn `supplementalGroupsPolicy` auf `Strict` gesetzt ist, sollte der Pod zusätzliche Gruppenmitgliedschaften aus `/etc/group` innerhalb des Images nicht stillschweigend erben, wodurch das Verhalten von gruppenbasiertem Volume- und Dateizugriff vorhersehbarer wird.
- Namespace-Labels wie `pod-security.kubernetes.io/enforce=restricted` sollte man direkt prüfen. `warn` und `audit` sind nützlich, verhindern aber nicht, dass ein riskanter Pod erstellt wird.

## Resource-Exhaustion Examples

Resource-Kontrollen sind nicht glamourös, aber sie sind Teil der Container-Sicherheit, weil sie den Blast Radius einer Kompromittierung begrenzen. Ohne Memory-, CPU- oder PID-Limits kann schon eine einfache Shell ausreichen, um den Host oder benachbarte Workloads zu beeinträchtigen.

Beispiele für host-beeinflussende Tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Diese Beispiele sind nützlich, weil sie zeigen, dass nicht jedes gefährliche Container-Ergebnis ein sauberer "escape" ist. Schwache cgroup-Limits können code execution trotzdem in echten operativen Impact verwandeln.

In Kubernetes-gestützten Umgebungen solltest du außerdem prüfen, ob überhaupt Resource Controls vorhanden sind, bevor du DoS als theoretisch behandelst:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Für Docker-zentrierte Umgebungen bleibt `docker-bench-security` eine nützliche Host-seitige Audit-Baseline, da es häufige Konfigurationsprobleme anhand weithin anerkannter Benchmark-Empfehlungen überprüft:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Das Tool ist kein Ersatz für Threat Modeling, aber es ist dennoch wertvoll, um nachlässige Daemon-, Mount-, Network- und Runtime-Defaults zu finden, die sich im Laufe der Zeit ansammeln.

Für Kubernetes- und runtime-lastige Umgebungen kombiniere statische Checks mit Runtime-Visibility:

- `Tracee` ist nützlich für container-aware Runtime-Detection und schnelle Forensics, wenn du bestätigen musst, was ein kompromittierter Workload tatsächlich berührt hat.
- `Inspektor Gadget` ist nützlich, wenn die Assessment Kernel-Level-Telemetrie benötigt, die zurück zu Pods, Containern, DNS-Aktivität, Datei-Ausführung oder Network-Verhalten gemappt wird.

## Checks

Verwende diese als schnelle First-Pass-Commands während der Assessment:
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

- Ein Root-Prozess mit weitreichenden Capabilities und `Seccomp: 0` verdient sofortige Aufmerksamkeit.
- Ein Root-Prozess mit auch einem **1:1 UID map** ist weitaus interessanter als "root" innerhalb eines korrekt isolierten user namespace.
- `cgroup2fs` bedeutet meist, dass viele ältere **cgroup v1** Escape-Chains nicht dein bester Ausgangspunkt sind, während fehlendes `memory.max` oder `pids.max` weiterhin auf schwache blast-radius-Kontrollen hinweist.
- Verdächtige mounts und runtime sockets bieten oft einen schnelleren Weg zu Impact als jeder Kernel Exploit.
- Die Kombination aus schwacher runtime posture und schwachen resource limits deutet meist auf eine allgemein permissive container environment hin und nicht auf einen einzelnen isolierten Fehler.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
