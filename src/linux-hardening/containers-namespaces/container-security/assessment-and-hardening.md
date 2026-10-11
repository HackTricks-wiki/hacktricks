# Bewertung und Härtung

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Eine gute Container-Bewertung sollte zwei parallele Fragen beantworten. Erstens: Was kann ein Angreifer von der aktuellen Workload aus tun? Zweitens: Welche Entscheidungen der Betreiber haben das ermöglicht? Enumeration-Tools helfen bei der ersten Frage, Härtungsrichtlinien bei der zweiten. Beides auf einer Seite zusammenzuführen macht diesen Abschnitt als praktische Referenz vor Ort nützlicher als einen bloßen Katalog von Escape-Techniken.

Eine praktische Anpassung für moderne Umgebungen: Viele ältere Container-Beiträge setzen stillschweigend **rootful runtime**, **keine User-Namespace-Isolierung** und häufig **cgroup v1** voraus. Diese Annahmen sind nicht mehr sicher. Bevor du Zeit in alte Escape-Primitives investierst, prüfe zunächst, ob die Workload rootless oder userns-remapped ist, ob der Host cgroup v2 verwendet und ob Kubernetes oder die Runtime inzwischen standardmäßig Seccomp- und AppArmor-Profile anwendet. Diese Details entscheiden oft darüber, ob ein bekannter Breakout noch funktioniert.

## Enumeration-Tools

Eine Reihe von Tools ist weiterhin nützlich, um eine Container-Umgebung schnell zu charakterisieren:

- `linpeas` kann viele Container-Indikatoren, gemountete Sockets, Capability-Sets, gefährliche Dateisysteme und Hinweise auf Breakouts erkennen.
- `CDK` ist speziell auf Container-Umgebungen ausgerichtet und umfasst sowohl Enumeration als auch einige automatisierte Escape-Prüfungen.
- `amicontained` ist schlank und nützlich, um Container-Einschränkungen, Capabilities, Namespace-Sichtbarkeit und wahrscheinliche Breakout-Klassen zu erkennen.
- `deepce` ist ein weiteres auf Container ausgerichtetes Enumeration-Tool mit Breakout-orientierten Prüfungen.
- `grype` ist nützlich, wenn die Bewertung auch die Prüfung von Image-Paket-Schwachstellen umfasst und sich nicht nur auf die Escape-Analyse zur Laufzeit beschränkt.
- `Tracee` ist nützlich, wenn du **Laufzeitnachweise** statt ausschließlich einer statischen Bewertung benötigst, insbesondere bei verdächtiger Prozessausführung, Dateizugriff und der containerbewussten Erfassung von Ereignissen.
- `Inspektor Gadget` ist bei Kubernetes- und Linux-Host-Untersuchungen nützlich, wenn du eBPF-gestützte Sichtbarkeit benötigst, die sich Pods, Containern, Namespaces und anderen übergeordneten Konzepten zuordnen lässt.

Der Nutzen dieser Tools liegt in ihrer Geschwindigkeit und Abdeckung, nicht in ihrer Gewissheit. Sie helfen dabei, die allgemeine Sicherheitslage schnell zu erkennen; interessante Befunde müssen jedoch weiterhin manuell anhand des tatsächlichen Runtime-, Namespace-, Capability- und Mount-Modells interpretiert werden.

## Härtungsprioritäten

Die wichtigsten Härtungsprinzipien sind konzeptionell einfach, auch wenn ihre Umsetzung je nach Plattform variiert. Vermeide privilegierte Container. Vermeide gemountete Runtime-Sockets. Gib Containern keine beschreibbaren Host-Pfade, sofern es dafür keinen sehr konkreten Grund gibt. Verwende, sofern praktikabel, User-Namespaces oder eine rootless-Ausführung. Entferne alle Capabilities und füge nur diejenigen wieder hinzu, die die Workload tatsächlich benötigt. Lasse Seccomp, AppArmor und SELinux aktiviert, statt sie zur Behebung von Problemen mit der Anwendungskompatibilität zu deaktivieren. Begrenze Ressourcen, damit ein kompromittierter Container dem Host nicht ohne Weiteres den Dienst verweigern kann.

Die Sicherheit von Images und Builds ist ebenso wichtig wie die Runtime-Sicherheitslage. Verwende minimale Images, baue sie regelmäßig neu, scanne sie, fordere nach Möglichkeit Provenienznachweise und halte Secrets aus Image-Layern heraus. Ein Container, der als Nicht-Root mit einem kleinen Image und einer begrenzten Syscall- und Capability-Angriffsfläche ausgeführt wird, ist viel einfacher zu verteidigen als ein großes Komfort-Image, das mit hostäquivalenten Root-Rechten läuft und bereits Debugging-Tools enthält.

Für Kubernetes sind die aktuellen Härtungsbaselines verbindlicher, als viele Betreiber noch annehmen. Die integrierten **Pod Security Standards** betrachten `restricted` als Profil nach den „aktuellen Best Practices“: `allowPrivilegeEscalation` sollte `false` sein, Workloads sollten als Nicht-Root laufen, Seccomp sollte ausdrücklich auf `RuntimeDefault` oder `Localhost` gesetzt sein, und Capability-Sets sollten konsequent reduziert werden. Bei einer Bewertung ist das wichtig, denn ein Cluster, der nur `warn`- oder `audit`-Labels verwendet, kann auf dem Papier gehärtet wirken und in der Praxis dennoch riskante Pods zulassen.<sup>[[1]](#references)</sup>

Wenn ein Pod ein gemountetes Service-Account-Token hat, bewerte dessen Berechtigungen **für jeden Ziel-Namespace einzeln**. Eine Regel, die Pods in einem Namespace auflistet, belegt keine Berechtigung in einem anderen; ein in einem anderen Pod gemountetes Token kann andere Rechte haben. Verwende `kubectl auth can-i list pods -n <target-namespace>` und `kubectl auth can-i list secrets -n <target-namespace>` mit der Identität, die gerade geprüft wird. Eine erlaubte Secret-Auflistung ist ein ernst zu nehmender Hinweis, da eine Listenantwort Secret-Inhalte enthalten kann; sie beweist jedoch nicht, dass ein privilegiertes Token vorhanden ist. Für Hostzugriff sind zusätzlich ein nutzbares Recht zum Erstellen von Workloads, die Zulassung des vorgeschlagenen `hostPath`-Mounts und ein Node-/Pod-Sicherheitskontext erforderlich, der die vorgesehene Dateioperation erlaubt. Siehe die [Autorisierungsprüfungen](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) und die [RBAC-Anleitung zur Rechteausweitung](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) von Kubernetes.

## Fragen zur modernen Triage

Bevor du dich mit Seiten zu spezifischen Escape-Techniken befasst, beantworte diese kurzen Fragen:

1. Wird die Workload **rootful**, **rootless** oder **userns-remapped** ausgeführt?
2. Verwendet der Node **cgroup v1** oder **cgroup v2**?
3. Sind **seccomp** und **AppArmor/SELinux** ausdrücklich konfiguriert oder werden sie lediglich übernommen, sofern verfügbar?
4. Erzwingt der Namespace in Kubernetes tatsächlich `baseline` oder `restricted`, oder werden lediglich Warnungen ausgegeben beziehungsweise Audits durchgeführt?

Nützliche Prüfungen:

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

- Wenn `/proc/self/uid_map` zeigt, dass Container-root einem **hohen Host-UID-Bereich** zugeordnet ist, sind viele ältere Host-root-Write-ups weniger relevant, da root im Container nicht mehr host-root-äquivalent ist.
- Wenn `/sys/fs/cgroup` `cgroup2fs` ist, sollten ältere, speziell für **cgroup v1** verfasste Write-ups wie der Missbrauch von `release_agent` nicht mehr deine erste Vermutung sein.
- Wenn seccomp und AppArmor nur implizit übernommen werden, kann die Portabilität geringer sein, als Verteidiger erwarten. In Kubernetes ist das explizite Setzen von `RuntimeDefault` oft sicherer, als sich stillschweigend auf Node-Standardeinstellungen zu verlassen.
- Wenn `supplementalGroupsPolicy` auf `Strict` gesetzt ist, sollte der Pod vermeiden, stillschweigend zusätzliche Gruppenmitgliedschaften aus `/etc/group` innerhalb des Images zu übernehmen. Dadurch wird das Verhalten beim gruppenbasierten Zugriff auf Volumes und Dateien besser vorhersehbar.
- Namespace-Labels wie `pod-security.kubernetes.io/enforce=restricted` solltest du direkt überprüfen. `warn` und `audit` sind nützlich, verhindern aber nicht, dass ein riskanter Pod erstellt wird.

## Ersteinschätzung der Runtime-Baseline

Eine Runtime-Baseline ist die schnelle Überprüfung, mit der du feststellst, ob ein Container wie ein gewöhnlicher isolierter Workload oder eher wie ein Host-beeinflussender Control-Plane-Foothold aussieht. Sie sollte genügend Fakten erfassen, um festzulegen, welche Seite du als Nächstes liest: Missbrauch des Runtime-Sockets, Host-Mounts, Namespaces, cgroups, Capabilities oder eine Überprüfung der Image-Secrets.

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

- Fehlende oder unbegrenzte `memory.max`- / `pids.max`-Werte weisen auf schwache Kontrollen des Blast Radius hin, auch ohne einen sauber durchgeführten Escape.
- Eine Root-Shell mit `NoNewPrivs: 0`, weitreichenden Capabilities und permissivem seccomp ist deutlich interessanter als ein eng begrenzter Non-Root-Workload.
- Runtime-Sockets und beschreibbare Host-Mounts haben in der Regel Vorrang vor Kernel-Exploits, da sie bereits einen Verwaltungs- oder Dateisystem-Kontrollpfad bereitstellen.
- Gemeinsam genutzte PID-, Netzwerk-, IPC- oder cgroup-Namespaces sind nicht immer allein schon vollständige Escapes, erleichtern aber die Suche nach dem nächsten Schritt.

## Beispiele für Ressourcenerschöpfung

Ressourcenbeschränkungen sind nicht glamourös, gehören aber zur Container-Sicherheit, da sie den Blast Radius einer Kompromittierung begrenzen. Ohne Speicher-, CPU- oder PID-Limits kann bereits eine einfache Shell ausreichen, um den Host oder benachbarte Workloads zu beeinträchtigen.

Beispiele für Tests mit Auswirkungen auf den Host:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Diese Beispiele sind nützlich, weil sie zeigen, dass nicht jedes gefährliche Container-Ergebnis ein sauberer „Escape“ ist. Schwache cgroup-Limits können Codeausführung dennoch in reale betriebliche Auswirkungen verwandeln.

Prüfe in Kubernetes-gestützten Umgebungen außerdem, ob überhaupt Ressourcenbeschränkungen vorhanden sind, bevor du DoS als rein theoretisch betrachtest:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Hardening-Tools

Für Docker-zentrierte Umgebungen ist `docker-bench-security` weiterhin eine nützliche Audit-Grundlage auf Host-Ebene, da es häufige Konfigurationsprobleme anhand weithin anerkannter Benchmark-Empfehlungen überprüft. Laufzeit-Sicherheitshinweise sollten separat geprüft werden, da ein Konfigurations-Benchmark nicht erkennen kann, ob die installierte Laufzeitumgebung von einer neu bekannt gewordenen Schwachstelle betroffen ist. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Das Tool ist kein Ersatz für Threat Modeling, aber dennoch hilfreich, um nachlässige Daemon-, Mount-, Netzwerk- und Laufzeit-Standardeinstellungen aufzudecken, die sich mit der Zeit ansammeln.

Für Kubernetes- und laufzeitintensive Umgebungen sollten statische Prüfungen durch Laufzeitüberwachung ergänzt werden:

- `Tracee` eignet sich für die laufzeitbasierte Erkennung mit Container-Kontext und schnelle Forensik, wenn bestätigt werden muss, worauf eine kompromittierte Workload tatsächlich zugegriffen hat.
- `Inspektor Gadget` eignet sich, wenn bei der Bewertung Telemetriedaten auf Kernel-Ebene den entsprechenden Pods, Containern, DNS-Aktivitäten, Dateiausführungen oder Netzwerkverhalten zugeordnet werden müssen.

## Checks

Verwende diese Befehle für eine schnelle erste Prüfung während der Bewertung:

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

- Ein Root-Prozess mit umfangreichen Capabilities und `Seccomp: 0` verdient sofortige Aufmerksamkeit.
- Ein Root-Prozess mit einer **1:1-UID-Zuordnung** ist weitaus interessanter als „Root“ innerhalb eines ordnungsgemäß isolierten User-Namespaces.
- `cgroup2fs` bedeutet meist, dass viele ältere **cgroup-v1**-Escape-Ketten nicht der beste Ausgangspunkt sind, während fehlende `memory.max`- oder `pids.max`-Werte auf schwache Begrenzungen des Schadensradius hindeuten.
- Verdächtige Mounts und Runtime-Sockets bieten oft einen schnelleren Weg zu Auswirkungen als ein Kernel-Exploit.
- Die Kombination aus schwacher Runtime-Konfiguration und schwachen Ressourcenbeschränkungen deutet meist auf eine allgemein permissive Container-Umgebung hin und nicht auf einen einzelnen isolierten Fehler.

## References

- [1] [Kubernetes Pod-Sicherheitsstandards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker-Sicherheitshinweis: Mehrere Schwachstellen in runc, BuildKit und Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
