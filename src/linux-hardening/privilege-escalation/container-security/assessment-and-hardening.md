# Bewertung und Härtung

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Eine gute Container-Bewertung sollte zwei parallele Fragen beantworten. Erstens: Was kann ein Angreifer vom aktuellen Workload aus tun? Zweitens: Welche Betreiberentscheidungen haben das möglich gemacht? Enumeration-Tools helfen bei der ersten Frage, Härtungsleitfäden bei der zweiten. Beides auf einer Seite zu halten macht den Abschnitt nützlicher als Feldreferenz, nicht nur als Katalog von Escape-Tricks.

## Enumeration Tools

Eine Reihe von Tools ist weiterhin nützlich, um schnell eine Container-Umgebung zu charakterisieren:

- `linpeas` kann viele Container-Indikatoren, gemountete Sockets, Capability-Sets, gefährliche Dateisysteme und Breakout-Hinweise identifizieren.
- `CDK` fokussiert sich speziell auf Container-Umgebungen und enthält Enumeration sowie einige automatisierte Escape-Prüfungen.
- `amicontained` ist leichtgewichtig und nützlich zur Identifikation von Container-Einschränkungen, Capabilities, Namespace-Exposition und wahrscheinlichen Breakout-Klassen.
- `deepce` ist ein weiterer containerfokussierter Enumerator mit breakout-orientierten Prüfungen.
- `grype` ist nützlich, wenn die Bewertung auch eine Überprüfung von Image-Paket-Schwachstellen umfasst, statt sich nur auf Runtime-Escape-Analyse zu beschränken.

Der Wert dieser Tools liegt in Geschwindigkeit und Abdeckung, nicht in Gewissheit. Sie helfen, die grobe Lage schnell zu offenbaren, aber die interessanten Befunde müssen noch manuell gegen das tatsächliche Runtime-, Namespace-, Capability- und Mount-Modell interpretiert werden.

## Prioritäten der Härtung

Die wichtigsten Härtungsprinzipien sind konzeptionell einfach, auch wenn ihre Umsetzung je nach Plattform variiert. Vermeide privileged containers. Vermeide gemountete Runtime-Sockets. Gib Containern keine beschreibbaren Host-Pfade, außer es gibt einen sehr spezifischen Grund. Nutze User-Namespaces oder rootless-Ausführung, wo möglich. Droppe alle Capabilities und füge nur diejenigen wieder hinzu, die der Workload wirklich benötigt. Halte seccomp, AppArmor und SELinux aktiviert, anstatt sie zur Behebung von Anwendungskompatibilitätsproblemen zu deaktivieren. Begrenze Ressourcen, damit ein kompromittierter Container nicht trivial den Host oder Nachbar-Workloads den Dienst verweigern kann.

Image- und Build-Hygiene sind genauso wichtig wie das Runtime-Posture. Verwende minimale Images, baue häufig neu, scanne sie, fordere Provenance wo praktikabel, und halte Secrets aus den Layers. Ein Container, der nicht als root läuft, ein kleines Image und eine enge Syscall- und Capability-Oberfläche hat, ist deutlich leichter zu verteidigen als ein großes Convenience-Image, das als host-äquivalenter root läuft und mit Debugging-Tools vorinstalliert ist.

## Beispiele für Ressourcenerschöpfung

Ressourcenkontrollen sind nicht glamourös, aber sie gehören zur Container-Sicherheit, weil sie den Blast-Radius einer Kompromittierung begrenzen. Ohne Limits für Memory, CPU oder PID kann eine einfache Shell ausreichen, um den Host oder benachbarte Workloads zu degradieren.

Beispiele für Tests, die den Host beeinträchtigen:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Diese Beispiele sind nützlich, weil sie zeigen, dass nicht jedes gefährliche Container-Ergebnis ein sauberes "escape" ist. Schwache cgroup limits können code execution dennoch in reale operative Auswirkungen verwandeln.

## Härtungstools

Für Docker-zentrierte Umgebungen bleibt `docker-bench-security` eine nützliche Audit-Grundlage auf Host-Seite, da es häufige Konfigurationsprobleme gegen weithin anerkannte Benchmark-Empfehlungen prüft:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Das Tool ist kein Ersatz für threat modeling, bietet aber trotzdem wertvolle Hilfe beim Auffinden unachtsamer daemon-, mount-, network- und runtime-Defaults, die sich im Laufe der Zeit ansammeln.

## Checks

Verwende diese als schnelle Erstbefehle während eines Assessments:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Ein root-Prozess mit weitreichenden Capabilities und `Seccomp: 0` verdient sofortige Aufmerksamkeit.
- Verdächtige mounts und runtime sockets bieten oft einen schnelleren Weg zur Kompromittierung als jeder Kernel-Exploit.
- Die Kombination aus schwacher runtime posture und schwachen resource limits deutet normalerweise auf eine generell zu großzügige Container-Umgebung hin, statt auf einen einzelnen isolierten Fehler.
{{#include ../../../banners/hacktricks-training.md}}
