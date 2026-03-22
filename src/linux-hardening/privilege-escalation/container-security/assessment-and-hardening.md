# Bewertung und Härtung

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Eine gute Container-Bewertung sollte zwei parallele Fragen beantworten. Erstens: Was kann ein Angreifer aus dem aktuellen Workload tun? Zweitens: Welche Entscheidungen des Betreibers haben das möglich gemacht? Enumeration-Tools helfen bei der ersten Frage, und Hardening-Empfehlungen helfen bei der zweiten. Beides auf einer Seite zu haben macht den Abschnitt nützlicher als Praxisreferenz statt nur ein Katalog von Escape-Tricks.

## Enumeration-Tools

Eine Reihe von Tools ist weiterhin nützlich, um eine Container-Umgebung schnell zu charakterisieren:

- `linpeas` kann viele Container-Indikatoren, gemountete Sockets, Capability-Sätze, gefährliche Dateisysteme und Hinweise auf Breakouts identifizieren.
- `CDK` konzentriert sich speziell auf Container-Umgebungen und enthält Enumeration sowie einige automatisierte Escape-Checks.
- `amicontained` ist leichtgewichtig und nützlich, um Container-Einschränkungen, capabilities, Namespace-Exposition und wahrscheinliche Breakout-Klassen zu identifizieren.
- `deepce` ist ein weiterer containerfokussierter Enumerator mit auf Breakouts ausgerichteten Checks.
- `grype` ist nützlich, wenn die Bewertung Image-/Paket-Vulnerability-Reviews statt nur Laufzeit-Escape-Analyse umfasst.

Der Wert dieser Tools liegt in Geschwindigkeit und Abdeckung, nicht in Gewissheit. Sie helfen, die grobe Lage schnell aufzudecken, aber die interessanten Befunde müssen weiterhin manuell im Kontext des tatsächlichen Runtime-, Namespace-, Capability- und Mount-Modells interpretiert werden.

## Hardening-Prioritäten

Die wichtigsten Hardening-Prinzipien sind konzeptionell einfach, auch wenn ihre Umsetzung je nach Plattform variiert. Vermeide privilegierte Container. Vermeide gemountete Runtime-Sockets. Gib Containern keine schreibbaren Host-Pfade, es sei denn, es gibt einen sehr spezifischen Grund. Verwende user namespaces oder rootless execution, wo möglich. Entferne alle Capabilities und füge nur die wieder hinzu, die der Workload wirklich benötigt. Halte seccomp, AppArmor und SELinux aktiviert, anstatt sie zur Lösung von Anwendungskompatibilitätsproblemen zu deaktivieren. Begrenze Ressourcen so, dass ein kompromittierter Container dem Host nicht einfach den Dienst verweigern kann.

Image- und Build-Hygiene sind genauso wichtig wie die Runtime-Postur. Verwende minimale Images, baue regelmäßig neu, scanne sie, verlange Provenance, wo praktikabel, und deponiere Secrets nicht in Image-Layern. Ein Container, der als non-root läuft, mit einem kleinen Image und einer schmalen syscall- und capability-Oberfläche, ist viel leichter zu verteidigen als ein großes Convenience-Image, das als host-äquivalenter Root läuft und mit Debugging-Tools vorinstalliert ist.

## Beispiele für Ressourcen-Erschöpfung

Ressourcen-Kontrollen sind nicht glamourös, aber sie gehören zur Container-Sicherheit, weil sie den Blast-Radius eines Kompromisses begrenzen. Ohne Memory-, CPU- oder PID-Limits kann eine einfache Shell ausreichen, um den Host oder benachbarte Workloads zu beeinträchtigen.

Beispielhafte host-beeinträchtigende Tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Diese Beispiele sind nützlich, weil sie zeigen, dass nicht jedes gefährliche Container-Ergebnis ein sauberes "escape" ist. Schwache cgroup-Limits können code execution dennoch in reale operative Auswirkungen verwandeln.

## Härtungs-Tools

Für Docker-zentrierte Umgebungen bleibt `docker-bench-security` eine nützliche hostseitige Audit-Basis, da es häufige Konfigurationsprobleme gegen weithin anerkannte Benchmark-Empfehlungen prüft:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Das Tool ersetzt keine Bedrohungsmodellierung, ist aber dennoch nützlich, um nachlässige daemon-, mount-, network- und runtime-Defaults zu finden, die sich im Laufe der Zeit ansammeln.

## Prüfungen

Verwende diese als schnelle Befehle für einen ersten Durchgang während der Bewertung:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Ein root process mit weitreichenden capabilities und `Seccomp: 0` verdient sofortige Aufmerksamkeit.
- Verdächtige mounts und runtime sockets bieten oft einen schnelleren Weg zum Impact als jeder kernel exploit.
- Die Kombination aus schwacher runtime posture und schwachen resource limits deutet normalerweise auf eine generell permissive container environment hin, statt auf einen einzelnen isolierten Fehler.
{{#include ../../../banners/hacktricks-training.md}}
