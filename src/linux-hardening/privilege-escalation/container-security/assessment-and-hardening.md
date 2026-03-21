# Bewertung und Härtung

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Eine gute Container-Bewertung sollte zwei parallele Fragen beantworten. Erstens: Was kann ein Angreifer aus dem aktuellen Workload heraus tun? Zweitens: Welche Betreiberentscheidungen haben das möglich gemacht? Enumeration-Tools helfen bei der ersten Frage, und Härtungsrichtlinien helfen bei der zweiten. Beides auf einer Seite zu halten macht den Abschnitt eher zu einer Feldreferenz als nur zu einem Katalog von Escape-Tricks.

## Aufklärungs-Tools

Eine Reihe von Tools sind nützlich, um eine Container-Umgebung schnell zu charakterisieren:

- `linpeas` kann viele Container-Indikatoren, eingehängte Sockets, Capability-Sets, gefährliche Dateisysteme und Hinweise auf Breakouts identifizieren.
- `CDK` konzentriert sich speziell auf Container-Umgebungen und bietet Enumeration plus einige automatisierte Escape-Checks.
- `amicontained` ist leichtgewichtig und nützlich, um Container-Einschränkungen, Capabilities, Namespace-Exposition und wahrscheinliche Breakout-Klassen zu identifizieren.
- `deepce` ist ein weiterer container-fokussierter Enumerator mit breakout-orientierten Checks.
- `grype` ist nützlich, wenn die Bewertung die Überprüfung von Image-Paket-Schwachstellen statt nur die Analyse von Laufzeit-Escapes umfasst.

Der Wert dieser Tools liegt in Geschwindigkeit und Abdeckung, nicht in Gewissheit. Sie helfen, die grobe Lage schnell aufzudecken, aber die interessanten Befunde müssen weiterhin manuell gegen das tatsächliche Laufzeit-, Namespace-, Capability- und Mount-Modell interpretiert werden.

## Härtungsprioritäten

Die wichtigsten Härtungsprinzipien sind konzeptionell einfach, auch wenn ihre Umsetzung je nach Plattform variiert. Vermeiden Sie privilegierte Container. Vermeiden Sie eingehängte Runtime-Sockets. Geben Sie Containern keine beschreibbaren Host-Pfade, es sei denn, es gibt einen sehr spezifischen Grund. Verwenden Sie User-Namespaces oder rootless-Ausführung, wo möglich. Entfernen Sie alle Capabilities und fügen Sie nur die hinzu, die die Workload wirklich benötigt. Lassen Sie seccomp, AppArmor und SELinux aktiviert, anstatt sie zur Behebung von Anwendungs-Kompatibilitätsproblemen zu deaktivieren. Begrenzen Sie Ressourcen so, dass ein kompromittierter Container nicht einfach dem Host den Dienst verweigern kann.

Image- und Build-Hygiene sind genauso wichtig wie die Laufzeit-Postur. Verwenden Sie minimale Images, bauen Sie häufig neu, scannen Sie diese, verlangen Sie gegebenenfalls Provenienz und halten Sie Geheimnisse aus den Layern heraus. Ein Container, der nicht-root läuft, ein kleines Image und eine enge Syscall- und Capability-Oberfläche hat, ist viel einfacher zu verteidigen als ein großes Convenience-Image, das als host-äquivalenter Root läuft und Debugging-Tools vorinstalliert hat.

## Beispiele für Ressourcenerschöpfung

Ressourcenkontrollen sind nicht glamourös, aber sie gehören zur Container-Security, weil sie den Blast-Radius eines Kompromisses begrenzen. Ohne Speicher-, CPU- oder PID-Limits kann eine einfache Shell ausreichen, um den Host oder benachbarte Workloads zu beeinträchtigen.

Beispiele für Tests, die den Host beeinflussen:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Diese Beispiele sind nützlich, weil sie zeigen, dass nicht jedes gefährliche Ergebnis in Containern ein sauberer "escape" ist. Schwache cgroup-Limits können code execution dennoch in reale betriebliche Auswirkungen verwandeln.

## Härtungstools

Für Docker-zentrierte Umgebungen bleibt `docker-bench-security` eine nützliche hostseitige Audit-Baseline, da es häufige Konfigurationsprobleme anhand allgemein anerkannter Benchmark-Leitlinien prüft:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Das Tool ist kein Ersatz für threat modeling, liefert aber dennoch wertvolle Hinweise zum Aufspüren nachlässiger daemon-, mount-, network- und runtime defaults, die sich im Laufe der Zeit ansammeln.

## Prüfungen

Verwende diese als schnelle Erstbefehle während des Assessments:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Ein root-Prozess mit umfangreichen capabilities und `Seccomp: 0` verdient sofortige Aufmerksamkeit.
- Verdächtige mounts und runtime sockets bieten oft einen schnelleren Weg zum Impact als jeder kernel exploit.
- Die Kombination aus schwacher runtime posture und schwachen resource limits deutet normalerweise auf eine generell permissive container environment hin, statt auf einen einzelnen isolierten Fehler.
