# Autorisierte Adversary-Emulation-Labs

{{#include ../banners/hacktricks-training.md}}

Diese Übungen reproduzieren eine **beobachtbare Architektur**, keine unbefugte Kompromittierung. Führe sie auf einem dedizierten Linux-Lab-Host mit Docker, ohne vertrauliche Zugangsdaten und ohne Route zu Zielen Dritter aus. Die Namen sind festgelegt, damit das Teardown eindeutig ist.

{% hint style="danger" %}
Ersetze die unten genannten eigenen Container, APs, Router, Accounts oder synthetischen Transaktionen nicht durch öffentliche Proxies, das WLAN eines Nachbarn, einen Production-CDN-Tenant, den du nicht kontrollierst, oder echtes illegales Geld. Eine schriftliche Autorisierung muss jedes System und jede Funkumgebung abdecken.
{% endhint %}

## Lab 1: Eigene ORB- und Redirector-Kette

**Ziel:** Zeige, dass ein Ziel nur den Exit protokolliert, während jedes Relay benachbarte Hops sieht. Dies emuliert die T1090.003/T1584-Struktur ohne kompromittierte Geräte.

**Anforderungen:** Docker Engine und unbenutzte Containernamen, die mit `ht-orb-` beginnen.

### Erstellung
```bash
docker network create ht-orb-entry
docker network create ht-orb-transit
docker network create ht-orb-target

docker run -d --name ht-orb-target --network ht-orb-target nginx:alpine

docker run -d --name ht-orb-r2 --network ht-orb-transit \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-target:80
docker network connect ht-orb-target ht-orb-r2

docker run -d --name ht-orb-r1 --network ht-orb-entry \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-r2:8080
docker network connect ht-orb-transit ht-orb-r1

docker run --rm --network ht-orb-entry curlimages/curl:latest \
-sS http://ht-orb-r1:8080/ >/dev/null
```
### Überprüfe die Sichtbarkeitsgrenzen
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Erwartetes Ergebnis: Nginx zeichnet die Adresse `ht-orb-r2` auf `ht-orb-target` auf, nicht die des One-Shot-Clients. Die Relay-Logs zeigen Verbindungen ausschließlich aus ihrem jeweils angrenzenden Netzwerk. Die Inspektion der Docker-Control-Plane rekonstruiert weiterhin den gesamten Pfad – analog zu Provider-/Controller-Evidenz.

### Detection-Experimente

1. Wiederhole Requests alle 60 Sekunden und stelle die Zeit zwischen den Verbindungen sowie die Byte-Anzahl grafisch dar.
2. Ersetze `ht-orb-r2` durch einen neuen benannten Container bzw. eine neue Adresse, behalte jedoch denselben Takt und denselben Application-Request bei; bestätige, dass eine reine IP-Regel die Chain verliert, während das Verhalten weiterhin eine Verbindung herstellt.
3. Erfasse den Datenverkehr auf den drei Docker-Bridges mit `tcpdump` auf dem Lab-Host und vergleiche die Zeitstempel.
4. Stoppe `ht-orb-r2`; überprüfe, dass es keinen direkten Fallback vom Entry zum Target gibt.

### Teardown
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Labor 2: SNI/Host mismatch und Redirector-Logging

**Ziel:** das Routing-Primitiv hinter Domain Fronting an einem privaten lokalen Edge reproduzieren und zeigen, wo es sichtbar ist. Es ist kein öffentlicher CDN beteiligt.

### Einen lokalen TLS-Edge erstellen
```bash
ht_front_dir="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
-subj '/CN=front.lab' \
-keyout "$ht_front_dir/key.pem" -out "$ht_front_dir/cert.pem"

cat >"$ht_front_dir/default.conf" <<'EOF'
log_format routing '$remote_addr sni=$ssl_server_name host=$host request="$request"';
server {
listen 443 ssl;
server_name front.lab;
ssl_certificate /etc/nginx/tls/cert.pem;
ssl_certificate_key /etc/nginx/tls/key.pem;
access_log /var/log/nginx/access.log routing;
location / {
if ($host != origin.lab) { return 404; }
proxy_pass http://ht-front-target:80;
}
}
EOF

docker network create ht-front-net
docker run -d --name ht-front-target --network ht-front-net nginx:alpine
docker run -d --name ht-front-edge --network ht-front-net -p 127.0.0.1:8443:443 \
-v "$ht_front_dir/default.conf:/etc/nginx/conf.d/default.conf:ro" \
-v "$ht_front_dir:/etc/nginx/tls:ro" nginx:alpine
```
### Senden und die Abweichung beobachten
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Zu den erwarteten Log-Feldern gehören `sni=front.lab host=origin.lab`. Die Paketaufzeichnung zwischen Client und Edge legt SNI offen, sofern ECH nicht verwendet wird; der HTTP-Host ist auf dieser Verbindung verschlüsselt. Der terminierende Edge sieht beide.

Sende nun eine normale Anfrage und bestätige, dass die Policy sie ablehnt:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Erkennungsbedingung

Löse nur dann einen Alert für `sni != host` aus, nachdem Ports und Groß-/Kleinschreibung normalisiert und bekannte reverse-proxy-Ausnahmen geprüft wurden. Füge Prozess- sowie Tenant-/Origin-Kontext hinzu, bevor du den Schweregrad festlegst.

### Bereinigung
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Lab 3: fast-flux DNS telemetry

**Ziel:** Einen sicheren DNS-Datensatz mit niedrigem TTL-Wert und mehreren ASNs erzeugen und eine analytische Auswertung validieren. Die zurückgegebenen RFC-5737-Dokumentationsadressen sind für diesen Zweck nicht routbar.

### Einen autoritativen Server ausführen
```bash
ht_dns_dir="$(mktemp -d)"
cat >"$ht_dns_dir/Corefile" <<'EOF'
.:53 {
log
errors
file /zones/db.lab lab
}
EOF

mkdir -p "$ht_dns_dir/zones"
cat >"$ht_dns_dir/zones/db.lab" <<'EOF'
$ORIGIN lab.
@ 60 IN SOA ns.lab. hostmaster.lab. 1 60 60 60 5
@ 60 IN NS ns.lab.
ns 60 IN A 192.0.2.53
flux 5 IN A 192.0.2.10
flux 5 IN A 198.51.100.20
flux 5 IN A 203.0.113.30
EOF

docker run -d --name ht-flux-dns -p 127.0.0.1:1053:53/udp \
-v "$ht_dns_dir/Corefile:/Corefile:ro" \
-v "$ht_dns_dir/zones:/zones:ro" coredns/coredns:latest -conf /Corefile

for query_number in 1 2 3 4 5; do
dig @127.0.0.1 -p 1053 flux.lab A +noall +answer
done
docker logs ht-flux-dns
```
Erwartetes Ergebnis: Jede Antwort enthält drei Dokumentations-IP-Adressen und eine TTL von 5 Sekunden. Real Fast Flux rotiert außerdem im Laufe der Zeit Teilmengen; ändern Sie die Zone-Seriennummer/Adressen und starten Sie diesen kurzlebigen Server neu, um mehrere Epochen zu erzeugen.

### Analytische Validierung

Berechnen Sie für ein fünfminütiges Zeitfenster `median(TTL)`, die Anzahl unterschiedlicher Antworten, die Anzahl unterschiedlicher synthetischer ASN-/Geografie-Labels und den Antwortwechsel. Fordern Sie mindestens zwei verdächtige Dimensionen sowie ein Prozess-/Folgeereignis. Führen Sie dieselbe Analyse mit einem bekannten CDN-Sample durch, um False Positives zu messen.

### Teardown
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Lab 4: nearest-neighbor wireless pivot

**Ziel:** Den APT28-Boundary-Mismatch mit zwei eigenen „Organisationen“ reproduzieren. Da sich Wi-Fi-Hardware-/Treiberbefehle unterscheiden, legt dieses Lab überprüfbare Rollen und Nachweise fest, statt so zu tun, als würde ein einzelner `hostapd`-Befehl für jedes Radio funktionieren.

### Ausrüstung

- zwei eigene APs auf isolierten Laborkanälen/-SSIDs `HT-NEIGHBOR` und `HT-TARGET`;
- ein Zieldienst, der nur von `HT-TARGET` aus erreichbar ist;
- ein eigener Dual-Radio-Linux-Pivot, der sich mit beiden APs verbinden kann;
- eine Remote-Control-Workstation hinter `HT-NEIGHBOR`;
- RADIUS/NAC- oder AP-Association-Logs, DHCP-Logs sowie Pivot-Audit-/Prozess-Logs.

### Vorgehensweise

1. Isoliere oder dämpfe den Aufbau physisch, sodass keine der beiden SSIDs den autorisierten Bereich verlässt. Bestätige dies mit einer Vermessung.
2. Konfiguriere `HT-TARGET` mit einer Übungsidentität und lasse die Geräte-Zertifikats-/Posture-Validierung beim ersten Durchlauf absichtlich weg. Dokumentiere dies als zu prüfende Bedingung.
3. Verbinde das erste Interface des Pivots mit `HT-NEIGHBOR` und das zweite Interface mit `HT-TARGET`. Aktiviere **keine** allgemeine Bridge; lasse über eine Host-Firewall nur den Zieldienst/-port zu.
4. Öffne von der Workstation aus einen authentifizierten Tunnel zum Pivot und fordere den Zieldienst darüber an.
5. Zeichne die Erstellung des Pivot-Prozesses/-Interfaces, beide AP-Verbindungen, das Ziel-RADIUS-Ereignis, die DHCP-Lease und die Zielquelladresse auf.
6. Bitte das Detection-Team, die Kette ohne die Controller-Zuordnung zu rekonstruieren.
7. Aktiviere EAP-TLS/Managed-Device-Posture auf `HT-TARGET`, entferne das freigegebene Zielzertifikat des Pivots und wiederhole den Vorgang. Der Zugriff sollte bei der Zulassung fehlschlagen.
8. Wiederhole den Vorgang mit einer erstmalig gesehenen randomisierten MAC. Überprüfe, dass die Zertifikats-/Geräteentscheidung weiterhin funktioniert und keine Regel die MAC allein als Identität behandelt.

### Erfolgskriterien

- Das Ziel sieht zunächst einen lokalen Wi-Fi-Client statt der Workstation.
- Die erfasste Telemetrie identifiziert einen Pivot mit gleichzeitigem Neighbor-Control- und Target-Radio-Pfad.
- Die zertifikats-/gerätebasierte Zulassung blockiert den zweiten Durchlauf.
- Kein Paket erreicht ein Netzwerk außerhalb des isolierten Labs.

## Lab 5: dead-drop resolver sequence

**Ziel:** Einen Prozess erkennen, der ein legitim aussehendes Objekt liest, einen Pointer dekodiert und unmittelbar einen zweiten Dienst kontaktiert.

### Aufbau
```bash
docker network create ht-ddr-net
docker run -d --name ht-ddr-c2 --network ht-ddr-net nginx:alpine

docker run -d --name ht-ddr-web --network ht-ddr-net python:3-alpine \
sh -c 'mkdir -p /srv && printf aHR0cDovL2h0LWRkci1jMjo4MC8= > /srv/profile.txt && python -m http.server 8000 -d /srv'

docker run --rm --name ht-ddr-client --network ht-ddr-net python:3-alpine \
python -c 'import base64,urllib.request; p=urllib.request.urlopen("http://ht-ddr-web:8000/profile.txt").read(); u=base64.b64decode(p).decode(); print(urllib.request.urlopen(u).status)'

docker logs ht-ddr-web
docker logs ht-ddr-c2
```
Der encodierte Inhalt ist `http://ht-ddr-c2:80/`. Eine funktionierende Erkennung verbindet denselben kurzlebigen Prozess/Container, der `/profile.txt` liest, den Inhalt decodiert und innerhalb weniger Sekunden `ht-ddr-c2` kontaktiert. Hashen und die Objektausgabe aufbewahren.

### Bereinigung
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Lab 6: synthetic peel-chain und bridge graph

**Ziel:** Übe das Verfolgen von Werten ohne echte Assets, Accounts oder Services.

### Datensatz erstellen und verfolgen
```bash
ht_graph_dir="$(mktemp -d)"
cat >"$ht_graph_dir/edges.csv" <<'EOF'
time,chain,source,destination,amount,label
10:00,A,theft,a1,100,source
10:10,A,a1,shop1,3,payment
10:10,A,a1,a2,96.9,change
10:20,A,a2,shop2,4,payment
10:20,A,a2,a3,92.8,change
10:30,A,a3,bridge_in,90,bridge_deposit
10:36,X,bridge_in,bridge_out,89.5,bridge_link_inference
10:36,B,bridge_out,b1,89.5,bridge_withdrawal
10:50,B,b1,exchange,89,service_deposit
EOF

python3 - "$ht_graph_dir/edges.csv" <<'PY'
import csv, sys
edges = list(csv.DictReader(open(sys.argv[1], newline="")))
frontier, seen = {"theft"}, set()
while frontier:
src = frontier.pop()
for e in edges:
if e["source"] == src and (src, e["destination"]) not in seen:
seen.add((src, e["destination"]))
print(f'{e["time"]} {e["chain"]}: {src} -> {e["destination"]} {e["amount"]} [{e["label"]}]')
frontier.add(e["destination"])
PY
```
Analysten sollten das Peel-/Change-Muster identifizieren, den Bridge-Link als separat zu stützende Schlussfolgerung behandeln, die Gebühren-/Wertdifferenz berechnen und den Exchange als Anfrage nach Off-Chain-Belegen markieren. Ändern Sie einen Wert/Zeitpunkt und dokumentieren Sie, wie sich die Konfidenz verändert.

### Teardown
```bash
rm -rf -- "$ht_graph_dir"
```
## Labor 7: passiver Traffic-Signaling-Sensor

**Ziel:** die Netzwerksignatur eines passiven, durch einen Magic Value aktivierten Implants nachbilden, ohne eine Shell, Persistence oder Remote Access zu erstellen. Der Listener bindet sich ausschließlich an Loopback und protokolliert ein harmloses Ereignis.
```bash
ht_signal_dir="$(mktemp -d)"
cat >"$ht_signal_dir/listener.py" <<'PY'
import hmac, socket

token = b"HT-LAB-ACTIVATE"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 45679))
for _ in range(2):
data, peer = sock.recvfrom(1024)
if hmac.compare_digest(data, token):
print(f"authorized lab activation from {peer[0]}", flush=True)
PY

python3 "$ht_signal_dir/listener.py" >"$ht_signal_dir/events.log" &
ht_signal_pid=$!
sleep 1

python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"ordinary-traffic", ("127.0.0.1", 45679))
s.sendto(b"HT-LAB-ACTIVATE", ("127.0.0.1", 45679))
PY

wait "$ht_signal_pid"
cat "$ht_signal_dir/events.log"
rm -rf -- "$ht_signal_dir"
```
Erwartetes Ergebnis: Gewöhnlicher Traffic erzeugt kein Application-Event; nur das festgelegte Token tut dies. Zeichne während der Ausführung Loopback-Traffic auf und überprüfe, dass ein Network-Sensor weiterhin beide Datagramme sehen kann. Bewerte anschließend Host-Kontrollen, die einen unerwarteten, lange laufenden Packet-Listener oder Packet-Capture-Filter erkennen. Echte passive RedPenguin-Implants untersuchten den Traffic auf einem Router und boten gefährliche Funktionalität; dieses Lab tut dies absichtlich nicht.

## Exercise report template

Für jedes Lab dokumentieren:

- Autorisierung und isolierter Scope;
- Hypothese und ATT&CK-Technik;
- Topology- und Observer-Tabelle;
- exakte Start-/Endzeit und Configuration-Hashes;
- erwartete Events pro Sensor;
- tatsächlich beobachtete Events und Retention-Lücken;
- Analytic-Logik, Schwellenwert und False-Positive-Beispiel;
- ob das Zielteam den Pfad rekonstruiert hat;
- Ergebnis des Mitigation-Retests; und
- Nachweise für Teardown/Recovery.

Ein Exercise ist erst abgeschlossen, wenn die Detection nach der Mitigation erneut ausgeführt und jede Lab-Ressource entfernt wurde.

## References

- [1] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — Der Angriff auf den nächsten Nachbarn](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
