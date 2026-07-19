# Lokale Netzwerk- und Socket-Triage

{{#include ../../banners/hacktricks-training.md}}

Nach dem Erhalt einer shell auf einem Linux-Host sind die nützlichsten Netzwerkziele oft nicht von außen erreichbar. Nur auf Loopback gebundene Services, veth-Netzwerke, Unix-Sockets, temporäre Listener, Packet Captures und lokale Firewall-Regeln können Credentials oder ausschließlich lokal erreichbare Angriffsflächen offenlegen.

Diese Seite konzentriert sich auf praktische lokale post-exploitation-Techniken, nicht auf allgemeines remote network pentesting.

## Enumeration von Loopback- und lokalen Services

Beginne damit, lauschende Services, ihre Bind-Adressen und, sofern die Berechtigungen dies erlauben, den Prozessbesitzer zu identifizieren:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Wichtige Muster:

- `127.0.0.1:<port>` oder `[::1]:<port>`: standardmäßig nur vom Host aus erreichbar.
- `0.0.0.0:<port>`: über alle IPv4-Schnittstellen erreichbar, sofern nicht gefiltert.
- `172.x`, `10.x` oder `192.168.x` auf `veth*`, `docker*`, `br-*`, `cni*`: wahrscheinlich Container- oder lokale Labornetzwerke.
- Unix-Sockets unter `/run`, `/var/run`, `/tmp` oder in Anwendungsverzeichnissen: lokale IPC-Oberflächen.

Ordne lokale Ports mit einfachen Probes zu:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Verwende `nmap` lokal, sofern verfügbar:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Verborgene veth- und Container-Subnetze

Container- oder Laborumgebungen stellen Services häufig nur über ein Bridge- oder veth-Subnetz bereit. Liste Interfaces und Routen auf, bevor du annimmst, dass ein Service nicht erreichbar ist:
```bash
ip -br addr
ip route
ip neigh
```
Wahrscheinliche lokale Subnetze finden:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Untersuche ein entdecktes Subnetz sorgfältig:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Die Technik ist nützlich, wenn ein Webpanel, ein Debug-Endpunkt oder ein Hilfsdienst vor externen Scans verborgen ist, aber vom kompromittierten Host oder Container-Netzwerk aus erreichbar bleibt.

## Lokaler Pivot mit socat oder SSH

Wenn ein Dienst an loopback gebunden ist, leitet ihn über einen erlaubten Kanal weiter, anstatt den Dienst selbst zu ändern.

Leite einen rein lokalen HTTP-Dienst mit SSH weiter:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Einen lokalen Port mit `socat` überbrücken, wenn Sie bereits Shell-Zugriff haben:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Einen Unix-Socket für lokale Tests an TCP weiterleiten:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Dies allein nutzt nichts aus. Es macht eine nur lokal erreichbare Angriffsfläche aus deinen Tools erreichbar, sodass du mit ihr wie mit einem normalen Service interagieren kannst.

## Banner Grabbing und einfache Protokolle

Nicht jeder Service ist HTTP. Viele lokale Services geben über ein Banner oder ein einzeiliges Protokoll genügend Informationen preis.

Grundlegende Probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
HTTP-Überprüfung ohne Browser:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Für TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Das Ziel besteht darin, das Protokoll, das Authentifizierungsschema, die Version und festzustellen, ob der Dienst lokalen Clients vertraut.

## Loopback-Traffic erfassen

Lokaler Traffic kann Header, Bearer-Tokens, Basic-Auth-Credentials oder anwendungsspezifische Secrets offenlegen. Erfasse Traffic nur in autorisierten Umgebungen.

Loopback-HTTP-Traffic erfassen:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Einen bestimmten lokalen Dienst erfassen:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Basic Auth aus einem abgefangenen oder protokollierten Header decodieren:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Nützliche Zeichenfolgen, nach denen in Textmitschnitten gesucht werden sollte:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Wenn du in einer Lab-Umgebung die Client-Prozessumgebung kontrollieren kannst, kann `SSLKEYLOGFILE` TLS-Sitzungen in Wireshark oder kompatiblen Tools entschlüsselbar machen. Dies ist nützlich, um lokalen HTTPS-Datenverkehr zu verstehen, ohne TLS selbst anzugreifen.

Führe einen Client mit aktiviertem Key Logging aus:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Den Traffic gleichzeitig mitschneiden:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Lade anschließend `/tmp/tls.pcap` und `/tmp/sslkeys.log` in Wireshark. Dies funktioniert nur, wenn die Client-Bibliothek NSS-style key logging unterstützt und du die Umgebung vor dem Herstellen der Verbindung festlegen kannst.

## Unix-Socket-Interaktion und Command Injection

Unix-Sockets sind lokale IPC-Endpunkte. Sie können HTTP-APIs, benutzerdefinierte Protokolle oder unsichere Command-Handler bereitstellen.

Sockets finden:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Mit HTTP über einen Unix-Socket interagieren:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Mit einem Raw-Socket interagieren:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Wenn benutzergesteuerte Socket-Eingaben an eine Shell oder einen privilegierten Helper übergeben werden, kann daraus command injection entstehen. Ein fokussiertes Beispiel findest du unter [Socket Command Injection](socket-command-injection.md).

## nftables-Prüfung und autorisierte Regeländerungen

Lokale Firewall-Regeln können erklären, warum ein Service lokal sichtbar, aber remote blockiert ist, oder warum ein hoher Port von einem Interface aus unerreichbar erscheint.

Regeln prüfen:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Suche nach Drops, die einen Zielport betreffen:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Entferne in einem autorisierten Labor eine bestimmte blockierende Regel anhand ihres Handles:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Lösche vorzugsweise den exakten Handle, anstatt vollständige Tabellen zu leeren. Die Technik besteht darin, den genauen Filter zu identifizieren, der das Verhalten verursacht, und nur diese Regel zu ändern.

## Kurzer Workflow
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Priorisiere Dienste, die nur lokal verfügbar sind, unter einem privilegierteren Benutzer laufen, Admin-/Debug-Funktionen bereitstellen oder Loopback-/Container-Netzwerk-Clients vertrauen.
{{#include ../../banners/hacktricks-training.md}}
