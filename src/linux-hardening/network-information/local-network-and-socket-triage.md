# Triage des lokalen Netzwerks und der Sockets

{{#include ../../banners/hacktricks-training.md}}

Nach dem Erlangen einer Shell auf einem Linux-Host sind die nützlichsten Netzwerkziele oft nicht extern zugänglich. Nur an Loopback gebundene Services, veth-Netzwerke, Unix-Sockets, temporäre Listener, Packet Captures und lokale Firewall-Regeln können Zugangsdaten oder nur lokal erreichbare Angriffsflächen offenlegen.

Diese Seite konzentriert sich auf praktische lokale Post-Exploitation-Techniken, nicht auf allgemeines Remote-Network-Pentesting.

## Enumeration von Loopback- und lokalen Services

Beginne damit, lauschende Services, ihre Bind-Adressen und, sofern die Berechtigungen dies erlauben, den Prozess zu identifizieren, dem sie gehören.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Wichtige Muster:

- `127.0.0.1:<port>` oder `[::1]:<port>`: standardmäßig nur vom Host aus erreichbar.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: auf allen IPv4-Schnittstellen erreichbar, sofern nicht gefiltert.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` oder `192.168.0.0/16` auf `veth*`, `docker*`, `br-*`, `cni*`: wahrscheinlich Container- oder lokale Labornetzwerke.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix-Sockets unter `/run`, `/var/run`, `/tmp` oder in Anwendungsverzeichnissen: lokale IPC-Angriffsflächen.<sup>[[5]](#references)</sup>

Ordne lokale Ports mit leichten Probes zu.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Verwende `nmap` lokal, sofern verfügbar.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Verborgene veth- und Container-Subnetze

Containerisierte oder Laborumgebungen stellen Services häufig nur über ein Bridge- oder veth-Subnetz bereit. Ermittle Interfaces und Routen, bevor du annimmst, dass ein Service nicht erreichbar ist.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Finde wahrscheinliche lokale Subnetze.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Untersuche ein entdecktes Subnetz vorsichtig.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Die Technik ist nützlich, wenn ein Web-Panel, ein Debug-Endpunkt oder ein Hilfsdienst vor externen Scans verborgen, aber vom kompromittierten Host oder aus dem Container-Netzwerk erreichbar ist.

## Lokaler Pivot mit socat oder SSH

Wenn ein Dienst an die Loopback-Schnittstelle gebunden ist, stelle ihn über einen erlaubten Kanal bereit, anstatt den Dienst selbst zu ändern.

Leite einen nur lokal verfügbaren HTTP-Dienst mit SSH weiter.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Einen lokalen Port mit `socat` überbrücken, wenn Sie bereits Shell-Zugriff haben.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Einen Unix-Socket für lokale Tests an TCP weiterleiten.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Dies allein nutzt nichts aus. Es macht eine nur lokal erreichbare Angriffsfläche für deine Tools zugänglich, sodass du wie mit einem normalen Dienst mit ihr interagieren kannst.

## Banner Grabbing und einfache Protokolle

Nicht jeder Dienst ist HTTP. Viele lokale Dienste leak-en über ein Banner oder einzeiliges Protokoll ausreichend Informationen.

Grundlegende Prüfungen.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
HTTP-Überprüfung ohne Browser.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Für TLS.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Ziel ist es, das Protokoll, das Authentifizierungsschema, die Version und festzustellen, ob der Dienst lokalen Clients vertraut.

## Erfassen von Loopback-Datenverkehr

Lokaler Datenverkehr kann Header, Bearer-Tokens, Basic-Auth-Anmeldedaten oder anwendungsspezifische Geheimnisse offenlegen.<sup>[[17]](#references)[[25]](#references)</sup> Erfasse Datenverkehr nur in autorisierten Umgebungen.

Erfasse HTTP-Loopback-Datenverkehr.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Einen bestimmten lokalen Dienst erfassen.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Basic Auth aus einem abgefangenen oder protokollierten Header dekodieren.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Nützliche Zeichenfolgen, nach denen in Texterfassungen gesucht werden sollte:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Wenn du die Umgebung des Client-Prozesses in einer Laborumgebung kontrollieren kannst, kann `SSLKEYLOGFILE` TLS-Sitzungen in Wireshark oder kompatiblen Tools entschlüsselbar machen.<sup>[[19]](#references)[[20]](#references)</sup> Dies ist nützlich, um lokalen HTTPS-Datenverkehr zu verstehen, ohne TLS selbst anzugreifen.

Starte einen Client mit aktiviertem Key Logging.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Den Datenverkehr gleichzeitig erfassen.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Lade anschließend `/tmp/tls.pcap` und `/tmp/sslkeys.log` in Wireshark. Dies funktioniert nur, wenn die Client-Bibliothek NSS-style key logging unterstützt und du die Umgebung vor dem Herstellen der Verbindung festlegen kannst.<sup>[[20]](#references)[[21]](#references)</sup>

## Interaktion mit Unix-Sockets und Command Injection

Unix-Sockets sind lokale IPC-Endpunkte.<sup>[[5]](#references)</sup> Sie können HTTP-APIs, benutzerdefinierte Protokolle oder unsichere Command-Handler bereitstellen.<sup>[[12]](#references)[[14]](#references)</sup>

Finde Sockets.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Mit HTTP über einen Unix-Socket interagieren.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Mit einem Raw-Socket interagieren.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Wenn vom Benutzer kontrollierte Socket-Eingaben an eine Shell oder einen privilegierten Helper übergeben werden, kann daraus Command Injection entstehen.<sup>[[26]](#references)</sup> Ein gezieltes Beispiel findest du unter [Socket Command Injection](socket-command-injection.md).

## nftables-Review und autorisierte Regeländerungen

Lokale Firewall-Regeln können erklären, warum ein Service lokal sichtbar, aber remote blockiert ist, oder warum ein hoher Port von einem Interface aus unerreichbar erscheint.<sup>[[22]](#references)</sup>

Regeln überprüfen.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Suche nach Drops, die einen Zielport betreffen.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Entferne in einem autorisierten Labor eine bestimmte blockierende Regel anhand ihres Handles.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Löschen Sie möglichst das exakte Handle, anstatt vollständige Tabellen zu leeren. Die Technik besteht darin, den genauen Filter zu identifizieren, der das Verhalten verursacht, und nur diese Regel zu ändern.<sup>[[22]](#references)</sup>

## Schneller Workflow
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Priorisieren Sie Services, die nur lokal verfügbar sind, unter einem privilegierteren Benutzer ausgeführt werden, Admin-/Debug-Funktionen bereitstellen oder Loopback-/Container-Network-Clients vertrauen.

## References

- [1] [ss(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Adressierungsarchitektur für IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Umleitungen (Bash-Referenzhandbuch)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout-Aufruf (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port-Scanning-Techniken (Nmap-Referenzhandbuch)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host-Erkennung (Nmap-Referenzhandbuch)](https://nmap.org/book/man-host-discovery.html)
- [10] [Port-Spezifikation und Scan-Reihenfolge (Nmap-Referenzhandbuch)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — OpenBSD-Handbuchseite](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD-Handbuchseite](https://man.openbsd.org/nc.1)
- [14] [Handbuch zum curl-Kommandozeilentool](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL-Dokumentation](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Das „Basic“-HTTP-Authentifizierungsschema](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64-Aufruf (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL-Dokumentation](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark-Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark-Benutzerhandbuch](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables-Handbuch](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Adresszuweisung für private Internets (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Das OAuth-2.0-Autorisierungs-Framework: Verwendung von Bearer-Tokens (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Unsachgemäße Neutralisierung spezieller Elemente in einem OS-Befehl](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
