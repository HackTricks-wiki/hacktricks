# Wireshark-Tricks

{{#include ../../../banners/hacktricks-training.md}}

## Verbessere deine Wireshark-Kenntnisse

### Tutorials

Die folgenden Tutorials sind großartig, um einige coole grundlegende Tricks zu lernen:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysierte Informationen

**Experteninformationen**

Wenn du auf _**Analyze** --> **Expert Information**_ klickst, erhältst du einen **Überblick** darüber, was in den **analysierten** Paketen passiert:

![](<../../../images/image (256).png>)

**Aufgelöste Adressen**

Unter _**Statistics --> Resolved Addresses**_ findest du mehrere **Informationen**, die von wireshark "**aufgelöst**" wurden, wie z. B. Port/Transport zu Protokoll, MAC zum Hersteller usw. Es ist interessant zu wissen, was an der Kommunikation beteiligt ist.

![](<../../../images/image (893).png>)

**Protokollhierarchie**

Unter _**Statistics --> Protocol Hierarchy**_ findest du die an der Kommunikation **beteiligten Protokolle** und Daten darüber.

![](<../../../images/image (586).png>)

**Konversationen**

Unter _**Statistics --> Conversations**_ findest du eine **Zusammenfassung der Konversationen** in der Kommunikation und Daten darüber.

![](<../../../images/image (453).png>)

**Endpunkte**

Unter _**Statistics --> Endpoints**_ findest du eine **Zusammenfassung der Endpunkte** in der Kommunikation und Daten über jeden von ihnen.

![](<../../../images/image (896).png>)

**DNS-Info**

Unter _**Statistics --> DNS**_ findest du Statistiken über die erfassten DNS-Anfragen.

![](<../../../images/image (1063).png>)

**I/O-Graph**

Unter _**Statistics --> I/O Graph**_ findest du einen **Graphen der Kommunikation.**

![](<../../../images/image (992).png>)

### Filter

Hier findest du Wireshark-Filter je nach Protokoll: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
In aktuellem Wireshark verwende `tls.*` statt der alten `ssl.*`-Filternamen.\
Weitere interessante Filter:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP- und initialer HTTPS-Traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP- und initialer HTTPS-Traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP- und initialer HTTPS-Traffic + TCP SYN + DNS-Anfragen
- `tls.handshake.extensions_server_name contains "example.com"`
- Auf dem SNI im ClientHello pivoten, selbst wenn du die Nutzlast nicht entschlüsseln kannst
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Klassische HTTPS-, HTTP/2- und HTTP/3-fähige Sitzungen schnell trennen
- `quic or http3`
- Modernen UDP/443-Traffic finden, der übersehen wird, wenn du nur TCP-Konversationen prüfst

### Suche

Wenn du innerhalb des **Inhalts** der **Pakete** der Sitzungen **suchen** willst, drücke _CTRL+f_. Du kannst neue Spalten zur Hauptinformationsleiste (No., Time, Source, etc.) hinzufügen, indem du die rechte Maustaste drückst und dann die Spalte bearbeitest.

### Multiplexte Streams verfolgen

Neuere Wireshark-Versionen können `TLS`, `HTTP/2`- und `QUIC`-Streams direkt verfolgen. Bei lauten Captures ist das meist schneller als nur `Follow TCP Stream`, besonders wenn mehrere Requests dieselbe Verbindung teilen.

### Kostenlose pcap-Labs

**Übe mit den kostenlosen Challenges von:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domains identifizieren

Du kannst eine Spalte hinzufügen, die den HTTP-Host-Header anzeigt:

![](<../../../images/image (639).png>)

Und eine Spalte, die den Servernamen aus einer initiierenden HTTPS-Verbindung hinzufügt (**tls.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

Wenn der Capture größtenteils verschlüsselt ist, beschleunigt das Hinzufügen dieser Felder als Spalten das Triage deutlich:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Damit kannst du Sitzungen nach Hostname, ALPN (`http/1.1`, `h2`, `h3` usw.) und Client-Fingerprint clustern, selbst wenn die Nutzlast verschlüsselt bleibt. Für entschlüsselte HTTP/2- und HTTP/3-Captures ist es außerdem nützlich, `http2.header.value` oder `http3.headers.header.value` als Spalten hinzuzufügen und nach Paths, Authorities und anderen interessanten Metadaten zu pivoten.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Lokale Hostnames identifizieren

### Über DHCP

In aktuellem Wireshark musst du statt `bootp` nach `DHCP` suchen

![](<../../../images/image (1013).png>)

### Über NBNS

![](<../../../images/image (1003).png>)

## TLS entschlüsseln

### https-Traffic mit dem privaten Server-Key entschlüsseln

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Drücke _Edit_ und füge alle Daten des Servers und des privaten Keys hinzu (_IP, Port, Protocol, Key file and password_)

Diese Methode funktioniert nur in einer begrenzten Anzahl von Fällen. Für aktuellen TLS 1.3 / ECDHE-Traffic ist die Methode mit dem Session-Key-Log unten normalerweise die praktische Option.

### https-Traffic mit symmetrischen Session Keys entschlüsseln

Sowohl Firefox als auch Chrome können TLS Session Keys protokollieren, die mit Wireshark verwendet werden können, um TLS-Traffic zu entschlüsseln. Das ermöglicht eine tiefgehende Analyse sicherer Kommunikation. Weitere Details, wie diese Entschlüsselung durchgeführt wird, findest du in einem Guide bei [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). Das ist auch der normale Weg, um moderne TLS 1.3- und QUIC/HTTP/3-Captures zu entschlüsseln.

Um das zu erkennen, suche in der Umgebung nach der Variable `SSLKEYLOGFILE`

Eine Datei mit gemeinsamen Keys sieht so aus:

![](<../../../images/image (820).png>)

Wenn der Capture `pcapng` ist, prüfe zuerst, ob er bereits eingebettete Entschlüsselungs-Secrets enthält, bevor du das Host-Dateisystem durchsuchst:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Um dies in Wireshark zu importieren, gehe zu \_edit > preferences > protocols > tls > und importiere es in (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## ADB communication

Extrahiere ein APK aus einer ADB communication, bei der das APK gesendet wurde:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
## Referenzen

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
