# Wireshark-Tricks

{{#include ../../../banners/hacktricks-training.md}}

## Verbessere deine Wireshark-Kenntnisse

### Tutorials

Die folgenden Tutorials sind großartig, um einige nützliche grundlegende Tricks zu lernen:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysierte Informationen

**Experteninformationen**

Wenn du auf _**Analyze** --> **Expert Information**_ klickst, erhältst du eine **Übersicht** darüber, was in den **analysierten** Paketen passiert:

![Tutorials - Analysierte Informationen: Wenn du auf Analyze -- Expert Information klickst, erhältst du eine Übersicht darüber, was in den analysierten Paketen passiert](<../../../images/image (256).png>)

**Aufgelöste Adressen**

Unter _**Statistics --> Resolved Addresses**_ findest du verschiedene **Informationen**, die von Wireshark "**aufgelöst**" wurden, z. B. Port/Transport zu Protokoll, MAC-Adresse zum Hersteller usw. Es ist interessant zu wissen, was an der Kommunikation beteiligt ist.

![Tutorials - Analysierte Informationen: Unter Statistics -- Resolved Addresses findest du verschiedene Informationen, die von Wireshark "aufgelöst" wurden, z. B. Port/Transport zu Protokoll, MAC-Adresse zum...](<../../../images/image (893).png>)

**Protokollhierarchie**

Unter _**Statistics --> Protocol Hierarchy**_ findest du die an der Kommunikation **beteiligten** **Protokolle** sowie Daten zu diesen.

![Tutorials - Analysierte Informationen: Unter Statistics -- Protocol Hierarchy findest du die an der Kommunikation beteiligten Protokolle sowie Daten zu diesen](<../../../images/image (586).png>)

**Unterhaltungen**

Unter _**Statistics --> Conversations**_ findest du eine **Zusammenfassung der Unterhaltungen** in der Kommunikation sowie Daten zu diesen.

![Tutorials - Analysierte Informationen: Unter Statistics -- Conversations findest du eine Zusammenfassung der Unterhaltungen in der Kommunikation sowie Daten zu diesen](<../../../images/image (453).png>)

**Endpunkte**

Unter _**Statistics --> Endpoints**_ findest du eine **Zusammenfassung der Endpunkte** in der Kommunikation sowie Daten zu jedem einzelnen.

![Tutorials - Analysierte Informationen: Unter Statistics -- Endpoints findest du eine Zusammenfassung der Endpunkte in der Kommunikation sowie Daten zu jedem einzelnen](<../../../images/image (896).png>)

**DNS-Informationen**

Unter _**Statistics --> DNS**_ findest du Statistiken über die erfassten DNS-Anfragen.

![Tutorials - Analysierte Informationen: Unter Statistics -- DNS findest du Statistiken über die erfassten DNS-Anfragen](<../../../images/image (1063).png>)

**I/O-Graph**

Unter _**Statistics --> I/O Graph**_ findest du ein **Diagramm der Kommunikation.**

![Tutorials - Analysierte Informationen: Unter Statistics -- I/O Graph findest du ein Diagramm der Kommunikation](<../../../images/image (992).png>)

### Filter

Hier findest du Wireshark-Filter abhängig vom Protokoll: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Verwende im aktuellen Wireshark `tls.*` anstelle der alten `ssl.*`-Filternamen.<sup>[[1]](#references)</sup>\
Weitere interessante Filter:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP- und initialer HTTPS-Datenverkehr
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP- und initialer HTTPS-Datenverkehr + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP- und initialer HTTPS-Datenverkehr + TCP SYN + DNS-Anfragen
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot auf den im ClientHello gesendeten SNI, selbst wenn du die Payload nicht entschlüsseln kannst
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Klassische HTTPS-, HTTP/2- und HTTP/3-fähige Sitzungen schnell aufteilen
- `quic or http3`
- Modernen UDP/443-Datenverkehr finden, der übersehen wird, wenn du nur TCP-Unterhaltungen überprüfst

### Suche

Wenn du nach **Inhalten** innerhalb der **Pakete** der Sitzungen **suchen** möchtest, drücke _STRG+f_. Du kannst der Hauptinformationsleiste (Nr., Zeit, Quelle usw.) neue Spalten hinzufügen, indem du mit der rechten Maustaste klickst und anschließend die Spalte bearbeitest.

### Multiplexed Streams folgen

Wireshark kann `TLS`-, `HTTP/2`- und `QUIC`-Streams direkt verfolgen. Die HTTP/2- und QUIC-Dialoge bieten Selektoren für Verbindungen und Substreams, wodurch sich multiplexed Streams isolieren lassen, die dieselbe Verbindung auf niedrigerer Ebene verwenden.<sup>[[4]](#references)</sup>

### Kostenlose pcap-Labs

**Übe mit den kostenlosen Challenges auf:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domains identifizieren

Du kannst eine Spalte hinzufügen, die den HTTP-Host-Header anzeigt:

![Free pcap labs - Domains identifizieren: Du kannst eine Spalte hinzufügen, die den HTTP-Host-Header anzeigt](<../../../images/image (639).png>)

Außerdem kannst du eine Spalte hinzufügen, die den Servernamen einer initiierenden HTTPS-Verbindung anzeigt (**tls.handshake.type == 1**):

![Free pcap labs - Domains identifizieren: Außerdem kannst du eine Spalte hinzufügen, die den Servernamen einer initiierenden HTTPS-Verbindung anzeigt ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Wenn die Aufzeichnung größtenteils verschlüsselt ist, beschleunigt das Hinzufügen dieser Felder als Spalten die Triage erheblich:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Damit kannst du Sitzungen nach Hostnamen, ALPN (`http/1.1`, `h2`, `h3` usw.) und Client-Fingerprint gruppieren, selbst wenn die Payload selbst verschlüsselt bleibt. Bei entschlüsselten HTTP/2- und HTTP/3-Aufzeichnungen ist es außerdem nützlich, `http2.header.value` oder `http3.headers.header.value` als Spalten hinzuzufügen und anhand von Pfaden, Authorities und anderen interessanten Metadaten zu pivotieren.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Lokale Hostnamen identifizieren

### Von DHCP

In aktuellem Wireshark müssen Sie anstelle von `bootp` nach `DHCP` suchen

![Lokale Hostnamen identifizieren - Von DHCP: In aktuellem Wireshark müssen Sie anstelle von bootp nach DHCP suchen](<../../../images/image (1013).png>)

### Von NBNS

![Von DHCP - Von NBNS: In aktuellem Wireshark müssen Sie anstelle von bootp nach DHCP suchen](<../../../images/image (1003).png>)

## TLS entschlüsseln

### https-Traffic mit dem privaten Server-Schlüssel entschlüsseln

_Bearbeiten > Einstellungen > Protokolle > tls >_

![TLS entschlüsseln - https-Traffic mit dem privaten Server-Schlüssel entschlüsseln: https-Traffic mit dem privaten Server-Schlüssel entschlüsseln](<../../../images/image (1103).png>)

Klicken Sie auf _Bearbeiten_ und fügen Sie alle Daten des Servers und den privaten Schlüssel hinzu (_IP, Port, Protokoll, Schlüsseldatei und Passwort_).

Diese Methode funktioniert nur in einer begrenzten Anzahl von Fällen. Für aktuellen TLS-1.3- / ECDHE-Traffic ist die unten beschriebene Methode mit dem Session-Key-Log normalerweise die praktikable Option.<sup>[[1]](#references)</sup>

### https-Traffic mit symmetrischen Session-Keys entschlüsseln

Sowohl Firefox als auch Chrome können TLS-Session-Keys protokollieren, die mit Wireshark zum Entschlüsseln von TLS-Traffic verwendet werden können. Dies ermöglicht eine detaillierte Analyse sicherer Kommunikation. Weitere Informationen zur Durchführung dieser Entschlüsselung finden Sie in einem Guide von [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Dies ist auch der normale Weg zum Entschlüsseln moderner TLS-1.3- und QUIC/HTTP/3-Captures.<sup>[[2]](#references)</sup>

Um dies zu erkennen, suchen Sie innerhalb der Umgebung nach der Variable `SSLKEYLOGFILE`.

Eine Datei mit gemeinsam verwendeten Keys sieht folgendermaßen aus:

![https-Traffic mit dem privaten Server-Schlüssel entschlüsseln - https-Traffic mit symmetrischen Session-Keys entschlüsseln: Eine Datei mit gemeinsam verwendeten Keys sieht folgendermaßen aus](<../../../images/image (820).png>)

Wenn der Capture `pcapng` ist, prüfen Sie, ob er bereits eingebettete Entschlüsselungs-Secrets enthält, bevor Sie das Host-Dateisystem durchsuchen:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Um dies in Wireshark zu importieren, gehe zu \_Edit > Preferences > Protocols > TLS > und importiere es in (Pre)-Master-Secret log filename:

![Entschlüsseln von HTTPS-Datenverkehr mit dem privaten Serverschlüssel – Entschlüsseln von HTTPS-Datenverkehr mit symmetrischen Sitzungsschlüsseln: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB-Kommunikation

Extrahiere ein APK aus einer ADB-Kommunikation, in der das APK gesendet wurde:
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
## References

- [1] [Wireshark TLS-Wiki](https://wiki.wireshark.org/TLS)
- [2] [Entschlüsseln und Parsen von HTTP/3-Traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [TLS-Browser-Traffic mit Wireshark entschlüsseln – der einfache Weg!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protokoll-Streams verfolgen](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Referenz für Anzeigefilter: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Referenz für Anzeigefilter: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Referenz für Anzeigefilter: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
