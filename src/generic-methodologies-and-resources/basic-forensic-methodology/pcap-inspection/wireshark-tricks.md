# Wireshark-Tricks

{{#include ../../../banners/hacktricks-training.md}}

## Verbessern Sie Ihre Wireshark-Fähigkeiten

### Tutorials

Die folgenden Tutorials sind großartig, um einige coole grundlegende Tricks zu lernen:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysierte Informationen

**Experteninformationen**

Durch Klicken auf _**Analyse** --> **Experteninformationen**_ erhalten Sie eine **Übersicht** darüber, was in den **analysierten** Paketen passiert:

![](<../../../images/image (256).png>)

**Aufgelöste Adressen**

Unter _**Statistiken --> Aufgelöste Adressen**_ finden Sie mehrere **Informationen**, die von Wireshark "**aufgelöst**" wurden, wie Port/Transport zu Protokoll, MAC zu Hersteller usw. Es ist interessant zu wissen, was an der Kommunikation beteiligt ist.

![](<../../../images/image (893).png>)

**Protokollhierarchie**

Unter _**Statistiken --> Protokollhierarchie**_ finden Sie die **Protokolle**, die an der Kommunikation **beteiligt** sind, sowie Daten über sie.

![](<../../../images/image (586).png>)

**Gespräche**

Unter _**Statistiken --> Gespräche**_ finden Sie eine **Zusammenfassung der Gespräche** in der Kommunikation und Daten darüber.

![](<../../../images/image (453).png>)

**Endpunkte**

Unter _**Statistiken --> Endpunkte**_ finden Sie eine **Zusammenfassung der Endpunkte** in der Kommunikation und Daten über jeden von ihnen.

![](<../../../images/image (896).png>)

**DNS-Informationen**

Unter _**Statistiken --> DNS**_ finden Sie Statistiken über die erfasste DNS-Anfrage.

![](<../../../images/image (1063).png>)

**I/O-Diagramm**

Unter _**Statistiken --> I/O-Diagramm**_ finden Sie ein **Diagramm der Kommunikation.**

![](<../../../images/image (992).png>)

### Filter

Hier finden Sie Wireshark-Filter je nach Protokoll: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Weitere interessante Filter:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP- und anfänglicher HTTPS-Verkehr
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP- und anfänglicher HTTPS-Verkehr + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP- und anfänglicher HTTPS-Verkehr + TCP SYN + DNS-Anfragen

### Suche

Wenn Sie nach **Inhalt** innerhalb der **Pakete** der Sitzungen suchen möchten, drücken Sie _CTRL+f_. Sie können neue Ebenen zur Hauptinformationsleiste (Nr., Zeit, Quelle usw.) hinzufügen, indem Sie mit der rechten Maustaste klicken und dann die Spalte bearbeiten.

### Kostenlose pcap-Labore

**Üben Sie mit den kostenlosen Herausforderungen von:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifizierung von Domains

Sie können eine Spalte hinzufügen, die den Host-HTTP-Header anzeigt:

![](<../../../images/image (639).png>)

Und eine Spalte, die den Servernamen von einer initiierenden HTTPS-Verbindung (**ssl.handshake.type == 1**) hinzufügt:

![](<../../../images/image (408) (1).png>)

## Identifizierung lokaler Hostnamen

### Von DHCP

In der aktuellen Wireshark-Version müssen Sie anstelle von `bootp` nach `DHCP` suchen

![](<../../../images/image (1013).png>)

### Von NBNS

![](<../../../images/image (1003).png>)

## Entschlüsselung von TLS

### Entschlüsselung von HTTPS-Verkehr mit dem privaten Schlüssel des Servers

_edit>präferenz>protokoll>ssl>_

![](<../../../images/image (1103).png>)

Drücken Sie _Bearbeiten_ und fügen Sie alle Daten des Servers und den privaten Schlüssel (_IP, Port, Protokoll, Schlüsseldatei und Passwort_) hinzu.

### Entschlüsselung von HTTPS-Verkehr mit symmetrischen Sitzungsschlüsseln

Sowohl Firefox als auch Chrome haben die Fähigkeit, TLS-Sitzungsschlüssel zu protokollieren, die mit Wireshark verwendet werden können, um TLS-Verkehr zu entschlüsseln. Dies ermöglicht eine eingehende Analyse sicherer Kommunikation. Weitere Details zur Durchführung dieser Entschlüsselung finden Sie in einem Leitfaden bei [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Um dies zu erkennen, suchen Sie in der Umgebung nach der Variablen `SSLKEYLOGFILE`.

Eine Datei mit gemeinsamen Schlüsseln sieht so aus:

![](<../../../images/image (820).png>)

Um dies in Wireshark zu importieren, gehen Sie zu _bearbeiten > präferenz > protokoll > ssl > und importieren Sie es in (Pre)-Master-Secret-Protokolldateinamen:

![](<../../../images/image (989).png>)

## ADB-Kommunikation

Extrahieren Sie eine APK aus einer ADB-Kommunikation, bei der die APK gesendet wurde:
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
{{#include ../../../banners/hacktricks-training.md}}
