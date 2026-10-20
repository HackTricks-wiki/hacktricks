# Wireshark-Tricks

{{#include ../../../banners/hacktricks-training.md}}

## Verbessere deine Wireshark-Kenntnisse

### Tutorials

Mit den folgenden Tutorials lernst du einige coole grundlegende Tricks:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysierte Informationen

**Expert Information**

Wenn du auf _**Analyze** --> **Expert Information**_ klickst, erhältst du einen **Überblick** darüber, was in den **analysierten** Paketen passiert:

![Tutorials - Analysierte Informationen: Wenn du auf Analyze -- Expert Information klickst, erhältst du einen Überblick darüber, was in den analysierten Paketen passiert](<../../../images/image (256).png>)

**Resolved Addresses**

Unter _**Statistics --> Resolved Addresses**_ findest du verschiedene von Wireshark „aufgelöste“ **Informationen**, zum Beispiel Port/Transportprotokoll, MAC-Adresse zum Hersteller usw. Es ist interessant zu wissen, woran die Kommunikation beteiligt ist.

![Tutorials - Analysierte Informationen: Unter Statistics -- Resolved Addresses findest du verschiedene von Wireshark „aufgelöste“ Informationen, zum Beispiel Port/Transportprotokoll, MAC-Adresse zum...](<../../../images/image (893).png>)

**Protocol Hierarchy**

Unter _**Statistics --> Protocol Hierarchy**_ findest du die an der Kommunikation **beteiligten Protokolle** und Informationen zu ihnen.

![Tutorials - Analysierte Informationen: Unter Statistics -- Protocol Hierarchy findest du die an der Kommunikation beteiligten Protokolle und Informationen zu ihnen](<../../../images/image (586).png>)

**Conversations**

Unter _**Statistics --> Conversations**_ findest du eine **Zusammenfassung der Kommunikationsverbindungen** und Informationen zu ihnen.

![Tutorials - Analysierte Informationen: Unter Statistics -- Conversations findest du eine Zusammenfassung der Kommunikationsverbindungen und Informationen zu ihnen](<../../../images/image (453).png>)

**Endpoints**

Unter _**Statistics --> Endpoints**_ findest du eine **Zusammenfassung der Endpunkte** in der Kommunikation und Informationen zu jedem einzelnen.

![Tutorials - Analysierte Informationen: Unter Statistics -- Endpoints findest du eine Zusammenfassung der Endpunkte in der Kommunikation und Informationen zu jedem einzelnen](<../../../images/image (896).png>)

**DNS-Informationen**

Unter _**Statistics --> DNS**_ findest du Statistiken zu den erfassten DNS-Anfragen.

![Tutorials - Analysierte Informationen: Unter Statistics -- DNS findest du Statistiken zu den erfassten DNS-Anfragen](<../../../images/image (1063).png>)

**I/O Graph**

Unter _**Statistics --> I/O Graph**_ findest du ein **Diagramm der Kommunikation.**

![Tutorials - Analysierte Informationen: Unter Statistics -- I/O Graph findest du ein Diagramm der Kommunikation](<../../../images/image (992).png>)

### Filter

Hier findest du Wireshark-Filter nach Protokoll: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Verwende in aktuellen Wireshark-Versionen `tls.*` statt der alten Filterbezeichnungen `ssl.*`.<sup>[[1]](#references)</sup>\
Weitere interessante Filter:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTP- und anfänglicher HTTPS-Datenverkehr
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTP- und anfänglicher HTTPS-Datenverkehr + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTP- und anfänglicher HTTPS-Datenverkehr + TCP SYN + DNS-Anfragen
- `tls.handshake.extensions_server_name contains "example.com"`
  - Nutze den im ClientHello gesendeten SNI als Pivot, auch wenn du den Payload nicht entschlüsseln kannst
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Unterscheide schnell zwischen Sitzungen mit klassischem HTTPS, HTTP/2 und HTTP/3
- `quic or http3`
  - Finde modernen UDP/443-Datenverkehr, der bei einer Prüfung ausschließlich der TCP-Verbindungen übersehen würde

### Suchen

Wenn du nach **Inhalten** in den **Paketen** der Sitzungen **suchen** möchtest, drücke _CTRL+f_. Du kannst der Hauptinformationsleiste (No., Time, Source usw.) weitere Spalten hinzufügen, indem du mit der rechten Maustaste darauf klickst und anschließend „Spalte bearbeiten“ auswählst.

### Multiplexed Streams folgen

Wireshark kann `TLS`-, `HTTP/2`- und `QUIC`-Streams direkt verfolgen. In den Dialogen für HTTP/2 und QUIC kannst du Verbindungen und Substreams auswählen. So lassen sich multiplexed Streams isolieren, die dieselbe Verbindung auf einer niedrigeren Ebene gemeinsam nutzen.<sup>[[4]](#references)</sup>

Wenn Sitzungsschlüssel verfügbar sind, ermittle zuerst die Stream-ID der Anfrage und folge dann diesem Substream statt der gesamten TCP- oder UDP-Kommunikation. Das Beispiel `0,1` wählt die HTTP/2-Stream-ID 1 auf TCP-Stream 0 aus; für QUIC verwende `follow,quic,utf-8,<connection-number>,<stream-id>`. Wenn du nur einem Fünf-Tupel folgst, können unabhängige Anfragen vermischt werden oder eine QUIC-Verbindung nach einer Migration übersehen werden.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Kostenlose pcap-Labs

**Übe mit den kostenlosen Challenges unter:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domains identifizieren

Du kannst eine Spalte hinzufügen, die den HTTP-Host-Header anzeigt:

![Kostenlose pcap-Labs – Domains identifizieren: Du kannst eine Spalte hinzufügen, die den HTTP-Host-Header anzeigt](<../../../images/image (639).png>)

Und eine Spalte, die den Servernamen einer initiierenden HTTPS-Verbindung anzeigt (**tls.handshake.type == 1**):

![Kostenlose pcap-Labs – Domains identifizieren: Und eine Spalte, die den Servernamen einer initiierenden HTTPS-Verbindung anzeigt ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Wenn der Mitschnitt größtenteils verschlüsselt ist, beschleunigt das Hinzufügen dieser Felder als Spalten die erste Sichtung erheblich:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

So kannst du Sitzungen nach Hostname, ALPN (`http/1.1`, `h2`, `h3` usw.) und Client-Fingerprint gruppieren, auch wenn die Nutzdaten selbst verschlüsselt bleiben. Bei entschlüsselten HTTP/2- und HTTP/3-Mitschnitten ist es außerdem hilfreich, `http2.header.value` oder `http3.headers.header.value` als Spalten hinzuzufügen und nach Pfaden, Authorities und anderen interessanten Metadaten zu pivotieren.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: die äußere SNI nicht mit dem Ursprungsserver verwechseln

Encrypted ClientHello (ECH) kann einen öffentlichen Tarnnamen in der sichtbaren äußeren SNI platzieren und dabei den inneren Namen verschlüsseln. Daher kann ein Domaininventar, das nur auf der SNI basiert, ECH-Traffic dem falschen Ursprungsserver zuordnen. Die ECH-Erweiterung allein beweist nicht, dass ECH erfolgreich war: Clients können eine GREASE-ECH-Erweiterung senden. Verwende Wireshark 4.2 oder neuer, um äußere ECH-Angebote mit dem folgenden Filter zu finden, und behandle die gemeldete SNI als möglichen Tarnnamen, nicht als angeforderte Website.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Wenn du über die passenden Client-Sitzungsschlüssel verfügst, untersuche die entschlüsselte HTTP authority/Host, statt den Ursprung aus dem äußeren SNI abzuleiten. Ohne die Schlüssel prüfe andere erfasste Hinweise auf den Ursprung, etwa Klartext-DNS, setze aber das äußere SNI nicht mit dem verborgenen Namen gleich.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Lokale Hostnamen identifizieren

### Über DHCP

In aktuellen Wireshark-Versionen musst du statt `bootp` nach `DHCP` suchen.

![Lokale Hostnamen identifizieren – Über DHCP: In aktuellen Wireshark-Versionen musst du statt bootp nach DHCP suchen](<../../../images/image (1013).png>)

### Über NBNS

![Über DHCP – Über NBNS: In aktuellen Wireshark-Versionen musst du statt bootp nach DHCP suchen](<../../../images/image (1003).png>)

## TLS entschlüsseln

Die Entschlüsselung der Wi-Fi-Verbindungsschicht ist unabhängig von der Entschlüsselung der TLS-Sitzung. Siehe [Wi-Fi-PCAP-Analyse](wifi-pcap-analysis.md) für die erforderlichen Schlüssel und Handshake-Voraussetzungen.

### HTTPS-Verkehr mit dem privaten Serverschlüssel entschlüsseln

_edit > preferences > protocols > tls >_

![TLS entschlüsseln – HTTPS-Verkehr mit dem privaten Serverschlüssel entschlüsseln: HTTPS-Verkehr mit dem privaten Serverschlüssel entschlüsseln](<../../../images/image (1103).png>)

Klicke auf _Edit_ und füge alle Serverdaten und den privaten Schlüssel hinzu (_IP, Port, Protokoll, Schlüsseldatei und Passwort_).

Diese Methode funktioniert nur in einer begrenzten Anzahl von Fällen. Bei aktuellem TLS-1.3-/ECDHE-Verkehr ist die unten beschriebene Methode mit dem Sitzungsschlüsselprotokoll normalerweise die praktische Option.<sup>[[1]](#references)</sup>

### HTTPS-Verkehr mit symmetrischen Sitzungsschlüsseln entschlüsseln

Sowohl Firefox als auch Chrome können TLS-Sitzungsschlüssel protokollieren, die mit Wireshark zum Entschlüsseln von TLS-Verkehr verwendet werden können. Das ermöglicht eine detaillierte Analyse sicherer Kommunikation. Weitere Informationen zur Durchführung dieser Entschlüsselung findest du in einer Anleitung bei [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Dies ist auch der übliche Weg, um Mitschnitte mit modernem TLS 1.3 und QUIC/HTTP/3 zu entschlüsseln.<sup>[[2]](#references)</sup>

Suche in der Umgebung nach der Variable `SSLKEYLOGFILE`, um dies zu erkennen.

Eine Datei mit Sitzungsschlüsseln sieht folgendermaßen aus:

![TLS entschlüsseln – HTTPS-Verkehr mit dem privaten Serverschlüssel entschlüsseln – HTTPS-Verkehr mit symmetrischen Sitzungsschlüsseln entschlüsseln: Eine Datei mit Sitzungsschlüsseln sieht folgendermaßen aus](<../../../images/image (820).png>)

Wenn es sich beim Mitschnitt um eine `pcapng`-Datei handelt, prüfe, ob sie bereits eingebettete Entschlüsselungsgeheimnisse enthält, bevor du das Host-Dateisystem durchsuchst:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Um dies in Wireshark zu importieren, gehe zu \_Bearbeiten > Einstellungen > Protokolle > TLS > und importiere es unter „(Pre)-Master-Secret-Logdatei“:

![HTTPS-Verkehr mit dem privaten Schlüssel des Servers entschlüsseln – HTTPS-Verkehr mit symmetrischen Sitzungsschlüsseln entschlüsseln: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB-Kommunikation

Extrahiere eine APK aus einer ADB-Kommunikation, bei der die APK gesendet wurde:

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
- [2] [HTTP/3-Datenverkehr in Wireshark entschlüsseln und parsen](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [TLS-Browserdatenverkehr mit Wireshark entschlüsseln – ganz einfach!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protokollstreams verfolgen](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Referenz für Anzeigefilter: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Referenz für Anzeigefilter: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Referenz für Anzeigefilter: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: Verschlüsselter TLS-ClientHello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [TShark-Handbuch](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
