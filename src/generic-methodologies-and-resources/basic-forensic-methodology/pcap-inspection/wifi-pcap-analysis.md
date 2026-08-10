# Wifi Pcap-analise

## Kontroleer BSSIDs

Met 'n Wi-Fi-capture oop in Wireshark, kies _Wireless → WLAN Traffic_ om die draadlose netwerke wat in die capture waargeneem is, op te som; elke ry verteenwoordig een draadlose netwerk.<sup>[[1]](#references)</sup>

![Wifi Pcap-analise - Kontroleer BSSIDs: Wanneer jy 'n capture ontvang waarvan die hoofverkeer Wifi is en WireShark gebruik, kan jy begin om al die SSIDs van die capture met Wireless --... te ondersoek](<../../../images/image (106).png>)

![Wifi Pcap-analise - Kontroleer BSSIDs: Wanneer jy 'n capture ontvang waarvan die hoofverkeer Wifi is en WireShark gebruik, kan jy begin om al die SSIDs van die capture met Wireless --... te ondersoek](<../../../images/image (492).png>)

### Brute Force

Vir WPA/WPA2-PSK-captures vereis `aircrack-ng` 'n bruikbare four-way EAPOL-handshake en toets dit kandidaat-wagfrases met 'n woordelys. Gebruik `-w` om die woordelys te verskaf en `-b` om die access point se BSSID te teiken:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
As ’n kandidaat ooreenstem, herstel Aircrack-ng die pre-shared key; die ooreenstemmende password en SSID kan dan in Wireshark se 802.11-dekripsie-instellings gekonfigureer word wanneer die capture en sekuriteitsmodus dit ondersteun.<sup>[[2]](#references)[[5]](#references)</sup>

## Data in Beacons / Side Channel

As jy vermoed dat **data in beacon-side-channel-verkeer geleak word**, begin met ’n display filter soos `wlan contains "NAMEofNETWORK"` of `wlan.ssid == "NAMEofNETWORK"`, en inspekteer dan ooreenstemmende rame vir verdagte strings. Die eerste vorm is ’n breë byte-soektog; die tweede stem met die SSID-veld ooreen.<sup>[[3]](#references)[[4]](#references)</sup>

## Vind Onbekende MAC Addresses in ’n Wi-Fi-netwerk

Wireshark stel `wlan.ta` as die transmitter address en `wlan.addr` as ’n hardware/MAC address beskikbaar; display filters kan hierdie velde met logiese operators kombineer:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

As jy reeds **MAC addresses ken**, verwyder hulle uit die uitvoer deur checks soos `&& !(wlan.addr == 5c:51:88:31:a0:3b)` by te voeg.

Sodra jy **onbekende MAC** addresses opgespoor het wat binne die netwerk kommunikeer, gebruik ’n filter soos `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` om die verkeer daarvan te beperk. Die FTP-, HTTP-, SSH- en Telnet-filters is slegs nuttig wanneer Wireshark die ooreenstemmende decrypted payload kan dissekteer.<sup>[[3]](#references)[[5]](#references)</sup>

## Dekripteer Verkeer

Om ’n 802.11-decryption key in Wireshark by te voeg, maak _Edit → Preferences → Protocols → IEEE 802.11_ oop en klik _Edit_ langs _Decryption Keys_.<sup>[[5]](#references)</sup>

![Vind Onbekende MAC Addresses in ’n Wi-Fi-netwerk - Dekripteer Verkeer: Sodra jy onbekende MAC addresses opgespoor het wat binne die netwerk kommunikeer, kan jy filters soos die volgende een gebruik:...](<../../../images/image (499).png>)

Vir WPA/WPA2 benodig Wireshark normaalweg die EAPOL four-way handshake en die ooreenstemmende password/SSID; die verskaffing van die transient key kan die behoefte aan die handshake uitskakel. WPA3-dekripsie per verbinding vereis die verbinding se PMK.<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide: WLAN-verkeer](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Bou van Display Filter Expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
