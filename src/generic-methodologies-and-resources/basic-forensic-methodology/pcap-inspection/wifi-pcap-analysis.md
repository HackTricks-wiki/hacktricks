# Wi-Fi Pcap-analise

{{#include ../../../banners/hacktricks-training.md}}

## Kontroleer BSSIDs

Met ’n Wi-Fi-opname oop in Wireshark, kies _Wireless → WLAN Traffic_ om ’n opsomming te sien van die draadlose netwerke wat in die opname waargeneem is; elke ry verteenwoordig een draadlose netwerk.<sup>[[1]](#references)</sup>

![Wifi Pcap Analysis - Kontroleer BSSIDs: Wanneer jy ’n opname ontvang waarvan die hoofverkeer Wi-Fi is, kan jy WireShark gebruik om al die SSIDs in die opname te begin ondersoek met Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap Analysis - Kontroleer BSSIDs: Wanneer jy ’n opname ontvang waarvan die hoofverkeer Wi-Fi is, kan jy WireShark gebruik om al die SSIDs in die opname te begin ondersoek met Wireless --...](<../../../images/image (492).png>)

### Brute Force

Vir WPA/WPA2-PSK-opnames benodig `aircrack-ng` ’n bruikbare vierweg-EAPOL-handshake en toets dit kandidaat-wagfrases met ’n woordelys. Gebruik `-w` om die woordelys te spesifiseer en `-b` om die toegangspunt se BSSID te teiken:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

As ’n kandidaat ooreenstem, herwin Aircrack-ng die vooraf gedeelde sleutel; die ooreenstemmende wagwoord en SSID kan dan in Wireshark se 802.11-dekripteringsinstellings opgestel word wanneer die vaslegging en sekuriteitsmodus dit ondersteun.<sup>[[2]](#references)[[5]](#references)</sup>

## Data in bakens / sykanaal

As jy vermoed dat **data in baken-sykanaalverkeer uitgelek word**, begin met ’n vertoonfilter soos `wlan contains "NAMEofNETWORK"` of `wlan.ssid == "NAMEofNETWORK"`, en ondersoek dan ooreenstemmende rame vir verdagte stringe. Die eerste vorm is ’n breë soektog na grepe; die tweede pas by die SSID-veld.<sup>[[3]](#references)[[4]](#references)</sup>

## Vind onbekende MAC-adresse in ’n Wi-Fi-netwerk

Wireshark stel `wlan.ta` as die senderadres en `wlan.addr` as ’n hardeware-/MAC-adres beskikbaar; vertoonfilters kan hierdie velde met logiese operateurs kombineer:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

As jy reeds **MAC-adresse ken, verwyder hulle uit die uitvoer** deur kontroles soos `&& !(wlan.addr == 5c:51:88:31:a0:3b)` by te voeg.

Sodra jy **onbekende MAC**-adresse opgespoor het wat binne die netwerk kommunikeer, gebruik ’n filter soos `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` om die verkeer te beperk. Die FTP-, HTTP-, SSH- en Telnet-filters is net nuttig wanneer Wireshark die ooreenstemmende gedekripteerde loonvrag kan ontleed.<sup>[[3]](#references)[[5]](#references)</sup>

## Dekripteer verkeer

Om ’n 802.11-dekripsiesleutel in Wireshark by te voeg, maak _Edit → Preferences → Protocols → IEEE 802.11_ oop en klik _Edit_ langs _Decryption Keys_.<sup>[[5]](#references)</sup>

![Vind onbekende MAC-adresse in ’n Wi-Fi-netwerk - Dekripteer verkeer: Sodra jy onbekende MAC-adresse opgespoor het wat binne die netwerk kommunikeer, kan jy filters soos die volgende een gebruik:...](<../../../images/image (499).png>)

Vir WPA/WPA2 benodig Wireshark gewoonlik die EAPOL-vierrigting-handdruk en die ooreenstemmende wagwoord/SSID; deur die tydelike sleutel te verskaf, kan die handdrukvereiste vermy word. WPA3-dekripsie per verbinding vereis die verbinding se PMK.<sup>[[5]](#references)</sup>

Vir TLS-dekripsie op die toepassingslaag nadat Wi-Fi-verkeer herwin is, sien [Wireshark-truuks](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Wireshark User's Guide: WLAN-verkeer](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Bou van vertoonfilteruitdrukkings](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11-draadlose LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN-dekripsiesleutels](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
