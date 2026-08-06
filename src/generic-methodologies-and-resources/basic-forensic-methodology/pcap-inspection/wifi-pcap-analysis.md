# Wifi Pcap-analise

{{#include ../../../banners/hacktricks-training.md}}

## Kontroleer BSSIDs

Wanneer jy 'n capture ontvang waarvan die hoofverkeer Wifi is en WireShark gebruik, kan jy begin om al die SSIDs van die capture te ondersoek met _Wireless --> WLAN Traffic_:

![Wifi Pcap-analise - Kontroleer BSSIDs: Wanneer jy 'n capture ontvang waarvan die hoofverkeer Wifi is en WireShark gebruik, kan jy begin om al die SSIDs van die capture te ondersoek met Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap-analise - Kontroleer BSSIDs: Wanneer jy 'n capture ontvang waarvan die hoofverkeer Wifi is en WireShark gebruik, kan jy begin om al die SSIDs van die capture te ondersoek met Wireless --...](<../../../images/image (492).png>)

### Brute Force

Een van die kolomme op daardie skerm dui aan of **enige authentication binne die pcap gevind is**. Indien wel, kan jy probeer om dit met `aircrack-ng` te Brute force:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Byvoorbeeld, dit sal die WPA passphrase wat 'n PSK (pre shared-key) beskerm, retrieve; dit sal later benodig word om die traffic te decrypt.

## Data in Beacons / Side Channel

As jy vermoed dat **data binne beacons van 'n Wifi-netwerk geleak word**, kan jy die beacons van die netwerk nagaan deur 'n filter soos die volgende te gebruik: `wlan contains <NAMEofNETWORK>`, of `wlan.ssid == "NAMEofNETWORK"`; soek binne die gefiltreerde packets vir verdagte strings.

## Find Unknown MAC Addresses in A Wifi Network

Die volgende skakel sal nuttig wees om die **machines wat data binne 'n Wifi Network stuur** te vind:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

As jy reeds **MAC addresses** ken, kan jy hulle uit die output verwyder deur checks soos hierdie een by te voeg: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Sodra jy **unknown MAC** addresses opgespoor het wat binne die netwerk kommunikeer, kan jy **filters** soos die volgende een gebruik: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` om sy traffic te filter. Let daarop dat ftp/http/ssh/telnet-filters nuttig is indien jy die traffic gedekripteer het.

## Decrypt Traffic

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Find Unknown MAC Addresses in A Wifi Network - Decrypt Traffic: Sodra jy unknown MAC addresses opgespoor het wat binne die netwerk kommunikeer, kan jy filters soos die volgende een gebruik:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
