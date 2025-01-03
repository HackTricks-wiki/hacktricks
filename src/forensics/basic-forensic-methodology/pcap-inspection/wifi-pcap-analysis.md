{{#include ../../../banners/hacktricks-training.md}}

# Kontroleer BSSIDs

Wanneer jy 'n opname ontvang waarvan die hoofverkeer Wifi is met WireShark, kan jy begin om al die SSIDs van die opname te ondersoek met _Wireless --> WLAN Traffic_:

![](<../../../images/image (424).png>)

![](<../../../images/image (425).png>)

## Brute Force

Een van die kolomme van daardie skerm dui aan of **enige outentisering binne die pcap gevind is**. As dit die geval is, kan jy probeer om dit te Brute force met `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Byvoorbeeld, dit sal die WPA wagwoord wat 'n PSK (pre shared-key) beskerm, terughaal, wat benodig sal word om die verkeer later te ontsleutel.

# Data in Beacons / Sy Kanaal

As jy vermoed dat **data binne beacons van 'n Wifi-netwerk gelek word**, kan jy die beacons van die netwerk nagaan met 'n filter soos die volgende: `wlan contains <NAMEofNETWORK>`, of `wlan.ssid == "NAMEofNETWORK"` soek binne die gefilterde pakkette vir verdagte stringe.

# Vind Onbekende MAC Adresse in 'n Wifi Netwerk

Die volgende skakel sal nuttig wees om die **masjiene wat data binne 'n Wifi-netwerk stuur** te vind:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

As jy reeds **MAC adresse weet, kan jy hulle uit die uitvoer verwyder** deur kontroles soos hierdie een by te voeg: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Sodra jy **onbekende MAC** adresse wat binne die netwerk kommunikeer, opgespoor het, kan jy **filters** soos die volgende gebruik: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` om sy verkeer te filter. Let daarop dat ftp/http/ssh/telnet filters nuttig is as jy die verkeer ontsleutel het.

# Ontsleutel Verkeer

Edit --> Voorkeure --> Protokolle --> IEEE 802.11--> Edit

![](<../../../images/image (426).png>)

{{#include ../../../banners/hacktricks-training.md}}
