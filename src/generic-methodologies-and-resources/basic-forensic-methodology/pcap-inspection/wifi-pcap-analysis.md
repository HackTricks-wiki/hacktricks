# Wifi Pcap analiza

{{#include ../../../banners/hacktricks-training.md}}

## Provera BSSID-ova

Kada primite capture čiji je glavni saobraćaj Wifi i koristite WireShark, možete početi da istražujete sve SSID-ove iz capture-a pomoću opcije _Wireless --> WLAN Traffic_:

![Wifi Pcap analiza - Provera BSSID-ova: Kada primite capture čiji je glavni saobraćaj Wifi i koristite WireShark, možete početi da istražujete sve SSID-ove iz capture-a pomoću opcije Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap analiza - Provera BSSID-ova: Kada primite capture čiji je glavni saobraćaj Wifi i koristite WireShark, možete početi da istražujete sve SSID-ove iz capture-a pomoću opcije Wireless --...](<../../../images/image (492).png>)

### Brute Force

Jedna od kolona na tom ekranu pokazuje da li je **bilo koja autentikacija pronađena unutar pcap-a**. Ako jeste, možete pokušati da izvršite Brute force pomoću `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Na primer, preuzeće WPA passphrase koji štiti PSK (pre-shared key), a koji će kasnije biti potreban za dešifrovanje saobraćaja.

## Podaci u Beacon-ima / Side Channel

Ako sumnjate da se **podaci leak-uju unutar beacon-a WiFi mreže**, možete proveriti beacon-e mreže koristeći filter poput sledećeg: `wlan contains <NAMEofNETWORK>`, ili `wlan.ssid == "NAMEofNETWORK"` i pretražiti filtrirane pakete u potrazi za sumnjivim stringovima.

## Pronalaženje nepoznatih MAC adresa u WiFi mreži

Sledeća veza će biti korisna za pronalaženje **mašina koje šalju podatke unutar WiFi mreže**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ako već znate **MAC adrese, možete ih ukloniti iz izlaza** dodavanjem provera poput ove: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Kada detektujete **nepoznate MAC** adrese koje komuniciraju unutar mreže, možete koristiti **filtere** poput sledećeg: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` da filtrirate njihov saobraćaj. Imajte na umu da su ftp/http/ssh/telnet filteri korisni ako ste dešifrovali saobraćaj.

## Dešifrovanje saobraćaja

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Pronalaženje nepoznatih MAC adresa u WiFi mreži - Dešifrovanje saobraćaja: Kada detektujete nepoznate MAC adrese koje komuniciraju unutar mreže, možete koristiti filtere poput sledećeg:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
