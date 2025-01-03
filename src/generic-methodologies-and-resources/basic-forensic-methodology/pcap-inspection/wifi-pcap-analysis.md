# Wifi Pcap Analiza

{{#include ../../../banners/hacktricks-training.md}}

## Proverite BSSID-ove

Kada primite snimak čiji je glavni saobraćaj Wifi koristeći WireShark, možete početi da istražujete sve SSID-ove snimka sa _Wireless --> WLAN Traffic_:

![](<../../../images/image (106).png>)

![](<../../../images/image (492).png>)

### Brute Force

Jedna od kolona tog ekrana pokazuje da li je **bilo kakva autentifikacija pronađena unutar pcap-a**. Ako je to slučaj, možete pokušati da je brute force-ujete koristeći `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Na primer, dobiće WPA lozinku koja štiti PSK (pre shared-key), koja će biti potrebna za dekriptovanje saobraćaja kasnije.

## Podaci u Beacon-ima / Sporedni Kanal

Ako sumnjate da se **podaci curi unutar beacon-a Wifi mreže**, možete proveriti beacon-e mreže koristeći filter kao što je sledeći: `wlan contains <NAMEofNETWORK>`, ili `wlan.ssid == "NAMEofNETWORK"` pretražujući unutar filtriranih paketa za sumnjive stringove.

## Pronađite Nepoznate MAC Adrese u Wifi Mreži

Sledeći link će biti koristan za pronalaženje **mašina koje šalju podatke unutar Wifi mreže**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ako već znate **MAC adrese, možete ih ukloniti iz izlaza** dodajući provere kao što je ova: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Kada detektujete **nepoznate MAC** adrese koje komuniciraju unutar mreže, možete koristiti **filtre** kao što je sledeći: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` da filtrirate njihov saobraćaj. Imajte na umu da su ftp/http/ssh/telnet filteri korisni ako ste dekriptovali saobraćaj.

## Dekriptovanje Saobraćaja

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
