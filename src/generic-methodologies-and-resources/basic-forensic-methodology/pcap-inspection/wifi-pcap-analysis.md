# Wifi Pcap analiza

{{#include ../../../banners/hacktricks-training.md}}

## Provera BSSID-ova

Kada je Wi-Fi capture otvoren u Wireshark-u, izaberite _Wireless → WLAN Traffic_ da biste dobili sažetak bežičnih mreža uočenih u capture-u; svaki red predstavlja jednu bežičnu mrežu.<sup>[[1]](#references)</sup>

![Wifi Pcap analiza - Provera BSSID-ova: Kada primite capture čiji je glavni saobraćaj Wifi i koristite WireShark, možete početi da istražujete sve SSID-ove iz capture-a pomoću Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap analiza - Provera BSSID-ova: Kada primite capture čiji je glavni saobraćaj Wifi i koristite WireShark, možete početi da istražujete sve SSID-ove iz capture-a pomoću Wireless --...](<../../../images/image (492).png>)

### Brute Force

Za WPA/WPA2-PSK capture-e, `aircrack-ng` zahteva upotrebljiv četvorostrani EAPOL handshake i testira potencijalne lozinke pomoću rečnika. Koristite `-w` da navedete wordlist, a `-b` da ciljate BSSID access point-a:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Ako se pronađe podudaranje, Aircrack-ng oporavlja pre-shared key; odgovarajuća lozinka i SSID se zatim mogu konfigurisati u Wireshark-ovim postavkama za dešifrovanje 802.11 saobraćaja, kada to podržavaju capture i bezbednosni režim.<sup>[[2]](#references)[[5]](#references)</sup>

## Podaci u Beacon-ima / Side Channel

Ako sumnjate da se **podaci leak-uju u beacon-side-channel saobraćaju**, počnite sa display filter-om kao što je `wlan contains "NAMEofNETWORK"` ili `wlan.ssid == "NAMEofNETWORK"`, a zatim pregledajte odgovarajuće frame-ove u potrazi za sumnjivim stringovima. Prvi oblik predstavlja široku pretragu bajtova; drugi se podudara sa SSID poljem.<sup>[[3]](#references)[[4]](#references)</sup>

## Pronalaženje nepoznatih MAC adresa u Wi-Fi mreži

Wireshark izlaže `wlan.ta` kao adresu predajnika, a `wlan.addr` kao hardversku/MAC adresu; display filter-i mogu kombinovati ova polja pomoću logičkih operatora:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ako već znate **MAC adrese, uklonite ih iz izlaza** dodavanjem provera kao što je `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Kada otkrijete **nepoznate MAC** adrese koje komuniciraju unutar mreže, koristite filter kao što je `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` da biste suzili saobraćaj. FTP, HTTP, SSH i Telnet filter-i korisni su samo kada Wireshark može da disektuje odgovarajući dešifrovani payload.<sup>[[3]](#references)[[5]](#references)</sup>

## Dešifrovanje saobraćaja

Da biste dodali ključ za dešifrovanje 802.11 u Wireshark-u, otvorite _Edit → Preferences → Protocols → IEEE 802.11_ i kliknite na _Edit_ pored stavke _Decryption Keys_.<sup>[[5]](#references)</sup>

![Pronalaženje nepoznatih MAC adresa u Wi-Fi mreži - Dešifrovanje saobraćaja: Kada otkrijete nepoznate MAC adrese koje komuniciraju unutar mreže, možete koristiti filter-e kao što je sledeći:...](<../../../images/image (499).png>)

Za WPA/WPA2, Wireshark-u je obično potreban EAPOL four-way handshake i odgovarajuća lozinka/SSID; navođenje transient key-a može izbeći zahtev za handshake-om. WPA3 dešifrovanje po konekciji zahteva PMK te konekcije.<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Building Display Filter Expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
