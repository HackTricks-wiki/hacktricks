# Analiza WiFi PCAP-a

{{#include ../../../banners/hacktricks-training.md}}

## Provera BSSID-ova

Kada otvorite Wi-Fi capture u Wireshark-u, izaberite _Wireless → WLAN Traffic_ da biste dobili pregled bežičnih mreža zabeleženih u capture-u; svaki red predstavlja jednu bežičnu mrežu.<sup>[[1]](#references)</sup>

![Analiza WiFi PCAP-a - Provera BSSID-ova: Kada dobijete capture čiji se glavni saobraćaj odvija preko WiFi-ja, možete početi da istražujete sve SSID-ove iz capture-a pomoću opcije Wireless --...](<../../../images/image (106).png>)

![Analiza WiFi PCAP-a - Provera BSSID-ova: Kada dobijete capture čiji se glavni saobraćaj odvija preko WiFi-ja, možete početi da istražujete sve SSID-ove iz capture-a pomoću opcije Wireless --...](<../../../images/image (492).png>)

### Brute Force

Za WPA/WPA2-PSK capture-ove, `aircrack-ng` zahteva upotrebljiv četvorostruki EAPOL handshake i testira moguće lozinke pomoću rečnika. Koristite `-w` da navedete wordlist, a `-b` da odredite BSSID access point-a:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Ako se kandidat podudara, Aircrack-ng oporavlja unapred deljeni ključ; odgovarajuća lozinka i SSID zatim mogu da se podese u Wiresharkovim postavkama za dešifrovanje 802.11 saobraćaja, ako to podržavaju snimak i režim bezbednosti.<sup>[[2]](#references)[[5]](#references)</sup>

## Podaci u beacon-ima / bočni kanal

Ako sumnjate da se **podaci odaju u saobraćaju bočnog kanala beacon-a**, počnite filterom za prikaz kao što je `wlan contains "NAMEofNETWORK"` ili `wlan.ssid == "NAMEofNETWORK"`, a zatim pregledajte odgovarajuće frejmove tražeći sumnjive nizove znakova. Prvi oblik je široka pretraga bajtova; drugi podudara polje SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Pronalaženje nepoznatih MAC adresa u Wi-Fi mreži

Wireshark prikazuje `wlan.ta` kao adresu predajnika, a `wlan.addr` kao hardversku/MAC adresu; filteri za prikaz mogu da kombinuju ova polja pomoću logičkih operatora:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ako već znate **MAC adrese, uklonite ih iz izlaza** dodavanjem provera kao što je `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Kada otkrijete **nepoznate MAC** adrese koje komuniciraju unutar mreže, upotrebite filter kao što je `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` da biste suzili saobraćaj. Filteri za FTP, HTTP, SSH i Telnet korisni su samo kada Wireshark može da raščlani odgovarajući dešifrovani sadržaj.<sup>[[3]](#references)[[5]](#references)</sup>

## Dešifrovanje saobraćaja

Da biste dodali ključ za dešifrovanje 802.11 u Wireshark, otvorite _Edit → Preferences → Protocols → IEEE 802.11_ i kliknite na _Edit_ pored stavke _Decryption Keys_.<sup>[[5]](#references)</sup>

![Pronalaženje nepoznatih MAC adresa u Wi-Fi mreži – Dešifrovanje saobraćaja: Kada otkrijete nepoznate MAC adrese koje komuniciraju unutar mreže, možete upotrebiti filtere kao što je sledeći:...](<../../../images/image (499).png>)

Za WPA/WPA2, Wiresharku su obično potrebni četvorostruko rukovanje EAPOL i odgovarajuća lozinka/SSID; dostavljanjem prolaznog ključa može se zaobići zahtev za rukovanjem. Dešifrovanje WPA3 saobraćaja za pojedinačnu vezu zahteva PMK te veze.<sup>[[5]](#references)</sup>

Za dešifrovanje TLS-a na aplikacionom sloju nakon oporavka Wi-Fi saobraćaja pogledajte [Wireshark tricks](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Korisnički vodič za Wireshark: WLAN saobraćaj](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Korisnički vodič za Wireshark: Izrada izraza filtera za prikaz](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Referenca filtera za prikaz u Wiresharku: IEEE 802.11 bežični LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Korisnički vodič za Wireshark: Ključevi za dešifrovanje IEEE 802.11 WLAN-a](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
