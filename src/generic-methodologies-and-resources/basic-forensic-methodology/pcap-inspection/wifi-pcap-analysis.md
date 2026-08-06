# Analiza Wifi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Sprawdzanie BSSID

Gdy otrzymasz capture, w którym główny ruch stanowi Wifi, możesz rozpocząć analizę wszystkich SSID z capture w WireShark, korzystając z opcji _Wireless --> WLAN Traffic_:

![Analiza Wifi Pcap - Sprawdzanie BSSID: Gdy otrzymasz capture, w którym główny ruch stanowi Wifi, możesz rozpocząć analizę wszystkich SSID z capture w WireShark, korzystając z opcji Wireless --...](<../../../images/image (106).png>)

![Analiza Wifi Pcap - Sprawdzanie BSSID: Gdy otrzymasz capture, w którym główny ruch stanowi Wifi, możesz rozpocząć analizę wszystkich SSID z capture w WireShark, korzystając z opcji Wireless --...](<../../../images/image (492).png>)

### Brute Force

Jedna z kolumn tego ekranu wskazuje, czy **w pcap znaleziono jakiekolwiek uwierzytelnianie**. Jeśli tak, możesz spróbować przeprowadzić Brute Force za pomocą `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Na przykład odzyska ono hasło WPA chroniące PSK (pre-shared key), które będzie wymagane do późniejszego odszyfrowania ruchu.

## Dane w Beaconach / Side Channel

Jeśli podejrzewasz, że **dane są wykradane wewnątrz beaconów sieci Wi-Fi**, możesz sprawdzić beacony sieci, używając filtra takiego jak: `wlan contains <NAMEofNETWORK>` lub `wlan.ssid == "NAMEofNETWORK"`, a następnie wyszukać podejrzane ciągi znaków wewnątrz przefiltrowanych pakietów.

## Znajdowanie nieznanych adresów MAC w sieci Wi-Fi

Poniższy filtr będzie przydatny do znalezienia **maszyn wysyłających dane w sieci Wi-Fi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Jeśli znasz już **adresy MAC, możesz usunąć je z wyników**, dodając sprawdzenia takie jak: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Po wykryciu **nieznanych adresów MAC** komunikujących się w sieci możesz użyć **filtrów** takich jak poniższy, aby filtrować ich ruch: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`. Pamiętaj, że filtry ftp/http/ssh/telnet są przydatne, jeśli odszyfrowałeś ruch.

## Odszyfrowywanie ruchu

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Znajdowanie nieznanych adresów MAC w sieci Wi-Fi - odszyfrowywanie ruchu: Po wykryciu nieznanych adresów MAC komunikujących się w sieci możesz użyć filtrów takich jak poniższy...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
