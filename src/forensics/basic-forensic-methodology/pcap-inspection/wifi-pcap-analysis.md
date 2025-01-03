{{#include ../../../banners/hacktricks-training.md}}

# Sprawdź BSSID

Kiedy otrzymasz zrzut, którego głównym ruchem jest Wifi, używając WireShark, możesz zacząć badać wszystkie SSID zrzutu za pomocą _Wireless --> WLAN Traffic_:

![](<../../../images/image (424).png>)

![](<../../../images/image (425).png>)

## Brute Force

Jedna z kolumn na tym ekranie wskazuje, czy **znaleziono jakąkolwiek autoryzację w pcap**. Jeśli tak, możesz spróbować przeprowadzić atak Brute force używając `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Na przykład, odzyska hasło WPA chroniące PSK (klucz współdzielony), które będzie wymagane do odszyfrowania ruchu później.

# Dane w Beaconach / Kanał boczny

Jeśli podejrzewasz, że **dane są wyciekane w beaconach sieci Wifi**, możesz sprawdzić beacony sieci, używając filtru takiego jak poniższy: `wlan contains <NAMEofNETWORK>`, lub `wlan.ssid == "NAMEofNETWORK"` przeszukując przefiltrowane pakiety w poszukiwaniu podejrzanych ciągów.

# Znajdowanie nieznanych adresów MAC w sieci Wifi

Poniższy link będzie przydatny do znalezienia **maszyn wysyłających dane w sieci Wifi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Jeśli już znasz **adresy MAC, możesz je usunąć z wyników**, dodając kontrole takie jak ta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Gdy już wykryjesz **nieznane adresy MAC** komunikujące się w sieci, możesz użyć **filtrów** takich jak poniższy: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` aby filtrować jego ruch. Zauważ, że filtry ftp/http/ssh/telnet są przydatne, jeśli odszyfrowałeś ruch.

# Odszyfrowanie ruchu

Edytuj --> Preferencje --> Protokoły --> IEEE 802.11--> Edytuj

![](<../../../images/image (426).png>)

{{#include ../../../banners/hacktricks-training.md}}
