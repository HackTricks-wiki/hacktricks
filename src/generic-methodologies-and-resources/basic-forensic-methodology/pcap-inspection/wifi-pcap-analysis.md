# Analiza WiFi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Sprawdzanie BSSID

Mając otwarty przechwycony ruch Wi-Fi w Wireshark, wybierz _Wireless → WLAN Traffic_, aby podsumować sieci bezprzewodowe zaobserwowane w przechwyconym ruchu; każdy wiersz reprezentuje jedną sieć bezprzewodową.<sup>[[1]](#references)</sup>

![Analiza Wifi Pcap - Sprawdzanie BSSID: Po otrzymaniu przechwyconego ruchu, w którym dominuje ruch Wi-Fi, za pomocą WireShark możesz rozpocząć analizowanie wszystkich SSID przechwyconego ruchu za pomocą Wireless --...](<../../../images/image (106).png>)

![Analiza Wifi Pcap - Sprawdzanie BSSID: Po otrzymaniu przechwyconego ruchu, w którym dominuje ruch Wi-Fi, za pomocą WireShark możesz rozpocząć analizowanie wszystkich SSID przechwyconego ruchu za pomocą Wireless --...](<../../../images/image (492).png>)

### Brute Force

W przypadku przechwyconego ruchu WPA/WPA2-PSK `aircrack-ng` wymaga użytecznego four-way EAPOL handshake i testuje potencjalne hasła za pomocą słownika. Użyj `-w`, aby podać wordlistę, oraz `-b`, aby wskazać BSSID punktu dostępu:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Jeśli kandydat pasuje, Aircrack-ng odzyskuje pre-shared key; pasujące hasło i SSID można następnie skonfigurować w ustawieniach deszyfrowania 802.11 w Wireshark, gdy przechwycony ruch i tryb zabezpieczeń to obsługują.<sup>[[2]](#references)[[5]](#references)</sup>

## Dane w Beaconach / Side Channel

Jeśli podejrzewasz, że **dane są leakowane w ruchu beacon-side-channel**, zacznij od filtra wyświetlania, takiego jak `wlan contains "NAMEofNETWORK"` lub `wlan.ssid == "NAMEofNETWORK"`, a następnie przejrzyj pasujące ramki pod kątem podejrzanych ciągów. Pierwsza forma to szerokie wyszukiwanie bajtów; druga dopasowuje pole SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Znajdowanie nieznanych adresów MAC w sieci Wi-Fi

Wireshark udostępnia `wlan.ta` jako adres nadajnika oraz `wlan.addr` jako adres sprzętowy/MAC; filtry wyświetlania mogą łączyć te pola za pomocą operatorów logicznych:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Jeśli znasz już **adresy MAC, usuń je z wyników** przez dodanie sprawdzeń takich jak `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Po wykryciu **nieznanych adresów MAC** komunikujących się wewnątrz sieci użyj filtra takiego jak `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)`, aby zawęzić analizowany ruch. Filtry FTP, HTTP, SSH i Telnet są przydatne tylko wtedy, gdy Wireshark może zinterpretować odpowiadający im odszyfrowany payload.<sup>[[3]](#references)[[5]](#references)</sup>

## Deszyfrowanie ruchu

Aby dodać klucz deszyfrowania 802.11 w Wireshark, otwórz _Edit → Preferences → Protocols → IEEE 802.11_ i kliknij _Edit_ obok _Decryption Keys_.<sup>[[5]](#references)</sup>

![Znajdowanie nieznanych adresów MAC w sieci Wi-Fi - Deszyfrowanie ruchu: po wykryciu nieznanych adresów MAC komunikujących się wewnątrz sieci można użyć filtrów takich jak poniższy:...](<../../../images/image (499).png>)

W przypadku WPA/WPA2 Wireshark zwykle potrzebuje czterokierunkowego handshake EAPOL oraz pasującego hasła/SSID; podanie klucza transient może wyeliminować wymaganie handshake. Deszyfrowanie WPA3 dla poszczególnych połączeń wymaga PMK danego połączenia.<sup>[[5]](#references)</sup>

## References

- [1] [Przewodnik użytkownika Wireshark: ruch WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Przewodnik użytkownika Wireshark: tworzenie wyrażeń filtrów wyświetlania](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Dokumentacja filtrów wyświetlania Wireshark: bezprzewodowa sieć LAN IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Przewodnik użytkownika Wireshark: klucze deszyfrowania sieci WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
