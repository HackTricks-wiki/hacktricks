# Analiza Wifi Pcap

## Sprawdzanie BSSID

Przy otwartym przechwyceniu Wi-Fi w Wireshark wybierz _Wireless → WLAN Traffic_, aby podsumować sieci bezprzewodowe zaobserwowane w przechwyceniu; każdy wiersz reprezentuje jedną sieć bezprzewodową.<sup>[[1]](#references)</sup>

![Analiza Wifi Pcap - Sprawdzanie BSSID: Po otrzymaniu przechwycenia, w którym główny ruch stanowi Wifi, za pomocą WireShark możesz rozpocząć badanie wszystkich SSID z przechwycenia za pomocą Wireless --...](<../../../images/image (106).png>)

![Analiza Wifi Pcap - Sprawdzanie BSSID: Po otrzymaniu przechwycenia, w którym główny ruch stanowi Wifi, za pomocą WireShark możesz rozpocząć badanie wszystkich SSID z przechwycenia za pomocą Wireless --...](<../../../images/image (492).png>)

### Brute Force

W przypadku przechwyceń WPA/WPA2-PSK `aircrack-ng` wymaga poprawnego, czterokierunkowego handshake'u EAPOL i testuje potencjalne hasła za pomocą słownika. Użyj `-w`, aby podać wordlistę, oraz `-b`, aby wskazać BSSID punktu dostępowego:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Jeśli kandydat pasuje, Aircrack-ng odzyskuje pre-shared key; pasujące hasło i SSID można następnie skonfigurować w ustawieniach deszyfrowania 802.11 w Wiresharku, gdy przechwycony ruch i tryb zabezpieczeń to obsługują.<sup>[[2]](#references)[[5]](#references)</sup>

## Dane w Beaconach / kanale bocznym

Jeśli podejrzewasz, że **dane są wyprowadzane w ruchu kanału bocznego beaconów**, zacznij od filtra wyświetlania, takiego jak `wlan contains "NAMEofNETWORK"` lub `wlan.ssid == "NAMEofNETWORK"`, a następnie sprawdź pasujące ramki pod kątem podejrzanych ciągów. Pierwsza forma wykonuje szerokie wyszukiwanie bajtów; druga dopasowuje pole SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Znajdowanie nieznanych adresów MAC w sieci Wi-Fi

Wireshark udostępnia `wlan.ta` jako adres nadawcy oraz `wlan.addr` jako adres sprzętowy/MAC; filtry wyświetlania mogą łączyć te pola za pomocą operatorów logicznych:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Jeśli znasz już **adresy MAC, usuń je z wyników**, dodając sprawdzenia takie jak `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Po wykryciu **nieznanych adresów MAC** komunikujących się wewnątrz sieci użyj filtra takiego jak `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)`, aby zawęzić analizowany ruch. Filtry FTP, HTTP, SSH i Telnet są przydatne tylko wtedy, gdy Wireshark może zdekodować odpowiedni odszyfrowany payload.<sup>[[3]](#references)[[5]](#references)</sup>

## Deszyfrowanie ruchu

Aby dodać klucz deszyfrowania 802.11 w Wiresharku, otwórz _Edit → Preferences → Protocols → IEEE 802.11_ i kliknij _Edit_ obok _Decryption Keys_.<sup>[[5]](#references)</sup>

![Znajdowanie nieznanych adresów MAC w sieci Wi-Fi - deszyfrowanie ruchu: Po wykryciu nieznanych adresów MAC komunikujących się wewnątrz sieci można użyć filtrów takich jak poniższy:...](<../../../images/image (499).png>)

W przypadku WPA/WPA2 Wireshark zwykle potrzebuje czteroelementowego handshake'u EAPOL oraz pasującego hasła/SSID; podanie transient key może pozwolić uniknąć wymogu handshake'u. Deszyfrowanie WPA3 dla poszczególnych połączeń wymaga PMK tego połączenia.<sup>[[5]](#references)</sup>

## References

- [1] [Podręcznik użytkownika Wireshark: ruch WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Podręcznik użytkownika Wireshark: tworzenie wyrażeń filtrów wyświetlania](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Dokumentacja filtrów wyświetlania Wireshark: bezprzewodowa sieć LAN IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Podręcznik użytkownika Wireshark: klucze deszyfrowania WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
