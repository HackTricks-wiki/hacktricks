# Analiza Wi-Fi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Sprawdzanie BSSID

Po otwarciu przechwyconego ruchu Wi-Fi w Wiresharku wybierz _Wireless → WLAN Traffic_, aby podsumować sieci bezprzewodowe zaobserwowane w przechwyconym ruchu; każdy wiersz reprezentuje jedną sieć bezprzewodową.<sup>[[1]](#references)</sup>

![Analiza Wi-Fi Pcap - Sprawdzanie BSSID: Gdy otrzymasz przechwycony ruch, w którym dominuje ruch Wi-Fi, możesz rozpocząć analizę wszystkich SSID z przechwyconego ruchu, wybierając w WireShark Wireless --...](<../../../images/image (106).png>)

![Analiza Wi-Fi Pcap - Sprawdzanie BSSID: Gdy otrzymasz przechwycony ruch, w którym dominuje ruch Wi-Fi, możesz rozpocząć analizę wszystkich SSID z przechwyconego ruchu, wybierając w WireShark Wireless --...](<../../../images/image (492).png>)

### Brute Force

W przypadku przechwyconego ruchu WPA/WPA2-PSK `aircrack-ng` wymaga użytecznego four-way EAPOL handshake i testuje kandydackie hasła z użyciem słownika. Użyj `-w`, aby podać wordlistę, a `-b`, aby wskazać BSSID punktu dostępowego:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Jeśli kandydat pasuje, Aircrack-ng odzyskuje klucz współdzielony; pasujące hasło i SSID można następnie skonfigurować w ustawieniach deszyfrowania 802.11 w Wiresharku, o ile pozwalają na to przechwycone dane i tryb zabezpieczeń.<sup>[[2]](#references)[[5]](#references)</sup>

## Dane w beaconach / kanał boczny

Jeśli podejrzewasz, że **dane wyciekają w ruchu kanału bocznego beaconów**, zacznij od filtra wyświetlania, takiego jak `wlan contains "NAMEofNETWORK"` lub `wlan.ssid == "NAMEofNETWORK"`, a następnie sprawdź pasujące ramki pod kątem podejrzanych ciągów znaków. Pierwsza forma wyszukuje dowolne bajty, a druga dopasowuje pole SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Znajdowanie nieznanych adresów MAC w sieci Wi-Fi

Wireshark udostępnia `wlan.ta` jako adres nadawcy, a `wlan.addr` jako adres sprzętowy/MAC; filtry wyświetlania mogą łączyć te pola za pomocą operatorów logicznych:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Jeśli znasz już **adresy MAC, usuń je z wyników**, dodając warunki takie jak `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Po wykryciu **nieznanych adresów MAC** komunikujących się wewnątrz sieci użyj filtra takiego jak `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)`, aby zawęzić wyniki do ich ruchu. Filtry FTP, HTTP, SSH i Telnet są przydatne tylko wtedy, gdy Wireshark może przeanalizować odpowiadający im odszyfrowany ładunek.<sup>[[3]](#references)[[5]](#references)</sup>

## Odszyfrowywanie ruchu

Aby dodać klucz deszyfrujący 802.11 w Wiresharku, otwórz _Edit → Preferences → Protocols → IEEE 802.11_ i kliknij _Edit_ obok _Decryption Keys_.<sup>[[5]](#references)</sup>

![Znajdowanie nieznanych adresów MAC w sieci Wi-Fi — odszyfrowywanie ruchu: Po wykryciu nieznanych adresów MAC komunikujących się wewnątrz sieci możesz użyć filtrów takich jak poniższy:...](<../../../images/image (499).png>)

W przypadku WPA/WPA2 Wireshark zwykle potrzebuje czterostronnego uzgadniania EAPOL oraz pasującego hasła/SSID; podanie klucza tymczasowego może wyeliminować wymóg uzgadniania. Deszyfrowanie WPA3 dla poszczególnych połączeń wymaga PMK danego połączenia.<sup>[[5]](#references)</sup>

Aby odszyfrować ruch TLS warstwy aplikacji po odzyskaniu ruchu Wi-Fi, zobacz [sztuczki Wiresharka](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Podręcznik użytkownika Wiresharka: ruch WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Podręcznik użytkownika Wiresharka: tworzenie wyrażeń filtrów wyświetlania](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Dokumentacja filtrów wyświetlania Wiresharka: bezprzewodowa sieć LAN IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Podręcznik użytkownika Wiresharka: klucze deszyfrujące WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
