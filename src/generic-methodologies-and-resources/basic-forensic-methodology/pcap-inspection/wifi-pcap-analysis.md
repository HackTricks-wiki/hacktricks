# Wifi Pcap Analysis

## BSSID'leri Kontrol Etme

Wireshark'ta bir Wi-Fi capture açıkken, capture'da gözlemlenen wireless network'leri özetlemek için _Wireless → WLAN Traffic_ seçeneğini belirleyin; her satır bir wireless network'ü temsil eder.<sup>[[1]](#references)</sup>

![Wifi Pcap Analysis - BSSID'leri Kontrol Etme: Ana trafiği Wifi olan bir capture'ı WireShark kullanarak aldığınızda, Wireless --... seçeneğiyle capture'daki tüm SSID'leri incelemeye başlayabilirsiniz](<../../../images/image (106).png>)

![Wifi Pcap Analysis - BSSID'leri Kontrol Etme: Ana trafiği Wifi olan bir capture'ı WireShark kullanarak aldığınızda, Wireless --... seçeneğiyle capture'daki tüm SSID'leri incelemeye başlayabilirsiniz](<../../../images/image (492).png>)

### Brute Force

WPA/WPA2-PSK capture'ları için `aircrack-ng`, kullanılabilir bir four-way EAPOL handshake gerektirir ve aday passphrase'leri bir dictionary ile test eder. Wordlist sağlamak için `-w`, access point'in BSSID'sini hedeflemek için `-b` kullanın:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Bir aday eşleşirse Aircrack-ng pre-shared key değerini kurtarır; eşleşen password ve SSID, capture ve security mode desteklediğinde Wireshark'ın 802.11 decryption settings bölümünde yapılandırılabilir.<sup>[[2]](#references)[[5]](#references)</sup>

## Beacons / Side Channel İçindeki Veriler

**data'nın beacon-side-channel traffic içinde leak edildiğinden** şüpheleniyorsanız, `wlan contains "NAMEofNETWORK"` veya `wlan.ssid == "NAMEofNETWORK"` gibi bir display filter ile başlayın ve eşleşen frame'leri şüpheli string'ler açısından inceleyin. İlk form geniş kapsamlı bir byte search yapar; ikinci form SSID field ile eşleşir.<sup>[[3]](#references)[[4]](#references)</sup>

## Bir Wi-Fi Network'ündeki Bilinmeyen MAC Addresses'leri Bulma

Wireshark, `wlan.ta` alanını transmitter address, `wlan.addr` alanını ise hardware/MAC address olarak sunar; display filter'lar bu alanları logical operator'lerle birleştirebilir:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Bilinen **MAC addresses** değerlerini zaten biliyorsanız, `&& !(wlan.addr == 5c:51:88:31:a0:3b)` gibi kontroller ekleyerek bunları output'tan çıkarın.

Network içinde iletişim kuran **unknown MAC** addresses değerlerini tespit ettikten sonra, traffic'ini daraltmak için `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` gibi bir filter kullanın. FTP, HTTP, SSH ve Telnet filter'ları yalnızca Wireshark ilgili decrypted payload'ı dissect edebildiğinde kullanışlıdır.<sup>[[3]](#references)[[5]](#references)</sup>

## Traffic'i Decrypt Etme

Wireshark'a bir 802.11 decryption key eklemek için _Edit → Preferences → Protocols → IEEE 802.11_ yolunu açın ve _Decryption Keys_ yanında bulunan _Edit_ seçeneğine tıklayın.<sup>[[5]](#references)</sup>

![Bir Wi-Fi Network'ündeki Bilinmeyen MAC Addresses'leri Bulma - Traffic'i Decrypt Etme: Network içinde iletişim kuran bilinmeyen MAC addresses değerlerini tespit ettikten sonra aşağıdaki gibi filter'lar kullanabilirsiniz:...](<../../../images/image (499).png>)

WPA/WPA2 için Wireshark normalde EAPOL four-way handshake ile eşleşen password/SSID değerlerine ihtiyaç duyar; transient key sağlamak handshake gereksinimini ortadan kaldırabilir. WPA3 için connection başına decryption işlemi connection'ın PMK değerini gerektirir.<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Display Filter Expressions Oluşturma](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
