# Wifi Pcap Analizi

{{#include ../../../banners/hacktricks-training.md}}

## BSSID'leri Kontrol Etme

Wi-Fi yakalamasını Wireshark'ta açtıktan sonra, yakalamada gözlemlenen kablosuz ağları özetlemek için _Wireless → WLAN Traffic_ öğesini seçin; her satır bir kablosuz ağı temsil eder.<sup>[[1]](#references)</sup>

![Wifi Pcap Analizi - BSSID'leri Kontrol Etme: Ana trafiği WiFi olan bir yakalamayı WireShark ile aldığınızda, Wireless --... seçeneğiyle yakalamadaki tüm SSID'leri incelemeye başlayabilirsiniz](<../../../images/image (106).png>)

![Wifi Pcap Analizi - BSSID'leri Kontrol Etme: Ana trafiği WiFi olan bir yakalamayı WireShark ile aldığınızda, Wireless --... seçeneğiyle yakalamadaki tüm SSID'leri incelemeye başlayabilirsiniz](<../../../images/image (492).png>)

### Brute Force

WPA/WPA2-PSK yakalamalarında `aircrack-ng`, kullanılabilir bir dört yönlü EAPOL handshake gerektirir ve bir sözlük kullanarak aday parolaları dener. Wordlist'i belirtmek için `-w`, erişim noktasının BSSID'sini hedeflemek için `-b` kullanın:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Bir aday eşleşirse Aircrack-ng, önceden paylaşılan anahtarı kurtarır; eşleşen parola ve SSID, yakalama ve güvenlik modu destekliyorsa Wireshark'ın 802.11 şifre çözme ayarlarında yapılandırılabilir.<sup>[[2]](#references)[[5]](#references)</sup>

## Beacon'larda Veri / Yan Kanal

**Beacon yan kanal trafiğinde veri sızdırıldığından şüpheleniyorsanız**, `wlan contains "NAMEofNETWORK"` veya `wlan.ssid == "NAMEofNETWORK"` gibi bir görüntüleme filtresiyle başlayın, ardından eşleşen çerçeveleri şüpheli dizeler açısından inceleyin. İlk biçim geniş kapsamlı bir bayt aramasıdır; ikincisi SSID alanıyla eşleşir.<sup>[[3]](#references)[[4]](#references)</sup>

## Wi-Fi Ağında Bilinmeyen MAC Adreslerini Bulma

Wireshark, `wlan.ta` alanını verici adresi, `wlan.addr` alanını ise donanım/MAC adresi olarak sunar; görüntüleme filtreleri bu alanları mantıksal işleçlerle birleştirebilir:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

**MAC adreslerini zaten biliyorsanız**, `&& !(wlan.addr == 5c:51:88:31:a0:3b)` gibi kontroller ekleyerek bunları çıktından kaldırın.

Ağ içinde iletişim kuran **bilinmeyen MAC** adreslerini tespit ettikten sonra, trafiğini daraltmak için `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` gibi bir filtre kullanın. FTP, HTTP, SSH ve Telnet filtreleri yalnızca Wireshark ilgili şifresi çözülmüş yükü ayrıştırabildiğinde işe yarar.<sup>[[3]](#references)[[5]](#references)</sup>

## Trafiğin Şifresini Çözme

Wireshark'a bir 802.11 şifre çözme anahtarı eklemek için _Edit → Preferences → Protocols → IEEE 802.11_ yolunu izleyin ve _Decryption Keys_ yanındaki _Edit_ düğmesine tıklayın.<sup>[[5]](#references)</sup>

![Bir Wi-Fi Ağında Bilinmeyen MAC Adreslerini Bulma - Trafiğin Şifresini Çözme: Ağ içinde iletişim kuran bilinmeyen MAC adreslerini tespit ettikten sonra aşağıdaki gibi filtreler kullanabilirsiniz:...](<../../../images/image (499).png>)

WPA/WPA2 için Wireshark'ın genellikle EAPOL dört yönlü el sıkışmasına ve eşleşen parola/SSID'ye ihtiyacı vardır; geçici anahtarı sağlamak el sıkışma gereksinimini ortadan kaldırabilir. WPA3'te bağlantı başına şifre çözme için bağlantının PMK'si gerekir.<sup>[[5]](#references)</sup>

Wi-Fi trafiğini kurtardıktan sonra uygulama katmanındaki TLS şifre çözme hakkında bilgi için [Wireshark tricks](wireshark-tricks.md#decrypting-tls) sayfasına bakın.

## References

- [1] [Wireshark Kullanım Kılavuzu: WLAN Trafiği](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark Kullanım Kılavuzu: Görüntüleme Filtresi İfadeleri Oluşturma](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Görüntüleme Filtresi Başvurusu: IEEE 802.11 kablosuz LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark Kullanım Kılavuzu: IEEE 802.11 WLAN Şifre Çözme Anahtarları](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
