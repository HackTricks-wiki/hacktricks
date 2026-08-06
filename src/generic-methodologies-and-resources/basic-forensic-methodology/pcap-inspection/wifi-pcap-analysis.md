# WiFi Pcap Analizi

{{#include ../../../banners/hacktricks-training.md}}

## BSSID'leri Kontrol Etme

Ana trafiği WiFi olan bir capture'ı WireShark kullanarak aldığınızda, _Wireless --> WLAN Traffic_ ile capture içindeki tüm SSID'leri incelemeye başlayabilirsiniz:

![WiFi Pcap Analizi - BSSID'leri Kontrol Etme: Ana trafiği WiFi olan bir capture'ı WireShark kullanarak aldığınızda, Wireless --...](<../../../images/image (106).png>)

![WiFi Pcap Analizi - BSSID'leri Kontrol Etme: Ana trafiği WiFi olan bir capture'ı WireShark kullanarak aldığınızda, Wireless --...](<../../../images/image (492).png>)

### Brute Force

Bu ekrandaki sütunlardan biri, **pcap içinde herhangi bir authentication bulunup bulunmadığını** gösterir. Durum buysa `aircrack-ng` kullanarak Brute force deneyebilirsiniz:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Örneğin, daha sonra trafiği çözmek için gerekecek olan bir PSK'yi (önceden paylaşılmış anahtar) koruyan WPA passphrase'ini alır.

## Beacons / Side Channel İçindeki Veriler

**Bir Wifi network'ünün beacon'ları içinde data leak edildiğinden şüpheleniyorsanız**, aşağıdaki gibi bir filter kullanarak network'ün beacon'larını kontrol edebilirsiniz: `wlan contains <NAMEofNETWORK>` veya `wlan.ssid == "NAMEofNETWORK"`; filtrelenmiş paketler içinde şüpheli string'leri arayın.

## Bir Wifi Network'ündeki Bilinmeyen MAC Address'leri Bulma

Aşağıdaki link, **bir Wifi Network'ü içinde data gönderen makineleri** bulmak için kullanışlı olacaktır:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Bilinen **MAC address'leriniz varsa**, şu tür kontroller ekleyerek bunları output'tan çıkarabilirsiniz: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Network içinde iletişim kuran **bilinmeyen MAC** address'leri tespit ettikten sonra, trafiğini filtrelemek için şu tür **filter**'ları kullanabilirsiniz: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`. ftp/http/ssh/telnet filter'larının, trafiğin şifresini çözmüşseniz kullanışlı olduğunu unutmayın.

## Trafiğin Şifresini Çözme

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Bir Wifi Network'ündeki Bilinmeyen MAC Address'leri Bulma - Trafiğin Şifresini Çözme: Network içinde iletişim kuran bilinmeyen MAC address'leri tespit ettikten sonra, şu tür filter'ları kullanabilirsiniz:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
