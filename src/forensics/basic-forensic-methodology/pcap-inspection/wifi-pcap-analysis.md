{{#include ../../../banners/hacktricks-training.md}}

# BSSID'leri Kontrol Et

WireShark kullanarak ana trafiği Wifi olan bir yakalama aldığınızda, _Wireless --> WLAN Traffic_ ile yakalamadaki tüm SSID'leri araştırmaya başlayabilirsiniz:

![](<../../../images/image (424).png>)

![](<../../../images/image (425).png>)

## Kaba Kuvvet

O ekranın sütunlarından biri **pcap içinde herhangi bir kimlik doğrulama bulunup bulunmadığını** gösterir. Eğer durum böyleyse, `aircrack-ng` kullanarak kaba kuvvet denemesi yapabilirsiniz:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Örneğin, daha sonra trafiği şifrelemek için gerekli olan bir PSK (önceden paylaşılan anahtar) koruyan WPA parolasını alacaktır.

# Beacon'larda / Yan Kanalda Veri

Eğer **bir Wifi ağının beacon'larında verinin sızdırıldığını düşünüyorsanız**, ağın beacon'larını aşağıdaki gibi bir filtre kullanarak kontrol edebilirsiniz: `wlan contains <NAMEofNETWORK>`, veya `wlan.ssid == "NAMEofNETWORK"` filtrelenmiş paketler içinde şüpheli dizeleri arayın.

# Bir Wifi Ağında Bilinmeyen MAC Adreslerini Bulma

Aşağıdaki bağlantı, **bir Wifi Ağı içinde veri gönderen makineleri bulmak için** faydalı olacaktır:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Eğer **MAC adreslerini zaten biliyorsanız, bunları çıktılardan çıkarabilirsiniz** bu gibi kontroller ekleyerek: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Ağ içinde iletişim kuran **bilinmeyen MAC** adreslerini tespit ettikten sonra, trafiğini filtrelemek için **filtreler** kullanabilirsiniz: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`. ftp/http/ssh/telnet filtrelerinin, trafiği şifrelediyseniz faydalı olduğunu unutmayın.

# Trafiği Şifre Çözme

Düzenle --> Tercihler --> Protokoller --> IEEE 802.11--> Düzenle

![](<../../../images/image (426).png>)

{{#include ../../../banners/hacktricks-training.md}}
