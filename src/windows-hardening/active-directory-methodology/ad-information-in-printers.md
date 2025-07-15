# Yazıcılarındaki Bilgiler

{{#include ../../banners/hacktricks-training.md}}

İnternette, **varsayılan/zayıf** oturum açma kimlik bilgileriyle yapılandırılmış yazıcıların tehlikelerini **vurgulayan** birkaç blog bulunmaktadır.  \
Bunun nedeni, bir saldırganın yazıcıyı **sahte bir LDAP sunucusuna kimlik doğrulaması yapmaya kandırabilmesidir** (genellikle bir `nc -vv -l -p 389` veya `slapd -d 2` yeterlidir) ve yazıcının **kimlik bilgilerini düz metin olarak** yakalayabilmesidir.

Ayrıca, birçok yazıcı **kullanıcı adlarıyla günlükler** içerecek veya hatta **Tüm kullanıcı adlarını** Alan Denetleyicisinden indirebilecek yeteneğe sahip olabilir.

Tüm bu **hassas bilgiler** ve yaygın **güvenlik eksiklikleri**, yazıcıları saldırganlar için çok ilginç hale getiriyor.

Konu hakkında bazı tanıtıcı bloglar:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## Yazıcı Yapılandırması

- **Konum**: LDAP sunucu listesi genellikle web arayüzünde bulunur (örneğin, *Ağ ➜ LDAP Ayarı ➜ LDAP Kurulumu*).
- **Davranış**: Birçok gömülü web sunucusu, kimlik bilgilerini yeniden girmeden LDAP sunucu değişikliklerine **izin verir** (kullanılabilirlik özelliği → güvenlik riski).
- **Sömürü**: LDAP sunucu adresini saldırganın kontrolündeki bir ana bilgisayara yönlendirin ve yazıcının size bağlanmasını sağlamak için *Bağlantıyı Test Et* / *Adres Defteri Senkronizasyonu* düğmesini kullanın.

---
## Kimlik Bilgilerini Yakalama

### Yöntem 1 – Netcat Dinleyici
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Küçük/eski MFP'ler, netcat'in yakalayabileceği basit bir *simple-bind* gönderebilir. Modern cihazlar genellikle önce anonim bir sorgu yapar ve ardından bind denemesi yapar, bu nedenle sonuçlar değişkenlik gösterir.

### Yöntem 2 – Tam Rogue LDAP sunucusu (önerilir)

Birçok cihaz, kimlik doğrulamadan *önce* anonim bir arama yapacağından, gerçek bir LDAP daemon'u kurmak çok daha güvenilir sonuçlar verir:
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Yazıcı arama işlemini gerçekleştirdiğinde, hata ayıklama çıktısında açık metin kimlik bilgilerini göreceksiniz.

> 💡  Ayrıca `impacket/examples/ldapd.py` (Python rogue LDAP) veya `Responder -w -r -f` kullanarak LDAP/SMB üzerinden NTLMv2 hash'lerini toplayabilirsiniz.

---
## Son Geçiş Geri Dönüş Açıkları (2024-2025)

Geçiş geri dönüşü *teorik* bir sorun değildir – satıcılar 2024/2025'te bu saldırı sınıfını tam olarak tanımlayan bildirimler yayınlamaya devam ediyor.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFP'lerin 57.69.91 veya daha düşük yazılımı, kimlik doğrulaması yapılmış bir yöneticinin (veya varsayılan kimlik bilgileri kaldığında herhangi birinin) şunları yapmasına izin verdi:

* **CVE-2024-12510 – LDAP geçiş geri dönüşü**: LDAP sunucu adresini değiştirmek ve bir arama tetiklemek, cihazın yapılandırılmış Windows kimlik bilgilerini saldırgan kontrolündeki ana bilgisayara sızdırmasına neden olur.
* **CVE-2024-12511 – SMB/FTP geçiş geri dönüşü**: *scan-to-folder* hedefleri aracılığıyla benzer bir sorun, NetNTLMv2 veya FTP açık metin kimlik bilgilerini sızdırır.

Basit bir dinleyici şöyle olabilir:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
or bir siber SMB sunucusu (`impacket-smbserver`) kimlik bilgilerini toplamak için yeterlidir.

### Canon imageRUNNER / imageCLASS – Tavsiye 20 Mayıs 2025

Canon, birçok Laser & MFP ürün serisinde bir **SMTP/LDAP geri dönüş** zayıflığını doğruladı. Yönetici erişimine sahip bir saldırgan, sunucu yapılandırmasını değiştirebilir ve LDAP **veya** SMTP için saklanan kimlik bilgilerini alabilir (birçok kuruluş, tarama için e-posta gönderimini sağlamak amacıyla ayrıcalıklı bir hesap kullanır).

Satıcı kılavuzu açıkça şunları önermektedir:

1. Mevcut olduğunda yamanmış firmware'e güncelleme yapın.
2. Güçlü, benzersiz yönetici şifreleri kullanın.
3. Yazıcı entegrasyonu için ayrıcalıklı AD hesaplarından kaçının.

---
## Otomatik Sayım / Sömürü Araçları

| Araç | Amaç | Örnek |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL kötüye kullanımı, dosya sistemi erişimi, varsayılan kimlik bilgileri kontrolü, *SNMP keşfi* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS üzerinden yapılandırma (adres defterleri & LDAP kimlik bilgileri dahil) toplama | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | SMB/FTP geri dönüşünden NetNTLM hash'lerini yakalama & iletme | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Düz metin bağlamalarını almak için hafif bir sahte LDAP hizmeti | `python ldapd.py -debug` |

---
## Güçlendirme & Tespit

1. **Yamanız / firmware güncellemesi** MFP'leri zamanında yapın (satıcı PSIRT bültenlerini kontrol edin).
2. **En Az Ayrıcalık Hizmet Hesapları** – LDAP/SMB/SMTP için asla Domain Admin kullanmayın; *salt okunur* OU kapsamları ile sınırlayın.
3. **Yönetim Erişimini Kısıtlayın** – yazıcı web/IPP/SNMP arayüzlerini bir yönetim VLAN'ında veya bir ACL/VPN arkasında yerleştirin.
4. **Kullanılmayan Protokolleri Devre Dışı Bırakın** – FTP, Telnet, raw-9100, eski SSL şifreleri.
5. **Denetim Günlüğü Oluşturmayı Etkinleştirin** – bazı cihazlar LDAP/SMTP hatalarını syslog yapabilir; beklenmedik bağlamaları ilişkilendirin.
6. **Alışılmadık Kaynaklarda Düz Metin LDAP bağlamalarını İzleyin** (yazıcılar normalde yalnızca DC'lerle iletişim kurmalıdır).
7. **SNMPv3 veya SNMP'yi devre dışı bırakın** – topluluk `public` genellikle cihaz & LDAP yapılandırmasını sızdırır.

---
## Referanslar

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Xerox VersaLink C7025 MFP Geri Dönüş Saldırı Zayıflıkları.” Şubat 2025.
- Canon PSIRT. “Laser Yazıcılar ve Küçük Ofis Çok Fonksiyonlu Yazıcılar için SMTP/LDAP Geri Dönüşüne Karşı Zayıflık Azaltma.” Mayıs 2025.

{{#include ../../banners/hacktricks-training.md}}
