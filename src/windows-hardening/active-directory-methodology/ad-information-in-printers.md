# Yazıcılardaki Bilgiler

{{#include ../../banners/hacktricks-training.md}}

Kaydedilmiş LDAP kimlik bilgilerine sahip bir yazıcı, sunucu ayarı değiştirilip yazıcı sahte bir uç noktaya kimlik doğrulaması yaptığında bu bilgileri açığa çıkarabilir.<sup>[[2]](#references)</sup> Sonuç, bind yöntemine bağlıdır: korumasız bir simple bind parolayı açığa çıkarırken SASL challenge-response bind parolayı düz metin olarak açığa çıkarmaz.<sup>[[8]](#references)</sup> Bkz. [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Ayrıca, bazı yazıcılar **kullanıcı adlarını içeren loglar** tutar veya Domain Controller'dan **tüm kullanıcı adlarını indirme** olanağı sunabilir.

Tüm bu **hassas bilgiler** ve yaygın **güvenlik eksikliği**, yazıcıları saldırganlar için oldukça ilgi çekici hâle getirir.

Konuyla ilgili bazı başlangıç blogları:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Yazıcı Yapılandırması

- **Konum**: LDAP sunucu listesi genellikle web arayüzünde bulunur (örn. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Davranış**: Birçok gömülü web sunucusu, LDAP sunucusu değişikliklerine **kimlik bilgilerini yeniden girmeden** izin verir (kullanılabilirlik özelliği → güvenlik riski).
- **İstismar**: LDAP sunucu adresini saldırganın kontrolündeki bir host'a yönlendirin ve yazıcının size bind yapmasını sağlamak için *Test Connection* / *Address Book Sync* düğmesini kullanın.

---

## Kimlik Bilgilerini Yakalama

### Yöntem 1 – Netcat Dinleyicisi

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Basit bir BindRequest, sunucu daha sonra oturum açma girişimini reddetse bile BER akışında bind DN'yi ve parolayı açığa çıkarabilir. Tek başına anonim bir arama veya SASL müzakeresi kayıtlı parolayı açığa çıkarmaz.<sup>[[8]](#references)</sup>

636/3269 portunda çalışan sıradan bir `nc` dinleyicisi LDAP bind işlemini değil, TLS el sıkışmasını görür. LDAPS, TLS destekli bir uç nokta gerektirir. Yazıcı değiştirilmiş bir hostname'i kabul ediyor ve yeni uç noktanın bu hostname için geçerli bir sertifikası varsa, yalnızca sertifika doğrulaması pass-back'i önlemez; istemci, kayıtlı kimlik bilgisini hangi sunucunun almaya yetkili olduğunu da kısıtlamalıdır.<sup>[[8]](#references)</sup>

### Method 2 – Tam Rogue LDAP server (önerilen)

Yazıcı, bind girişiminde bulunmadan önce geçerli bir LDAP yanıtı gerektirebilir.<sup>[[10]](#references)</sup> Tam bir LDAP sunucusu bu ön görüşmeyi gerçekleştirebilir; ancak güçlü bir SASL mekanizmasına veya amaçlanan TLS sunucusuna sabitlenmiş bir istemciye parolasını açığa vurduramaz.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Bir lookup işlemini bağlantı kanıtı olarak değerlendirin, parola ifşasının kanıtı olarak değil. Parola yalnızca istemci, parola içeren bir bind işlemini düz metin olarak gönderirse açığa çıkar; gerçek bind mekanizmasını ve TLS durumunu kontrol edin.<sup>[[8]](#references)</sup>

> 💡  Responder, rogue LDAP ve SMB kimlik doğrulama hizmetleri içerir. Basit bir LDAP bind işlemi yapılandırılmış parolayı açığa çıkarabilirken NTLM kimlik doğrulaması challenge-response verisi üretir; her iki sonucu da düz metin parola olarak tanımlamayın.

### SASL mekanizması seçimi

Bazı yazıcı LDAP istemcileri, LDAP sunucusunun duyurduğu mekanizmalar arasından seçim yapar.<sup>[[8]](#references)[[10]](#references)</sup> Araştırmalar, duyurulan bir düz metin SASL mekanizmasını kabul etmeye istekli bir istemcinin, normal NTLM anlaşmasının yalnızca challenge-response verisi üreteceği durumda parola gönderebildiğini gösterdi.<sup>[[9]](#references)[[10]](#references)</sup> Bu, tüm SASL bind işlemlerinin bir özelliği değil, **istemci ilkesi hatasıdır**: daha güçlü bir mekanizma gerektiren veya hedeflenen TLS sunucusunu sabitleyen bir istemci bunun yerine güvenli biçimde başarısız olmalıdır.<sup>[[8]](#references)</sup> OpenLDAP, düz metin desteği olan SASL mekanizmalarını varsayılan olarak devre dışı bırakır; dolayısıyla standart bir arka plan programı, bu davranışın bir yazıcıda bulunduğunu kanıtlamaz.<sup>[[11]](#references)</sup>

---

## Yakın Tarihli Pass-Back Güvenlik Açıkları (2024-2025)

Pass-back teorik bir sorun *değildir* – satıcılar 2024/2025'te bu saldırı sınıfını tam olarak açıklayan güvenlik duyuruları yayımlamaya devam ediyor.

### Xerox VersaLink – CVE-2024-12510 ve CVE-2024-12511

Xerox VersaLink C70xx MFP'lerin ≤ 57.69.91 ürün yazılımı, kimliği doğrulanmış bir yöneticinin (veya varsayılan kimlik bilgileri değiştirilmemişse herhangi birinin) şunları yapmasına izin veriyordu:

* **CVE-2024-12510 – LDAP pass-back**: LDAP sunucu adresini değiştirmek ve bir lookup işlemi başlatmak; böylece cihazın yapılandırılmış Windows kimlik bilgilerini saldırganın kontrolündeki ana makineye leak etmesine neden olmak.
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* hedefleri üzerinden aynı sorun; NetNTLMv2 veya FTP düz metin kimlik bilgilerinin leak edilmesine yol açar.<sup>[[2]](#references)</sup>

Şu gibi basit bir dinleyici:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

veya sahte bir SMB sunucusu (`impacket-smbserver`) kimlik bilgilerini ele geçirmek için yeterlidir.  

### Canon imageRUNNER / imageCLASS – 20 Mayıs 2025 tarihli güvenlik duyurusu

Canon, onlarca Laser ve MFP ürün serisinde **SMTP/LDAP pass-back** zafiyetini doğruladı. Yönetici erişimine sahip bir saldırgan sunucu yapılandırmasını değiştirebilir ve LDAP **veya** SMTP için kayıtlı kimlik bilgilerini ele geçirebilir (birçok kuruluş tarama-e-posta entegrasyonu için ayrıcalıklı bir hesap kullanır).<sup>[[3]](#references)</sup>

Üreticinin yönergeleri açıkça şunları öneriyor:

1. Kullanıma sunulur sunulmaz yamalı firmware'e güncelleme yapmak.
2. Güçlü ve benzersiz yönetici parolaları kullanmak.
3. Yazıcı entegrasyonu için ayrıcalıklı AD hesapları kullanmaktan kaçınmak.

---

### Brother cihazları ve OEM varyantları – seri numarasından türetilen yönetici erişimi, hizmet kimlik bilgilerini açığa çıkarıyor

2025'te yapılan koordineli bir açıklama, etkilenen Brother cihazlarında özellikle yararlı bir saldırı zincirini ortaya koydu; zafiyet kümesinin bazı bölümleri OEM modellerini de etkilediğinden, tam modeli üreticinin güvenlik duyurusundan doğrulayın. Kimliği doğrulanmamış bir saldırgan, güvenlik açığı bulunan firmware'de HTTP/HTTPS/IPP üzerinden cihazın seri numarasını edinebilir; seri numaraları SNMP veya PJL gibi yönetim protokolleri üzerinden de erişilebilir olabilir. Fabrika parolası hiç değiştirilmediyse, seri numarası yönetici parolasını belirli biçimde oluşturur. Kimlik doğrulamasının ardından ayrı pass-back zafiyeti CVE-2024-51984, LDAP veya FTP gibi harici hizmetler için yapılandırılmış parolaları düz metin olarak açığa çıkararak yazıcı yönetim erişimini yeniden kullanılabilir ağ kimlik bilgilerine dönüştürür. Firmware güncellemeleri hizmet parolalarının açığa çıkmasını önler; ancak daha önce üretilmiş cihazlarda operatörün seri numarasından türetilen başlangıç yönetici parolasını değiştirmesi gerekir.<sup>[[6]](#references)</sup>

Güncel Metasploit, seri numarasını HTTP, SNMP veya PJL üzerinden bulan, başlangıç parolası adayını oluşturan ve isteğe bağlı olarak bunu web konsolunda doğrulayan bir auxiliary modül içerir. `DiscoverSerialVia=AUTO`, desteklenen bulma yöntemlerini dener; varlık envanterinde seri numarası zaten bulunuyorsa bunun yerine `TargetSerial` değerini sağlayın.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Sonucu yalnızca yetkili varlıkları doğrulamak için kullanın. Parolanın çalışıp çalışmayacağı tam modele ve özellikle fabrika yöneticisi parolasının daha önce değiştirilip değiştirilmediğine bağlıdır.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Otomatik Sayımlama / Exploitation Araçları

| Araç | Amaç | Örnek |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL kötüye kullanımı, dosya sistemi erişimi, varsayılan kimlik bilgilerini kontrol etme, *SNMP keşfi*; bkz. [PJL değerlendirmesi](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS üzerinden yapılandırmayı (adres defterleri ve LDAP kimlik bilgileri dahil) toplama | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Sahte kimlik doğrulama hizmetleri çalıştırma ve SMB callback'leri üzerinden NetNTLM yakalama/aktarma | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Bir seri numarası keşfetme, aday fabrika yöneticisi parolasını türetme ve web konsolu erişimini doğrulama | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Güçlendirme ve Tespit

1. **Yama uygulayın / firmware'i güncelleyin** – MFP'leri zamanında güncelleyin (üreticinin PSIRT bültenlerini kontrol edin).
2. **Fabrika yöneticisi parolalarını değiştirin** – yalnızca firmware güncellemesi, daha önce üretilmiş ve etkilenen Brother/OEM cihazlardaki seri numarasından türetilen başlangıç parolalarını kaldırmaz.<sup>[[6]](#references)</sup>
3. **En Az Ayrıcalıklı Hizmet Hesapları** – LDAP/SMB/SMTP için asla Domain Admin kullanmayın; OU kapsamlarını *salt okunur* olacak şekilde kısıtlayın.
4. **Yönetim Erişimini Kısıtlayın** – yazıcı web/IPP/SNMP arayüzlerini bir yönetim VLAN'ına veya ACL/VPN arkasına yerleştirin.
5. **Yazıcının giden trafiğini kısıtlayın** – her cihazın yalnızca beklenen DC/LDAP, mail, DNS/NTP, print ve tarama dosyası hedefleriyle iletişim kurmasına izin verin. Pass-back için saldırganın seçtiği bir uç noktaya callback gerekir.
6. **Kullanılmayan Protokolleri Devre Dışı Bırakın** – FTP, Telnet, raw-9100 ve eski SSL şifreleri.
7. **Denetim Günlüğünü Etkinleştirin** – bazı cihazlar LDAP/SMTP hatalarını syslog'a gönderebilir; beklenmeyen bind işlemlerini ilişkilendirin.
8. **Kimlik doğrulama hedeflerini izleyin** – özellikle yönetim oturum açma veya yapılandırma değişikliğinin hemen ardından bir yazıcı izin verilenler listesinin dışındaki bir ana bilgisayara LDAP, SMB, SMTP veya FTP bağlantısı başlattığında uyarı verin.
9. **SNMPv3 kullanın veya SNMP'yi devre dışı bırakın** – `public` community değeri genellikle cihaz ve seri numarası bilgilerini sızdırır.

---



---



## References

- [1] [Sadece bir yazıcı… Olabilecek en kötü şey ne?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Çok İşlevli Yazıcı: Pass-Back Saldırısı Güvenlik Açıkları (Düzeltildi)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Üretim Yazıcıları, Ofis/Küçük Ofis Çok İşlevli Yazıcıları ve Lazer Yazıcılar için Güvenlik Açığı Azaltma/Giderme](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat ile Yazıcı Üzerinden Domain Kimlik Bilgilerini Elde Etme](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Bir Penetration Testi Sırasında Çok İşlevli Yazıcıları Exploit Etme](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Birden Fazla Brother Cihazı: Birden Fazla Güvenlik Açığı (DÜZELTİLDİ)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother varsayılan yönetici kimlik doğrulamasını atlama modülü](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – LDAP kimlik doğrulama yöntemleri ve güvenlik mekanizmaları](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [LDAP passback Docker sunucusu](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [LDAP pass back saldırısı – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – SASL güvenlik özellikleri](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
