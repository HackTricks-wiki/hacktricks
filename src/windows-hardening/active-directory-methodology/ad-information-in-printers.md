# Yazıcılardaki Bilgiler

{{#include ../../banners/hacktricks-training.md}}

İnternette, varsayılan/zayıf oturum açma kimlik bilgileriyle LDAP kullanacak şekilde yapılandırılmış yazıcıları açık bırakmanın tehlikelerine **dikkat çeken** çeşitli bloglar var.  \
Bunun nedeni, bir saldırganın **yazıcıyı sahte bir LDAP sunucusuna karşı kimlik doğrulaması yapmaya kandırabilmesi** (genellikle `nc -vv -l -p 389` veya `slapd -d 2` yeterlidir) ve yazıcının **kimlik bilgilerini düz metin olarak** ele geçirebilmesidir.

Ayrıca, bazı yazıcılar **kullanıcı adlarını içeren günlükler** barındırır veya hatta Domain Controller'dan **tüm kullanıcı adlarını indirebilir**.

Tüm bu **hassas bilgiler** ve yaygın **güvenlik eksikliği**, yazıcıları saldırganlar için oldukça ilgi çekici hâle getirir.

Konuyla ilgili bazı giriş niteliğinde bloglar:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Yazıcı Yapılandırması

- **Konum**: LDAP sunucu listesi genellikle web arayüzünde bulunur (ör. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Davranış**: Birçok gömülü web sunucusu, kimlik bilgilerini **yeniden girmeden** LDAP sunucusunun değiştirilmesine izin verir (kullanılabilirlik özelliği → güvenlik riski).
- **İstismar**: LDAP sunucusu adresini saldırganın kontrolündeki bir ana bilgisayara yönlendirin ve yazıcıyı size bağlanmaya zorlamak için *Test Connection* / *Address Book Sync* düğmesine basın.

---

## Kimlik Bilgilerini Yakalama

### Yöntem 1 – Netcat Dinleyicisi

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Küçük/eski MFP'ler, bind DN'si ve parolası ham BER akışında görünür olan basit bir *simple-bind* gönderebilir. Modern cihazlar genellikle önce anonim bir sorgu yapıp ardından bind işlemini dener; bu nedenle sonuçlar değişebilir.<sup>[[1]](#references)</sup>

636/3269 portunda çalışan basit bir `nc` dinleyicisi yalnızca TLS şifreli verisini alır; LDAPS'yi test etmek için TLS destekli bir LDAP uç noktası gerekir ve cihaz sunucu sertifikasını doğru şekilde doğruluyorsa yönlendirme başarısız olmalıdır.

### Yöntem 2 – Tam Rogue LDAP server (önerilen)

Birçok cihaz kimlik doğrulamasından *önce* anonim bir arama yapacağından, gerçek bir LDAP daemon'u çalıştırmak çok daha güvenilir sonuçlar sağlar:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Yazıcı lookup işlemini gerçekleştirdiğinde debug çıktısında clear-text kimlik bilgilerini görürsünüz.

> 💡  Responder, rogue LDAP ve SMB kimlik doğrulama hizmetleri içerir. Basit bir LDAP bind işlemi yapılandırılmış parolayı açığa çıkarabilir; NTLM kimlik doğrulaması ise challenge-response verisi üretir. Bu iki sonucu da clear-text parola olarak tanımlamayın.

---

## Yakın Zamandaki Pass-Back Güvenlik Açıkları (2024-2025)

Pass-back teorik bir sorun *değildir* – satıcılar 2024/2025'te bu saldırı sınıfını tam olarak açıklayan güvenlik duyuruları yayımlamaya devam ediyor.

### Xerox VersaLink – CVE-2024-12510 ve CVE-2024-12511

Xerox VersaLink C70xx MFP'lerin ≤ 57.69.91 ürün yazılımı sürümleri, kimliği doğrulanmış bir yöneticinin (veya varsayılan kimlik bilgileri değiştirilmemişse herhangi birinin) şunları yapmasına olanak tanıyordu:

* **CVE-2024-12510 – LDAP pass-back**: LDAP sunucusu adresini değiştirmek ve bir lookup işlemi başlatmak; bunun sonucunda cihaz, yapılandırılmış Windows kimlik bilgilerini saldırganın kontrolündeki ana bilgisayara leak eder.
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* hedefleri üzerinden aynı sorun; NetNTLMv2 veya FTP clear-text kimlik bilgileri leak edilir.<sup>[[2]](#references)</sup>

Şu tür basit bir listener:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

veya kötü amaçlı bir SMB sunucusu (`impacket-smbserver`) kimlik bilgilerini toplamak için yeterlidir.  

### Canon imageRUNNER / imageCLASS – 20 Mayıs 2025 tarihli güvenlik duyurusu

Canon, düzinelerce Laser ve MFP ürün serisinde **SMTP/LDAP pass-back** güvenlik açığı bulunduğunu doğruladı. Yönetici erişimine sahip bir saldırgan sunucu yapılandırmasını değiştirebilir ve LDAP **veya** SMTP için kayıtlı kimlik bilgilerini alabilir (birçok kurum, tarama-e-posta entegrasyonu için ayrıcalıklı bir hesap kullanır).<sup>[[3]](#references)</sup>

Üreticinin yönergeleri açıkça şunları öneriyor:

1. Yama içeren firmware’i kullanıma sunulur sunulmaz yüklemek.
2. Güçlü ve benzersiz yönetici parolaları kullanmak.
3. Yazıcı entegrasyonu için ayrıcalıklı AD hesapları kullanmaktan kaçınmak.

---

### Brother cihazları ve OEM varyantları – seri numarasından türetilen yönetici erişimiyle servis kimlik bilgilerine ulaşma

2025’te yapılan koordineli bir açıklama, etkilenen Brother cihazlarında özellikle işe yarar bir saldırı zincirini ortaya koydu. Güvenlik açıkları kümesinin bazı kısımları OEM modellerini de etkiliyor; bu nedenle tam modelin üretici güvenlik duyurusunda yer aldığını doğrulayın. Kimliği doğrulanmamış bir saldırgan, güvenlik açığı bulunan firmware’de HTTP/HTTPS/IPP üzerinden cihazın seri numarasını elde edebilir. Seri numaraları SNMP veya PJL gibi yönetim protokolleri üzerinden de alınabilir. Fabrika parolası hiç değiştirilmediyse seri numarası, yönetici parolasını belirleyici şekilde verir. Kimlik doğrulamasının ardından ayrı pass-back güvenlik açığı CVE-2024-51984, LDAP veya FTP gibi harici servisler için yapılandırılmış parolaları düz metin olarak açığa çıkarır ve yazıcı yönetimi erişimini ağda yeniden kullanılabilir kimlik bilgilerine dönüştürür. Firmware güncellemesi servis parolalarının açığa çıkması sorununu giderir, ancak daha önce üretilmiş cihazlarda operatörün seri numarasından türetilen ilk yönetici parolasını değiştirmesi gerekir.<sup>[[6]](#references)</sup>

Güncel Metasploit sürümünde, seri numarasını HTTP, SNMP veya PJL üzerinden keşfeden, olası ilk parolayı oluşturan ve isteğe bağlı olarak web konsolunda doğrulayan bir auxiliary modül bulunur. `DiscoverSerialVia=AUTO` desteklenen keşif yollarını dener; varlık envanterinde seri numarası zaten varsa bunun yerine `TargetSerial` belirtin.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Sonucu yalnızca yetkili varlıkları doğrulamak için kullanın. Parolanın çalışıp çalışmayacağı tam modele ve en önemlisi fabrika yöneticisi parolasının daha önce değiştirilip değiştirilmediğine bağlıdır.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Otomatik Keşif / Exploitation Araçları

| Araç | Amaç | Örnek |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL kötüye kullanımı, dosya sistemi erişimi, default-creds kontrolü, *SNMP keşfi* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS üzerinden yapılandırma bilgilerini (adres defterleri ve LDAP kimlik bilgileri dahil) toplama | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Sahte kimlik doğrulama hizmetleri çalıştırma ve SMB callback'lerinden NetNTLM yakalama/aktarma | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Seri numarasını keşfetme, olası fabrika yöneticisi parolasını türetme ve web konsolu erişimini doğrulama | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Güçlendirme ve Tespit

1. MFP'lere derhal **yama uygulayın / firmware güncellemesi yapın** (satıcının PSIRT duyurularını kontrol edin).
2. **Fabrika yöneticisi parolalarını değiştirin** – yalnızca firmware güncellemesi, daha önce üretilmiş etkilenen Brother/OEM cihazlarında seri numarasından türetilen başlangıç parolalarını kaldırmaz.<sup>[[6]](#references)</sup>
3. **En Az Ayrıcalıklı Hizmet Hesapları** – LDAP/SMB/SMTP için hiçbir zaman Domain Admin kullanmayın; kapsamı *salt okunur* OU'larla sınırlayın.
4. **Yönetim Erişimini Kısıtlayın** – yazıcı web/IPP/SNMP arayüzlerini bir yönetim VLAN'ına veya ACL/VPN arkasına yerleştirin.
5. **Yazıcıların dışarıya bağlantılarını sınırlandırın** – her cihazın yalnızca beklenen DC/LDAP, mail, DNS/NTP, print ve scan-file hedeflerine bağlanmasına izin verin. Pass-back, saldırganın seçtiği bir uç noktaya callback gerektirir.
6. **Kullanılmayan Protokolleri Devre Dışı Bırakın** – FTP, Telnet, raw-9100, eski SSL şifreleri.
7. **Denetim Günlüğünü Etkinleştirin** – bazı cihazlar LDAP/SMTP hatalarını syslog'a yazabilir; beklenmeyen bind olaylarını ilişkilendirin.
8. **Kimlik doğrulama hedeflerini izleyin** – özellikle yönetim oturum açma veya yapılandırma değişikliğinin hemen ardından bir yazıcı izin verilenler listesi dışındaki bir ana bilgisayara LDAP, SMB, SMTP veya FTP bağlantısı başlattığında uyarı verin.
9. **SNMPv3 kullanın veya SNMP'yi devre dışı bırakın** – `public` community değeri genellikle cihaz ve seri numarası bilgilerini sızdırır.

---



---

## References

- [1] [Bu sadece bir yazıcı… Olabilecek en kötü şey nedir?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Çok İşlevli Yazıcı: Pass-Back Saldırısı Güvenlik Açıkları (Düzeltildi)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Üretim Yazıcıları, Ofis/Küçük Ofis Çok İşlevli Yazıcıları ve Lazer Yazıcılar için Güvenlik Açığı Azaltma/Giderme](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat ile Yazıcı Üzerinden Etki Alanı Kimlik Bilgilerini Elde Etme](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Bir Penetrasyon Testi Çalışması Sırasında Çok İşlevli Yazıcıları Exploit Etme](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Birden Fazla Brother Cihazı: Birden Fazla Güvenlik Açığı (DÜZELTİLDİ)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother varsayılan yönetici kimlik doğrulama atlatma modülü](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
