# Yazıcılardaki Bilgiler

{{#include ../../banners/hacktricks-training.md}}

İnternette, yazıcıların LDAP ile varsayılan/zayıf **oturum açma kimlik bilgileriyle yapılandırılmış şekilde bırakılmasının tehlikelerini vurgulayan** çeşitli blog yazıları bulunmaktadır.  \
Bunun nedeni, bir saldırganın **yazıcıyı sahte bir LDAP sunucusuna karşı authenticate olmaya kandırabilmesi** (genellikle `nc -vv -l -p 389` veya `slapd -d 2` yeterlidir) ve yazıcının **kimlik bilgilerini düz metin olarak** ele geçirebilmesidir.

Ayrıca birçok yazıcıda **kullanıcı adlarını içeren loglar** bulunur veya yazıcılar Domain Controller'dan **tüm kullanıcı adlarını indirme** yeteneğine sahip olabilir.

Tüm bu **hassas bilgiler** ve yaygın **güvenlik eksikliği**, yazıcıları saldırganlar için oldukça ilgi çekici hâle getirir.

Konuyla ilgili bazı giriş niteliğinde blog yazıları:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Yazıcı Yapılandırması

- **Konum**: LDAP sunucu listesi genellikle web arayüzünde bulunur (ör. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Davranış**: Birçok gömülü web sunucusu, **kimlik bilgilerini yeniden girmeden LDAP sunucusu değişikliklerine** izin verir (kullanılabilirlik özelliği → güvenlik riski).
- **Exploit**: LDAP sunucusu adresini saldırganın kontrolündeki bir host'a yönlendirin ve yazıcıyı size bind olmaya zorlamak için *Test Connection* / *Address Book Sync* düğmesini kullanın.

---

## Kimlik Bilgilerini Yakalama

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
Küçük/eski MFP'ler, bind DN'sinin ve parolanın ham BER akışında görünür olduğu basit bir *simple-bind* gönderebilir. Modern cihazlar genellikle önce anonim bir sorgu gerçekleştirir ve ardından bind işlemini dener; bu nedenle sonuçlar değişiklik gösterir.<sup>[[1]](#references)</sup>

636/3269 portlarında çalışan basit bir `nc` listener yalnızca TLS ciphertext alır; LDAPS'i test etmek için TLS destekli bir LDAP endpoint gerekir ve cihaz sunucu sertifikasını doğru şekilde doğruladığında yönlendirme başarısız olmalıdır.

### Method 2 – Rogue LDAP server (önerilir)

Birçok cihaz kimlik doğrulamasından *önce* anonim bir arama gerçekleştireceğinden, gerçek bir LDAP daemon kurmak çok daha güvenilir sonuçlar sağlar:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Yazıcı lookup işlemini gerçekleştirdiğinde debug çıktısında clear-text kimlik bilgilerini göreceksiniz.

> 💡  Responder, rogue LDAP ve SMB authentication servislerini içerir. Basit bir LDAP bind yapılandırılmış parolayı açığa çıkarabilirken NTLM authentication challenge-response materyali üretir; her iki sonucu da clear-text parola olarak tanımlamayın.

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back *teorik bir sorun değildir* – vendor'lar 2024/2025 yıllarında bu saldırı sınıfını tam olarak tanımlayan advisory'ler yayımlamaya devam ediyor.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFP'lerinin 57.69.91 ve önceki firmware sürümleri, authenticated bir admin'in (veya default creds hâlâ geçerliyse herhangi bir kişinin):

* **CVE-2024-12510 – LDAP pass-back**: LDAP server adresini değiştirmesine ve bir lookup tetiklemesine izin vererek cihazın yapılandırılmış Windows kimlik bilgilerini attacker-controlled host'a leak etmesine,
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* hedefleri üzerinden aynı sorunun oluşmasına ve NetNTLMv2 veya FTP clear-text kimlik bilgilerinin leak edilmesine olanak tanıyordu.<sup>[[2]](#references)</sup>

Şu tür basit bir listener:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
veya sahte bir SMB server (`impacket-smbserver`) kimlik bilgilerini toplamak için yeterlidir.

### Canon imageRUNNER / imageCLASS – 20 Mayıs 2025 tarihli Advisory

Canon, düzinelerce Laser & MFP ürün serisinde bir **SMTP/LDAP pass-back** zafiyetini doğruladı. Admin erişimine sahip bir attacker, server yapılandırmasını değiştirebilir ve LDAP **veya** SMTP için kayıtlı kimlik bilgilerini elde edebilir (birçok kuruluş scan-to-mail özelliğine izin vermek için ayrıcalıklı bir hesap kullanır).<sup>[[3]](#references)</sup>

Vendor rehberi açıkça şunları önerir:

1. Kullanılabilir olur olmaz patched firmware sürümüne güncelleme yapılması.
2. Güçlü ve benzersiz admin parolalarının kullanılması.
3. Printer integration için ayrıcalıklı AD hesaplarının kullanılmaması.

---

### Brother cihazları ve OEM varyantları – service credentials'a serial üzerinden admin erişimi

2025 yılında gerçekleştirilen coordinated disclosure, etkilenen Brother cihazlarında özellikle kullanışlı bir chain ortaya koydu; vulnerability set'in bazı bölümleri OEM modellerini de etkiler, bu nedenle tam modeli vendor advisory ile doğrulayın. Unauthenticated bir attacker, vulnerable firmware üzerinde HTTP/HTTPS/IPP aracılığıyla cihaz serial bilgisini elde edebilir; serial bilgileri SNMP veya PJL gibi management protocol'leri üzerinden de erişilebilir olabilir. Factory password hiç değiştirilmediyse serial, administrator password'ünü deterministik olarak üretir. Authenticate olduktan sonra ayrı pass-back flaw olan CVE-2024-51984, LDAP veya FTP gibi yapılandırılmış external-service password'lerini plaintext olarak açığa çıkarır ve printer-management erişimini yeniden kullanılabilir network credentials'a dönüştürür. Firmware, service-password disclosure sorununu düzeltir; ancak daha önce üretilmiş cihazlarda operator'ün serial üzerinden türetilen initial administrator password'ünü değiştirmesi gerekir.<sup>[[6]](#references)</sup>

Güncel Metasploit, serial bilgisini HTTP, SNMP veya PJL üzerinden bulan, candidate initial password'ü üreten ve isteğe bağlı olarak bunu web console'a karşı doğrulayan bir auxiliary module içerir. `DiscoverSerialVia=AUTO`, desteklenen discovery path'lerini dener; asset inventory serial bilgisini zaten içeriyorsa bunun yerine `TargetSerial` sağlayın.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Yetkili varlıkları doğrulamak için sonucu kullanın. Parolanın çalışıp çalışmayacağı, tam modele ve kritik olarak fabrika yöneticisi parolasının daha önce değiştirilip değiştirilmediğine bağlıdır.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL abuse, file-system access, default-creds check, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS üzerinden yapılandırmayı (adres defterleri ve LDAP kimlik bilgileri dahil) toplama | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Rogue authentication services çalıştırma ve SMB callbacks üzerinden NetNTLM yakalama/relay etme | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Bir seri numarası keşfetme, aday fabrika yöneticisi parolasını türetme ve web konsolu erişimini doğrulama | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening & Detection

1. **MFP'leri derhal patch / firmware-update edin** (vendor PSIRT bültenlerini kontrol edin).
2. **Fabrika yöneticisi parolalarını değiştirin** – yalnızca firmware, daha önce üretilmiş etkilenen Brother/OEM cihazlarındaki seri numarasından türetilen başlangıç parolalarını kaldırmaz.<sup>[[6]](#references)</sup>
3. **Least-Privilege Service Accounts** – LDAP/SMB/SMTP için asla Domain Admin kullanmayın; yalnızca *salt okunur* OU kapsamlarıyla sınırlandırın.
4. **Management Access'i kısıtlayın** – yazıcı web/IPP/SNMP arayüzlerini bir management VLAN'ına veya ACL/VPN arkasına yerleştirin.
5. **Yazıcı egress'ini sınırlandırın** – her cihazın yalnızca beklenen DC/LDAP, mail, DNS/NTP, print ve scan-file hedefleriyle iletişim kurmasına izin verin. Pass-back, attacker tarafından seçilen bir endpoint'e callback gerektirir.
6. **Kullanılmayan protokolleri devre dışı bırakın** – FTP, Telnet, raw-9100 ve eski SSL şifreleri.
7. **Audit Logging'i etkinleştirin** – bazı cihazlar LDAP/SMTP hatalarını syslog'a yazabilir; beklenmeyen bind işlemlerini ilişkilendirin.
8. **Authentication hedeflerini izleyin** – bir yazıcı allowlist dışında bir host'a LDAP, SMB, SMTP veya FTP başlattığında, özellikle bir management login'i ya da yapılandırma değişikliğinin hemen ardından uyarı verin.
9. **SNMPv3 kullanın veya SNMP'yi devre dışı bırakın** – `public` community değeri genellikle cihaz ve seri numarası bilgilerini leak eder.

---



---

## References

- [1] [Bu sadece bir yazıcı… Olabilecek en kötü şey nedir?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Çok İşlevli Yazıcı: Pass-Back Attack Güvenlik Açıkları (Düzeltildi)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [Üretim Yazıcıları, Ofis/Küçük Ofis Çok İşlevli Yazıcıları ve Lazer Yazıcılar için CP2025-004 Güvenlik Açığı Azaltma/Giderme](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat ile Bir Yazıcı Üzerinden Domain Kimlik Bilgilerini Elde Etme](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Bir Penetration Test Çalışması Sırasında Çok İşlevli Yazıcılardan Yararlanma](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Birden Fazla Brother Cihazı: Birden Fazla Güvenlik Açığı (DÜZELTİLDİ)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother varsayılan yönetici authentication bypass modülü](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
