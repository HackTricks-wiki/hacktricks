# Yazıcılardaki Bilgiler

{{#include ../../banners/hacktricks-training.md}}

Internet'te, **yazıcıların LDAP ile varsayılan/zayıf** oturum açma kimlik bilgileri kullanacak şekilde yapılandırılmış bırakılmasının **tehlikelerini vurgulayan** çeşitli bloglar bulunmaktadır.  \
Bunun nedeni, bir saldırganın **yazıcıyı sahte bir LDAP sunucusuna karşı authenticate olmaya kandırabilmesi** (genellikle bir `nc -vv -l -p 389` veya `slapd -d 2` yeterlidir) ve yazıcının **kimlik bilgilerini clear-text olarak** ele geçirebilmesidir.

Ayrıca, birçok yazıcı **kullanıcı adlarını içeren loglar** barındırır veya hatta Domain Controller'dan **tüm kullanıcı adlarını download edebilir**.

Tüm bu **hassas bilgiler** ve yaygın **güvenlik eksikliği**, yazıcıları saldırganlar için oldukça ilgi çekici hâle getirir.

Konuyla ilgili bazı başlangıç niteliğinde bloglar:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Yazıcı Yapılandırması

- **Konum**: LDAP sunucu listesi genellikle web arayüzünde bulunur (ör. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Davranış**: Birçok embedded web server, LDAP sunucusu değişikliklerine **kimlik bilgilerinin yeniden girilmesini gerektirmeden** izin verir (kullanılabilirlik özelliği → güvenlik riski).
- **Exploit**: LDAP sunucusu adresini saldırganın kontrolündeki bir host'a yönlendirin ve yazıcıyı size bind olmaya zorlamak için *Test Connection* / *Address Book Sync* düğmesini kullanın.

---

## Kimlik Bilgilerini Yakalama

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Küçük/eski MFP'ler, netcat'in yakalayabileceği şekilde basit bir *simple-bind* işlemini clear-text olarak gönderebilir. Modern cihazlar genellikle önce anonymous bir query gerçekleştirir ve ardından bind işlemini dener; bu nedenle sonuçlar değişiklik gösterebilir.<sup>[[1]](#references)</sup>

### Method 2 – Tam Rogue LDAP server (önerilir)

Birçok cihaz authentication işlemi yapmadan *önce* anonymous bir search gerçekleştireceğinden, gerçek bir LDAP daemon'ı çalıştırmak çok daha güvenilir sonuçlar sağlar:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Yazıcı lookup işlemini gerçekleştirdiğinde, debug çıktısında clear-text kimlik bilgilerini göreceksiniz.

> 💡  LDAP üzerinden NTLMv2 hash'lerini toplamak için `impacket/examples/ldapd.py` (Python rogue LDAP) veya `Responder -w -r -f` de kullanabilirsiniz.

---

## Güncel Pass-Back Vulnerability'leri (2024-2025)

Pass-back *teorik bir sorun değildir* – vendor'lar 2024/2025 yıllarında bu attack class'ını tam olarak açıklayan advisory'ler yayımlamaya devam ediyor.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFP'lerinin 57.69.91 ve önceki firmware sürümleri, yetkili bir admin'in (veya default creds hâlâ duruyorsa herhangi bir kişinin):

* **CVE-2024-12510 – LDAP pass-back**: LDAP server adresini değiştirmesine ve bir lookup tetiklemesine izin veriyordu; bunun sonucunda cihaz, yapılandırılmış Windows credentials'larını attacker-controlled host'a leak ediyordu.
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* hedefleri üzerinden aynı sorun yaşanıyor ve NetNTLMv2 veya FTP clear-text creds leak ediliyordu.<sup>[[2]](#references)</sup>

Şu tür basit bir listener:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
veya sahte bir SMB server (`impacket-smbserver`) kimlik bilgilerini toplamak için yeterlidir.

### Canon imageRUNNER / imageCLASS – 20 Mayıs 2025 Advisory

Canon, düzinelerce Laser & MFP ürün serisinde bir **SMTP/LDAP pass-back** zafiyetini doğruladı. Admin erişimine sahip bir attacker, server yapılandırmasını değiştirebilir ve LDAP **veya** SMTP için kaydedilmiş kimlik bilgilerini alabilir (birçok kuruluş scan-to-mail özelliğine izin vermek için ayrıcalıklı bir hesap kullanır).<sup>[[3]](#references)</sup>

Vendor guidance açıkça şunları önerir:

1. Kullanılabilir olur olmaz patched firmware sürümüne güncelleme yapılması.
2. Güçlü ve benzersiz admin password kullanılması.
3. Printer integration için ayrıcalıklı AD hesaplarının kullanılmaması.

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL abuse, file-system access, default-creds check, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS üzerinden configuration (address books ve LDAP creds dahil) toplama | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | SMB/FTP pass-back üzerinden NetNTLM hash'lerini capture etme ve relay etme | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Clear-text bind'leri almak için lightweight rogue LDAP service | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **Patch / firmware-update** işlemlerini MFP'lerde zamanında gerçekleştirin (vendor PSIRT bulletins'lerini kontrol edin).
2. **Least-Privilege Service Accounts** – LDAP/SMB/SMTP için hiçbir zaman Domain Admin kullanmayın; *read-only* OU scope'larıyla sınırlandırın.
3. **Restrict Management Access** – printer web/IPP/SNMP interface'lerini bir management VLAN'ına veya ACL/VPN arkasına yerleştirin.
4. **Disable Unused Protocols** – FTP, Telnet, raw-9100 ve eski SSL cipher'ları devre dışı bırakın.
5. **Enable Audit Logging** – bazı device'lar LDAP/SMTP failure'larını syslog'a yazabilir; beklenmeyen bind'leri ilişkilendirin.
6. Olağandışı kaynaklardaki **Clear-Text LDAP bind** işlemlerini izleyin (printer'lar normalde yalnızca DC'lerle iletişim kurmalıdır).
7. **SNMPv3 veya SNMP'yi devre dışı bırakın** – `public` community değeri çoğu zaman device ve LDAP config bilgilerini leak eder.

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
