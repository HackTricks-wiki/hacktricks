# AD Sertifikaları

{{#include ../../banners/hacktricks-training.md}}

## Giriş

### Sertifika Bileşenleri

- Sertifikanın **Sahibi**, sertifikanın sahibini belirtir.
- **Açık Anahtar**, sertifikayı gerçek sahibine bağlamak için özel bir anahtarla eşleştirilir.
- **Geçerlilik Süresi**, **NotBefore** ve **NotAfter** tarihleri ile tanımlanır ve sertifikanın etkin süresini işaret eder.
- Sertifikayı tanımlayan benzersiz bir **Seri Numarası**, Sertifika Otoritesi (CA) tarafından sağlanır.
- **Verici**, sertifikayı veren CA'yı ifade eder.
- **SubjectAlternativeName**, kimlik tanımlama esnekliğini artırarak konu için ek adlar sağlar.
- **Temel Kısıtlamalar**, sertifikanın bir CA veya son varlık için olup olmadığını belirler ve kullanım kısıtlamalarını tanımlar.
- **Genişletilmiş Anahtar Kullanımları (EKU'lar)**, sertifikanın belirli amaçlarını, örneğin kod imzalama veya e-posta şifreleme gibi, Nesne Tanımlayıcıları (OID'ler) aracılığıyla belirler.
- **İmza Algoritması**, sertifikayı imzalamak için kullanılan yöntemi belirtir.
- **İmza**, vericinin özel anahtarı ile oluşturulur ve sertifikanın doğruluğunu garanti eder.

### Özel Dikkatler

- **Subject Alternative Names (SAN'lar)**, bir sertifikanın birden fazla kimliğe uygulanabilirliğini genişletir, bu da birden fazla alan adı olan sunucular için kritik öneme sahiptir. Güvenli verilme süreçleri, saldırganların SAN spesifikasyonunu manipüle ederek kimlik taklidi risklerini önlemek için hayati öneme sahiptir.

### Aktif Dizin (AD) İçindeki Sertifika Otoriteleri (CA)

AD CS, AD ormanında CA sertifikalarını belirlenmiş konteynerler aracılığıyla tanır; her biri benzersiz roller üstlenir:

- **Sertifika Otoriteleri** konteyneri, güvenilir kök CA sertifikalarını tutar.
- **Kayıt Hizmetleri** konteyneri, Kurumsal CA'lar ve sertifika şablonlarını detaylandırır.
- **NTAuthCertificates** nesnesi, AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Otorite Bilgi Erişimi)** konteyneri, ara ve çapraz CA sertifikaları ile sertifika zinciri doğrulamasını kolaylaştırır.

### Sertifika Edinimi: İstemci Sertifika Talep Akışı

1. Talep süreci, istemcilerin bir Kurumsal CA bulmasıyla başlar.
2. Bir kamu anahtarı ve diğer detayları içeren bir CSR oluşturulur, ardından bir açık-özel anahtar çifti üretilir.
3. CA, mevcut sertifika şablonlarına karşı CSR'yi değerlendirir ve şablonun izinlerine dayanarak sertifikayı verir.
4. Onaylandığında, CA sertifikayı özel anahtarı ile imzalar ve istemciye geri gönderir.

### Sertifika Şablonları

AD içinde tanımlanan bu şablonlar, sertifika vermek için ayarları ve izinleri belirler; izin verilen EKU'lar ve kayıt veya değişiklik hakları dahil, sertifika hizmetlerine erişimi yönetmek için kritik öneme sahiptir.

## Sertifika Kaydı

Sertifikalar için kayıt süreci, bir yöneticinin **bir sertifika şablonu oluşturması** ile başlar; bu şablon daha sonra bir Kurumsal Sertifika Otoritesi (CA) tarafından **yayınlanır**. Bu, şablonu istemci kaydı için kullanılabilir hale getirir; bu adım, şablonun adını bir Active Directory nesnesinin `certificatetemplates` alanına ekleyerek gerçekleştirilir.

Bir istemcinin sertifika talep edebilmesi için, **kayıt hakları** verilmelidir. Bu haklar, sertifika şablonundaki güvenlik tanımlayıcıları ve Kurumsal CA'nın kendisi tarafından tanımlanır. Bir talebin başarılı olması için her iki konumda da izinler verilmelidir.

### Şablon Kayıt Hakları

Bu haklar, aşağıdaki gibi izinleri detaylandıran Erişim Kontrol Girişleri (ACE'ler) aracılığıyla belirtilir:

- **Sertifika-Kayıt** ve **Sertifika-OtomatikKayıt** hakları, her biri belirli GUID'lerle ilişkilidir.
- **GenişletilmişHaklar**, tüm genişletilmiş izinlere izin verir.
- **TamKontrol/GeniGenericAll**, şablon üzerinde tam kontrol sağlar.

### Kurumsal CA Kayıt Hakları

CA'nın hakları, Sertifika Otoritesi yönetim konsolu aracılığıyla erişilebilen güvenlik tanımlayıcısında belirtilmiştir. Bazı ayarlar, düşük ayrıcalıklı kullanıcıların uzaktan erişimine bile izin verebilir, bu da bir güvenlik endişesi olabilir.

### Ek Verme Kontrolleri

Bazı kontroller uygulanabilir, örneğin:

- **Yönetici Onayı**: Talepleri, bir sertifika yöneticisi tarafından onaylanana kadar beklemede tutar.
- **Kayıt Temsilcileri ve Yetkili İmzalar**: Bir CSR üzerindeki gerekli imza sayısını ve gerekli Uygulama Politika OID'lerini belirtir.

### Sertifika Talep Yöntemleri

Sertifikalar aşağıdaki yöntemlerle talep edilebilir:

1. **Windows İstemci Sertifika Kayıt Protokolü** (MS-WCCE), DCOM arayüzlerini kullanarak.
2. **ICertPassage Uzak Protokolü** (MS-ICPR), adlandırılmış borular veya TCP/IP aracılığıyla.
3. **Sertifika kayıt web arayüzü**, Sertifika Otoritesi Web Kayıt rolü yüklü olduğunda.
4. **Sertifika Kayıt Hizmeti** (CES), Sertifika Kayıt Politikası (CEP) hizmeti ile birlikte.
5. **Ağ Cihazı Kayıt Hizmeti** (NDES) için ağ cihazları, Basit Sertifika Kayıt Protokolü (SCEP) kullanarak.

Windows kullanıcıları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) veya komut satırı araçları (`certreq.exe` veya PowerShell'in `Get-Certificate` komutu) aracılığıyla sertifika talep edebilir.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifika Kimlik Doğrulama

Active Directory (AD) sertifika kimlik doğrulamayı destekler, esasen **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanır.

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, bir kullanıcının Ticket Granting Ticket (TGT) talebi, kullanıcının sertifikasının **özel anahtarı** ile imzalanır. Bu talep, alan denetleyicisi tarafından sertifikanın **geçerliliği**, **yolu** ve **iptal durumu** dahil olmak üzere birkaç doğrulamadan geçer. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğini doğrulamayı ve vericinin **NTAUTH sertifika deposu** içindeki varlığını onaylamayı içerir. Başarılı doğrulamalar, bir TGT'nin verilmesiyle sonuçlanır. AD'deki **`NTAuthCertificates`** nesnesi, şu adreste bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
güvenilirliği sağlamak için merkezi bir öneme sahiptir.

### Güvenli Kanal (Schannel) Kimlik Doğrulaması

Schannel, bir el sıkışma sırasında istemcinin, başarılı bir şekilde doğrulandığında erişimi yetkilendiren bir sertifika sunduğu güvenli TLS/SSL bağlantılarını kolaylaştırır. Bir sertifikanın bir AD hesabına eşlenmesi, Kerberos'un **S4U2Self** işlevini veya sertifikanın **Subject Alternative Name (SAN)**'ini içeren diğer yöntemleri içerebilir.

### AD Sertifika Hizmetleri Sayımı

AD'nin sertifika hizmetleri, **Enterprise Certificate Authorities (CAs)** ve bunların yapılandırmaları hakkında bilgi ortaya çıkaran LDAP sorguları aracılığıyla sayılabilir. Bu, özel ayrıcalıklara sahip olmadan herhangi bir alan kimlik doğrulamalı kullanıcı tarafından erişilebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar, AD CS ortamlarında sayım ve güvenlik açığı değerlendirmesi için kullanılır.

Bu araçları kullanmak için komutlar şunlardır:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
---

## Son Güvenlik Açıkları & Güncellemeler (2022-2025)

| Yıl | ID / İsim | Etki | Ana Çıkarımlar |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Yetki yükseltme* PKINIT sırasında makine hesap sertifikalarının taklit edilmesiyle. | Yamanın **10 Mayıs 2022** güvenlik güncellemelerine dahil edildi. Denetim ve güçlü eşleme kontrolleri **KB5014754** aracılığıyla tanıtıldı; ortamların artık *Tam Uygulama* modunda olması gerekiyor. citeturn2search0 |
| 2023 | **CVE-2023-35350 / 35351** | *Uzaktan kod yürütme* AD CS Web Enrollment (certsrv) ve CES rollerinde. | Kamuya açık PoC'ler sınırlıdır, ancak savunmasız IIS bileşenleri genellikle dahili olarak açığa çıkar. Yamanın **Temmuz 2023** Yamanın Salısı itibarıyla mevcut. citeturn3search0 |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Kayıt haklarına sahip düşük yetkili kullanıcılar, CSR oluşturma sırasında **herhangi** bir EKU veya SAN'ı geçersiz kılabilir, istemci kimlik doğrulaması veya kod imzalama için kullanılabilir sertifikalar vererek *alanın tehlikeye girmesine* yol açabilir. | **Nisan 2024** güncellemelerinde ele alındı. Şablonlardan “Talepte Sağla”yı kaldırın ve kayıt izinlerini kısıtlayın. citeturn1search3 |

### Microsoft sertifika güçlendirme zaman çizelgesi (KB5014754)

Microsoft, Kerberos sertifika kimlik doğrulamasını zayıf örtük eşlemelerden uzaklaştırmak için üç aşamalı bir dağıtım (Uyumluluk → Denetim → Uygulama) tanıttı. **11 Şubat 2025** itibarıyla, `StrongCertificateBindingEnforcement` kayıt defteri değeri ayarlanmamışsa, etki alanı denetleyicileri otomatik olarak **Tam Uygulama** moduna geçer. Yöneticilerin:

1. Tüm DC'leri ve AD CS sunucularını yamalaması (Mayıs 2022 veya sonrası).
2. *Denetim* aşamasında zayıf eşlemeler için Olay ID 39/41'i izlemesi.
3. Şubat 2025'ten önce yeni **SID uzantısı** ile istemci kimlik sertifikalarını yeniden vermesi veya güçlü manuel eşlemeleri yapılandırması gerekir. citeturn2search0

---

## Tespit & Güçlendirme Geliştirmeleri

* **Defender for Identity AD CS sensörü (2023-2024)** artık ESC1-ESC8/ESC11 için duruş değerlendirmeleri sunmakta ve *“Bir DC için sertifika verilmesi”* (ESC8) ve *“Rastgele Uygulama Politikaları ile Sertifika Kaydını Önle”* (ESC15) gibi gerçek zamanlı uyarılar üretmektedir. Bu tespitlerden yararlanmak için sensörlerin tüm AD CS sunucularına dağıtıldığından emin olun. citeturn5search0
* Tüm şablonlarda **“Talepte Sağla”** seçeneğini devre dışı bırakın veya sıkı bir şekilde sınırlayın; açıkça tanımlanmış SAN/EKU değerlerini tercih edin.
* Şablonlardan **Her Amaç** veya **No EKU**'yu kaldırın, aksi takdirde kesinlikle gerekli olmadıkça (ESC2 senaryolarını ele alır).
* Hassas şablonlar için **yönetici onayı** veya özel Kayıt Temsilcisi iş akışları gerektirin (örneğin, WebSunucu / Kod İmzalama).
* Web kaydını (`certsrv`) ve CES/NDES uç noktalarını güvenilir ağlarla veya istemci sertifika kimlik doğrulaması arkasında kısıtlayın.
* ESC11'i azaltmak için RPC kayıt şifrelemesini zorlayın (`certutil –setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQ`).

---

## Referanslar

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
