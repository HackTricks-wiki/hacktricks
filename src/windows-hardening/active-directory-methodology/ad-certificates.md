# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- Sertifikanın **Sahibi**, sertifikanın sahibini belirtir.
- **Açık Anahtar**, sertifikayı gerçek sahibine bağlamak için özel bir anahtarla eşleştirilir.
- **Geçerlilik Süresi**, **NotBefore** ve **NotAfter** tarihleri ile tanımlanır ve sertifikanın etkin süresini işaret eder.
- Sertifikayı tanımlayan benzersiz bir **Seri Numarası**, Sertifika Otoritesi (CA) tarafından sağlanır.
- **Verici**, sertifikayı veren CA'yı ifade eder.
- **SubjectAlternativeName**, kimlik tanımlama esnekliğini artırarak konu için ek adlar sağlar.
- **Temel Kısıtlamalar**, sertifikanın bir CA veya son varlık için olup olmadığını tanımlar ve kullanım kısıtlamalarını belirler.
- **Genişletilmiş Anahtar Kullanımları (EKUs)**, sertifikanın belirli amaçlarını, örneğin kod imzalama veya e-posta şifreleme gibi, Nesne Tanımlayıcıları (OIDs) aracılığıyla belirler.
- **İmza Algoritması**, sertifikayı imzalamak için kullanılan yöntemi belirtir.
- **İmza**, vericinin özel anahtarı ile oluşturulur ve sertifikanın doğruluğunu garanti eder.

### Special Considerations

- **Subject Alternative Names (SANs)**, bir sertifikanın birden fazla kimliğe uygulanabilirliğini genişletir, bu da birden fazla alan adı olan sunucular için kritik öneme sahiptir. Güvenli verilme süreçleri, saldırganların SAN spesifikasyonunu manipüle ederek kimlik taklit etme risklerini önlemek için hayati öneme sahiptir.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS, AD ormanında CA sertifikalarını belirlenmiş konteynerler aracılığıyla tanır; her biri benzersiz roller üstlenir:

- **Sertifika Otoriteleri** konteyneri, güvenilir kök CA sertifikalarını tutar.
- **Kayıt Hizmetleri** konteyneri, Kurumsal CA'ları ve sertifika şablonlarını detaylandırır.
- **NTAuthCertificates** nesnesi, AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Otorite Bilgi Erişimi)** konteyneri, ara ve çapraz CA sertifikaları ile sertifika zinciri doğrulamasını kolaylaştırır.

### Certificate Acquisition: Client Certificate Request Flow

1. İstek süreci, istemcilerin bir Kurumsal CA bulmasıyla başlar.
2. Bir kamu-özel anahtar çifti oluşturulduktan sonra, bir kamu anahtarı ve diğer detayları içeren bir CSR oluşturulur.
3. CA, mevcut sertifika şablonlarına karşı CSR'yi değerlendirir ve şablonun izinlerine dayanarak sertifikayı verir.
4. Onaylandığında, CA sertifikayı özel anahtarı ile imzalar ve istemciye geri gönderir.

### Certificate Templates

AD içinde tanımlanan bu şablonlar, sertifika vermek için ayarları ve izinleri belirler; izin verilen EKU'lar ve kayıt veya değişiklik hakları dahil, sertifika hizmetlerine erişimi yönetmek için kritik öneme sahiptir.

## Certificate Enrollment

Sertifikalar için kayıt süreci, bir yöneticinin **bir sertifika şablonu oluşturması** ile başlar; bu şablon daha sonra bir Kurumsal Sertifika Otoritesi (CA) tarafından **yayınlanır**. Bu, şablonu istemci kaydı için kullanılabilir hale getirir; bu adım, şablonun adını bir Active Directory nesnesinin `certificatetemplates` alanına ekleyerek gerçekleştirilir.

Bir istemcinin sertifika talep edebilmesi için, **kayıt hakları** verilmelidir. Bu haklar, sertifika şablonundaki güvenlik tanımlayıcıları ve Kurumsal CA'nın kendisi tarafından tanımlanır. Bir talebin başarılı olması için her iki konumda da izinler verilmelidir.

### Template Enrollment Rights

Bu haklar, aşağıdaki gibi izinleri detaylandıran Erişim Kontrol Girişleri (ACE'ler) aracılığıyla belirtilir:

- **Sertifika-Kayıt** ve **Sertifika-OtomatikKayıt** hakları, her biri belirli GUID'lerle ilişkilidir.
- **GenişletilmişHaklar**, tüm genişletilmiş izinlere izin verir.
- **TamKontrol/GeniGenericAll**, şablon üzerinde tam kontrol sağlar.

### Enterprise CA Enrollment Rights

CA'nın hakları, Sertifika Otoritesi yönetim konsolu aracılığıyla erişilebilen güvenlik tanımlayıcısında belirtilmiştir. Bazı ayarlar, düşük ayrıcalıklı kullanıcıların uzaktan erişim sağlamasına bile izin verebilir, bu da bir güvenlik endişesi olabilir.

### Additional Issuance Controls

Bazı kontroller uygulanabilir, örneğin:

- **Yönetici Onayı**: Talepleri, bir sertifika yöneticisi tarafından onaylanana kadar beklemede tutar.
- **Kayıt Ajanları ve Yetkili İmzalar**: Bir CSR üzerindeki gerekli imza sayısını ve gerekli Uygulama Politika OID'lerini belirtir.

### Methods to Request Certificates

Sertifikalar aşağıdaki yöntemlerle talep edilebilir:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM arayüzlerini kullanarak.
2. **ICertPassage Remote Protocol** (MS-ICPR), adlandırılmış borular veya TCP/IP aracılığıyla.
3. **Sertifika kayıt web arayüzü**, Sertifika Otoritesi Web Kayıt rolü yüklü olduğunda.
4. **Sertifika Kayıt Servisi** (CES), Sertifika Kayıt Politikası (CEP) servisi ile birlikte.
5. **Ağ Cihazı Kayıt Servisi** (NDES) için ağ cihazları, Basit Sertifika Kayıt Protokolü (SCEP) kullanarak.

Windows kullanıcıları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) veya komut satırı araçları (`certreq.exe` veya PowerShell'in `Get-Certificate` komutu) aracılığıyla sertifika talep edebilir.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifika Kimlik Doğrulaması

Active Directory (AD) sertifika kimlik doğrulamasını destekler, esasen **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanır.

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, bir kullanıcının Ticket Granting Ticket (TGT) talebi, kullanıcının sertifikasının **özel anahtarı** ile imzalanır. Bu talep, alan denetleyicisi tarafından sertifikanın **geçerliliği**, **yolu** ve **iptal durumu** dahil olmak üzere birkaç doğrulamadan geçer. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğini doğrulamayı ve vericinin **NTAUTH sertifika deposu** içindeki varlığını onaylamayı içerir. Başarılı doğrulamalar, bir TGT'nin verilmesiyle sonuçlanır. AD'deki **`NTAuthCertificates`** nesnesi, şu adreste bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
güvenilirliği sağlamak için merkezi bir öneme sahiptir.

### Güvenli Kanal (Schannel) Kimlik Doğrulaması

Schannel, bir el sıkışma sırasında istemcinin, başarılı bir şekilde doğrulanırsa erişimi yetkilendiren bir sertifika sunduğu güvenli TLS/SSL bağlantılarını kolaylaştırır. Bir sertifikanın bir AD hesabına eşlenmesi, Kerberos’un **S4U2Self** fonksiyonu veya sertifikanın **Subject Alternative Name (SAN)** gibi diğer yöntemleri içerebilir.

### AD Sertifika Hizmetleri Sayımı

AD'nin sertifika hizmetleri, **Enterprise Certificate Authorities (CAs)** ve bunların yapılandırmaları hakkında bilgi açığa çıkaran LDAP sorguları aracılığıyla sayılabilir. Bu, özel ayrıcalıklara sahip olmadan herhangi bir alan kimlik doğrulama kullanıcısı tarafından erişilebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar, AD CS ortamlarında sayım ve güvenlik açığı değerlendirmesi için kullanılır.

Bu araçları kullanmak için komutlar şunlardır:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Referanslar

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../banners/hacktricks-training.md}}
