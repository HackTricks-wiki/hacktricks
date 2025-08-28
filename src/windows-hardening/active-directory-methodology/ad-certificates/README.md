# AD Sertifikaları

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

### Bir Sertifikanın Bileşenleri

- **Subject** sertifikanın sahibini belirtir.
- Bir **Public Key**, sertifikayı gerçek sahibine bağlamak için özel tutulan bir anahtar ile eşleştirilir.
- **Validity Period**, **NotBefore** ve **NotAfter** tarihleriyle tanımlanır ve sertifikanın geçerli olduğu süreyi gösterir.
- Her sertifikayı tanımlayan benzersiz bir **Serial Number**, Certificate Authority (CA) tarafından sağlanır.
- **Issuer**, sertifikayı düzenleyen CA'yı ifade eder.
- **SubjectAlternativeName** konu için ek isimlere izin vererek tanımlama esnekliğini artırır.
- **Basic Constraints**, sertifikanın bir CA için mi yoksa bir uç varlık için mi olduğunu belirler ve kullanım kısıtlamalarını tanımlar.
- **Extended Key Usages (EKUs)**, Object Identifier'lar (OIDs) aracılığıyla sertifikanın kod imzalama veya e-posta şifreleme gibi belirli amaçlarını belirtir.
- **Signature Algorithm**, sertifikanın imzalanma yöntemini belirtir.
- **Signature**, sertifikanın gerçekliğini garanti etmek için issuer'ın özel anahtarıyla oluşturulur.

### Özel Hususlar

- **Subject Alternative Names (SANs)** bir sertifikanın birden çok kimliğe uygulanabilirliğini genişletir; çoklu alan adlarına sahip sunucular için kritiktir. SAN tanımının kötüye kullanılmasını önlemek için güvenli sertifika verme süreçleri çok önemlidir; aksi takdirde saldırganlar taklit riskine yol açabilir.

### Active Directory (AD) İçindeki Certificate Authorities (CAs)

AD CS, bir AD ormanında CA sertifikalarını belirli konteynerler aracılığıyla tanır; her biri farklı rollere hizmet eder:

- **Certification Authorities** container, güvenilen root CA sertifikalarını tutar.
- **Enrolment Services** container, Enterprise CAs ve onların certificate templates bilgilerini içerir.
- **NTAuthCertificates** objesi, AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Authority Information Access)** container, ara ve cross CA sertifikaları ile sertifika zinciri doğrulamasını kolaylaştırır.

### Sertifika Edinimi: İstemci Sertifika İsteği Akışı

1. Süreç, istemcilerin bir Enterprise CA bulmasıyla başlar.
2. Bir public-private anahtar çifti oluşturulduktan sonra bir CSR (Certificate Signing Request) oluşturulur; bu CSR içinde bir public key ve diğer bilgiler bulunur.
3. CA, CSR'yi mevcut certificate templates ile karşılaştırır ve şablonun izinlerine göre sertifikayı yayınlar.
4. Onaylandıktan sonra CA, sertifikayı kendi özel anahtarıyla imzalar ve istemciye geri gönderir.

### Certificate Templates

AD içinde tanımlanan bu şablonlar, hangi EKU'ların izinli olduğu, kayıt veya değişiklik hakları gibi sertifika yayınlama ayarları ve izinlerini belirler; bu, sertifika hizmetlerine erişimin yönetimi için kritiktir.

## Sertifika Kaydı

Sertifikalar için kayıt süreci, bir yönetici tarafından **bir certificate template oluşturulması** ile başlatılır; bu template daha sonra bir Enterprise Certificate Authority (CA) tarafından **yayınlanır**. Bu, template'in istemci kayıtları için kullanılabilir olmasını sağlar ve genellikle Active Directory nesnesinin `certificatetemplates` alanına şablonun adının eklenmesiyle gerçekleştirilir.

Bir istemcinin sertifika talep edebilmesi için **enrollment rights** verilmiş olmalıdır. Bu haklar, certificate template üzerindeki ve Enterprise CA'nin kendisindeki security descriptor'lar tarafından tanımlanır. Bir isteğin başarılı olması için izinlerin her iki yerde de verilmiş olması gerekir.

### Şablon Kayıt Hakları

Bu haklar Access Control Entry (ACE) üzerinden belirtilir ve şu izinleri içerebilir:

- **Certificate-Enrollment** ve **Certificate-AutoEnrollment** hakları, her biri belirli GUID'lerle ilişkilidir.
- **ExtendedRights**, tüm genişletilmiş izinlere olanak tanır.
- **FullControl/GenericAll**, şablon üzerinde tam kontrol sağlar.

### Enterprise CA Kayıt Hakları

CA'nın hakları, Certificate Authority yönetim konsolu aracılığıyla erişilebilen security descriptor'da belirtilir. Bazı ayarlar düşük ayrıcalıklı kullanıcılara uzaktan erişim izni verebilir; bu durum bir güvenlik endişesi oluşturabilir.

### Ek Yayınlama Kontrolleri

Bazı kontroller uygulanabilir, örneğin:

- **Manager Approval**: Talepleri bir certificate manager onaylayana kadar bekleyen durumda tutar.
- **Enrolment Agents and Authorized Signatures**: Bir CSR üzerinde gereken imza sayısını ve gerekli Application Policy OID'lerini belirtir.

### Sertifika İstem Yöntemleri

Sertifikalar şu yollarla istenebilir:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM arayüzleri kullanılarak.
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes veya TCP/IP üzerinden.
3. Certificate Authority Web Enrollment rolü yüklü ise **certificate enrollment web interface** üzerinden.
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) servisi ile birlikte.
5. Network cihazları için **Network Device Enrollment Service** (NDES) ve Simple Certificate Enrollment Protocol (SCEP) kullanılarak.

Windows kullanıcıları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) veya komut satırı araçları (`certreq.exe` veya PowerShell'in `Get-Certificate` komutu) aracılığıyla da sertifika talep edebilirler.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD), öncelikli olarak **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak sertifika kimlik doğrulamayı destekler.

### Kerberos Authentication Process

Kerberos kimlik doğrulama sürecinde, bir kullanıcının Ticket Granting Ticket (TGT) talebi, kullanıcının sertifikasının **özel anahtarı** ile imzalanır. Bu istek, domain controller tarafından sertifikanın **geçerliliği**, **yolu** ve **iptal durumu** dahil olmak üzere birkaç doğrulamadan geçer. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğinin ve düzenleyicinin **NTAUTH certificate store** içinde bulunduğunun teyit edilmesini içerir. Başarılı doğrulamalar TGT'nin verilmesiyle sonuçlanır. AD içindeki **`NTAuthCertificates`** nesnesi, şu konumda bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
Sertifika kimlik doğrulaması için güvenin kurulmasında merkezi öneme sahiptir.

### Güvenli Kanal (Schannel) Kimlik Doğrulaması

Schannel, TLS/SSL bağlantılarını kolaylaştırır; el sıkışma sırasında istemci bir sertifika sunar ve bu sertifika başarıyla doğrulanırsa erişimi yetkilendirir. Bir sertifikanın bir AD hesabına eşlenmesi, diğer yöntemlerin yanı sıra Kerberos'un **S4U2Self** fonksiyonunu veya sertifikanın **Subject Alternative Name (SAN)** alanını içerebilir.

### AD Sertifika Servislerinin Keşfi

AD'nin sertifika servisleri LDAP sorguları aracılığıyla keşfedilebilir; bu, **Enterprise Certificate Authorities (CAs)** ve yapılandırmaları hakkında bilgi açığa çıkarır. Bu, özel ayrıcalıklara ihtiyaç duymadan etki alanı kimlik doğrulaması yapılmış herhangi bir kullanıcı tarafından erişilebilir. AD CS ortamlarında keşif ve zafiyet değerlendirmesi için **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar kullanılır.

Bu araçları kullanmak için komutlar şunlardır:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Referanslar

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
