# AD Sertifikaları

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

### Bir Sertifikanın Bileşenleri

- **Subject** sertifikanın sahibini belirtir.
- Bir **Public Key**, sertifikayı gerçek sahibine bağlamak için özel olarak tutulan bir anahtar ile eşleştirilir.
- **Validity Period**, **NotBefore** ve **NotAfter** tarihlerince tanımlanan sertifikanın geçerli olduğu süredir.
- Benzersiz bir **Serial Number**, Sertifika Yetkilisi (CA) tarafından sağlanır ve her sertifikayı tanımlar.
- **Issuer**, sertifikayı düzenleyen CA'yı ifade eder.
- **SubjectAlternativeName** konu için ek adlar izin vererek tanımlama esnekliğini artırır.
- **Basic Constraints** sertifikanın bir CA mı yoksa son nokta varlık mı olduğunu ve kullanım kısıtlamalarını tanımlar.
- **Extended Key Usages (EKUs)**, Object Identifier (OID) aracılığıyla kod imzalama veya e-posta şifreleme gibi sertifikanın özel amaçlarını belirtir.
- **Signature Algorithm** sertifikanın imzalanma yöntemini belirtir.
- **Signature**, düzenleyenin özel anahtarı ile oluşturularak sertifikanın doğruluğunu garanti eder.

### Özel Hususlar

- **Subject Alternative Names (SANs)** bir sertifikanın birden çok kimliğe uygulanmasını sağlar; birden fazla domaine sahip sunucular için kritiktir. SAN tanımının kötüye kullanımıyla saldırganların taklit riskini önlemek için güvenli sertifika verme süreçleri hayati öneme sahiptir.

### Active Directory (AD) İçindeki Sertifika Yetkilileri (CAs)

AD CS, AD ormanındaki CA sertifikalarını belirlenmiş konteynerler aracılığıyla tanır; her biri farklı roller sağlar:

- **Certification Authorities** konteyneri güvenilen root CA sertifikalarını tutar.
- **Enrolment Services** konteyneri Enterprise CAs ve bunların sertifika şablonları hakkında ayrıntı içerir.
- **NTAuthCertificates** nesnesi AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Authority Information Access)** konteyneri, ara ve çapraz CA sertifikaları ile sertifika zinciri doğrulamasını kolaylaştırır.

### Sertifika Edinimi: İstemci Sertifika İsteği Akışı

1. İstek süreci, istemcilerin bir Enterprise CA bulmasıyla başlar.
2. Bir CSR, bir public-private anahtar çifti oluşturulduktan sonra public key ve diğer bilgileri içerecek şekilde oluşturulur.
3. CA, CSR'yi mevcut sertifika şablonlarına göre değerlendirir ve şablonun izinlerine bağlı olarak sertifikayı verir.
4. Onaylandığında, CA sertifikayı kendi özel anahtarıyla imzalar ve istemciye döner.

### Sertifika Şablonları

AD içinde tanımlanan bu şablonlar, sertifika verme ayarlarını ve izinlerini (izin verilen EKU'lar, kayıt veya değişiklik hakları gibi) belirler; sertifika hizmetlerine erişimi yönetmek için kritiktir.

## Sertifika Kaydı (Enrollment)

Sertifikalar için kayıt süreci, bir yönetici tarafından **bir sertifika şablonu oluşturulması** ile başlatılır; bu şablon daha sonra bir Enterprise Certificate Authority (CA) tarafından **yayınlanır**. Bu, şablonu istemci kaydı için kullanılabilir hale getirir; bu adım, şablonun adının bir Active Directory nesnesinin `certificatetemplates` alanına eklenmesiyle gerçekleştirilir.

Bir istemcinin sertifika talep edebilmesi için **enrollment rights** verilmiş olmalıdır. Bu haklar, sertifika şablonu ve Enterprise CA üzerindeki güvenlik descriptor'larıyla tanımlanır. Bir isteğin başarılı olabilmesi için izinlerin her iki yerde de verilmiş olması gerekir.

### Şablon Kayıt Hakları

Bu haklar Access Control Entry (ACE) aracılığıyla belirtilir ve şu izinleri içerebilir:

- **Certificate-Enrollment** ve **Certificate-AutoEnrollment** hakları, her biri belirli GUID'lerle ilişkilidir.
- **ExtendedRights**, tüm genişletilmiş izinlere izin verir.
- **FullControl/GenericAll**, şablon üzerinde tam kontrol sağlar.

### Enterprise CA Kayıt Hakları

CA'nın hakları, Certificate Authority yönetim konsolu üzerinden erişilebilen güvenlik descriptor'unda özetlenir. Bazı ayarlar, düşük ayrıcalıklı kullanıcılara bile uzaktan erişim sağlayabilecek şekilde yapılandırılabilir; bu bir güvenlik endişesi olabilir.

### Ek Veriliş Kontrolleri

Bazı kontroller uygulanabilir, örneğin:

- **Manager Approval**: Talepleri onaylanana kadar beklemede bırakır.
- **Enrolment Agents ve Authorized Signatures**: Bir CSR üzerinde gerekli imza sayısını ve gerekli Application Policy OID'lerini belirtir.

### Sertifika İsteme Yöntemleri

Sertifikalar şu yollarla talep edilebilir:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM arayüzleri kullanılarak.
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes veya TCP/IP üzerinden.
3. **certificate enrollment web interface**, Certificate Authority Web Enrollment rolü yüklüyken.
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) servisi ile birlikte.
5. **Network Device Enrollment Service** (NDES) için network cihazları, Simple Certificate Enrollment Protocol (SCEP) kullanılarak.

Windows kullanıcıları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) veya komut satırı araçları (`certreq.exe` veya PowerShell'in `Get-Certificate` komutu) aracılığıyla sertifika talep edebilirler.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifika Kimlik Doğrulaması

Active Directory (AD), öncelikle **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak sertifika ile kimlik doğrulamayı destekler.

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, bir kullanıcının Ticket Granting Ticket (TGT) talebi, kullanıcının sertifikasının **özel anahtarı** ile imzalanır. Bu istek, etki alanı denetleyicisi tarafından sertifikanın **geçerliliği**, **zinciri** ve **iptal durumu** dahil olmak üzere çeşitli doğrulamaya tabi tutulur. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğinin ve düzenleyenin **NTAUTH certificate store** içinde bulunduğunun teyit edilmesini içerir. Doğrulamaların başarılı olması TGT'nin verilmesiyle sonuçlanır. AD içindeki **`NTAuthCertificates`** objesi, şu konumda bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
sertifika kimlik doğrulaması için güven oluşturmanın merkezindedir.

### Güvenli Kanal (Schannel) Kimlik Doğrulaması

Schannel, bir handshake sırasında istemcinin bir sertifika sunduğu güvenli TLS/SSL bağlantılarını kolaylaştırır; bu sertifika başarıyla doğrulanırsa erişime izin verilir. Bir sertifikanın bir AD hesabına eşlenmesi, Kerberos’un **S4U2Self** işlevini veya sertifikanın **Subject Alternative Name (SAN)**'ını ve diğer yöntemleri içerebilir.

### AD Certificate Services Enumeration

AD'nin certificate services'i LDAP sorguları aracılığıyla enumerate edilebilir; bu, **Enterprise Certificate Authorities (CAs)** ve yapılandırmaları hakkında bilgi açığa çıkarır. Bu, özel ayrıcalık gerektirmeden etki alanında kimliği doğrulanmış herhangi bir kullanıcı tarafından erişilebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar, AD CS ortamlarında enumeration ve zafiyet değerlendirmesi için kullanılır.

Bu araçların kullanımı için komutlar şunları içerir:
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
