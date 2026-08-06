# AD Sertifikaları

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

### Sertifikanın Bileşenleri

- Sertifikanın **Subject** alanı sahibini belirtir.
- Bir **Public Key**, sertifikayı gerçek sahibiyle ilişkilendirmek için özel olarak tutulan bir anahtarla eşleştirilir.
- **NotBefore** ve **NotAfter** tarihleriyle tanımlanan **Validity Period**, sertifikanın geçerli olduğu süreyi belirtir.
- Certificate Authority (CA) tarafından sağlanan benzersiz bir **Serial Number**, her sertifikayı tanımlar.
- **Issuer**, sertifikayı düzenleyen CA'yı belirtir.
- **SubjectAlternativeName**, subject için ek adlara izin vererek kimlik belirleme esnekliğini artırır.
- **Basic Constraints**, sertifikanın bir CA'ya mı yoksa bir uç varlığa mı ait olduğunu belirler ve kullanım kısıtlamalarını tanımlar.
- **Extended Key Usages (EKUs)**, Object Identifiers (OID'ler) aracılığıyla sertifikanın kod imzalama veya e-posta şifreleme gibi belirli amaçlarını tanımlar.
- **Signature Algorithm**, sertifikanın imzalanma yöntemini belirtir.
- Issuer'ın özel anahtarıyla oluşturulan **Signature**, sertifikanın gerçekliğini garanti eder.<sup>[[1]](#references)</sup>

### Özel Hususlar

- **Subject Alternative Names (SANs)**, bir sertifikanın birden fazla kimlik için kullanılabilmesini sağlar ve birden fazla domain'e sahip sunucular için kritik önem taşır. Saldırganların SAN belirtimini manipüle ederek impersonation gerçekleştirmesini önlemek için güvenli issuance süreçleri hayati önem taşır.<sup>[[1]](#references)</sup>

### Active Directory'de (AD) Certificate Authorities (CA'ler)

AD CS, bir AD forest içindeki CA sertifikalarını, her biri benzersiz rollere sahip belirlenmiş container'lar aracılığıyla tanır:<sup>[[1]](#references)</sup>

- **Certification Authorities** container'ı, güvenilen root CA sertifikalarını barındırır.
- **Enrolment Services** container'ı, Enterprise CA'leri ve bunların certificate template'lerini içerir.
- **NTAuthCertificates** nesnesi, AD authentication için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Authority Information Access)** container'ı, intermediate ve cross CA sertifikalarıyla certificate chain validation işlemini kolaylaştırır.

### Certificate Acquisition: Client Certificate Request Flow

1. Request süreci, client'ların bir Enterprise CA bulmasıyla başlar.
2. Bir public-private key pair oluşturulduktan sonra, bir public key ve diğer ayrıntıları içeren bir CSR oluşturulur.
3. CA, CSR'ı mevcut certificate template'lerine göre değerlendirir ve sertifikayı template'in izinlerine dayanarak düzenler.
4. Onaydan sonra CA, sertifikayı özel anahtarıyla imzalar ve client'a geri gönderir.<sup>[[1]](#references)</sup>

### Certificate Templates

AD içinde tanımlanan bu template'ler, izin verilen EKU'lar ile enrollment veya modification hakları da dahil olmak üzere sertifikaların düzenlenmesine ilişkin ayarları ve izinleri belirler. Bu, certificate services'e erişimin yönetilmesi açısından kritiktir.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Sertifikalar için enrollment süreci, bir administrator'ın **certificate template oluşturmasıyla** başlatılır ve ardından bu template bir Enterprise Certificate Authority (CA) tarafından **publish edilir**. Bu işlem, template'in adının bir Active Directory nesnesinin `certificatetemplates` alanına eklenmesiyle template'i client enrollment için kullanılabilir hale getirir.<sup>[[1]](#references)</sup>

Bir client'ın sertifika talep edebilmesi için **enrollment rights** verilmelidir. Bu haklar, certificate template ve Enterprise CA üzerindeki security descriptor'lar tarafından tanımlanır. Bir request'in başarılı olması için izinlerin her iki konumda da verilmesi gerekir.<sup>[[1]](#references)</sup>

### Template Enrollment Rights

Bu haklar, aşağıdaki izinleri ayrıntılandıran Access Control Entries (ACE'ler) aracılığıyla belirtilir:<sup>[[1]](#references)</sup>

- Her biri belirli GUID'lerle ilişkilendirilmiş **Certificate-Enrollment** ve **Certificate-AutoEnrollment** hakları.
- Tüm extended permission'ları sağlayan **ExtendedRights**.
- Template üzerinde tam control sağlayan **FullControl/GenericAll**.

### Enterprise CA Enrollment Rights

CA'nin hakları, Certificate Authority management console üzerinden erişilebilen security descriptor'ında belirtilir. Bazı ayarlar, düşük ayrıcalıklı user'lara remote access verilmesine bile izin verir; bu durum bir security concern oluşturabilir.<sup>[[1]](#references)</sup>

### Additional Issuance Controls

Aşağıdaki gibi belirli control'ler uygulanabilir:<sup>[[1]](#references)</sup>

- **Manager Approval**: Request'leri bir certificate manager tarafından onaylanana kadar pending durumunda tutar.
- **Enrolment Agents and Authorized Signatures**: Bir CSR üzerinde gerekli signature sayısını ve gerekli Application Policy OID'lerini belirtir.

### Methods to Request Certificates

Sertifikalar aşağıdaki yöntemlerle request edilebilir:<sup>[[1]](#references)</sup>

1. DCOM interface'lerini kullanan **Windows Client Certificate Enrollment Protocol** (MS-WCCE).
2. Named pipe'lar veya TCP/IP üzerinden **ICertPassage Remote Protocol** (MS-ICPR).
3. Certificate Authority Web Enrollment role'ünün kurulu olduğu **certificate enrollment web interface**.
4. Certificate Enrollment Policy (CEP) service ile birlikte **Certificate Enrollment Service** (CES).
5. Simple Certificate Enrollment Protocol (SCEP) kullanan network device'lar için **Network Device Enrollment Service** (NDES).

Windows user'ları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) ya da command-line tool'ları (`certreq.exe` veya PowerShell'ın `Get-Certificate` command'ı) aracılığıyla da sertifika request edebilir.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifika Kimlik Doğrulaması

Active Directory (AD), öncelikli olarak **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak sertifika kimlik doğrulamasını destekler.<sup>[[1]](#references)</sup>

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, bir kullanıcının Ticket Granting Ticket (TGT) isteği, kullanıcının sertifikasının **özel anahtarı** kullanılarak imzalanır. Bu istek, etki alanı denetleyicisi tarafından sertifikanın **geçerliliği**, **yolu** ve **iptal durumu** dahil olmak üzere çeşitli doğrulamalardan geçirilir. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğinin doğrulanmasını ve issuer'ın **NTAUTH certificate store** içinde bulunduğunun onaylanmasını da içerir. Doğrulamaların başarılı olması, bir TGT verilmesiyle sonuçlanır. AD'deki **`NTAuthCertificates`** nesnesi şu konumda bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
sertifika authentication için güven tesisinin oluşturulmasında merkezi bir rol oynar.<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) Authentication

Schannel, güvenli TLS/SSL bağlantılarını kolaylaştırır; handshake sırasında client, başarıyla doğrulanırsa erişim yetkisi sağlayan bir sertifika sunar.<sup>[[2]](#references)</sup> Bir sertifikanın AD hesabıyla eşleştirilmesi, diğer yöntemlerin yanı sıra Kerberos’un **S4U2Self** işlevini veya sertifikanın **Subject Alternative Name (SAN)** alanını içerebilir.<sup>[[1]](#references)</sup>

### AD Certificate Services Enumeration

AD’nin certificate services bileşenleri LDAP sorguları aracılığıyla enumerate edilebilir; bu işlem **Enterprise Certificate Authorities (CAs)** ve yapılandırmaları hakkında bilgi ortaya çıkarır. Bu bilgilere, özel ayrıcalıklara sahip olmayan, domain kimlik doğrulaması yapılmış herhangi bir kullanıcı erişebilir.<sup>[[1]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar, AD CS ortamlarında enumeration ve vulnerability assessment için kullanılır.<sup>[[3]](#references)</sup>

Bu araçları kullanmaya yönelik komutlar şunlardır:
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

- [1] [Certified Pre-Owned: Active Directory Certificate Services Abuse](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [SSL/TLS İstemci Kimlik Doğrulaması Nedir ve Nasıl Çalışır?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
