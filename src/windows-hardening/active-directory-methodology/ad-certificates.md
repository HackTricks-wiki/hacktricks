# AD Sertifikaları

{{#include ../../banners/hacktricks-training.md}}

## Giriş

### Bir Sertifikanın Bileşenleri

- Sertifikanın **Subject** alanı sahibini belirtir.
- Bir **Public Key**, sertifikayı gerçek sahibiyle ilişkilendirmek için özel olarak tutulan bir anahtarla eşleştirilir.
- **NotBefore** ve **NotAfter** tarihleriyle tanımlanan **Validity Period**, sertifikanın geçerli olduğu süreyi belirtir.
- Certificate Authority (CA) tarafından sağlanan benzersiz **Serial Number**, her sertifikayı tanımlar.
- **Issuer**, sertifikayı yayınlayan CA'yı belirtir.
- **SubjectAlternativeName**, subject için ek adlara izin vererek tanımlama esnekliğini artırır.
- **Basic Constraints**, sertifikanın bir CA'ya mı yoksa bir end entity'ye mi ait olduğunu belirler ve kullanım kısıtlamalarını tanımlar.
- **Extended Key Usages (EKUs)**, Object Identifiers (OIDs) aracılığıyla sertifikanın code signing veya email encryption gibi belirli amaçlarını tanımlar.
- **Signature Algorithm**, sertifikanın imzalanmasında kullanılan yöntemi belirtir.
- Issuer'ın özel anahtarıyla oluşturulan **Signature**, sertifikanın gerçekliğini garanti eder.<sup>[[4]](#references)</sup>

### Özel Hususlar

- **Subject Alternative Names (SANs)**, bir sertifikanın birden fazla kimlik için kullanılabilmesini sağlar ve birden fazla domain'e sahip sunucular için kritik önem taşır. Saldırganların SAN belirtimini manipüle ederek impersonation riskleri oluşturmasını önlemek için güvenli issuance süreçleri hayati önem taşır.<sup>[[4]](#references)</sup>

### Active Directory (AD) içindeki Certificate Authorities (CAs)

AD CS, bir AD forest içindeki CA sertifikalarını, her biri benzersiz roller üstlenen belirlenmiş container'lar aracılığıyla tanır:<sup>[[4]](#references)</sup>

- **Certification Authorities** container'ı, güvenilen root CA sertifikalarını içerir.
- **Enrolment Services** container'ı, Enterprise CA'leri ve bunların certificate template'lerini açıklar.
- **NTAuthCertificates** object'i, AD authentication için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Authority Information Access)** container'ı, intermediate ve cross CA sertifikalarıyla certificate chain doğrulamasını kolaylaştırır.

### Sertifika Edinme: Client Certificate Request Flow

1. Request süreci, client'ların bir Enterprise CA bulmasıyla başlar.
2. Bir public-private key pair oluşturulduktan sonra, public key ve diğer bilgileri içeren bir CSR oluşturulur.
3. CA, CSR'yi mevcut certificate template'lerine göre değerlendirir ve sertifikayı template'in permissions ayarlarına göre yayınlar.
4. Onaydan sonra CA, sertifikayı özel anahtarıyla imzalar ve client'a geri gönderir.<sup>[[4]](#references)</sup>

### Certificate Templates

AD içinde tanımlanan bu template'ler, izin verilen EKU'lar ile enrollment veya modification hakları dahil olmak üzere sertifikaların yayınlanmasına ilişkin ayarları ve izinleri belirtir. Bu özellikler, certificate services erişiminin yönetilmesi açısından kritiktir.<sup>[[4]](#references)</sup>

**Template schema version önemlidir.** Eski **v1** template'leri (örneğin, yerleşik **WebServer** template'i) çeşitli modern enforcement kontrollerinden yoksundur. **ESC15/EKUwu** araştırması, **v1 template'lerinde** requester's CSR içine **Application Policies/EKUs** ekleyebildiğini ve bunların template'te yapılandırılmış EKU'lara **tercih edildiğini** gösterdi. Bu durum yalnızca enrollment rights ile client-auth, enrollment agent veya code-signing sertifikalarının oluşturulmasını mümkün kılar. **v2/v3 template'lerini** tercih edin, v1 varsayılanlarını kaldırın veya bunların yerine daha yeni template'ler kullanın ve EKU'ları amaçlanan kullanımla sıkı biçimde sınırlandırın.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Sertifikalar için enrollment süreci, bir yöneticinin **bir certificate template oluşturmasıyla** başlar. Daha sonra bu template bir Enterprise Certificate Authority (CA) tarafından **publish edilir**. Bu işlem, template adının bir Active Directory object'inin `certificatetemplates` field'ına eklenmesiyle template'i client enrollment için kullanılabilir hale getirir.<sup>[[4]](#references)</sup>

Bir client'ın sertifika request edebilmesi için **enrollment rights** verilmelidir. Bu haklar, certificate template ve Enterprise CA üzerindeki security descriptor'lar tarafından tanımlanır. Bir request'in başarılı olması için her iki konumda da gerekli permissions verilmelidir.

### Template Enrollment Rights

Bu haklar, aşağıdakiler gibi permissions ayrıntılarını belirleyen Access Control Entries (ACEs) aracılığıyla tanımlanır:

- Her biri belirli GUID'lerle ilişkilendirilmiş **Certificate-Enrollment** ve **Certificate-AutoEnrollment** hakları.
- Tüm extended permissions'ları sağlayan **ExtendedRights**.
- Template üzerinde tam control sağlayan **FullControl/GenericAll**.

### Enterprise CA Enrollment Rights

CA'nin hakları, Certificate Authority management console üzerinden erişilebilen security descriptor'ında belirtilir. Bazı ayarlar low-privileged user'lara remote access verilmesine dahi izin verir; bu durum bir security concern oluşturabilir.

### Additional Issuance Controls

Aşağıdaki gibi belirli kontroller uygulanabilir:

- **Manager Approval**: Request'leri bir certificate manager tarafından onaylanana kadar pending durumunda tutar.
- **Enrolment Agents and Authorized Signatures**: Bir CSR üzerinde gerekli signature sayısını ve gerekli Application Policy OID'lerini belirtir.

### Sertifika Request Etme Yöntemleri

Sertifikalar aşağıdaki yöntemlerle request edilebilir:

1. DCOM interfaces kullanan **Windows Client Certificate Enrollment Protocol** (MS-WCCE).
2. Named pipes veya TCP/IP üzerinden çalışan **ICertPassage Remote Protocol** (MS-ICPR).
3. Certificate Authority Web Enrollment rolünün kurulu olduğu **certificate enrollment web interface**.
4. Certificate Enrollment Policy (CEP) service ile birlikte kullanılan **Certificate Enrollment Service** (CES).
5. Simple Certificate Enrollment Protocol (SCEP) kullanan network device'lar için **Network Device Enrollment Service** (NDES).

Windows user'ları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) ya da command-line tools (`certreq.exe` veya PowerShell'ın `Get-Certificate` command'ı) aracılığıyla sertifika request edebilir.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifika Kimlik Doğrulaması

Active Directory (AD), öncelikli olarak **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak sertifika kimlik doğrulamasını destekler.

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, kullanıcının Ticket Granting Ticket (TGT) isteği, kullanıcının sertifikasının **özel anahtarı** kullanılarak imzalanır. Bu istek, domain controller tarafından sertifikanın **geçerliliği**, **yolu** ve **iptal durumu** dahil olmak üzere çeşitli doğrulamalardan geçirilir. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğini doğrulamayı ve issuer'ın **NTAUTH certificate store** içindeki varlığını onaylamayı da kapsar. Doğrulamaların başarılı olması, bir TGT verilmesiyle sonuçlanır. AD'deki **`NTAuthCertificates`** nesnesi şu konumda bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
certificate authentication için güven tesisinin oluşturulmasında merkezi bir rol oynar.<sup>[[4]](#references)</sup>

**KB5014754** dağıtımından bu yana modern Kerberos certificate auth, yalnızca EKU'larla değil, çoğunlukla **mapping strength** ile ilgilidir.<sup>[[2]](#references)</sup> Hardened forest'larda:

- Yalnızca **UPN/DNS SAN** taşıyan bir certificate artık logon için yeterli olmayabilir.
- KDC, genellikle **SID security extension** (`1.3.6.1.4.1.311.25.2`) veya `altSecurityIdentities` içindeki güçlü bir açık mapping olan **strong binding**'i tercih eder.
- Certificate güçlü bir mapping içermiyorsa DC'ler compatibility mode'da **Kdcsvc Event ID 39/41** olaylarını log'lar ve enforcement mode'da auth işlemini reddeder.
- Karma attack path'lerinde **ESC9/ESC16** önemlidir; çünkü bu teknikler issued certificate'lardan SID extension'ı çıkarır. Operator'lar daha sonra explicit mapping'lere veya attack path'in desteklediği SAN URL SID formatlarına güvenir.

### Secure Channel (Schannel) Authentication

Schannel, güvenli TLS/SSL bağlantılarını kolaylaştırır. Handshake sırasında client, başarılı şekilde validate edilirse access yetkisi sağlayan bir certificate sunar. Bir certificate'ın AD account'a mapping'i, diğer yöntemlerin yanı sıra Kerberos'un **S4U2Self** işlevini veya certificate'ın **Subject Alternative Name (SAN)** alanını içerebilir.<sup>[[4]](#references)</sup>

**PKINIT** kullanılamadığında Schannel pratik bir fallback olarak da kullanılır. Örneğin, bir domain controller uygun bir **Smart Card Logon** certificate'ına sahip değilse, `certipy auth`/PKINIT tooling bir TGT almayı başaramayabilir; ancak aynı certificate authentication ve LDAP operasyonları için **LDAPS** veya **LDAP StartTLS** ile kullanılabilir.

### AD Certificate Services Enumeration

AD'nin certificate services bileşenleri LDAP sorguları üzerinden enumerate edilebilir; bu işlem **Enterprise Certificate Authorities (CAs)** ve bunların configuration'ları hakkında bilgi verir. Buna, özel privilege'lar olmadan domain-authenticated herhangi bir user erişebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar AD CS environment'larında enumeration ve vulnerability assessment için kullanılır.

Bu araçların kullanımına ilişkin komutlar şunlardır:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Güncel Vulnerabilities ve Security Updates (2022-2025)

| Yıl | ID / İsim | Etki | Temel Çıkarımlar |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT sırasında machine account certificate spoofing yoluyla *Privilege escalation*. | Yama, **10 Mayıs 2022** security updates içerisinde sunulmuştur. Auditing ve strong-mapping kontrolleri **KB5014754** ile kullanıma sunulmuştur; ortamlar artık *Full Enforcement* modunda olmalıdır. |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) ve CES rollerinde *Remote code-execution*. | Public PoC'ler sınırlıdır, ancak vulnerable IIS bileşenleri çoğunlukla kurum içinde erişime açıktır. **Temmuz 2023** Patch Tuesday itibarıyla yamalanmıştır. |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** üzerinde enrollment rights sahibi bir requester, CSR içerisine template EKU'larının önceliklendirdiği **Application Policies/EKUs** değerlerini ekleyebilir ve bunun sonucunda client-auth, enrollment agent veya code-signing certificates oluşturabilir. | **12 Kasım 2024** itibarıyla yamalanmıştır. v1 templates'leri (ör. varsayılan WebServer) değiştirin veya supersede edin, EKU'ları amaçlarıyla sınırlandırın ve enrollment rights değerlerini kısıtlayın. |

### Microsoft hardening timeline (KB5014754)

Microsoft, Kerberos certificate authentication'ı weak implicit mappings'ten uzaklaştırmak için üç aşamalı bir rollout (Compatibility → Audit → Enforcement) başlattı. **11 Şubat 2025** itibarıyla, `StrongCertificateBindingEnforcement` registry value ayarlanmamışsa domain controllers otomatik olarak **Full Enforcement** moduna geçer. Microsoft daha sonra timeline'ı güncelleyerek compatibility mode'a dönüşün **9 Eylül 2025** security update'ine kadar mümkün kalmasını sağladı.<sup>[[2]](#references)</sup> Administrators şunları yapmalıdır:

1. Tüm DC'leri ve AD CS server'larını patch edin (Mayıs 2022 veya sonrası).
2. *Audit* aşamasında weak mappings için Event ID 39/41 olaylarını izleyin.
3. Enforcement weak mappings'i engellemeden önce client-auth certificates'ları yeni **SID extension** ile yeniden issue edin veya strong manual mappings yapılandırın.

### Hardened forest'lar için operator notes

- **ESC1/ESC6 artık 2025+ ortamlarında tek başına tüm hikâye değildir.** Başka bir principal için cert request ettiğinizde genellikle SID extension veya explicit mapping gibi bir strong mapping artifact'a da ihtiyaç duyarsınız.
- **ESC15 (EKUwu)**, çoğunlukla unpatched ortamlarda değerlidir; çünkü **WebServer** gibi zararsız **v1** templates'lerini **Application Policies** inject ederek authentication veya enrollment-agent yetenekli cert'lere dönüştürür. Kerberos PKINIT hâlâ EKU'ları değerlendirir, ancak **LDAP Schannel** da Application Policies değerlerini kabul eder; bu durum LDAP tabanlı abuse yöntemlerinin geçerliliğini korur.<sup>[[1]](#references)</sup>
- **ESC16** CA-wide bir ayardır: CA, SID security extension'ı global olarak devre dışı bırakırsa, attack chain başka bir supported format kullanarak SID inject etmediği sürece verilen tüm certificates daha zayıf mapping davranışına geri döner.

---

## Detection ve Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** artık ESC1-ESC8/ESC11 için posture assessments sunar ve *“Domain-controller certificate issuance for a non-DC”* (ESC8) ile *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15) gibi real-time alerts üretir. Bu detections'tan yararlanmak için tüm AD CS server'larına sensor'ları deploy edin.<sup>[[3]](#references)</sup>
* Tüm templates üzerindeki **“Supply in the request”** seçeneğini devre dışı bırakın veya kapsamını sıkı şekilde sınırlandırın; açıkça tanımlanmış SAN/EKU değerlerini tercih edin.
* Mutlak surette gerekli olmadıkça templates'lerden **Any Purpose** veya **No EKU** değerlerini kaldırın (ESC2 senaryolarını ele alır).
* Hassas templates'ler (ör. WebServer / CodeSigning) için **manager approval** veya özel Enrollment Agent workflow'ları zorunlu kılın.
* Web enrollment (`certsrv`) ve CES/NDES endpoint'lerini trusted network'lerle sınırlandırın veya client-certificate authentication arkasına alın.
* ESC11'i (RPC relay) azaltmak için RPC enrollment encryption'ı zorunlu kılın (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`). Flag **varsayılan olarak açıktır**, ancak legacy clients için çoğunlukla devre dışı bırakılır ve relay riskini yeniden ortaya çıkarır.
* **IIS-based enrollment endpoint'lerini** (CES/Certsrv) güvenli hâle getirin: mümkün olduğunda NTLM'i devre dışı bırakın veya ESC8 relay'lerini engellemek için HTTPS + Extended Protection zorunlu kılın.

---

## References

- [1] [EKUwu: Başka bir AD CS ESC'den ibaret değil](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows domain controllers üzerindeki certificate-based authentication değişiklikleri](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services Abuse](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
