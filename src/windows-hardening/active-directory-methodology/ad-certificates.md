# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Giriş

### Bir Sertifikanın Bileşenleri

- Sertifikanın **Subject** değeri, sahibini belirtir.
- Bir **Public Key**, sertifikayı gerçek sahibine bağlamak için özel olarak tutulan bir anahtarla eşleştirilir.
- **Validity Period**, **NotBefore** ve **NotAfter** tarihleriyle tanımlanır ve sertifikanın geçerli olduğu süreyi belirtir.
- Certificate Authority (**CA**) tarafından sağlanan benzersiz bir **Serial Number**, her sertifikayı tanımlar.
- **Issuer**, sertifikayı veren CA'yı ifade eder.
- **SubjectAlternativeName**, subject için ek adlara izin vererek tanımlama esnekliğini artırır.
- **Basic Constraints**, sertifikanın bir CA mı yoksa bir end entity mi olduğunu belirler ve kullanım kısıtlamalarını tanımlar.
- **Extended Key Usages (EKUs)**, Object Identifiers (OIDs) aracılığıyla sertifikanın code signing veya email encryption gibi özel amaçlarını belirtir.
- **Signature Algorithm**, sertifikanın imzalanma yöntemini belirtir.
- Issuer'ın private key'i ile oluşturulan **Signature**, sertifikanın gerçekliğini garanti eder.

### Özel Hususlar

- **Subject Alternative Names (SANs)**, bir sertifikanın birden fazla kimliğe uygulanabilirliğini genişletir; bu, birden fazla domain'e sahip server'lar için kritiktir. Güvenli issuance süreçleri, SAN spesifikasyonunu manipüle eden attacker'ların impersonation risklerinden kaçınmak için hayati önemdedir.

### Active Directory (AD) İçindeki Certificate Authorities (CAs)

AD CS, bir AD forest içindeki CA certificate'larını belirlenmiş container'lar üzerinden tanır; her biri farklı roller üstlenir:

- **Certification Authorities** container'ı, güvenilen root CA certificate'larını tutar.
- **Enrolment Services** container'ı, Enterprise CAs ve bunların certificate template'leri hakkında ayrıntı içerir.
- **NTAuthCertificates** object'i, AD authentication için yetkilendirilmiş CA certificate'larını içerir.
- **AIA (Authority Information Access)** container'ı, intermediate ve cross CA certificate'larıyla certificate chain validation'ı kolaylaştırır.

### Certificate Acquisition: Client Certificate Request Flow

1. Request süreci, client'ların bir Enterprise CA bulmasıyla başlar.
2. Bir public-private key pair oluşturulduktan sonra, public key ve diğer ayrıntıları içeren bir CSR oluşturulur.
3. CA, CSR'yi mevcut certificate template'lerle karşılaştırarak değerlendirir ve certificate'ı template'in permissions'larına göre verir.
4. Onay üzerine, CA certificate'ı kendi private key'i ile imzalar ve client'a geri döner.

### Certificate Templates

AD içinde tanımlanan bu template'ler, certificate issuance için settings ve permissions'ları özetler; buna izin verilen EKU'lar ve enrollment veya modification rights dahildir ve certificate services erişimini yönetmek için kritiktir.

**Template schema version matters.** Eski **v1** template'ler (örneğin, yerleşik **WebServer** template'i) birkaç modern enforcement knob'undan yoksundur. **ESC15/EKUwu** araştırması, **v1 template'ler** üzerinde bir requester'ın CSR içine, template'in yapılandırılmış EKU'larına **tercih edilen** **Application Policies/EKUs** gömebileceğini gösterdi; bu da yalnızca enrollment rights ile client-auth, enrollment agent veya code-signing certificate'ları etkinleştirir. **v2/v3 template'leri** tercih edin, v1 varsayılanlarını kaldırın veya onların yerine geçin ve EKU'ları sıkı şekilde amaçlanan kullanıma göre sınırlandırın.

## Certificate Enrollment

Certificate'lar için enrollment süreci, bir administrator'ın bir **certificate template** oluşturmasıyla başlatılır; ardından bu template bir Enterprise Certificate Authority (CA) tarafından **published** edilir. Bu, template'i client enrollment için kullanılabilir hale getirir; bu adım, template'in adını bir Active Directory object'inin `certificatetemplates` field'ına ekleyerek gerçekleştirilir.

Bir client'ın bir certificate talep edebilmesi için **enrollment rights** verilmiş olmalıdır. Bu rights, certificate template ve Enterprise CA'nın kendisi üzerindeki security descriptor'lar tarafından tanımlanır. Request'in başarılı olması için permissions her iki konumda da verilmelidir.

### Template Enrollment Rights

Bu rights, Access Control Entries (ACEs) aracılığıyla belirtilir ve aşağıdaki gibi permissions'ları tanımlar:

- Belirli GUID'lerle ilişkilendirilen **Certificate-Enrollment** ve **Certificate-AutoEnrollment** rights.
- Tüm extended permissions'ları sağlayan **ExtendedRights**.
- Template üzerinde tam kontrol sağlayan **FullControl/GenericAll**.

### Enterprise CA Enrollment Rights

CA'nın rights'ları, Certificate Authority management console üzerinden erişilebilen security descriptor'ında tanımlanır. Hatta bazı ayarlar, düşük ayrıcalıklı kullanıcıların remote access elde etmesine izin verir; bu da bir security concern olabilir.

### Additional Issuance Controls

Aşağıdaki gibi bazı controls uygulanabilir:

- **Manager Approval**: Request'leri bir certificate manager tarafından onaylanana kadar pending durumda tutar.
- **Enrolment Agents and Authorized Signatures**: Bir CSR üzerindeki gerekli signature sayısını ve gerekli Application Policy OID'lerini belirtir.

### Methods to Request Certificates

Certificate'lar şu yollarla talep edilebilir:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces kullanarak.
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes veya TCP/IP üzerinden.
3. Certificate Authority Web Enrollment role'ü kurulu olduğunda, **certificate enrollment web interface**.
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service ile birlikte.
5. Network device'lar için, **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) kullanarak.

Windows kullanıcıları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) ya da command-line tools (`certreq.exe` veya PowerShell'in `Get-Certificate` command'ı) üzerinden certificate talep edebilir.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD), temel olarak **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak certificate authentication destekler.

### Kerberos Authentication Process

Kerberos authentication sürecinde, bir kullanıcının Ticket Granting Ticket (TGT) isteği, kullanıcının certificate’inin **private key**’i kullanılarak imzalanır. Bu istek, domain controller tarafından certificate’in **validity**’si, **path**’i ve **revocation status**’u dahil olmak üzere birkaç validation’dan geçer. Validation’lar ayrıca certificate’in trusted bir kaynaktan geldiğini doğrulamayı ve issuer’ın **NTAUTH certificate store** içinde bulunduğunu onaylamayı da içerir. Başarılı validation’lar bir TGT verilmesiyle sonuçlanır. AD içindeki **`NTAuthCertificates`** object’i, şurada bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is certificate authentication için güven kurmanın merkezindedir.

**KB5014754** dağıtımından bu yana, modern Kerberos certificate auth büyük ölçüde **mapping strength** ile ilgilidir, sadece EKU’larla değil. Hardened forests içinde:

- Sadece **UPN/DNS SAN** içeren bir certificate artık logon için yeterli olmayabilir.
- KDC, genellikle **SID security extension** (`1.3.6.1.4.1.311.25.2`) veya `altSecurityIdentities` içinde güçlü bir explicit mapping olan **strong binding**’i tercih eder.
- Cert güçlü bir mapping içermiyorsa, DC’ler compatibility mode’da **Kdcsvc Event ID 39/41** loglar ve enforcement mode’da auth’ı reddeder.
- Mixed attack paths içinde **ESC9/ESC16** önemlidir çünkü issued cert’lerden SID extension’ı kaldırırlar; operator’lar ardından explicit mappings’e veya attack path destekliyorsa SAN URL SID formatlarına güvenir.

### Secure Channel (Schannel) Authentication

Schannel, secure TLS/SSL bağlantılarını sağlar; handshake sırasında client, başarıyla doğrulanırsa erişim yetkisi veren bir certificate sunar. Bir certificate’in bir AD account’a mapping’i, diğer yöntemlerin yanı sıra Kerberos’un **S4U2Self** fonksiyonunu veya certificate’in **Subject Alternative Name (SAN)** alanını içerebilir.

Schannel aynı zamanda **PKINIT** kullanılamadığında pratik fallback’tir. Örneğin, bir domain controller uygun bir **Smart Card Logon** certificate’ına sahip değilse, `certipy auth`/PKINIT tooling bir TGT almada başarısız olabilir; ancak aynı certificate yine de authentication ve LDAP operations için **LDAPS** veya **LDAP StartTLS** karşısında kullanılabilir durumda olabilir.

### AD Certificate Services Enumeration

AD'nin certificate services’i LDAP queries aracılığıyla enumerate edilebilir; bu da **Enterprise Certificate Authorities (CAs)** ve onların configurations hakkında bilgi açığa çıkarır. Buna, özel ayrıcalıklar olmadan herhangi bir domain-authenticated user erişebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi tools, AD CS ortamlarında enumeration ve vulnerability assessment için kullanılır.

Bu tools’u kullanmak için komutlar şunları içerir:
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

## Son Güvenlik Açıkları & Güvenlik Güncellemeleri (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT sırasında makine hesabı sertifikalarını taklit ederek *Privilege escalation*. | Yama **10 Mayıs 2022** güvenlik güncellemelerine dahildir. Denetim ve güçlü eşleme kontrolleri **KB5014754** ile getirildi; ortamlar artık *Full Enforcement* modunda olmalıdır.  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) ve CES rollerinde *Remote code-execution*. | Public PoC’ler sınırlıdır, ancak vulnerable IIS bileşenleri çoğu zaman dahili olarak açıktır. Yama, **Temmuz 2023** Patch Tuesday sürümündedir.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** üzerinde, enrollment rights sahibi bir requester CSR içine template EKU’lerinden önce tercih edilen **Application Policies/EKUs** gömebilir; bu da client-auth, enrollment agent veya code-signing sertifikaları üretir. | **12 Kasım 2024** itibarıyla yamalandı. v1 templates’leri (ör. varsayılan WebServer) değiştirin veya geçersiz kılın, EKU’leri amaca göre kısıtlayın ve enrollment rights’ları sınırlayın. |

### Microsoft hardening zaman çizelgesi (KB5014754)

Microsoft, zayıf implicit mappings’den Kerberos certificate authentication’ı uzaklaştırmak için üç aşamalı bir dağıtım (Compatibility → Audit → Enforcement) başlattı. **11 Şubat 2025** itibarıyla, `StrongCertificateBindingEnforcement` registry değeri ayarlı değilse domain controller’lar otomatik olarak **Full Enforcement** moduna geçer. Microsoft daha sonra zaman çizelgesini güncelledi; böylece **9 Eylül 2025** security update’ine kadar compatibility mode’a geri dönüş mümkün olmaya devam eder. Yöneticiler şunları yapmalıdır:

1. Tüm DC’leri & AD CS server’larını yamalayın (Mayıs 2022 veya sonrası).
2. *Audit* aşamasında zayıf mappings için Event ID 39/41’i izleyin.
3. Enforcement zayıf mappings’i engellemeden önce client-auth sertifikalarını yeni **SID extension** ile yeniden verin veya güçlü manual mappings yapılandırın.

### Hardened forest’lar için operator notları

- **ESC1/ESC6 tek başına artık tüm hikaye değil** 2025+ ortamlarında. Başka bir principal için sertifika talep ediyorsanız, genellikle SID extension gibi güçlü bir mapping artifact’i veya explicit bir mapping de gerekir.
- **ESC15 (EKUwu)** çoğunlukla yamalanmamış ortamlarda değerlidir; çünkü zararsız **v1** templates’leri, örneğin **WebServer**’ı, **Application Policies** enjekte ederek authentication- veya enrollment-agent-capable sertifikalara dönüştürür. Kerberos PKINIT hâlâ EKU’leri değerlendirir, ancak **LDAP Schannel** de Application Policies’i kabul eder; bu da LDAP tabanlı abuse’u geçerli tutar.
- **ESC16** CA-genel bir ayardır: CA SID security extension’ı global olarak devre dışı bırakırsa, attack chain supported başka bir formatla SID enjekte etmedikçe verilen her sertifika daha zayıf mapping davranışına geri döner.

---

## Detection & Hardening İyileştirmeleri

* **Defender for Identity AD CS sensor (2023-2024)** artık ESC1-ESC8/ESC11 için posture assessments gösterir ve *“Domain-controller certificate issuance for a non-DC”* (ESC8) ile *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15) gibi gerçek zamanlı uyarılar üretir. Bu tespitlerden yararlanmak için sensörlerin tüm AD CS server’larına dağıtıldığından emin olun.
* Tüm templates üzerinde **“Supply in the request”** seçeneğini devre dışı bırakın veya çok sıkı kapsamlandırın; açıkça tanımlanmış SAN/EKU değerlerini tercih edin.
* Kesinlikle gerekli olmadıkça templates’lerden **Any Purpose** veya **No EKU** kaldırın (ESC2 senaryolarını ele alır).
* Hassas templates için **manager approval** veya özel Enrollment Agent iş akışları gerektirin (ör. WebServer / CodeSigning).
* Web enrollment (`certsrv`) ve CES/NDES endpoint’lerini güvenilir ağlarla sınırlayın veya client-certificate authentication arkasına alın.
* RPC enrollment şifrelemesini etkinleştirin (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) ki ESC11 (RPC relay) azaltılsın. Bu bayrak varsayılan olarak **açık** gelir, ancak çoğu zaman legacy clients için devre dışı bırakılır; bu da relay riskini yeniden açar.
* **IIS-based enrollment endpoints** (CES/Certsrv) güvenliğini sağlayın: mümkünse NTLM’i devre dışı bırakın veya ESC8 relay’lerini engellemek için HTTPS + Extended Protection zorunlu kılın.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
