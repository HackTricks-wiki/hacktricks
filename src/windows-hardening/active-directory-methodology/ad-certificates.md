# AD Sertifikaları

{{#include ../../banners/hacktricks-training.md}}

## Giriş

### Bir Sertifikanın Bileşenleri

- Bir sertifikanın **Subject** alanı sahibini belirtir.
- Bir **Public Key**, sertifikayı gerçek sahibine bağlamak için özel (private) bir anahtarla eşleştirilir.
- **Validity Period**, **NotBefore** ve **NotAfter** tarihleriyle tanımlanır ve sertifikanın geçerli olduğu zamanı gösterir.
- Her sertifikayı tanımlayan benzersiz bir **Serial Number**, Certificate Authority (CA) tarafından sağlanır.
- **Issuer**, sertifikayı veren CA'yı ifade eder.
- **SubjectAlternativeName** konu için ek adlar sağlayarak tanımlama esnekliğini artırır.
- **Basic Constraints** sertifikanın bir CA mı yoksa uç varlık (end entity) için mi olduğunu ve kullanım kısıtlamalarını tanımlar.
- **Extended Key Usages (EKUs)**, Object Identifier (OID) aracılığıyla sertifikanın belirli amaçlarını (ör. code signing, e-posta şifreleme) sınırlar.
- **Signature Algorithm** sertifikayı imzalama yöntemini belirtir.
- **Signature**, issuer'ın private key'iyle oluşturulur ve sertifikanın özgünlüğünü garanti eder.

### Özel Hususlar

- **Subject Alternative Names (SANs)** bir sertifikanın birden fazla kimliğe uygulanmasını sağlar; çoklu alan adlarına sahip sunucular için kritiktir. SAN tanımının kötüye kullanılarak taklit riskini önlemek için güvenli bir issuance süreci şarttır.

### Active Directory (AD) İçindeki Certificate Authorities (CAs)

AD CS, bir AD forest içinde CA sertifikalarını belirli konteynerler aracılığıyla tanır; her biri farklı roller üstlenir:

- **Certification Authorities** container'ı güvenilen root CA sertifikalarını barındırır.
- **Enrolment Services** container'ı Enterprise CA'ları ve onların certificate template'lerini açıklar.
- **NTAuthCertificates** nesnesi AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Authority Information Access)** container'ı, ara ve cross CA sertifikaları ile sertifika zinciri doğrulamasını kolaylaştırır.

### Sertifika Edinimi: İstemci Sertifika Talep Akışı

1. İstek süreci, istemcilerin bir Enterprise CA bulmasıyla başlar.
2. Bir public-private anahtar çifti oluşturulduktan sonra, public key ve diğer bilgiler içeren bir CSR oluşturulur.
3. CA, CSR'yi mevcut certificate template'lere göre değerlendirir ve template izinlerine göre sertifikayı verir.
4. Onaylandığında, CA sertifikayı kendi private key'i ile imzalar ve istemciye geri gönderir.

### Certificate Templates

AD içinde tanımlanan bu template'ler, sertifika verme ayarlarını ve izinlerini (izin verilen EKU'lar, enrollment veya modification hakları gibi) belirler ve sertifika hizmetlerine erişimi yönetmek için kritik öneme sahiptir.

**Template schema version matters.** Legacy **v1** template'ler (ör. yerleşik **WebServer** template'i) birçok modern enforcement seçeneğinden yoksundur. **ESC15/EKUwu** araştırması, **v1 template'lerde** bir istekte bulunanın CSR içine template'in yapılandırdığı EKU'lardan **daha öncelikli** olarak **Application Policies/EKU** ekleyebildiğini; bunun sadece enrollment hakkına sahipken client-auth, enrollment agent veya code-signing sertifikaları edinmeye izin verebildiğini göstermiştir. Mümkünse **v2/v3 template'leri** tercih edin, v1 varsayılanlarını kaldırın veya geçersiz kılın ve EKU'ları amaçlanan kullanım için sıkı bir şekilde sınırlandırın.

## Sertifika Enrollment (Kayıt) Süreci

Sertifika enrollment süreci, bir yönetici tarafından **certificate template** oluşturulmasıyla başlatılır; bu template daha sonra bir Enterprise Certificate Authority (CA) tarafından **publish** edilir. Bu, template'in istemci enrollment'larına açık hale gelmesini sağlar; bu adım, template adının bir Active Directory nesnesinin `certificatetemplates` alanına eklenmesiyle gerçekleştirilir.

Bir istemcinin sertifika talep edebilmesi için **enrollment rights** verilmiş olmalıdır. Bu haklar certificate template üzerindeki ve Enterprise CA'nın kendisindeki security descriptor'lar tarafından tanımlanır. Bir isteğin başarılı olması için izinler her iki yerde de verilmiş olmalıdır.

### Template Enrollment Hakları

Bu haklar Access Control Entries (ACE'ler) aracılığıyla belirtilir ve aşağıdaki izinleri içerir:

- **Certificate-Enrollment** ve **Certificate-AutoEnrollment** hakları, her biri belirli GUID'lerle ilişkilidir.
- **ExtendedRights**, tüm genişletilmiş izinlere izin verir.
- **FullControl/GenericAll**, template üzerinde tam kontrol sağlar.

### Enterprise CA Enrollment Hakları

CA'nın hakları, Certificate Authority yönetim konsolu üzerinden erişilebilen security descriptor içinde belirtilir. Bazı ayarlar düşük ayrıcalıklı kullanıcıların uzaktan erişimine izin verecek şekilde yapılandırılabilir; bu bir güvenlik sorunu teşkil edebilir.

### Ek İssuance Kontrolleri

Bazı kontroller uygulanabilir, örneğin:

- **Manager Approval**: İstekleri, bir certificate manager onaylayana kadar beklemede (pending) tutar.
- **Enrolment Agents and Authorized Signatures**: Bir CSR üzerindeki gerekli imza sayısını ve gerekli Application Policy OID'lerini belirtir.

### Sertifika Talep Etme Yöntemleri

Sertifikalar aşağıdaki yollarla talep edilebilir:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM arayüzleri kullanılarak.
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipe'lar veya TCP/IP üzerinden.
3. Certificate Authority Web Enrollment rolü yüklüyken **certificate enrollment web interface**.
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) servisi ile birlikte.
5. Ağ cihazları için **Network Device Enrollment Service** (NDES) kullanılarak, Simple Certificate Enrollment Protocol (SCEP) ile.

Windows kullanıcıları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) veya komut satırı araçları (`certreq.exe` veya PowerShell'in `Get-Certificate` komutu) aracılığıyla sertifika talep edebilirler.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifika Kimlik Doğrulama

Active Directory (AD) sertifika ile kimlik doğrulamayı destekler; öncelikle **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanır.

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, bir kullanıcının Ticket Granting Ticket (TGT) talebi, kullanıcının sertifikasının **özel anahtarı** ile imzalanır. Bu istek, domain controller tarafından sertifikanın **geçerliliği**, **zinciri** ve **iptal durumu** dahil olmak üzere bir dizi doğrulamadan geçirilir. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğini ve düzenleyicinin **NTAUTH certificate store** içinde bulunduğunu teyit etmeyi kapsar. Başarılı doğrulamalar TGT'nin verilmesiyle sonuçlanır. AD'deki **`NTAuthCertificates`** nesnesi, şu konumda bulunur:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
Sertifika kimlik doğrulaması için güvenin tesisinde merkezi öneme sahiptir.

### Secure Channel (Schannel) Kimlik Doğrulama

Schannel, güvenli TLS/SSL bağlantılarını kolaylaştırır; el sıkışma sırasında istemci bir sertifika sunar ve bu sertifika başarıyla doğrulanırsa erişime izin verilir. Bir sertifikanın bir AD hesabına eşlenmesi, diğer yöntemlerin yanı sıra Kerberos’un **S4U2Self** işlevini veya sertifikanın **Subject Alternative Name (SAN)**'ını içerebilir.

### AD Sertifika Hizmetleri Keşfi

AD'nin sertifika hizmetleri LDAP sorguları aracılığıyla keşfedilebilir; bu, **Enterprise Certificate Authorities (CAs)** ve yapılandırmaları hakkında bilgi açığa çıkarır. Bu, özel ayrıcalık gerektirmeden etki alanı tarafından kimlik doğrulanmış herhangi bir kullanıcı tarafından erişilebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar AD CS ortamlarında keşif ve güvenlik açığı değerlendirmesi için kullanılır.

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
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Recent Vulnerabilities & Security Updates (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is included in the **May 10 2022** security updates. Auditing & strong-mapping controls were introduced via **KB5014754**; environments should now be in *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Public PoCs are limited, but the vulnerable IIS components are often exposed internally. Patch as of **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched as of **November 12, 2024**. Replace or supersede v1 templates (e.g., default WebServer), restrict EKUs to intent, and limit enrollment rights. |

### Microsoft hardening timeline (KB5014754)

Microsoft introduced a three-phase rollout (Compatibility → Audit → Enforcement) to move Kerberos certificate authentication away from weak implicit mappings. As of **February 11 2025**, domain controllers automatically switch to **Full Enforcement** if the `StrongCertificateBindingEnforcement` registry value is not set. Administrators should:

1. Patch all DCs & AD CS servers (May 2022 or later).
2. Monitor Event ID 39/41 for weak mappings during the *Audit* phase.
3. Re-issue client-auth certificates with the new **SID extension** or configure strong manual mappings before February 2025.

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** now surfaces posture assessments for ESC1-ESC8/ESC11 and generates real-time alerts such as *“Domain-controller certificate issuance for a non-DC”* (ESC8) and *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Ensure sensors are deployed to all AD CS servers to benefit from these detections.
* Disable or tightly scope the **“Supply in the request”** option on all templates; prefer explicitly defined SAN/EKU values.
* Remove **Any Purpose** or **No EKU** from templates unless absolutely required (addresses ESC2 scenarios).
* Require **manager approval** or dedicated Enrollment Agent workflows for sensitive templates (e.g., WebServer / CodeSigning).
* Restrict web enrollment (`certsrv`) and CES/NDES endpoints to trusted networks or behind client-certificate authentication.
* Enforce RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) to mitigate ESC11 (RPC relay). The flag is **on by default**, but is often disabled for legacy clients, which re-opens relay risk.
* Secure **IIS-based enrollment endpoints** (CES/Certsrv): disable NTLM where possible or require HTTPS + Extended Protection to block ESC8 relays.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
