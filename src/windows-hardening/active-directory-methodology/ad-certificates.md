# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- Sertifikanın **Subject** alanı sahibini belirtir.
- **Public Key**, sertifikayı gerçek sahibiyle ilişkilendirmek için özel olarak tutulan bir anahtarla eşleştirilir.
- **Validity Period**, **NotBefore** ve **NotAfter** tarihleriyle tanımlanır ve sertifikanın geçerli olduğu süreyi gösterir.
- Certificate Authority (CA) tarafından sağlanan benzersiz bir **Serial Number**, her sertifikayı tanımlar.
- **Issuer**, sertifikayı veren CA'yı ifade eder.
- **SubjectAlternativeName**, subject için ek adlar tanımlayarak kimlik belirleme esnekliğini artırır.
- **Basic Constraints**, sertifikanın bir CA'ya mı yoksa bir son varlığa mı ait olduğunu belirtir ve kullanım kısıtlamalarını tanımlar.
- **Extended Key Usages (EKUs)**, Object Identifiers (OIDs) aracılığıyla sertifikanın kod imzalama veya e-posta şifreleme gibi belirli amaçlarını tanımlar.
- **Signature Algorithm**, sertifikayı imzalamak için kullanılan yöntemi belirtir.
- Issuer'ın özel anahtarıyla oluşturulan **Signature**, sertifikanın gerçekliğini garanti eder.<sup>[[4]](#references)</sup>

### Special Considerations

- **Subject Alternative Names (SANs)**, bir sertifikanın birden fazla kimlikte kullanılabilmesini sağlar. Bu, birden fazla etki alanına sahip sunucular için önemlidir. Saldırganların SAN tanımını manipüle ederek kimliğe bürünme riski oluşturmasını önlemek için güvenli sertifika verme süreçleri kritik öneme sahiptir.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS, bir AD forest'taki CA sertifikalarını, her biri farklı bir amaca hizmet eden belirlenmiş container'lar aracılığıyla tanır:<sup>[[4]](#references)</sup>

- **Certification Authorities** container'ı, güvenilen root CA sertifikalarını barındırır.
- **Enrolment Services** container'ı, Enterprise CA'ları ve sertifika template'lerini listeler.
- **NTAuthCertificates** object'i, AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Authority Information Access)** container'ı, ara CA ve çapraz CA sertifikalarıyla sertifika zinciri doğrulamasını kolaylaştırır.

### Certificate Acquisition: Client Certificate Request Flow

1. İstemcilerin bir Enterprise CA bulmasıyla istek süreci başlar.
2. Bir public-private key pair oluşturulduktan sonra, public key ve diğer bilgileri içeren bir CSR oluşturulur.
3. CA, CSR'yi mevcut sertifika template'lerine göre değerlendirir ve template'in izinlerine göre sertifikayı verir.
4. Onaylandıktan sonra CA, sertifikayı özel anahtarıyla imzalar ve istemciye geri gönderir.<sup>[[4]](#references)</sup>

### Certificate Templates

AD içinde tanımlanan bu template'ler, izin verilen EKU'lar ile enrollment veya değişiklik hakları dahil olmak üzere sertifika verme ayarlarını ve izinlerini belirler. Sertifika hizmetlerine erişimi yönetmek için kritik öneme sahiptirler.<sup>[[4]](#references)</sup>

**Template şema sürümü önemlidir.** Eski **v1** template'lerinde (örneğin, yerleşik **WebServer** template'i) modern zorunlu kılma seçeneklerinin birçoğu bulunmaz. **ESC15/EKUwu** araştırması, **v1 template'lerinde** istekte bulunanın CSR'ye eklediği **Application Policies/EKU'ların**, template'te yapılandırılmış EKU'lara **tercih edilebildiğini** gösterdi. Bu sayede yalnızca enrollment haklarıyla client-auth, enrollment agent veya code-signing sertifikaları alınabilir. **v2/v3 template'lerini** tercih edin, varsayılan v1 template'lerini kaldırın veya onların yerine yenilerini kullanın ve EKU'ları amaçlanan kullanımla sınırlayın.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Sertifika enrollment süreci, bir yöneticinin **certificate template oluşturmasıyla** başlar. Ardından bu template bir Enterprise Certificate Authority (CA) tarafından **yayımlanır**. Böylece template istemci enrollment işlemlerinde kullanılabilir hale gelir. Bunun için template'in adı bir Active Directory object'inin `certificatetemplates` alanına eklenir.<sup>[[4]](#references)</sup>

Bir istemcinin sertifika isteyebilmesi için **enrollment haklarının** verilmiş olması gerekir. Bu haklar, sertifika template'i ve Enterprise CA'nın kendisi üzerindeki security descriptor'larda tanımlanır. İsteğin başarılı olması için her iki konumda da izin verilmelidir.

### Template Enrollment Rights

Bu haklar, aşağıdakiler gibi izinleri belirten Access Control Entries (ACE'ler) aracılığıyla tanımlanır:

- **Certificate-Enrollment** ve **Certificate-AutoEnrollment** hakları; her biri belirli GUID'lerle ilişkilidir.
- Tüm genişletilmiş izinlere olanak tanıyan **ExtendedRights**.
- Template üzerinde tam denetim sağlayan **FullControl/GenericAll**.

### Enterprise CA Enrollment Rights

CA'nın hakları, Certificate Authority yönetim konsolu üzerinden erişilebilen security descriptor'ında belirtilir. Bazı ayarlar, düşük ayrıcalıklı kullanıcılara uzaktan erişim bile sağlayabilir; bu bir güvenlik sorunu oluşturabilir.

### Additional Issuance Controls

Aşağıdakiler gibi belirli denetimler uygulanabilir:

- **Manager Approval**: İstekleri, bir certificate manager onaylayana kadar bekleme durumunda tutar.
- **Enrolment Agents and Authorized Signatures**: Bir CSR için gereken imza sayısını ve gerekli Application Policy OID'lerini belirtir.

### Methods to Request Certificates

Sertifikalar şu yollarla istenebilir:

1. DCOM interface'lerini kullanan **Windows Client Certificate Enrollment Protocol** (MS-WCCE).
2. Named pipe'lar veya TCP/IP üzerinden **ICertPassage Remote Protocol** (MS-ICPR).
3. Certificate Authority Web Enrollment rolü yüklüyse **certificate enrollment web interface**.
4. **Certificate Enrollment Service** (CES) ile birlikte **Certificate Enrollment Policy** (CEP) service'i.
5. Simple Certificate Enrollment Protocol (SCEP) kullanan ağ cihazları için **Network Device Enrollment Service** (NDES).

Windows kullanıcıları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) ya da komut satırı araçları (`certreq.exe` veya PowerShell'deki `Get-Certificate` komutu) aracılığıyla da sertifika isteyebilir.

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Sertifika Kimlik Doğrulaması

Active Directory (AD), öncelikli olarak **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak sertifika kimlik doğrulamasını destekler.

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, kullanıcının Ticket Granting Ticket (TGT) isteği, kullanıcının sertifikasının **private key**'i kullanılarak imzalanır. Bu istek, etki alanı denetleyicisi tarafından sertifikanın **geçerliliği**, **yolu** ve **iptal durumu** dahil olmak üzere çeşitli doğrulamalardan geçirilir. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğini doğrulamayı ve verenin **NTAUTH sertifika deposunda** bulunduğunu teyit etmeyi de içerir. Doğrulamalar başarılı olursa bir TGT verilir. AD'deki **`NTAuthCertificates`** nesnesi şu konumda bulunur:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

sertifika kimlik doğrulaması için güven tesis etmenin temelini oluşturur.<sup>[[4]](#references)</sup>

**KB5014754** dağıtımından bu yana, modern Kerberos sertifika kimlik doğrulaması yalnızca EKU'larla değil, çoğunlukla **eşleme gücüyle** ilgilidir.<sup>[[2]](#references)</sup> Güçlendirilmiş forest'larda:

- Yalnızca **UPN/DNS SAN** taşıyan bir sertifika artık oturum açmak için yeterli olmayabilir.
- KDC, **SID güvenlik uzantısını** (`1.3.6.1.4.1.311.25.2`) veya `altSecurityIdentities` içindeki güçlü bir açık eşlemeyi içeren **güçlü bir bağlamayı** tercih eder.
- Sertifikada güçlü bir eşleme yoksa, DC'ler uyumluluk modunda **Kdcsvc Event ID 39/41** günlüklerini kaydeder ve zorlama modunda kimlik doğrulamayı reddeder.
- Karma saldırı yollarında **ESC9/ESC16** önemlidir; çünkü verilen sertifikalardan SID uzantısını kaldırırlar. Operatörler daha sonra, saldırı yolu destekliyorsa açık eşlemelere veya SAN URL SID biçimlerine güvenir.

### Secure Channel (Schannel) Authentication

Schannel, güvenli TLS/SSL bağlantılarını sağlar. El sıkışma sırasında istemci, başarıyla doğrulanması halinde erişim yetkisi veren bir sertifika sunar. Bir sertifikanın AD hesabıyla eşlenmesi, diğer yöntemlerin yanı sıra Kerberos'un **S4U2Self** işlevini veya sertifikanın **Subject Alternative Name (SAN)** alanını kullanabilir.<sup>[[4]](#references)</sup>

**PKINIT** kullanılamadığında Schannel, pratik bir yedek yöntemdir. Örneğin, bir etki alanı denetleyicisinde uygun bir **Smart Card Logon** sertifikası yoksa `certipy auth`/PKINIT araçları TGT almayı başaramayabilir; ancak aynı sertifika **LDAPS** veya kimlik doğrulama ve LDAP işlemleri için **LDAP StartTLS** üzerinden kullanılabilir.

### AD Certificate Services Enumeration

AD'nin sertifika hizmetleri LDAP sorguları aracılığıyla numaralandırılabilir; bu sayede **Enterprise Certificate Authorities (CA'lar)** ve yapılandırmaları hakkında bilgi edinilebilir. Buna, özel ayrıcalıkları olmayan, etki alanında kimliği doğrulanmış tüm kullanıcılar erişebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar, AD CS ortamlarında numaralandırma ve güvenlik açığı değerlendirmesi için kullanılır.

Bu araçların kullanım komutları şunlardır:

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

## Son Güvenlik Açıkları ve Güvenlik Güncellemeleri (2022-2025)

| Yıl | Kimlik / Ad | Etki | Önemli Çıkarımlar |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT sırasında makine hesabı sertifikalarını taklit ederek *yetki yükseltme*. | Yama, **10 Mayıs 2022** güvenlik güncellemelerine dahil edildi. Denetim ve güçlü eşleme denetimleri **KB5014754** ile sunuldu; ortamlar artık *Full Enforcement* modunda olmalıdır.  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) ve CES rollerinde *uzaktan kod yürütme*. | Herkese açık PoC'ler sınırlı olsa da savunmasız IIS bileşenleri çoğu zaman kurum içinde açıktadır. **Temmuz 2023** Patch Tuesday güncellemesiyle yamalayın.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 şablonlarında**, kayıt hakkına sahip bir istekte bulunan, şablon EKU'larına tercih edilen **Application Policies/EKU'ları** CSR içine ekleyerek istemci kimlik doğrulama, enrollment agent veya kod imzalama sertifikaları oluşturabilir. | **12 Kasım 2024** itibarıyla yamalanmıştır. v1 şablonlarını (ör. varsayılan WebServer) değiştirin veya yenileriyle geçersiz kılın, EKU'ları amaca göre kısıtlayın ve kayıt haklarını sınırlayın. |

### Microsoft'un sağlamlaştırma zaman çizelgesi (KB5014754)

Microsoft, Kerberos sertifika kimlik doğrulamasını zayıf örtük eşlemelerden uzaklaştırmak için üç aşamalı bir dağıtım süreci (Compatibility → Audit → Enforcement) başlattı. **11 Şubat 2025** itibarıyla, `StrongCertificateBindingEnforcement` kayıt defteri değeri ayarlanmamışsa etki alanı denetleyicileri otomatik olarak **Full Enforcement** moduna geçer. Microsoft daha sonra zaman çizelgesini güncelleyerek **9 Eylül 2025** güvenlik güncellemesine kadar uyumluluk moduna geri dönüşün mümkün kalmasını sağladı.<sup>[[2]](#references)</sup> Yöneticiler şunları yapmalıdır:

1. Tüm DC'lere ve AD CS sunucularına Mayıs 2022 veya sonraki yamaları yükleyin.
2. *Audit* aşamasında zayıf eşlemeleri görmek için Event ID 39/41'i izleyin.
3. Uygulama zayıf eşlemeleri engellemeden önce istemci kimlik doğrulama sertifikalarını yeni **SID extension** ile yeniden verin veya güçlü manuel eşlemeler yapılandırın.

### Sağlamlaştırılmış ormanlar için operatör notları

- 2025 ve sonrası ortamlarda **ESC1/ESC6 tek başına artık hikâyenin tamamı değil**. Başka bir principal adına sertifika talep ediyorsanız genellikle SID extension veya açık bir eşleme gibi güçlü bir eşleme öğesine de ihtiyacınız olur.
- **ESC15 (EKUwu)**, çoğunlukla yamalanmamış ortamlarda değerlidir; çünkü **Application Policies** enjekte ederek **WebServer** gibi zararsız **v1** şablonlarını kimlik doğrulama veya enrollment agent yeteneğine sahip sertifikalara dönüştürür. Kerberos PKINIT, EKU'ları değerlendirmeye devam eder; ancak **LDAP Schannel** da Application Policies'i dikkate alır ve bu da LDAP tabanlı kötüye kullanımı geçerli kılar.<sup>[[1]](#references)</sup>
- **ESC16**, CA genelinde geçerli bir ayardır: CA, SID security extension'ı genel olarak devre dışı bırakırsa saldırı zinciri başka bir desteklenen biçimle SID eklemediği sürece verilen tüm sertifikalar daha zayıf eşleme davranışına geri döner.
- **ESC7 hakları birbirinden farklıdır:** CA üzerindeki `ManageCA` izni, `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) gibi ayarlarda değişiklik yapılmasına olanak tanıyabilir; `ManageCertificates` ise istek onayını yönetir. Sertifika yöneticisi haklarına uygulanan açık bir Deny, Allow izni de bulunsa bu onay yolunu engelleyebilir; ayarları ve şablonları bir zincire bağlamadan önce etkin CA ACL'sini değerlendirin. Bkz. [Microsoft'un CA ACL değerlendirmesi](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Tespit ve Sağlamlaştırma İyileştirmeleri

* **Defender for Identity AD CS sensor (2023-2024)** artık ESC1-ESC8/ESC11 için güvenlik duruşu değerlendirmeleri sunuyor ve *“DC olmayan bir sunucu için domain-controller sertifikası verilmesi”* (ESC8) ile *“İsteğe bağlı Application Policies ile sertifika kaydının engellenmesi”* (ESC15) gibi gerçek zamanlı uyarılar oluşturuyor. Bu tespitlerden yararlanmak için sensor'ları tüm AD CS sunucularına dağıtın.<sup>[[3]](#references)</sup>
* Tüm şablonlarda **“Supply in the request”** seçeneğini devre dışı bırakın veya kapsamını sıkı biçimde sınırlayın; açıkça tanımlanmış SAN/EKU değerlerini tercih edin.
* Kesinlikle gerekli olmadıkça şablonlardan **Any Purpose** veya **No EKU** seçeneklerini kaldırın (ESC2 senaryolarını ele alır).
* Hassas şablonlar (ör. WebServer / CodeSigning) için **manager approval** veya özel Enrollment Agent iş akışları zorunlu kılın.
* Web enrollment (`certsrv`) ve CES/NDES uç noktalarını güvenilir ağlarla veya istemci sertifikası kimlik doğrulamasının arkasında sınırlandırın.
* ESC11'i (RPC relay) azaltmak için RPC enrollment şifrelemesini zorunlu kılın (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`). Bu bayrak varsayılan olarak **açıktır**, ancak eski istemciler için sıklıkla devre dışı bırakılır; bu da relay riskini yeniden ortaya çıkarır.
* **IIS tabanlı enrollment uç noktalarını** (CES/Certsrv) güvenli hale getirin: mümkün olduğunda NTLM'yi devre dışı bırakın veya ESC8 relay'lerini engellemek için HTTPS + Extended Protection zorunlu kılın.

ESC11'i CA'nın çalıştığı makinede değerlendirin; bu makine etki alanı denetleyicisi yerine etki alanına üye bir sunucu olabilir. Etkin CA'nın `InterfaceFlags` değerini `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` altında okuyun; okunamayan veya bulunmayan bir değer, RPC şifrelemesinin devre dışı olduğunun kanıtı değil, bilinmeyen bir sonuçtur. `IF_ENFORCEENCRYPTICERTREQUEST` bitinin kapalı olması, erişilebilir bir enrollment RPC uç noktası, kimlik bilgilerini zorlayabilme ve kullanılabilir bir sertifika şablonu gerektiren bir yapılandırma bulgusudur. ESC8 için tek başına bir HTTP NTLM challenge yeterli değildir: çalışan bir enrollment uç noktasının bulunduğunu doğrulayın.

---

## References

- [1] [EKUwu: Yalnızca başka bir AD CS ESC değil](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows etki alanı denetleyicilerinde sertifika tabanlı kimlik doğrulama değişiklikleri](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Sertifikalar güvenlik duruşu değerlendirmeleri - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services'in kötüye kullanılması](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
