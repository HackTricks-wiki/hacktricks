# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- Sertifikanın **Subject** alanı sahibini belirtir.
- **Public Key**, sertifikayı doğru sahibiyle ilişkilendirmek için gizli tutulan bir anahtarla eşleştirilir.
- **NotBefore** ve **NotAfter** tarihleriyle tanımlanan **Validity Period**, sertifikanın geçerli olduğu süreyi belirtir.
- Certificate Authority (CA) tarafından sağlanan benzersiz bir **Serial Number**, her sertifikayı tanımlar.
- **Issuer**, sertifikayı veren CA'yı belirtir.
- **SubjectAlternativeName**, subject için ek adlar tanımlayarak kimlik belirleme esnekliğini artırır.
- **Basic Constraints**, sertifikanın bir CA'ya mı yoksa bir son kullanıcı varlığına mı ait olduğunu belirler ve kullanım kısıtlamalarını tanımlar.
- **Extended Key Usages (EKUs)**, Object Identifier'lar (OID'ler) aracılığıyla kod imzalama veya e-posta şifreleme gibi sertifikanın özel kullanım amaçlarını tanımlar.
- **Signature Algorithm**, sertifikayı imzalamak için kullanılan yöntemi belirtir.
- Issuer'ın özel anahtarıyla oluşturulan **Signature**, sertifikanın gerçekliğini garanti eder.<sup>[[4]](#references)</sup>

### Özel Hususlar

- **Subject Alternative Names (SANs)**, bir sertifikanın birden fazla kimlik için kullanılabilmesini sağlar. Bu, birden fazla etki alanına sahip sunucular için önemlidir. Saldırganların SAN tanımını manipüle ederek kimliğe bürünme riskini önlemek için güvenli sertifika verme süreçleri kritik öneme sahiptir.<sup>[[4]](#references)</sup>

### Active Directory'deki (AD) Certificate Authority'ler (CA'ler)

AD CS, bir AD forest'ındaki CA sertifikalarını, her biri farklı bir işleve sahip belirlenmiş kapsayıcılar aracılığıyla tanır:<sup>[[4]](#references)</sup>

- **Certification Authorities** kapsayıcısı, güvenilen kök CA sertifikalarını barındırır.
- **Enrolment Services** kapsayıcısı, Enterprise CA'leri ve sertifika şablonlarını listeler.
- **NTAuthCertificates** nesnesi, AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Authority Information Access)** kapsayıcısı, ara CA ve çapraz CA sertifikalarıyla sertifika zinciri doğrulamasını sağlar.

### Sertifika Edinme: İstemci Sertifika İsteği Akışı

1. İstek süreci, istemcilerin bir Enterprise CA bulmasıyla başlar.
2. Bir public-private key pair oluşturulduktan sonra, public key ve diğer ayrıntıları içeren bir CSR oluşturulur.
3. CA, CSR'yi mevcut sertifika şablonlarına göre değerlendirir ve şablonun izinlerine göre sertifikayı verir.
4. Onaylandıktan sonra CA, sertifikayı özel anahtarıyla imzalar ve istemciye geri gönderir.<sup>[[4]](#references)</sup>

### Sertifika Şablonları

AD'de tanımlanan bu şablonlar, izin verilen EKU'ler ve kayıt veya değiştirme hakları dahil olmak üzere sertifika verme ayarlarını ve izinlerini belirler. Sertifika hizmetlerine erişimi yönetmek için kritik öneme sahiptirler.<sup>[[4]](#references)</sup>

**Şablon şema sürümü önemlidir.** Eski **v1** şablonlarında (örneğin yerleşik **WebServer** şablonu) modern güvenlik denetimi seçeneklerinin birçoğu bulunmaz. **ESC15/EKUwu** araştırması, **v1 şablonlarında** istekte bulunanın CSR'ye **Application Policies/EKUs** ekleyebildiğini ve bunların şablonda yapılandırılmış EKU'lere **öncelik kazandığını** gösterdi. Bu, yalnızca kayıt haklarıyla client-auth, enrollment agent veya code-signing sertifikaları alınmasını mümkün kılar. **v2/v3 şablonlarını** tercih edin, v1 varsayılanlarını kaldırın veya yenileriyle değiştirin ve EKU'leri amaçlanan kullanımla sıkı biçimde sınırlandırın.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Sertifika kayıt süreci, bir yöneticinin **sertifika şablonu oluşturmasıyla** başlar. Ardından bu şablon bir Enterprise Certificate Authority (CA) tarafından **yayımlanır**. Böylece şablon istemci kaydı için kullanılabilir hale gelir. Bunun için şablonun adı bir Active Directory nesnesinin `certificatetemplates` alanına eklenir.<sup>[[4]](#references)</sup>

İstemcinin sertifika isteyebilmesi için **kayıt hakları** verilmelidir. Bu haklar, sertifika şablonunun ve Enterprise CA'nın güvenlik tanımlayıcılarıyla belirlenir. İsteğin başarılı olması için izinlerin her iki konumda da verilmesi gerekir.

### Şablon Kayıt Hakları

Bu haklar, aşağıdaki gibi izinleri tanımlayan Access Control Entry'ler (ACE'ler) aracılığıyla belirtilir:

- Belirli GUID'lerle ilişkilendirilmiş **Certificate-Enrollment** ve **Certificate-AutoEnrollment** hakları.
- Tüm genişletilmiş izinleri sağlayan **ExtendedRights**.
- Şablon üzerinde tam denetim sağlayan **FullControl/GenericAll**.

### Enterprise CA Kayıt Hakları

CA'nın hakları, Certificate Authority yönetim konsolundan erişilebilen güvenlik tanımlayıcısında belirtilir. Bazı ayarlar, düşük ayrıcalıklı kullanıcıların uzaktan erişmesine bile izin verir; bu da güvenlik riski oluşturabilir.

### Ek Sertifika Verme Denetimleri

Aşağıdakiler gibi belirli denetimler uygulanabilir:

- **Manager Approval**: İstekleri, bir certificate manager onaylayana kadar beklemede tutar.
- **Enrolment Agents and Authorized Signatures**: CSR için gereken imza sayısını ve gerekli Application Policy OID'lerini belirtir.

### Sertifika İsteme Yöntemleri

Sertifikalar şu yollarla istenebilir:

1. DCOM arayüzlerini kullanan **Windows Client Certificate Enrollment Protocol** (MS-WCCE).
2. Named pipe'lar veya TCP/IP üzerinden çalışan **ICertPassage Remote Protocol** (MS-ICPR).
3. Certificate Authority Web Enrollment rolü yüklüyse **certificate enrollment web interface**.
4. **Certificate Enrollment Policy (CEP)** hizmetiyle birlikte kullanılan **Certificate Enrollment Service** (CES).
5. Simple Certificate Enrollment Protocol (SCEP) kullanan ağ cihazları için **Network Device Enrollment Service** (NDES).

Windows kullanıcıları ayrıca GUI (`certmgr.msc` veya `certlm.msc`) ya da komut satırı araçları (`certreq.exe` veya PowerShell'ın `Get-Certificate` komutu) aracılığıyla da sertifika isteyebilir.

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Sertifika Kimlik Doğrulaması

Active Directory (AD), öncelikli olarak **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak sertifika kimlik doğrulamasını destekler.

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, kullanıcının Ticket Granting Ticket (TGT) talebi, kullanıcının sertifikasının **özel anahtarı** kullanılarak imzalanır. Bu talep, etki alanı denetleyicisi tarafından sertifikanın **geçerliliği**, **zinciri** ve **iptal durumu** dahil olmak üzere çeşitli doğrulamalardan geçirilir. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğini teyit etmeyi ve verenin **NTAUTH sertifika deposunda** bulunduğunu doğrulamayı da içerir. Doğrulamalar başarılı olursa bir TGT verilir. AD'deki **`NTAuthCertificates`** nesnesi şu konumda bulunur:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

sertifika kimlik doğrulaması için güven tesis etmenin merkezinde yer alır.<sup>[[4]](#references)</sup>

**KB5014754** dağıtımından bu yana, modern Kerberos sertifika kimlik doğrulaması yalnızca EKU’larla değil, çoğunlukla **eşleştirme gücüyle** ilgilidir.<sup>[[2]](#references)</sup> Güçlendirilmiş forest’larda:

- Yalnızca **UPN/DNS SAN** içeren bir sertifika, oturum açmak için artık yeterli olmayabilir.
- KDC, genellikle **SID security extension** (`1.3.6.1.4.1.311.25.2`) veya `altSecurityIdentities` içindeki güçlü bir açık eşleştirme olan **güçlü bir bağlamayı** tercih eder.
- Sertifikada güçlü bir eşleştirme yoksa DC’ler uyumluluk modunda **Kdcsvc Event ID 39/41** olaylarını kaydeder ve zorunlu kılma modunda kimlik doğrulamayı reddeder.
- Karma saldırı yollarında **ESC9/ESC16** önemlidir; çünkü verilen sertifikalardan SID extension’ı kaldırırlar. Saldırganlar daha sonra, saldırı yolunun desteklediği durumlarda açık eşleştirmelere veya SAN URL SID biçimlerine güvenir.

### Secure Channel (Schannel) Authentication

Schannel, güvenli TLS/SSL bağlantılarını sağlar. El sıkışma sırasında istemci, başarıyla doğrulanırsa erişim yetkisi veren bir sertifika sunar. Bir sertifikanın AD hesabıyla eşleştirilmesinde, diğer yöntemlerin yanı sıra Kerberos’un **S4U2Self** işlevi veya sertifikanın **Subject Alternative Name (SAN)** alanı kullanılabilir.<sup>[[4]](#references)</sup>

**PKINIT** kullanılamadığında Schannel, pratik bir yedek seçenektir. Örneğin, bir domain controller’da uygun bir **Smart Card Logon** sertifikası yoksa `certipy auth`/PKINIT araçları TGT alma işlemini başaramayabilir; ancak aynı sertifika, kimlik doğrulaması ve LDAP işlemleri için **LDAPS** veya **LDAP StartTLS** üzerinden yine de kullanılabilir.

### AD Certificate Services Enumeration

AD’nin sertifika hizmetleri, LDAP sorguları aracılığıyla numaralandırılabilir ve **Enterprise Certificate Authorities (CA’lar)** ile yapılandırmaları hakkındaki bilgiler açığa çıkarılabilir. Bu bilgilere, özel ayrıcalıkları olmayan, domain’de kimliği doğrulanmış tüm kullanıcılar erişebilir. **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar, AD CS ortamlarında numaralandırma ve güvenlik açığı değerlendirmesi için kullanılır.

Bu araçları kullanmaya yönelik komutlar:

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

| Yıl | ID / Ad | Etki | Önemli Çıkarımlar |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT sırasında makine hesabı sertifikalarını taklit ederek *yetki yükseltme*. | Yama, **10 Mayıs 2022** güvenlik güncellemelerine dahildir. Denetim ve güçlü eşleme denetimleri **KB5014754** ile kullanıma sunuldu; ortamlar artık *Full Enforcement* modunda olmalıdır. |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) ve CES rollerinde *uzaktan kod yürütme*. | Herkese açık PoC'ler sınırlıdır; ancak savunmasız IIS bileşenleri çoğunlukla şirket içi ağlarda erişime açıktır. **Temmuz 2023** Patch Tuesday itibarıyla yamalayın. |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 şablonlarında**, kayıt hakkı olan bir başvuru sahibi CSR içine, şablondaki EKU'lardan öncelikli olan **Application Policies/EKUs** değerlerini ekleyebilir; böylece client-auth, enrollment agent veya code-signing sertifikaları oluşturabilir. | **12 Kasım 2024** itibarıyla yamalanmıştır. v1 şablonlarını (ör. varsayılan WebServer) değiştirin veya yenileriyle geçersiz kılın, EKU'ları kullanım amacına göre kısıtlayın ve kayıt haklarını sınırlandırın. |

### Microsoft güçlendirme zaman çizelgesi (KB5014754)

Microsoft, Kerberos sertifika kimlik doğrulamasını zayıf örtük eşlemelerden uzaklaştırmak için üç aşamalı bir geçiş süreci (Compatibility → Audit → Enforcement) başlattı. **11 Şubat 2025** itibarıyla, `StrongCertificateBindingEnforcement` kayıt defteri değeri ayarlanmamışsa etki alanı denetleyicileri otomatik olarak **Full Enforcement** moduna geçer. Microsoft daha sonra zaman çizelgesini güncelleyerek **9 Eylül 2025** güvenlik güncellemesine kadar uyumluluk moduna dönüşün mümkün olmasını sağladı.<sup>[[2]](#references)</sup> Yöneticiler:

1. Tüm DC'leri ve AD CS sunucularını yamalamalıdır (Mayıs 2022 veya sonrası).
2. *Audit* aşamasında zayıf eşlemeler için Event ID 39/41'i izlemelidir.
3. İstemci kimlik doğrulama sertifikalarını yeni **SID extension** ile yeniden vermeli veya enforcement zayıf eşlemeleri engellemeden önce güçlü manuel eşlemeler yapılandırmalıdır.

### Güçlendirilmiş ormanlar için operatör notları

- 2025 ve sonrasındaki ortamlarda **tek başına ESC1/ESC6 artık tüm hikâye değildir**. Başka bir principal için sertifika talep ediyorsanız genellikle SID extension veya açık bir eşleme gibi güçlü bir eşleme öğesine de ihtiyacınız vardır.
- **ESC15 (EKUwu)**, çoğunlukla yamalanmamış ortamlarda işe yarar; **Application Policies** enjekte ederek **WebServer** gibi zararsız **v1** şablonlarını kimlik doğrulama veya enrollment agent özelliğine sahip sertifikalara dönüştürür. Kerberos PKINIT, EKU'ları değerlendirmeye devam eder; ancak **LDAP Schannel** da Application Policies değerlerini dikkate alır ve bu da LDAP tabanlı kötüye kullanımı hâlâ mümkün kılar.<sup>[[1]](#references)</sup>
- **ESC16**, CA genelinde geçerli bir ayardır: CA, SID security extension'ı genel olarak devre dışı bırakırsa saldırı zinciri desteklenen başka bir biçimle SID eklemediği sürece verilen tüm sertifikalar daha zayıf eşleme davranışına yönelir.
- **ESC7 hakları birbirinden farklıdır:** CA üzerindeki `ManageCA` izni, `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) gibi ayarlarda değişiklik yapılmasına olanak tanıyabilir; `ManageCertificates` ise istek onayını yönetir. Sertifika yöneticisi haklarında açık bir Deny, Allow izni de bulunsa bu onay yolunu engelleyebilir; ayarları ve şablonları zincirlemeden önce etkin CA ACL'ini değerlendirin. Bkz. [Microsoft'un CA ACL değerlendirmesi](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Tespit ve Güçlendirme İyileştirmeleri

* **Defender for Identity AD CS sensor (2023-2024)** artık ESC1-ESC8/ESC11 için güvenlik durumu değerlendirmeleri sunuyor ve *“Domain-controller certificate issuance for a non-DC”* (ESC8) ile *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15) gibi gerçek zamanlı uyarılar oluşturuyor. Bu tespitlerden yararlanmak için tüm AD CS sunucularına sensor'ları dağıtın.<sup>[[3]](#references)</sup>
* Tüm şablonlarda **“Supply in the request”** seçeneğini devre dışı bırakın veya kapsamını sıkı biçimde sınırlandırın; SAN/EKU değerlerini açıkça tanımlamayı tercih edin.
* Mutlaka gerekli olmadıkça şablonlardan **Any Purpose** veya **No EKU** değerlerini kaldırın (ESC2 senaryolarını ele alır).
* Hassas şablonlar (ör. WebServer / CodeSigning) için **manager approval** veya özel Enrollment Agent iş akışları zorunlu kılın.
* Web enrollment (`certsrv`) ve CES/NDES uç noktalarını güvenilir ağlarla veya istemci sertifikası kimlik doğrulamasının arkasında sınırlandırın.
* ESC11'i (RPC relay) azaltmak için RPC enrollment şifrelemesini zorunlu kılın (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`). Bu ayar varsayılan olarak **açıktır**, ancak eski istemciler için sıklıkla devre dışı bırakılır ve relay riskini yeniden ortaya çıkarır.
* **IIS tabanlı enrollment uç noktalarını** (CES/Certsrv) güvenli hâle getirin: mümkünse NTLM'yi devre dışı bırakın veya ESC8 relay'lerini engellemek için HTTPS + Extended Protection zorunlu kılın.

ESC11'i CA'nın çalıştığı ana bilgisayarda değerlendirin; bu ana bilgisayar etki alanı denetleyicisi yerine etki alanına üye bir sunucu olabilir. Etkin CA'nın `InterfaceFlags` değerini `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` altında okuyun; okunamayan veya bulunmayan bir değer, RPC şifrelemesinin devre dışı olduğunun kanıtı değil, bilinmeyen bir sonuçtur. `IF_ENFORCEENCRYPTICERTREQUEST` bitinin ayarlı olmaması, yine de erişilebilir bir enrollment RPC uç noktası, kimlik bilgileri elde etmeye elverişli bir yöntem ve kullanılabilir bir sertifika şablonu gerektiren bir yapılandırma ipucudur. ESC8 için yalnızca HTTP NTLM challenge bulunması yeterli değildir: çalışan bir enrollment uç noktasının bulunduğunu doğrulayın.

---

## References

- [1] [EKUwu: Sıradan bir AD CS ESC'den ibaret değil](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows etki alanı denetleyicilerinde sertifika tabanlı kimlik doğrulama değişiklikleri](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Sertifika güvenlik durumu değerlendirmeleri - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services'in kötüye kullanılması](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
