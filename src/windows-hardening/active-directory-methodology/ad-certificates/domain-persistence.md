# AD CS Etki Alanı Kalıcılığı

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresinde paylaşılan etki alanı kalıcılığı tekniklerinin bir özetidir**. Daha fazla ayrıntı için kontrol edin.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Bir sertifikanın CA sertifikası olduğunu nasıl anlarsınız?

Bir sertifikanın CA sertifikası olduğu, birkaç koşulun sağlanması durumunda belirlenebilir:

- Sertifika CA sunucusunda depolanmıştır; özel anahtarı makinenin DPAPI'si tarafından veya işletim sistemi destekliyorsa TPM/HSM gibi donanım tarafından korunur.
- Sertifikanın Issuer ve Subject alanlarının her ikisi de CA'nın distinguished name ile eşleşir.
- Sadece CA sertifikalarında "CA Version" uzantısı bulunur.
- Sertifika Extended Key Usage (EKU) alanlarından yoksundur.

Bu sertifikanın özel anahtarını çıkarmak için, CA sunucusundaki `certsrv.msc` aracı yerleşik GUI üzerinden desteklenen yöntemdir. Bununla birlikte, bu sertifika sistemde depolanan diğerlerinden farklı değildir; bu nedenle [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) gibi yöntemler çıkarım için uygulanabilir.

Sertifika ve özel anahtar ayrıca Certipy kullanılarak aşağıdaki komutla elde edilebilir:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA sertifikası ve özel anahtar `.pfx` formatında elde edildikten sonra, [ForgeCert](https://github.com/GhostPack/ForgeCert) gibi araçlar geçerli sertifikalar oluşturmak için kullanılabilir:
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
> Sahte sertifika düzenleme hedefindeki kullanıcı, işlemin başarılı olması için Active Directory'de etkin ve kimlik doğrulaması yapabilecek durumda olmalıdır. krbtgt gibi özel hesaplar için sertifika düzenlemek etkisizdir.

Bu sahte sertifika belirtilen bitiş tarihine kadar ve **root CA sertifikası geçerli olduğu sürece** (genellikle 5 ila **10+ yıl**) **geçerli** olacaktır. Ayrıca **makineler** için de geçerlidir; bu nedenle **S4U2Self** ile birleştirildiğinde, bir saldırgan **CA sertifikası geçerli olduğu sürece herhangi bir domain makinesinde sürekliliği sürdürebilir**.\
Ayrıca, bu yöntemle oluşturulan **sertifikalar** CA bunlardan haberdar olmadığı için **iptal edilemez**.

### Operating under Strong Certificate Mapping Enforcement (2025+)

11 Şubat 2025'ten itibaren (KB5014754 dağıtımından sonra), domain denetleyicileri sertifika eşlemeleri için varsayılan olarak **Full Enforcement** modundadır. Pratikte bu, sahte sertifikalarınızın ya şunlardan birine sahip olması gerektiği anlamına gelir:

- Hedef hesaba güçlü bir bağ içermek (örneğin, SID security extension), veya
- Hedef nesnenin `altSecurityIdentities` özniteliğinde güçlü, açık bir eşleme ile eşleştirilmiş olmak.

Süreklilik için güvenilir bir yaklaşım, çalınmış Enterprise CA'ya zincirli sahte bir sertifika düzenlemek ve ardından mağdur principal'a güçlü, açık bir eşleme eklemektir:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notlar
- SID güvenlik uzantısını içeren sahte sertifikalar oluşturabiliyorsanız, bunlar Full Enforcement altında bile dolaylı olarak eşlenecektir. Aksi takdirde, açık ve güçlü eşlemeleri tercih edin. Daha fazla bilgi için [account-persistence](account-persistence.md) sayfasına bakın.
- İptal burada savunmacılara yardımcı olmaz: sahte sertifikalar CA veritabanında bilinmez ve bu yüzden iptal edilemez.

#### Full-Enforcement ile uyumlu sahteleme (SID bilgisi içeren)

Güncellenmiş araçlar SID'i doğrudan gömmenize izin verir, böylece DCs zayıf eşlemeleri reddetse bile golden certificates kullanılabilir durumda kalır:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SID'yi gömerek, izleniyor olabilecek `altSecurityIdentities` ile uğraşmak zorunda kalmazsınız; yine de güçlü eşleme kontrollerini sağlarsınız.

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` nesnesi, Active Directory (AD) tarafından kullanılan `cacertificate` özniteliğinde bir veya daha fazla **CA certificates** içerecek şekilde tanımlanmıştır. **domain controller** tarafından yapılan doğrulama süreci, kimlik doğrulayan **certificate**'ın Issuer alanında belirtilen **CA** ile eşleşen bir giriş olup olmadığını kontrol etmek için `NTAuthCertificates` nesnesini inceler. Bir eşleşme bulunursa kimlik doğrulama devam eder.

Bir saldırgan, bu AD nesnesi üzerinde kontrol sahibi olduğu takdirde, `NTAuthCertificates` nesnesine self-signed bir CA certificate ekleyebilir. Normalde bu nesneyi değiştirme izni yalnızca **Enterprise Admin** grubunun üyelerine ve ayrıca **forest root’s domain** içindeki **Domain Admins** veya **Administrators**'a verilir. `NTAuthCertificates` nesnesini `certutil.exe` ile `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` komutunu kullanarak veya [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) aracılığıyla düzenleyebilirler.

Ek olarak bu teknik için faydalı komutlar:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Bu yetenek, ForgeCert kullanılarak dinamik sertifika oluşturmayı içeren daha önce anlatılan yöntemle birlikte kullanıldığında özellikle önemlidir.

> 2025 sonrası eşleme dikkate alınması: NTAuth içine sahte bir CA yerleştirmek yalnızca veren CA'ya güvenilirlik sağlar. DC'ler **Full Enforcement** modunda iken oturum açmak için leaf sertifikaların ya SID security extension'ı içermesi ya da hedef nesnede güçlü açık bir eşleme olması gerekir (örneğin, `altSecurityIdentities` içinde Issuer+Serial). Bkz. {{#ref}}account-persistence.md{{#endref}}.

## Kötü Niyetli Yanlış Yapılandırma - DPERSIST3

AD CS bileşenlerinin security descriptor değişiklikleri yoluyla **persistence** fırsatları çok fazladır. "[Domain Escalation](domain-escalation.md)" bölümünde anlatılan değişiklikler, yükseltilmiş erişime sahip bir saldırgan tarafından kötü amaçlı olarak uygulanabilir. Bu, duyarlı bileşenlere "control rights" (ör. WriteOwner/WriteDACL/…) eklenmesini içerir; örnekler:

- **CA sunucusunun AD bilgisayar** nesnesi
- **CA sunucusunun RPC/DCOM servisi**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** içindeki herhangi bir **alt AD nesnesi veya konteyner** (örneğin, Certificate Templates container, Certification Authorities container, NTAuthCertificates nesnesi, vb.)
- Varsayılan veya kuruluş tarafından AD CS'yi kontrol etme hakları devredilmiş **AD grupları** (ör. built-in Cert Publishers grubu ve üyeleri)

Kötü amaçlı bir uygulama örneği, domainde **yükseltilmiş izinlere** sahip bir saldırganın varsayılan **`User`** sertifika şablonuna **`WriteOwner`** iznini eklemesi ve bu hakkın sahibi olarak kendisini ataması olurdu. Bunu istismar etmek için saldırgan önce **`User`** şablonunun sahipliğini kendisine geçirirdi. Ardından şablonda **`mspki-certificate-name-flag`** değeri **1** olarak ayarlanarak **`ENROLLEE_SUPPLIES_SUBJECT`** etkinleştirilir; bu, kullanıcının talepte Subject Alternative Name sağlamasına izin verir. Sonrasında saldırgan, **şablonu** kullanarak alternatif ad olarak bir **domain administrator** adını seçip kaydolabilir ve elde ettiği sertifikayı DA olarak kimlik doğrulama için kullanabilir.

Uzun vadeli domain persistence için saldırganların ayarlayabileceği pratik kontroller (tam detaylar ve tespit için bkz. {{#ref}}domain-escalation.md{{#endref}}):

- Talepten SAN’e izin veren CA politika bayrakları (ör. `EDITF_ATTRIBUTESUBJECTALTNAME2`'nin etkinleştirilmesi). Bu, ESC1 benzeri yolları kullanılabilir tutar.
- Kimlik doğrulamaya uygun sertifika verebilecek şekilde Template DACL veya ayarları (ör. Client Authentication EKU eklemek, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`'i etkinleştirmek).
- Savunucular temizlemeye çalışırsa sahte verenleri sürekli yeniden eklemek için `NTAuthCertificates` nesnesini veya CA konteynerlerini kontrol etmek.

> [!TIP]
> KB5014754 sonrası sertleştirilmiş ortamlarda, bu yanlış yapılandırmaları açık güçlü eşlemelerle (`altSecurityIdentities`) eşleştirmek, DC'ler güçlü eşleme uygulasalar bile düzenlediğiniz veya sahtelediğiniz sertifikaların kullanılabilir kalmasını sağlar.

### Sertifika yenileme suistimali (ESC14) ile persistence

Kimlik doğrulamaya elverişli bir sertifikayı (veya bir Enrollment Agent sertifikasını) ele geçirirseniz, veren şablon yayınlı kaldığı ve CA'nız hâlen issuer zincirine güvendiği sürece, sertifikayı **süresiz olarak yenileyebilirsiniz**. Yenileme orijinal kimlik bağlamalarını korur ancak geçerliliği uzatır; bu da şablon düzeltilmediği veya CA yeniden yayımlanmadığı sürece sertifikayı sistemden atmayı zorlaştırır.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Domain denetleyicileri **Full Enforcement** modundaysa, yenilenen leaf sertifika `altSecurityIdentities`'e dokunmadan güçlü şekilde eşlenmeye devam etmesi için `-sid <victim SID>` ekleyin (veya SID security extension'ı hâlâ içeren bir şablon kullanın). CA admin haklarına sahip saldırganlar ayrıca kendilerine sertifika vermeden önce yenilenen geçerlilik sürelerini uzatmak için `policy\RenewalValidityPeriodUnits`'ı ayarlayabilirler.

## Referanslar

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
