# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresinde paylaşılan alan kalıcılığı tekniklerinin bir özetidir**. Daha fazla ayrıntı için kontrol edin.

## Çalınan CA Sertifikaları ile Sertifika Sahteciliği - DPERSIST1

Bir sertifikanın CA sertifikası olduğunu nasıl anlarsınız?

Bir sertifikanın CA sertifikası olduğu, birkaç koşulun sağlanması durumunda belirlenebilir:

- Sertifika, CA sunucusunda depolanır ve özel anahtarı makinenin DPAPI'si veya işletim sistemi destekliyorsa TPM/HSM gibi donanım tarafından korunur.
- Sertifikanın Hem Verici (Issuer) hem de Konu (Subject) alanları CA'nın ayırt edici adıyla eşleşir.
- CA sertifikalarında yalnızca "CA Version" uzantısı bulunur.
- Sertifika, Genişletilmiş Anahtar Kullanımı (EKU) alanlarından yoksundur.

Bu sertifikanın özel anahtarını çıkarmak için, CA sunucusundaki `certsrv.msc` aracı, yerleşik GUI aracılığıyla desteklenen yöntemdir. Ancak, bu sertifika sistemde depolanan diğerlerinden farklı değildir; bu nedenle, [THEFT2 tekniği](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) gibi yöntemler çıkarım için uygulanabilir.

Sertifika ve özel anahtar, aşağıdaki komut ile Certipy kullanılarak da elde edilebilir:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA sertifikası ve özel anahtarını `.pfx` formatında edindikten sonra, geçerli sertifikalar oluşturmak için [ForgeCert](https://github.com/GhostPack/ForgeCert) gibi araçlar kullanılabilir:
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
> Sertifika sahteciliği hedeflenen kullanıcının aktif olması ve Active Directory'de kimlik doğrulama yapabilme yeteneğine sahip olması gerekmektedir. krbtgt gibi özel hesaplar için sertifika sahteciliği etkisizdir.

Bu sahte sertifika, belirtilen son tarihine kadar **geçerli** olacak ve **kök CA sertifikası geçerli olduğu sürece** (genellikle 5 ila **10+ yıl** arasında) geçerliliğini koruyacaktır. Ayrıca, **makineler** için de geçerlidir, bu nedenle **S4U2Self** ile birleştirildiğinde, bir saldırgan **CA sertifikası geçerli olduğu sürece** herhangi bir alan makinesinde **kalıcılığı sürdürebilir**.\
Ayrıca, bu yöntemle **oluşturulan sertifikalar** **iptal edilemez** çünkü CA bunlardan haberdar değildir.

## Sahte CA Sertifikalarına Güvenme - DPERSIST2

`NTAuthCertificates` nesnesi, Active Directory'nin (AD) kullandığı `cacertificate` niteliği içinde bir veya daha fazla **CA sertifikası** içerecek şekilde tanımlanmıştır. **Alan denetleyicisi** tarafından yapılan doğrulama süreci, kimlik doğrulama **sertifikasının** İhraççı alanında belirtilen **CA ile** eşleşen bir girişi kontrol etmeyi içerir. Eşleşme bulunursa kimlik doğrulama devam eder.

Bir saldırgan, bu AD nesnesi üzerinde kontrol sahibi olduğu sürece `NTAuthCertificates` nesnesine kendinden imzalı bir CA sertifikası ekleyebilir. Normalde, yalnızca **Enterprise Admin** grubunun üyeleri ile **Domain Admins** veya **orman kök alanındaki** **Yönetici** grubu bu nesneyi değiştirme iznine sahiptir. `NTAuthCertificates` nesnesini `certutil.exe` kullanarak `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126` komutuyla veya [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) kullanarak düzenleyebilirler.

Bu yetenek, daha önce belirtilen ForgeCert yöntemini kullanarak dinamik olarak sertifikalar oluşturmak için kullanıldığında özellikle önemlidir.

## Kötü Amaçlı Yanlış Yapılandırma - DPERSIST3

AD CS bileşenlerinin **güvenlik tanımlayıcıları** üzerinde **kalıcılık** sağlama fırsatları bolca mevcuttur. "[Domain Escalation](domain-escalation.md)" bölümünde açıklanan değişiklikler, yükseltilmiş erişime sahip bir saldırgan tarafından kötü niyetle uygulanabilir. Bu, aşağıdaki gibi hassas bileşenlere "kontrol hakları" (örneğin, WriteOwner/WriteDACL/ vb.) eklenmesini içerir:

- **CA sunucusunun AD bilgisayar** nesnesi
- **CA sunucusunun RPC/DCOM sunucusu**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** içindeki herhangi bir **torun AD nesnesi veya konteyner** (örneğin, Sertifika Şablonları konteyneri, Sertifikasyon Otoriteleri konteyneri, NTAuthCertificates nesnesi vb.)
- **AD gruplarının AD CS'yi kontrol etme hakları** varsayılan olarak veya organizasyon tarafından (örneğin, yerleşik Sertifika Yayıncıları grubu ve üyeleri)

Kötü niyetli bir uygulama örneği, alan içinde **yükseltilmiş izinlere** sahip bir saldırganın, **`User`** sertifika şablonuna **`WriteOwner`** iznini eklemesi olacaktır; burada saldırgan, bu hakkın sahibi olur. Bunu istismar etmek için, saldırgan önce **`User`** şablonunun sahipliğini kendisine değiştirecektir. Ardından, **`mspki-certificate-name-flag`** şablon üzerinde **1** olarak ayarlanacak ve **`ENROLLEE_SUPPLIES_SUBJECT`** etkinleştirilecektir; bu, bir kullanıcının talepte bir Subject Alternative Name sağlamasına olanak tanır. Sonrasında, saldırgan **şablonu** kullanarak, alternatif bir ad olarak bir **alan yöneticisi** adı seçerek **kayıt** olabilir ve elde edilen sertifikayı DA olarak kimlik doğrulama için kullanabilir.

{{#include ../../../banners/hacktricks-training.md}}
