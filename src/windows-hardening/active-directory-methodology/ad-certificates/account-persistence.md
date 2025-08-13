# AD CS Hesap Sürekliliği

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresindeki harika araştırmanın makine sürekliliği bölümlerinin küçük bir özetidir.**

## **Sertifikalar ile Aktif Kullanıcı Kimlik Bilgisi Hırsızlığını Anlamak – PERSIST1**

Bir kullanıcının alan kimlik doğrulamasına izin veren bir sertifika talep edebileceği bir senaryoda, bir saldırganın bu sertifikayı **talep etme** ve **çalma** fırsatı vardır, böylece bir ağda **sürekliliği sağlama** imkanı bulur. Varsayılan olarak, Active Directory'deki `User` şablonu bu tür taleplere izin verir, ancak bazen devre dışı bırakılabilir.

[**Certify**](https://github.com/GhostPack/Certify) adlı bir araç kullanarak, sürekli erişimi sağlayan geçerli sertifikaları aramak mümkündür:
```bash
Certify.exe find /clientauth
```
Bir sertifikanın gücünün, sertifikanın ait olduğu **kullanıcı olarak kimlik doğrulama** yeteneğinde yattığı, sertifika **geçerli** olduğu sürece, herhangi bir şifre değişikliğinden bağımsız olarak vurgulanmaktadır.

Sertifikalar, `certmgr.msc` kullanarak grafik arayüz üzerinden veya `certreq.exe` ile komut satırından talep edilebilir. **Certify** ile, bir sertifika talep etme süreci aşağıdaki gibi basitleştirilmiştir:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Başarılı bir istek üzerine, bir sertifika ve onun özel anahtarı `.pem` formatında oluşturulur. Bunu Windows sistemlerinde kullanılabilir bir `.pfx` dosyasına dönüştürmek için aşağıdaki komut kullanılır:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
`.pfx` dosyası daha sonra bir hedef sisteme yüklenebilir ve kullanıcının bir Ticket Granting Ticket (TGT) talep etmesi için [**Rubeus**](https://github.com/GhostPack/Rubeus) adlı bir araçla kullanılabilir, saldırganın erişimini sertifika **geçerli** olduğu sürece (genellikle bir yıl) uzatır:
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Önemli bir uyarı, bu tekniğin, **THEFT5** bölümünde belirtilen başka bir yöntemle birleştirildiğinde, bir saldırganın Yerel Güvenlik Otoritesi Alt Sistemi Hizmeti (LSASS) ile etkileşime girmeden ve yükseltilmemiş bir bağlamdan bir hesabın **NTLM hash**'ini sürekli olarak elde etmesine olanak tanıdığını paylaşmaktadır. Bu, uzun vadeli kimlik bilgisi hırsızlığı için daha gizli bir yöntem sunar.

## **Sertifikalar ile Makine Sürekliliği Elde Etme - PERSIST2**

Başka bir yöntem, bir tehlikeye atılmış sistemin makine hesabını bir sertifika için kaydetmeyi içerir; bu, böyle eylemlere izin veren varsayılan `Machine` şablonunu kullanır. Bir saldırgan bir sistemde yükseltilmiş ayrıcalıklar elde ederse, **SYSTEM** hesabını kullanarak sertifika talep edebilir ve bu da bir tür **süreklilik** sağlar:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Bu erişim, saldırganın makine hesabı olarak **Kerberos**'a kimlik doğrulaması yapmasını ve ev sahibi üzerindeki herhangi bir hizmet için Kerberos hizmet biletleri almak üzere **S4U2Self**'i kullanmasını sağlar, bu da saldırgana makineye kalıcı erişim sağlar.

## **Sertifika Yenileme ile Kalıcılığı Uzatma - PERSIST3**

Son olarak tartışılan yöntem, sertifika şablonlarının **geçerlilik** ve **yenileme sürelerinden** yararlanmaktır. Bir sertifikayı süresi dolmadan önce **yenileyerek**, bir saldırgan, Sertifika Otoritesi (CA) sunucusunda iz bırakmadan ek bilet kaydı gerektirmeden Active Directory'ye kimlik doğrulamasını sürdürebilir.

### Certify 2.0 ile Sertifika Yenileme

**Certify 2.0** ile yenileme iş akışı, yeni `request-renew` komutu aracılığıyla tamamen otomatik hale getirilmiştir. Daha önce verilmiş bir sertifika ( **base-64 PKCS#12** formatında) verildiğinde, bir saldırgan bunu orijinal sahibiyle etkileşime girmeden yenileyebilir - gizli, uzun vadeli kalıcılık için mükemmel:
```powershell
Certify.exe request-renew --ca SERVER\\CA-NAME \
--cert-pfx MIACAQMwgAYJKoZIhvcNAQcBoIAkgA...   # original PFX
```
Komut, ilk sertifika süresi dolduktan veya iptal edildikten sonra bile kimlik doğrulamaya devam etmenizi sağlayan, başka bir tam yaşam süresi için geçerli olan yeni bir PFX döndürecektir.


## Referanslar

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}
