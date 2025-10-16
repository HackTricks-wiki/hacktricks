# AD CS डोमेन परसिस्टेंस

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) में साझा किए गए domain persistence techniques का सारांश है। आगे के विवरण के लिए उसे देखें।**

## चोरी किए गए CA Certificates से प्रमाणपत्र बनाना (Golden Certificate) - DPERSIST1

आप कैसे पहचान सकते हैं कि कोई प्रमाणपत्र CA प्रमाणपत्र है?

यह पहचाना जा सकता है कि कोई प्रमाणपत्र CA प्रमाणपत्र है यदि निम्न शर्तें पूरी होती हैं:

- प्रमाणपत्र CA सर्वर पर संग्रहीत होता है, और इसकी private key मशीन के DPAPI द्वारा सुरक्षित होती है, या अगर operating system का समर्थन हो तो TPM/HSM जैसे हार्डवेयर द्वारा।
- प्रमाणपत्र के Issuer और Subject फ़ील्ड दोनों CA के distinguished name से मेल खाते हैं।
- केवल CA प्रमाणपत्रों में ही एक "CA Version" extension मौजूद होता है।
- प्रमाणपत्र में Extended Key Usage (EKU) फ़ील्ड नहीं होते हैं।

इस प्रमाणपत्र की private key निकालने के लिए, CA सर्वर पर `certsrv.msc` tool को built-in GUI के माध्यम से उपयोग करना समर्थित तरीका है। फिर भी, यह प्रमाणपत्र सिस्टम में संग्रहीत अन्य प्रमाणपत्रों से अलग नहीं होता; इसलिए extraction के लिए [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) जैसी विधियाँ लागू की जा सकती हैं।

प्रमाणपत्र और private key को Certipy का उपयोग करके भी निम्नलिखित command से प्राप्त किया जा सकता है:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
जब आप `.pfx` फ़ॉर्मैट में CA प्रमाणपत्र और उसकी निजी कुंजी प्राप्त कर लेते हैं, तो [ForgeCert](https://github.com/GhostPack/ForgeCert) जैसे टूल्स का उपयोग वैध प्रमाणपत्र जनरेट करने के लिए किया जा सकता है:
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
> प्रमाणपत्र धोखाधड़ी के लक्ष्य किए गए उपयोगकर्ता को प्रक्रिया सफल होने के लिए Active Directory में सक्रिय और प्रमाणीकृत करने में सक्षम होना चाहिए। krbtgt जैसे विशेष खातों के लिए प्रमाणपत्र बनाना अप्रभावी है।

यह जाली प्रमाणपत्र निर्दिष्ट समाप्ति तिथि तक और तब तक **मान्य** रहेगा जब तक root CA प्रमाणपत्र **मान्य** है (आम तौर पर 5 से **10+ वर्षों** तक)। यह **मशीनों** के लिए भी मान्य है, इसलिए **S4U2Self** के साथ मिलकर, एक हमलावर CA प्रमाणपत्र के मान्य होने तक किसी भी डोमेन मशीन पर **पर्सिस्टेंस बनाए रख सकता है**।\
इसके अलावा, इस विधि से जनित **प्रमाणपत्रों** को **रद्द नहीं किया जा सकता** क्योंकि CA उनके बारे में जानकारी नहीं रखता।

### Operating under Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- लक्ष्य खाते के साथ एक मजबूत बाइंडिंग शामिल हो (उदाहरण के लिए, the SID security extension), या
- लक्ष्य ऑब्जेक्ट के `altSecurityIdentities` attribute पर एक मजबूत, स्पष्ट mapping के साथ जोड़ा गया हो।

पर्सिस्टेंस के लिए एक भरोसेमंद तरीका है चोरी किए गए Enterprise CA से chained एक जाली प्रमाणपत्र mint करना और फिर लक्षित प्रिंसिपल पर एक मजबूत स्पष्ट मैपिंग जोड़ना:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- यदि आप ऐसे forged certificates बना सकते हैं जिनमें SID security extension शामिल हो, तो वे Full Enforcement के तहत भी implicitly map हो जाएँगे। अन्यथा, explicit strong mappings को प्राथमिकता दें। देखें [account-persistence](account-persistence.md) अधिक जानकारी के लिए।
- Revocation यहाँ defenders की मदद नहीं करता: forged certificates CA database के लिए अज्ञात होते हैं और इसलिए इन्हें revoked नहीं किया जा सकता।

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object को परिभाषित किया गया है कि यह अपने `cacertificate` attribute में एक या अधिक **CA certificates** रखता है, जिसे Active Directory (AD) उपयोग करता है। सत्यापन प्रक्रिया **domain controller** द्वारा यह जांचती है कि `NTAuthCertificates` object में authenticating **certificate** के Issuer field में निर्दिष्ट **CA specified** के अनुरूप कोई entry मौजूद है या नहीं। अगर मैच मिल जाता है तो authentication आगे बढ़ती है।

एक self-signed CA certificate को `NTAuthCertificates` object में एक attacker जोड़ सकता है, बशर्ते उसके पास इस AD object पर नियंत्रण हो। सामान्यतः, केवल **Enterprise Admin** group के सदस्य, साथ ही **Domain Admins** या **Administrators** जो **forest root’s domain** में हैं, को इस object को संशोधित करने की अनुमति दी जाती है। वे `NTAuthCertificates` object को `certutil.exe` से इस कमांड के साथ एडिट कर सकते हैं: `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, या [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) का उपयोग करके।

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
This capability is especially relevant when used in conjunction with a previously outlined method involving ForgeCert to dynamically generate certificates.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## दुष्ट कॉन्फ़िगरेशन - DPERSIST3

AD CS घटकों के **security descriptor** संशोधनों के माध्यम से **persistence** के अवसर बहुत हैं। "[Domain Escalation](domain-escalation.md)" सेक्शन में वर्णित संशोधनों को डोमेन में उन्नत पहुँच रखने वाले एक हमलावर द्वारा दुष्ट रूप से लागू किया जा सकता है। इसमें संवेदनशील घटकों पर "control rights" (उदा., WriteOwner/WriteDACL/etc.) जोड़ना शामिल है, जैसे:

- CA सर्वर के **AD computer** ऑब्जेक्ट पर
- CA सर्वर के **RPC/DCOM server** पर
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** में किसी भी **descendant AD object या container** पर (उदाहरण के लिए, Certificate Templates container, Certification Authorities container, NTAuthCertificates object, आदि)
- **AD समूह जो AD CS नियंत्रित करने के अधिकार दिए गए हैं** (डिफ़ॉल्ट या संगठन द्वारा) (जैसे built-in Cert Publishers समूह और उसके सदस्य)

एक दुष्ट कार्यान्वयन का उदाहरण यह होगा कि डोमेन में जिनके पास **उन्नत permissions** हैं वे डिफ़ॉल्ट **`User`** certificate template पर **`WriteOwner`** अनुमति अपने आप को principal बनाकर जोड़ दें। इसका शोषण करने के लिए, हमलावर पहले **`User`** टेम्पलेट की ownership खुद कर लेगा। इसके बाद टेम्पलेट पर **`mspki-certificate-name-flag`** को **1** पर सेट किया जाएगा ताकि **`ENROLLEE_SUPPLIES_SUBJECT`** सक्षम हो और अनुरोधकर्ता request में Subject Alternative Name प्रदान कर सके। उसके बाद हमलावर उस **template** का उपयोग करके **enroll** कर सकता है, एक alternative name के रूप में किसी **domain administrator** का नाम चुनकर, और प्राप्त प्रमाणपत्र का उपयोग DA के रूप में authentication के लिए कर सकता है।

लॉन्ग‑टर्म डोमेन persistence के लिए हमलावर जिन practical knobs को सेट कर सकते हैं (पूर्ण विवरण और पता लगाने के लिए देखें {{#ref}}domain-escalation.md{{#endref}}):

- CA नीति flags जो requesters से SAN की अनुमति देते हैं (उदा., `EDITF_ATTRIBUTESUBJECTALTNAME2` को सक्षम करना)। यह ESC1‑like paths को explot करने योग्य बनाए रखता है।
- Template DACL या सेटिंग्स जो authentication-capable issuance की अनुमति देती हैं (उदा., Client Authentication EKU जोड़ना, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` को सक्षम करना).
- `NTAuthCertificates` ऑब्जेक्ट या CA containers को नियंत्रित करके, अगर defenders cleanup करने की कोशिश करें तो rogue issuers को लगातार पुनः प्रस्तुत करना।

> [!TIP]
> KB5014754 के बाद hardened वातावरणों में, इन मिसकन्फ़िगरेशनों को explicit strong mappings (`altSecurityIdentities`) के साथ जोड़ने से आपके जारी या forged प्रमाणपत्र तब भी उपयोगी बने रहते हैं जब DCs strong mapping लागू करते हैं।



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
