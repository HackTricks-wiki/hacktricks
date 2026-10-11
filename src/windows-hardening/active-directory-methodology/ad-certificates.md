# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## परिचय

### Certificate के Components

- Certificate का **Subject** उसके owner को दर्शाता है।
- **Public Key** को एक निजी तौर पर रखी गई key के साथ जोड़ा जाता है, ताकि certificate को उसके सही owner से जोड़ा जा सके।
- **Validity Period**, जिसे **NotBefore** और **NotAfter** dates से परिभाषित किया जाता है, certificate की प्रभावी अवधि बताता है।
- Certificate Authority (CA) द्वारा दिया गया एक unique **Serial Number**, प्रत्येक certificate की पहचान करता है।
- **Issuer** उस CA को दर्शाता है जिसने certificate जारी किया है।
- **SubjectAlternativeName** subject के लिए अतिरिक्त names की अनुमति देता है, जिससे पहचान में अधिक लचीलापन आता है।
- **Basic Constraints** बताते हैं कि certificate किसी CA के लिए है या end entity के लिए, और उपयोग से जुड़ी सीमाएँ तय करते हैं।
- **Extended Key Usages (EKUs)** Object Identifiers (OIDs) के ज़रिए certificate के विशिष्ट उद्देश्यों, जैसे code signing या email encryption, को परिभाषित करते हैं।
- **Signature Algorithm** certificate पर हस्ताक्षर करने का तरीका बताता है।
- Issuer की private key से बनाई गई **Signature**, certificate की प्रामाणिकता की गारंटी देती है।<sup>[[4]](#references)</sup>

### विशेष बातें

- **Subject Alternative Names (SANs)** certificate को कई identities पर लागू करने की सुविधा देते हैं, जो कई domains वाले servers के लिए महत्वपूर्ण है। SAN specification में बदलाव करके attackers द्वारा impersonation के जोखिम से बचने के लिए सुरक्षित issuance प्रक्रियाएँ आवश्यक हैं।<sup>[[4]](#references)</sup>

### Active Directory (AD) में Certificate Authorities (CAs)

AD CS, AD forest में CA certificates को निर्धारित containers के ज़रिए पहचानता है; हर container की अपनी विशिष्ट भूमिका होती है:<sup>[[4]](#references)</sup>

- **Certification Authorities** container में trusted root CA certificates होते हैं।
- **Enrolment Services** container में Enterprise CAs और उनके certificate templates की जानकारी होती है।
- **NTAuthCertificates** object में AD authentication के लिए अधिकृत CA certificates शामिल होते हैं।
- **AIA (Authority Information Access)** container, intermediate और cross CA certificates के साथ certificate chain validation को संभव बनाता है।

### Certificate प्राप्त करना: Client Certificate Request Flow

1. Request प्रक्रिया तब शुरू होती है जब clients किसी Enterprise CA को खोजते हैं।
2. Public-private key pair बनाने के बाद CSR बनाया जाता है, जिसमें public key और अन्य जानकारी होती है।
3. CA, उपलब्ध certificate templates के अनुसार CSR का आकलन करता है और template की permissions के आधार पर certificate जारी करता है।
4. स्वीकृति मिलने पर, CA अपनी private key से certificate पर हस्ताक्षर करता है और उसे client को वापस भेजता है।<sup>[[4]](#references)</sup>

### Certificate Templates

AD में परिभाषित ये templates, certificates जारी करने की settings और permissions तय करते हैं। इनमें अनुमत EKUs और enrollment या modification rights शामिल हैं, जो certificate services तक पहुँच प्रबंधित करने के लिए महत्वपूर्ण हैं।<sup>[[4]](#references)</sup>

**Template schema version महत्वपूर्ण है।** Legacy **v1** templates (उदाहरण के लिए, built-in **WebServer** template) में कई आधुनिक enforcement controls नहीं होते। **ESC15/EKUwu** research से पता चला कि **v1 templates** पर requester CSR में **Application Policies/EKUs** जोड़ सकता है, जिन्हें template में configured EKUs से **अधिक प्राथमिकता** दी जाती है। इससे केवल enrollment rights के साथ client-auth, enrollment agent, या code-signing certificates प्राप्त किए जा सकते हैं। **v2/v3 templates** को प्राथमिकता दें, v1 defaults को हटाएँ या उनसे बेहतर templates लागू करें, और EKUs को उनके निर्धारित उद्देश्य तक सीमित रखें।<sup>[[1]](#references)</sup>

## Certificate Enrollment

Certificates की enrollment प्रक्रिया एक administrator द्वारा **certificate template बनाने** से शुरू होती है, जिसे फिर Enterprise Certificate Authority (CA) द्वारा **publish** किया जाता है। इससे template client enrollment के लिए उपलब्ध हो जाता है। इसके लिए template का नाम Active Directory object के `certificatetemplates` field में जोड़ा जाता है।<sup>[[4]](#references)</sup>

Client द्वारा certificate request करने के लिए **enrollment rights** दिए जाने चाहिए। ये rights certificate template और Enterprise CA पर security descriptors के ज़रिए परिभाषित होते हैं। Request सफल होने के लिए, दोनों जगह permissions देना आवश्यक है।

### Template Enrollment Rights

ये rights Access Control Entries (ACEs) के ज़रिए निर्दिष्ट होते हैं, जिनमें निम्नलिखित जैसी permissions शामिल हैं:

- **Certificate-Enrollment** और **Certificate-AutoEnrollment** rights, जिनमें से हर एक विशिष्ट GUID से जुड़ा होता है।
- **ExtendedRights**, जो सभी extended permissions की अनुमति देते हैं।
- **FullControl/GenericAll**, जो template पर पूरा control देते हैं।

### Enterprise CA Enrollment Rights

CA के rights उसके security descriptor में दिए गए होते हैं, जिसे Certificate Authority management console के ज़रिए देखा जा सकता है। कुछ settings कम-privileged users को remote access भी देती हैं, जो सुरक्षा के लिए चिंता का विषय हो सकता है।

### अतिरिक्त Issuance Controls

कुछ controls लागू हो सकते हैं, जैसे:

- **Manager Approval**: Requests को तब तक pending रखता है, जब तक certificate manager उन्हें approve न करे।
- **Enrolment Agents and Authorized Signatures**: CSR पर आवश्यक signatures की संख्या और ज़रूरी Application Policy OIDs निर्दिष्ट करते हैं।

### Certificates Request करने के तरीके

Certificates को इन तरीकों से request किया जा सकता है:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces का उपयोग करके।
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes या TCP/IP के ज़रिए।
3. **certificate enrollment web interface**, जिसमें Certificate Authority Web Enrollment role installed हो।
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service के साथ।
5. Network devices के लिए **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) का उपयोग करके।

Windows users GUI (`certmgr.msc` या `certlm.msc`) या command-line tools (`certreq.exe` या PowerShell के `Get-Certificate` command) के ज़रिए भी certificates request कर सकते हैं।

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## प्रमाणपत्र प्रमाणीकरण

Active Directory (AD) प्रमाणपत्र प्रमाणीकरण का समर्थन करता है, जिसमें मुख्य रूप से **Kerberos** और **Secure Channel (Schannel)** प्रोटोकॉल का उपयोग होता है।

### Kerberos प्रमाणीकरण प्रक्रिया

Kerberos प्रमाणीकरण प्रक्रिया में, उपयोगकर्ता द्वारा Ticket Granting Ticket (TGT) के लिए किए गए अनुरोध पर उपयोगकर्ता के प्रमाणपत्र की **private key** से हस्ताक्षर किए जाते हैं। इस अनुरोध की domain controller द्वारा कई जाँचें की जाती हैं, जिनमें प्रमाणपत्र की **वैधता**, **पाथ** और **निरस्तीकरण स्थिति** शामिल हैं। इन जाँचों में यह सत्यापित करना भी शामिल है कि प्रमाणपत्र किसी विश्वसनीय स्रोत से आया है और जारीकर्ता **NTAUTH certificate store** में मौजूद है। जाँच सफल होने पर TGT जारी किया जाता है। AD में मौजूद **`NTAuthCertificates`** ऑब्जेक्ट यहाँ मिलता है:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

प्रमाणपत्र authentication के लिए trust स्थापित करने में केंद्रीय भूमिका निभाता है।<sup>[[4]](#references)</sup>

**KB5014754** rollout के बाद, modern Kerberos certificate auth मुख्यतः **mapping strength** पर निर्भर करता है, सिर्फ EKUs पर नहीं।<sup>[[2]](#references)</sup> Hardened forests में:

- केवल **UPN/DNS SAN** वाला certificate अब logon के लिए पर्याप्त नहीं हो सकता।
- KDC, आम तौर पर **SID security extension** (`1.3.6.1.4.1.311.25.2`) या `altSecurityIdentities` में strong explicit mapping के रूप में, **strong binding** को प्राथमिकता देता है।
- अगर cert में strong mapping नहीं है, तो DCs compatibility mode में **Kdcsvc Event ID 39/41** log करते हैं और enforcement mode में auth अस्वीकार कर देते हैं।
- Mixed attack paths में **ESC9/ESC16** मायने रखते हैं, क्योंकि वे जारी किए गए certs से SID extension हटा देते हैं; इसके बाद operators explicit mappings या SAN URL SID formats पर निर्भर करते हैं, जहाँ attack path में ये समर्थित हों।

### Secure Channel (Schannel) Authentication

Schannel सुरक्षित TLS/SSL connections की सुविधा देता है। Handshake के दौरान client एक certificate प्रस्तुत करता है, जिसे सफलतापूर्वक validate किए जाने पर access की अनुमति मिलती है। Certificate को AD account से map करने में Kerberos का **S4U2Self** function या certificate का **Subject Alternative Name (SAN)**, अन्य तरीकों के साथ, शामिल हो सकता है।<sup>[[4]](#references)</sup>

**PKINIT** उपलब्ध न होने पर Schannel व्यावहारिक fallback भी है। उदाहरण के लिए, यदि किसी domain controller के पास उपयुक्त **Smart Card Logon** certificate नहीं है, तो `certipy auth`/PKINIT tooling TGT प्राप्त करने में विफल हो सकती है, लेकिन वही certificate authentication और LDAP operations के लिए **LDAPS** या **LDAP StartTLS** के विरुद्ध फिर भी उपयोगी हो सकता है।

### AD Certificate Services Enumeration

AD की certificate services को LDAP queries के ज़रिए enumerate किया जा सकता है, जिससे **Enterprise Certificate Authorities (CAs)** और उनके configurations की जानकारी सामने आती है। यह बिना किसी विशेष privilege के, domain-authenticated किसी भी user के लिए उपलब्ध है। **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** जैसे tools का उपयोग AD CS environments में enumeration और vulnerability assessment के लिए किया जाता है।

इन tools का उपयोग करने के commands में शामिल हैं:

```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## हाल की Vulnerabilities और Security Updates (2022-2025)

| वर्ष | ID / नाम | प्रभाव | मुख्य निष्कर्ष |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT के दौरान machine account certificates को spoof करके *Privilege escalation*। | Patch, **May 10 2022** के security updates में शामिल है। Auditing और strong-mapping controls, **KB5014754** के ज़रिए शुरू किए गए; अब environments को *Full Enforcement* mode में होना चाहिए।  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) और CES roles में *Remote code-execution*। | सार्वजनिक PoCs सीमित हैं, लेकिन vulnerable IIS components अक्सर internal network में exposed होते हैं। **July 2023** Patch Tuesday के अनुसार patch करें।  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** पर, enrollment rights वाला requester CSR में **Application Policies/EKUs** शामिल कर सकता है, जिन्हें template EKUs पर प्राथमिकता मिलती है; इससे client-auth, enrollment agent या code-signing certificates बन सकते हैं। | **November 12, 2024** तक patch उपलब्ध है। v1 templates (जैसे, default WebServer) को replace या supersede करें, EKUs को उनके उद्देश्य तक सीमित रखें और enrollment rights सीमित करें। |

### Microsoft hardening की समयरेखा (KB5014754)

Microsoft ने Kerberos certificate authentication को कमजोर implicit mappings से दूर ले जाने के लिए तीन चरणों वाला rollout (Compatibility → Audit → Enforcement) शुरू किया। **February 11, 2025** से, यदि `StrongCertificateBindingEnforcement` registry value सेट नहीं है, तो domain controllers अपने-आप **Full Enforcement** पर switch हो जाते हैं। Microsoft ने बाद में समयरेखा अपडेट की, ताकि **September 9, 2025** security update तक compatibility mode पर वापस जाना संभव रहे।<sup>[[2]](#references)</sup> Administrators को चाहिए कि वे:

1. सभी DCs और AD CS servers को patch करें (May 2022 या बाद का update)।
2. *Audit* phase के दौरान कमजोर mappings के लिए Event ID 39/41 की निगरानी करें।
3. नई **SID extension** के साथ client-auth certificates फिर से जारी करें या enforcement द्वारा कमजोर mappings को block करने से पहले strong manual mappings configure करें।

### Hardened forests के लिए Operator notes

- 2025+ environments में **केवल ESC1/ESC6 पूरी कहानी नहीं हैं**। यदि आप किसी अन्य principal के लिए cert request करते हैं, तो आम तौर पर आपको किसी strong mapping artifact की भी ज़रूरत होती है, जैसे SID extension या explicit mapping।
- **ESC15 (EKUwu)** unpatched environments में सबसे ज़्यादा उपयोगी है, क्योंकि यह **Application Policies** inject करके हानिरहित **v1** templates, जैसे **WebServer**, को authentication- या enrollment-agent-capable certs में बदल देता है। Kerberos PKINIT अब भी EKUs का मूल्यांकन करता है, लेकिन **LDAP Schannel** भी Application Policies को मानता है, इसलिए LDAP-आधारित abuse प्रासंगिक बना रहता है।<sup>[[1]](#references)</sup>
- **ESC16** CA-wide setting है: यदि CA SID security extension को globally disable कर देता है, तो जारी किया गया हर certificate कमजोर mapping behavior की ओर लौट जाता है—जब तक attack chain किसी अन्य supported format से SID inject न करे।
- **ESC7 rights अलग-अलग हैं:** CA का `ManageCA` grant `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) जैसी settings में बदलाव की अनुमति दे सकता है, जबकि `ManageCertificates` request approval को नियंत्रित करता है। Certificate-manager rights पर explicit Deny, Allow मौजूद होने पर भी उस approval route को block कर सकता है; settings और templates को chain करने से पहले प्रभावी CA ACL का आकलन करें। [Microsoft का CA ACL assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting) देखें।

---

## Detection और Hardening में सुधार

* **Defender for Identity AD CS sensor (2023-2024)** अब ESC1-ESC8/ESC11 के लिए posture assessments दिखाता है और *“Domain-controller certificate issuance for a non-DC”* (ESC8) तथा *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15) जैसे real-time alerts जनरेट करता है। इन detections का लाभ लेने के लिए सभी AD CS servers पर sensors deploy करें।<sup>[[3]](#references)</sup>
* सभी templates पर **“Supply in the request”** option को disable करें या उसका scope सख्ती से सीमित करें; स्पष्ट रूप से निर्धारित SAN/EKU values को प्राथमिकता दें।
* जब तक बिल्कुल आवश्यक न हो, templates से **Any Purpose** या **No EKU** हटाएँ (इससे ESC2 scenarios का जोखिम घटता है)।
* संवेदनशील templates (जैसे, WebServer / CodeSigning) के लिए **manager approval** या dedicated Enrollment Agent workflows अनिवार्य करें।
* Web enrollment (`certsrv`) और CES/NDES endpoints को trusted networks तक सीमित रखें या client-certificate authentication के पीछे रखें।
* ESC11 (RPC relay) को कम करने के लिए RPC enrollment encryption लागू करें (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`)। यह flag **डिफ़ॉल्ट रूप से on** होता है, लेकिन legacy clients के लिए अक्सर disable कर दिया जाता है, जिससे relay risk फिर से पैदा हो जाता है।
* **IIS-आधारित enrollment endpoints** (CES/Certsrv) को secure करें: जहाँ संभव हो NTLM disable करें या ESC8 relays को block करने के लिए HTTPS + Extended Protection अनिवार्य करें।

ESC11 का आकलन उस host पर करें जहाँ CA चल रहा है; यह domain controller के बजाय domain member server भी हो सकता है। Active CA के `InterfaceFlags` को `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` के अंतर्गत पढ़ें; value का unreadable या missing होना अज्ञात परिणाम है, RPC encryption disabled होने का प्रमाण नहीं। `IF_ENFORCEENCRYPTICERTREQUEST` bit clear होना configuration की जाँच का संकेत है; फिर भी इसके लिए reachable enrollment RPC endpoint, coercible credentials और उपयोगी certificate template की ज़रूरत होती है। ESC8 के लिए, केवल HTTP NTLM challenge होना पर्याप्त नहीं है: पुष्टि करें कि working enrollment endpoint मौजूद है।

---

## References

- [1] [EKUwu: सिर्फ़ एक और AD CS ESC नहीं](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows domain controllers पर certificate-based authentication में बदलाव](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services का दुरुपयोग](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
