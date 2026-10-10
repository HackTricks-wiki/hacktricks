# AD प्रमाणपत्र

{{#include ../../banners/hacktricks-training.md}}

## परिचय

### प्रमाणपत्र के घटक

- प्रमाणपत्र का **Subject** उसके स्वामी को दर्शाता है।
- **Public Key** का संबंध निजी रूप से रखी गई key से होता है, जिससे प्रमाणपत्र को उसके वास्तविक स्वामी से जोड़ा जा सके।
- **Validity Period**, जिसे **NotBefore** और **NotAfter** तारीखों से परिभाषित किया जाता है, प्रमाणपत्र की प्रभावी अवधि बताता है।
- Certificate Authority (CA) द्वारा दिया गया एक विशिष्ट **Serial Number**, प्रत्येक प्रमाणपत्र की पहचान करता है।
- **Issuer** उस CA को दर्शाता है जिसने प्रमाणपत्र जारी किया है।
- **SubjectAlternativeName** विषय के लिए अतिरिक्त नाम जोड़ता है, जिससे पहचान में अधिक लचीलापन मिलता है।
- **Basic Constraints** बताते हैं कि प्रमाणपत्र CA के लिए है या किसी end entity के लिए, और उपयोग संबंधी सीमाएँ निर्धारित करते हैं।
- **Extended Key Usages (EKUs)** Object Identifiers (OIDs) के ज़रिए प्रमाणपत्र के विशिष्ट उद्देश्यों, जैसे code signing या email encryption, को परिभाषित करते हैं।
- **Signature Algorithm** प्रमाणपत्र पर हस्ताक्षर करने का तरीका बताता है।
- Issuer की private key से बनाया गया **Signature**, प्रमाणपत्र की प्रामाणिकता की गारंटी देता है।<sup>[[4]](#references)</sup>

### विशेष विचार

- **Subject Alternative Names (SANs)** प्रमाणपत्र को कई identities पर लागू करने की सुविधा देते हैं, जो कई domains वाले servers के लिए महत्वपूर्ण है। SAN specification में बदलाव करके attackers द्वारा impersonation के जोखिम से बचने के लिए, प्रमाणपत्र जारी करने की सुरक्षित प्रक्रियाएँ बेहद ज़रूरी हैं।<sup>[[4]](#references)</sup>

### Active Directory (AD) में Certificate Authorities (CAs)

AD CS, AD forest में CA प्रमाणपत्रों को निर्धारित containers के ज़रिए पहचानता है, जिनमें से प्रत्येक की भूमिका अलग होती है:<sup>[[4]](#references)</sup>

- **Certification Authorities** container में trusted root CA certificates होते हैं।
- **Enrolment Services** container में Enterprise CAs और उनके certificate templates की जानकारी होती है।
- **NTAuthCertificates** object में AD authentication के लिए अधिकृत CA certificates शामिल होते हैं।
- **AIA (Authority Information Access)** container, intermediate और cross CA certificates के साथ certificate chain validation को आसान बनाता है।

### प्रमाणपत्र प्राप्त करना: Client Certificate Request Flow

1. अनुरोध प्रक्रिया की शुरुआत clients द्वारा Enterprise CA खोजने से होती है।
2. Public-private key pair बनाने के बाद, public key और अन्य विवरणों वाला CSR बनाया जाता है।
3. CA, उपलब्ध certificate templates के आधार पर CSR का आकलन करता है और template की permissions के अनुसार प्रमाणपत्र जारी करता है।
4. मंज़ूरी मिलने पर, CA अपनी private key से प्रमाणपत्र पर हस्ताक्षर करके उसे client को लौटाता है।<sup>[[4]](#references)</sup>

### Certificate Templates

AD में परिभाषित ये templates, प्रमाणपत्र जारी करने के लिए settings और permissions तय करते हैं। इनमें अनुमत EKUs और enrollment या modification rights शामिल हैं, जो certificate services तक पहुँच प्रबंधित करने के लिए महत्वपूर्ण हैं।<sup>[[4]](#references)</sup>

**Template schema version महत्वपूर्ण है।** पुराने **v1** templates (उदाहरण के लिए, बिल्ट-इन **WebServer** template) में कई आधुनिक enforcement controls नहीं होते। **ESC15/EKUwu** research से पता चला कि **v1 templates** पर अनुरोधकर्ता CSR में **Application Policies/EKUs** शामिल कर सकता है, जिन्हें template में कॉन्फ़िगर किए गए EKUs से **अधिक प्राथमिकता दी जाती है**। इससे केवल enrollment rights के साथ client-auth, enrollment agent या code-signing certificates प्राप्त किए जा सकते हैं। **v2/v3 templates** को प्राथमिकता दें, v1 defaults हटाएँ या उनका स्थान लें, और EKUs को उनके निर्धारित उद्देश्य तक सख्ती से सीमित रखें।<sup>[[1]](#references)</sup>

## Certificate Enrollment

प्रमाणपत्र enrollment प्रक्रिया तब शुरू होती है जब कोई administrator **certificate template बनाता है**, जिसे फिर Enterprise Certificate Authority (CA) **प्रकाशित करता है**। इससे template client enrollment के लिए उपलब्ध हो जाता है। इसके लिए Active Directory object के `certificatetemplates` field में template का नाम जोड़ा जाता है।<sup>[[4]](#references)</sup>

किसी client के प्रमाणपत्र का अनुरोध करने के लिए **enrollment rights** देना ज़रूरी है। ये rights, certificate template और स्वयं Enterprise CA पर मौजूद security descriptors से परिभाषित होते हैं। अनुरोध सफल होने के लिए दोनों जगह permissions देना आवश्यक है।

### Template Enrollment Rights

इन rights को Access Control Entries (ACEs) के ज़रिए निर्दिष्ट किया जाता है। इनमें ऐसी permissions शामिल हैं:

- **Certificate-Enrollment** और **Certificate-AutoEnrollment** rights, जिनमें से प्रत्येक विशिष्ट GUIDs से जुड़ा होता है।
- **ExtendedRights**, जो सभी extended permissions की अनुमति देता है।
- **FullControl/GenericAll**, जो template पर पूरा नियंत्रण देता है।

### Enterprise CA Enrollment Rights

CA के rights उसके security descriptor में बताए जाते हैं, जिसे Certificate Authority management console के ज़रिए देखा जा सकता है। कुछ settings कम privileges वाले users को remote access भी देती हैं, जो सुरक्षा संबंधी चिंता हो सकती है।

### अतिरिक्त Issuance Controls

कुछ controls लागू हो सकते हैं, जैसे:

- **Manager Approval**: अनुरोधों को certificate manager की मंज़ूरी मिलने तक लंबित रखता है।
- **Enrolment Agents and Authorized Signatures**: CSR पर आवश्यक signatures की संख्या और ज़रूरी Application Policy OIDs निर्दिष्ट करते हैं।

### प्रमाणपत्र अनुरोध करने के तरीके

प्रमाणपत्रों का अनुरोध इन तरीकों से किया जा सकता है:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces का उपयोग करके।
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes या TCP/IP के ज़रिए।
3. **certificate enrollment web interface**, जिसमें Certificate Authority Web Enrollment role इंस्टॉल हो।
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service के साथ।
5. Network devices के लिए **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) का उपयोग करके।

Windows users GUI (`certmgr.msc` या `certlm.msc`) या command-line tools (`certreq.exe` या PowerShell के `Get-Certificate` command) से भी प्रमाणपत्रों का अनुरोध कर सकते हैं।

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Certificate Authentication

Active Directory (AD), मुख्य रूप से **Kerberos** और **Secure Channel (Schannel)** protocols का उपयोग करके, certificate authentication को support करता है।

### Kerberos Authentication Process

Kerberos authentication process में, Ticket Granting Ticket (TGT) के लिए user की request पर user के certificate की **private key** से हस्ताक्षर किए जाते हैं। यह request domain controller द्वारा कई validations से गुजरती है, जिनमें certificate की **validity**, **path**, और **revocation status** शामिल हैं। Validations में यह verify करना भी शामिल है कि certificate किसी trusted source से आया है और issuer **NTAUTH certificate store** में मौजूद है। सफल validations के बाद TGT जारी किया जाता है। AD में **`NTAuthCertificates`** object यहां मिलता है:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

प्रमाणपत्र प्रमाणीकरण के लिए trust स्थापित करने में केंद्रीय भूमिका निभाता है।<sup>[[4]](#references)</sup>

**KB5014754** rollout के बाद, आधुनिक Kerberos certificate auth मुख्यतः **mapping strength** पर निर्भर करता है, सिर्फ EKUs पर नहीं।<sup>[[2]](#references)</sup> Hardened forests में:

- सिर्फ **UPN/DNS SAN** वाला certificate अब logon के लिए पर्याप्त नहीं हो सकता।
- KDC **strong binding** को प्राथमिकता देता है, आम तौर पर **SID security extension** (`1.3.6.1.4.1.311.25.2`) या `altSecurityIdentities` में strong explicit mapping को।
- अगर cert में strong mapping नहीं है, तो DCs compatibility mode में **Kdcsvc Event ID 39/41** log करते हैं और enforcement mode में auth अस्वीकार कर देते हैं।
- मिले-जुले attack paths में, **ESC9/ESC16** महत्वपूर्ण हैं, क्योंकि वे जारी किए गए certs से SID extension हटा देते हैं; फिर operators explicit mappings या SAN URL SID formats पर निर्भर करते हैं, जहाँ attack path इनका समर्थन करता है।

### Secure Channel (Schannel) Authentication

Schannel सुरक्षित TLS/SSL connections की सुविधा देता है। Handshake के दौरान client एक certificate प्रस्तुत करता है, जिसे सफलतापूर्वक validate किए जाने पर access की अनुमति मिलती है। Certificate को AD account से map करने में Kerberos का **S4U2Self** function या certificate का **Subject Alternative Name (SAN)**, अन्य तरीकों के साथ, शामिल हो सकता है।<sup>[[4]](#references)</sup>

**PKINIT** उपलब्ध न होने पर Schannel एक व्यावहारिक fallback भी है। उदाहरण के लिए, यदि domain controller के पास उपयुक्त **Smart Card Logon** certificate नहीं है, तो `certipy auth`/PKINIT tooling TGT प्राप्त करने में विफल हो सकता है, लेकिन वही certificate authentication और LDAP operations के लिए **LDAPS** या **LDAP StartTLS** के विरुद्ध उपयोगी हो सकता है।

### AD Certificate Services Enumeration

AD की certificate services को LDAP queries के ज़रिए enumerate किया जा सकता है, जिससे **Enterprise Certificate Authorities (CAs)** और उनके configurations की जानकारी सामने आती है। यह बिना किसी विशेष privilege के, domain-authenticated किसी भी user के लिए सुलभ है। **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** जैसे tools का उपयोग AD CS environments में enumeration और vulnerability assessment के लिए किया जाता है।

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

## हाल की कमजोरियाँ और सुरक्षा अपडेट (2022-2025)

| वर्ष | ID / नाम | प्रभाव | मुख्य बातें |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT के दौरान machine account certificates को spoof करके *Privilege escalation*। | पैच **May 10 2022** के security updates में शामिल है। Auditing और strong-mapping controls **KB5014754** के ज़रिए लाए गए थे; अब environments को *Full Enforcement* mode में होना चाहिए। |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) और CES roles में *Remote code-execution*। | सार्वजनिक PoCs सीमित हैं, लेकिन vulnerable IIS components अक्सर आंतरिक रूप से exposed होते हैं। **July 2023** Patch Tuesday तक का पैच लागू करें। |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** पर, enrollment rights वाला requester CSR में **Application Policies/EKUs** जोड़ सकता है, जिन्हें template EKUs पर प्राथमिकता मिलती है। इससे client-auth, enrollment agent या code-signing certificates बन सकते हैं। | **November 12, 2024** तक पैच उपलब्ध है। v1 templates (जैसे default WebServer) को बदलें या supersede करें, EKUs को उनके उद्देश्य तक सीमित रखें और enrollment rights सीमित करें। |

### Microsoft hardening की समयरेखा (KB5014754)

Microsoft ने Kerberos certificate authentication को weak implicit mappings से हटाने के लिए तीन-चरणीय rollout (Compatibility → Audit → Enforcement) शुरू किया। **February 11, 2025** से, यदि `StrongCertificateBindingEnforcement` registry value सेट नहीं है, तो domain controllers अपने-आप **Full Enforcement** पर स्विच हो जाते हैं। Microsoft ने बाद में समयरेखा अपडेट की, ताकि **September 9, 2025** के security update तक compatibility mode पर वापस जाना संभव रहे।<sup>[[2]](#references)</sup> Administrators को चाहिए कि वे:

1. सभी DCs और AD CS servers पर (May 2022 या उसके बाद के) पैच लागू करें।
2. *Audit* चरण के दौरान weak mappings के लिए Event ID 39/41 की निगरानी करें।
3. enforcement द्वारा weak mappings को ब्लॉक करने से पहले, client-auth certificates को नए **SID extension** के साथ दोबारा जारी करें या strong manual mappings configure करें।

### Hardened forests के लिए operator notes

- **2025+ environments में केवल ESC1/ESC6 पूरी कहानी नहीं है**। यदि आप किसी अन्य principal के लिए cert का अनुरोध करते हैं, तो आमतौर पर आपको strong mapping artifact, जैसे SID extension या explicit mapping, की भी ज़रूरत होती है।
- **ESC15 (EKUwu)** unpatched environments में मुख्य रूप से उपयोगी है, क्योंकि इससे **WebServer** जैसे हानिरहित **v1** templates में **Application Policies** inject करके authentication- या enrollment-agent-capable certs बनाए जा सकते हैं। Kerberos PKINIT अब भी EKUs को evaluate करता है, लेकिन **LDAP Schannel** Application Policies को भी मानता है, इसलिए LDAP-आधारित दुरुपयोग प्रासंगिक बना रहता है।<sup>[[1]](#references)</sup>
- **ESC16** CA-व्यापी knob है: यदि CA SID security extension को globally disable करता है, तो जारी किया गया हर certificate weaker mapping behavior की ओर लौटता है—जब तक कि attack chain किसी अन्य supported format से SID inject न करे।
- **ESC7 rights अलग-अलग हैं:** CA का `ManageCA` grant `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) जैसी settings में बदलाव की अनुमति दे सकता है, जबकि `ManageCertificates` request approval को नियंत्रित करता है। Certificate-manager rights पर explicit Deny उस approval route को रोक सकता है, भले ही Allow भी मौजूद हो; settings और templates को chain करने से पहले प्रभावी CA ACL का आकलन करें। [Microsoft का CA ACL आकलन](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting) देखें।

---

## Detection और Hardening में सुधार

* **Defender for Identity AD CS sensor (2023-2024)** अब ESC1-ESC8/ESC11 के लिए posture assessments दिखाता है और real-time alerts जारी करता है, जैसे *“Domain-controller certificate issuance for a non-DC”* (ESC8) और *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15)। इन detections का लाभ पाने के लिए सभी AD CS servers पर sensors deploy करना सुनिश्चित करें।<sup>[[3]](#references)</sup>
* सभी templates पर **“Supply in the request”** विकल्प को disable करें या उसका दायरा सख्ती से सीमित रखें; स्पष्ट रूप से निर्धारित SAN/EKU values को प्राथमिकता दें।
* जब तक बिल्कुल आवश्यक न हो, templates से **Any Purpose** या **No EKU** हटाएँ (इससे ESC2 scenarios को संबोधित किया जाता है)।
* संवेदनशील templates (जैसे WebServer / CodeSigning) के लिए **manager approval** या dedicated Enrollment Agent workflows आवश्यक करें।
* Web enrollment (`certsrv`) और CES/NDES endpoints को trusted networks तक सीमित रखें या client-certificate authentication के पीछे रखें।
* ESC11 (RPC relay) को कम करने के लिए RPC enrollment encryption लागू करें (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`)। यह flag **डिफ़ॉल्ट रूप से चालू** होता है, लेकिन legacy clients के लिए अक्सर disable किया जाता है, जिससे relay का जोखिम फिर से पैदा हो जाता है।
* **IIS-आधारित enrollment endpoints** (CES/Certsrv) सुरक्षित करें: जहाँ संभव हो NTLM disable करें या ESC8 relays को रोकने के लिए HTTPS + Extended Protection आवश्यक करें।

ESC11 का आकलन CA चलाने वाले host पर करें, जो domain controller के बजाय domain member server भी हो सकता है। `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` के अंतर्गत active CA का `InterfaceFlags` पढ़ें; value का unreadable या missing होना unknown result है, RPC encryption disabled होने का प्रमाण नहीं। `IF_ENFORCEENCRYPTICERTREQUEST` bit clear होना configuration की जाँच के लिए एक संकेत है; फिर भी reachable enrollment RPC endpoint, coercible credentials और उपयोग योग्य certificate template की आवश्यकता होती है। ESC8 के लिए, केवल HTTP NTLM challenge पर्याप्त नहीं है: पुष्टि करें कि काम करने वाला enrollment endpoint मौजूद है।

---

## References

- [1] [EKUwu: केवल एक और AD CS ESC नहीं](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows domain controllers पर certificate-आधारित authentication में बदलाव](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates की सुरक्षा स्थिति का आकलन - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services का दुरुपयोग](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
