# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## परिचय

### Certificate के Components

- Certificate का **Subject** उसके owner को दर्शाता है।
- एक **Public Key** को privately held key के साथ pair किया जाता है, ताकि Certificate को उसके सही owner से जोड़ा जा सके।
- **Validity Period**, जिसे **NotBefore** और **NotAfter** dates द्वारा परिभाषित किया जाता है, Certificate की प्रभावी अवधि दर्शाता है।
- Certificate Authority (CA) द्वारा प्रदान किया गया unique **Serial Number**, प्रत्येक Certificate की पहचान करता है।
- **Issuer** उस CA को संदर्भित करता है जिसने Certificate जारी किया है।
- **SubjectAlternativeName** Subject के लिए additional names की अनुमति देता है, जिससे identification में अधिक flexibility मिलती है।
- **Basic Constraints** यह पहचानते हैं कि Certificate CA के लिए है या end entity के लिए, और usage restrictions निर्धारित करते हैं।
- **Extended Key Usages (EKUs)** Object Identifiers (OIDs) के माध्यम से Certificate के specific purposes, जैसे code signing या email encryption, निर्धारित करते हैं।
- **Signature Algorithm** Certificate पर signing के लिए उपयोग की जाने वाली method निर्दिष्ट करता है।
- Issuer की private key से बनाई गई **Signature**, Certificate की authenticity सुनिश्चित करती है।<sup>[[4]](#references)</sup>

### विशेष विचार

- **Subject Alternative Names (SANs)** Certificate की applicability को multiple identities तक बढ़ाते हैं, जो multiple domains वाले servers के लिए महत्वपूर्ण है। SAN specification में attackers द्वारा manipulation से impersonation risks को रोकने के लिए secure issuance processes आवश्यक हैं।<sup>[[4]](#references)</sup>

### Active Directory (AD) में Certificate Authorities (CAs)

AD CS, AD forest में CA certificates को designated containers के माध्यम से पहचानता है, जिनमें से प्रत्येक की unique role होती है:<sup>[[4]](#references)</sup>

- **Certification Authorities** container में trusted root CA certificates होते हैं।
- **Enrolment Services** container में Enterprise CAs और उनके certificate templates की details होती हैं।
- **NTAuthCertificates** object में AD authentication के लिए authorized CA certificates शामिल होते हैं।
- **AIA (Authority Information Access)** container intermediate और cross CA certificates के साथ certificate chain validation को facilitate करता है।

### Certificate Acquisition: Client Certificate Request Flow

1. Request process clients द्वारा Enterprise CA खोजने से शुरू होता है।
2. Public-private key pair generate करने के बाद एक CSR बनाया जाता है, जिसमें public key और अन्य details शामिल होती हैं।
3. CA उपलब्ध certificate templates के अनुसार CSR का assessment करता है और template की permissions के आधार पर Certificate जारी करता है।
4. Approval मिलने पर CA अपनी private key से Certificate पर sign करता है और उसे client को वापस भेजता है।<sup>[[4]](#references)</sup>

### Certificate Templates

AD के भीतर defined ये templates Certificates जारी करने के लिए settings और permissions निर्धारित करते हैं। इनमें permitted EKUs तथा enrollment या modification rights शामिल होते हैं, जो certificate services तक access manage करने के लिए critical हैं।<sup>[[4]](#references)</sup>

**Template schema version महत्वपूर्ण है।** Legacy **v1** templates (उदाहरण के लिए, built-in **WebServer** template) में कई modern enforcement knobs नहीं होते। **ESC15/EKUwu** research से पता चला कि **v1 templates** पर requester CSR में **Application Policies/EKUs** embed कर सकता है, जिन्हें template में configured EKUs की **preferred** priority मिलती है। इससे केवल enrollment rights के साथ client-auth, enrollment agent या code-signing certificates enable हो सकते हैं। **v2/v3 templates** को प्राथमिकता दें, v1 defaults को remove या supersede करें, और EKUs को intended purpose तक tightly scope करें।<sup>[[1]](#references)</sup>

## Certificate Enrollment

Certificates के लिए enrollment process एक administrator द्वारा **certificate template create** करने से शुरू होता है, जिसे बाद में Enterprise Certificate Authority (CA) द्वारा **publish** किया जाता है। इससे template client enrollment के लिए available हो जाता है। यह Active Directory object के `certificatetemplates` field में template का name add करके किया जाता है।<sup>[[4]](#references)</sup>

किसी client द्वारा Certificate request करने के लिए **enrollment rights** grant किए जाने आवश्यक हैं। ये rights certificate template और Enterprise CA पर मौजूद security descriptors द्वारा defined होते हैं। Request को successful बनाने के लिए दोनों locations पर permissions grant की जानी चाहिए।

### Template Enrollment Rights

ये rights Access Control Entries (ACEs) के माध्यम से specified होते हैं, जो निम्न permissions जैसी permissions का विवरण देते हैं:

- **Certificate-Enrollment** और **Certificate-AutoEnrollment** rights, जिनमें से प्रत्येक specific GUIDs से associated होता है।
- **ExtendedRights**, जो सभी extended permissions की अनुमति देता है।
- **FullControl/GenericAll**, जो template पर complete control प्रदान करता है।

### Enterprise CA Enrollment Rights

CA के rights उसके security descriptor में outlined होते हैं, जिसे Certificate Authority management console के माध्यम से access किया जा सकता है। कुछ settings low-privileged users को remote access भी allow करती हैं, जो security concern हो सकता है।

### Additional Issuance Controls

कुछ controls लागू हो सकते हैं, जैसे:

- **Manager Approval**: Requests को pending state में रखता है, जब तक कि certificate manager उन्हें approve न कर दे।
- **Enrolment Agents and Authorized Signatures**: CSR पर required signatures की संख्या और आवश्यक Application Policy OIDs specify करते हैं।

### Certificates Request करने के Methods

Certificates को निम्न methods के माध्यम से request किया जा सकता है:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces का उपयोग करके।
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes या TCP/IP के माध्यम से।
3. **certificate enrollment web interface**, जिसमें Certificate Authority Web Enrollment role installed हो।
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service के साथ।
5. Network devices के लिए **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) का उपयोग करके।

Windows users GUI (`certmgr.msc` या `certlm.msc`) या command-line tools (`certreq.exe` या PowerShell के `Get-Certificate` command) के माध्यम से भी Certificates request कर सकते हैं।
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) प्रमाणपत्र प्रमाणीकरण का समर्थन करता है, जिसमें मुख्य रूप से **Kerberos** और **Secure Channel (Schannel)** protocols का उपयोग किया जाता है।

### Kerberos Authentication Process

Kerberos authentication process में, किसी user का Ticket Granting Ticket (TGT) के लिए request उसके certificate की **private key** का उपयोग करके sign किया जाता है। यह request domain controller द्वारा कई validations से गुजरती है, जिनमें certificate की **validity**, **path**, और **revocation status** शामिल हैं। Validations में यह verify करना भी शामिल है कि certificate किसी trusted source से आया है और issuer की उपस्थिति **NTAUTH certificate store** में है। सफल validations के परिणामस्वरूप TGT जारी किया जाता है। AD में **`NTAuthCertificates`** object यहां पाया जाता है:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
प्रमाणपत्र authentication के लिए trust स्थापित करने में केंद्रीय भूमिका निभाता है।<sup>[[4]](#references)</sup>

**KB5014754** के rollout के बाद, modern Kerberos certificate auth मुख्य रूप से केवल EKUs पर नहीं, बल्कि **mapping strength** पर निर्भर करता है।<sup>[[2]](#references)</sup> Hardened forests में:

- केवल **UPN/DNS SAN** वाला प्रमाणपत्र अब logon के लिए पर्याप्त नहीं हो सकता।
- KDC एक **strong binding** को प्राथमिकता देता है, आमतौर पर **SID security extension** (`1.3.6.1.4.1.311.25.2`) या `altSecurityIdentities` में strong explicit mapping को।
- यदि प्रमाणपत्र में strong mapping नहीं है, तो DCs compatibility mode में **Kdcsvc Event ID 39/41** log करते हैं और enforcement mode में auth अस्वीकार कर देते हैं।
- Mixed attack paths में **ESC9/ESC16** महत्वपूर्ण हैं, क्योंकि वे जारी किए गए प्रमाणपत्रों से SID extension हटा देते हैं; इसके बाद operators explicit mappings या SAN URL SID formats पर निर्भर करते हैं, जहां attack path में उनका support हो।

### Secure Channel (Schannel) Authentication

Schannel secure TLS/SSL connections को enable करता है। Handshake के दौरान client एक प्रमाणपत्र प्रस्तुत करता है, जिसे सफलतापूर्वक validate किए जाने पर access authorize किया जाता है। किसी प्रमाणपत्र को AD account से map करने में अन्य methods के साथ Kerberos का **S4U2Self** function या प्रमाणपत्र का **Subject Alternative Name (SAN)** शामिल हो सकता है।<sup>[[4]](#references)</sup>

जब **PKINIT** उपलब्ध नहीं होता, तब Schannel एक practical fallback भी है। उदाहरण के लिए, यदि किसी domain controller के पास उपयुक्त **Smart Card Logon** प्रमाणपत्र नहीं है, तो `certipy auth`/PKINIT tooling TGT प्राप्त करने में विफल हो सकती है, लेकिन वही प्रमाणपत्र authentication और LDAP operations के लिए **LDAPS** या **LDAP StartTLS** के विरुद्ध फिर भी उपयोग किया जा सकता है।

### AD Certificate Services Enumeration

AD की certificate services को LDAP queries के माध्यम से enumerate किया जा सकता है, जिससे **Enterprise Certificate Authorities (CAs)** और उनकी configurations की जानकारी मिलती है। यह किसी भी domain-authenticated user के लिए special privileges के बिना accessible है। **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** जैसे tools का उपयोग AD CS environments में enumeration और vulnerability assessment के लिए किया जाता है।

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
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT के दौरान machine account certificates को spoof करके *Privilege escalation*। | पैच **May 10 2022** के security updates में शामिल है। **KB5014754** के माध्यम से Auditing और strong-mapping controls शुरू किए गए; अब environments को *Full Enforcement* mode में होना चाहिए।  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) और CES roles में *Remote code-execution*। | Public PoCs सीमित हैं, लेकिन vulnerable IIS components अक्सर internally exposed होते हैं। **July 2023** Patch Tuesday के अनुसार पैच उपलब्ध है।  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** पर, enrollment rights वाला requester CSR में **Application Policies/EKUs** embed कर सकता है, जिन्हें template EKUs की तुलना में प्राथमिकता दी जाती है। इससे client-auth, enrollment agent या code-signing certificates बनाए जा सकते हैं। | **November 12, 2024** तक पैच उपलब्ध है। v1 templates (जैसे default WebServer) को replace या supersede करें, EKUs को उनके उद्देश्य तक सीमित करें और enrollment rights को सीमित रखें। |

### Microsoft hardening timeline (KB5014754)

Microsoft ने Kerberos certificate authentication को weak implicit mappings से दूर ले जाने के लिए तीन-phase rollout (Compatibility → Audit → Enforcement) शुरू किया। **February 11, 2025** तक, यदि `StrongCertificateBindingEnforcement` registry value set नहीं है, तो domain controllers स्वतः **Full Enforcement** पर switch हो जाते हैं। Microsoft ने बाद में timeline को update किया, जिससे **September 9, 2025** security update तक compatibility mode पर fallback संभव रहेगा।<sup>[[2]](#references)</sup> Administrators को:

1. सभी DCs और AD CS servers को patch करें (May 2022 या बाद का संस्करण)।
2. *Audit* phase के दौरान weak mappings के लिए Event ID 39/41 को monitor करें।
3. Enforcement द्वारा weak mappings को block करने से पहले client-auth certificates को नए **SID extension** के साथ re-issue करें या strong manual mappings configure करें।

### Hardened forests के लिए Operator notes

- **ESC1/ESC6 अब अकेले पूरी कहानी नहीं हैं**, खासकर 2025+ environments में। यदि आप किसी अन्य principal के लिए cert request करते हैं, तो आमतौर पर आपको SID extension या explicit mapping जैसे strong mapping artifact की भी आवश्यकता होगी।
- **ESC15 (EKUwu)** unpatched environments में मुख्य रूप से उपयोगी है, क्योंकि यह **Application Policies** inject करके **WebServer** जैसे harmless **v1** templates को authentication- या enrollment-agent-capable certs में बदल देता है। Kerberos PKINIT अभी भी EKUs को evaluate करता है, लेकिन **LDAP Schannel** भी Application Policies को honor करता है, जिससे LDAP-based abuse relevant बना रहता है।<sup>[[1]](#references)</sup>
- **ESC16** एक CA-wide knob है: यदि CA globally SID security extension को disable कर देता है, तो हर issued certificate weaker mapping behavior की ओर fallback करता है, जब तक attack chain किसी अन्य supported format से SID inject न करे।

---

## Detection और Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** अब ESC1-ESC8/ESC11 के लिए posture assessments दिखाता है और real-time alerts generate करता है, जैसे *“Domain-controller certificate issuance for a non-DC”* (ESC8) और *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15)। इन detections का लाभ लेने के लिए सभी AD CS servers पर sensors deploy करें।<sup>[[3]](#references)</sup>
* सभी templates पर **“Supply in the request”** option को disable करें या इसका scope कड़ाई से सीमित करें; explicitly defined SAN/EKU values को प्राथमिकता दें।
* जब तक बिल्कुल आवश्यक न हो, templates से **Any Purpose** या **No EKU** हटाएं (यह ESC2 scenarios को address करता है)।
* Sensitive templates (जैसे WebServer / CodeSigning) के लिए **manager approval** या dedicated Enrollment Agent workflows अनिवार्य करें।
* Web enrollment (`certsrv`) और CES/NDES endpoints को trusted networks तक सीमित करें या client-certificate authentication के पीछे रखें।
* ESC11 (RPC relay) को mitigate करने के लिए RPC enrollment encryption लागू करें (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`)। यह flag **by default on** होता है, लेकिन legacy clients के लिए अक्सर disabled रहता है, जिससे relay risk फिर से खुल जाता है।
* **IIS-based enrollment endpoints** (CES/Certsrv) को secure करें: जहां संभव हो NTLM disable करें या ESC8 relays को block करने के लिए HTTPS + Extended Protection अनिवार्य करें।

---

## References

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
