# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **Subject** certificate का मालिक दर्शाता है।
- एक **Public Key** एक निजी रूप से रखी गई key के साथ जोड़ी जाती है ताकि certificate को उसके सही मालिक से जोड़ा जा सके।
- **Validity Period**, जो **NotBefore** और **NotAfter** dates द्वारा परिभाषित है, certificate की प्रभावी अवधि को दर्शाता है।
- एक unique **Serial Number**, जो Certificate Authority (CA) द्वारा प्रदान किया जाता है, हर certificate की पहचान करता है।
- **Issuer** उस CA को संदर्भित करता है जिसने certificate जारी किया है।
- **SubjectAlternativeName** subject के लिए अतिरिक्त नामों की अनुमति देता है, जिससे identification flexibility बढ़ती है।
- **Basic Constraints** पहचानते हैं कि certificate CA के लिए है या end entity के लिए, और usage restrictions परिभाषित करते हैं।
- **Extended Key Usages (EKUs)** Object Identifiers (OIDs) के माध्यम से certificate के specific purposes, जैसे code signing या email encryption, को बताता है।
- **Signature Algorithm** certificate को sign करने की method निर्दिष्ट करता है।
- **Signature**, issuer की private key से बनाई गई, certificate की authenticity की गारंटी देती है।

### Special Considerations

- **Subject Alternative Names (SANs)** certificate की applicability को multiple identities तक बढ़ाते हैं, जो multiple domains वाले servers के लिए महत्वपूर्ण है। Secure issuance processes जरूरी हैं ताकि attackers द्वारा SAN specification में manipulation करके impersonation risks से बचा जा सके।

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS AD forest में CA certificates को designated containers के माध्यम से मान्यता देता है, जिनमें से हर एक unique roles निभाता है:

- **Certification Authorities** container trusted root CA certificates रखता है।
- **Enrolment Services** container Enterprise CAs और उनके certificate templates का विवरण देता है।
- **NTAuthCertificates** object AD authentication के लिए authorized CA certificates शामिल करता है।
- **AIA (Authority Information Access)** container intermediate और cross CA certificates के साथ certificate chain validation को आसान बनाता है।

### Certificate Acquisition: Client Certificate Request Flow

1. request process clients द्वारा Enterprise CA खोजने से शुरू होता है।
2. public-private key pair generate करने के बाद, public key और अन्य details सहित एक CSR बनाया जाता है।
3. CA उपलब्ध certificate templates के विरुद्ध CSR का मूल्यांकन करता है, और template permissions के आधार पर certificate जारी करता है।
4. approval मिलने पर, CA अपनी private key से certificate sign करता है और उसे client को लौटाता है।

### Certificate Templates

AD के भीतर defined, ये templates certificate issuing के लिए settings और permissions outline करते हैं, जिनमें permitted EKUs और enrollment या modification rights शामिल हैं, जो certificate services तक access manage करने के लिए महत्वपूर्ण हैं।

**Template schema version matters.** Legacy **v1** templates (for example, the built-in **WebServer** template) में कई modern enforcement knobs नहीं होते। **ESC15/EKUwu** research ने दिखाया कि **v1 templates** पर, requester CSR में **Application Policies/EKUs** embed कर सकता है जो template के configured EKUs पर **preferred over** होते हैं, जिससे केवल enrollment rights के साथ client-auth, enrollment agent, या code-signing certificates enable हो जाते हैं। **v2/v3 templates** को prefer करें, v1 defaults को remove या supersede करें, और EKUs को intended purpose तक tightly scope करें।

## Certificate Enrollment

certificate के लिए enrollment process एक administrator द्वारा शुरू किया जाता है जो **creates a certificate template** करता है, जिसे फिर Enterprise Certificate Authority (CA) द्वारा **published** किया जाता है। इससे template client enrollment के लिए उपलब्ध हो जाता है, जो Active Directory object के `certificatetemplates` field में template का name जोड़कर हासिल किया जाता है।

एक client को certificate request करने के लिए, **enrollment rights** granted होने चाहिए। ये rights certificate template और Enterprise CA स्वयं पर security descriptors द्वारा defined होते हैं। request सफल होने के लिए दोनों स्थानों पर permissions granted होनी चाहिए।

### Template Enrollment Rights

ये rights Access Control Entries (ACEs) के माध्यम से specified होते हैं, जिनमें permissions का विवरण होता है जैसे:

- **Certificate-Enrollment** और **Certificate-AutoEnrollment** rights, जिनमें से प्रत्येक specific GUIDs से associated है।
- **ExtendedRights**, जो सभी extended permissions की अनुमति देता है।
- **FullControl/GenericAll**, जो template पर complete control प्रदान करता है।

### Enterprise CA Enrollment Rights

CA के rights उसके security descriptor में outlined होते हैं, जो Certificate Authority management console के माध्यम से accessible है। कुछ settings तो low-privileged users को remote access भी allow करती हैं, जो एक security concern हो सकता है।

### Additional Issuance Controls

कुछ controls लागू हो सकते हैं, जैसे:

- **Manager Approval**: requests को pending state में रखता है जब तक certificate manager द्वारा approved न हो जाए।
- **Enrolment Agents and Authorized Signatures**: एक CSR पर required signatures की संख्या और आवश्यक Application Policy OIDs specify करते हैं।

### Methods to Request Certificates

Certificates इनके माध्यम से requested किए जा सकते हैं:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces का उपयोग करके।
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes या TCP/IP के माध्यम से।
3. **certificate enrollment web interface**, जब Certificate Authority Web Enrollment role installed हो।
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service के साथ।
5. नेटवर्क devices के लिए **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) का उपयोग करके।

Windows users GUI (`certmgr.msc` or `certlm.msc`) या command-line tools (`certreq.exe` or PowerShell's `Get-Certificate` command) के माध्यम से भी certificates request कर सकते हैं।
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) certificate authentication को सपोर्ट करता है, मुख्यतः **Kerberos** और **Secure Channel (Schannel)** protocols का उपयोग करके।

### Kerberos Authentication Process

Kerberos authentication process में, user के Ticket Granting Ticket (TGT) के लिए request, user के certificate की **private key** का उपयोग करके signed होती है। यह request domain controller द्वारा कई validations से गुजरती है, जिनमें certificate की **validity**, **path**, और **revocation status** शामिल हैं। Validations में यह भी verify करना शामिल है कि certificate एक trusted source से आया है और issuer की **NTAUTH certificate store** में presence confirm करना। Successful validations के परिणामस्वरूप TGT जारी किया जाता है। AD में **`NTAuthCertificates`** object, यहां पाया जाता है:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is certificate authentication के लिए trust स्थापित करने का मूल है।

**KB5014754** rollout के बाद, modern Kerberos certificate auth अब ज़्यादातर **mapping strength** पर आधारित है, सिर्फ EKUs पर नहीं। hardened forests में:

- सिर्फ **UPN/DNS SAN** वाला certificate logon के लिए अब पर्याप्त नहीं भी हो सकता।
- KDC आमतौर पर **strong binding** को प्राथमिकता देता है, खासकर **SID security extension** (`1.3.6.1.4.1.311.25.2`) या `altSecurityIdentities` में strong explicit mapping।
- अगर cert में strong mapping नहीं है, तो DCs compatibility mode में **Kdcsvc Event ID 39/41** log करते हैं और enforcement mode में auth deny करते हैं।
- mixed attack paths में **ESC9/ESC16** महत्वपूर्ण हैं क्योंकि ये issued certs से SID extension हटा देते हैं; फिर operators explicit mappings या SAN URL SID formats पर निर्भर करते हैं जहाँ attack path उन्हें support करता है।

### Secure Channel (Schannel) Authentication

Schannel secure TLS/SSL connections को facilitate करता है, जहाँ handshake के दौरान client एक certificate प्रस्तुत करता है, और अगर वह successfully validate हो जाए, तो access authorize हो जाता है। किसी certificate को AD account से map करने में Kerberos का **S4U2Self** function या certificate का **Subject Alternative Name (SAN)**, और अन्य methods शामिल हो सकते हैं।

Schannel तब भी practical fallback है जब **PKINIT** unavailable हो। उदाहरण के लिए, अगर किसी domain controller के पास suitable **Smart Card Logon** certificate नहीं है, तो `certipy auth`/PKINIT tooling TGT प्राप्त करने में fail हो सकता है, लेकिन वही certificate अभी भी authentication और LDAP operations के लिए **LDAPS** या **LDAP StartTLS** के against usable हो सकता है।

### AD Certificate Services Enumeration

AD की certificate services को LDAP queries के जरिए enumerate किया जा सकता है, जिससे **Enterprise Certificate Authorities (CAs)** और उनकी configurations की information मिलती है। यह किसी भी domain-authenticated user के लिए, बिना special privileges के, accessible है। **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** जैसे tools AD CS environments में enumeration और vulnerability assessment के लिए उपयोग किए जाते हैं।

इन tools के उपयोग के commands में शामिल हैं:
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

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT के दौरान machine account certificates को spoof करके *Privilege escalation*। | Patch **10 May 2022** के security updates में शामिल है। Auditing और strong-mapping controls **KB5014754** के जरिए introduced किए गए; environments अब *Full Enforcement* mode में होने चाहिए। |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) और CES roles में *Remote code-execution*। | Public PoCs सीमित हैं, लेकिन vulnerable IIS components अक्सर internally exposed होते हैं। Patch **July 2023** Patch Tuesday तक उपलब्ध था। |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** पर, enrollment rights वाला requester CSR में **Application Policies/EKUs** embed कर सकता है, जो template EKUs पर प्राथमिकता लेते हैं, और client-auth, enrollment agent, या code-signing certificates बनते हैं। | **12 November, 2024** तक patched। v1 templates (जैसे default WebServer) को replace या supersede करें, EKUs को intent तक सीमित रखें, और enrollment rights सीमित करें। |

### Microsoft hardening timeline (KB5014754)

Microsoft ने Kerberos certificate authentication को weak implicit mappings से दूर ले जाने के लिए तीन-चरण rollout (Compatibility → Audit → Enforcement) introduced किया। **11 February, 2025** तक, यदि `StrongCertificateBindingEnforcement` registry value set नहीं है, तो domain controllers automatically **Full Enforcement** पर switch हो जाते हैं। बाद में Microsoft ने timeline अपडेट की ताकि compatibility mode में fallback **9 September, 2025** security update तक संभव रहे। Administrators को:

1. सभी DCs & AD CS servers (May 2022 या बाद के) patch करने चाहिए।
2. *Audit* phase के दौरान weak mappings के लिए Event ID 39/41 monitor करना चाहिए।
3. enforcement weak mappings को block करने से पहले client-auth certificates को नए **SID extension** के साथ re-issue करना चाहिए या strong manual mappings configure करनी चाहिए।

### Hardened forests के लिए operator notes

- **ESC1/ESC6 अकेले 2025+ environments में पूरी कहानी नहीं है**। यदि आप किसी अन्य principal के लिए cert request करते हैं, तो आमतौर पर आपको SID extension या explicit mapping जैसे strong mapping artifact की भी आवश्यकता होती है।
- **ESC15 (EKUwu)** अधिकतर unpatched environments में valuable है क्योंकि यह **WebServer** जैसे harmless **v1** templates को **Application Policies** inject करके authentication- या enrollment-agent-capable certs में बदल देता है। Kerberos PKINIT अभी भी EKUs evaluate करता है, लेकिन **LDAP Schannel** भी Application Policies honor करता है, जिससे LDAP-based abuse relevant बना रहता है।
- **ESC16** एक CA-wide knob है: यदि CA globally SID security extension disable करता है, तो जारी किया गया हर certificate weaker mapping behavior की ओर fall back करेगा, जब तक attack chain किसी अन्य supported format द्वारा SID inject न करे।

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** अब ESC1-ESC8/ESC11 के लिए posture assessments दिखाता है और real-time alerts generate करता है जैसे *“Domain-controller certificate issuance for a non-DC”* (ESC8) और *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15)। इन detections का लाभ लेने के लिए सुनिश्चित करें कि sensors सभी AD CS servers पर deployed हों।
* सभी templates पर **“Supply in the request”** option disable करें या tightly scope करें; explicitly defined SAN/EKU values को prefer करें।
* जब तक absolutely required न हो, templates से **Any Purpose** या **No EKU** हटाएँ (ESC2 scenarios को address करता है)।
* sensitive templates (जैसे WebServer / CodeSigning) के लिए **manager approval** या dedicated Enrollment Agent workflows required करें।
* web enrollment (`certsrv`) और CES/NDES endpoints को trusted networks तक या client-certificate authentication के पीछे restrict करें।
* RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) enforce करें ताकि ESC11 (RPC relay) mitigate हो सके। यह flag **by default on** है, लेकिन अक्सर legacy clients के लिए disabled कर दिया जाता है, जिससे relay risk फिर खुल जाता है।
* **IIS-based enrollment endpoints** (CES/Certsrv) secure करें: जहां संभव हो NTLM disable करें या ESC8 relays block करने के लिए HTTPS + Extended Protection required करें।

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
