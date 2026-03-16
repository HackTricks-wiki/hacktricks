# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- The **Subject** of the certificate denotes its owner.  
  प्रमाणपत्र का **Subject** इसका मालिक दर्शाता है।
- A **Public Key** is paired with a privately held key to link the certificate to its rightful owner.  
  एक **Public Key** को निजी रूप से रखे गए की के साथ जोड़ा जाता है ताकि प्रमाणपत्र को उसके सही मालिक से जोड़ा जा सके।
- The **Validity Period**, defined by **NotBefore** and **NotAfter** dates, marks the certificate's effective duration.  
  **Validity Period**, जिसे **NotBefore** और **NotAfter** तिथियों द्वारा परिभाषित किया जाता है, प्रमाणपत्र की प्रभावी अवधि को दर्शाता है।
- A unique **Serial Number**, provided by the Certificate Authority (CA), identifies each certificate.  
  एक अद्वितीय **Serial Number**, जो Certificate Authority (CA) द्वारा दिया जाता है, हर प्रमाणपत्र की पहचान करता है।
- The **Issuer** refers to the CA that has issued the certificate.  
  **Issuer** उस CA को संदर्भित करता है जिसने प्रमाणपत्र जारी किया है।
- **SubjectAlternativeName** allows for additional names for the subject, enhancing identification flexibility.  
  **SubjectAlternativeName** विषय के लिए अतिरिक्त नामों की अनुमति देता है, जिससे पहचान की लचीलापन बढ़ती है।
- **Basic Constraints** identify if the certificate is for a CA or an end entity and define usage restrictions.  
  **Basic Constraints** निर्धारित करते हैं कि प्रमाणपत्र CA के लिए है या किसी end entity के लिए और उपयोग प्रतिबंधों को परिभाषित करते हैं।
- **Extended Key Usages (EKUs)** delineate the certificate's specific purposes, like code signing or email encryption, through Object Identifiers (OIDs).  
  **Extended Key Usages (EKUs)** Object Identifiers (OIDs) के माध्यम से प्रमाणपत्र के विशिष्ट उद्देश्यों को निर्दिष्ट करते हैं, जैसे code signing या email encryption।
- The **Signature Algorithm** specifies the method for signing the certificate.  
  **Signature Algorithm** प्रमाणपत्र पर हस्ताक्षर करने की विधि को निर्दिष्ट करता है।
- The **Signature**, created with the issuer's private key, guarantees the certificate's authenticity.  
  **Signature**, जिसे issuer की private key से बनाया जाता है, प्रमाणपत्र की प्रामाणिकता की गारंटी देती है।

### Special Considerations

- **Subject Alternative Names (SANs)** expand a certificate's applicability to multiple identities, crucial for servers with multiple domains. Secure issuance processes are vital to avoid impersonation risks by attackers manipulating the SAN specification.  
  **Subject Alternative Names (SANs)** एक प्रमाणपत्र की उपयोगिता को कई पहचानियों तक बढ़ाते हैं, जो कई डोमेन्स वाले सर्वरों के लिए महत्वपूर्ण है। SAN विनिर्देश को बदलकर हमलावरों द्वारा impersonation के जोखिम से बचने के लिए सुरक्षित जारी करने की प्रक्रियाएँ आवश्यक हैं।

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS acknowledges CA certificates in an AD forest through designated containers, each serving unique roles:

- **Certification Authorities** container holds trusted root CA certificates.  
  **Certification Authorities** कंटेनर ट्रस्टेड root CA प्रमाणपत्र रखता है।
- **Enrolment Services** container details Enterprise CAs and their certificate templates.  
  **Enrolment Services** कंटेनर Enterprise CAs और उनके certificate templates का विवरण रखता है।
- **NTAuthCertificates** object includes CA certificates authorized for AD authentication.  
  **NTAuthCertificates** ऑब्जेक्ट में AD authentication के लिए अधिकृत CA प्रमाणपत्र शामिल होते हैं।
- **AIA (Authority Information Access)** container facilitates certificate chain validation with intermediate and cross CA certificates.  
  **AIA (Authority Information Access)** कंटेनर intermediate और cross CA प्रमाणपत्रों के साथ certificate chain validation की सुविधा देता है।

### Certificate Acquisition: Client Certificate Request Flow

1. The request process begins with clients finding an Enterprise CA.  
   अनुरोध प्रक्रिया क्लाइंट के Enterprise CA खोजने से शुरू होती है।
2. A CSR is created, containing a public key and other details, after generating a public-private key pair.  
   public-private key pair जेनरेट करने के बाद एक CSR बनाया जाता है, जिसमें एक public key और अन्य विवरण होते हैं।
3. The CA assesses the CSR against available certificate templates, issuing the certificate based on the template's permissions.  
   CA उपलब्ध certificate templates के खिलाफ CSR का मूल्यांकन करता है और template की permissions के आधार पर प्रमाणपत्र जारी करता है।
4. Upon approval, the CA signs the certificate with its private key and returns it to the client.  
   मंज़ूरी मिलने पर, CA अपने private key से प्रमाणपत्र पर हस्ताक्षर करता है और इसे क्लाइंट को वापस कर देता है।

### Certificate Templates

Defined within AD, these templates outline the settings and permissions for issuing certificates, including permitted EKUs and enrollment or modification rights, critical for managing access to certificate services.  
AD के भीतर परिभाषित, ये templates प्रमाणपत्र जारी करने के लिए सेटिंग्स और permissions का खाका तैयार करते हैं, जिनमें permitted EKUs और enrollment या modification rights शामिल हैं, जो certificate services तक पहुँच प्रबंधित करने के लिए महत्वपूर्ण हैं।

**Template schema version matters.** Legacy **v1** templates (for example, the built-in **WebServer** template) lack several modern enforcement knobs. The **ESC15/EKUwu** research showed that on **v1 templates**, a requester can embed **Application Policies/EKUs** in the CSR that are **preferred over** the template's configured EKUs, enabling client-auth, enrollment agent, or code-signing certificates with only enrollment rights. Prefer **v2/v3 templates**, remove or supersede v1 defaults, and tightly scope EKUs to the intended purpose.  
**Template schema version महत्वपूर्ण है।** Legacy **v1** templates (उदाहरण के लिए, built-in **WebServer** template) कई आधुनिक लागू करने वाले नियंत्रणों की कमी रखते हैं। **ESC15/EKUwu** research ने दिखाया कि **v1 templates** पर, एक requester CSR में **Application Policies/EKUs** embed कर सकता है जो template के configured EKUs पर **prefer** होते हैं, जिससे केवल enrollment rights के साथ client-auth, enrollment agent, या code-signing प्रमाणपत्र सक्षम हो जाते हैं। **v2/v3 templates** को प्राथमिकता दें, v1 defaults को हटाएँ या supersede करें, और EKUs को इच्छित उद्देश्य तक सख्ती से सीमित करें।

## Certificate Enrollment

The enrollment process for certificates is initiated by an administrator who **creates a certificate template**, which is then **published** by an Enterprise Certificate Authority (CA). This makes the template available for client enrollment, a step achieved by adding the template's name to the `certificatetemplates` field of an Active Directory object.  
प्रमाणपत्रों के लिए enrollment प्रक्रिया एक प्रशासक द्वारा शुरू की जाती है जो **एक certificate template बनाता है**, जिसे बाद में Enterprise Certificate Authority (CA) द्वारा **published** किया जाता है। इससे template क्लाइंट enrollment के लिए उपलब्ध हो जाता है, जो Active Directory ऑब्जेक्ट के `certificatetemplates` फील्ड में template का नाम जोड़कर प्राप्त किया जाता है।

For a client to request a certificate, **enrollment rights** must be granted. These rights are defined by security descriptors on the certificate template and the Enterprise CA itself. Permissions must be granted in both locations for a request to be successful.  
किसी क्लाइंट के द्वारा प्रमाणपत्र अनुरोध करने के लिए **enrollment rights** दिए जाने चाहिए। ये rights certificate template और Enterprise CA दोनों पर security descriptors द्वारा परिभाषित होते हैं। अनुरोध सफल होने के लिए दोनों स्थानों पर permissions दिए जाने चाहिए।

### Template Enrollment Rights

These rights are specified through Access Control Entries (ACEs), detailing permissions like:

- **Certificate-Enrollment** and **Certificate-AutoEnrollment** rights, each associated with specific GUIDs.  
  **Certificate-Enrollment** और **Certificate-AutoEnrollment** rights, प्रत्येक विशिष्ट GUIDs से जुड़ा हुआ।
- **ExtendedRights**, allowing all extended permissions.  
  **ExtendedRights**, सभी विस्तारित permissions की अनुमति देता है।
- **FullControl/GenericAll**, providing complete control over the template.  
  **FullControl/GenericAll**, template पर पूर्ण नियंत्रण प्रदान करता है।

### Enterprise CA Enrollment Rights

The CA's rights are outlined in its security descriptor, accessible via the Certificate Authority management console. Some settings even allow low-privileged users remote access, which could be a security concern.  
CA के rights उसके security descriptor में सूचीबद्ध होते हैं, जिन्हें Certificate Authority management console के माध्यम से एक्सेस किया जा सकता है। कुछ सेटिंग्स निम्न-प्राधिकार वाले उपयोगकर्ताओं को remote access भी देती हैं, जो सुरक्षा के लिहाज़ से चिंता का विषय हो सकता है।

### Additional Issuance Controls

Certain controls may apply, such as:

- **Manager Approval**: Places requests in a pending state until approved by a certificate manager.  
  **Manager Approval**: अनुरोधों को pending स्थिति में रखता है जब तक कि प्रमाणपत्र मैनेजर द्वारा स्वीकृत न हो।
- **Enrolment Agents and Authorized Signatures**: Specify the number of required signatures on a CSR and the necessary Application Policy OIDs.  
  **Enrolment Agents and Authorized Signatures**: CSR पर आवश्यक signatures की संख्या और आवश्यक Application Policy OIDs निर्दिष्ट करते हैं।

### Methods to Request Certificates

Certificates can be requested through:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), using DCOM interfaces.  
   **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces का उपयोग करके।
2. **ICertPassage Remote Protocol** (MS-ICPR), through named pipes or TCP/IP.  
   **ICertPassage Remote Protocol** (MS-ICPR), named pipes या TCP/IP के माध्यम से।
3. The **certificate enrollment web interface**, with the Certificate Authority Web Enrollment role installed.  
   **certificate enrollment web interface**, जब Certificate Authority Web Enrollment role स्थापित हो।
4. The **Certificate Enrollment Service** (CES), in conjunction with the Certificate Enrollment Policy (CEP) service.  
   **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service के साथ मिलकर।
5. The **Network Device Enrollment Service** (NDES) for network devices, using the Simple Certificate Enrollment Protocol (SCEP).  
   नेटवर्क उपकरणों के लिए **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) का उपयोग करते हुए।

Windows users can also request certificates via the GUI (`certmgr.msc` or `certlm.msc`) or command-line tools (`certreq.exe` or PowerShell's `Get-Certificate` command).  
Windows उपयोगकर्ता GUI (`certmgr.msc` या `certlm.msc`) या command-line tools (`certreq.exe` या PowerShell का `Get-Certificate` command) के माध्यम से भी प्रमाणपत्र अनुरोध कर सकते हैं।
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## प्रमाणपत्र प्रमाणीकरण

Active Directory (AD) प्रमाणपत्र प्रमाणीकरण का समर्थन करता है, जो मुख्य रूप से **Kerberos** और **Secure Channel (Schannel)** प्रोटोकॉल का उपयोग करता है।

### Kerberos प्रमाणीकरण प्रक्रिया

Kerberos प्रमाणीकरण प्रक्रिया में, उपयोगकर्ता का Ticket Granting Ticket (TGT) के लिए अनुरोध उपयोगकर्ता के प्रमाणपत्र की **निजी कुंजी** का उपयोग करके साइन किया जाता है। यह अनुरोध डोमेन कंट्रोलर द्वारा कई सत्यापनों से गुजरता है, जिनमें प्रमाणपत्र की **वैधता**, **पाथ**, और **निरस्तीकरण स्थिति** शामिल हैं। सत्यापनों में यह भी शामिल है कि प्रमाणपत्र किसी विश्वसनीय स्रोत से आया है और जारीकर्ता की उपस्थिति **NTAUTH certificate store** में पुष्टि की गयी है। सफल सत्यापन TGT जारी होने का परिणाम होते हैं। AD में **`NTAuthCertificates`** ऑब्जेक्ट, पाया जाता है:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
यह प्रमाणपत्र प्रमाणीकरण के लिए भरोसा स्थापित करने में केंद्रीय है।

### Secure Channel (Schannel) प्रमाणीकरण

Schannel सुरक्षित TLS/SSL कनेक्शनों को सक्षम करता है, जहाँ हैंडशेक के दौरान क्लाइंट एक प्रमाणपत्र प्रस्तुत करता है जिसे सफलतापूर्वक सत्यापित होने पर एक्सेस की अनुमति मिलती है। प्रमाणपत्र को AD खाते से मैप करने में Kerberos’s **S4U2Self** फ़ंक्शन या प्रमाणपत्र का **Subject Alternative Name (SAN)**, अन्य विधियों के साथ शामिल हो सकता है।

### AD Certificate Services का एन्यूमरेशन

AD की certificate services को LDAP क्वेरीज़ के माध्यम से एन्यूमरेट किया जा सकता है, जिससे **Enterprise Certificate Authorities (CAs)** और उनकी कॉन्फ़िगरेशन की जानकारी पता चलती है। यह किसी भी डोमेन-प्रमाणीकृत उपयोगकर्ता के लिए बिना किसी विशेष अधिकार के सुलभ है। एन्यूमरेशन और vulnerability assessment के लिए AD CS वातावरण में **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** जैसे टूल उपयोग किए जाते हैं।

Commands for using these tools include:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Recent Vulnerabilities & Security Updates (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is included in the **May 10 2022** security updates. Auditing & strong-mapping controls were introduced via **KB5014754**; environments should now be in *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Public PoCs are limited, but the vulnerable IIS components are often exposed internally. Patch as of **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched as of **November 12, 2024**. Replace or supersede v1 templates (e.g., default WebServer), restrict EKUs to intent, and limit enrollment rights. |

### Microsoft hardening timeline (KB5014754)

Microsoft ने Kerberos certificate authentication को कमजोर implicit mappings से हटाने के लिए तीन-चरणीय rollout (Compatibility → Audit → Enforcement) पेश किया। जैसा कि **February 11 2025** तक, domain controllers स्वचालित रूप से **Full Enforcement** में स्विच कर देते हैं अगर `StrongCertificateBindingEnforcement` registry value सेट नहीं है। Administrators को चाहिए:

1. Patch सभी DCs & AD CS servers (May 2022 या बाद के)।
2. *Audit* चरण के दौरान weak mappings के लिए Event ID 39/41 की निगरानी करें।
3. नए **SID extension** के साथ client-auth certificates को फिर से जारी करें या February 2025 से पहले strong manual mappings कॉन्फ़िगर करें।

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** अब ESC1-ESC8/ESC11 के लिए posture assessments दिखाता है और real-time alerts जेनरेट करता है जैसे *“Domain-controller certificate issuance for a non-DC”* (ESC8) और *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15)। इन detections का लाभ उठाने के लिए सुनिश्चित करें कि sensors सभी AD CS servers पर तैनात हों।
* सभी templates पर **“Supply in the request”** विकल्प को disable या कड़ाई से सीमित करें; स्पष्ट रूप से परिभाषित SAN/EKU मानों को प्राथमिकता दें।
* Templates से **Any Purpose** या **No EKU** को हटा दें जब तक कि यह अनिवार्य न हो (ESC2 परिदृश्यों को संबोधित करता है)।
* संवेदनशील templates (जैसे WebServer / CodeSigning) के लिए **manager approval** या समर्पित Enrollment Agent वर्कफ़्लो आवश्यक करें।
* web enrollment (`certsrv`) और CES/NDES endpoints को trusted networks तक सीमित करें या client-certificate authentication के पीछे रखें।
* ESC11 (RPC relay) को कम करने के लिए RPC enrollment encryption लागू करें (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`)। यह flag **on by default** है, लेकिन अक्सर legacy clients के लिए disabled रहता है, जो फिर से relay जोखिम खोल देता है।
* **IIS-based enrollment endpoints** (CES/Certsrv) को सुरक्षित करें: जहाँ संभव हो NTLM को disable करें या ESC8 relays को रोकने के लिए HTTPS + Extended Protection आवश्यक करें।

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
