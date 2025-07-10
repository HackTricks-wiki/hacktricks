# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- The **Subject** of the certificate denotes its owner.
- A **Public Key** is paired with a privately held key to link the certificate to its rightful owner.
- The **Validity Period**, defined by **NotBefore** and **NotAfter** dates, marks the certificate's effective duration.
- A unique **Serial Number**, provided by the Certificate Authority (CA), identifies each certificate.
- The **Issuer** refers to the CA that has issued the certificate.
- **SubjectAlternativeName** allows for additional names for the subject, enhancing identification flexibility.
- **Basic Constraints** identify if the certificate is for a CA or an end entity and define usage restrictions.
- **Extended Key Usages (EKUs)** delineate the certificate's specific purposes, like code signing or email encryption, through Object Identifiers (OIDs).
- The **Signature Algorithm** specifies the method for signing the certificate.
- The **Signature**, created with the issuer's private key, guarantees the certificate's authenticity.

### Special Considerations

- **Subject Alternative Names (SANs)** expand a certificate's applicability to multiple identities, crucial for servers with multiple domains. Secure issuance processes are vital to avoid impersonation risks by attackers manipulating the SAN specification.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS acknowledges CA certificates in an AD forest through designated containers, each serving unique roles:

- **Certification Authorities** container holds trusted root CA certificates.
- **Enrolment Services** container details Enterprise CAs and their certificate templates.
- **NTAuthCertificates** object includes CA certificates authorized for AD authentication.
- **AIA (Authority Information Access)** container facilitates certificate chain validation with intermediate and cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. The request process begins with clients finding an Enterprise CA.
2. A CSR is created, containing a public key and other details, after generating a public-private key pair.
3. The CA assesses the CSR against available certificate templates, issuing the certificate based on the template's permissions.
4. Upon approval, the CA signs the certificate with its private key and returns it to the client.

### Certificate Templates

Defined within AD, these templates outline the settings and permissions for issuing certificates, including permitted EKUs and enrollment or modification rights, critical for managing access to certificate services.

## Certificate Enrollment

The enrollment process for certificates is initiated by an administrator who **creates a certificate template**, which is then **published** by an Enterprise Certificate Authority (CA). This makes the template available for client enrollment, a step achieved by adding the template's name to the `certificatetemplates` field of an Active Directory object.

For a client to request a certificate, **enrollment rights** must be granted. These rights are defined by security descriptors on the certificate template and the Enterprise CA itself. Permissions must be granted in both locations for a request to be successful.

### Template Enrollment Rights

These rights are specified through Access Control Entries (ACEs), detailing permissions like:

- **Certificate-Enrollment** and **Certificate-AutoEnrollment** rights, each associated with specific GUIDs.
- **ExtendedRights**, allowing all extended permissions.
- **FullControl/GenericAll**, providing complete control over the template.

### Enterprise CA Enrollment Rights

The CA's rights are outlined in its security descriptor, accessible via the Certificate Authority management console. Some settings even allow low-privileged users remote access, which could be a security concern.

### Additional Issuance Controls

Certain controls may apply, such as:

- **Manager Approval**: Places requests in a pending state until approved by a certificate manager.
- **Enrolment Agents and Authorized Signatures**: Specify the number of required signatures on a CSR and the necessary Application Policy OIDs.

### Methods to Request Certificates

Certificates can be requested through:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), using DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), through named pipes or TCP/IP.
3. The **certificate enrollment web interface**, with the Certificate Authority Web Enrollment role installed.
4. The **Certificate Enrollment Service** (CES), in conjunction with the Certificate Enrollment Policy (CEP) service.
5. The **Network Device Enrollment Service** (NDES) for network devices, using the Simple Certificate Enrollment Protocol (SCEP).

Windows users can also request certificates via the GUI (`certmgr.msc` or `certlm.msc`) or command-line tools (`certreq.exe` or PowerShell's `Get-Certificate` command).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) प्रमाणपत्र प्रमाणीकरण का समर्थन करता है, मुख्य रूप से **Kerberos** और **Secure Channel (Schannel)** प्रोटोकॉल का उपयोग करते हुए।

### Kerberos Authentication Process

Kerberos प्रमाणीकरण प्रक्रिया में, एक उपयोगकर्ता के Ticket Granting Ticket (TGT) के लिए अनुरोध को उपयोगकर्ता के प्रमाणपत्र की **निजी कुंजी** का उपयोग करके हस्ताक्षरित किया जाता है। यह अनुरोध डोमेन नियंत्रक द्वारा कई मान्यताओं से गुजरता है, जिसमें प्रमाणपत्र की **वैधता**, **पथ**, और **रद्दीकरण स्थिति** शामिल हैं। मान्यताओं में यह भी शामिल है कि प्रमाणपत्र एक विश्वसनीय स्रोत से आता है और **NTAUTH प्रमाणपत्र स्टोर** में जारीकर्ता की उपस्थिति की पुष्टि करना। सफल मान्यताओं के परिणामस्वरूप एक TGT जारी किया जाता है। AD में **`NTAuthCertificates`** ऑब्जेक्ट, जो कि यहाँ पाया जाता है:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is प्रमाणपत्र प्रमाणीकरण के लिए विश्वास स्थापित करने में केंद्रीय।

### सुरक्षित चैनल (Schannel) प्रमाणीकरण

Schannel सुरक्षित TLS/SSL कनेक्शनों को सुविधाजनक बनाता है, जहाँ एक हैंडशेक के दौरान, क्लाइंट एक प्रमाणपत्र प्रस्तुत करता है जो, यदि सफलतापूर्वक मान्य किया जाता है, तो पहुँच अधिकृत करता है। एक प्रमाणपत्र को AD खाते से जोड़ने में Kerberos का **S4U2Self** फ़ंक्शन या प्रमाणपत्र का **Subject Alternative Name (SAN)** शामिल हो सकता है, अन्य तरीकों के बीच।

### AD प्रमाणपत्र सेवाओं की गणना

AD की प्रमाणपत्र सेवाओं को LDAP क्वेरी के माध्यम से गणना की जा सकती है, जो **Enterprise Certificate Authorities (CAs)** और उनकी कॉन्फ़िगरेशन के बारे में जानकारी प्रकट करती है। यह किसी भी डोमेन-प्रमाणित उपयोगकर्ता द्वारा विशेष विशेषाधिकार के बिना सुलभ है। **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** जैसे उपकरण AD CS वातावरण में गणना और कमजोरियों के आकलन के लिए उपयोग किए जाते हैं।

इन उपकरणों का उपयोग करने के लिए कमांड में शामिल हैं:
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
---

## हाल की कमजोरियाँ और सुरक्षा अपडेट (2022-2025)

| वर्ष | आईडी / नाम | प्रभाव | मुख्य निष्कर्ष |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *अधिकार वृद्धि* मशीन खाता प्रमाणपत्रों को PKINIT के दौरान धोखा देकर। | पैच **10 मई 2022** सुरक्षा अपडेट में शामिल है। ऑडिटिंग और मजबूत-मैपिंग नियंत्रण **KB5014754** के माध्यम से पेश किए गए; वातावरण अब *पूर्ण प्रवर्तन* मोड में होना चाहिए। |
| 2023 | **CVE-2023-35350 / 35351** | *दूरस्थ कोड-कार्यन्वयन* AD CS वेब नामांकन (certsrv) और CES भूमिकाओं में। | सार्वजनिक PoCs सीमित हैं, लेकिन कमजोर IIS घटक अक्सर आंतरिक रूप से उजागर होते हैं। पैच **जुलाई 2023** पैच मंगलवार के रूप में। |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | कम-विशिष्ट उपयोगकर्ता जिनके पास नामांकन अधिकार हैं, वे CSR जनरेशन के दौरान **किसी भी** EKU या SAN को ओवरराइड कर सकते हैं, जो क्लाइंट-प्रमाणीकरण या कोड-हस्ताक्षर के लिए उपयोगी प्रमाणपत्र जारी करते हैं और *डोमेन समझौता* की ओर ले जाते हैं। | **अप्रैल 2024** अपडेट में संबोधित किया गया। टेम्पलेट से “अनुरोध में आपूर्ति करें” को हटा दें और नामांकन अनुमतियों को प्रतिबंधित करें। |

### Microsoft हार्डनिंग टाइमलाइन (KB5014754)

Microsoft ने कमजोर निहित मैपिंग से केर्बेरोस प्रमाणपत्र प्रमाणीकरण को स्थानांतरित करने के लिए तीन-चरणीय रोलआउट (संगतता → ऑडिट → प्रवर्तन) पेश किया। **11 फरवरी 2025** से, डोमेन नियंत्रक स्वचालित रूप से **पूर्ण प्रवर्तन** पर स्विच हो जाते हैं यदि `StrongCertificateBindingEnforcement` रजिस्ट्री मान सेट नहीं किया गया है। प्रशासकों को चाहिए:

1. सभी DCs और AD CS सर्वरों को पैच करें (मई 2022 या बाद में)।
2. *ऑडिट* चरण के दौरान कमजोर मैपिंग के लिए इवेंट आईडी 39/41 की निगरानी करें।
3. फरवरी 2025 से पहले नए **SID एक्सटेंशन** के साथ क्लाइंट-प्रमाण पत्र फिर से जारी करें या मजबूत मैनुअल मैपिंग कॉन्फ़िगर करें।

---

## पहचान और हार्डनिंग सुधार

* **डिफेंडर फॉर आइडेंटिटी AD CS सेंसर (2023-2024)** अब ESC1-ESC8/ESC11 के लिए स्थिति आकलन प्रस्तुत करता है और *“गैर-DC के लिए डोमेन-नियंत्रक प्रमाणपत्र जारी करना”* (ESC8) और *“मनमाने एप्लिकेशन नीतियों के साथ प्रमाणपत्र नामांकन को रोकें”* (ESC15) जैसे वास्तविक समय के अलर्ट उत्पन्न करता है। सुनिश्चित करें कि इन पहचानियों से लाभ उठाने के लिए सभी AD CS सर्वरों पर सेंसर तैनात हैं।
* सभी टेम्पलेट्स पर **“अनुरोध में आपूर्ति करें”** विकल्प को बंद करें या कड़ी सीमा निर्धारित करें; स्पष्ट रूप से परिभाषित SAN/EKU मानों को प्राथमिकता दें।
* टेम्पलेट्स से **किसी भी उद्देश्य** या **कोई EKU** को हटा दें जब तक कि यह बिल्कुल आवश्यक न हो (ESC2 परिदृश्यों को संबोधित करता है)।
* संवेदनशील टेम्पलेट्स (जैसे, वेब सर्वर / कोड साइनिंग) के लिए **प्रबंधक अनुमोदन** या समर्पित नामांकन एजेंट कार्यप्रवाह की आवश्यकता करें।
* वेब नामांकन (`certsrv`) और CES/NDES एंडपॉइंट्स को विश्वसनीय नेटवर्क या क्लाइंट-प्रमाणपत्र प्रमाणीकरण के पीछे सीमित करें।
* ESC11 को कम करने के लिए RPC नामांकन एन्क्रिप्शन को लागू करें (`certutil –setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQ`)।

---

## संदर्भ

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
