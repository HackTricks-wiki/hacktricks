# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- The **Subject** of the certificate denotes its owner.  
  - प्रमाणपत्र का **Subject** इसके मालिक को दर्शाता है।
- A **Public Key** is paired with a privately held key to link the certificate to its rightful owner.  
  - एक **Public Key** को निजी कुंजी के साथ जोड़ा जाता है ताकि प्रमाणपत्र उसके वैध मालिक से जुड़ सके।
- The **Validity Period**, defined by **NotBefore** and **NotAfter** dates, marks the certificate's effective duration.  
  - **Validity Period**, जिसे **NotBefore** और **NotAfter** तारीखों द्वारा परिभाषित किया जाता है, प्रमाणपत्र की वास्तविक अवधि दिखाती है।
- A unique **Serial Number**, provided by the Certificate Authority (CA), identifies each certificate.  
  - एक अद्वितीय **Serial Number**, जिसे Certificate Authority (CA) द्वारा प्रदान किया जाता है, प्रत्येक प्रमाणपत्र की पहचान करता है।
- The **Issuer** refers to the CA that has issued the certificate.  
  - **Issuer** उस CA को संदर्भित करता है जिसने प्रमाणपत्र जारी किया है।
- **SubjectAlternativeName** allows for additional names for the subject, enhancing identification flexibility.  
  - **SubjectAlternativeName** विषय के लिए अतिरिक्त नामों की अनुमति देता है, जिससे पहचान अधिक लचीली बनती है।
- **Basic Constraints** identify if the certificate is for a CA or an end entity and define usage restrictions.  
  - **Basic Constraints** यह दर्शाते हैं कि प्रमाणपत्र CA के लिए है या end entity के लिए, और उपयोग पर प्रतिबंध तय करते हैं।
- **Extended Key Usages (EKUs)** delineate the certificate's specific purposes, like code signing or email encryption, through Object Identifiers (OIDs).  
  - **Extended Key Usages (EKUs)** Object Identifiers (OIDs) के माध्यम से प्रमाणपत्र के विशिष्ट उद्देश्यों को निर्दिष्ट करते हैं, जैसे code signing या email encryption।
- The **Signature Algorithm** specifies the method for signing the certificate.  
  - **Signature Algorithm** प्रमाणपत्र पर हस्ताक्षर करने की विधि को निर्दिष्ट करता है।
- The **Signature**, created with the issuer's private key, guarantees the certificate's authenticity.  
  - **Signature**, जिसे issuer की निजी कुंजी से बनाया जाता है, प्रमाणपत्र की प्रामाणिकता की गारंटी देता है।

### Special Considerations

- **Subject Alternative Names (SANs)** expand a certificate's applicability to multiple identities, crucial for servers with multiple domains. Secure issuance processes are vital to avoid impersonation risks by attackers manipulating the SAN specification.  
  - **Subject Alternative Names (SANs)** प्रमाणपत्र की उपयुक्तता को कई पहचानों तक बढ़ाते हैं, जो कई डोमेन वाले सर्वरों के लिए महत्वपूर्ण है। SAN विनिर्देशन में छेड़छाड़ करके हमलावरों द्वारा impersonation के जोखिम से बचने के लिए secure issuance प्रक्रियाएँ आवश्यक हैं।

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS acknowledges CA certificates in an AD forest through designated containers, each serving unique roles:

- **Certification Authorities** container holds trusted root CA certificates.  
  - **Certification Authorities** कंटेनर में trusted root CA प्रमाणपत्र रखे जाते हैं।
- **Enrolment Services** container details Enterprise CAs and their certificate templates.  
  - **Enrolment Services** कंटेनर Enterprise CAs और उनके certificate templates का विवरण रखता है।
- **NTAuthCertificates** object includes CA certificates authorized for AD authentication.  
  - **NTAuthCertificates** ऑब्जेक्ट में वे CA प्रमाणपत्र शामिल होते हैं जिन्हें AD authentication के लिए अधिकृत किया गया है।
- **AIA (Authority Information Access)** container facilitates certificate chain validation with intermediate and cross CA certificates.  
  - **AIA (Authority Information Access)** कंटेनर intermediate और cross CA प्रमाणपत्रों के साथ certificate chain validation को सक्षम बनाता है।

### Certificate Acquisition: Client Certificate Request Flow

1. The request process begins with clients finding an Enterprise CA.  
   - अनुरोध प्रक्रिया क्लाइंट्स के Enterprise CA खोजने से शुरू होती है।
2. A CSR is created, containing a public key and other details, after generating a public-private key pair.  
   - public-private key जोड़ी बनाने के बाद एक CSR बनाया जाता है, जिसमें public key और अन्य विवरण होते हैं।
3. The CA assesses the CSR against available certificate templates, issuing the certificate based on the template's permissions.  
   - CA उपलब्ध certificate templates के खिलाफ CSR का मूल्यांकन करता है और template की permissions के आधार पर प्रमाणपत्र जारी करता है।
4. Upon approval, the CA signs the certificate with its private key and returns it to the client.  
   - अनुमोदन पर, CA अपनी निजी कुंजी से प्रमाणपत्र पर हस्ताक्षर करता है और इसे क्लाइंट को लौटाता है।

### Certificate Templates

Defined within AD, these templates outline the settings and permissions for issuing certificates, including permitted EKUs and enrollment or modification rights, critical for managing access to certificate services.  
- AD में परिभाषित, ये templates प्रमाणपत्र जारी करने के लिए settings और permissions को रेखांकित करते हैं, जिनमें अनुमत EKUs और enrollment या modification अधिकार शामिल हैं — ये certificate services तक पहुँच प्रबंधन के लिए महत्वपूर्ण हैं।

## Certificate Enrollment

The enrollment process for certificates is initiated by an administrator who **creates a certificate template**, which is then **published** by an Enterprise Certificate Authority (CA). This makes the template available for client enrollment, a step achieved by adding the template's name to the `certificatetemplates` field of an Active Directory object.

- प्रमाणपत्रों के लिए enrollment प्रक्रिया उस administrator द्वारा प्रारम्भ की जाती है जो **एक certificate template बनाता है**, जिसे बाद में Enterprise Certificate Authority (CA) द्वारा **published** किया जाता है। इससे template client enrollment के लिए उपलब्ध हो जाता है, जो Active Directory ऑब्जेक्ट के `certificatetemplates` फील्ड में template का नाम जोड़कर किया जाता है।

For a client to request a certificate, **enrollment rights** must be granted. These rights are defined by security descriptors on the certificate template and the Enterprise CA itself. Permissions must be granted in both locations for a request to be successful.

- किसी क्लाइंट को प्रमाणपत्र अनुरोध करने के लिए **enrollment rights** प्रदान किए जाने चाहिए। ये अधिकार certificate template और Enterprise CA पर security descriptors द्वारा परिभाषित होते हैं। अनुरोध सफल होने के लिए दोनों स्थानों पर permissions दिए जाने आवश्यक हैं।

### Template Enrollment Rights

These rights are specified through Access Control Entries (ACEs), detailing permissions like:

- **Certificate-Enrollment** and **Certificate-AutoEnrollment** rights, each associated with specific GUIDs.  
  - **Certificate-Enrollment** और **Certificate-AutoEnrollment** अधिकार, जिनमें से प्रत्येक विशिष्ट GUIDs से जुड़ा होता है।
- **ExtendedRights**, allowing all extended permissions.  
  - **ExtendedRights**, जो सभी extended permissions की अनुमति देता है।
- **FullControl/GenericAll**, providing complete control over the template.  
  - **FullControl/GenericAll**, जो template पर पूर्ण नियंत्रण प्रदान करता है।

### Enterprise CA Enrollment Rights

The CA's rights are outlined in its security descriptor, accessible via the Certificate Authority management console. Some settings even allow low-privileged users remote access, which could be a security concern.

- CA के अधिकार उसके security descriptor में सूचीबद्ध होते हैं, जिन्हें Certificate Authority management console के माध्यम से एक्सेस किया जा सकता है। कुछ सेटिंग्स कम-privileged उपयोगकर्ताओं को remote access भी देती हैं, जो सुरक्षा चिंता का कारण बन सकता है।

### Additional Issuance Controls

Certain controls may apply, such as:

- **Manager Approval**: Places requests in a pending state until approved by a certificate manager.  
  - **Manager Approval**: अनुरोधों को pending स्थिति में रखता है जब तक कि certificate manager द्वारा स्वीकृत न हो।
- **Enrolment Agents and Authorized Signatures**: Specify the number of required signatures on a CSR and the necessary Application Policy OIDs.  
  - **Enrolment Agents and Authorized Signatures**: CSR पर आवश्यक हस्ताक्षरों की संख्या और आवश्यक Application Policy OIDs निर्दिष्ट करते हैं।

### Methods to Request Certificates

Certificates can be requested through:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), using DCOM interfaces.  
   - **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces का उपयोग करते हुए।
2. **ICertPassage Remote Protocol** (MS-ICPR), through named pipes or TCP/IP.  
   - **ICertPassage Remote Protocol** (MS-ICPR), named pipes या TCP/IP के माध्यम से।
3. The **certificate enrollment web interface**, with the Certificate Authority Web Enrollment role installed.  
   - **certificate enrollment web interface**, जब Certificate Authority Web Enrollment role स्थापित हो।
4. The **Certificate Enrollment Service** (CES), in conjunction with the Certificate Enrollment Policy (CEP) service.  
   - **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service के साथ मिलकर।
5. The **Network Device Enrollment Service** (NDES) for network devices, using the Simple Certificate Enrollment Protocol (SCEP).  
   - नेटवर्क उपकरणों के लिए **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) का उपयोग करते हुए।

Windows users can also request certificates via the GUI (`certmgr.msc` or `certlm.msc`) or command-line tools (`certreq.exe` or PowerShell's `Get-Certificate` command).  
- Windows उपयोगकर्ता GUI (`certmgr.msc` या `certlm.msc`) के माध्यम से या command-line उपकरणों (`certreq.exe` या PowerShell का `Get-Certificate` command) के जरिए भी प्रमाणपत्र अनुरोध कर सकते हैं।
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## प्रमाणपत्र प्रमाणीकरण

Active Directory (AD) प्रमाणपत्र प्रमाणीकरण का समर्थन करता है, मुख्यतः **Kerberos** और **Secure Channel (Schannel)** प्रोटोकॉल का उपयोग करते हुए।

### Kerberos प्रमाणीकरण प्रक्रिया

Kerberos प्रमाणीकरण प्रक्रिया में, उपयोगकर्ता का Ticket Granting Ticket (TGT) के लिए अनुरोध उपयोगकर्ता के प्रमाणपत्र की **private key** का उपयोग करके हस्ताक्षरित किया जाता है। यह अनुरोध domain controller द्वारा कई सत्यापनों से गुज़रता है, जिनमें प्रमाणपत्र की **validity**, **path**, और **revocation status** शामिल हैं। सत्यापन में यह भी शामिल है कि प्रमाणपत्र किसी विश्वसनीय स्रोत से आया है और जारीकर्ता की उपस्थिति **NTAUTH certificate store** में पुष्टि करना। सफल सत्यापन TGT के जारी होने का कारण बनते हैं। AD में **`NTAuthCertificates`** ऑब्जेक्ट निम्न स्थान पर पाया जाता है:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
यह सर्टिफिकेट प्रमाणीकरण के लिए विश्वास स्थापित करने में केंद्रीय है।

### Secure Channel (Schannel) प्रमाणीकरण

Schannel सुरक्षित TLS/SSL कनेक्शनों को सक्षम करता है, जहाँ हैंडशेक के दौरान क्लाइंट एक certificate प्रस्तुत करता है जो सफलतापूर्वक validate होने पर access को authorize करता है। किसी certificate का AD account से mapping Kerberos के **S4U2Self** function या certificate के **Subject Alternative Name (SAN)** सहित अन्य तरीकों के माध्यम से हो सकता है।

### AD Certificate Services एन्यूमरेशन

AD की certificate services को LDAP queries के माध्यम से enumerate किया जा सकता है, जो **Enterprise Certificate Authorities (CAs)** और उनके configurations के बारे में जानकारी उजागर करती हैं। यह किसी भी domain-authenticated user द्वारा बिना किसी विशेष privileges के उपलब्ध है। AD CS environments में enumeration और vulnerability assessment के लिए **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** जैसे tools का उपयोग किया जाता है।

इन tools का उपयोग करने के लिए Commands में शामिल हैं:
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
## संदर्भ

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
