# AD प्रमाणपत्र

{{#include ../../../banners/hacktricks-training.md}}

## परिचय

### Components of a Certificate

- प्रमाणपत्र का **Subject** इसके मालिक का संकेत देता है।
- एक **Public Key** को निजी रूप से रखी गई कुंजी के साथ जोड़ा जाता है ताकि प्रमाणपत्र उसके सही मालिक से जुड़ा रहे।
- **Validity Period**, जो **NotBefore** और **NotAfter** तारीखों द्वारा परिभाषित होता है, प्रमाणपत्र की प्रभावी अवधि को दर्शाता है।
- एक अद्वितीय **Serial Number**, जो Certificate Authority (CA) द्वारा प्रदान किया जाता है, हर प्रमाणपत्र की पहचान करता है।
- **Issuer** उस CA को संदर्भित करता है जिसने प्रमाणपत्र जारी किया है।
- **SubjectAlternativeName** विषय के लिए अतिरिक्त नामों की अनुमति देता है, जिससे पहचान की लचीलापन बढ़ती है।
- **Basic Constraints** यह पहचानते हैं कि प्रमाणपत्र CA के लिए है या एक end entity के लिए और उपयोग प्रतिबंधों को परिभाषित करते हैं।
- **Extended Key Usages (EKUs)** Object Identifiers (OIDs) के माध्यम से प्रमाणपत्र के विशिष्ट प्रयोजनों को स्पष्ट करते हैं, जैसे code signing या email encryption।
- **Signature Algorithm** प्रमाणपत्र पर हस्ताक्षर करने की विधि निर्दिष्ट करता है।
- **Signature**, issuer की private key के साथ बनाई जाती है, और प्रमाणपत्र की प्रामाणिकता की गारंटी देती है।

### Special Considerations

- **Subject Alternative Names (SANs)** प्रमाणपत्र की प्रासंगिकता को कई पहचानों तक बढ़ाते हैं, जो एकाधिक डोमेन वाले सर्वरों के लिए महत्वपूर्ण है। SAN विनिर्देशन में हेरफेर करके attackers द्वारा impersonation के जोखिम से बचने के लिए secure issuance प्रक्रियाएँ आवश्यक हैं।

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS AD forest में CA प्रमाणपत्रों को नामित कंटेनरों के माध्यम से स्वीकार करता है, जिनमें से प्रत्येक अलग भूमिका निभाता है:

- **Certification Authorities** कंटेनर में trusted root CA प्रमाणपत्र होते हैं।
- **Enrolment Services** कंटेनर Enterprise CAs और उनके certificate templates का विवरण रखता है।
- **NTAuthCertificates** object में AD authentication के लिए अधिकृत CA प्रमाणपत्र शामिल होते हैं।
- **AIA (Authority Information Access)** कंटेनर intermediate और cross CA प्रमाणपत्रों के साथ certificate chain validation की सुविधा प्रदान करता है।

### Certificate Acquisition: Client Certificate Request Flow

1. प्रक्रिया क्लाइंट्स द्वारा Enterprise CA खोजने से शुरू होती है।
2. एक CSR बनाया जाता है, जिसमें एक public key और अन्य विवरण होते हैं, यह public-private key pair बनाने के बाद होता है।
3. CA उपलब्ध certificate templates के खिलाफ CSR का मूल्यांकन करता है और template की permissions के आधार पर प्रमाणपत्र जारी करता है।
4. अनुमोदन पर, CA अपने private key से प्रमाणपत्र पर हस्ताक्षर करता है और उसे क्लाइंट को वापस भेजता है।

### Certificate Templates

AD में परिभाषित ये templates प्रमाणपत्र जारी करने के लिए सेटिंग्स और अनुमतियों को रेखांकित करते हैं, जिनमें अनुमति प्राप्त EKUs और enrollment या modification अधिकार शामिल हैं, जो certificate services तक पहुँच प्रबंधित करने के लिए महत्वपूर्ण हैं।

## Certificate Enrollment

प्रमाणपत्रों के लिए enrollment प्रक्रिया उस administrator द्वारा प्रारंभ की जाती है जो **certificate template** बनाता है, जिसे फिर एक Enterprise Certificate Authority (CA) द्वारा **publish** किया जाता है। इससे template क्लाइंट enrollment के लिए उपलब्ध हो जाता है, यह चरण Active Directory object के `certificatetemplates` फ़ील्ड में template के नाम को जोड़ने के द्वारा प्राप्त किया जाता है।

किसी क्लाइंट को प्रमाणपत्र अनुरोध करने के लिए **enrollment rights** प्रदान किए जाने चाहिए। ये अधिकार certificate template और Enterprise CA पर security descriptors द्वारा परिभाषित होते हैं। अनुरोध सफल होने के लिए दोनों स्थानों पर permissions प्रदान किए जाने चाहिए।

### Template Enrollment Rights

ये अधिकार Access Control Entries (ACEs) के माध्यम से निर्दिष्ट होते हैं, जो निम्नलिखित जैसे permissions का विवरण देते हैं:

- **Certificate-Enrollment** और **Certificate-AutoEnrollment** अधिकार, प्रत्येक विशिष्ट GUIDs से जुड़े होते हैं।
- **ExtendedRights**, सभी विस्तारित अनुमतियों की अनुमति देता है।
- **FullControl/GenericAll**, template पर पूरा नियंत्रण प्रदान करता है।

### Enterprise CA Enrollment Rights

CA के अधिकार उसके security descriptor में सूचीबद्ध होते हैं, जिन्हें Certificate Authority management console के माध्यम से एक्सेस किया जा सकता है। कुछ सेटिंग्स यहाँ तक कि low-privileged users को remote access की अनुमति देती हैं, जो एक सुरक्षा चिंता हो सकती है।

### Additional Issuance Controls

कुछ नियंत्रण लागू हो सकते हैं, जैसे:

- **Manager Approval**: अनुरोधों को pending स्थिति में रखता है जब तक कि certificate manager द्वारा अनुमोदन न हो।
- **Enrolment Agents and Authorized Signatures**: CSR पर आवश्यक signatures की संख्या और आवश्यक Application Policy OIDs निर्दिष्ट करते हैं।

### Methods to Request Certificates

प्रमाणपत्र निम्न तरीकों से अनुरोध किए जा सकते हैं:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces का उपयोग करते हुए।
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes या TCP/IP के माध्यम से।
3. certificate enrollment web interface, जब Certificate Authority Web Enrollment role इंस्टॉल हो।
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service के साथ मिलकर।
5. **Network Device Enrollment Service** (NDES) नेटवर्क उपकरणों के लिए, Simple Certificate Enrollment Protocol (SCEP) का उपयोग करते हुए।

Windows उपयोगकर्ता GUI (`certmgr.msc` या `certlm.msc`) या command-line tools (`certreq.exe` या PowerShell's `Get-Certificate` command) के माध्यम से भी प्रमाणपत्र अनुरोध कर सकते हैं।
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## प्रमाणपत्र प्रमाणीकरण

Active Directory (AD) प्रमाणपत्र प्रमाणीकरण का समर्थन करता है, मुख्य रूप से **Kerberos** और **Secure Channel (Schannel)** प्रोटोकॉल का उपयोग करते हुए।

### Kerberos प्रमाणीकरण प्रक्रिया

Kerberos प्रमाणीकरण प्रक्रिया में, किसी उपयोगकर्ता के Ticket Granting Ticket (TGT) के लिए अनुरोध पर उपयोगकर्ता के प्रमाणपत्र की **private key** से हस्ताक्षर किए जाते हैं। यह अनुरोध डोमेन कंट्रोलर द्वारा कई सत्यापनों से गुजरता है, जिनमें प्रमाणपत्र की **वैधता**, **पथ**, और **रद्दीकरण स्थिति** शामिल हैं। सत्यापन में यह भी जांच शामिल है कि प्रमाणपत्र किसी विश्वसनीय स्रोत से आया है और जारीकर्ता की उपस्थिति **NTAUTH certificate store** में पुष्ट की जाती है। सफल सत्यापनों का परिणाम TGT जारी होना होता है। AD में **`NTAuthCertificates`** ऑब्जेक्ट, जो निम्न पर पाया जाता है:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
प्रमाणपत्र प्रमाणीकरण के लिए विश्वास स्थापित करने में केंद्रीय है।

### Secure Channel (Schannel) प्रमाणीकरण

Schannel सुरक्षित TLS/SSL कनेक्शनों को सक्षम करता है, जहाँ हैण्डशेक के दौरान क्लाइंट एक प्रमाणपत्र प्रस्तुत करता है जिसे सफलतापूर्वक मान्य किया जाने पर एक्सेस अधिकृत होता है। किसी प्रमाणपत्र को AD खाते से मैप करने में Kerberos’s **S4U2Self** फ़ंक्शन या प्रमाणपत्र का **Subject Alternative Name (SAN)** सहित अन्य तरीके शामिल हो सकते हैं।

### AD Certificate Services Enumeration

LDAP क्वेरीज के माध्यम से AD की certificate services को एन्यूमरेट किया जा सकता है, जिससे **Enterprise Certificate Authorities (CAs)** और उनके कॉन्फ़िगरेशन के बारे में जानकारी खुलती है। यह किसी भी domain-authenticated उपयोगकर्ता द्वारा विशेष privileges के बिना उपलब्ध है। उपकरण जैसे **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** का उपयोग AD CS environments में enumeration और vulnerability assessment के लिए किया जाता है।

Commands for using these tools include:
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
