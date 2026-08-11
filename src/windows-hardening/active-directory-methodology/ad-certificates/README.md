# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## परिचय

### Certificate के Components

- Certificate का **Subject** उसके owner को दर्शाता है।
- एक **Public Key** को privately held key के साथ pair किया जाता है, ताकि certificate को उसके सही owner से जोड़ा जा सके।
- **Validity Period**, जिसे **NotBefore** और **NotAfter** dates द्वारा परिभाषित किया जाता है, certificate की प्रभावी अवधि दर्शाता है।
- Certificate Authority (CA) द्वारा प्रदान किया गया unique **Serial Number**, प्रत्येक certificate की पहचान करता है।
- **Issuer** उस CA को दर्शाता है जिसने certificate जारी किया है।
- **SubjectAlternativeName** subject के लिए additional names की अनुमति देता है, जिससे identification flexibility बढ़ती है।
- **Basic Constraints** यह पहचानते हैं कि certificate CA के लिए है या end entity के लिए, और usage restrictions निर्धारित करते हैं।
- **Extended Key Usages (EKUs)** Object Identifiers (OIDs) के माध्यम से certificate के specific purposes, जैसे code signing या email encryption, निर्धारित करते हैं।
- **Signature Algorithm** certificate पर signing के लिए उपयोग की जाने वाली method निर्दिष्ट करता है।
- Issuer की private key से बनाई गई **Signature**, certificate की authenticity सुनिश्चित करती है।<sup>[[1]](#references)</sup>

### विशेष विचार

- **Subject Alternative Names (SANs)** certificate की applicability को multiple identities तक बढ़ाते हैं, जो multiple domains वाले servers के लिए महत्वपूर्ण है। SAN specification में attackers द्वारा impersonation risks से बचने के लिए secure issuance processes आवश्यक हैं।<sup>[[1]](#references)</sup>

### Active Directory (AD) में Certificate Authorities (CAs)

AD CS, AD forest में CA certificates को designated containers के माध्यम से स्वीकार करता है, जिनमें प्रत्येक की unique भूमिका होती है:<sup>[[1]](#references)</sup>

- **Certification Authorities** container में trusted root CA certificates होते हैं।
- **Enrolment Services** container Enterprise CAs और उनके certificate templates का विवरण रखता है।
- **NTAuthCertificates** object में AD authentication के लिए authorized CA certificates शामिल होते हैं।
- **AIA (Authority Information Access)** container intermediate और cross CA certificates के साथ certificate chain validation की सुविधा देता है।

### Certificate Acquisition: Client Certificate Request Flow

1. Request process clients द्वारा Enterprise CA खोजने से शुरू होता है।
2. Public-private key pair generate करने के बाद एक CSR बनाया जाता है, जिसमें public key और अन्य details शामिल होती हैं।
3. CA उपलब्ध certificate templates के आधार पर CSR का assessment करता है और template की permissions के अनुसार certificate जारी करता है।
4. Approval के बाद CA अपनी private key से certificate पर sign करता है और उसे client को वापस भेजता है।<sup>[[1]](#references)</sup>

### Certificate Templates

AD के भीतर defined ये templates certificates जारी करने की settings और permissions निर्धारित करते हैं। इनमें permitted EKUs तथा enrollment या modification rights शामिल होते हैं, जो certificate services तक access manage करने के लिए महत्वपूर्ण हैं।<sup>[[1]](#references)</sup>

## Certificate Enrollment

Certificates के enrollment process की शुरुआत एक administrator द्वारा **certificate template create** करने से होती है, जिसे फिर Enterprise Certificate Authority (CA) द्वारा **publish** किया जाता है। इससे template client enrollment के लिए available हो जाता है। यह Active Directory object के `certificatetemplates` field में template का name जोड़कर किया जाता है।<sup>[[1]](#references)</sup>

किसी client द्वारा certificate request करने के लिए **enrollment rights** grant किए जाने चाहिए। ये rights certificate template और Enterprise CA पर security descriptors द्वारा defined होते हैं। Request के successful होने के लिए दोनों locations में permissions grant की जानी चाहिए।<sup>[[1]](#references)</sup>

### Template Enrollment Rights

ये rights Access Control Entries (ACEs) के माध्यम से specified होते हैं, जो निम्न permissions का विवरण देते हैं:<sup>[[1]](#references)</sup>

- **Certificate-Enrollment** और **Certificate-AutoEnrollment** rights, जिनमें से प्रत्येक specific GUIDs से associated होता है।
- **ExtendedRights**, जो सभी extended permissions की अनुमति देते हैं।
- **FullControl/GenericAll**, जो template पर complete control प्रदान करते हैं।

### Enterprise CA Enrollment Rights

CA के rights उसके security descriptor में outlined होते हैं, जिसे Certificate Authority management console के माध्यम से access किया जा सकता है। कुछ settings low-privileged users को remote access भी देती हैं, जो security concern हो सकता है।<sup>[[1]](#references)</sup>

### Additional Issuance Controls

कुछ controls लागू हो सकते हैं, जैसे:<sup>[[1]](#references)</sup>

- **Manager Approval**: Requests को pending state में रखता है, जब तक certificate manager उन्हें approve न कर दे।
- **Enrolment Agents and Authorized Signatures**: CSR पर required signatures की संख्या और आवश्यक Application Policy OIDs निर्दिष्ट करते हैं।

### Methods to Request Certificates

Certificates निम्न तरीकों से request किए जा सकते हैं:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), DCOM interfaces का उपयोग करके।
2. **ICertPassage Remote Protocol** (MS-ICPR), named pipes या TCP/IP के माध्यम से।
3. **certificate enrollment web interface**, जिसमें Certificate Authority Web Enrollment role installed हो।
4. **Certificate Enrollment Service** (CES), Certificate Enrollment Policy (CEP) service के साथ।
5. Network devices के लिए **Network Device Enrollment Service** (NDES), Simple Certificate Enrollment Protocol (SCEP) का उपयोग करके।

Windows users GUI (`certmgr.msc` या `certlm.msc`) या command-line tools (`certreq.exe` या PowerShell के `Get-Certificate` command) के माध्यम से भी certificates request कर सकते हैं।
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## प्रमाणपत्र प्रमाणीकरण

Active Directory (AD) प्रमाणपत्र प्रमाणीकरण का समर्थन करता है, जिसमें मुख्य रूप से **Kerberos** और **Secure Channel (Schannel)** protocols का उपयोग होता है।<sup>[[1]](#references)</sup>

### Kerberos प्रमाणीकरण प्रक्रिया

Kerberos प्रमाणीकरण प्रक्रिया में, किसी user का Ticket Granting Ticket (TGT) प्राप्त करने का request उसके certificate की **private key** का उपयोग करके sign किया जाता है। यह request domain controller द्वारा कई validations से गुजरता है, जिनमें certificate की **validity**, **path**, और **revocation status** शामिल हैं। Validations में यह सत्यापित करना भी शामिल है कि certificate किसी trusted source से आया है और issuer **NTAUTH certificate store** में मौजूद है। सफल validations के परिणामस्वरूप TGT जारी किया जाता है। AD में मौजूद **`NTAuthCertificates`** object, जिसका स्थान है:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
certificate authentication के लिए trust स्थापित करने में केंद्रीय भूमिका निभाता है।<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) Authentication

Schannel सुरक्षित TLS/SSL connections को सक्षम करता है, जहाँ handshake के दौरान client एक certificate प्रस्तुत करता है, जिसे सफलतापूर्वक validate किए जाने पर access authorize किया जाता है।<sup>[[2]](#references)</sup> किसी certificate को AD account से map करने में, अन्य methods के साथ, Kerberos का **S4U2Self** function या certificate का **Subject Alternative Name (SAN)** शामिल हो सकता है।<sup>[[1]](#references)</sup>

### AD Certificate Services Enumeration

AD की certificate services को LDAP queries के माध्यम से enumerate किया जा सकता है, जिससे **Enterprise Certificate Authorities (CAs)** और उनके configurations की जानकारी प्राप्त होती है। यह किसी भी domain-authenticated user के लिए, special privileges के बिना, accessible है।<sup>[[1]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** और **[Certipy](https://github.com/ly4k/Certipy)** जैसे tools का उपयोग AD CS environments में enumeration और vulnerability assessment के लिए किया जाता है।<sup>[[3]](#references)</sup>

इन tools का उपयोग करने के commands में शामिल हैं:
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
Rubeus password-protected PFX certificate का उपयोग PKINIT authentication के लिए भी कर सकता है और TGT का अनुरोध कर सकता है। वैकल्पिक `/getcredentials` switch U2U service ticket का अनुरोध करता है और account NT hash recover करने का प्रयास करता है:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned: Active Directory Certificate Services का दुरुपयोग](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [SSL/TLS Client Authentication क्या है और यह कैसे काम करता है?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
