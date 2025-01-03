# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) में साझा किए गए डोमेन स्थिरता तकनीकों का सारांश है**। आगे की जानकारी के लिए इसे देखें।

## चोरी किए गए CA प्रमाणपत्रों के साथ प्रमाणपत्रों का निर्माण - DPERSIST1

आप कैसे बता सकते हैं कि एक प्रमाणपत्र CA प्रमाणपत्र है?

यह निर्धारित किया जा सकता है कि एक प्रमाणपत्र CA प्रमाणपत्र है यदि कई शर्तें पूरी होती हैं:

- प्रमाणपत्र CA सर्वर पर संग्रहीत है, जिसकी निजी कुंजी मशीन के DPAPI द्वारा सुरक्षित है, या हार्डवेयर जैसे TPM/HSM द्वारा यदि ऑपरेटिंग सिस्टम इसका समर्थन करता है।
- प्रमाणपत्र के Issuer और Subject फ़ील्ड CA के विशिष्ट नाम से मेल खाते हैं।
- CA प्रमाणपत्रों में विशेष रूप से "CA Version" एक्सटेंशन मौजूद है।
- प्रमाणपत्र में Extended Key Usage (EKU) फ़ील्ड की कमी है।

इस प्रमाणपत्र की निजी कुंजी निकालने के लिए, CA सर्वर पर `certsrv.msc` उपकरण समर्थित विधि है जो अंतर्निहित GUI के माध्यम से है। फिर भी, यह प्रमाणपत्र सिस्टम में संग्रहीत अन्य प्रमाणपत्रों से भिन्न नहीं है; इसलिए, [THEFT2 तकनीक](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) जैसी विधियों का उपयोग निकासी के लिए किया जा सकता है।

प्रमाणपत्र और निजी कुंजी को Certipy का उपयोग करके निम्नलिखित कमांड के साथ भी प्राप्त किया जा सकता है:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA प्रमाणपत्र और इसके निजी कुंजी को `.pfx` प्रारूप में प्राप्त करने के बाद, [ForgeCert](https://github.com/GhostPack/ForgeCert) जैसे उपकरणों का उपयोग वैध प्रमाणपत्र उत्पन्न करने के लिए किया जा सकता है:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> प्रमाणपत्र धोखाधड़ी के लिए लक्षित उपयोगकर्ता को सक्रिय होना चाहिए और प्रक्रिया सफल होने के लिए Active Directory में प्रमाणीकरण करने में सक्षम होना चाहिए। विशेष खातों जैसे krbtgt के लिए प्रमाणपत्र धोखाधड़ी अप्रभावी है।

यह धोखा दिया गया प्रमाणपत्र **मान्य** रहेगा जब तक कि निर्दिष्ट समाप्ति तिथि तक और **जब तक कि रूट CA प्रमाणपत्र मान्य है** (आमतौर पर 5 से **10+ वर्ष** तक)। यह **मशीनों** के लिए भी मान्य है, इसलिए **S4U2Self** के साथ मिलकर, एक हमलावर **किसी भी डोमेन मशीन पर स्थिरता बनाए रख सकता है** जब तक CA प्रमाणपत्र मान्य है।\
इसके अलावा, इस विधि से **जनरेट किए गए प्रमाणपत्र** **रद्द नहीं किए जा सकते** क्योंकि CA उनके बारे में अवगत नहीं है।

## धोखेबाज CA प्रमाणपत्रों पर भरोसा करना - DPERSIST2

`NTAuthCertificates` ऑब्जेक्ट को एक या अधिक **CA प्रमाणपत्रों** को अपने `cacertificate` विशेषता में रखने के लिए परिभाषित किया गया है, जिसका उपयोग Active Directory (AD) करता है। **डोमेन नियंत्रक** द्वारा सत्यापन प्रक्रिया में प्रमाणीकरण **प्रमाणपत्र** के जारीकर्ता क्षेत्र में निर्दिष्ट **CA** के लिए एक प्रविष्टि के लिए `NTAuthCertificates` ऑब्जेक्ट की जांच करना शामिल है। यदि एक मेल मिलता है, तो प्रमाणीकरण आगे बढ़ता है।

एक आत्म-हस्ताक्षरित CA प्रमाणपत्र को हमलावर द्वारा `NTAuthCertificates` ऑब्जेक्ट में जोड़ा जा सकता है, बशर्ते कि उनके पास इस AD ऑब्जेक्ट पर नियंत्रण हो। सामान्यतः, केवल **Enterprise Admin** समूह के सदस्य, साथ ही **Domain Admins** या **Administrators** को **फॉरेस्ट रूट के डोमेन** में इस ऑब्जेक्ट को संशोधित करने की अनुमति दी जाती है। वे `certutil.exe` का उपयोग करके `NTAuthCertificates` ऑब्जेक्ट को संपादित कर सकते हैं, कमांड `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126` के साथ, या [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) का उपयोग करके।

यह क्षमता विशेष रूप से ForgeCert के साथ मिलकर प्रमाणपत्रों को गतिशील रूप से उत्पन्न करने की पहले वर्णित विधि के साथ उपयोग करने पर प्रासंगिक है।

## दुर्भावनापूर्ण गलत कॉन्फ़िगरेशन - DPERSIST3

AD CS घटकों के **सुरक्षा वर्णनकर्ता संशोधनों** के माध्यम से **स्थिरता** के अवसर प्रचुर मात्रा में हैं। "[Domain Escalation](domain-escalation.md)" अनुभाग में वर्णित संशोधन एक हमलावर द्वारा दुर्भावनापूर्ण रूप से लागू किए जा सकते हैं जिनके पास उच्च स्तर की पहुंच है। इसमें संवेदनशील घटकों जैसे कि:

- **CA सर्वर का AD कंप्यूटर** ऑब्जेक्ट
- **CA सर्वर का RPC/DCOM सर्वर**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** में कोई भी **वंशज AD ऑब्जेक्ट या कंटेनर** (उदाहरण के लिए, प्रमाणपत्र टेम्पलेट कंटेनर, प्रमाणन प्राधिकरण कंटेनर, NTAuthCertificates ऑब्जेक्ट, आदि)
- **AD समूहों को AD CS को नियंत्रित करने के लिए अधिकार सौंपे गए** डिफ़ॉल्ट या संगठन द्वारा (जैसे कि अंतर्निहित Cert Publishers समूह और इसके किसी भी सदस्य)

दुर्भावनापूर्ण कार्यान्वयन का एक उदाहरण एक हमलावर होगा, जिसके पास डोमेन में **उच्च अनुमतियाँ** हैं, जो **`User`** प्रमाणपत्र टेम्पलेट पर **`WriteOwner`** अनुमति जोड़ता है, जिसमें हमलावर अधिकार के लिए प्रमुख होता है। इसका लाभ उठाने के लिए, हमलावर पहले **`User`** टेम्पलेट की स्वामित्व को अपने पास बदल देगा। इसके बाद, **`mspki-certificate-name-flag`** को **1** पर सेट किया जाएगा ताकि **`ENROLLEE_SUPPLIES_SUBJECT`** सक्षम हो सके, जिससे एक उपयोगकर्ता अनुरोध में एक विषय वैकल्पिक नाम प्रदान कर सके। इसके बाद, हमलावर **टेम्पलेट** का उपयोग करके **नामांकित** कर सकता है, एक **डोमेन प्रशासक** नाम को वैकल्पिक नाम के रूप में चुन सकता है, और अधिग्रहित प्रमाणपत्र का उपयोग प्रमाणीकरण के लिए DA के रूप में कर सकता है।

{{#include ../../../banners/hacktricks-training.md}}
