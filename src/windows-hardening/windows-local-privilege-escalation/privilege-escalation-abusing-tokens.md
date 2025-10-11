# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи tokens, які у вас вже є**

### SeImpersonatePrivilege

Це привілей, що дає будь-якому процесу змогу виконувати impersonation (але не створювати) будь-який token, за умови, що вдасться отримати handle на нього. Привілейований token можна отримати від Windows service (DCOM), підштовхнувши його виконати NTLM authentication проти експлойта, що в подальшому дозволяє виконати процес з SYSTEM privileges. Цю вразливість можна експлуатувати за допомогою різних інструментів, таких як [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (which requires winrm to be disabled), [SweetPotato](https://github.com/CCob/SweetPotato), and [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

It is very similar to **SeImpersonatePrivilege**, it will use the **same method** to get a privileged token.\
Потім цей привілей дозволяє **assign a primary token** новому/зупиненому процесу. Маючи привілейований impersonation token, ви можете вивести primary token (DuplicateTokenEx).\
За допомогою цього token ви можете створити **новий процес** за допомогою 'CreateProcessAsUser' або створити процес у suspended стані та **set the token** (зазвичай ви не можете змінити primary token запущеного процесу).

### SeTcbPrivilege

Якщо у вас увімкнено цей привілей, ви можете використати **KERB_S4U_LOGON** щоб отримати **impersonation token** для будь-якого іншого користувача без знання облікових даних, **додати довільну групу** (admins) до token, встановити **рівень цілісності** token до "**medium**", і призначити цей token для **поточого потоку** (SetThreadToken).

### SeBackupPrivilege

Цей привілей змушує систему **надавати повний доступ на читання** до будь-якого файлу (обмежено операціями читання). Він використовується для **читання паролів/хешів локального Administrator** з реєстру, після чого можна скористатися інструментами типу "**psexec**" або "**wmiexec**" з хешем (Pass-the-Hash technique). Однак ця техніка не спрацює за двох умов: коли Local Administrator обліковий запис відключений, або коли політика видаляє адміністративні права у Local Administrators при віддалених підключеннях.\
Ви можете **зловживати цим привілеєм** за допомогою:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Цей привілей надає дозвіл на **запис** у будь-який системний файл незалежно від його ACL. Це відкриває багато можливостей для ескалації, включаючи зміну services, DLL Hijacking, та налаштування **debugger'ів** через Image File Execution Options серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — потужний привілей, особливо корисний коли користувач має можливість impersonate tokens, але також застосовний і без SeImpersonatePrivilege. Ця можливість базується на вмінні impersonate token, який представляє того ж користувача і рівень його integrity не перевищує рівень процесу, що намагається здійснити impersonation.

**Ключові моменти:**

- **Impersonation без SeImpersonatePrivilege:** Можна використати SeCreateTokenPrivilege для EoP, імперсонуючи токени за певних умов.
- **Умови для impersonation токена:** Успішне impersonation вимагає, щоб цільовий token належав тому ж користувачу і мав integrity level менший або рівний integrity level процесу, що намагається impersonate.
- **Створення та модифікація impersonation токенів:** Користувачі можуть створити impersonation token і розширити його, додавши SID привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дозволяє **завантажувати і розвантажувати device drivers** шляхом створення запису в реєстрі з певними значеннями для `ImagePath` та `Type`. Оскільки прямий запис до `HKLM` (HKEY_LOCAL_MACHINE) зазвичай заборонений, потрібно використовувати `HKCU` (HKEY_CURRENT_USER). Однак щоб зробити `HKCU` впізнаваним для kernel при конфігурації драйвера, треба слідувати специфічному шляху.

Цей шлях — `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача. Усередині `HKCU` потрібно створити весь цей шлях і встановити два значення:

- `ImagePath`, який вказує шлях до бінарника для виконання
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
Більше способів зловживання цим привілеєм — див. у [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **прийняти на себе власність об'єкта**, обходячи вимогу явного дискреційного доступу шляхом надання прав доступу WRITE_OWNER. Процес включає спочатку отримання власності на відповідний ключ реєстру для запису, а потім зміну DACL для дозволу операцій запису.
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

Ця привілегія дозволяє **налагоджувати інші процеси**, зокрема читати й записувати в пам'ять. За допомогою цієї привілегії можна використовувати різні методи ін'єкції в пам'ять, які здатні обходити більшість антивірусів і HIPS.

#### Вивантаження пам'яті

Ви можете використовувати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **знімати пам'ять процесу**. Зокрема це може стосуватися процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за збереження облікових даних користувачів після їхнього успішного входу в систему.

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

(Виконувати завдання з обслуговування томів)

Це право дозволяє відкривати сирі дескриптори пристроїв томів (наприклад, \\.\C:) для прямого disk I/O, що обходить NTFS ACLs. Маючи його, можна копіювати байти будь-якого файлу на томі, читаючи базові блоки, що дає можливість довільного читання файлів із чутливою інформацією (наприклад, приватні ключі машини в %ProgramData%\Microsoft\Crypto\, вузли реєстру, SAM/NTDS через VSS). Це особливо критично для CA-серверів, де витяг приватного ключа CA дозволяє підробити Golden Certificate і видавати себе за будь-який обліковий запис.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Перевірка привілеїв
```
whoami /priv
```
Ті **tokens, які відображаються як Disabled**, можна увімкнути — ви насправді можете зловживати _Enabled_ та _Disabled_ tokens.

### Увімкнення всіх tokens

Якщо у вас є tokens, які вимкнені, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) щоб увімкнути всі tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- May be more interesting if you can read %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (and robocopy) is not helpful when it comes to open files.<br><br>- Robocopy requires both SeBackup and SeRestore to work with /b parameter.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load buggy kernel driver such as <code>szkg64.sys</code><br>2. Exploit the driver vulnerability<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>ftlMC</code> builtin command. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. The <code>szkg64</code> vulnerability is listed as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. The <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> was created by <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
