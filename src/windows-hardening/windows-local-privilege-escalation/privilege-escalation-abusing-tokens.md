# Зловживання Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Якщо ви **не знаєте, що таке Windows Access Tokens** — прочитайте цю сторінку перед продовженням:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи tokens, які вже маєте**

### SeImpersonatePrivilege

Цей привілей, який має будь-який процес, дозволяє імперсонувати (але не створювати) будь-який token, якщо вдасться отримати дескриптор (handle) до нього. Привілейований token можна отримати від Windows service (DCOM), примусивши його виконати NTLM-аутентифікацію проти експлойта, після чого можна запустити процес з привілеями SYSTEM. Цю вразливість можна використати за допомогою різних інструментів, таких як [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (потребує вимкненого winrm), [SweetPotato](https://github.com/CCob/SweetPotato), та [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Це дуже схоже на **SeImpersonatePrivilege** — використовує **той самий метод** для отримання привілейованого token.\
Потім цей привілей дозволяє **призначити primary token** новому/приупиненому процесу. Маючи привілейований impersonation token, ви можете отримати primary token (DuplicateTokenEx).\
Зі token можна створити **новий процес** за допомогою 'CreateProcessAsUser' або створити процес у стані suspended і **встановити token** (зазвичай ви не можете змінити primary token запущеного процесу).

### SeTcbPrivilege

Якщо у вас увімкнено цей привілей, ви можете використати **KERB_S4U_LOGON** щоб отримати **impersonation token** для будь-якого іншого користувача без знання облікових даних, **додати довільну групу** (admins) до token, встановити **integrity level** token на "**medium**" та призначити цей token **поточному потоку** (SetThreadToken).

### SeBackupPrivilege

Цей привілей змушує систему **надавати повний доступ для читання** до будь-якого файлу (обмежено операціями читання). Він використовується для **читання хешів паролів локальних Administrator** акаунтів з реєстру, після чого можна використовувати інструменти на кшталт "**psexec**" або "**wmiexec**" з хешем (Pass-the-Hash). Однак ця техніка не працює в двох випадках: коли обліковий запис Local Administrator вимкнено, або коли політика позбавляє адміністративних прав Local Administrators при віддаленому підключенні.\
Ви можете **зловживати цим привілеєм** за допомогою:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- слідуючи **IppSec** у [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Або як описано в розділі **escalating privileges with Backup Operators** у:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Цей привілей надає право **запису** в будь-який системний файл незалежно від його Access Control List (ACL). Це відкриває безліч можливостей для ескалації, включаючи можливість **змінювати services**, виконувати DLL Hijacking та встановлювати **debugger-и** через Image File Execution Options серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — потужний привілей, особливо корисний коли користувач має можливість імперсонувати tokens, але також застосовується і за відсутності SeImpersonatePrivilege. Ця можливість базується на здатності імперсонувати token, який належить тому самому користувачу і має integrity level не вищий за рівень поточного процесу.

**Ключові моменти:**

- **Імперсонація без SeImpersonatePrivilege:** можна використовувати SeCreateTokenPrivilege для EoP, імперсонуючи tokens за певних умов.
- **Умови для імперсонації token-а:** успішна імперсонація вимагає, щоб цільовий token належав тому самому користувачу і мав integrity level менший або рівний integrity level процесу, що намагається імперсонувати.
- **Створення та модифікація impersonation token-ів:** користувачі можуть створити impersonation token і розширити його, додавши SID привілейованої групи (Security Identifier).

### SeLoadDriverPrivilege

Цей привілей дозволяє **завантажувати та вивантажувати драйвери пристроїв** шляхом створення запису в реєстрі з певними значеннями для `ImagePath` та `Type`. Оскільки прямий запис до `HKLM` (HKEY_LOCAL_MACHINE) заборонений, слід використовувати `HKCU` (HKEY_CURRENT_USER). Однак щоб kernel розпізнав `HKCU` для конфігурації драйвера, потрібно виконати специфічний шлях.

Цей шлях — `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача. Всередині `HKCU` потрібно створити увесь цей шлях і задати два значення:

- `ImagePath`, який вказує шлях до виконуваного бінарного файлу
- `Type`, зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Кроки:**

1. Доступ до `HKCU` замість `HKLM` через обмеження прав запису.
2. Створити шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` в `HKCU`, де `<RID>` — Relative Identifier поточного користувача.
3. Встановити `ImagePath` на шлях виконуваного бінарного файлу.
4. Призначити `Type` значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
More ways to abuse this privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **перейняти право власності на об'єкт**, обходячи необхідність явного дискреційного контролю доступу шляхом надання прав доступу WRITE_OWNER. Процес передбачає спочатку отримання права власності на цільовий реєстровий ключ для можливості запису, а потім зміну DACL для дозволу операцій запису.
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

Ця привілегія дозволяє **відлагоджувати інші процеси**, зокрема читати та записувати в пам'ять. За допомогою цієї привілегії можна застосовувати різні стратегії ін'єкції в пам'ять, здатні обходити більшість антивірусів та систем запобігання вторгненням на хості.

#### Dump memory

Ви можете використовувати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **захопити пам'ять процесу**. Зокрема це може стосуватися процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувача після успішного входу в систему.

Потім ви можете завантажити цей дамп у mimikatz, щоб отримати паролі:
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

Це право (Perform volume maintenance tasks) дозволяє відкривати сирі дескриптори пристроїв томів (наприклад, \\.\C:) для прямого дискового вводу/виводу, що оминає ACL NTFS. За допомогою цього права можна копіювати байти будь‑якого файлу на томі, читаючи підлеглі блоки, що дає змогу довільно читати файли з конфіденційним вмістом (наприклад, приватні ключі машини в %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS через VSS). Це особливо небезпечно на CA-серверах, де ексфільтрація приватного ключа CA дозволяє підробити Golden Certificate для видавання себе за будь‑який принципал.

Див. детальні техніки та заходи пом'якшення:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Перевірка привілеїв
```
whoami /priv
```
Ті **tokens, які відображаються як Disabled**, можна ввімкнути — насправді можна зловживати як _Enabled_, так і _Disabled_ tokens.

### Увімкнути всі tokens

Якщо у вас є вимкнені tokens, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) щоб увімкнути всі tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **скрипт**, вставлений у цьому [**пості**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Таблиця

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Адмін**_ | сторонній інструмент    | _"Це дозволить користувачу імітувати токени та privesc до nt system, використовуючи інструменти такі як potato.exe, rottenpotato.exe та juicypotato.exe"_                                                                                                                                                                                           | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Я спробую незабаром перефразувати це у більш рецептурному стилі.                                                                                                                                                                                           |
| **`SeBackup`**             | **Загроза** | _**вбудовані команди**_ | Читати чутливі файли за допомогою `robocopy /b`                                                                                                                                                                                                                                                                                                   | <p>- Може бути цікавіше, якщо ви зможете прочитати %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (та robocopy) не допомагає при роботі з відкритими файлами.<br><br>- Robocopy вимагає обох прав SeBackup і SeRestore для роботи з параметром /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Адмін**_ | сторонній інструмент    | Створити довільний токен, включаючи локальні права адміністратора, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Адмін**_ | **PowerShell**          | Дублювати токен `lsass.exe`.                                                                                                                                                                                                                                                                                                                       | Скрипт доступний на [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                          |
| **`SeLoadDriver`**         | _**Адмін**_ | сторонній інструмент    | <p>1. Завантажити вразливий драйвер ядра, такий як <code>szkg64.sys</code><br>2. Експлуатувати уразливість драйвера<br><br>Альтернативно, привілей може бути використаний для відвантаження драйверів, пов'язаних із безпекою, за допомогою вбудованої команди <code>ftlMC</code>. i.e.: <code>fltMC sysmondrv</code></p> | <p>1. Уразливість <code>szkg64</code> зазначена як <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Експлоіт-код для <code>szkg64</code> був створений <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Адмін**_ | **PowerShell**          | <p>1. Запустіть PowerShell/ISE з активним привілеєм SeRestore.<br>2. Увімкніть привілей за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Перейменуйте utilman.exe у utilman.old<br>4. Перейменуйте cmd.exe у utilman.exe<br>5. Заблокуйте консоль і натисніть Win+U</p> | <p>Атака може бути виявлена деякими AV-програмами.</p><p>Альтернативний метод базується на заміні бінарників сервісів, що зберігаються в "Program Files", використовуючи той самий привілей</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Адмін**_ | _**вбудовані команди**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменувати cmd.exe у utilman.exe<br>4. Заблокуйте консоль і натисніть Win+U</p>                                                                                                                                       | <p>Атака може бути виявлена деякими AV-програмами.</p><p>Альтернативний метод базується на заміні бінарників сервісів, що зберігаються в "Program Files", використовуючи той самий привілей.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Адмін**_ | сторонній інструмент    | <p>Маніпулювати токенами, щоб включити локальні права адміністратора. Може вимагати SeImpersonate.</p><p>Потребує перевірки.</p>                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Посилання

- Перегляньте цю таблицю, що визначає токени Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Перегляньте [**цю статтю**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) про privesc з токенами.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
