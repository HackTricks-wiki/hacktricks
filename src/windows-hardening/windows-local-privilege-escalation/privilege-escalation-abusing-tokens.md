# Зловживання токенами

{{#include ../../banners/hacktricks-training.md}}

## Токени

Якщо ви **не знаєте, що таке токени доступу Windows**, прочитайте цю сторінку перед продовженням:

{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи токенами, які у вас вже є**

### SeImpersonatePrivilege

Це привілей, який має будь-який процес, що дозволяє імперсонувати (але не створювати) будь-який токен, за умови, що можна отримати дескриптор до нього. Привілейований токен можна отримати з Windows-сервісу (DCOM), спонукаючи його виконати NTLM-аутентифікацію проти експлойту, що, в свою чергу, дозволяє виконати процес з привілеями SYSTEM. Цю вразливість можна експлуатувати за допомогою різних інструментів, таких як [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (який вимагає, щоб winrm був вимкнений), [SweetPotato](https://github.com/CCob/SweetPotato) та [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Цей привілей дуже схожий на **SeImpersonatePrivilege**, він використовує **той же метод** для отримання привілейованого токена.\
Потім цей привілей дозволяє **призначити первинний токен** новому/призупиненому процесу. З привілейованим токеном імперсонування ви можете отримати первинний токен (DuplicateTokenEx).\
З токеном ви можете створити **новий процес** за допомогою 'CreateProcessAsUser' або створити призупинений процес і **встановити токен** (в загальному, ви не можете змінити первинний токен працюючого процесу).

### SeTcbPrivilege

Якщо ви активували цей токен, ви можете використовувати **KERB_S4U_LOGON** для отримання **токена імперсонування** для будь-якого іншого користувача без знання облікових даних, **додати довільну групу** (адміністратори) до токена, встановити **рівень цілісності** токена на "**середній**" і призначити цей токен **поточному потоку** (SetThreadToken).

### SeBackupPrivilege

Цей привілей змушує систему **надавати всі права на читання** для будь-якого файлу (обмежено до операцій читання). Він використовується для **читання хешів паролів локальних облікових записів адміністратора** з реєстру, після чого такі інструменти, як "**psexec**" або "**wmiexec**", можуть бути використані з хешем (техніка Pass-the-Hash). Однак ця техніка не спрацьовує за двох умов: коли обліковий запис локального адміністратора вимкнено або коли діє політика, яка позбавляє адміністративних прав локальних адміністраторів, які підключаються віддалено.\
Ви можете **зловживати цим привілеєм** за допомогою:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- слідуючи **IppSec** на [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Або як пояснено в розділі **підвищення привілеїв з операторами резервного копіювання**:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Цей привілей надає дозвіл на **запис** до будь-якого системного файлу, незалежно від списку контролю доступу (ACL) файлу. Це відкриває численні можливості для підвищення привілеїв, включаючи можливість **модифікувати сервіси**, виконувати DLL Hijacking і встановлювати **дебагери** через параметри виконання образу серед інших технік.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege - це потужний привілей, особливо корисний, коли користувач має можливість імперсонувати токени, але також і за відсутності SeImpersonatePrivilege. Ця можливість залежить від здатності імперсонувати токен, який представляє того ж користувача і рівень цілісності якого не перевищує рівень цілісності поточного процесу.

**Ключові моменти:**

- **Імперсонування без SeImpersonatePrivilege:** Можливо використовувати SeCreateTokenPrivilege для EoP, імперсуючи токени за певних умов.
- **Умови для імперсонування токена:** Успішне імперсонування вимагає, щоб цільовий токен належав тому ж користувачу і мав рівень цілісності, який менший або рівний рівню цілісності процесу, що намагається імперсувати.
- **Створення та модифікація токенів імперсонування:** Користувачі можуть створювати токен імперсонування та покращувати його, додаючи SID (ідентифікатор безпеки) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дозволяє **завантажувати та вивантажувати драйвери пристроїв** з створенням запису реєстру з конкретними значеннями для `ImagePath` та `Type`. Оскільки прямий доступ на запис до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, потрібно використовувати `HKCU` (HKEY_CURRENT_USER). Однак, щоб зробити `HKCU` впізнаваним для ядра для конфігурації драйвера, потрібно дотримуватися певного шляху.

Цей шлях: `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` - це відносний ідентифікатор поточного користувача. Всередині `HKCU` потрібно створити цей весь шлях і встановити два значення:

- `ImagePath`, що є шляхом до виконуваного бінарного файлу
- `Type`, зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Кроки для виконання:**

1. Доступ до `HKCU` замість `HKLM` через обмежений доступ на запис.
2. Створити шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` в `HKCU`, де `<RID>` представляє відносний ідентифікатор поточного користувача.
3. Встановити `ImagePath` на шлях виконання бінарного файлу.
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
Більше способів зловживання цим привілеєм у [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дозволяє процесу **приймати власність на об'єкт**, обходячи вимогу явного дискреційного доступу шляхом надання прав доступу WRITE_OWNER. Процес включає спочатку отримання власності на потрібний ключ реєстру для запису, а потім зміну DACL для дозволу операцій запису.
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

Ця привілегія дозволяє **налагоджувати інші процеси**, включаючи читання та запис у пам'ять. Можна використовувати різні стратегії для ін'єкції пам'яті, здатні уникати більшості антивірусних рішень та рішень для запобігання вторгненням на хост.

#### Dump memory

Ви можете використовувати [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), щоб **захопити пам'ять процесу**. Зокрема, це може стосуватися процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувача після успішного входу користувача в систему.

Потім ви можете завантажити цей дамп у mimikatz, щоб отримати паролі:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Якщо ви хочете отримати `NT SYSTEM` оболонку, ви можете використати:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Перевірка привілеїв
```
whoami /priv
```
**Токени, які з'являються як Вимкнені**, можуть бути увімкнені, ви насправді можете зловживати _Увімкненими_ та _Вимкненими_ токенами.

### Увімкнути всі токени

Якщо у вас є вимкнені токени, ви можете використовувати скрипт [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) для увімкнення всіх токенів:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Або **скрипт**, вбудований у цей [**пост**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Таблиця

Повна шпаргалка з привілеїв токенів доступна за адресою [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), нижче наведено лише прямі способи експлуатації привілею для отримання адміністративної сесії або читання чутливих файлів.

| Привілей                   | Вплив       | Інструмент              | Шлях виконання                                                                                                                                                                                                                                                                                                                                     | Зауваження                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Адмін**_ | 3rd party tool          | _"Це дозволить користувачу імітувати токени та підвищити привілеї до системи nt, використовуючи такі інструменти, як potato.exe, rottenpotato.exe та juicypotato.exe"_                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Я спробую перефразувати це на щось більш схоже на рецепт найближчим часом.                                                                                                                                                                                         |
| **`SeBackup`**             | **Загроза** | _**Вбудовані команди**_ | Читати чутливі файли за допомогою `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Може бути більш цікавим, якщо ви можете прочитати %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (і robocopy) не допомагають, коли йдеться про відкриті файли.<br><br>- Robocopy вимагає як SeBackup, так і SeRestore для роботи з параметром /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Адмін**_ | 3rd party tool          | Створити довільний токен, включаючи права локального адміністратора, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Адмін**_ | **PowerShell**          | Дублювати токен `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Скрипт можна знайти на [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Адмін**_ | 3rd party tool          | <p>1. Завантажити помилковий драйвер ядра, наприклад <code>szkg64.sys</code><br>2. Використати вразливість драйвера<br><br>Альтернативно, привілей може бути використаний для вивантаження драйверів, пов'язаних із безпекою, за допомогою вбудованої команди <code>ftlMC</code>, тобто: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Вразливість <code>szkg64</code> вказана як <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">код експлуатації</a> був створений <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Адмін**_ | **PowerShell**          | <p>1. Запустіть PowerShell/ISE з присутнім привілеєм SeRestore.<br>2. Увімкніть привілей за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Перейменуйте utilman.exe в utilman.old<br>4. Перейменуйте cmd.exe в utilman.exe<br>5. Заблокуйте консоль і натисніть Win+U</p> | <p>Атаку можуть виявити деякі антивірусні програми.</p><p>Альтернативний метод ґрунтується на заміні бінарних файлів служб, збережених у "Program Files", використовуючи той же привілей</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Адмін**_ | _**Вбудовані команди**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменуйте cmd.exe в utilman.exe<br>4. Заблокуйте консоль і натисніть Win+U</p>                                                                                                                                       | <p>Атаку можуть виявити деякі антивірусні програми.</p><p>Альтернативний метод ґрунтується на заміні бінарних файлів служб, збережених у "Program Files", використовуючи той же привілей.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Адмін**_ | 3rd party tool          | <p>Маніпулювати токенами, щоб включити права локального адміністратора. Може вимагати SeImpersonate.</p><p>Підлягає перевірці.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Посилання

- Ознайомтеся з цією таблицею, що визначає токени Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Ознайомтеся з [**цією статтею**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) про підвищення привілеїв за допомогою токенів.

{{#include ../../banners/hacktricks-training.md}}
