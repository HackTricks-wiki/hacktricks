# Підвищення привілеїв за допомогою Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** можна використовувати для запуску програм під час **запуску системи**. Перегляньте, які двійкові файли запрограмовані для запуску під час запуску системи, за допомогою:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Заплановані завдання

**Завдання** можна запланувати на виконання з **певною періодичністю**. Скористайтеся наведеними командами, щоб побачити, які бінарні файли заплановано до запуску:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Увімкнене завдання, що запускається від імені SYSTEM, варто перевірити, навіть якщо його визначення та файл дії захищені. [Для запуску завдання за запитом Планувальнику завдань потрібен дозвіл на виконання цього завдання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Якщо такий дозвіл має користувач із низькими привілеями, перевірте точну дію, особливо сценарії PowerShell, які змінюють ACL Active Directory або скидають параметри захисту облікових записів. Перевірте параметр завдання `AllowDemandStart` і переконайтеся, що вхідні дані та результати роботи сценарію безпечні; сам по собі дозвіл запускати фіксоване завдання не означає можливість довільного виконання коду.

## Папки

Усі бінарні файли, розташовані в **папках автозавантаження, виконуються під час запуску системи**. Найпоширеніші папки автозавантаження наведено нижче, але папку автозавантаження вказано в реєстрі. [Прочитайте тут, щоб дізнатися де.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Запис Startup користувача з вищими привілеями може запускати захищений скрипт, який повторно відкриває файли з каталогу, доступного для запису іншому користувачеві. Перш ніж вважати цей каталог шляхом підвищення привілеїв, перевірте **фактичний обліковий запис, під яким виконується вхід**, каталог, з якого скрипт бере файли, права доступу до нього та точну дію скрипту. Зокрема, [`hh.exe` відкриває скомпільовані файли HTML Help (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); скрипт, який передає йому файли, надані користувачем, перетинає межу довіри до вмісту, навіть якщо перевіряє ім’я файлу або перші байти. [Політики HTML Help можуть обмежувати виконання ярликів](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), тому перевірте встановлену політику та поведінку доступного вмісту. Розширення `.chm` або сигнатурні байти самі по собі не доводять виконання коду з вищими привілеями. Під час інвентаризації перевірте autorun-запис, командний рядок процесу та права доступу до шляхів, не відкриваючи ненадійний файл.

Така сама межа довіри до вмісту виникає, коли особа з вищими привілеями **вручну відкриває** файл `.chm` із папки документації, яку може змінити інший користувач. Перевірте точний файл і права на запис до батьківського каталогу, фактичний обліковий запис переглядача, подію відкриття та ефективну політику HTML Help. Доступна для запису папка або прохання переглянути документацію не доводять, що користувач із вищими привілеями відкрив контрольований зловмисником вміст.

> **ДО ВІДОМА**: Уразливості *path traversal* під час розпакування архівів (наприклад, та, яку використовували у WinRAR до версії 7.13 — CVE-2025-8088) можна використати, щоб **безпосередньо розмістити payloads у цих папках Startup під час розпакування**, що призведе до виконання коду під час наступного входу користувача в систему. Щоб детальніше ознайомитися з цією технікою, дивіться:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Реєстр

> [!TIP]
> [Примітка звідси](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): запис реєстру **Wow6432Node** вказує, що ви використовуєте 64-розрядну версію Windows. Операційна система використовує цей ключ, щоб відображати окреме представлення HKEY_LOCAL_MACHINE\SOFTWARE для 32-розрядних програм, що запускаються у 64-розрядних версіях Windows.

### Запуски

**Загальновідомі** ключі реєстру AutoRun:

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

Ключі реєстру **Run** і **RunOnce** призначені для автоматичного запуску програм щоразу, коли користувач входить у систему. Командний рядок, указаний як значення даних ключа, може містити не більше ніж 260 символів.<sup>[[2]](#references)</sup>

**Запуски служб** (можуть керувати автоматичним запуском служб під час завантаження системи):

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

У Windows Vista та новіших версіях ключі реєстру **Run** і **RunOnce** не створюються автоматично. Записи в цих ключах можуть безпосередньо запускати програми або визначати їх як залежності. Наприклад, щоб завантажити DLL-файл під час входу в систему, можна скористатися ключем реєстру **RunOnceEx** разом із ключем «Depend». Нижче показано, як додати запис реєстру для виконання «C:\temp\evil.dll» під час запуску системи:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Якщо ви можете записувати в будь-який із зазначених розділів реєстру в **HKLM**, ви можете підвищити привілеї, коли ввійде інший користувач.

> [!TIP]
> **Exploit 2**: Якщо ви можете перезаписати будь-який із бінарних файлів, указаних у розділах реєстру в **HKLM**, ви можете змінити цей файл, додавши backdoor, щоб підвищити привілеї, коли ввійде інший користувач.

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

Ярлики, розміщені в папці **Startup**, автоматично запускають служби або програми під час входу користувача в систему або її перезавантаження. Розташування папки **Startup** визначається в реєстрі окремо для областей **Local Machine** і **Current User**. Це означає, що будь-який ярлик, доданий у зазначені розташування **Startup**, забезпечить запуск пов’язаної з ним служби або програми після входу в систему чи перезавантаження, що є простим способом налаштувати автоматичний запуск програм.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Якщо ви можете перезаписати будь-яку папку \[User] Shell Folder у **HKLM**, то зможете вказати для неї папку під вашим контролем і розмістити там бекдор, який виконуватиметься щоразу, коли користувач входитиме в систему, підвищуючи ваші привілеї.

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

Це значення реєстру для конкретного користувача може вказувати на скрипт або команду, яка виконується під час входу цього користувача в систему. Це переважно примітив **persistence**, оскільки виконується лише в контексті ураженого користувача, але його все одно варто перевіряти під час post-exploitation та аналізу autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Якщо ви можете записати це значення для поточного користувача, то зможете повторно запустити виконання під час наступного інтерактивного входу без прав адміністратора. Якщо ви можете записати його у вулик реєстру іншого користувача, то зможете виконати код, коли цей користувач увійде в систему.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Примітки:

- Віддавайте перевагу повним шляхам до файлів `.bat`, `.cmd`, `.ps1` або інших файлів запуску, які цільовий користувач уже може читати.
- Це зберігається після виходу із системи чи перезавантаження, доки значення не буде видалено.
- На відміну від `HKLM\...\Run`, це саме по собі **не надає підвищених привілеїв**; це механізм збереження доступу в межах користувача.

### Ключі Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Зазвичай ключ **Userinit** має значення **userinit.exe**. Однак, якщо цей ключ змінити, вказаний виконуваний файл також запускатиметься **Winlogon** під час входу користувача в систему. Так само ключ **Shell** має вказувати на **explorer.exe** — оболонку Windows за замовчуванням.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Якщо ви можете перезаписати значення реєстру або бінарний файл, ви зможете підвищити привілеї.

### Параметри політики

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

### Зміна командного рядка в безпечному режимі

У реєстрі Windows, у розділі `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, є значення **`AlternateShell`**, за замовчуванням встановлене як `cmd.exe`. Це означає, що під час вибору «Безпечний режим із командним рядком» під час запуску (натисканням F8) використовується `cmd.exe`. Але комп’ютер можна налаштувати так, щоб він автоматично запускався в цьому режимі без натискання F8 і ручного вибору.

Кроки для створення параметра завантаження, який автоматично запускає «Безпечний режим із командним рядком»:<sup>[[5]](#references)</sup>

1. Змініть атрибути файлу `boot.ini`, щоб зняти прапорці «лише читання», «системний» і «прихований»: `attrib c:\boot.ini -r -s -h`
2. Відкрийте `boot.ini` для редагування.
3. Додайте рядок на зразок: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Збережіть зміни у файлі `boot.ini`.
5. Відновіть початкові атрибути файлу: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Зміна ключа реєстру **AlternateShell** дає змогу налаштувати власну командну оболонку, що потенційно може забезпечити несанкціонований доступ.
- **Exploit 2 (PATH Write Permissions):** Наявність дозволів на запис у будь-яку частину системної змінної **PATH**, особливо перед `C:\Windows\system32`, дає змогу виконати власний `cmd.exe`, який може слугувати бекдором, якщо система запускається в безпечному режимі.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Доступ на запис до `boot.ini` дає змогу налаштувати автоматичний запуск у безпечному режимі, що сприяє несанкціонованому доступу після наступного перезавантаження.

Щоб перевірити поточне значення **AlternateShell**, скористайтеся такими командами:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Встановлений компонент

Active Setup — це функція Windows, яка **запускається до повного завантаження середовища робочого стола**. Вона надає пріоритет виконанню певних команд, які мають завершитися до продовження входу користувача в систему. Цей процес відбувається навіть до запуску інших записів автозавантаження, наприклад у розділах реєстру Run або RunOnce.

Active Setup керується за допомогою таких ключів реєстру:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

У цих ключах є різні підрозділи, кожен із яких відповідає певному компоненту. Особливий інтерес становлять такі значення ключів:

- **IsInstalled:**
  - `0` означає, що команда компонента не виконуватиметься.
  - `1` означає, що команда виконається один раз для кожного користувача; це стандартна поведінка, якщо значення `IsInstalled` відсутнє.
- **StubPath:** Визначає команду, яку має виконати Active Setup. Це може бути будь-який коректний командний рядок, наприклад запуск `notepad`.

**Відомості про безпеку:**

- Зміна ключа або запис до нього, де **`IsInstalled`** має значення `"1"` і задано певний **`StubPath`**, може призвести до несанкціонованого виконання команд і потенційно до підвищення привілеїв.
- Зміна бінарного файла, на який посилається будь-яке значення **`StubPath`**, також може забезпечити підвищення привілеїв за наявності достатніх дозволів.

Щоб переглянути конфігурації **`StubPath`** компонентів Active Setup, можна скористатися такими командами:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Огляд Browser Helper Objects (BHO)

Browser Helper Objects (BHO) — це DLL-модулі, які додають додаткові функції до Microsoft Internet Explorer. Вони завантажуються в Internet Explorer і Windows Explorer під час кожного запуску. Однак їх виконання можна заблокувати, встановивши для ключа **NoExplorer** значення 1, що не дозволить завантажувати їх у екземпляри Windows Explorer.<sup>[[1]](#references)</sup>

BHO сумісні з Windows 10 через Internet Explorer 11, але не підтримуються в Microsoft Edge — браузері за замовчуванням у новіших версіях Windows.

Щоб переглянути зареєстровані в системі BHO, перевірте такі ключі реєстру:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Кожен BHO представлений у реєстрі своїм **CLSID**, який слугує унікальним ідентифікатором. Детальну інформацію про кожен CLSID можна знайти в `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Для запиту відомостей про BHO в реєстрі можна скористатися такими командами:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Розширення Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Зверніть увагу: у реєстрі буде створено новий розділ для кожної DLL, і він буде представлений **CLSID**. Інформацію про CLSID можна знайти в `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Драйвери шрифтів

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Команда відкриття

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Обробники COM контекстного меню

Обробники контекстного меню Explorer — це розширення оболонки, зареєстровані в таких розділах, як `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` і `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Значення за замовчуванням обробника, а іноді й назва його розділу — це CLSID. Перейдіть за цим CLSID до `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; його значення за замовчуванням указує DLL, яку завантажують під час виклику обробника.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Перевірте обидва представлення реєстру: 32-бітне та 64-бітне. `HKCR` об’єднує реєстрації класів для поточного користувача та всього комп’ютера, тому перевірте, до якого базового ключа звертатиметься процес. Ідентичність із низькими привілеями, яка може змінити машинне значення `InprocServer32`, може перенаправити привілейованіший процес до іншої DLL, але для ескалації потрібно, щоб цей процес викликав обробник. Шлях до DLL із правами на запис може створити подібний ризик, навіть якщо саме значення реєстру захищене.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Зверніть увагу, що всі місця, де можна знайти autoruns, **вже перевіряє**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Однак, щоб отримати **повніший список файлів, що запускаються автоматично**, можна скористатися [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)від Sysinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Більше

**Знайдіть більше записів Autoruns, пов’язаних із реєстром, у** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Поширені механізми закріплення шкідливого ПЗ](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – категорії автозапуску (Усунення несправностей за допомогою інструментів Windows Sysinternals, 2-ге видання)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Як додати параметр завантаження, який запускає альтернативну оболонку?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Підсумки Metasploit за 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
