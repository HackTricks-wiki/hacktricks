# Підвищення привілеїв за допомогою Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** можна використовувати для запуску програм під час **запуску системи**. Переглянути, які бінарні файли налаштовані на запуск під час запуску системи, можна за допомогою:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Заплановані завдання

**Завдання** можна запланувати на запуск із **певною періодичністю**. Скористайтеся наведеними нижче командами, щоб переглянути, які бінарні файли заплановано запускати:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Завдання, створене з `/sc ONLOGON /rl HIGHEST`, запитує найвищий рівень запуску, **доступний його зареєстрованому обліковому запису**; сам цей параметр ані не змінює цей обліковий запис, ані не обходить UAC. Процес із низькими привілеями не може зареєструвати завдання з найвищим рівнем запуску або вибрати SYSTEM як обліковий запис для завдання. Розглядайте наведений вище приклад як дію вже підвищеного процесу, а не як спосіб перейти від стандартного користувача до SYSTEM.<sup>[[8]](#references)</sup>

Увімкнене завдання, що запускається від імені SYSTEM, варто перевірити, навіть якщо його визначення та файл дії захищені. [Для запуску завдання на вимогу планувальнику завдань потрібен дозвіл на його виконання](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Якщо такий дозвіл має користувач із низькими привілеями, перевірте точну дію, особливо сценарії PowerShell, які змінюють ACL Active Directory або скидають параметри захисту облікових записів. Перевірте параметр `AllowDemandStart` завдання, а також входи й наслідки виконання сценарію; сам дозвіл запускати фіксоване завдання не означає можливості виконувати довільний код.

## Папки

Усі двійкові файли, розташовані в **папках автозавантаження, запускатимуться під час запуску системи**. Поширені папки автозавантаження перелічено нижче, але розташування папки автозавантаження вказано в реєстрі. [Прочитайте тут, щоб дізнатися де.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Запис Startup для користувача з вищими привілеями може запускати захищений скрипт, який багаторазово відкриває файли з каталогу, доступного для запису іншому користувачеві. Перш ніж вважати цей каталог шляхом до підвищення привілеїв, перевірте **фактичний обліковий запис, від імені якого виконується вхід**, каталог вхідних файлів скрипту та його ACL, а також точну дію. Зокрема, [`hh.exe` відкриває файли довідки HTML Help (`.chm`)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); скрипт, який передає йому файли, надані викликачем, перетинає межу довіри до вмісту, навіть якщо перевіряє ім’я файлу або його перші байти. [Політики HTML Help можуть обмежувати виконання ярликів](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), тому перевірте встановлену політику та доступну поведінку вмісту. Самі лише розширення `.chm` або сигнатурні байти не доводять виконання коду з вищими привілеями. Під час перевірки перелічіть записи автозапуску, командний рядок процесу та дозволи для шляхів, не відкриваючи ненадійний файл.

Така сама межа довіри до вмісту виникає, коли особа з вищими привілеями **вручну відкриває** файл `.chm` із каталогу документації, який може замінити інший користувач. Перевірте точний файл і права на запис до батьківського каталогу, фактичний обліковий запис програми перегляду й подію відкриття, а також чинну політику HTML Help. Доступний для запису каталог або прохання переглянути документацію не доводять, що користувач із вищими привілеями відкрив вміст, контрольований зловмисником.

> **До відома**: Уразливості *path traversal* під час розпакування архівів (наприклад, уразливість, якою зловживали у WinRAR до версії 7.13 — CVE-2025-8088) можна використати, щоб **розмістити payloads безпосередньо в цих каталогах Startup під час розпакування**, що призведе до виконання коду під час наступного входу користувача в систему. Докладний розбір цієї техніки дивіться тут:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Реєстр

> [!TIP]
> [Примітка звідси](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): запис реєстру **Wow6432Node** означає, що ви використовуєте 64-бітну версію Windows. Операційна система використовує цей ключ для відображення окремого представлення HKEY_LOCAL_MACHINE\SOFTWARE для 32-бітних програм, що працюють у 64-бітних версіях Windows.

### Запуски

**Загальновідомі** ключі AutoRun реєстру:

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

Ключі реєстру **Run** і **RunOnce** призначені для автоматичного запуску програм щоразу, коли користувач входить у систему. Довжина командного рядка, призначеного як значення даних ключа, не може перевищувати 260 символів.<sup>[[2]](#references)</sup>

**Запуски служб** (можуть керувати автоматичним запуском служб під час завантаження):

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

У Windows Vista та пізніших версіях ключі реєстру **Run** і **RunOnce** не створюються автоматично. Записи в цих ключах можуть безпосередньо запускати програми або вказувати їх як залежності. Наприклад, щоб завантажити файл DLL під час входу в систему, можна використати ключ реєстру **RunOnceEx** разом із ключем «Depend». Це можна зробити, додавши запис реєстру для виконання «C:\temp\evil.dll» під час запуску системи:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Якщо ви можете записувати до будь-якого зі згаданих розділів реєстру в **HKLM**, ви можете підвищити привілеї, коли входить інший користувач.

> [!TIP]
> **Exploit 2**: Якщо ви можете перезаписати будь-який із бінарних файлів, указаних у будь-якому розділі реєстру в **HKLM**, ви можете змінити цей файл, додавши backdoor, коли входить інший користувач, і підвищити привілеї.

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

Ярлики, розміщені в папці **Startup**, автоматично запускатимуть служби або програми під час входу користувача в систему чи її перезавантаження. Розташування папки **Startup** визначається в реєстрі для областей **Local Machine** і **Current User**. Це означає, що будь-який ярлик, доданий у вказані розташування **Startup**, забезпечить запуск пов’язаної служби або програми після входу в систему чи її перезавантаження, що є простим способом налаштувати автоматичний запуск програм.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Якщо ви можете перезаписати будь-яку папку \[User] Shell у **HKLM**, ви зможете вказати її на папку під вашим контролем і розмістити там backdoor, який виконуватиметься щоразу, коли користувач входитиме в систему, підвищуючи привілеї.

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

Це значення реєстру для окремого користувача може вказувати на скрипт або команду, що виконується під час входу цього користувача в систему. Це переважно примітив **persistence**, оскільки він запускається лише в контексті відповідного користувача, але його все одно варто перевіряти під час post-exploitation і перевірок autoruns.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Якщо ви можете змінити це значення для поточного користувача, то зможете повторно запустити його під час наступного інтерактивного входу в систему без прав адміністратора. Якщо ви можете змінити його у вулику реєстру іншого користувача, то можете отримати виконання коду, коли цей користувач увійде в систему.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Примітки:

- Віддавайте перевагу повним шляхам до файлів запуску `.bat`, `.cmd`, `.ps1` або інших, які вже доступні для читання цільовому користувачу.
- Це зберігається після виходу з системи чи перезавантаження, доки значення не буде видалено.
- На відміну від `HKLM\...\Run`, це **саме по собі не надає підвищених привілеїв**; це механізм збереження доступу в контексті користувача.

### Ключі Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Зазвичай ключ **Userinit** має значення **userinit.exe**. Однак якщо цей ключ змінити, зазначений виконуваний файл також запускатиметься **Winlogon** під час входу користувача в систему. Аналогічно, ключ **Shell** має вказувати на **explorer.exe** — оболонку Windows за замовчуванням.<sup>[[1]](#references)</sup>

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

### Зміна командного рядка в безпечному режимі

У реєстрі Windows у розділі `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` є значення **`AlternateShell`**, яке за замовчуванням задано як `cmd.exe`. Це означає, що під час вибору «Безпечний режим із командним рядком» під час запуску (натисканням F8) використовується `cmd.exe`. Але можна налаштувати комп’ютер так, щоб він автоматично запускався в цьому режимі без потреби натискати F8 і вибирати його вручну.

Кроки для створення варіанта завантаження з автоматичним запуском у «Безпечному режимі з командним рядком»:<sup>[[5]](#references)</sup>

1. Змініть атрибути файлу `boot.ini`, щоб зняти прапорці «лише для читання», «системний» і «прихований»: `attrib c:\boot.ini -r -s -h`
2. Відкрийте `boot.ini` для редагування.
3. Додайте рядок на зразок: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Збережіть зміни в `boot.ini`.
5. Відновіть початкові атрибути файлу: `attrib c:\boot.ini +r +s +h`

- **Експлойт 1:** Зміна ключа реєстру **AlternateShell** дає змогу налаштувати власну командну оболонку, що потенційно може забезпечити несанкціонований доступ.
- **Експлойт 2 (права на запис у PATH):** Права на запис у будь-яку частину системної змінної **PATH**, особливо перед `C:\Windows\system32`, дають змогу запускати власний `cmd.exe`, який може бути бекдором, якщо систему запущено в безпечному режимі.
- **Експлойт 3 (права на запис у PATH і boot.ini):** Доступ на запис до `boot.ini` дає змогу налаштувати автоматичний запуск у безпечному режимі, що полегшує несанкціонований доступ після наступного перезавантаження.

Щоб перевірити поточне значення **AlternateShell**, скористайтеся такими командами:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Встановлений компонент

Active Setup — це функція Windows, яка **запускається до повного завантаження робочого середовища**. Вона надає пріоритет виконанню певних команд, які мають завершитися до продовження входу користувача в систему. Цей процес відбувається ще до запуску інших елементів автозапуску, наприклад тих, що містяться в розділах реєстру Run або RunOnce.

Active Setup керується за допомогою таких розділів реєстру:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

У цих розділах є різні підрозділи, кожен із яких відповідає певному компоненту. Особливий інтерес становлять такі значення ключів:

- **IsInstalled:**
  - `0` означає, що команда компонента не виконуватиметься.
  - `1` означає, що команда виконуватиметься один раз для кожного користувача. Це типова поведінка, якщо значення `IsInstalled` відсутнє.
- **StubPath:** Визначає команду, яку має виконати Active Setup. Це може бути будь-який коректний командний рядок, наприклад запуск `notepad`.

**Відомості про безпеку:**

- Зміна або запис у ключ, де для **`IsInstalled`** встановлено значення `"1"` і задано певний **`StubPath`**, може призвести до несанкціонованого виконання команд, потенційно — до підвищення привілеїв.
- Зміна бінарного файлу, на який посилається будь-яке значення **`StubPath`**, також може забезпечити підвищення привілеїв за наявності достатніх прав.

Щоб перевірити конфігурації **`StubPath`** у компонентах Active Setup, можна скористатися такими командами:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Об’єкти-помічники браузера

### Огляд об’єктів-помічників браузера (BHO)

Об’єкти-помічники браузера (BHO) — це модулі DLL, які додають додаткові функції до Microsoft Internet Explorer. Вони завантажуються в Internet Explorer і Windows Explorer під час кожного запуску. Однак їх виконання можна заблокувати, встановивши значення ключа **NoExplorer** на 1, щоб запобігти їх завантаженню в екземплярах Windows Explorer.<sup>[[1]](#references)</sup>

BHO сумісні з Windows 10 через Internet Explorer 11, але не підтримуються в Microsoft Edge — браузері за замовчуванням у новіших версіях Windows.

Щоб переглянути зареєстровані в системі BHO, перевірте такі ключі реєстру:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Кожен BHO представлений у реєстрі своїм **CLSID**, що слугує унікальним ідентифікатором. Докладну інформацію про кожен CLSID можна знайти в розділі `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Для пошуку BHO в реєстрі можна скористатися такими командами:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Розширення Internet Explorer

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Зверніть увагу, що для кожної DLL у реєстрі буде створено новий розділ, позначений **CLSID**. Інформацію про CLSID можна знайти в `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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

### COM-обробники контекстного меню

Обробники контекстного меню Explorer — це розширення оболонки, зареєстровані в таких ключах, як `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` і `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Значення за замовчуванням обробника або іноді назва його ключа — це CLSID. За цим CLSID перейдіть до `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; його значення за замовчуванням указує DLL, що завантажується під час виклику обробника.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Перевірте обидва подання реєстру: 32-бітне та 64-бітне. `HKCR` об’єднує реєстрації класів для поточного користувача та всієї системи, тому перевірте, до якого базового ключа звертатиметься процес. Ідентичність із низькими привілеями, яка може змінити значення `InprocServer32` для всієї системи, може перенаправити привілейованіший процес до іншої DLL, але для підвищення привілеїв потрібно, щоб цей процес викликав обробник. Шлях до DLL із правом запису може створити подібний ризик, навіть якщо саме значення реєстру захищене.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Зверніть увагу, що **[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) уже перевіряє всі місця, де можна знайти autoruns. Однак, щоб отримати **повніший список файлів, що запускаються автоматично**, можна скористатися [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) від systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Більше

**Знайдіть більше записів Autoruns, як-от розділи реєстру, тут:** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Поширені механізми закріплення шкідливого ПЗ](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Автоматичне виконання під час завантаження або входу: ключі реєстру Run / папка автозапуску](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Скрипти ініціалізації під час завантаження або входу: скрипт входу (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – категорії автозапуску (Усунення несправностей за допомогою інструментів Windows Sysinternals, 2-ге видання)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Як додати параметр завантаження для запуску альтернативної оболонки?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Підсумки Metasploit за 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – контексти безпеки для завдань](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
